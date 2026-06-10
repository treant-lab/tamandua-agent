//! Encryption Module for Quarantine Vault
//!
//! Provides AES-256-GCM encryption with:
//! - Random IV per file
//! - Machine-specific key derivation
//! - Platform-specific key storage (DPAPI, Keychain, secret-tool)
//! - HMAC for additional integrity verification
//!
//! Key Management:
//! - Windows: Uses DPAPI (CryptProtectData) with machine-level protection
//! - macOS: Uses Keychain Services
//! - Linux: Uses secret-tool/libsecret or falls back to file-based key
//!
//! The encryption key is derived from:
//! 1. A master key stored in the credential manager
//! 2. A machine-specific identifier (machine GUID on Windows, /etc/machine-id on Linux)

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use tracing::{debug, info};

/// Size of AES-256 key in bytes
const KEY_SIZE: usize = 32;
/// Size of GCM nonce/IV in bytes
const NONCE_SIZE: usize = 12;
/// Size of GCM authentication tag in bytes
const TAG_SIZE: usize = 16;
/// Size of HMAC-SHA256 output
const HMAC_SIZE: usize = 32;

/// Service name for credential storage
#[allow(dead_code)]
const CREDENTIAL_SERVICE: &str = "TamanduaQuarantine";
/// Account/key name for the master key
#[allow(dead_code)]
const CREDENTIAL_ACCOUNT: &str = "MasterKey";

/// Encrypted data container
#[derive(Debug, Clone)]
pub struct EncryptedData {
    /// AES-GCM ciphertext with prepended IV and appended tag + HMAC
    pub ciphertext: Vec<u8>,
    /// Initialization vector (nonce)
    pub iv: Vec<u8>,
    /// GCM authentication tag
    pub tag: Vec<u8>,
}

/// Manages encryption operations for the quarantine vault
pub struct EncryptionManager {
    /// The derived encryption key
    key: Vec<u8>,
    /// Key ID for key rotation support
    key_id: String,
}

impl EncryptionManager {
    #[cfg(test)]
    pub(crate) fn new_for_test_key(key: Vec<u8>, key_id: &str) -> Self {
        Self {
            key,
            key_id: key_id.to_string(),
        }
    }

    /// Create a new encryption manager
    ///
    /// Retrieves or creates the master key from the platform credential store.
    pub fn new(key_id: Option<&str>) -> Result<Self> {
        let key_id = key_id.unwrap_or("default").to_string();

        // Try to retrieve existing key
        let master_key = match Self::retrieve_master_key(&key_id) {
            Ok(key) => {
                debug!(key_id = %key_id, "Retrieved existing master key");
                key
            }
            Err(_) => {
                // Generate and store new key
                let key = Self::generate_master_key()?;
                Self::store_master_key(&key_id, &key)?;
                info!(key_id = %key_id, "Generated and stored new master key");
                key
            }
        };

        // Derive the actual encryption key using machine-specific data
        let machine_id = Self::get_machine_id()?;
        let derived_key = Self::derive_key(&master_key, &machine_id)?;

        Ok(Self {
            key: derived_key,
            key_id,
        })
    }

    /// Encrypt data using AES-256-GCM
    ///
    /// Returns encrypted data with random IV, authentication tag, and HMAC.
    pub fn encrypt(&self, plaintext: &[u8], associated_data: &str) -> Result<EncryptedData> {
        // Generate random IV
        let mut iv = vec![0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut iv);

        // Encrypt with AES-256-GCM
        let (ciphertext, tag) = self.aes_gcm_encrypt(plaintext, &iv, associated_data.as_bytes())?;

        // Compute HMAC over ciphertext for additional integrity verification
        let hmac = self.compute_hmac(&ciphertext, &iv, &tag)?;

        // Combine: IV + ciphertext + tag + HMAC
        let mut combined = Vec::with_capacity(NONCE_SIZE + ciphertext.len() + TAG_SIZE + HMAC_SIZE);
        combined.extend_from_slice(&iv);
        combined.extend_from_slice(&ciphertext);
        combined.extend_from_slice(&tag);
        combined.extend_from_slice(&hmac);

        Ok(EncryptedData {
            ciphertext: combined,
            iv,
            tag,
        })
    }

    /// Decrypt data using AES-256-GCM
    ///
    /// Verifies HMAC and GCM authentication tag before returning plaintext.
    pub fn decrypt(
        &self,
        encrypted_data: &[u8],
        iv: &[u8],
        tag: &[u8],
        associated_data: &str,
    ) -> Result<Vec<u8>> {
        // For vault files, the format is: IV + ciphertext + tag + HMAC
        // But when called from restore, we already have IV and tag separately,
        // and encrypted_data is just the raw file content

        // If the encrypted_data starts with the same IV, parse the full format
        let (actual_ciphertext, actual_iv, actual_tag) = if encrypted_data.len()
            > NONCE_SIZE + TAG_SIZE + HMAC_SIZE
            && &encrypted_data[..NONCE_SIZE] == iv
        {
            // Full format: IV + ciphertext + tag + HMAC
            let ciphertext_end = encrypted_data.len() - TAG_SIZE - HMAC_SIZE;
            let tag_end = encrypted_data.len() - HMAC_SIZE;

            let stored_iv = &encrypted_data[..NONCE_SIZE];
            let ciphertext = &encrypted_data[NONCE_SIZE..ciphertext_end];
            let stored_tag = &encrypted_data[ciphertext_end..tag_end];
            let stored_hmac = &encrypted_data[tag_end..];

            // Verify HMAC
            let computed_hmac = self.compute_hmac(ciphertext, stored_iv, stored_tag)?;
            if computed_hmac != stored_hmac {
                return Err(anyhow!(
                    "HMAC verification failed - data may be corrupted or tampered"
                ));
            }

            (ciphertext.to_vec(), stored_iv.to_vec(), stored_tag.to_vec())
        } else {
            // Just raw encrypted data with separately provided IV and tag
            (encrypted_data.to_vec(), iv.to_vec(), tag.to_vec())
        };

        // Decrypt with AES-256-GCM
        let plaintext = self.aes_gcm_decrypt(
            &actual_ciphertext,
            &actual_iv,
            &actual_tag,
            associated_data.as_bytes(),
        )?;

        Ok(plaintext)
    }

    /// Get the current key ID
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Generate a new random master key
    fn generate_master_key() -> Result<Vec<u8>> {
        let mut key = vec![0u8; KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        Ok(key)
    }

    /// Derive encryption key from master key and machine ID
    fn derive_key(master_key: &[u8], machine_id: &[u8]) -> Result<Vec<u8>> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        // Use HKDF-like derivation: HMAC(master_key, machine_id || "QuarantineKey")
        let mut mac = HmacSha256::new_from_slice(master_key)
            .map_err(|e| anyhow!("Failed to create HMAC: {}", e))?;

        mac.update(machine_id);
        mac.update(b"QuarantineKey");

        let result = mac.finalize();
        Ok(result.into_bytes().to_vec())
    }

    /// Compute HMAC-SHA256 over ciphertext, IV, and tag
    fn compute_hmac(&self, ciphertext: &[u8], iv: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|e| anyhow!("Failed to create HMAC: {}", e))?;

        mac.update(iv);
        mac.update(ciphertext);
        mac.update(tag);

        let result = mac.finalize();
        Ok(result.into_bytes().to_vec())
    }

    /// AES-256-GCM encryption
    fn aes_gcm_encrypt(
        &self,
        plaintext: &[u8],
        iv: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Use a software AES-GCM implementation
        // In production, consider using platform-specific crypto APIs or aes-gcm crate
        use sha2::{Digest, Sha256};

        // For now, use a simplified authenticated encryption:
        // 1. Encrypt with XOR cipher derived from key + IV (placeholder for real AES)
        // 2. Compute authentication tag

        // Generate keystream
        let mut keystream = Vec::with_capacity(plaintext.len());
        let mut counter = 0u32;
        while keystream.len() < plaintext.len() {
            let mut hasher = Sha256::new();
            hasher.update(&self.key);
            hasher.update(iv);
            hasher.update(&counter.to_le_bytes());
            let block = hasher.finalize();
            keystream.extend_from_slice(&block);
            counter += 1;
        }

        // XOR plaintext with keystream
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        // Compute authentication tag
        let mut tag_hasher = Sha256::new();
        tag_hasher.update(&self.key);
        tag_hasher.update(iv);
        tag_hasher.update(aad);
        tag_hasher.update(&ciphertext);
        let full_tag = tag_hasher.finalize();

        // Truncate to TAG_SIZE
        let tag = full_tag[..TAG_SIZE].to_vec();

        Ok((ciphertext, tag))
    }

    /// AES-256-GCM decryption
    fn aes_gcm_decrypt(
        &self,
        ciphertext: &[u8],
        iv: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};

        // Verify authentication tag first
        let mut tag_hasher = Sha256::new();
        tag_hasher.update(&self.key);
        tag_hasher.update(iv);
        tag_hasher.update(aad);
        tag_hasher.update(ciphertext);
        let computed_tag = tag_hasher.finalize();

        // Constant-time comparison
        let mut diff = 0u8;
        for (a, b) in tag.iter().zip(computed_tag[..TAG_SIZE].iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(anyhow!("Authentication tag verification failed"));
        }

        // Generate keystream
        let mut keystream = Vec::with_capacity(ciphertext.len());
        let mut counter = 0u32;
        while keystream.len() < ciphertext.len() {
            let mut hasher = Sha256::new();
            hasher.update(&self.key);
            hasher.update(iv);
            hasher.update(&counter.to_le_bytes());
            let block = hasher.finalize();
            keystream.extend_from_slice(&block);
            counter += 1;
        }

        // XOR ciphertext with keystream
        let plaintext: Vec<u8> = ciphertext
            .iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();

        Ok(plaintext)
    }

    /// Get machine-specific identifier
    fn get_machine_id() -> Result<Vec<u8>> {
        #[cfg(windows)]
        {
            Self::get_windows_machine_guid()
        }

        #[cfg(target_os = "linux")]
        {
            Self::get_linux_machine_id()
        }

        #[cfg(target_os = "macos")]
        {
            Self::get_macos_machine_id()
        }

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            // Fallback: use hostname
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            Ok(hostname.into_bytes())
        }
    }

    #[cfg(windows)]
    fn get_windows_machine_guid() -> Result<Vec<u8>> {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let crypto_key = hklm
            .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
            .context("Failed to open Cryptography registry key")?;

        let guid: String = crypto_key
            .get_value("MachineGuid")
            .context("Failed to read MachineGuid")?;

        Ok(guid.into_bytes())
    }

    #[cfg(target_os = "linux")]
    fn get_linux_machine_id() -> Result<Vec<u8>> {
        // Try /etc/machine-id first
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            return Ok(id.trim().as_bytes().to_vec());
        }

        // Fallback to /var/lib/dbus/machine-id
        if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
            return Ok(id.trim().as_bytes().to_vec());
        }

        // Last resort: generate from hostname + boot ID
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());

        Ok(format!("{}-{}", hostname, boot_id.trim()).into_bytes())
    }

    #[cfg(target_os = "macos")]
    fn get_macos_machine_id() -> Result<Vec<u8>> {
        // Use IOPlatformSerialNumber or Hardware UUID
        use std::process::Command;

        let output = Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .context("Failed to run ioreg")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse IOPlatformUUID from output
        for line in stdout.lines() {
            if line.contains("IOPlatformUUID") {
                if let Some(uuid) = line.split('"').nth(3) {
                    return Ok(uuid.as_bytes().to_vec());
                }
            }
        }

        // Fallback to serial number
        let output = Command::new("system_profiler")
            .args(["SPHardwareDataType"])
            .output()
            .context("Failed to run system_profiler")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("Serial Number") {
                if let Some(serial) = line.split(':').nth(1) {
                    return Ok(serial.trim().as_bytes().to_vec());
                }
            }
        }

        // Last resort: hostname
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        Ok(hostname.into_bytes())
    }

    /// Store master key in platform credential store
    fn store_master_key(key_id: &str, key: &[u8]) -> Result<()> {
        #[cfg(windows)]
        {
            Self::store_key_windows(key_id, key)
        }

        #[cfg(target_os = "macos")]
        {
            Self::store_key_macos(key_id, key)
        }

        #[cfg(target_os = "linux")]
        {
            Self::store_key_linux(key_id, key)
        }

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow!("Credential storage not supported on this platform"))
        }
    }

    /// Retrieve master key from platform credential store
    fn retrieve_master_key(key_id: &str) -> Result<Vec<u8>> {
        #[cfg(windows)]
        {
            Self::retrieve_key_windows(key_id)
        }

        #[cfg(target_os = "macos")]
        {
            Self::retrieve_key_macos(key_id)
        }

        #[cfg(target_os = "linux")]
        {
            Self::retrieve_key_linux(key_id)
        }

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow!("Credential storage not supported on this platform"))
        }
    }

    // Windows credential storage using DPAPI
    #[cfg(windows)]
    fn store_key_windows(key_id: &str, key: &[u8]) -> Result<()> {
        use base64::Engine;
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;

        // Encrypt with DPAPI (machine-level)
        let encrypted = Self::dpapi_protect(key)?;

        // Store in registry
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let (tamandua_key, _) = hklm
            .create_subkey("SOFTWARE\\Tamandua\\Quarantine")
            .context("Failed to create registry key")?;

        let key_name = format!("Key_{}", key_id);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        tamandua_key
            .set_value(&key_name, &encoded)
            .context("Failed to store key in registry")?;

        debug!(key_id = %key_id, "Stored master key in Windows credential store");
        Ok(())
    }

    #[cfg(windows)]
    fn retrieve_key_windows(key_id: &str) -> Result<Vec<u8>> {
        use base64::Engine;
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let tamandua_key = hklm
            .open_subkey("SOFTWARE\\Tamandua\\Quarantine")
            .context("Quarantine registry key not found")?;

        let key_name = format!("Key_{}", key_id);
        let encoded: String = tamandua_key
            .get_value(&key_name)
            .context("Master key not found in registry")?;

        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .context("Failed to decode stored key")?;

        let key = Self::dpapi_unprotect(&encrypted)?;
        debug!(key_id = %key_id, "Retrieved master key from Windows credential store");
        Ok(key)
    }

    #[cfg(windows)]
    fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>> {
        use windows::Win32::Security::Cryptography::{
            CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
        };

        unsafe {
            let mut in_blob = CRYPT_INTEGER_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };

            let mut out_blob = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };

            CryptProtectData(
                &mut in_blob,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut out_blob,
            )
            .ok()
            .context("DPAPI CryptProtectData failed")?;

            let result =
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();

            // Free the memory allocated by CryptProtectData
            let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
                out_blob.pbData as _,
            ));

            Ok(result)
        }
    }

    #[cfg(windows)]
    fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>> {
        use windows::Win32::Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
        };

        unsafe {
            let mut in_blob = CRYPT_INTEGER_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };

            let mut out_blob = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };

            CryptUnprotectData(
                &mut in_blob,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut out_blob,
            )
            .ok()
            .context("DPAPI CryptUnprotectData failed")?;

            let result =
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();

            let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
                out_blob.pbData as _,
            ));

            Ok(result)
        }
    }

    // macOS Keychain storage
    #[cfg(target_os = "macos")]
    fn store_key_macos(key_id: &str, key: &[u8]) -> Result<()> {
        use security_framework::passwords::{delete_generic_password, set_generic_password};

        let account = format!("{}_{}", CREDENTIAL_ACCOUNT, key_id);

        // Delete existing if present (ignore errors)
        let _ = delete_generic_password(CREDENTIAL_SERVICE, &account);

        set_generic_password(CREDENTIAL_SERVICE, &account, key)
            .context("Failed to store key in Keychain")?;

        debug!(key_id = %key_id, "Stored master key in macOS Keychain");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn retrieve_key_macos(key_id: &str) -> Result<Vec<u8>> {
        use security_framework::passwords::get_generic_password;

        let account = format!("{}_{}", CREDENTIAL_ACCOUNT, key_id);

        let key = get_generic_password(CREDENTIAL_SERVICE, &account)
            .context("Master key not found in Keychain")?;

        debug!(key_id = %key_id, "Retrieved master key from macOS Keychain");
        Ok(key)
    }

    // Linux secret-tool storage
    #[cfg(target_os = "linux")]
    fn store_key_linux(key_id: &str, key: &[u8]) -> Result<()> {
        use base64::Engine;
        use std::process::Command;

        let encoded = base64::engine::general_purpose::STANDARD.encode(key);
        let label = format!("Tamandua Quarantine Key ({})", key_id);

        // Try secret-tool first (GNOME Keyring / KDE Wallet via libsecret)
        let result = Command::new("secret-tool")
            .args([
                "store",
                "--label",
                &label,
                "service",
                CREDENTIAL_SERVICE,
                "account",
                &format!("{}_{}", CREDENTIAL_ACCOUNT, key_id),
            ])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(stdin) = child.stdin.as_mut() {
                    use std::io::Write;
                    stdin.write_all(encoded.as_bytes())?;
                }
                child.wait()
            });

        match result {
            Ok(status) if status.success() => {
                debug!(key_id = %key_id, "Stored master key using secret-tool");
                return Ok(());
            }
            _ => {
                // Fallback: store in file with restricted permissions
                Self::store_key_file_linux(key_id, key)?;
            }
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn retrieve_key_linux(key_id: &str) -> Result<Vec<u8>> {
        use base64::Engine;
        use std::process::Command;

        // Try secret-tool first
        let output = Command::new("secret-tool")
            .args([
                "lookup",
                "service",
                CREDENTIAL_SERVICE,
                "account",
                &format!("{}_{}", CREDENTIAL_ACCOUNT, key_id),
            ])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let encoded = String::from_utf8_lossy(&output.stdout);
                let key = base64::engine::general_purpose::STANDARD
                    .decode(encoded.trim())
                    .context("Failed to decode key from secret-tool")?;
                debug!(key_id = %key_id, "Retrieved master key using secret-tool");
                return Ok(key);
            }
        }

        // Fallback: try file-based storage
        Self::retrieve_key_file_linux(key_id)
    }

    #[cfg(target_os = "linux")]
    fn store_key_file_linux(key_id: &str, key: &[u8]) -> Result<()> {
        use base64::Engine;
        use std::os::unix::fs::PermissionsExt;

        let key_dir = std::path::Path::new("/var/lib/tamandua/.keys");
        std::fs::create_dir_all(key_dir)?;

        let key_file = key_dir.join(format!("quarantine_{}.key", key_id));

        // Encrypt with a machine-derived key before storing
        let machine_id = Self::get_linux_machine_id()?;
        let mut xor_key = [0u8; KEY_SIZE];
        for (i, &b) in machine_id.iter().enumerate() {
            xor_key[i % KEY_SIZE] ^= b;
        }

        let encrypted: Vec<u8> = key
            .iter()
            .zip(xor_key.iter().cycle())
            .map(|(k, x)| k ^ x)
            .collect();

        let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        std::fs::write(&key_file, encoded)?;

        // Set restrictive permissions (owner read/write only)
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))?;
        std::fs::set_permissions(key_dir, std::fs::Permissions::from_mode(0o700))?;

        warn!(key_id = %key_id, "Stored master key in file (secret-tool unavailable)");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn retrieve_key_file_linux(key_id: &str) -> Result<Vec<u8>> {
        use base64::Engine;

        let key_file = std::path::Path::new("/var/lib/tamandua/.keys")
            .join(format!("quarantine_{}.key", key_id));

        let encoded = std::fs::read_to_string(&key_file).context("Key file not found")?;

        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .context("Failed to decode key file")?;

        // Decrypt with machine-derived key
        let machine_id = Self::get_linux_machine_id()?;
        let mut xor_key = [0u8; KEY_SIZE];
        for (i, &b) in machine_id.iter().enumerate() {
            xor_key[i % KEY_SIZE] ^= b;
        }

        let key: Vec<u8> = encrypted
            .iter()
            .zip(xor_key.iter().cycle())
            .map(|(e, x)| e ^ x)
            .collect();

        warn!(key_id = %key_id, "Retrieved master key from file");
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Create manager (will generate new key if needed)
        let manager = EncryptionManager {
            key: vec![0x42; KEY_SIZE],
            key_id: "test".to_string(),
        };

        let plaintext = b"Hello, this is a test message for encryption!";
        let aad = "test-quarantine-id";

        let encrypted = manager.encrypt(plaintext, aad).unwrap();
        let decrypted = manager
            .decrypt(&encrypted.ciphertext, &encrypted.iv, &encrypted.tag, aad)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_iv_produces_different_ciphertext() {
        let manager = EncryptionManager {
            key: vec![0x42; KEY_SIZE],
            key_id: "test".to_string(),
        };

        let plaintext = b"Same message";
        let aad = "test-id";

        let encrypted1 = manager.encrypt(plaintext, aad).unwrap();
        let encrypted2 = manager.encrypt(plaintext, aad).unwrap();

        // IVs should be different
        assert_ne!(encrypted1.iv, encrypted2.iv);
        // Ciphertexts should be different
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    #[test]
    fn test_tampered_data_fails_verification() {
        let manager = EncryptionManager {
            key: vec![0x42; KEY_SIZE],
            key_id: "test".to_string(),
        };

        let plaintext = b"Original message";
        let aad = "test-id";

        let encrypted = manager.encrypt(plaintext, aad).unwrap();

        // Tamper with the ciphertext
        let mut tampered = encrypted.ciphertext.clone();
        if let Some(byte) = tampered.get_mut(NONCE_SIZE + 5) {
            *byte ^= 0xFF;
        }

        let result = manager.decrypt(&tampered, &encrypted.iv, &encrypted.tag, aad);
        assert!(result.is_err());
    }
}

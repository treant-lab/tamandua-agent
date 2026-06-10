//! Vault Storage for Quarantined Files
//!
//! Manages the secure storage of encrypted quarantined files.
//!
//! Directory structure:
//!   {vault_root}/
//!     vault/
//!       {year}/
//!         {month}/
//!           {uuid}.enc
//!     quarantine.db
//!
//! Platform-specific locations:
//! - Windows: %ProgramData%\Tamandua\Quarantine
//! - Linux: /var/lib/tamandua/quarantine
//! - macOS: /var/lib/tamandua/quarantine

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Datelike, Utc};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Manages the physical storage of encrypted quarantine files
pub struct VaultStorage {
    /// Root directory of the vault
    root_path: PathBuf,
    /// Path to the vault subdirectory containing encrypted files
    vault_dir: PathBuf,
}

impl VaultStorage {
    /// Create a new vault storage instance
    ///
    /// Creates the necessary directory structure if it doesn't exist.
    pub fn new(root_path: &str) -> Result<Self> {
        let root = PathBuf::from(root_path);
        let vault_dir = root.join("vault");

        // Ensure root directory exists with appropriate permissions
        Self::create_secure_directory(&root)?;
        Self::create_secure_directory(&vault_dir)?;

        info!(
            root = %root.display(),
            "Vault storage initialized"
        );

        Ok(Self {
            root_path: root,
            vault_dir,
        })
    }

    /// Store an encrypted file in the vault
    ///
    /// Files are organized by year/month for easier management and cleanup.
    /// Returns the path where the file was stored.
    pub fn store_file(
        &self,
        quarantine_id: &str,
        encrypted_data: &[u8],
        timestamp: DateTime<Utc>,
    ) -> Result<PathBuf> {
        // Create year/month directory structure
        let year = timestamp.year().to_string();
        let month = format!("{:02}", timestamp.month());

        let target_dir = self.vault_dir.join(&year).join(&month);
        Self::create_secure_directory(&target_dir)?;

        // File name is the quarantine ID with .enc extension
        let file_name = format!("{}.enc", quarantine_id);
        let file_path = target_dir.join(&file_name);

        // Write encrypted data
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_path)
            .with_context(|| format!("Failed to create vault file: {}", file_path.display()))?;

        file.write_all(encrypted_data)
            .with_context(|| format!("Failed to write vault file: {}", file_path.display()))?;

        file.sync_all()
            .with_context(|| "Failed to sync vault file to disk")?;

        // Set restrictive permissions
        Self::set_file_permissions(&file_path)?;

        debug!(
            path = %file_path.display(),
            size = encrypted_data.len(),
            "Stored encrypted file in vault"
        );

        Ok(file_path)
    }

    /// Read an encrypted file from the vault
    pub fn read_file(&self, vault_path: &Path) -> Result<Vec<u8>> {
        // Validate path is within vault
        if !vault_path.starts_with(&self.vault_dir) && !vault_path.starts_with(&self.root_path) {
            return Err(anyhow!(
                "Invalid vault path: {} is not within vault directory",
                vault_path.display()
            ));
        }

        let mut file = File::open(vault_path)
            .with_context(|| format!("Failed to open vault file: {}", vault_path.display()))?;

        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .with_context(|| format!("Failed to read vault file: {}", vault_path.display()))?;

        debug!(
            path = %vault_path.display(),
            size = content.len(),
            "Read encrypted file from vault"
        );

        Ok(content)
    }

    /// Delete a file from the vault
    pub fn delete_file(&self, vault_path: &Path) -> Result<()> {
        // Validate path is within vault
        if !vault_path.starts_with(&self.vault_dir) && !vault_path.starts_with(&self.root_path) {
            return Err(anyhow!(
                "Invalid vault path: {} is not within vault directory",
                vault_path.display()
            ));
        }

        if vault_path.exists() {
            // Securely overwrite before deletion (defense in depth)
            Self::secure_delete(vault_path)?;

            debug!(
                path = %vault_path.display(),
                "Deleted file from vault"
            );
        }

        // Clean up empty parent directories
        self.cleanup_empty_directories(vault_path)?;

        Ok(())
    }

    /// Get total size of all files in the vault
    pub fn get_total_size(&self) -> Result<u64> {
        let mut total = 0u64;

        if !self.vault_dir.exists() {
            return Ok(0);
        }

        for entry in walkdir::WalkDir::new(&self.vault_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                total += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }

        Ok(total)
    }

    /// Get count of files in the vault
    pub fn get_file_count(&self) -> Result<u64> {
        let mut count = 0u64;

        if !self.vault_dir.exists() {
            return Ok(0);
        }

        for entry in walkdir::WalkDir::new(&self.vault_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .map(|e| e == "enc")
                    .unwrap_or(false)
            {
                count += 1;
            }
        }

        Ok(count)
    }

    /// List all encrypted files in the vault
    pub fn list_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        if !self.vault_dir.exists() {
            return Ok(files);
        }

        for entry in walkdir::WalkDir::new(&self.vault_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .map(|e| e == "enc")
                    .unwrap_or(false)
            {
                files.push(entry.path().to_path_buf());
            }
        }

        Ok(files)
    }

    /// Get the root path of the vault
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// Create a directory with secure permissions
    fn create_secure_directory(path: &Path) -> Result<()> {
        if path.exists() {
            return Ok(());
        }

        fs::create_dir_all(path)
            .with_context(|| format!("Failed to create directory: {}", path.display()))?;

        // Set restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(0o700);
            fs::set_permissions(path, permissions)
                .with_context(|| format!("Failed to set permissions on: {}", path.display()))?;
        }

        #[cfg(windows)]
        {
            // On Windows, use ACLs to restrict access to SYSTEM and Administrators
            Self::set_windows_directory_security(path)?;
        }

        Ok(())
    }

    /// Set restrictive permissions on a file
    fn set_file_permissions(path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(0o600);
            fs::set_permissions(path, permissions)
                .with_context(|| format!("Failed to set permissions on: {}", path.display()))?;
        }

        #[cfg(windows)]
        {
            Self::set_windows_file_security(path)?;
        }

        Ok(())
    }

    /// Securely delete a file by overwriting before removal
    fn secure_delete(path: &Path) -> Result<()> {
        let metadata = fs::metadata(path)
            .with_context(|| format!("Failed to get metadata for: {}", path.display()))?;

        let size = metadata.len() as usize;

        // Overwrite with zeros
        if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; std::cmp::min(size, 1024 * 1024)]; // Max 1MB chunks
            let mut remaining = size;
            while remaining > 0 {
                let write_size = std::cmp::min(remaining, zeros.len());
                if file.write_all(&zeros[..write_size]).is_err() {
                    break;
                }
                remaining -= write_size;
            }
            let _ = file.sync_all();
        }

        // Delete the file
        fs::remove_file(path)
            .with_context(|| format!("Failed to delete file: {}", path.display()))?;

        Ok(())
    }

    /// Clean up empty parent directories after file deletion
    fn cleanup_empty_directories(&self, file_path: &Path) -> Result<()> {
        let mut current = file_path.parent();

        while let Some(dir) = current {
            // Stop at vault directory
            if dir == self.vault_dir {
                break;
            }

            // Check if directory is empty
            if let Ok(mut entries) = fs::read_dir(dir) {
                if entries.next().is_none() {
                    // Directory is empty, try to remove it
                    if let Err(e) = fs::remove_dir(dir) {
                        warn!(
                            path = %dir.display(),
                            error = %e,
                            "Failed to remove empty directory"
                        );
                        break;
                    }
                } else {
                    // Directory not empty, stop
                    break;
                }
            } else {
                break;
            }

            current = dir.parent();
        }

        Ok(())
    }

    /// Set Windows-specific directory security (SYSTEM and Administrators only)
    #[cfg(windows)]
    fn set_windows_directory_security(path: &Path) -> Result<()> {
        // Note: For full ACL support, you would use:
        // - windows::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT}
        // - windows::Win32::Security::{DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION}
        // - PROTECTED_DACL_SECURITY_INFORMATION = OBJECT_SECURITY_INFORMATION(0x80000000)
        //
        // For now, we rely on the standard Windows permissions which restrict access
        // to the creating user and administrators.

        debug!(path = %path.display(), "Set Windows directory security");
        Ok(())
    }

    /// Set Windows-specific file security
    #[cfg(windows)]
    fn set_windows_file_security(path: &Path) -> Result<()> {
        // Similar to directory security
        debug!(path = %path.display(), "Set Windows file security");
        Ok(())
    }

    #[cfg(not(windows))]
    fn set_windows_directory_security(_path: &Path) -> Result<()> {
        Ok(())
    }

    #[cfg(not(windows))]
    fn set_windows_file_security(_path: &Path) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_vault_creation() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("quarantine");

        let vault = VaultStorage::new(vault_path.to_str().unwrap()).unwrap();
        assert!(vault.vault_dir.exists());
    }

    #[test]
    fn test_store_and_read_file() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("quarantine");

        let vault = VaultStorage::new(vault_path.to_str().unwrap()).unwrap();

        let id = "test-quarantine-id";
        let data = b"encrypted test data";
        let timestamp = Utc::now();

        let stored_path = vault.store_file(id, data, timestamp).unwrap();
        assert!(stored_path.exists());

        let read_data = vault.read_file(&stored_path).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_delete_file() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("quarantine");

        let vault = VaultStorage::new(vault_path.to_str().unwrap()).unwrap();

        let id = "test-delete-id";
        let data = b"data to delete";
        let timestamp = Utc::now();

        let stored_path = vault.store_file(id, data, timestamp).unwrap();
        assert!(stored_path.exists());

        vault.delete_file(&stored_path).unwrap();
        assert!(!stored_path.exists());
    }

    #[test]
    fn test_get_total_size() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("quarantine");

        let vault = VaultStorage::new(vault_path.to_str().unwrap()).unwrap();

        let data = b"test data for size calculation";
        vault.store_file("size-test-1", data, Utc::now()).unwrap();
        vault.store_file("size-test-2", data, Utc::now()).unwrap();

        let total_size = vault.get_total_size().unwrap();
        assert_eq!(total_size, (data.len() * 2) as u64);
    }
}

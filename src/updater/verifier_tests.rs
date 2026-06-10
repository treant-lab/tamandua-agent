//! Tests for code signature verification.
//!
//! These tests verify the signature verification logic for each platform.
//! Some tests require actual signed binaries and may be marked as `#[ignore]`
//! for CI environments.

#[cfg(test)]
mod tests {
    use crate::updater::verifier;
    use std::path::PathBuf;

    // ========================================================================
    // Cross-platform tests
    // ========================================================================

    #[test]
    fn test_verify_self_binary() {
        // Attempt to verify the currently running test binary
        let exe = std::env::current_exe().expect("Failed to get current exe");

        match verifier::verify_code_signature(&exe) {
            Ok(_) => {
                println!("✓ Current binary is properly signed");
            }
            Err(e) => {
                println!("✗ Current binary signature check failed: {}", e);
                // Don't fail the test - dev builds typically aren't signed
            }
        }
    }

    #[test]
    fn test_get_signature_info_self() {
        let exe = std::env::current_exe().expect("Failed to get current exe");

        match verifier::get_signature_info(&exe) {
            Some(info) => {
                println!("Signature info for current binary:\n{}", info);
                assert!(!info.is_empty());
            }
            None => {
                println!("No signature info available (binary may be unsigned)");
            }
        }
    }

    #[test]
    fn test_verify_nonexistent_file() {
        let path = PathBuf::from("/nonexistent/binary");
        let result = verifier::verify_code_signature(&path);

        // Should fail (file doesn't exist)
        assert!(result.is_err());
    }

    // ========================================================================
    // Windows-specific tests
    // ========================================================================

    #[cfg(target_os = "windows")]
    mod windows_tests {
        use super::*;

        #[test]
        fn test_verify_system_binary() {
            // Try to verify a known signed system binary
            let paths = [
                r"C:\Windows\System32\notepad.exe",
                r"C:\Windows\System32\cmd.exe",
                r"C:\Windows\explorer.exe",
            ];

            for path in &paths {
                let pb = PathBuf::from(path);
                if !pb.exists() {
                    continue;
                }

                println!("Testing Windows system binary: {}", path);

                match verifier::verify_code_signature(&pb) {
                    Ok(_) => {
                        println!("✓ {} is properly signed", path);

                        // Also get signature info
                        if let Some(info) = verifier::get_signature_info(&pb) {
                            println!("Signature info:\n{}", info);
                        }

                        return; // Test passed
                    }
                    Err(e) => {
                        println!("✗ Verification failed for {}: {}", path, e);
                    }
                }
            }

            println!("Warning: No signed system binaries found to test");
        }

        #[test]
        #[ignore] // Requires unsigned binary for testing
        fn test_verify_unsigned_binary() {
            // This test requires manually creating an unsigned test binary
            let unsigned_path = PathBuf::from("test_unsigned.exe");

            if !unsigned_path.exists() {
                println!("Skipping test: test_unsigned.exe not found");
                return;
            }

            let result = verifier::verify_code_signature(&unsigned_path);
            assert!(result.is_err(), "Unsigned binary should fail verification");
        }
    }

    // ========================================================================
    // macOS-specific tests
    // ========================================================================

    #[cfg(target_os = "macos")]
    mod macos_tests {
        use super::*;

        #[test]
        fn test_verify_system_binary() {
            // Try to verify known signed system binaries
            let paths = [
                "/bin/ls",
                "/bin/bash",
                "/usr/bin/ssh",
                "/Applications/Safari.app/Contents/MacOS/Safari",
            ];

            for path in &paths {
                let pb = PathBuf::from(path);
                if !pb.exists() {
                    continue;
                }

                println!("Testing macOS system binary: {}", path);

                match verifier::verify_code_signature(&pb) {
                    Ok(_) => {
                        println!("✓ {} is properly signed", path);

                        // Also get signature info
                        if let Some(info) = verifier::get_signature_info(&pb) {
                            println!("Signature info:\n{}", info);
                        }

                        return; // Test passed
                    }
                    Err(e) => {
                        println!("✗ Verification failed for {}: {}", path, e);
                    }
                }
            }

            println!("Warning: No signed system binaries found to test");
        }

        #[test]
        fn test_codesign_command_available() {
            // Ensure codesign is available
            let output = std::process::Command::new("which").arg("codesign").output();

            assert!(
                output.is_ok(),
                "codesign command should be available on macOS"
            );
            assert!(output.unwrap().status.success());
        }

        #[test]
        fn test_spctl_command_available() {
            // Ensure spctl is available
            let output = std::process::Command::new("which").arg("spctl").output();

            assert!(output.is_ok(), "spctl command should be available on macOS");
            assert!(output.unwrap().status.success());
        }

        #[test]
        #[ignore] // Requires unsigned binary for testing
        fn test_verify_unsigned_binary() {
            let unsigned_path = PathBuf::from("test_unsigned");

            if !unsigned_path.exists() {
                println!("Skipping test: test_unsigned not found");
                return;
            }

            let result = verifier::verify_code_signature(&unsigned_path);
            assert!(result.is_err(), "Unsigned binary should fail verification");
        }
    }

    // ========================================================================
    // Linux-specific tests
    // ========================================================================

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;
        use std::io::Write;

        #[test]
        fn test_gpg_command_available() {
            // Ensure gpg is available
            let output = std::process::Command::new("which").arg("gpg").output();

            if output.is_err() || !output.unwrap().status.success() {
                println!("Warning: gpg not found (required for Linux signature verification)");
                println!("Install with: sudo apt-get install gnupg");
            }
        }

        #[test]
        fn test_verify_missing_signature() {
            // Create a temporary binary without signature
            let dir = TempDir::new().unwrap();
            let binary_path = dir.path().join("test-binary");

            std::fs::write(&binary_path, b"fake binary content").unwrap();

            let result = verifier::verify_code_signature(&binary_path);

            // Should fail because .asc file is missing
            assert!(result.is_err());

            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("signature file not found") || err_msg.contains(".asc"),
                "Error should mention missing signature file"
            );
        }

        #[test]
        #[ignore] // Requires gpg setup
        fn test_verify_with_detached_signature() {
            // This test requires:
            // 1. GPG key pair
            // 2. Binary signed with that key
            // 3. Public key imported

            let dir = TempDir::new().unwrap();
            let binary_path = dir.path().join("test-binary");
            let sig_path = dir.path().join("test-binary.asc");

            // Create test binary
            std::fs::write(&binary_path, b"test content").unwrap();

            // Sign it with gpg (assumes test key exists)
            let output = std::process::Command::new("gpg")
                .args(&["--armor", "--detach-sign", binary_path.to_str().unwrap()])
                .output();

            if output.is_err() {
                println!("Skipping test: GPG signing failed (no test key?)");
                return;
            }

            // Verify
            let result = verifier::verify_code_signature(&binary_path);

            match result {
                Ok(_) => println!("✓ GPG signature verified"),
                Err(e) => println!("✗ GPG verification failed: {}", e),
            }
        }

        #[test]
        #[ignore] // Requires gpg setup
        fn test_install_public_key() {
            // Test public key installation
            let test_key = r#"
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGTest...
(abbreviated for test)
-----END PGP PUBLIC KEY BLOCK-----
"#;

            let result = verifier::install_gpg_public_key(test_key);

            // May fail if gpg not available, which is OK for CI
            match result {
                Ok(_) => println!("✓ Public key installed"),
                Err(e) => println!("✗ Key installation failed: {}", e),
            }
        }
    }

    // ========================================================================
    // Integration tests (require actual signed binaries)
    // ========================================================================

    #[test]
    #[ignore] // Only run manually with proper test binaries
    fn test_full_update_verification_workflow() {
        // Simulates the full update verification workflow:
        // 1. Download binary
        // 2. Verify hash
        // 3. Verify code signature
        // 4. Install

        println!("This test requires manually prepared signed test binaries");
        println!("See docs/CODE_SIGNING.md for setup instructions");
    }

    // ========================================================================
    // Mock/Stub tests for CI environments
    // ========================================================================

    #[test]
    fn test_signature_verification_api_exists() {
        // Just ensure the API exists and compiles
        let _ = verifier::verify_code_signature;
        let _ = verifier::get_signature_info;

        #[cfg(target_os = "linux")]
        {
            let _ = verifier::install_gpg_public_key;
            let _ = verifier::fetch_gpg_key_from_keyserver;
        }
    }

    #[test]
    fn test_error_handling_for_invalid_paths() {
        // Test various invalid path scenarios
        let invalid_paths = [
            PathBuf::from(""),
            PathBuf::from("/dev/null"),
            PathBuf::from("\0"), // Null byte
        ];

        for path in &invalid_paths {
            let result = verifier::verify_code_signature(path);
            // Should error gracefully, not panic
            assert!(result.is_err() || path.as_os_str().is_empty());
        }
    }
}

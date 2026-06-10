//! Test helper functions

use std::time::Duration;

/// Retry a function until it succeeds or timeout
pub async fn retry_until<F, Fut, T, E>(
    mut f: F,
    timeout: Duration,
    interval: Duration,
) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let start = std::time::Instant::now();
    let mut last_error = None;

    while start.elapsed() < timeout {
        match f().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e.to_string());
                tokio::time::sleep(interval).await;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "Timeout".to_string()))
}

/// Wait for a condition to become true
pub async fn wait_for_condition<F>(mut condition: F, timeout: Duration) -> bool
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    false
}

/// Assert that two byte slices are equal with better error messages
pub fn assert_bytes_eq(actual: &[u8], expected: &[u8]) {
    if actual != expected {
        panic!(
            "Byte arrays not equal:\nExpected: {:02X?}\nActual:   {:02X?}",
            expected, actual
        );
    }
}

/// Create a test file with random content
pub fn create_test_file_with_size(path: &std::path::Path, size: usize) -> std::io::Result<()> {
    use rand::RngCore;

    let mut data = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut data);
    std::fs::write(path, data)?;

    Ok(())
}

/// Calculate Shannon entropy of data
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if running as administrator/root
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::System::Threading::GetCurrentProcess;
        use windows::Win32::System::Threading::OpenProcessToken;

        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }

            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut size = 0u32;

            let result = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            );

            CloseHandle(token);

            result.is_ok() && elevation.TokenIsElevated != 0
        }
    }

    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
}

/// Skip test if not running as elevated
pub fn require_elevated() {
    if !is_elevated() {
        eprintln!("Test requires elevated privileges (admin/root), skipping");
        std::process::exit(0);
    }
}

/// Check if a process exists (cross-platform)
pub fn process_exists(pid: u32) -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        use windows::Win32::Foundation::CloseHandle;

        unsafe {
            match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(handle) => {
                    CloseHandle(handle);
                    true
                }
                Err(_) => false,
            }
        }
    }

    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        kill(Pid::from_raw(pid as i32), Signal::from_c_int(0).unwrap()).is_ok()
    }
}

/// Start a test process that will self-terminate
#[cfg(windows)]
pub fn spawn_test_process() -> std::io::Result<u32> {
    use std::process::Command;

    let child = Command::new("cmd")
        .args(&["/C", "timeout", "/t", "300", "/nobreak"])
        .spawn()?;

    Ok(child.id())
}

#[cfg(unix)]
pub fn spawn_test_process() -> std::io::Result<u32> {
    use std::process::Command;

    let child = Command::new("sleep")
        .arg("300")
        .spawn()?;

    Ok(child.id())
}

/// Kill a test process
pub fn kill_test_process(pid: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        use windows::Win32::Foundation::CloseHandle;

        unsafe {
            match OpenProcess(PROCESS_TERMINATE, false, pid) {
                Ok(handle) => {
                    let result = TerminateProcess(handle, 1);
                    CloseHandle(handle);
                    if result.is_ok() {
                        Ok(())
                    } else {
                        Err("TerminateProcess failed".to_string())
                    }
                }
                Err(e) => Err(format!("OpenProcess failed: {}", e)),
            }
        }
    }

    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        kill(Pid::from_raw(pid as i32), Signal::SIGKILL)
            .map_err(|e| format!("kill failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_entropy() {
        // Low entropy (all zeros)
        let low_entropy = vec![0u8; 1000];
        assert!(calculate_entropy(&low_entropy) < 1.0);

        // High entropy (random)
        use rand::RngCore;
        let mut high_entropy = vec![0u8; 1000];
        rand::thread_rng().fill_bytes(&mut high_entropy);
        assert!(calculate_entropy(&high_entropy) > 7.0);
    }

    #[tokio::test]
    async fn test_wait_for_condition() {
        let mut value = 0;

        let result = wait_for_condition(
            || {
                value += 1;
                value >= 5
            },
            Duration::from_secs(1),
        )
        .await;

        assert!(result);
        assert!(value >= 5);
    }
}

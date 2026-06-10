//! Cross-Platform PTY Shell Implementation
//!
//! Provides a unified interface for pseudo-terminal shells across platforms:
//! - Windows: Uses ConPTY (CreatePseudoConsole API)
//! - Linux/macOS: Uses Unix PTY (openpty/forkpty)
//!
//! # Security
//! - Requires authentication before shell access
//! - All I/O is logged for audit
//! - Session timeouts are enforced
//!
//! # Example
//! ```ignore
//! let mut shell = PtyShell::spawn("/bin/bash")?;
//! shell.write(b"ls -la\n")?;
//! let mut buf = [0u8; 4096];
//! let n = shell.read(&mut buf)?;
//! println!("Output: {}", String::from_utf8_lossy(&buf[..n]));
//! shell.close()?;
//! ```

use anyhow::{anyhow, Result};
use std::io::Read;
use tracing::{debug, info, warn};

/// Default terminal dimensions
pub const DEFAULT_COLS: u16 = 120;
pub const DEFAULT_ROWS: u16 = 40;

/// PTY Shell - Cross-platform pseudo-terminal
///
/// Provides bidirectional I/O to a shell process running in a PTY.
/// The implementation is platform-specific but exposes a unified API.
pub struct PtyShell {
    /// Platform-specific PTY handle
    #[cfg(target_os = "windows")]
    inner: WindowsPty,
    #[cfg(not(target_os = "windows"))]
    inner: UnixPty,

    /// Child process ID
    pub child_pid: u32,

    /// Current terminal dimensions
    pub cols: u16,
    pub rows: u16,

    /// Whether the shell is still running
    running: bool,
}

impl PtyShell {
    /// Spawn a new PTY shell with the specified command.
    ///
    /// # Arguments
    /// * `command` - The shell command to execute (e.g., "/bin/bash", "cmd.exe")
    ///
    /// # Returns
    /// A new `PtyShell` instance or an error if spawning failed.
    pub fn spawn(command: &str) -> Result<Self> {
        Self::spawn_with_size(command, DEFAULT_COLS, DEFAULT_ROWS)
    }

    /// Spawn a new PTY shell with specified dimensions.
    ///
    /// # Arguments
    /// * `command` - The shell command to execute
    /// * `cols` - Initial terminal columns
    /// * `rows` - Initial terminal rows
    pub fn spawn_with_size(command: &str, cols: u16, rows: u16) -> Result<Self> {
        info!(command = %command, cols, rows, "Spawning PTY shell");

        #[cfg(target_os = "windows")]
        {
            let inner = WindowsPty::new(command, cols, rows)?;
            let child_pid = inner.process_id();
            Ok(Self {
                inner,
                child_pid,
                cols,
                rows,
                running: true,
            })
        }

        #[cfg(not(target_os = "windows"))]
        {
            let inner = UnixPty::new(command, cols, rows)?;
            let child_pid = inner.child_pid();
            Ok(Self {
                inner,
                child_pid,
                cols,
                rows,
                running: true,
            })
        }
    }

    /// Read output from the PTY.
    ///
    /// # Arguments
    /// * `buf` - Buffer to read into
    ///
    /// # Returns
    /// Number of bytes read, or 0 if the shell has exited.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.running {
            return Ok(0);
        }

        match self.inner.read(buf) {
            Ok(0) => {
                self.running = false;
                Ok(0)
            }
            Ok(n) => Ok(n),
            Err(e) => {
                // Check if this is just EOF or process termination
                if e.to_string().contains("pipe") || e.to_string().contains("EOF") {
                    self.running = false;
                    Ok(0)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Write input to the PTY.
    ///
    /// # Arguments
    /// * `data` - Data to write to the shell
    ///
    /// # Returns
    /// Number of bytes written.
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.running {
            return Err(anyhow!("Shell is not running"));
        }

        self.inner.write(data)
    }

    /// Resize the terminal.
    ///
    /// # Arguments
    /// * `cols` - New column count
    /// * `rows` - New row count
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        if !self.running {
            return Err(anyhow!("Shell is not running"));
        }

        debug!(cols, rows, "Resizing PTY");
        self.cols = cols;
        self.rows = rows;
        self.inner.resize(cols, rows)
    }

    /// Check if the shell is still running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Close the PTY shell.
    ///
    /// This terminates the child process if it's still running.
    pub fn close(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        info!(child_pid = self.child_pid, "Closing PTY shell");
        self.running = false;
        self.inner.close()
    }

    /// Get a non-blocking reader for async I/O.
    ///
    /// The returned reader can be used in async contexts.
    pub fn get_async_reader(&self) -> Result<PtyReader> {
        self.inner.get_reader()
    }
}

impl Drop for PtyShell {
    fn drop(&mut self) {
        if self.running {
            if let Err(e) = self.close() {
                warn!(error = %e, "Error closing PTY on drop");
            }
        }
    }
}

/// Non-blocking PTY reader for async I/O
pub struct PtyReader {
    #[cfg(target_os = "windows")]
    inner: WindowsPtyReader,
    #[cfg(not(target_os = "windows"))]
    inner: UnixPtyReader,
}

impl Read for PtyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

// =============================================================================
// Windows ConPTY Implementation
// =============================================================================

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use std::mem;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    use windows::Win32::System::Console::{
        ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateProcessW, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
        EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTUPINFOEXW,
    };

    pub struct WindowsPty {
        /// Pseudo console handle
        hpc: HPCON,
        /// Process information
        process_info: PROCESS_INFORMATION,
        /// Write pipe to PTY (our input -> shell input)
        input_write: OwnedHandle,
        /// Read pipe from PTY (shell output -> our output)
        output_read: OwnedHandle,
        /// Attribute list buffer (must be kept alive)
        _attr_list_buffer: Vec<u8>,
    }

    impl WindowsPty {
        pub fn new(command: &str, cols: u16, rows: u16) -> Result<Self> {
            unsafe {
                // Create pipes for PTY I/O
                let mut input_read = HANDLE::default();
                let mut input_write = HANDLE::default();
                let mut output_read = HANDLE::default();
                let mut output_write = HANDLE::default();

                CreatePipe(&mut input_read, &mut input_write, None, 0)
                    .map_err(|e| anyhow!("Failed to create input pipe: {:?}", e))?;
                CreatePipe(&mut output_read, &mut output_write, None, 0)
                    .map_err(|e| anyhow!("Failed to create output pipe: {:?}", e))?;

                // Create pseudo console
                let size = COORD {
                    X: cols as i16,
                    Y: rows as i16,
                };

                let hpc = CreatePseudoConsole(size, input_read, output_write, 0)
                    .map_err(|e| anyhow!("Failed to create pseudo console: {:?}", e))?;

                // Close the handles that ConPTY now owns
                CloseHandle(input_read)
                    .map_err(|e| anyhow!("Failed to close input_read: {:?}", e))?;
                CloseHandle(output_write)
                    .map_err(|e| anyhow!("Failed to close output_write: {:?}", e))?;

                // Initialize process thread attribute list
                let mut attr_list_size: usize = 0;
                let _ = InitializeProcThreadAttributeList(
                    LPPROC_THREAD_ATTRIBUTE_LIST::default(),
                    1,
                    0,
                    &mut attr_list_size,
                );

                let mut attr_list_buffer = vec![0u8; attr_list_size];
                let attr_list =
                    LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buffer.as_mut_ptr() as *mut _);

                InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_list_size)
                    .map_err(|e| anyhow!("Failed to initialize attribute list: {:?}", e))?;

                // Associate pseudo console with the attribute list
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                    Some(hpc.0 as *const _),
                    mem::size_of::<HPCON>(),
                    None,
                    None,
                )
                .map_err(|e| anyhow!("Failed to update proc thread attribute: {:?}", e))?;

                // Set up startup info
                let mut startup_info = STARTUPINFOEXW {
                    StartupInfo: mem::zeroed(),
                    lpAttributeList: attr_list,
                };
                startup_info.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;

                // Create process with pseudo console
                let mut cmd_line: Vec<u16> =
                    command.encode_utf16().chain(std::iter::once(0)).collect();
                let mut process_info: PROCESS_INFORMATION = mem::zeroed();

                CreateProcessW(
                    None,
                    PWSTR(cmd_line.as_mut_ptr()),
                    None,
                    None,
                    false,
                    EXTENDED_STARTUPINFO_PRESENT,
                    None,
                    None,
                    &startup_info.StartupInfo,
                    &mut process_info,
                )
                .map_err(|e| anyhow!("Failed to create process: {:?}", e))?;

                // Note: We don't delete the attribute list here because we store the buffer
                // The buffer must remain valid while the process is running

                Ok(Self {
                    hpc,
                    process_info,
                    input_write: OwnedHandle::from_raw_handle(input_write.0 as RawHandle),
                    output_read: OwnedHandle::from_raw_handle(output_read.0 as RawHandle),
                    _attr_list_buffer: attr_list_buffer,
                })
            }
        }

        pub fn process_id(&self) -> u32 {
            self.process_info.dwProcessId
        }

        pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            unsafe {
                let mut bytes_read: u32 = 0;
                let handle = HANDLE(self.output_read.as_raw_handle() as isize);

                match ReadFile(handle, Some(buf), Some(&mut bytes_read), None) {
                    Ok(_) => Ok(bytes_read as usize),
                    Err(e) => Err(anyhow!("Failed to read from PTY: {:?}", e)),
                }
            }
        }

        pub fn write(&mut self, data: &[u8]) -> Result<usize> {
            unsafe {
                let mut bytes_written: u32 = 0;
                let handle = HANDLE(self.input_write.as_raw_handle() as isize);

                WriteFile(handle, Some(data), Some(&mut bytes_written), None)
                    .map_err(|e| anyhow!("Failed to write to PTY: {:?}", e))?;

                Ok(bytes_written as usize)
            }
        }

        pub fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
            unsafe {
                let size = COORD {
                    X: cols as i16,
                    Y: rows as i16,
                };
                ResizePseudoConsole(self.hpc, size)
                    .map_err(|e| anyhow!("Failed to resize pseudo console: {:?}", e))?;
            }
            Ok(())
        }

        pub fn get_reader(&self) -> Result<PtyReader> {
            // Clone the handle for the reader
            // Note: On Windows, we can't truly clone a handle without DuplicateHandle
            // For now, we'll create a reader that shares the same handle
            Ok(PtyReader {
                inner: WindowsPtyReader {
                    handle: HANDLE(self.output_read.as_raw_handle() as isize),
                },
            })
        }

        pub fn close(&mut self) -> Result<()> {
            unsafe {
                // Close the pseudo console first
                ClosePseudoConsole(self.hpc);

                // Then close process handles
                let _ = CloseHandle(self.process_info.hProcess);
                let _ = CloseHandle(self.process_info.hThread);
            }
            Ok(())
        }
    }

    pub struct WindowsPtyReader {
        handle: HANDLE,
    }

    impl Read for WindowsPtyReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            unsafe {
                let mut bytes_read: u32 = 0;
                match ReadFile(self.handle, Some(buf), Some(&mut bytes_read), None) {
                    Ok(_) => Ok(bytes_read as usize),
                    Err(e) => Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )),
                }
            }
        }
    }

    // Safety: Windows handles can be sent between threads
    unsafe impl Send for WindowsPty {}
    unsafe impl Sync for WindowsPty {}
    unsafe impl Send for WindowsPtyReader {}
    unsafe impl Sync for WindowsPtyReader {}
}

#[cfg(target_os = "windows")]
use windows_impl::{WindowsPty, WindowsPtyReader};

// =============================================================================
// Unix PTY Implementation
// =============================================================================

#[cfg(not(target_os = "windows"))]
mod unix_impl {
    use super::*;
    use nix::libc::{self, ioctl, TIOCSWINSZ};
    use nix::pty::{openpty, Winsize};
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::{dup2, execvp, fork, setsid, ForkResult, Pid};
    use std::ffi::CString;
    use std::fs::File;
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
    use std::path::Path;

    pub struct UnixPty {
        /// Master PTY file descriptor (raw fd for operations)
        master_fd: RawFd,
        /// Master as a File for I/O (owns the fd)
        master_file: File,
        /// Child process PID
        child: Pid,
    }

    impl UnixPty {
        pub fn new(command: &str, cols: u16, rows: u16) -> Result<Self> {
            let winsize = Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };

            let pty =
                openpty(Some(&winsize), None).map_err(|e| anyhow!("Failed to open PTY: {}", e))?;

            // nix 0.27+ returns OwnedFd - get raw fd before consuming
            let master_raw_fd = pty.master.as_raw_fd();
            let slave_raw_fd = pty.slave.as_raw_fd();

            // Fork and execute the shell in the child
            match unsafe { fork() }.map_err(|e| anyhow!("Failed to fork: {}", e))? {
                ForkResult::Child => {
                    // Child process - drop master side (OwnedFd will close it)
                    drop(pty.master);

                    // Create new session and set controlling terminal
                    setsid().ok();

                    #[cfg(any(target_os = "macos", target_os = "linux"))]
                    unsafe {
                        // A daemon-created PTY needs the slave set as the controlling terminal
                        // so interactive shells enable prompts, line discipline, and echo.
                        let _ = libc::ioctl(slave_raw_fd, libc::TIOCSCTTY as libc::c_ulong, 0);
                    }

                    // Set up slave as stdin/stdout/stderr
                    dup2(slave_raw_fd, 0).ok(); // stdin
                    dup2(slave_raw_fd, 1).ok(); // stdout
                    dup2(slave_raw_fd, 2).ok(); // stderr

                    // Drop slave (OwnedFd will close original fd)
                    drop(pty.slave);

                    // Execute the shell
                    let shell =
                        CString::new(command).map_err(|e| anyhow!("Invalid shell path: {}", e))?;
                    let shell_name = Path::new(command)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or_default();
                    let mut args = vec![shell.clone()];
                    if matches!(shell_name, "sh" | "bash" | "zsh" | "ksh" | "fish") {
                        args.push(CString::new("-i").expect("static interactive shell flag"));
                    }
                    std::env::set_var("TERM", "xterm-256color");
                    std::env::set_var("HOME", default_home_dir());
                    std::env::set_var("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");

                    // This doesn't return on success
                    if let Err(e) = execvp(&shell, &args) {
                        // If exec fails, print error and exit
                        eprintln!("Failed to execute shell: {}", e);
                    }
                    std::process::exit(1);
                }
                ForkResult::Parent { child } => {
                    // Parent process - drop slave side (OwnedFd will close it)
                    drop(pty.slave);

                    // Convert master OwnedFd to a File for I/O
                    // IntoRawFd consumes the OwnedFd without closing
                    let master_raw = pty.master.into_raw_fd();
                    let master_file = unsafe { File::from_raw_fd(master_raw) };

                    Ok(Self {
                        master_fd: master_raw,
                        master_file,
                        child,
                    })
                }
            }
        }

        pub fn child_pid(&self) -> u32 {
            self.child.as_raw() as u32
        }

        pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            use std::io::Read;
            self.master_file
                .read(buf)
                .map_err(|e| anyhow!("Failed to read from PTY: {}", e))
        }

        pub fn write(&mut self, data: &[u8]) -> Result<usize> {
            use std::io::Write;
            self.master_file
                .write(data)
                .map_err(|e| anyhow!("Failed to write to PTY: {}", e))
        }

        pub fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
            let winsize = Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };

            unsafe {
                let ret = ioctl(self.master_fd, TIOCSWINSZ, &winsize);
                if ret < 0 {
                    return Err(anyhow!(
                        "Failed to resize PTY: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            Ok(())
        }

        pub fn get_reader(&self) -> Result<PtyReader> {
            // Duplicate the fd for the reader (nix 0.27+ returns OwnedFd)
            let dup_owned = nix::unistd::dup(self.master_fd)
                .map_err(|e| anyhow!("Failed to duplicate fd: {}", e))?;

            // Convert OwnedFd to raw fd for our reader
            let dup_fd = dup_owned.into_raw_fd();

            Ok(PtyReader {
                inner: UnixPtyReader { fd: dup_fd },
            })
        }

        pub fn close(&mut self) -> Result<()> {
            // Send SIGTERM to child process
            let _ = kill(self.child, Signal::SIGTERM);

            // Wait a short time for graceful shutdown
            std::thread::sleep(std::time::Duration::from_millis(100));

            // Send SIGKILL if still running
            let _ = kill(self.child, Signal::SIGKILL);

            // The master_file will be closed when it's dropped
            Ok(())
        }
    }

    pub struct UnixPtyReader {
        fd: RawFd,
    }

    impl Read for UnixPtyReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            // Use libc::read directly since nix::unistd::read now requires &impl AsFd
            unsafe {
                let ret = libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
                if ret < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(ret as usize)
                }
            }
        }
    }

    impl Drop for UnixPtyReader {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }

    // Safety: The PTY fd can be sent between threads
    unsafe impl Send for UnixPty {}
    unsafe impl Sync for UnixPty {}
    unsafe impl Send for UnixPtyReader {}
    unsafe impl Sync for UnixPtyReader {}

    fn default_home_dir() -> &'static str {
        #[cfg(target_os = "macos")]
        {
            "/var/root"
        }

        #[cfg(not(target_os = "macos"))]
        {
            "/root"
        }
    }
}

#[cfg(not(target_os = "windows"))]
use unix_impl::{UnixPty, UnixPtyReader};

// =============================================================================
// Async Wrapper
// =============================================================================

/// Async wrapper for PTY operations
pub struct AsyncPtyShell {
    shell: PtyShell,
}

impl std::fmt::Debug for AsyncPtyShell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncPtyShell")
            .field("child_pid", &self.shell.child_pid)
            .field("cols", &self.shell.cols)
            .field("rows", &self.shell.rows)
            .field("running", &self.shell.is_running())
            .finish()
    }
}

impl AsyncPtyShell {
    /// Spawn a new async PTY shell.
    pub async fn spawn(command: &str) -> Result<Self> {
        // Spawn in blocking context since it involves system calls
        let command = command.to_string();
        let shell = tokio::task::spawn_blocking(move || PtyShell::spawn(&command))
            .await
            .map_err(|e| anyhow!("Failed to spawn blocking task: {}", e))??;

        Ok(Self { shell })
    }

    /// Spawn with custom size.
    pub async fn spawn_with_size(command: &str, cols: u16, rows: u16) -> Result<Self> {
        let command = command.to_string();
        let shell =
            tokio::task::spawn_blocking(move || PtyShell::spawn_with_size(&command, cols, rows))
                .await
                .map_err(|e| anyhow!("Failed to spawn blocking task: {}", e))??;

        Ok(Self { shell })
    }

    /// Read from the PTY asynchronously.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        // For truly async I/O, we'd need to use tokio's AsyncFd
        // For now, we use a blocking read in a spawn_blocking context
        // This is acceptable because PTY reads are generally fast

        // Get the reader
        let mut reader = self.shell.get_async_reader()?;
        let buf_len = buf.len();

        // Create a buffer to read into (we can't pass buf to spawn_blocking)
        let result = tokio::task::spawn_blocking(move || {
            let mut temp_buf = vec![0u8; buf_len];
            match reader.read(&mut temp_buf) {
                Ok(n) => Ok((n, temp_buf)),
                Err(e) => Err(anyhow!("Read failed: {}", e)),
            }
        })
        .await
        .map_err(|e| anyhow!("Blocking task failed: {}", e))??;

        let (n, temp_buf) = result;
        buf[..n].copy_from_slice(&temp_buf[..n]);
        Ok(n)
    }

    /// Create an independent reader for PTY output.
    ///
    /// The interactive bridge uses this so the blocking output read does not
    /// hold the session lock and starve input writes.
    pub fn get_reader(&self) -> Result<PtyReader> {
        self.shell.get_async_reader()
    }

    /// Write to the PTY asynchronously.
    pub async fn write(&mut self, data: &[u8]) -> Result<usize> {
        self.shell.write(data)
    }

    /// Resize the terminal.
    pub async fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.shell.resize(cols, rows)
    }

    /// Check if running.
    pub fn is_running(&self) -> bool {
        self.shell.is_running()
    }

    /// Get child PID.
    pub fn child_pid(&self) -> u32 {
        self.shell.child_pid
    }

    /// Close the PTY.
    pub async fn close(&mut self) -> Result<()> {
        self.shell.close()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_spawn_shell_unix() {
        let shell = PtyShell::spawn("/bin/sh");
        assert!(shell.is_ok(), "Failed to spawn shell: {:?}", shell.err());

        let mut shell = shell.unwrap();
        assert!(shell.is_running());
        assert!(shell.child_pid > 0);

        // Clean up
        shell.close().expect("Failed to close shell");
        assert!(!shell.is_running());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_spawn_shell_windows() {
        let shell = PtyShell::spawn("cmd.exe");
        assert!(shell.is_ok(), "Failed to spawn shell: {:?}", shell.err());

        let mut shell = shell.unwrap();
        assert!(shell.is_running());
        assert!(shell.child_pid > 0);

        // Clean up
        shell.close().expect("Failed to close shell");
        assert!(!shell.is_running());
    }

    #[test]
    fn test_resize() {
        #[cfg(target_os = "windows")]
        let mut shell = PtyShell::spawn("cmd.exe").expect("Failed to spawn");
        #[cfg(not(target_os = "windows"))]
        let mut shell = PtyShell::spawn("/bin/sh").expect("Failed to spawn");

        assert!(shell.resize(80, 24).is_ok());
        assert_eq!(shell.cols, 80);
        assert_eq!(shell.rows, 24);

        shell.close().ok();
    }

    #[tokio::test]
    async fn test_async_spawn() {
        #[cfg(target_os = "windows")]
        let shell = AsyncPtyShell::spawn("cmd.exe").await;
        #[cfg(not(target_os = "windows"))]
        let shell = AsyncPtyShell::spawn("/bin/sh").await;

        assert!(
            shell.is_ok(),
            "Failed to spawn async shell: {:?}",
            shell.err()
        );

        let mut shell = shell.unwrap();
        assert!(shell.is_running());

        shell.close().await.ok();
    }
}

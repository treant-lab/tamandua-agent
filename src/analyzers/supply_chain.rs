//! Local supply-chain behavior detection.
//!
//! This analyzer tags endpoint events that are strong signals of malicious
//! package-manager or installer behavior before they reach the server-side
//! correlation engine.

use crate::collectors::{Detection, DetectionType, EventPayload, TelemetryEvent};

const TRUSTED_PACKAGE_DOMAINS: &[&str] = &[
    "registry.npmjs.org",
    "npm.pkg.github.com",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "index.crates.io",
    "rubygems.org",
    "proxy.golang.org",
    "sum.golang.org",
    "github.com",
    "raw.githubusercontent.com",
];

const SENSITIVE_PATH_MARKERS: &[&str] = &[
    ".ssh/",
    ".ssh\\",
    "id_rsa",
    "id_ed25519",
    ".aws/credentials",
    ".aws\\credentials",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo\\credentials",
    ".kube/config",
    ".kube\\config",
    ".env",
    "wallet",
    "keypair",
    "solana/id.json",
    "solana\\id.json",
];

const WEB3_PACKAGE_NAMES: &[&str] = &[
    "@solana/web3.js",
    "@coral-xyz/anchor",
    "@metaplex-foundation/js",
    "@phantom/wallet-adapter",
    "solana",
    "anchor",
    "metaplex",
    "phantom",
];

/// Analyze an event for local supply-chain compromise indicators.
pub fn analyze_event(event: &TelemetryEvent) -> Vec<Detection> {
    match &event.payload {
        EventPayload::Process(process) => analyze_process_event(process),
        EventPayload::File(file) => analyze_file_event(file),
        EventPayload::Network(network) => analyze_network_event(network),
        EventPayload::Dns(dns) => analyze_dns_event(dns),
        _ => Vec::new(),
    }
}

fn analyze_process_event(process: &crate::collectors::ProcessEvent) -> Vec<Detection> {
    let name = process.name.to_ascii_lowercase();
    let parent = process
        .parent_name
        .clone()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let cmd = process.cmdline.to_ascii_lowercase();
    let mut detections = Vec::new();

    if is_package_manager(&parent) && is_shell_or_lolbin(&name) && has_suspicious_script_args(&cmd)
    {
        detections.push(supply_chain_detection(
            "SUPPLY_CHAIN_INSTALL_HOOK_SHELL",
            0.86,
            format!(
                "Package manager parent '{}' spawned suspicious child '{}' with command line: {}",
                parent, process.name, process.cmdline
            ),
            vec!["T1195.001", "T1059"],
        ));
    }

    if is_package_manager(&name) && has_suspicious_script_args(&cmd) {
        detections.push(supply_chain_detection(
            "SUPPLY_CHAIN_PACKAGE_MANAGER_ABUSE",
            0.78,
            format!(
                "Package manager '{}' executed suspicious install command: {}",
                process.name, process.cmdline
            ),
            vec!["T1195.001", "T1059"],
        ));
    }

    if is_package_manager(&name) {
        for package_name in extract_candidate_package_names(&cmd) {
            if looks_like_web3_typosquat(&package_name) {
                detections.push(supply_chain_detection(
                    "SUPPLY_CHAIN_WEB3_TYPOSQUAT_PACKAGE",
                    0.82,
                    format!(
                        "Package manager command references a Web3/Solana-like suspicious package name: {}",
                        package_name
                    ),
                    vec!["T1195.001"],
                ));
            }
        }
    }

    detections
}

fn analyze_file_event(file: &crate::collectors::FileEvent) -> Vec<Detection> {
    let process = file.process_name.to_ascii_lowercase();
    let path = normalize_path(&file.path);

    if is_package_manager(&process) && is_sensitive_path(&path) {
        return vec![supply_chain_detection(
            "SUPPLY_CHAIN_PACKAGE_MANAGER_SENSITIVE_FILE_ACCESS",
            0.88,
            format!(
                "Package manager '{}' accessed sensitive file path during install activity: {}",
                file.process_name, file.path
            ),
            vec!["T1195.001", "T1552"],
        )];
    }

    Vec::new()
}

fn analyze_network_event(network: &crate::collectors::NetworkEvent) -> Vec<Detection> {
    let process = network.process_name.to_ascii_lowercase();

    if !is_package_manager(&process) {
        return Vec::new();
    }

    let observed_domain = network
        .domain
        .as_ref()
        .or(network.tls_sni.as_ref())
        .or(network.sni.as_ref());

    if let Some(domain) = observed_domain {
        let domain_lower = domain.to_ascii_lowercase();
        if !is_trusted_package_domain(&domain_lower) {
            return vec![supply_chain_detection(
                "SUPPLY_CHAIN_PACKAGE_MANAGER_UNTRUSTED_NETWORK",
                0.68,
                format!(
                    "Package manager '{}' connected to non-registry domain '{}'",
                    network.process_name, domain
                ),
                vec!["T1195.001", "T1105"],
            )];
        }
    }

    Vec::new()
}

fn analyze_dns_event(dns: &crate::collectors::DnsEvent) -> Vec<Detection> {
    let process = dns.process_name.to_ascii_lowercase();
    let query = dns.query.to_ascii_lowercase();

    if is_package_manager(&process) && !is_trusted_package_domain(&query) {
        return vec![supply_chain_detection(
            "SUPPLY_CHAIN_PACKAGE_MANAGER_UNTRUSTED_DNS",
            0.58,
            format!(
                "Package manager '{}' resolved non-registry domain '{}'",
                dns.process_name, dns.query
            ),
            vec!["T1195.001"],
        )];
    }

    Vec::new()
}

fn supply_chain_detection(
    rule_name: &str,
    confidence: f32,
    description: String,
    techniques: Vec<&str>,
) -> Detection {
    Detection {
        detection_type: DetectionType::SupplyChain,
        rule_name: rule_name.to_string(),
        confidence,
        description,
        mitre_tactics: vec!["Initial Access".to_string(), "Execution".to_string()],
        mitre_techniques: techniques.into_iter().map(str::to_string).collect(),
    }
}

fn is_package_manager(name: &str) -> bool {
    let base = executable_basename(name);
    matches!(
        base.as_str(),
        "npm"
            | "npm.cmd"
            | "npm.exe"
            | "npx"
            | "npx.cmd"
            | "npx.exe"
            | "yarn"
            | "yarn.cmd"
            | "pnpm"
            | "pnpm.cmd"
            | "bun"
            | "pip"
            | "pip.exe"
            | "pip3"
            | "python"
            | "python.exe"
            | "python3"
            | "cargo"
            | "cargo.exe"
            | "gem"
            | "go"
            | "go.exe"
            | "composer"
            | "composer.phar"
            | "msiexec"
            | "msiexec.exe"
            | "winget"
            | "winget.exe"
            | "choco"
            | "choco.exe"
            | "docker"
            | "docker.exe"
    )
}

fn is_shell_or_lolbin(name: &str) -> bool {
    let base = executable_basename(name);
    matches!(
        base.as_str(),
        "sh" | "bash"
            | "zsh"
            | "cmd"
            | "cmd.exe"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "rundll32.exe"
            | "regsvr32.exe"
            | "curl"
            | "curl.exe"
            | "wget"
            | "wget.exe"
            | "certutil.exe"
            | "bitsadmin.exe"
    )
}

fn has_suspicious_script_args(cmd: &str) -> bool {
    let markers = [
        " -enc",
        " encodedcommand",
        "frombase64string",
        "iex ",
        "invoke-expression",
        "invoke-webrequest",
        "iwr ",
        "downloadstring",
        "curl ",
        "wget ",
        "chmod +x",
        "bash -c",
        "sh -c",
        "/tmp/",
        "\\temp\\",
        ".ssh",
        ".aws",
        ".npmrc",
        ".pypirc",
        "solana/id.json",
        "keypair",
        "wallet",
        "webhook",
        "pastebin",
        "ngrok",
        "transfer.sh",
        "web3.storage",
    ];

    markers.iter().any(|marker| cmd.contains(marker))
}

fn extract_candidate_package_names(cmd: &str) -> Vec<String> {
    let mut packages = Vec::new();
    let tokens: Vec<&str> = cmd.split_whitespace().collect();

    for (idx, token) in tokens.iter().enumerate() {
        let t = token.trim_matches(|c: char| c == '"' || c == '\'' || c == ',' || c == ';');
        if matches!(t, "install" | "add" | "i" | "dlx" | "exec") {
            if let Some(next) = tokens.get(idx + 1) {
                let candidate = next
                    .trim_matches(|c: char| c == '"' || c == '\'' || c == ',' || c == ';')
                    .to_ascii_lowercase();
                if !candidate.starts_with('-') && candidate.len() > 2 {
                    packages.push(candidate);
                }
            }
        }
    }

    packages
}

fn looks_like_web3_typosquat(package_name: &str) -> bool {
    let canonical = package_name.trim_start_matches('@');
    // A package that exactly matches a known canonical name is legitimate,
    // not a typosquat. Compare dot-preserving so `web3.js` != `web3js`.
    if WEB3_PACKAGE_NAMES
        .iter()
        .any(|known| canonical.eq_ignore_ascii_case(known.trim_start_matches('@')))
    {
        return false;
    }

    let normalized = package_name
        .trim_start_matches('@')
        .replace(['-', '_', '.', '/', '\\'], "");

    WEB3_PACKAGE_NAMES.iter().any(|known| {
        let known_normalized = known
            .trim_start_matches('@')
            .replace(['-', '_', '.', '/', '\\'], "");
        normalized != known_normalized
            && (normalized.contains(&known_normalized)
                || levenshtein_bounded(&normalized, &known_normalized, 2) <= 2)
    })
}

fn is_sensitive_path(path: &str) -> bool {
    SENSITIVE_PATH_MARKERS
        .iter()
        .any(|marker| path.contains(marker))
}

fn is_trusted_package_domain(domain: &str) -> bool {
    TRUSTED_PACKAGE_DOMAINS
        .iter()
        .any(|trusted| domain == *trusted || domain.ends_with(&format!(".{trusted}")))
}

fn normalize_path(path: &str) -> String {
    path.to_ascii_lowercase().replace('\\', "/")
}

fn executable_basename(name: &str) -> String {
    name.rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase()
}

fn levenshtein_bounded(a: &str, b: &str, max: usize) -> usize {
    if a.len().abs_diff(b.len()) > max {
        return max + 1;
    }

    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0; b.len() + 1];

    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        let mut row_min = curr[0];

        for (j, cb) in b.chars().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
            row_min = row_min.min(curr[j + 1]);
        }

        if row_min > max {
            return max + 1;
        }

        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::{EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent};

    #[test]
    fn detects_package_manager_shell_hook() {
        let event = TelemetryEvent::new(
            EventType::ProcessCreate,
            Severity::Info,
            EventPayload::Process(ProcessEvent {
                pid: 42,
                ppid: 10,
                name: "powershell.exe".to_string(),
                path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
                cmdline: "powershell -enc AAAA".to_string(),
                user: "test".to_string(),
                sha256: vec![],
                entropy: 0.0,
                is_elevated: false,
                parent_name: Some("npm.cmd".to_string()),
                parent_path: None,
                is_signed: true,
                signer: Some("Microsoft".to_string()),
                start_time: 0,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
        );

        let detections = analyze_event(&event);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].rule_name, "SUPPLY_CHAIN_INSTALL_HOOK_SHELL");
    }

    #[test]
    fn detects_web3_typosquat_candidate() {
        assert!(looks_like_web3_typosquat("solanna"));
        assert!(looks_like_web3_typosquat("@solana/web3js"));
        assert!(!looks_like_web3_typosquat("@solana/web3.js"));
    }
}

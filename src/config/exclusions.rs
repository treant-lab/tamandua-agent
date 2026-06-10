//! Exclusions management for the Tamandua EDR agent.
//!
//! This module provides comprehensive exclusion management for files, processes,
//! extensions, and hashes. It supports:
//!
//! - Path exclusions with wildcard support (* and **)
//! - Process exclusions by name, path, or publisher
//! - File extension exclusions with risky extension warnings
//! - SHA256 hash allowlisting with VirusTotal integration
//!
//! Safety features:
//! - Protected system paths cannot be excluded
//! - Broad exclusion warnings (e.g., C:\, /*)
//! - Audit logging for all changes
//! - Optional admin approval workflow
//! - Temporary exclusions with expiry

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use glob::Pattern;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use uuid::Uuid;

/// Type of exclusion
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionType {
    Path,
    Process,
    Extension,
    Hash,
}

impl std::fmt::Display for ExclusionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path => write!(f, "path"),
            Self::Process => write!(f, "process"),
            Self::Extension => write!(f, "extension"),
            Self::Hash => write!(f, "hash"),
        }
    }
}

/// Base exclusion metadata common to all types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionMetadata {
    /// Unique identifier
    pub id: String,
    /// Type of exclusion
    #[serde(rename = "type")]
    pub exclusion_type: ExclusionType,
    /// User who created the exclusion
    pub created_by: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: Option<DateTime<Utc>>,
    /// Reason/note for the exclusion
    pub reason: Option<String>,
    /// Expiration timestamp (optional, for temporary exclusions)
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether the exclusion is currently enabled
    pub enabled: bool,
}

impl ExclusionMetadata {
    pub fn new(exclusion_type: ExclusionType, created_by: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            exclusion_type,
            created_by,
            created_at: Utc::now(),
            updated_at: None,
            reason: None,
            expires_at: None,
            enabled: true,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|e| e < Utc::now()).unwrap_or(false)
    }

    pub fn is_active(&self) -> bool {
        self.enabled && !self.is_expired()
    }
}

/// Path exclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathExclusion {
    #[serde(flatten)]
    pub metadata: ExclusionMetadata,
    /// Path to exclude (supports wildcards if use_wildcards is true)
    pub path: String,
    /// Include all subdirectories
    pub is_recursive: bool,
    /// Interpret path as a glob pattern
    pub use_wildcards: bool,
    /// Compiled glob pattern (not serialized)
    #[serde(skip)]
    compiled_pattern: Option<Pattern>,
}

impl PathExclusion {
    pub fn new(path: String, created_by: String) -> Self {
        Self {
            metadata: ExclusionMetadata::new(ExclusionType::Path, created_by),
            path,
            is_recursive: false,
            use_wildcards: false,
            compiled_pattern: None,
        }
    }

    /// Compile the glob pattern for matching
    pub fn compile(&mut self) -> Result<()> {
        if self.use_wildcards {
            let pattern = if self.is_recursive && !self.path.contains("**") {
                format!(
                    "{}/**",
                    self.path.trim_end_matches('/').trim_end_matches('\\')
                )
            } else {
                self.path.clone()
            };
            self.compiled_pattern = Some(Pattern::new(&pattern)?);
        }
        Ok(())
    }

    /// Check if a path matches this exclusion
    pub fn matches(&self, check_path: &Path) -> bool {
        if !self.metadata.is_active() {
            return false;
        }

        let check_str = check_path.to_string_lossy();
        let exclusion_path = PathBuf::from(&self.path);

        if self.use_wildcards {
            if let Some(ref pattern) = self.compiled_pattern {
                return pattern.matches(&check_str);
            }
        }

        if self.is_recursive {
            // Check if check_path starts with exclusion_path
            check_path.starts_with(&exclusion_path)
        } else {
            // Exact match or direct child
            check_path == exclusion_path || check_path.parent() == Some(&exclusion_path)
        }
    }
}

/// Process exclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExclusion {
    #[serde(flatten)]
    pub metadata: ExclusionMetadata,
    /// Process name (e.g., "myapp.exe")
    pub process_name: Option<String>,
    /// Full path to executable
    pub process_path: Option<String>,
    /// Code signing publisher (must match exactly)
    pub publisher: Option<String>,
    /// Also trust child processes spawned by this process
    pub include_child_processes: bool,
    /// Exclude network activity monitoring for this process
    pub exclude_network_activity: bool,
}

impl ProcessExclusion {
    pub fn new(created_by: String) -> Self {
        Self {
            metadata: ExclusionMetadata::new(ExclusionType::Process, created_by),
            process_name: None,
            process_path: None,
            publisher: None,
            include_child_processes: false,
            exclude_network_activity: false,
        }
    }

    /// Check if a process matches this exclusion
    pub fn matches(&self, name: &str, path: Option<&str>, signer: Option<&str>) -> bool {
        if !self.metadata.is_active() {
            return false;
        }

        // All specified criteria must match
        let name_matches = self
            .process_name
            .as_ref()
            .map_or(true, |n| n.eq_ignore_ascii_case(name));

        let path_matches = match (&self.process_path, path) {
            (Some(excl_path), Some(proc_path)) => excl_path.eq_ignore_ascii_case(proc_path),
            (Some(_), None) => false,
            (None, _) => true,
        };

        let publisher_matches = match (&self.publisher, signer) {
            (Some(excl_pub), Some(proc_signer)) => excl_pub.eq_ignore_ascii_case(proc_signer),
            (Some(_), None) => false,
            (None, _) => true,
        };

        name_matches && path_matches && publisher_matches
    }
}

/// Extension exclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionExclusion {
    #[serde(flatten)]
    pub metadata: ExclusionMetadata,
    /// File extension (with or without leading dot)
    pub extension: String,
    /// Whether this extension is considered risky
    pub is_risky: bool,
}

/// List of risky extensions that commonly contain executable code
pub const RISKY_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".msi",
    ".msp", ".msc", ".lnk", ".pif", ".com", ".gadget", ".jar", ".hta", ".cpl", ".inf", ".reg",
    ".scf",
];

impl ExtensionExclusion {
    pub fn new(extension: String, created_by: String) -> Self {
        let normalized = Self::normalize_extension(&extension);
        let is_risky = RISKY_EXTENSIONS
            .iter()
            .any(|e| e.eq_ignore_ascii_case(&normalized));

        Self {
            metadata: ExclusionMetadata::new(ExclusionType::Extension, created_by),
            extension: normalized,
            is_risky,
        }
    }

    fn normalize_extension(ext: &str) -> String {
        let trimmed = ext.trim().to_lowercase();
        if trimmed.starts_with('.') {
            trimmed
        } else {
            format!(".{}", trimmed)
        }
    }

    /// Check if a file path matches this extension exclusion
    pub fn matches(&self, path: &Path) -> bool {
        if !self.metadata.is_active() {
            return false;
        }

        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{}", e.to_lowercase()) == self.extension)
            .unwrap_or(false)
    }
}

/// Hash exclusion (allowlist)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashExclusion {
    #[serde(flatten)]
    pub metadata: ExclusionMetadata,
    /// SHA256 hash (lowercase hex)
    pub sha256: String,
    /// Optional associated filename for reference
    pub associated_filename: Option<String>,
    /// Whether this hash has been checked against VirusTotal
    pub virustotal_checked: bool,
    /// VirusTotal result if checked
    pub virustotal_result: Option<VirusTotalResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VirusTotalResult {
    Clean,
    Malicious,
    Unknown,
}

impl HashExclusion {
    pub fn new(sha256: String, created_by: String) -> Result<Self> {
        let normalized = sha256.trim().to_lowercase();
        if !Self::validate_sha256(&normalized) {
            return Err(anyhow!(
                "Invalid SHA256 hash: must be 64 hexadecimal characters"
            ));
        }

        Ok(Self {
            metadata: ExclusionMetadata::new(ExclusionType::Hash, created_by),
            sha256: normalized,
            associated_filename: None,
            virustotal_checked: false,
            virustotal_result: None,
        })
    }

    fn validate_sha256(hash: &str) -> bool {
        hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Check if a hash matches this exclusion
    pub fn matches(&self, hash: &str) -> bool {
        if !self.metadata.is_active() {
            return false;
        }

        self.sha256.eq_ignore_ascii_case(hash.trim())
    }
}

/// Audit log entry for exclusion changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionAuditEntry {
    pub id: String,
    pub action: AuditAction,
    pub exclusion_type: ExclusionType,
    pub exclusion_id: String,
    pub user: String,
    pub timestamp: DateTime<Utc>,
    pub details: String,
    pub previous_value: Option<String>,
    pub new_value: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Created,
    Updated,
    Deleted,
    Enabled,
    Disabled,
}

/// Suggested exclusion based on installed software
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedExclusion {
    #[serde(rename = "type")]
    pub exclusion_type: ExclusionType,
    pub value: String,
    pub reason: String,
    pub software: String,
    pub confidence: SuggestionConfidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionConfidence {
    High,
    Medium,
    Low,
}

/// Warning for risky exclusions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskyExclusionWarning {
    pub exclusion_id: String,
    #[serde(rename = "type")]
    pub exclusion_type: ExclusionType,
    pub value: String,
    pub risk_level: RiskLevel,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    High,
    Medium,
    Low,
}

/// Validation result for an exclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ExclusionValidationResult {
    pub fn valid() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.errors.push(error.into());
        self.is_valid = false;
        self
    }

    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }
}

/// Protected system paths that cannot be excluded
pub fn get_protected_paths() -> Vec<&'static str> {
    #[cfg(target_os = "windows")]
    {
        vec![
            r"C:\Windows\System32",
            r"C:\Windows\SysWOW64",
            r"C:\Windows\Boot",
            r"C:\Program Files\Windows Defender",
            r"C:\Windows\WinSxS",
        ]
    }

    #[cfg(target_os = "linux")]
    {
        vec![
            "/boot",
            "/etc/passwd",
            "/etc/shadow",
            "/usr/bin",
            "/usr/sbin",
            "/bin",
            "/sbin",
        ]
    }

    #[cfg(target_os = "macos")]
    {
        vec![
            "/System",
            "/usr/bin",
            "/usr/sbin",
            "/sbin",
            "/Library/Apple",
        ]
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

/// Broad exclusion patterns that are risky
pub fn is_broad_exclusion(path: &str) -> bool {
    let broad_patterns = [
        "C:\\", "C:/", "D:\\", "D:/", "/", "/*", "C:\\*", "**", "*.*", "/home", "/Users",
    ];

    let normalized = path.replace('/', "\\").to_lowercase();
    broad_patterns.iter().any(|p| {
        let pattern = p.replace('/', "\\").to_lowercase();
        normalized == pattern || normalized.trim_end_matches('\\') == pattern.trim_end_matches('\\')
    })
}

/// Check if a path is protected
pub fn is_protected_path(path: &str) -> bool {
    let protected = get_protected_paths();
    let normalized = path.to_lowercase().replace('/', "\\");

    protected.iter().any(|p| {
        let protected_normalized = p.to_lowercase().replace('/', "\\");
        normalized.starts_with(&protected_normalized)
    })
}

/// Exclusions manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionsConfig {
    pub path_exclusions: Vec<PathExclusion>,
    pub process_exclusions: Vec<ProcessExclusion>,
    pub extension_exclusions: Vec<ExtensionExclusion>,
    pub hash_exclusions: Vec<HashExclusion>,
    #[serde(default)]
    pub audit_log: Vec<ExclusionAuditEntry>,
    /// Require admin approval for new exclusions
    #[serde(default)]
    pub require_admin_approval: bool,
}

impl Default for ExclusionsConfig {
    fn default() -> Self {
        Self {
            path_exclusions: Vec::new(),
            process_exclusions: Vec::new(),
            extension_exclusions: Vec::new(),
            hash_exclusions: Vec::new(),
            audit_log: Vec::new(),
            require_admin_approval: false,
        }
    }
}

impl ExclusionsConfig {
    /// Load exclusions from a file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())?;
        let mut config: Self = serde_json::from_str(&content)?;

        // Compile glob patterns
        for exclusion in &mut config.path_exclusions {
            if let Err(e) = exclusion.compile() {
                warn!(path = %exclusion.path, error = %e, "Failed to compile exclusion pattern");
            }
        }

        Ok(config)
    }

    /// Save exclusions to a file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Get the default exclusions file path
    pub fn default_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(r"C:\ProgramData\Tamandua\exclusions.json")
        }

        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/var/lib/tamandua/exclusions.json")
        }

        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/Library/Application Support/Tamandua/exclusions.json")
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            PathBuf::from("./exclusions.json")
        }
    }

    /// Validate a path exclusion before adding
    pub fn validate_path_exclusion(&self, exclusion: &PathExclusion) -> ExclusionValidationResult {
        let mut result = ExclusionValidationResult::valid();

        if exclusion.path.trim().is_empty() {
            return result.with_error("Path cannot be empty");
        }

        if is_protected_path(&exclusion.path) {
            return result.with_error("Cannot exclude protected system paths");
        }

        if is_broad_exclusion(&exclusion.path) {
            result = result.with_warning(
                "This is a very broad exclusion that may significantly reduce security",
            );
        }

        // Check for duplicates
        if self
            .path_exclusions
            .iter()
            .any(|e| e.path == exclusion.path && e.metadata.id != exclusion.metadata.id)
        {
            return result.with_error("This path is already excluded");
        }

        result
    }

    /// Validate a process exclusion before adding
    pub fn validate_process_exclusion(
        &self,
        exclusion: &ProcessExclusion,
    ) -> ExclusionValidationResult {
        let mut result = ExclusionValidationResult::valid();

        if exclusion.process_name.is_none() && exclusion.process_path.is_none() {
            return result.with_error("Either process name or path must be specified");
        }

        // Check for very broad exclusions (no publisher, include children, exclude network)
        if exclusion.publisher.is_none()
            && exclusion.include_child_processes
            && exclusion.exclude_network_activity
        {
            result = result
                .with_warning("This exclusion is very broad - consider adding a publisher filter");
        }

        result
    }

    /// Validate an extension exclusion before adding
    pub fn validate_extension_exclusion(
        &self,
        exclusion: &ExtensionExclusion,
    ) -> ExclusionValidationResult {
        let mut result = ExclusionValidationResult::valid();

        if exclusion.extension.trim().is_empty() {
            return result.with_error("Extension cannot be empty");
        }

        if exclusion.is_risky {
            result = result.with_warning(format!(
                "Extension {} is commonly associated with executable files. Excluding it may allow malware to bypass detection.",
                exclusion.extension
            ));
        }

        // Check for duplicates
        if self.extension_exclusions.iter().any(|e| {
            e.extension.eq_ignore_ascii_case(&exclusion.extension)
                && e.metadata.id != exclusion.metadata.id
        }) {
            return result.with_error("This extension is already excluded");
        }

        result
    }

    /// Validate a hash exclusion before adding
    pub fn validate_hash_exclusion(&self, exclusion: &HashExclusion) -> ExclusionValidationResult {
        let mut result = ExclusionValidationResult::valid();

        if exclusion.sha256.len() != 64 || !exclusion.sha256.chars().all(|c| c.is_ascii_hexdigit())
        {
            return result.with_error("Invalid SHA256 hash - must be 64 hexadecimal characters");
        }

        // Check for duplicates
        if self.hash_exclusions.iter().any(|e| {
            e.sha256.eq_ignore_ascii_case(&exclusion.sha256)
                && e.metadata.id != exclusion.metadata.id
        }) {
            return result.with_error("This hash is already excluded");
        }

        // Warn if VT hasn't been checked
        if !exclusion.virustotal_checked {
            result = result
                .with_warning("Consider checking this hash against VirusTotal before allowing it");
        }

        result
    }

    /// Add an audit log entry
    pub fn add_audit_entry(&mut self, entry: ExclusionAuditEntry) {
        // Keep only the last 1000 entries
        if self.audit_log.len() >= 1000 {
            self.audit_log.remove(0);
        }
        self.audit_log.push(entry);
    }

    /// Create an audit entry for an action
    pub fn create_audit_entry(
        &self,
        action: AuditAction,
        exclusion_type: ExclusionType,
        exclusion_id: &str,
        user: &str,
        details: String,
    ) -> ExclusionAuditEntry {
        ExclusionAuditEntry {
            id: Uuid::new_v4().to_string(),
            action,
            exclusion_type,
            exclusion_id: exclusion_id.to_string(),
            user: user.to_string(),
            timestamp: Utc::now(),
            details,
            previous_value: None,
            new_value: None,
        }
    }

    /// Check if a file path should be excluded
    pub fn is_path_excluded(&self, path: &Path) -> bool {
        self.path_exclusions.iter().any(|e| e.matches(path))
    }

    /// Check if a file extension should be excluded
    pub fn is_extension_excluded(&self, path: &Path) -> bool {
        self.extension_exclusions.iter().any(|e| e.matches(path))
    }

    /// Check if a hash should be excluded (allowed)
    pub fn is_hash_excluded(&self, hash: &str) -> bool {
        self.hash_exclusions.iter().any(|e| e.matches(hash))
    }

    /// Check if a process should be excluded
    pub fn is_process_excluded(
        &self,
        name: &str,
        path: Option<&str>,
        signer: Option<&str>,
    ) -> bool {
        self.process_exclusions
            .iter()
            .any(|e| e.matches(name, path, signer))
    }

    /// Check if a process's network activity should be excluded
    pub fn is_process_network_excluded(
        &self,
        name: &str,
        path: Option<&str>,
        signer: Option<&str>,
    ) -> bool {
        self.process_exclusions
            .iter()
            .any(|e| e.matches(name, path, signer) && e.exclude_network_activity)
    }

    /// Get all risky exclusions
    pub fn get_risky_exclusions(&self) -> Vec<RiskyExclusionWarning> {
        let mut warnings = Vec::new();

        // Check path exclusions
        for excl in &self.path_exclusions {
            if is_broad_exclusion(&excl.path) {
                warnings.push(RiskyExclusionWarning {
                    exclusion_id: excl.metadata.id.clone(),
                    exclusion_type: ExclusionType::Path,
                    value: excl.path.clone(),
                    risk_level: RiskLevel::High,
                    reason: "Very broad path exclusion".to_string(),
                });
            }
        }

        // Check extension exclusions
        for excl in &self.extension_exclusions {
            if excl.is_risky {
                warnings.push(RiskyExclusionWarning {
                    exclusion_id: excl.metadata.id.clone(),
                    exclusion_type: ExclusionType::Extension,
                    value: excl.extension.clone(),
                    risk_level: RiskLevel::High,
                    reason: "Executable file extension excluded".to_string(),
                });
            }
        }

        // Check process exclusions
        for excl in &self.process_exclusions {
            if excl.include_child_processes
                && excl.exclude_network_activity
                && excl.publisher.is_none()
            {
                let name = excl
                    .process_name
                    .clone()
                    .or_else(|| excl.process_path.clone())
                    .unwrap_or_else(|| "Unknown".to_string());
                warnings.push(RiskyExclusionWarning {
                    exclusion_id: excl.metadata.id.clone(),
                    exclusion_type: ExclusionType::Process,
                    value: name,
                    risk_level: RiskLevel::Medium,
                    reason: "Broad process exclusion without publisher verification".to_string(),
                });
            }
        }

        warnings
    }

    /// Clean up expired exclusions
    pub fn cleanup_expired(&mut self) -> usize {
        let initial_count = self.path_exclusions.len()
            + self.process_exclusions.len()
            + self.extension_exclusions.len()
            + self.hash_exclusions.len();

        self.path_exclusions.retain(|e| !e.metadata.is_expired());
        self.process_exclusions.retain(|e| !e.metadata.is_expired());
        self.extension_exclusions
            .retain(|e| !e.metadata.is_expired());
        self.hash_exclusions.retain(|e| !e.metadata.is_expired());

        let final_count = self.path_exclusions.len()
            + self.process_exclusions.len()
            + self.extension_exclusions.len()
            + self.hash_exclusions.len();

        let removed = initial_count - final_count;
        if removed > 0 {
            info!(removed_count = removed, "Cleaned up expired exclusions");
        }

        removed
    }

    /// Export exclusions to JSON
    pub fn export_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Import exclusions from JSON
    pub fn import_json(&mut self, json: &str, user: &str) -> Result<ImportResult> {
        let imported: ExclusionsConfig = serde_json::from_str(json)?;
        let mut result = ImportResult::default();

        // Import path exclusions
        for mut excl in imported.path_exclusions {
            excl.metadata.id = Uuid::new_v4().to_string();
            excl.metadata.created_by = user.to_string();
            excl.metadata.created_at = Utc::now();

            let validation = self.validate_path_exclusion(&excl);
            if validation.is_valid {
                self.path_exclusions.push(excl);
                result.imported += 1;
            } else {
                result.failed += 1;
                result.errors.extend(validation.errors);
            }
        }

        // Import process exclusions
        for mut excl in imported.process_exclusions {
            excl.metadata.id = Uuid::new_v4().to_string();
            excl.metadata.created_by = user.to_string();
            excl.metadata.created_at = Utc::now();

            let validation = self.validate_process_exclusion(&excl);
            if validation.is_valid {
                self.process_exclusions.push(excl);
                result.imported += 1;
            } else {
                result.failed += 1;
                result.errors.extend(validation.errors);
            }
        }

        // Import extension exclusions
        for mut excl in imported.extension_exclusions {
            excl.metadata.id = Uuid::new_v4().to_string();
            excl.metadata.created_by = user.to_string();
            excl.metadata.created_at = Utc::now();

            let validation = self.validate_extension_exclusion(&excl);
            if validation.is_valid {
                self.extension_exclusions.push(excl);
                result.imported += 1;
            } else {
                result.failed += 1;
                result.errors.extend(validation.errors);
            }
        }

        // Import hash exclusions
        for mut excl in imported.hash_exclusions {
            excl.metadata.id = Uuid::new_v4().to_string();
            excl.metadata.created_by = user.to_string();
            excl.metadata.created_at = Utc::now();

            let validation = self.validate_hash_exclusion(&excl);
            if validation.is_valid {
                self.hash_exclusions.push(excl);
                result.imported += 1;
            } else {
                result.failed += 1;
                result.errors.extend(validation.errors);
            }
        }

        // Add audit entry
        let audit = self.create_audit_entry(
            AuditAction::Created,
            ExclusionType::Path, // Generic
            "bulk_import",
            user,
            format!(
                "Bulk import: {} imported, {} failed",
                result.imported, result.failed
            ),
        );
        self.add_audit_entry(audit);

        Ok(result)
    }
}

/// Result of importing exclusions
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    pub success: bool,
    pub imported: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

/// Suggested exclusions for common software
pub fn get_suggested_exclusions() -> Vec<SuggestedExclusion> {
    let mut suggestions = Vec::new();

    // Visual Studio Code
    #[cfg(target_os = "windows")]
    {
        suggestions.push(SuggestedExclusion {
            exclusion_type: ExclusionType::Path,
            value: r"C:\Users\*\AppData\Local\Programs\Microsoft VS Code".to_string(),
            reason: "VS Code installation directory - trusted IDE".to_string(),
            software: "Visual Studio Code".to_string(),
            confidence: SuggestionConfidence::High,
        });

        suggestions.push(SuggestedExclusion {
            exclusion_type: ExclusionType::Process,
            value: "Code.exe".to_string(),
            reason: "VS Code main process - trusted IDE".to_string(),
            software: "Visual Studio Code".to_string(),
            confidence: SuggestionConfidence::High,
        });
    }

    // Node.js
    suggestions.push(SuggestedExclusion {
        exclusion_type: ExclusionType::Extension,
        value: ".node".to_string(),
        reason: "Node.js native module extension".to_string(),
        software: "Node.js".to_string(),
        confidence: SuggestionConfidence::Medium,
    });

    // Git
    suggestions.push(SuggestedExclusion {
        exclusion_type: ExclusionType::Path,
        value: "**/.git/**".to_string(),
        reason: "Git repository metadata".to_string(),
        software: "Git".to_string(),
        confidence: SuggestionConfidence::High,
    });

    // Docker
    #[cfg(target_os = "linux")]
    {
        suggestions.push(SuggestedExclusion {
            exclusion_type: ExclusionType::Path,
            value: "/var/lib/docker".to_string(),
            reason: "Docker data directory - container runtime".to_string(),
            software: "Docker".to_string(),
            confidence: SuggestionConfidence::Medium,
        });
    }

    suggestions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_exclusion_matching() {
        let mut excl =
            PathExclusion::new(r"C:\Program Files\MyApp".to_string(), "test".to_string());
        excl.is_recursive = true;

        assert!(excl.matches(Path::new(r"C:\Program Files\MyApp\app.exe")));
        assert!(excl.matches(Path::new(r"C:\Program Files\MyApp\subdir\file.dll")));
        assert!(!excl.matches(Path::new(r"C:\Program Files\Other\app.exe")));
    }

    #[test]
    fn test_extension_exclusion() {
        let excl = ExtensionExclusion::new("txt".to_string(), "test".to_string());
        assert!(excl.matches(Path::new("file.txt")));
        assert!(!excl.matches(Path::new("file.exe")));
    }

    #[test]
    fn test_risky_extension_detection() {
        let excl = ExtensionExclusion::new("exe".to_string(), "test".to_string());
        assert!(excl.is_risky);

        let safe_excl = ExtensionExclusion::new("txt".to_string(), "test".to_string());
        assert!(!safe_excl.is_risky);
    }

    #[test]
    fn test_hash_validation() {
        let valid_hash = HashExclusion::new(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            "test".to_string(),
        );
        assert!(valid_hash.is_ok());

        let invalid_hash = HashExclusion::new("invalid".to_string(), "test".to_string());
        assert!(invalid_hash.is_err());
    }

    #[test]
    fn test_protected_path_detection() {
        #[cfg(target_os = "windows")]
        {
            assert!(is_protected_path(r"C:\Windows\System32\cmd.exe"));
            assert!(!is_protected_path(r"C:\Users\Test\file.txt"));
        }
    }

    #[test]
    fn test_broad_exclusion_detection() {
        assert!(is_broad_exclusion("C:\\"));
        assert!(is_broad_exclusion("/"));
        assert!(!is_broad_exclusion(r"C:\Program Files\MyApp"));
    }

    #[test]
    fn test_process_exclusion_matching() {
        let mut excl = ProcessExclusion::new("test".to_string());
        excl.process_name = Some("myapp.exe".to_string());
        excl.publisher = Some("My Company".to_string());

        // Matches when both name and publisher match
        assert!(excl.matches("myapp.exe", None, Some("My Company")));

        // Doesn't match when publisher is different
        assert!(!excl.matches("myapp.exe", None, Some("Other Company")));

        // Doesn't match when name is different
        assert!(!excl.matches("otherapp.exe", None, Some("My Company")));
    }
}

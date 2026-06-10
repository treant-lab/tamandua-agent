//! MachO Binary Parser for macOS Injection Detection
//!
//! Provides functionality to parse MachO binaries and detect:
//! - Suspicious load commands (LC_LOAD_DYLIB, LC_INSERT_LIBRARIES)
//! - DYLD environment variables (DYLD_INSERT_LIBRARIES, DYLD_FORCE_FLAT_NAMESPACE)
//! - Code signature validation
//! - Dyld interposing sections
//! - Unusual library load orders

use anyhow::{Context, Result};
use goblin::mach::{load_command::CommandVariant, Mach, MachO};
use std::fs;
use std::path::Path;
use tracing::{debug, warn};

/// Suspicious MachO characteristics
#[derive(Debug, Clone)]
pub struct MachOSuspiciousFeatures {
    /// Suspicious dylibs loaded
    pub suspicious_dylibs: Vec<String>,
    /// DYLD environment variables found
    pub dyld_env_vars: Vec<String>,
    /// Has __interpose section
    pub has_interpose_section: bool,
    /// Has LC_DYLD_ENVIRONMENT load command
    pub has_dyld_environment: bool,
    /// Unsigned or invalid signature
    pub unsigned_or_invalid: bool,
    /// Weak dylib imports (can be exploited)
    pub weak_dylibs: Vec<String>,
    /// rpath load commands (can be exploited for dylib hijacking)
    pub rpath_commands: Vec<String>,
    /// Overall suspicion score (0.0-1.0)
    pub suspicion_score: f32,
}

impl MachOSuspiciousFeatures {
    pub fn new() -> Self {
        Self {
            suspicious_dylibs: Vec::new(),
            dyld_env_vars: Vec::new(),
            has_interpose_section: false,
            has_dyld_environment: false,
            unsigned_or_invalid: false,
            weak_dylibs: Vec::new(),
            rpath_commands: Vec::new(),
            suspicion_score: 0.0,
        }
    }

    /// Calculate overall suspicion score
    pub fn calculate_score(&mut self) {
        let mut score = 0.0;

        // DYLD environment variables are very suspicious
        if self.has_dyld_environment {
            score += 0.4;
        }
        if !self.dyld_env_vars.is_empty() {
            score += 0.3;
        }

        // Interpose sections can be legitimate but suspicious in some contexts
        if self.has_interpose_section {
            score += 0.2;
        }

        // Suspicious dylibs
        score += (self.suspicious_dylibs.len() as f32 * 0.1).min(0.3);

        // Unsigned binaries
        if self.unsigned_or_invalid {
            score += 0.15;
        }

        // Weak dylibs and rpaths
        if !self.weak_dylibs.is_empty() {
            score += 0.1;
        }
        if !self.rpath_commands.is_empty() {
            score += 0.05;
        }

        self.suspicion_score = score.min(1.0);
    }

    /// Check if features are suspicious enough to alert
    pub fn is_suspicious(&self) -> bool {
        self.suspicion_score > 0.5
    }
}

/// MachO parser for injection detection
pub struct MachOParser;

impl MachOParser {
    /// Parse a MachO file and extract suspicious features
    pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<MachOSuspiciousFeatures> {
        let path = path.as_ref();
        let buffer = fs::read(path)
            .with_context(|| format!("Failed to read MachO file: {}", path.display()))?;

        Self::parse_buffer(&buffer, path)
    }

    /// Parse MachO from memory buffer
    pub fn parse_buffer(buffer: &[u8], path: &Path) -> Result<MachOSuspiciousFeatures> {
        let mut features = MachOSuspiciousFeatures::new();

        // Parse the MachO binary
        let mach = match Mach::parse(buffer)? {
            Mach::Binary(macho) => macho,
            Mach::Fat(fat_mach) => {
                // For fat binaries, analyze the first architecture
                // In a real scenario, you might want to check all architectures
                debug!(
                    "Fat MachO binary detected with {} architectures",
                    fat_mach.narches
                );
                if let Some(arch) = fat_mach.iter_arches().next() {
                    let arch = arch?;
                    MachO::parse(&buffer[arch.offset as usize..], 0)?
                } else {
                    return Ok(features);
                }
            }
        };

        // Analyze load commands
        Self::analyze_load_commands(&mach, &mut features)?;

        // Check for interpose sections
        Self::check_interpose_sections(&mach, &mut features);

        // Check code signature
        Self::check_code_signature(path, &mut features);

        // Calculate overall suspicion score
        features.calculate_score();

        Ok(features)
    }

    /// Analyze MachO load commands for suspicious patterns
    fn analyze_load_commands(macho: &MachO, features: &mut MachOSuspiciousFeatures) -> Result<()> {
        // Known suspicious dylib paths
        let suspicious_patterns = [
            "/tmp/",
            "/var/tmp/",
            "/dev/shm/",
            "/private/tmp/",
            "../",
            "~/",
        ];

        for name in &macho.libs {
            debug!("Found dylib: {}", name);

            for pattern in &suspicious_patterns {
                if name.contains(pattern) {
                    warn!("Suspicious dylib path: {}", name);
                    features.suspicious_dylibs.push((*name).to_string());
                    break;
                }
            }
        }

        for path in &macho.rpaths {
            debug!("Found rpath: {}", path);
            features.rpath_commands.push((*path).to_string());

            for pattern in &suspicious_patterns {
                if path.contains(pattern) {
                    warn!("Suspicious rpath: {}", path);
                    features.suspicious_dylibs.push(format!("rpath:{}", path));
                    break;
                }
            }
        }

        for load_cmd in &macho.load_commands {
            match &load_cmd.command {
                CommandVariant::LoadWeakDylib(_) => {
                    features
                        .weak_dylibs
                        .push(format!("weak-dylib-load-command@{}", load_cmd.offset));
                }
                CommandVariant::DyldEnvironment(_) => {
                    // LC_DYLD_ENVIRONMENT is very suspicious
                    features.has_dyld_environment = true;
                    features
                        .dyld_env_vars
                        .push(format!("LC_DYLD_ENVIRONMENT@{}", load_cmd.offset));
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Check for __interpose section (used for function interposing)
    fn check_interpose_sections(macho: &MachO, features: &mut MachOSuspiciousFeatures) {
        for segment in &macho.segments {
            for section_result in segment {
                if let Ok((section, _)) = section_result {
                    // Check for __interpose section in __DATA segment
                    if section.name().unwrap_or("") == "__interpose" {
                        debug!("Found __interpose section");
                        features.has_interpose_section = true;
                    }
                }
            }
        }
    }

    /// Check code signature using codesign tool
    fn check_code_signature(path: &Path, features: &mut MachOSuspiciousFeatures) {
        use std::process::Command;

        let output = match Command::new("codesign")
            .args(["-dvv", path.to_str().unwrap_or("")])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                debug!("Failed to run codesign: {}", e);
                features.unsigned_or_invalid = true;
                return;
            }
        };

        let stderr = String::from_utf8_lossy(&output.stderr);

        // Check if signature is valid
        if !output.status.success() || stderr.contains("not signed") || stderr.contains("invalid") {
            warn!(
                "Binary is unsigned or has invalid signature: {}",
                path.display()
            );
            features.unsigned_or_invalid = true;
        }

        // Check for ad-hoc signatures (not from identified developer)
        if stderr.contains("adhoc") {
            debug!("Binary has ad-hoc signature: {}", path.display());
            // Ad-hoc is slightly suspicious but common in development
        }
    }

    /// Extract all dylib dependencies from a MachO binary
    pub fn get_dylib_dependencies<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
        let path = path.as_ref();
        let buffer = fs::read(path)
            .with_context(|| format!("Failed to read MachO file: {}", path.display()))?;

        let mach = match Mach::parse(&buffer)? {
            Mach::Binary(macho) => macho,
            Mach::Fat(fat_mach) => {
                if let Some(arch) = fat_mach.iter_arches().next() {
                    let arch = arch?;
                    MachO::parse(&buffer[arch.offset as usize..], 0)?
                } else {
                    return Ok(Vec::new());
                }
            }
        };

        Ok(mach.libs.iter().map(|name| (*name).to_string()).collect())
    }

    /// Check if a MachO binary has unusual library load order
    /// (e.g., loading user-controlled libs before system libs)
    pub fn check_load_order<P: AsRef<Path>>(path: P) -> Result<bool> {
        let dylibs = Self::get_dylib_dependencies(path)?;

        let mut seen_user_lib = false;
        let system_lib_prefixes = ["/usr/lib/", "/System/Library/"];

        for dylib in dylibs {
            let is_system_lib = system_lib_prefixes
                .iter()
                .any(|prefix| dylib.starts_with(prefix));

            if !is_system_lib {
                seen_user_lib = true;
            } else if seen_user_lib {
                // System lib loaded after user lib - potentially suspicious
                return Ok(true);
            }
        }

        Ok(false)
    }
}

/// Parse MachO from process memory
pub fn parse_macho_from_memory(
    pid: u32,
    address: u64,
    size: usize,
) -> Result<MachOSuspiciousFeatures> {
    use crate::collectors::memory::macos_memory;

    // Get task port for the process
    let task = macos_memory::get_task_for_pid(pid as i32)
        .map_err(|e| anyhow::anyhow!("Failed to get task for PID {}: {}", pid, e))?;

    // Read memory from the process
    let buffer = macos_memory::read_memory(task, address, size)
        .ok_or_else(|| anyhow::anyhow!("Failed to read memory at 0x{:x}", address))?;

    // Parse the MachO from memory
    MachOParser::parse_buffer(
        &buffer,
        Path::new(&format!("memory:{}:0x{:x}", pid, address)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_features_score() {
        let mut features = MachOSuspiciousFeatures::new();
        features.has_dyld_environment = true;
        features.calculate_score();
        assert!(features.suspicion_score > 0.3);
    }

    #[test]
    fn test_suspicious_features_threshold() {
        let mut features = MachOSuspiciousFeatures::new();
        features.has_dyld_environment = true;
        features
            .dyld_env_vars
            .push("DYLD_INSERT_LIBRARIES".to_string());
        features.calculate_score();
        assert!(features.is_suspicious());
    }
}

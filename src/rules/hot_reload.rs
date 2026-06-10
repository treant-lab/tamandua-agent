//! Hot Reload Support
//!
//! Watch for changes to rule files and reload automatically.

use super::engine::RuleEngine;
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn, error};

/// Hot reload watcher for rule files
pub struct HotReloadWatcher {
    /// Path to watch
    watch_path: PathBuf,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// Debounce duration
    debounce_ms: u64,
}

impl HotReloadWatcher {
    /// Create a new hot reload watcher
    pub fn new<P: AsRef<Path>>(watch_path: P) -> Self {
        Self {
            watch_path: watch_path.as_ref().to_path_buf(),
            shutdown_tx: None,
            debounce_ms: 500,
        }
    }

    /// Set debounce duration in milliseconds
    pub fn with_debounce(mut self, ms: u64) -> Self {
        self.debounce_ms = ms;
        self
    }

    /// Start watching for changes
    pub async fn start(&mut self, engine: Arc<RuleEngine>) -> Result<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        let watch_path = self.watch_path.clone();
        let debounce_ms = self.debounce_ms;

        // Use a simple polling approach for cross-platform compatibility
        tokio::spawn(async move {
            let mut last_check = std::time::Instant::now();
            let mut known_files: std::collections::HashMap<PathBuf, std::time::SystemTime> =
                std::collections::HashMap::new();

            // Initial scan
            if let Ok(files) = scan_rule_files(&watch_path) {
                known_files = files;
            }

            let poll_interval = Duration::from_millis(1000);

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("Hot reload watcher shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(poll_interval) => {
                        // Check for file changes
                        if let Ok(current_files) = scan_rule_files(&watch_path) {
                            let mut changed = false;

                            // Check for new or modified files
                            for (path, mtime) in &current_files {
                                match known_files.get(path) {
                                    None => {
                                        info!(path = %path.display(), "New rule file detected");
                                        changed = true;
                                    }
                                    Some(old_mtime) if mtime != old_mtime => {
                                        info!(path = %path.display(), "Rule file modified");
                                        changed = true;
                                    }
                                    _ => {}
                                }
                            }

                            // Check for deleted files
                            for path in known_files.keys() {
                                if !current_files.contains_key(path) {
                                    info!(path = %path.display(), "Rule file deleted");
                                    changed = true;
                                }
                            }

                            // Debounce: only reload if enough time has passed
                            if changed && last_check.elapsed().as_millis() >= debounce_ms as u128 {
                                info!("Reloading rules due to file changes");
                                match engine.reload_rules().await {
                                    Ok(stats) => {
                                        info!(
                                            total = stats.total_rules,
                                            enabled = stats.enabled_rules,
                                            "Rules hot-reloaded successfully"
                                        );
                                    }
                                    Err(e) => {
                                        error!(error = %e, "Failed to hot-reload rules");
                                    }
                                }
                                last_check = std::time::Instant::now();
                                known_files = current_files;
                            } else if changed {
                                // Update known files even during debounce
                                known_files = current_files;
                            }
                        }
                    }
                }
            }
        });

        info!(path = %self.watch_path.display(), "Hot reload watcher started");
        Ok(())
    }

    /// Stop watching for changes
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }
}

/// Scan directory for rule files and their modification times
fn scan_rule_files(
    dir: &Path,
) -> Result<std::collections::HashMap<PathBuf, std::time::SystemTime>> {
    let mut files = std::collections::HashMap::new();

    if !dir.exists() {
        return Ok(files);
    }

    scan_directory(dir, &mut files)?;
    Ok(files)
}

/// Recursively scan a directory
fn scan_directory(
    dir: &Path,
    files: &mut std::collections::HashMap<PathBuf, std::time::SystemTime>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            scan_directory(&path, files)?;
        } else if is_rule_file(&path) {
            if let Ok(metadata) = std::fs::metadata(&path) {
                if let Ok(modified) = metadata.modified() {
                    files.insert(path, modified);
                }
            }
        }
    }
    Ok(())
}

/// Check if a file is a rule file
fn is_rule_file(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    matches!(ext.to_lowercase().as_str(), "yml" | "yaml" | "json")
}

/// Configuration for hot reload
#[derive(Debug, Clone)]
pub struct HotReloadConfig {
    /// Enable hot reload
    pub enabled: bool,
    /// Poll interval in milliseconds
    pub poll_interval_ms: u64,
    /// Debounce duration in milliseconds
    pub debounce_ms: u64,
    /// Watch subdirectories recursively
    pub recursive: bool,
}

impl Default for HotReloadConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_ms: 1000,
            debounce_ms: 500,
            recursive: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_is_rule_file() {
        assert!(is_rule_file(Path::new("rules.yml")));
        assert!(is_rule_file(Path::new("rules.yaml")));
        assert!(is_rule_file(Path::new("rules.json")));
        assert!(!is_rule_file(Path::new("rules.txt")));
        assert!(!is_rule_file(Path::new("rules.rs")));
    }

    #[test]
    fn test_scan_rule_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create some rule files
        let rule1 = temp_dir.path().join("rules1.yml");
        let rule2 = temp_dir.path().join("rules2.yaml");
        let other = temp_dir.path().join("other.txt");

        std::fs::write(&rule1, "rules: []").unwrap();
        std::fs::write(&rule2, "rules: []").unwrap();
        std::fs::write(&other, "not a rule file").unwrap();

        let files = scan_rule_files(temp_dir.path()).unwrap();

        assert_eq!(files.len(), 2);
        assert!(files.contains_key(&rule1));
        assert!(files.contains_key(&rule2));
        assert!(!files.contains_key(&other));
    }
}

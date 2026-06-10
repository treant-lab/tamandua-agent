//! Vault Statistics Module
//!
//! Provides comprehensive statistics about the quarantine vault:
//! - Total files and size
//! - Oldest and newest entries
//! - Top threat families
//! - Restoration rate
//! - Severity distribution

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::metadata::MetadataDb;
use super::vault::VaultStorage;
use super::ThreatSeverity;

/// Comprehensive vault statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStats {
    /// Total number of files in quarantine
    pub total_files: u64,
    /// Total size of encrypted files in bytes
    pub total_size_bytes: u64,
    /// Total size formatted as human-readable string
    pub total_size_human: String,
    /// Timestamp of oldest quarantined file
    pub oldest_entry: Option<DateTime<Utc>>,
    /// Timestamp of newest quarantined file
    pub newest_entry: Option<DateTime<Utc>>,
    /// Top threat families by count
    pub top_threat_families: Vec<ThreatFamilyStats>,
    /// Severity distribution
    pub severity_distribution: SeverityDistribution,
    /// Restoration statistics
    pub restoration_stats: RestorationStats,
    /// Detection source distribution
    pub detection_sources: HashMap<String, u64>,
    /// Files quarantined per day (last 30 days)
    pub daily_quarantine_counts: Vec<DailyCount>,
    /// Average file size
    pub average_file_size_bytes: u64,
    /// Vault capacity usage percentage
    pub capacity_used_percent: f64,
    /// Number of permanently deleted files
    pub deleted_count: u64,
}

/// Statistics for a threat family
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFamilyStats {
    /// Threat family name
    pub family_name: String,
    /// Number of files in this family
    pub count: u64,
    /// Total size of files in this family
    pub total_size_bytes: u64,
    /// Average severity
    pub average_severity: String,
    /// Most recent quarantine time
    pub most_recent: DateTime<Utc>,
}

/// Severity level distribution
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityDistribution {
    pub low: u64,
    pub medium: u64,
    pub high: u64,
    pub critical: u64,
}

/// Restoration statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RestorationStats {
    /// Total number of restorations
    pub total_restorations: u64,
    /// Number of files restored at least once
    pub files_restored: u64,
    /// Restoration rate (files restored / total files)
    pub restoration_rate_percent: f64,
    /// Files re-quarantined after restoration
    pub requarantined_count: u64,
}

/// Daily quarantine count
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyCount {
    pub date: String,
    pub count: u64,
}

/// Calculate comprehensive vault statistics
pub fn calculate_stats(db: &MetadataDb, vault: &VaultStorage) -> Result<VaultStats> {
    // Get basic counts
    let total_files = db.get_entry_count(false)?;
    let total_size_bytes = vault.get_total_size()?;
    let deleted_count = db.get_entry_count(true)? - total_files;

    // Get time boundaries
    let oldest_entry = db.get_oldest_entry_time()?;
    let newest_entry = db.get_newest_entry_time()?;

    // Get threat family stats
    let family_stats_raw = db.get_threat_family_stats()?;
    let top_threat_families = calculate_family_stats(db, &family_stats_raw)?;

    // Get restoration stats
    let restoration_count = db.get_restoration_count()?;
    let restoration_stats = RestorationStats {
        total_restorations: restoration_count,
        files_restored: count_files_with_restorations(db)?,
        restoration_rate_percent: if total_files > 0 {
            (count_files_with_restorations(db)? as f64 / total_files as f64) * 100.0
        } else {
            0.0
        },
        requarantined_count: 0, // Would need additional tracking
    };

    // Calculate severity distribution
    let severity_distribution = calculate_severity_distribution(db)?;

    // Calculate detection source distribution
    let detection_sources = calculate_detection_sources(db)?;

    // Calculate daily counts
    let daily_quarantine_counts = calculate_daily_counts(db)?;

    // Calculate averages and percentages
    let average_file_size_bytes = if total_files > 0 {
        db.get_total_file_size()? / total_files
    } else {
        0
    };

    // Assume 10GB max capacity for percentage calculation
    let max_capacity = 10 * 1024 * 1024 * 1024u64;
    let capacity_used_percent = (total_size_bytes as f64 / max_capacity as f64) * 100.0;

    Ok(VaultStats {
        total_files,
        total_size_bytes,
        total_size_human: format_size(total_size_bytes),
        oldest_entry,
        newest_entry,
        top_threat_families,
        severity_distribution,
        restoration_stats,
        detection_sources,
        daily_quarantine_counts,
        average_file_size_bytes,
        capacity_used_percent,
        deleted_count,
    })
}

/// Calculate detailed threat family statistics
fn calculate_family_stats(
    db: &MetadataDb,
    family_counts: &[(String, u64)],
) -> Result<Vec<ThreatFamilyStats>> {
    let mut stats = Vec::new();

    for (family_name, count) in family_counts.iter().take(10) {
        // Get entries for this family to calculate additional stats
        let entries = db.list_entries(None, None, false)?;
        let family_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.threat_family.as_deref() == Some(family_name.as_str()))
            .collect();

        let total_size: u64 = family_entries.iter().map(|e| e.file_size).sum();
        let most_recent = family_entries
            .iter()
            .map(|e| e.quarantined_at)
            .max()
            .unwrap_or_else(Utc::now);

        // Calculate average severity
        let severity_sum: u32 = family_entries
            .iter()
            .map(|e| match e.severity {
                ThreatSeverity::Low => 1,
                ThreatSeverity::Medium => 2,
                ThreatSeverity::High => 3,
                ThreatSeverity::Critical => 4,
            })
            .sum();

        let avg_severity = if family_entries.is_empty() {
            "Medium".to_string()
        } else {
            let avg = severity_sum as f64 / family_entries.len() as f64;
            if avg >= 3.5 {
                "Critical".to_string()
            } else if avg >= 2.5 {
                "High".to_string()
            } else if avg >= 1.5 {
                "Medium".to_string()
            } else {
                "Low".to_string()
            }
        };

        stats.push(ThreatFamilyStats {
            family_name: family_name.clone(),
            count: *count,
            total_size_bytes: total_size,
            average_severity: avg_severity,
            most_recent,
        });
    }

    Ok(stats)
}

/// Calculate severity distribution
fn calculate_severity_distribution(db: &MetadataDb) -> Result<SeverityDistribution> {
    let entries = db.list_entries(None, None, false)?;

    let mut dist = SeverityDistribution::default();
    for entry in entries {
        match entry.severity {
            ThreatSeverity::Low => dist.low += 1,
            ThreatSeverity::Medium => dist.medium += 1,
            ThreatSeverity::High => dist.high += 1,
            ThreatSeverity::Critical => dist.critical += 1,
        }
    }

    Ok(dist)
}

/// Calculate detection source distribution
fn calculate_detection_sources(db: &MetadataDb) -> Result<HashMap<String, u64>> {
    let entries = db.list_entries(None, None, false)?;

    let mut sources: HashMap<String, u64> = HashMap::new();
    for entry in entries {
        let source = if entry.detection_source.is_empty() {
            "unknown".to_string()
        } else {
            entry.detection_source
        };
        *sources.entry(source).or_insert(0) += 1;
    }

    Ok(sources)
}

/// Calculate daily quarantine counts for the last 30 days
fn calculate_daily_counts(db: &MetadataDb) -> Result<Vec<DailyCount>> {
    use chrono::Duration;

    let entries = db.list_entries(None, None, false)?;
    let now = Utc::now();

    let mut daily_counts: HashMap<String, u64> = HashMap::new();

    // Initialize last 30 days with 0
    for i in 0..30 {
        let date = (now - Duration::days(i)).format("%Y-%m-%d").to_string();
        daily_counts.insert(date, 0);
    }

    // Count entries
    for entry in entries {
        let date = entry.quarantined_at.format("%Y-%m-%d").to_string();
        if let Some(count) = daily_counts.get_mut(&date) {
            *count += 1;
        }
    }

    // Convert to sorted vector
    let mut counts: Vec<DailyCount> = daily_counts
        .into_iter()
        .map(|(date, count)| DailyCount { date, count })
        .collect();

    counts.sort_by(|a, b| a.date.cmp(&b.date));

    Ok(counts)
}

/// Count files that have been restored at least once
fn count_files_with_restorations(db: &MetadataDb) -> Result<u64> {
    let entries = db.list_entries(None, None, false)?;
    let count = entries
        .iter()
        .filter(|e| !e.restoration_history.is_empty())
        .count() as u64;
    Ok(count)
}

/// Format byte size as human-readable string
pub(crate) fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Generate a summary report of vault statistics
pub fn generate_summary_report(stats: &VaultStats) -> String {
    let mut report = String::new();

    report.push_str("=== Quarantine Vault Statistics ===\n\n");

    report.push_str(&format!("Total Files: {}\n", stats.total_files));
    report.push_str(&format!("Total Size: {}\n", stats.total_size_human));
    report.push_str(&format!(
        "Capacity Used: {:.1}%\n",
        stats.capacity_used_percent
    ));
    report.push_str(&format!(
        "Average File Size: {}\n",
        format_size(stats.average_file_size_bytes)
    ));
    report.push_str(&format!("Deleted Files: {}\n\n", stats.deleted_count));

    if let Some(oldest) = stats.oldest_entry {
        report.push_str(&format!(
            "Oldest Entry: {}\n",
            oldest.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }
    if let Some(newest) = stats.newest_entry {
        report.push_str(&format!(
            "Newest Entry: {}\n",
            newest.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }
    report.push('\n');

    report.push_str("--- Severity Distribution ---\n");
    report.push_str(&format!(
        "Critical: {}\n",
        stats.severity_distribution.critical
    ));
    report.push_str(&format!("High: {}\n", stats.severity_distribution.high));
    report.push_str(&format!("Medium: {}\n", stats.severity_distribution.medium));
    report.push_str(&format!("Low: {}\n\n", stats.severity_distribution.low));

    report.push_str("--- Top Threat Families ---\n");
    for family in &stats.top_threat_families {
        report.push_str(&format!(
            "{}: {} files, {}, avg severity: {}\n",
            family.family_name,
            family.count,
            format_size(family.total_size_bytes),
            family.average_severity
        ));
    }
    report.push('\n');

    report.push_str("--- Restoration Statistics ---\n");
    report.push_str(&format!(
        "Total Restorations: {}\n",
        stats.restoration_stats.total_restorations
    ));
    report.push_str(&format!(
        "Files Restored: {}\n",
        stats.restoration_stats.files_restored
    ));
    report.push_str(&format!(
        "Restoration Rate: {:.1}%\n\n",
        stats.restoration_stats.restoration_rate_percent
    ));

    report.push_str("--- Detection Sources ---\n");
    for (source, count) in &stats.detection_sources {
        report.push_str(&format!("{}: {}\n", source, count));
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(512), "512 bytes");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_size(1024 * 1024 * 1024 * 1024), "1.00 TB");
    }

    #[test]
    fn test_severity_distribution_default() {
        let dist = SeverityDistribution::default();
        assert_eq!(dist.low, 0);
        assert_eq!(dist.medium, 0);
        assert_eq!(dist.high, 0);
        assert_eq!(dist.critical, 0);
    }

    #[test]
    fn test_generate_summary_report() {
        let stats = VaultStats {
            total_files: 100,
            total_size_bytes: 1024 * 1024 * 500,
            total_size_human: "500.00 MB".to_string(),
            oldest_entry: Some(Utc::now()),
            newest_entry: Some(Utc::now()),
            top_threat_families: vec![ThreatFamilyStats {
                family_name: "Emotet".to_string(),
                count: 25,
                total_size_bytes: 1024 * 1024 * 50,
                average_severity: "High".to_string(),
                most_recent: Utc::now(),
            }],
            severity_distribution: SeverityDistribution {
                low: 10,
                medium: 40,
                high: 35,
                critical: 15,
            },
            restoration_stats: RestorationStats {
                total_restorations: 5,
                files_restored: 3,
                restoration_rate_percent: 3.0,
                requarantined_count: 1,
            },
            detection_sources: {
                let mut map = HashMap::new();
                map.insert("ml".to_string(), 60);
                map.insert("yara".to_string(), 40);
                map
            },
            daily_quarantine_counts: Vec::new(),
            average_file_size_bytes: 1024 * 1024 * 5,
            capacity_used_percent: 5.0,
            deleted_count: 10,
        };

        let report = generate_summary_report(&stats);

        assert!(report.contains("Total Files: 100"));
        assert!(report.contains("500.00 MB"));
        assert!(report.contains("Emotet"));
        assert!(report.contains("Critical: 15"));
    }
}

//! Linux-specific collectors
//!
//! This module provides Linux-specific telemetry collection capabilities,
//! primarily focused on auditd integration for ETW-equivalent visibility.

#[cfg(feature = "auditd")]
pub mod auditd_collector;
#[cfg(feature = "auditd")]
pub mod auditd_rules;
#[cfg(feature = "auditd")]
pub mod event_normalizer;

#[cfg(test)]
mod tests;

#[cfg(feature = "auditd")]
pub use auditd_collector::{AuditdCollector, AuditdCollectorConfig};
#[cfg(feature = "auditd")]
pub use auditd_rules::{AuditRuleConfig, AuditRuleGenerator};
#[cfg(feature = "auditd")]
pub use event_normalizer::{AuditRecord, EventNormalizer};

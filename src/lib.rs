//! Tamandua EDR Agent Library
//!
//! This library provides the core functionality for the Tamandua EDR agent,
//! including telemetry collection, analysis, and response capabilities.

pub mod analyzers;
pub mod collectors;
pub mod config;
pub mod detection;
#[cfg(target_os = "windows")]
pub mod driver;
pub mod event_triage;
pub mod health;
pub mod installer;
pub mod integrations;
pub mod ipc;
pub mod live_response;
pub mod memory;
pub mod offline;
pub mod pki;
pub mod protection;
pub mod quarantine;
pub mod resource_governor;
pub mod response;
pub mod scheduler;
pub mod service;
pub mod transport;
pub mod updater;

#[cfg(test)]
pub mod tests {
    pub mod property_tests;
    pub mod transport_property_tests;
}

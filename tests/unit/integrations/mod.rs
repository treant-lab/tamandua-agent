//! Integration tests for Windows security integrations

#[cfg(target_os = "windows")]
pub mod defender_tests;

#[cfg(target_os = "windows")]
pub mod wsc_tests;

#[cfg(target_os = "windows")]
pub mod amsi_provider_tests;

#[cfg(target_os = "linux")]
pub mod clamav_tests;

#[cfg(target_os = "macos")]
pub mod xprotect_tests;

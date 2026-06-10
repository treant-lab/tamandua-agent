//! Application Control Sub-modules
//!
//! This module contains platform-specific application control implementations.

#[cfg(target_os = "linux")]
pub mod apparmor;
#[cfg(target_os = "linux")]
pub mod selinux;

// Re-export for convenience
#[cfg(target_os = "linux")]
pub use apparmor::AppArmorBackend;
#[cfg(target_os = "linux")]
pub use selinux::SELinuxBackend;

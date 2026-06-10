//! Unit tests for Tamandua Agent components
//!
//! This module contains unit tests for all agent subsystems:
//! - Collectors (process, file, network, DNS, registry, etc.)
//! - Response actions (kill, quarantine, isolation, etc.)
//! - Transport layer
//! - Configuration management
//! - Analysis engines (YARA, entropy, etc.)

mod collectors;
mod response;
mod transport;
mod config;
mod analyzers;

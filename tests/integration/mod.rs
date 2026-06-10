//! Integration tests for Tamandua Agent
//!
//! These tests verify the complete agent functionality including:
//! - Server connection and authentication
//! - Telemetry collection and transmission
//! - Command reception and execution
//! - Configuration updates
//!
//! # Running Tests
//!
//! ```bash
//! # Run all integration tests
//! cargo test --test integration
//!
//! # Run with server connection tests (requires running server)
//! TAMANDUA_TEST_SERVER=ws://localhost:4000/socket/agent cargo test --test integration
//! ```

mod server_connection;
mod telemetry;
mod commands;
mod collectors;
mod agent_tests;

// VM-required response action tests (ignored by default, feature-gated)
mod response_actions;

pub use server_connection::*;
pub use telemetry::*;
pub use commands::*;
pub use collectors::*;
pub use agent_tests::*;

/// Test utilities
pub mod util {
    use std::time::Duration;

    /// Default test timeout
    pub const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    /// Create a test agent ID
    pub fn test_agent_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Get test server URL from environment or use default
    pub fn test_server_url() -> String {
        std::env::var("TAMANDUA_TEST_SERVER")
            .unwrap_or_else(|_| "ws://localhost:4000/socket/agent".to_string())
    }

    /// Check if integration tests should run (server available)
    pub fn should_run_server_tests() -> bool {
        std::env::var("TAMANDUA_TEST_SERVER").is_ok()
            || std::env::var("RUN_INTEGRATION_TESTS").is_ok()
    }
}

//! Log forwarding module
//!
//! Handles capturing and forwarding agent logs to the backend server
//! for centralized log aggregation and analysis.

pub mod forwarder;
pub mod buffer;
pub mod parser;

pub use forwarder::LogForwarder;
pub use buffer::LogBuffer;
pub use parser::{LogLevel, StructuredLog};

//! Live Response Module
//!
//! Advanced incident response capabilities including process management,
//! memory analysis, and forensic data collection.

pub mod process_manager;

pub use process_manager::{
    process_kill, process_list_handles, process_resume, process_set_priority, process_suspend,
    process_tree_list,
};

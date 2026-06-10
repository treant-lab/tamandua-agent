//! Structure validation tests for the eBPF uprobe program.
//!
//! These tests validate the source code structure without requiring
//! bpf-linker or eBPF compilation. They ensure the program has the
//! correct macros, functions, and map declarations.

use std::fs;
use std::path::Path;

#[test]
fn test_cargo_toml_has_ebpf_dependencies() {
    let cargo_toml = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
    ).expect("Failed to read Cargo.toml");

    assert!(cargo_toml.contains("aya-ebpf"), "Missing aya-ebpf dependency");
    assert!(cargo_toml.contains("aya-log-ebpf"), "Missing aya-log-ebpf dependency");
    assert!(cargo_toml.contains("tamandua-ebpf-common"), "Missing ebpf-common dependency");
}

#[test]
fn test_main_rs_has_uprobe_attribute() {
    let main_rs = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs")
    ).expect("Failed to read src/main.rs");

    assert!(main_rs.contains("#[uprobe]"), "Missing #[uprobe] attribute");
}

#[test]
fn test_main_rs_has_ssl_write_entry() {
    let main_rs = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs")
    ).expect("Failed to read src/main.rs");

    assert!(main_rs.contains("fn ssl_write_entry"), "Missing ssl_write_entry function");
    assert!(main_rs.contains("pub fn ssl_write_entry") || main_rs.contains("fn ssl_write_entry"),
            "ssl_write_entry should be defined");
}

#[test]
fn test_main_rs_has_ringbuf_map() {
    let main_rs = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs")
    ).expect("Failed to read src/main.rs");

    assert!(main_rs.contains("LLM_EVENTS"), "Missing LLM_EVENTS map");
    assert!(main_rs.contains("RingBuf"), "Missing RingBuf type");
    assert!(main_rs.contains("#[map]"), "Missing #[map] attribute");
}

#[test]
fn test_main_rs_imports_ebpf_common_types() {
    let main_rs = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs")
    ).expect("Failed to read src/main.rs");

    assert!(main_rs.contains("LlmRequestEvent"), "Missing LlmRequestEvent import");
    assert!(main_rs.contains("LLM_DATA_MAX_LEN") || main_rs.contains("tamandua_ebpf_common"),
            "Missing ebpf-common imports");
}

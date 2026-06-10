//! Global Allocator Configuration
//!
//! Configures jemalloc as the global allocator when the feature is enabled.

#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
use tikv_jemallocator::Jemalloc;

#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

/// Check if jemalloc is enabled
pub fn is_jemalloc_enabled() -> bool {
    cfg!(all(feature = "jemalloc", not(target_env = "msvc")))
}

/// Get allocator name
pub fn allocator_name() -> &'static str {
    if is_jemalloc_enabled() {
        "jemalloc"
    } else {
        "system"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocator_detection() {
        let name = allocator_name();
        assert!(name == "jemalloc" || name == "system");
        println!("Using allocator: {}", name);
    }
}

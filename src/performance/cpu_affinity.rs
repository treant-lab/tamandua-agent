//! CPU Affinity Management
//!
//! Pin collectors to specific CPU cores for better cache locality and reduced context switching.
//! Supports Windows (SetThreadAffinityMask) and Linux (sched_setaffinity).

use anyhow::{Context, Result};
use std::collections::HashMap;
use tracing::{debug, info, warn};

#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{GetCurrentThread, SetThreadAffinityMask};

#[cfg(target_os = "linux")]
use nix::sched::{sched_setaffinity, CpuSet};
#[cfg(target_os = "linux")]
use nix::unistd::Pid;

/// Collector types that can be pinned to specific cores
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CollectorType {
    Process,
    Network,
    File,
    Dns,
    Registry,
    Memory,
    Injection,
    Etw,
    Other,
}

impl CollectorType {
    pub fn from_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "process" => CollectorType::Process,
            "network" => CollectorType::Network,
            "file" => CollectorType::File,
            "dns" => CollectorType::Dns,
            "registry" => CollectorType::Registry,
            "memory" => CollectorType::Memory,
            "injection" => CollectorType::Injection,
            "etw" => CollectorType::Etw,
            _ => CollectorType::Other,
        }
    }
}

/// CPU affinity manager
pub struct CpuAffinity {
    mappings: HashMap<CollectorType, Vec<usize>>,
    numa_aware: bool,
}

impl CpuAffinity {
    /// Create a new CPU affinity manager
    pub fn new(numa_aware: bool) -> Self {
        Self {
            mappings: HashMap::new(),
            numa_aware,
        }
    }

    /// Set CPU affinity mapping for a collector
    pub fn set_mapping(&mut self, collector: CollectorType, cores: Vec<usize>) {
        info!(
            "Setting CPU affinity for {:?} to cores {:?}",
            collector, cores
        );
        self.mappings.insert(collector, cores);
    }

    /// Get CPU cores for a collector
    pub fn get_cores(&self, collector: CollectorType) -> Option<&Vec<usize>> {
        self.mappings.get(&collector)
    }

    /// Apply CPU affinity for the current thread
    pub fn apply(&self, collector: CollectorType) -> Result<()> {
        if let Some(cores) = self.get_cores(collector) {
            set_thread_affinity(cores)?;
            debug!(
                "Applied CPU affinity for {:?} to cores {:?}",
                collector, cores
            );
        }
        Ok(())
    }

    /// Detect NUMA topology
    #[cfg(target_os = "linux")]
    pub fn detect_numa_topology() -> Result<Vec<Vec<usize>>> {
        use std::fs;
        use std::path::Path;

        let mut numa_nodes = Vec::new();
        let numa_path = Path::new("/sys/devices/system/node");

        if !numa_path.exists() {
            return Ok(vec![Self::get_all_cores()]);
        }

        for entry in fs::read_dir(numa_path)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if name_str.starts_with("node") && path.is_dir() {
                let cpulist_path = path.join("cpulist");
                if let Ok(cpulist) = fs::read_to_string(cpulist_path) {
                    let cores = Self::parse_cpulist(&cpulist);
                    numa_nodes.push(cores);
                }
            }
        }

        if numa_nodes.is_empty() {
            numa_nodes.push(Self::get_all_cores());
        }

        Ok(numa_nodes)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn detect_numa_topology() -> Result<Vec<Vec<usize>>> {
        // For non-Linux systems, return all cores as a single NUMA node
        Ok(vec![Self::get_all_cores()])
    }

    /// Parse Linux cpulist format (e.g., "0-3,8-11")
    fn parse_cpulist(cpulist: &str) -> Vec<usize> {
        let mut cores = Vec::new();
        for part in cpulist.trim().split(',') {
            if let Some((start, end)) = part.split_once('-') {
                if let (Ok(start), Ok(end)) = (start.parse::<usize>(), end.parse::<usize>()) {
                    cores.extend(start..=end);
                }
            } else if let Ok(core) = part.parse::<usize>() {
                cores.push(core);
            }
        }
        cores
    }

    /// Get all available CPU cores
    fn get_all_cores() -> Vec<usize> {
        let num_cpus = num_cpus::get();
        (0..num_cpus).collect()
    }

    /// Create NUMA-aware default mappings
    pub fn create_numa_aware_mappings() -> Result<HashMap<CollectorType, Vec<usize>>> {
        let numa_nodes = Self::detect_numa_topology()?;
        let mut mappings = HashMap::new();

        info!("Detected {} NUMA node(s)", numa_nodes.len());

        if numa_nodes.is_empty() {
            return Ok(mappings);
        }

        // Assign collectors to NUMA nodes in a round-robin fashion
        let node0 = &numa_nodes[0];

        // Process collector on first core of node 0
        if !node0.is_empty() {
            mappings.insert(CollectorType::Process, vec![node0[0]]);
        }

        // Network collector on second core of node 0
        if node0.len() > 1 {
            mappings.insert(CollectorType::Network, vec![node0[1]]);
        }

        // File collector (CPU-intensive) on multiple cores
        if node0.len() > 3 {
            mappings.insert(CollectorType::File, vec![node0[2], node0[3]]);
        } else if node0.len() > 2 {
            mappings.insert(CollectorType::File, vec![node0[2]]);
        }

        // DNS collector on node 0
        if node0.len() > 4 {
            mappings.insert(CollectorType::Dns, vec![node0[4]]);
        }

        // If multiple NUMA nodes, use second node for registry/memory
        if numa_nodes.len() > 1 {
            let node1 = &numa_nodes[1];
            if !node1.is_empty() {
                mappings.insert(CollectorType::Registry, vec![node1[0]]);
                if node1.len() > 1 {
                    mappings.insert(CollectorType::Memory, vec![node1[1]]);
                }
            }
        } else {
            // Single NUMA node, continue on remaining cores
            if node0.len() > 5 {
                mappings.insert(CollectorType::Registry, vec![node0[5]]);
            }
            if node0.len() > 6 {
                mappings.insert(CollectorType::Memory, vec![node0[6]]);
            }
        }

        Ok(mappings)
    }
}

/// Set thread affinity for the current thread (Windows)
#[cfg(target_os = "windows")]
pub fn set_thread_affinity(cores: &[usize]) -> Result<()> {
    unsafe {
        let thread = GetCurrentThread();
        let mut affinity_mask: usize = 0;

        for &core in cores {
            if core < std::mem::size_of::<usize>() * 8 {
                affinity_mask |= 1 << core;
            } else {
                warn!(
                    "Core {} exceeds maximum supported ({})",
                    core,
                    std::mem::size_of::<usize>() * 8 - 1
                );
            }
        }

        if affinity_mask == 0 {
            anyhow::bail!("Invalid affinity mask");
        }

        SetThreadAffinityMask(thread, affinity_mask);
        debug!("Set thread affinity mask: 0x{:X}", affinity_mask);
    }

    Ok(())
}

/// Set thread affinity for the current thread (Linux)
#[cfg(target_os = "linux")]
pub fn set_thread_affinity(cores: &[usize]) -> Result<()> {
    let mut cpu_set = CpuSet::new();

    for &core in cores {
        cpu_set.set(core).context("Failed to set CPU in CpuSet")?;
    }

    sched_setaffinity(Pid::from_raw(0), &cpu_set).context("Failed to set thread affinity")?;

    debug!("Set thread affinity to cores: {:?}", cores);
    Ok(())
}

/// Set thread affinity for the current thread (macOS - no-op)
#[cfg(target_os = "macos")]
pub fn set_thread_affinity(cores: &[usize]) -> Result<()> {
    warn!(
        "CPU affinity is not supported on macOS, ignoring request for cores {:?}",
        cores
    );
    Ok(())
}

/// Get number of available CPU cores
pub fn get_num_cores() -> usize {
    num_cpus::get()
}

/// Get number of physical CPU cores
pub fn get_num_physical_cores() -> usize {
    num_cpus::get_physical()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_type_from_name() {
        assert_eq!(CollectorType::from_name("process"), CollectorType::Process);
        assert_eq!(CollectorType::from_name("Network"), CollectorType::Network);
        assert_eq!(CollectorType::from_name("FILE"), CollectorType::File);
        assert_eq!(CollectorType::from_name("unknown"), CollectorType::Other);
    }

    #[test]
    fn test_cpu_affinity_manager() {
        let mut affinity = CpuAffinity::new(false);
        affinity.set_mapping(CollectorType::Process, vec![0]);
        affinity.set_mapping(CollectorType::Network, vec![1]);

        assert_eq!(affinity.get_cores(CollectorType::Process), Some(&vec![0]));
        assert_eq!(affinity.get_cores(CollectorType::Network), Some(&vec![1]));
        assert_eq!(affinity.get_cores(CollectorType::File), None);
    }

    #[test]
    fn test_parse_cpulist() {
        let cores = CpuAffinity::parse_cpulist("0-3,8-11");
        assert_eq!(cores, vec![0, 1, 2, 3, 8, 9, 10, 11]);

        let cores = CpuAffinity::parse_cpulist("0,2,4");
        assert_eq!(cores, vec![0, 2, 4]);

        let cores = CpuAffinity::parse_cpulist("0");
        assert_eq!(cores, vec![0]);
    }

    #[test]
    fn test_get_num_cores() {
        let num_cores = get_num_cores();
        assert!(num_cores > 0);

        let num_physical = get_num_physical_cores();
        assert!(num_physical > 0);
        assert!(num_physical <= num_cores);
    }
}

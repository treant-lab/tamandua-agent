//! WMI Event Subscription Persistence for Tamandua EDR Agent
//!
//! Implements a backup persistence mechanism using WMI permanent event subscriptions.
//! This is a legitimate EDR technique used by security products (including CrowdStrike)
//! to ensure the agent remains running even if the primary service fails.
//!
//! The subscription monitors for agent process termination and automatically restarts it.
//!
//! Components created:
//! - EventFilter: Monitors for tamandua-agent.exe process deletion
//! - CommandLineEventConsumer: Restarts the agent when triggered
//! - FilterToConsumerBinding: Links the filter to the consumer
//!
//! MITRE ATT&CK: T1546.003 (Event Triggered Execution: WMI Event Subscription)
//! This is a defensive use of the technique for EDR persistence.

use anyhow::{bail, Context, Result};
use std::path::Path;
use tracing::{debug, info, warn};

/// Unique name for all Tamandua WMI objects
pub const WMI_PERSISTENCE_NAME: &str = "TamanduaAgentRecovery";

/// Event filter name
const FILTER_NAME: &str = "TamanduaAgentRecovery_Filter";

/// Event consumer name
const CONSUMER_NAME: &str = "TamanduaAgentRecovery_Consumer";

/// WMI namespace for permanent subscriptions
const SUBSCRIPTION_NAMESPACE: &str = r"root\subscription";

/// Process name to monitor
const AGENT_PROCESS_NAME: &str = "tamandua-agent.exe";

/// Polling interval for process deletion detection (in seconds)
const POLLING_INTERVAL: u32 = 5;

/// Install WMI persistence for the Tamandua agent.
///
/// Creates a permanent WMI event subscription that monitors for agent process
/// termination and automatically restarts it.
///
/// # Arguments
/// * `agent_path` - Full path to the agent executable
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if WMI objects cannot be created
#[cfg(target_os = "windows")]
pub fn install_wmi_persistence(agent_path: &Path) -> Result<()> {
    use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};

    info!(
        path = %agent_path.display(),
        "Installing WMI persistence mechanism"
    );

    // Validate the agent path exists
    if !agent_path.exists() {
        bail!("Agent executable not found at: {}", agent_path.display());
    }

    let agent_path_str = agent_path.to_string_lossy().to_string();

    unsafe {
        // Initialize COM
        CoInitializeEx(None, COINIT_MULTITHREADED).context("Failed to initialize COM")?;

        let _com_guard = scopeguard::guard((), |_| {
            CoUninitialize();
        });

        // Connect to WMI
        let services = connect_to_wmi(SUBSCRIPTION_NAMESPACE)?;

        // Remove any existing subscription first (clean slate)
        let _ = remove_wmi_objects_internal(&services);

        // Create the Event Filter
        create_event_filter(&services)?;

        // Create the CommandLine Event Consumer
        create_event_consumer(&services, &agent_path_str)?;

        // Create the Filter-to-Consumer Binding
        create_binding(&services)?;

        info!("WMI persistence installed successfully");
    }

    Ok(())
}

/// Remove WMI persistence for the Tamandua agent.
///
/// Removes all WMI objects created by install_wmi_persistence.
///
/// # Returns
/// * `Ok(())` on success (even if objects don't exist)
/// * `Err` if WMI connection fails
#[cfg(target_os = "windows")]
pub fn remove_wmi_persistence() -> Result<()> {
    use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};

    info!("Removing WMI persistence mechanism");

    unsafe {
        // Initialize COM
        CoInitializeEx(None, COINIT_MULTITHREADED).context("Failed to initialize COM")?;

        let _com_guard = scopeguard::guard((), |_| {
            CoUninitialize();
        });

        // Connect to WMI
        let services = connect_to_wmi(SUBSCRIPTION_NAMESPACE)?;

        // Remove all WMI objects
        remove_wmi_objects_internal(&services)?;

        info!("WMI persistence removed successfully");
    }

    Ok(())
}

/// Check if WMI persistence is currently installed.
///
/// # Returns
/// * `Ok(true)` if all WMI objects exist
/// * `Ok(false)` if any object is missing
/// * `Err` if WMI connection fails
#[cfg(target_os = "windows")]
pub fn check_wmi_persistence() -> Result<bool> {
    use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};

    debug!("Checking WMI persistence status");

    unsafe {
        // Initialize COM
        CoInitializeEx(None, COINIT_MULTITHREADED).context("Failed to initialize COM")?;

        let _com_guard = scopeguard::guard((), |_| {
            CoUninitialize();
        });

        // Connect to WMI
        let services = connect_to_wmi(SUBSCRIPTION_NAMESPACE)?;

        // Check for all three components
        let filter_exists = object_exists(&services, "__EventFilter", FILTER_NAME)?;
        let consumer_exists = object_exists(&services, "CommandLineEventConsumer", CONSUMER_NAME)?;
        let binding_exists = binding_exists_internal(&services)?;

        let all_exist = filter_exists && consumer_exists && binding_exists;

        debug!(
            filter = filter_exists,
            consumer = consumer_exists,
            binding = binding_exists,
            complete = all_exist,
            "WMI persistence status"
        );

        Ok(all_exist)
    }
}

/// Connect to a WMI namespace.
#[cfg(target_os = "windows")]
unsafe fn connect_to_wmi(namespace: &str) -> Result<windows::Win32::System::Wmi::IWbemServices> {
    use windows::core::{BSTR, PCWSTR};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoSetProxyBlanket, CLSCTX_INPROC_SERVER, EOAC_NONE,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Rpc::{RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_NONE};
    use windows::Win32::System::Wmi::{IWbemLocator, WbemLocator};

    // Create WMI locator
    let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
        .context("Failed to create WMI locator")?;

    // Connect to namespace
    let namespace_bstr = BSTR::from(namespace);
    let services = locator
        .ConnectServer(
            &namespace_bstr,
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            0,
            &BSTR::new(),
            None,
        )
        .context("Failed to connect to WMI namespace")?;

    // Set security on the proxy
    CoSetProxyBlanket(
        &services,
        RPC_C_AUTHN_DEFAULT as u32,
        RPC_C_AUTHZ_NONE as u32,
        PCWSTR::null(),
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        None,
        EOAC_NONE,
    )
    .context("Failed to set WMI security blanket")?;

    Ok(services)
}

/// Create the WMI Event Filter.
#[cfg(target_os = "windows")]
unsafe fn create_event_filter(services: &windows::Win32::System::Wmi::IWbemServices) -> Result<()> {
    use windows::core::BSTR;
    use windows::Win32::System::Wmi::WBEM_GENERIC_FLAG_TYPE;

    debug!("Creating WMI event filter: {}", FILTER_NAME);

    // Get the __EventFilter class
    let class_name = BSTR::from("__EventFilter");
    let mut class_obj: Option<windows::Win32::System::Wmi::IWbemClassObject> = None;
    services
        .GetObject(
            &class_name,
            WBEM_GENERIC_FLAG_TYPE(0),
            None,
            Some(&mut class_obj),
            None,
        )
        .context("Failed to get __EventFilter class")?;
    let class_obj =
        class_obj.ok_or_else(|| anyhow::anyhow!("GetObject returned None for __EventFilter"))?;

    // Spawn a new instance
    let instance = class_obj
        .SpawnInstance(0)
        .context("Failed to spawn __EventFilter instance")?;

    // Set properties
    set_wmi_property_str(&instance, "Name", FILTER_NAME)?;
    set_wmi_property_str(&instance, "QueryLanguage", "WQL")?;

    // WQL query to detect process termination
    // Uses __InstanceDeletionEvent to monitor for process removal from Win32_Process
    let query = format!(
        "SELECT * FROM __InstanceDeletionEvent WITHIN {} WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = '{}'",
        POLLING_INTERVAL,
        AGENT_PROCESS_NAME
    );
    set_wmi_property_str(&instance, "Query", &query)?;

    // EventNamespace for cross-namespace subscriptions
    set_wmi_property_str(&instance, "EventNamespace", r"root\cimv2")?;

    // Put the instance
    services
        .PutInstance(&instance, WBEM_GENERIC_FLAG_TYPE(0), None, None)
        .context("Failed to create __EventFilter instance")?;

    info!(name = FILTER_NAME, "WMI event filter created");
    Ok(())
}

/// Create the WMI CommandLine Event Consumer.
#[cfg(target_os = "windows")]
unsafe fn create_event_consumer(
    services: &windows::Win32::System::Wmi::IWbemServices,
    agent_path: &str,
) -> Result<()> {
    use windows::core::BSTR;
    use windows::Win32::System::Wmi::WBEM_GENERIC_FLAG_TYPE;

    debug!("Creating WMI event consumer: {}", CONSUMER_NAME);

    // Get the CommandLineEventConsumer class
    let class_name = BSTR::from("CommandLineEventConsumer");
    let mut class_obj: Option<windows::Win32::System::Wmi::IWbemClassObject> = None;
    services
        .GetObject(
            &class_name,
            WBEM_GENERIC_FLAG_TYPE(0),
            None,
            Some(&mut class_obj),
            None,
        )
        .context("Failed to get CommandLineEventConsumer class")?;
    let class_obj = class_obj
        .ok_or_else(|| anyhow::anyhow!("GetObject returned None for CommandLineEventConsumer"))?;

    // Spawn a new instance
    let instance = class_obj
        .SpawnInstance(0)
        .context("Failed to spawn CommandLineEventConsumer instance")?;

    // Set properties
    set_wmi_property_str(&instance, "Name", CONSUMER_NAME)?;

    // Command to restart the agent
    // Use a small delay to ensure the old process is fully gone
    // Then restart the agent in service mode
    let command = format!(
        "cmd.exe /c \"timeout /t 2 /nobreak >nul && \"{}\" service\"",
        agent_path
    );
    set_wmi_property_str(&instance, "CommandLineTemplate", &command)?;

    // Put the instance
    services
        .PutInstance(&instance, WBEM_GENERIC_FLAG_TYPE(0), None, None)
        .context("Failed to create CommandLineEventConsumer instance")?;

    info!(name = CONSUMER_NAME, "WMI event consumer created");
    Ok(())
}

/// Create the Filter-to-Consumer Binding.
#[cfg(target_os = "windows")]
unsafe fn create_binding(services: &windows::Win32::System::Wmi::IWbemServices) -> Result<()> {
    use windows::core::BSTR;
    use windows::Win32::System::Wmi::WBEM_GENERIC_FLAG_TYPE;

    debug!("Creating WMI filter-to-consumer binding");

    // Get the __FilterToConsumerBinding class
    let class_name = BSTR::from("__FilterToConsumerBinding");
    let mut class_obj: Option<windows::Win32::System::Wmi::IWbemClassObject> = None;
    services
        .GetObject(
            &class_name,
            WBEM_GENERIC_FLAG_TYPE(0),
            None,
            Some(&mut class_obj),
            None,
        )
        .context("Failed to get __FilterToConsumerBinding class")?;
    let class_obj = class_obj
        .ok_or_else(|| anyhow::anyhow!("GetObject returned None for __FilterToConsumerBinding"))?;

    // Spawn a new instance
    let instance = class_obj
        .SpawnInstance(0)
        .context("Failed to spawn __FilterToConsumerBinding instance")?;

    // Set Filter reference (path to the filter object)
    let filter_path = format!("__EventFilter.Name=\"{}\"", FILTER_NAME);
    set_wmi_property_str(&instance, "Filter", &filter_path)?;

    // Set Consumer reference (path to the consumer object)
    let consumer_path = format!("CommandLineEventConsumer.Name=\"{}\"", CONSUMER_NAME);
    set_wmi_property_str(&instance, "Consumer", &consumer_path)?;

    // Put the instance
    services
        .PutInstance(&instance, WBEM_GENERIC_FLAG_TYPE(0), None, None)
        .context("Failed to create __FilterToConsumerBinding instance")?;

    info!("WMI filter-to-consumer binding created");
    Ok(())
}

/// Remove all WMI objects created for persistence.
#[cfg(target_os = "windows")]
unsafe fn remove_wmi_objects_internal(
    services: &windows::Win32::System::Wmi::IWbemServices,
) -> Result<()> {
    // Remove binding first (it references the other objects)
    let binding_path = format!(
        "__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"{}\\\"\",Consumer=\"CommandLineEventConsumer.Name=\\\"{}\\\"\"",
        FILTER_NAME, CONSUMER_NAME
    );
    if let Err(e) = delete_wmi_object(services, &binding_path) {
        debug!(error = %e, "Binding removal failed (may not exist)");
    }

    // Remove consumer
    let consumer_path = format!("CommandLineEventConsumer.Name=\"{}\"", CONSUMER_NAME);
    if let Err(e) = delete_wmi_object(services, &consumer_path) {
        debug!(error = %e, "Consumer removal failed (may not exist)");
    }

    // Remove filter
    let filter_path = format!("__EventFilter.Name=\"{}\"", FILTER_NAME);
    if let Err(e) = delete_wmi_object(services, &filter_path) {
        debug!(error = %e, "Filter removal failed (may not exist)");
    }

    Ok(())
}

/// Delete a WMI object by path.
#[cfg(target_os = "windows")]
unsafe fn delete_wmi_object(
    services: &windows::Win32::System::Wmi::IWbemServices,
    object_path: &str,
) -> Result<()> {
    use windows::core::BSTR;
    use windows::Win32::System::Wmi::WBEM_GENERIC_FLAG_TYPE;

    let path_bstr = BSTR::from(object_path);
    services
        .DeleteInstance(&path_bstr, WBEM_GENERIC_FLAG_TYPE(0), None, None)
        .with_context(|| format!("Failed to delete WMI object: {}", object_path))?;
    debug!(path = object_path, "WMI object deleted");
    Ok(())
}

/// Check if a WMI object exists.
#[cfg(target_os = "windows")]
unsafe fn object_exists(
    services: &windows::Win32::System::Wmi::IWbemServices,
    class: &str,
    name: &str,
) -> Result<bool> {
    use windows::core::BSTR;
    use windows::Win32::System::Wmi::WBEM_FLAG_RETURN_IMMEDIATELY;

    let query = format!("SELECT * FROM {} WHERE Name = '{}'", class, name);
    let query_bstr = BSTR::from(query);
    let language_bstr = BSTR::from("WQL");

    let enumerator = services
        .ExecQuery(
            &language_bstr,
            &query_bstr,
            WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )
        .context("Failed to execute WMI query")?;

    // Try to get first result
    let mut objects = [None; 1];
    let mut returned: u32 = 0;

    let hr = enumerator.Next(
        windows::Win32::System::Wmi::WBEM_INFINITE,
        &mut objects,
        &mut returned,
    );

    // S_OK with returned > 0 means object exists
    Ok(hr.is_ok() && returned > 0)
}

/// Check if the binding exists.
#[cfg(target_os = "windows")]
unsafe fn binding_exists_internal(
    services: &windows::Win32::System::Wmi::IWbemServices,
) -> Result<bool> {
    use windows::core::BSTR;
    use windows::Win32::System::Wmi::WBEM_FLAG_RETURN_IMMEDIATELY;

    let query = format!(
        "SELECT * FROM __FilterToConsumerBinding WHERE Filter = \"__EventFilter.Name=\\\"{}\\\"\"",
        FILTER_NAME
    );
    let query_bstr = BSTR::from(query);
    let language_bstr = BSTR::from("WQL");

    let enumerator = match services.ExecQuery(
        &language_bstr,
        &query_bstr,
        WBEM_FLAG_RETURN_IMMEDIATELY,
        None,
    ) {
        Ok(e) => e,
        Err(_) => return Ok(false),
    };

    let mut objects = [None; 1];
    let mut returned: u32 = 0;

    let hr = enumerator.Next(
        windows::Win32::System::Wmi::WBEM_INFINITE,
        &mut objects,
        &mut returned,
    );

    Ok(hr.is_ok() && returned > 0)
}

/// Set a string property on a WMI object.
#[cfg(target_os = "windows")]
unsafe fn set_wmi_property_str(
    obj: &windows::Win32::System::Wmi::IWbemClassObject,
    name: &str,
    value: &str,
) -> Result<()> {
    use windows::core::{BSTR, PCWSTR};
    use windows::Win32::System::Variant::{VARIANT, VT_BSTR};

    let prop_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let value_bstr = BSTR::from(value);

    // Create VARIANT with BSTR
    let mut variant = VARIANT::default();
    // Access Anonymous union properly
    (*variant.Anonymous.Anonymous).vt = VT_BSTR;
    (*variant.Anonymous.Anonymous).Anonymous.bstrVal = std::mem::ManuallyDrop::new(value_bstr);

    obj.Put(PCWSTR(prop_name.as_ptr()), 0, &variant, 0)
        .with_context(|| format!("Failed to set WMI property: {}", name))?;

    Ok(())
}

/// Verify WMI persistence health and optionally repair.
///
/// # Arguments
/// * `agent_path` - Path to agent executable (for repair)
/// * `repair` - If true, reinstall missing components
///
/// # Returns
/// * `Ok(true)` if healthy (or repaired successfully)
/// * `Ok(false)` if unhealthy and repair not requested
/// * `Err` on WMI errors
#[cfg(target_os = "windows")]
pub fn verify_wmi_persistence(agent_path: &Path, repair: bool) -> Result<bool> {
    let is_healthy = check_wmi_persistence()?;

    if is_healthy {
        debug!("WMI persistence is healthy");
        return Ok(true);
    }

    if repair {
        warn!("WMI persistence incomplete, attempting repair");
        install_wmi_persistence(agent_path)?;
        return Ok(true);
    }

    warn!("WMI persistence is incomplete (use --repair to fix)");
    Ok(false)
}

// ============================================================================
// Non-Windows stubs
// ============================================================================

#[cfg(not(target_os = "windows"))]
pub fn install_wmi_persistence(_agent_path: &Path) -> Result<()> {
    info!("WMI persistence is only supported on Windows");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn remove_wmi_persistence() -> Result<()> {
    info!("WMI persistence is only supported on Windows");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn check_wmi_persistence() -> Result<bool> {
    Ok(false)
}

#[cfg(not(target_os = "windows"))]
pub fn verify_wmi_persistence(_agent_path: &Path, _repair: bool) -> Result<bool> {
    Ok(false)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        // Verify constants are properly defined
        assert!(!FILTER_NAME.is_empty());
        assert!(!CONSUMER_NAME.is_empty());
        assert!(POLLING_INTERVAL > 0);
        assert!(POLLING_INTERVAL <= 60); // Reasonable polling interval
    }

    #[test]
    fn test_agent_process_name() {
        // Ensure process name matches expected format
        assert!(AGENT_PROCESS_NAME.ends_with(".exe"));
        assert!(AGENT_PROCESS_NAME.contains("tamandua"));
    }

    #[test]
    fn test_wmi_persistence_name() {
        assert_eq!(WMI_PERSISTENCE_NAME, "TamanduaAgentRecovery");
        assert!(FILTER_NAME.starts_with(WMI_PERSISTENCE_NAME));
        assert!(CONSUMER_NAME.starts_with(WMI_PERSISTENCE_NAME));
    }

    // Integration tests require admin privileges and real WMI access
    // Run manually with: cargo test -- --ignored
    #[test]
    #[ignore]
    fn test_wmi_lifecycle() {
        let test_path = std::path::PathBuf::from(r"C:\Program Files\Tamandua\tamandua-agent.exe");

        // Install
        install_wmi_persistence(&test_path).expect("Install should succeed");

        // Verify
        assert!(
            check_wmi_persistence().expect("Check should succeed"),
            "WMI persistence should be installed"
        );

        // Remove
        remove_wmi_persistence().expect("Remove should succeed");

        // Verify removal
        assert!(
            !check_wmi_persistence().expect("Check should succeed"),
            "WMI persistence should be removed"
        );
    }
}

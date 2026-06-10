//! Example integration showing how collectors use the resource manager.
//!
//! This module demonstrates the full integration pattern for a collector
//! with per-collector resource budgets.

#![allow(dead_code, unused_imports)]

use super::{
    CollectorHandle, CollectorPriority, CollectorRegistration, ResourceManager,
    ResourceManagerConfig,
};
use crate::collectors::{EventPayload, EventType, Severity, TelemetryEvent};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::info;

/// Example collector with resource budget integration.
pub struct ExampleCollector {
    name: String,
    /// Throttle handle from resource manager
    throttle_handle: CollectorHandle,
    /// Event channel for publishing telemetry
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl ExampleCollector {
    /// Create a new collector and register with resource manager.
    pub fn new(
        name: String,
        resource_manager: &ResourceManager,
        event_tx: mpsc::Sender<TelemetryEvent>,
        priority: CollectorPriority,
    ) -> Self {
        // Register with resource manager
        let throttle_handle = resource_manager.register(CollectorRegistration {
            name: name.clone(),
            pid: None, // Use agent's own PID
            priority,
        });

        Self {
            name,
            throttle_handle,
            event_tx,
        }
    }

    /// Main collector loop with resource budget checks.
    pub async fn run(self) {
        info!(collector = %self.name, "Starting collector with resource budgets");

        loop {
            // 1. Check if we should throttle (soft budget exceeded)
            if let Some(delay) = self.throttle_handle.should_throttle() {
                info!(
                    collector = %self.name,
                    delay_ms = delay.as_millis(),
                    "Throttling due to resource budget"
                );
                tokio::time::sleep(delay).await;
            }

            // 2. Check if we're paused (hard budget exceeded)
            if self.throttle_handle.is_paused() {
                info!(
                    collector = %self.name,
                    "Paused due to critical resource overrun - waiting for resume"
                );
                self.throttle_handle.wait_for_resume().await;
                info!(collector = %self.name, "Resumed after pause");
            }

            // 3. Do actual collection work
            self.collect_events().await;

            // 4. Sleep before next iteration
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    /// Simulate event collection.
    async fn collect_events(&self) {
        // Simulate collecting some events
        for i in 0..10 {
            let event = self.create_sample_event(i);

            // Send event
            let _ = self.event_tx.send(event).await;

            // Small delay between events
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Create a sample telemetry event.
    fn create_sample_event(&self, seq: u32) -> TelemetryEvent {
        // This is just a placeholder - real collectors would create actual events
        TelemetryEvent::new(
            EventType::SystemHealth,
            Severity::Info,
            EventPayload::Custom(serde_json::json!({
                "collector": self.name,
                "sequence": seq,
            })),
        )
    }
}

/// Example: Starting collectors with resource manager.
#[cfg(test)]
pub async fn example_integration() {
    // 1. Create resource manager
    let config = ResourceManagerConfig {
        enabled: true,
        monitor_interval_secs: 2,
        ..Default::default()
    };
    let (resource_manager, mut snapshot_rx) = ResourceManager::new(config);
    let resource_manager = Arc::new(resource_manager);

    // 2. Start resource manager monitoring loop
    let manager_handle = {
        let manager = Arc::clone(&resource_manager);
        tokio::spawn(async move {
            manager.run().await;
        })
    };

    // 3. Start health snapshot consumer
    let health_handle = tokio::spawn(async move {
        while let Some(snapshot) = snapshot_rx.recv().await {
            info!(
                collector = %snapshot.collector_name,
                cpu = format!("{:.2}%", snapshot.cpu_percent),
                mem_mb = snapshot.memory_bytes / (1024 * 1024),
                budget_util = format!("{:.1}%", snapshot.budget_utilization_percent),
                throttled = snapshot.is_throttled,
                paused = snapshot.is_paused,
                "Resource usage snapshot"
            );
        }
    });

    // 4. Create event channel
    let (event_tx, mut event_rx) = mpsc::channel(1000);

    // 5. Start collectors with different priorities
    let collectors: Vec<_> = vec![
        ("process", CollectorPriority::Critical),
        ("network", CollectorPriority::High),
        ("file", CollectorPriority::High),
        ("registry", CollectorPriority::Normal),
        ("clipboard", CollectorPriority::Low),
    ]
    .into_iter()
    .map(|(name, priority)| {
        let collector = ExampleCollector::new(
            name.to_string(),
            &resource_manager,
            event_tx.clone(),
            priority,
        );
        tokio::spawn(async move {
            collector.run().await;
        })
    })
    .collect();

    // 6. Process events
    let event_handler = tokio::spawn(async move {
        while let Some(_event) = event_rx.recv().await {
            // Process event (send to backend, analyze, etc.)
        }
    });

    // 7. Run for 30 seconds then shutdown
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Clean shutdown
    manager_handle.abort();
    health_handle.abort();
    event_handler.abort();
    for handle in collectors {
        handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Long-running integration test
    async fn test_integration_example() {
        // Initialize tracing for test output
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .try_init();

        example_integration().await;
    }
}

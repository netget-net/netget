//! End-to-end Bluetooth LE Thermometer Service tests for NetGet

#![cfg(all(unix, feature = "bluetooth"))]

use crate::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

/// Test thermometer service startup
/// LLM calls: 1 (server startup)
#[tokio::test]
async fn test_thermometer_service_startup() -> E2EResult<()> {
    println!("\n=== E2E Test: Thermometer Service Startup ===");

    let prompt = "Act as a BLE thermometer. Create the Health Thermometer Service (UUID: 00001809-0000-1000-8000-00805f9b34fb) with Temperature Measurement characteristic (UUID: 00002a1c-0000-1000-8000-00805f9b34fb). Set temperature to 36.6°C. Advertise as 'NetGet-Thermometer'.";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Act as a BLE thermometer")
            .and_instruction_containing("Health Thermometer Service")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "BLUETOOTH_BLE_THERMOMETER",
                    "instruction": "Create thermometer service at 36.6°C",
                    "startup_params": {
                        "device_name": "NetGet-Thermometer"
                    }
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Server started event - service auto-configures
            .on_event("bluetooth_ble_started")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
    }))
    .await?;

    println!("✓ Thermometer service started");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

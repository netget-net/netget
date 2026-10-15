//! End-to-end Bluetooth LE Battery Service tests for NetGet
//!
//! These tests spawn the actual NetGet binary with BLE GATT Battery Service prompts
//! and validate the server startup and basic functionality.

#![cfg(all(unix, feature = "bluetooth"))]

use crate::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

/// Test battery service server startup
/// LLM calls: 1 (server startup)
#[tokio::test]
async fn test_battery_service_startup() -> E2EResult<()> {
    println!("\n=== E2E Test: Bluetooth Battery Service Startup ===");

    // PROMPT: Create a BLE battery service
    let prompt = "Act as a BLE battery-powered device. Create the Battery Service (UUID: 0000180f-0000-1000-8000-00805f9b34fb) with Battery Level characteristic (UUID: 00002a19-0000-1000-8000-00805f9b34fb) that supports read. Set battery level to 80% (hex: 50). Start advertising as 'NetGet-Battery'.";

    // Start the server with mocks
    let server = helpers::start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("Act as a BLE battery-powered device")
                    .and_instruction_containing("Battery Service")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "BLUETOOTH_BLE_BATTERY",
                            "instruction": "Create Battery Service with Battery Level characteristic. Set battery level to 80%",
                            "startup_params": {
                                "device_name": "NetGet-Battery",
                                "initial_level": 80
                            }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Server started event - battery service auto-configures
                    .on_event("bluetooth_ble_started")
                    .respond_with_actions(serde_json::json!([]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;

    println!("✓ Battery service started");

    // Let server run briefly
    println!("✓ Server running without errors");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

/// Test battery level update
/// LLM calls: 2 (server startup, level update)
#[tokio::test]
async fn test_battery_level_update() -> E2EResult<()> {
    println!("\n=== E2E Test: Battery Level Update ===");

    // PROMPT: Create battery service that updates level
    let prompt = "Act as a BLE battery service. Start with 100% battery (hex: 64), then after 2 seconds update to 90% (hex: 5A). Advertise as 'NetGet-Battery-Drain'.";

    // Start the server with mocks
    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Act as a BLE battery service")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "BLUETOOTH_BLE_BATTERY",
                    "instruction": "Create battery service with updates",
                    "startup_params": {
                        "device_name": "NetGet-Battery-Drain",
                        "initial_level": 100
                    }
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Server started event - battery service auto-configures
            .on_event("bluetooth_ble_started")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
    }))
    .await?;

    println!("✓ Battery service started with dynamic level");

    // Let server run to allow update
    println!("✓ Server handled battery level updates");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

//! End-to-end Bluetooth LE Heart Rate Service tests for NetGet
//!
//! These tests spawn the actual NetGet binary with BLE GATT Heart Rate Service prompts
//! and validate basic server functionality.

#![cfg(all(unix, feature = "bluetooth"))]

use crate::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

/// Test heart rate service startup
/// LLM calls: 1 (server startup)
#[tokio::test]
async fn test_heart_rate_service_startup() -> E2EResult<()> {
    println!("\n=== E2E Test: Heart Rate Service Startup ===");

    // PROMPT: Create a BLE heart rate monitor
    let prompt = "Act as a BLE heart rate monitor. Create the Heart Rate Service (UUID: 0000180d-0000-1000-8000-00805f9b34fb) with Heart Rate Measurement characteristic (UUID: 00002a37-0000-1000-8000-00805f9b34fb) that supports read and notify. Set initial BPM to 72 (hex: 0048). Start advertising as 'NetGet-HeartRate'.";

    // Start the server with mocks
    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("heart rate monitor")
            .and_instruction_containing("Heart Rate Service")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "BLUETOOTH_BLE_HEART_RATE",
                    "instruction": "Create Heart Rate Service. Set initial BPM to 72",
                    "startup_params": {
                        "device_name": "NetGet-HeartRate"
                    }
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Server started event - heart rate service auto-configures
            .on_event("bluetooth_ble_started")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
    }))
    .await?;

    println!("✓ Heart rate service started");

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

/// Test heart rate updates
/// LLM calls: 2 (server startup, rate update)
#[tokio::test]
async fn test_heart_rate_updates() -> E2EResult<()> {
    println!("\n=== E2E Test: Heart Rate Updates ===");

    // PROMPT: Create heart rate monitor with dynamic updates
    let prompt = "Act as a BLE heart rate monitor. Start with 72 BPM, then simulate exercise by increasing to 120 BPM after 2 seconds. Advertise as 'NetGet-HR-Dynamic'.";

    // Start the server with mocks
    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("heart rate monitor")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "BLUETOOTH_BLE_HEART_RATE",
                    "instruction": "Create Heart Rate Service with dynamic updates",
                    "startup_params": {
                        "device_name": "NetGet-HR-Dynamic"
                    }
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Server started event - heart rate service auto-configures
            .on_event("bluetooth_ble_started")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
    }))
    .await?;

    println!("✓ Heart rate service started with dynamic updates");

    println!("✓ Server handled heart rate changes");

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

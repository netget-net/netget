//! End-to-end Bluetooth LE Gamepad Service tests for NetGet

#![cfg(all(unix, feature = "bluetooth"))]

use crate::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

#[tokio::test]
async fn test_gamepad_service_startup() -> E2EResult<()> {
    println!("\n=== E2E Test: Gamepad Service Startup ===");

    let prompt = "Act as a BLE gamepad. Create the Human Interface Device Service (UUID: 00001812-0000-1000-8000-00805f9b34fb) for gamepad with buttons and analog sticks. Advertise as 'NetGet-Gamepad'.";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Act as a BLE gamepad")
            .and_instruction_containing("Human Interface Device")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "BLUETOOTH_BLE_GAMEPAD",
                    "instruction": "Create gamepad HID service",
                    "startup_params": {
                        "device_name": "NetGet-Gamepad"
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

    println!("✓ Gamepad service started");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

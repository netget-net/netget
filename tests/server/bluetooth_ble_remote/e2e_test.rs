//! End-to-end Bluetooth LE Remote Control Service tests for NetGet

#![cfg(all(unix, feature = "bluetooth"))]

use crate::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_remote_service_startup() -> E2EResult<()> {
    println!("\n=== E2E Test: Remote Control Service Startup ===");

    let prompt = "Act as a BLE remote control. Create HID service for media controls (play, pause, volume, track navigation). Advertise as 'NetGet-Remote'.";

    let server = timeout(
        Duration::from_secs(30),
        helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("Act as a BLE remote")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "BLUETOOTH_BLE_REMOTE",
                        "instruction": "Create remote control HID service",
                        "startup_params": {
                            "device_name": "NetGet-Remote"
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
        })),
    )
    .await
    .map_err(|_| "Server startup timeout")??;

    println!("✓ Remote control service started");

    // Wait for the exchange the mocks describe, rather than trusting a fixed sleep to have
    // covered it. Under load the last event routinely lands after the sleep expires, and the
    // test reports it as never having happened. The other four BLE HID suites already do
    // this; this one was left behind.
    server.wait_for_mocks(30).await;

    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;
    timeout(Duration::from_secs(30), server.stop())
        .await
        .map_err(|_| "Server stop timeout")??;
    println!("=== Test passed ===\n");
    Ok(())
}

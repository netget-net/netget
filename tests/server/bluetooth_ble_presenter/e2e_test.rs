//! End-to-end Bluetooth LE Presenter Service tests for NetGet

#![cfg(all(unix, feature = "bluetooth"))]

use crate::helpers::{self, E2EResult, NetGetConfig};

#[tokio::test]
async fn test_presenter_service_startup() -> E2EResult<()> {
    println!("\n=== E2E Test: Presenter Service Startup ===");

    let prompt = "Act as a BLE presentation remote. Create HID service for presenter controls (next slide, previous slide, laser pointer). Advertise as 'NetGet-Presenter'.";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("BLE presentation remote")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "BLUETOOTH_BLE_PRESENTER",
                    "instruction": "Create presenter HID service",
                    "startup_params": {
                        "device_name": "NetGet-Presenter"
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

    println!("✓ Presenter service started");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // a fixed sleep expires, and the test then reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

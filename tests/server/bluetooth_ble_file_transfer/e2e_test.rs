//! End-to-end Bluetooth LE File Transfer Service tests for NetGet

#![cfg(all(unix, feature = "bluetooth"))]

use crate::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

#[tokio::test]
async fn test_file_transfer_service_startup() -> E2EResult<()> {
    println!("\n=== E2E Test: File Transfer Service Startup ===");

    let prompt = "Act as a BLE file transfer service. Create a custom service for file transfer with characteristics for file name, size, data chunks, and control. Advertise as 'NetGet-FileTransfer'.";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Act as a BLE file transfer")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "BLUETOOTH_BLE_FILE_TRANSFER",
                    "instruction": "Create file transfer service",
                    "startup_params": {
                        "device_name": "NetGet-FileTransfer"
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

    println!("✓ File transfer service started");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

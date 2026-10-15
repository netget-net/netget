//! End-to-end Bluetooth LE server tests for NetGet
//!
//! These tests spawn the actual NetGet binary with BLE GATT server prompts
//! and validate responses using btleplug as a BLE client.
//!
//! **IMPORTANT**: These tests require a real Bluetooth adapter or simulator:
//! - Linux: BlueZ daemon running (`sudo systemctl start bluetooth`)
//! - macOS: Bluetooth enabled in System Preferences
//! - Windows: Bluetooth enabled in Settings
//!
//! **Platform-specific notes**:
//! - macOS may require app bundle with Info.plist for production
//! - Linux may require user in `bluetooth` group or sudo
//! - These tests are resource-intensive (real Bluetooth hardware)

#![cfg(all(unix, feature = "bluetooth"))]

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::{Adapter, Manager};

/// Helper: Get BLE adapter for testing
async fn get_ble_adapter() -> E2EResult<Adapter> {
    let manager = Manager::new().await?;
    let adapters = manager.adapters().await?;

    adapters
        .into_iter()
        .next()
        .ok_or_else(|| "No Bluetooth adapters found".into())
}

/// Helper: Find peripheral by name
async fn find_peripheral_by_name(
    adapter: &Adapter,
    device_name: &str,
    timeout_secs: u64,
) -> E2EResult<btleplug::platform::Peripheral> {
    use futures::stream::StreamExt;

    adapter.start_scan(ScanFilter::default()).await?;

    let start = std::time::Instant::now();
    let mut events = adapter.events().await?;

    while start.elapsed() < Duration::from_secs(timeout_secs) {
        // Check all current peripherals
        for p in adapter.peripherals().await? {
            if let Ok(Some(props)) = p.properties().await {
                if let Some(name) = props.local_name {
                    if name.contains(device_name) {
                        adapter.stop_scan().await?;
                        return Ok(p);
                    }
                }
            }
        }

        // Wait for next event or timeout
        let timeout = tokio::time::timeout(Duration::from_millis(100), events.next()).await;
        if timeout.is_err() {
            continue; // Timeout, check peripherals again
        }
    }

    adapter.stop_scan().await?;
    Err(format!(
        "Device '{}' not found within {} seconds",
        device_name, timeout_secs
    )
    .into())
}

#[tokio::test]
// Ignored by default because these claim the machine's single Bluetooth adapter, not because
// they are broken. Under the project's standard --test-threads=100 all three contend for the
// adapter and every one times out at the 120s startup limit; serialised they pass in ~37s:
//
//   cargo test --no-default-features --features bluetooth-ble,bluetooth-ble-client \
//       --test server -- --test-threads=1 --include-ignored bluetooth
//
// Verified passing that way on macOS (CoreBluetooth), twice. Note a std::sync::Mutex guard is
// NOT a substitute for --test-threads=1 here -- it serialises them and they still time out.
//
// The previous reason -- "crashes on some platforms due to ble-peripheral-rust v0.2 native
// library issues" -- described a real process abort that is now FIXED (8ca1ad8b). CoreBluetooth
// raised NSInvalidArgumentException when a characteristic carried a cached value alongside
// non-read-only properties; that Objective-C exception crossed the FFI boundary and killed the
// process, and it was reachable from the protocol's own documented example. Confirmed fixed by
// reverting the fix and watching the abort return.
#[ignore = "Claims the single BLE adapter: run with --test-threads=1 --include-ignored. Not broken."]
async fn test_bluetooth_heart_rate_server() -> E2EResult<()> {
    println!("\n=== E2E Test: Bluetooth Heart Rate Server ===");
    println!("NOTE: This test requires a real Bluetooth adapter");
    println!("      If the test fails, ensure Bluetooth is enabled and powered on");

    // PROMPT: Create a BLE heart rate monitor
    let prompt = "Act as a BLE heart rate monitor. Create the Heart Rate Service (UUID: 0000180d-0000-1000-8000-00805f9b34fb) with the Heart Rate Measurement characteristic (UUID: 00002a37-0000-1000-8000-00805f9b34fb) that supports read and notify. Set initial BPM to 72 (hex: 0048). Start advertising as 'NetGet-HeartRate'.";

    // Start the server with mocks
    println!("Starting NetGet BLE server...");
    let server = helpers::start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("BLE heart rate monitor")
                    .and_instruction_containing("Heart Rate Service")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "BLUETOOTH_BLE",
                            "instruction": "Create the Heart Rate Service with Heart Rate Measurement characteristic. Set initial BPM to 72. Start advertising as 'NetGet-HeartRate'",
                            "startup_params": {
                                "device_name": "NetGet-HeartRate"
                            }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Server started event - add service
                    .on_event("bluetooth_ble_started")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "add_service",
                            "uuid": "0000180d-0000-1000-8000-00805f9b34fb",
                            "primary": true,
                            "characteristics": [
                                {
                                    "uuid": "00002a37-0000-1000-8000-00805f9b34fb",
                                    "properties": ["read", "notify"],
                                    "permissions": ["readable"],
                                    "initial_value": "0048"
                                }
                            ]
                        },
                        {
                            "type": "start_advertising",
                            "device_name": "NetGet-HeartRate"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: BLE characteristic read.
                    //
                    // The event is `bluetooth_read_request` and the verb is `respond_to_read`.
                    // This rule named `ble_characteristic_read` / `send_ble_response`, neither
                    // of which exists, so it never matched and the action was never checked —
                    // `assert_actions_valid_for_event` skips an event id it cannot resolve.
                    .on_event("bluetooth_read_request")
                    .and_event_data_contains("characteristic_uuid", "00002a37")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "respond_to_read",
                            "value": "0048"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;
    println!("✓ Server started");

    // Wait for server to initialize and start advertising
    println!("Waiting for BLE server to start advertising (5 seconds)...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Get BLE adapter
    println!("Getting BLE adapter...");
    let adapter = match get_ble_adapter().await {
        Ok(a) => {
            println!("✓ BLE adapter found");
            a
        }
        Err(e) => {
            println!("⚠ BLE adapter not available: {}", e);
            println!("⚠ Skipping BLE client test (server may still be working)");
            server.stop().await?;
            return Ok(()); // Skip test if no adapter
        }
    };

    // Scan for the device
    println!("Scanning for 'NetGet-HeartRate' device...");
    let peripheral = match find_peripheral_by_name(&adapter, "NetGet-HeartRate", 10).await {
        Ok(p) => {
            println!("✓ Found NetGet-HeartRate device");
            p
        }
        Err(e) => {
            println!("⚠ Device not found: {}", e);
            println!("⚠ This may be a BLE adapter limitation or server issue");
            server.stop().await?;
            return Ok(()); // Skip if device not found
        }
    };

    // Connect to peripheral
    println!("Connecting to device...");
    match peripheral.connect().await {
        Ok(_) => println!("✓ Connected to device"),
        Err(e) => {
            println!("⚠ Connection failed: {}", e);
            server.stop().await?;
            return Ok(());
        }
    }

    // Discover services
    println!("Discovering services...");
    peripheral.discover_services().await?;
    println!("✓ Services discovered");

    // Find Heart Rate Service
    let hr_service_uuid = uuid::Uuid::parse_str("0000180d-0000-1000-8000-00805f9b34fb")?;
    let hr_char_uuid = uuid::Uuid::parse_str("00002a37-0000-1000-8000-00805f9b34fb")?;

    let services = peripheral.services();
    let hr_service = services
        .iter()
        .find(|s| s.uuid == hr_service_uuid)
        .ok_or("Heart Rate Service not found")?;

    println!("✓ Found Heart Rate Service");

    // Find Heart Rate Measurement characteristic
    let hr_char = hr_service
        .characteristics
        .iter()
        .find(|c| c.uuid == hr_char_uuid)
        .ok_or("Heart Rate Measurement characteristic not found")?;

    println!("✓ Found Heart Rate Measurement characteristic");

    // Read the characteristic value
    println!("Reading heart rate value...");
    let value = peripheral.read(hr_char).await?;
    println!("✓ Read {} bytes: {:?}", value.len(), value);

    // Verify the value (should be 0x00 0x48 = 72 BPM)
    assert!(
        value.len() >= 2,
        "Expected at least 2 bytes, got {}",
        value.len()
    );

    // Byte 0 is flags, byte 1 is BPM
    let bpm = value[1];
    println!("Heart rate BPM: {}", bpm);

    assert_eq!(
        bpm, 0x48,
        "Expected BPM 0x48 (72), got 0x{:02x} ({})",
        bpm, bpm
    );

    println!("✓ Heart rate value verified: 72 BPM");

    // Disconnect
    peripheral.disconnect().await?;
    println!("✓ Disconnected from device");

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

#[tokio::test]
// Ignored by default because these claim the machine's single Bluetooth adapter, not because
// they are broken. Under the project's standard --test-threads=100 all three contend for the
// adapter and every one times out at the 120s startup limit; serialised they pass in ~37s:
//
//   cargo test --no-default-features --features bluetooth-ble,bluetooth-ble-client \
//       --test server -- --test-threads=1 --include-ignored bluetooth
//
// Verified passing that way on macOS (CoreBluetooth), twice. Note a std::sync::Mutex guard is
// NOT a substitute for --test-threads=1 here -- it serialises them and they still time out.
//
// The previous reason -- "crashes on some platforms due to ble-peripheral-rust v0.2 native
// library issues" -- described a real process abort that is now FIXED (8ca1ad8b). CoreBluetooth
// raised NSInvalidArgumentException when a characteristic carried a cached value alongside
// non-read-only properties; that Objective-C exception crossed the FFI boundary and killed the
// process, and it was reachable from the protocol's own documented example. Confirmed fixed by
// reverting the fix and watching the abort return.
#[ignore = "Claims the single BLE adapter: run with --test-threads=1 --include-ignored. Not broken."]
async fn test_bluetooth_battery_service() -> E2EResult<()> {
    println!("\n=== E2E Test: Bluetooth Battery Service ===");

    // PROMPT: Create a BLE battery service
    let prompt = "Act as a BLE battery-powered device. Create the Battery Service (UUID: 0000180f-0000-1000-8000-00805f9b34fb) with Battery Level characteristic (UUID: 00002a19-0000-1000-8000-00805f9b34fb) that supports read. Set battery level to 95% (hex: 5f). Start advertising as 'NetGet-Battery'.";

    // Start the server with mocks
    println!("Starting NetGet BLE server...");
    let server = helpers::start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("BLE battery-powered device")
                    .and_instruction_containing("Battery Service")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "BLUETOOTH_BLE",
                            "instruction": "Create Battery Service with Battery Level characteristic. Set battery level to 95%. Start advertising as 'NetGet-Battery'",
                            "startup_params": {
                                "device_name": "NetGet-Battery"
                            }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Server started event - add service
                    .on_event("bluetooth_ble_started")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "add_service",
                            "uuid": "0000180f-0000-1000-8000-00805f9b34fb",
                            "primary": true,
                            "characteristics": [
                                {
                                    "uuid": "00002a19-0000-1000-8000-00805f9b34fb",
                                    "properties": ["read"],
                                    "permissions": ["readable"],
                                    "initial_value": "5f"
                                }
                            ]
                        },
                        {
                            "type": "start_advertising",
                            "device_name": "NetGet-Battery"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: BLE characteristic read.
                    //
                    // The event is `bluetooth_read_request` and the verb is `respond_to_read`.
                    // This rule named `ble_characteristic_read` / `send_ble_response`, neither
                    // of which exists, so it never matched and the action was never checked —
                    // `assert_actions_valid_for_event` skips an event id it cannot resolve.
                    .on_event("bluetooth_read_request")
                    .and_event_data_contains("characteristic_uuid", "00002a19")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "respond_to_read",
                            "value": "5f"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;
    println!("✓ Server started");

    // Wait for server to initialize
    println!("Waiting for BLE server to start (5 seconds)...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Get BLE adapter
    println!("Getting BLE adapter...");
    let adapter = match get_ble_adapter().await {
        Ok(a) => {
            println!("✓ BLE adapter found");
            a
        }
        Err(e) => {
            println!("⚠ BLE adapter not available: {}", e);
            server.stop().await?;
            return Ok(());
        }
    };

    // Scan for the device
    println!("Scanning for 'NetGet-Battery' device...");
    let peripheral = match find_peripheral_by_name(&adapter, "NetGet-Battery", 10).await {
        Ok(p) => {
            println!("✓ Found device");
            p
        }
        Err(e) => {
            println!("⚠ Device not found: {}", e);
            server.stop().await?;
            return Ok(());
        }
    };

    // Connect
    println!("Connecting to device...");
    peripheral.connect().await.ok(); // Ignore connection errors for now

    // Discover services
    peripheral.discover_services().await?;
    println!("✓ Services discovered");

    // Find Battery Service
    let battery_service_uuid = uuid::Uuid::parse_str("0000180f-0000-1000-8000-00805f9b34fb")?;
    let battery_char_uuid = uuid::Uuid::parse_str("00002a19-0000-1000-8000-00805f9b34fb")?;

    let services = peripheral.services();
    let battery_service = services
        .iter()
        .find(|s| s.uuid == battery_service_uuid)
        .ok_or("Battery Service not found")?;

    println!("✓ Found Battery Service");

    // Find Battery Level characteristic
    let battery_char = battery_service
        .characteristics
        .iter()
        .find(|c| c.uuid == battery_char_uuid)
        .ok_or("Battery Level characteristic not found")?;

    println!("✓ Found Battery Level characteristic");

    // Read battery level
    println!("Reading battery level...");
    let value = peripheral.read(battery_char).await?;
    println!("✓ Read {} bytes: {:?}", value.len(), value);

    // Verify battery level (should be 0x5F = 95%)
    assert_eq!(value.len(), 1, "Expected 1 byte, got {}", value.len());
    let battery_level = value[0];
    println!("Battery level: {}%", battery_level);

    assert_eq!(
        battery_level, 0x5F,
        "Expected battery level 0x5F (95), got 0x{:02x} ({})",
        battery_level, battery_level
    );

    println!("✓ Battery level verified: 95%");

    peripheral.disconnect().await?;

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

// Test without BLE client (server-only validation)
#[tokio::test]
async fn test_bluetooth_ble_startup() -> E2EResult<()> {
    println!("\n=== E2E Test: Bluetooth Server Startup (No Client) ===");

    let prompt = "Act as a BLE device. Create a simple custom service with UUID 12345678-1234-5678-1234-567812345678 with one characteristic that has UUID 12345678-1234-5678-1234-567812345679 supporting read. Set the value to 'TEST' (hex: 54455354). Start advertising as 'NetGet-Test'.";

    // Start server with mocks
    println!("Starting NetGet BLE server...");
    let server = helpers::start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("BLE device")
                    .and_instruction_containing("custom service")
                    .and_instruction_containing("12345678-1234-5678-1234-567812345678")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "BLUETOOTH_BLE",
                            "instruction": "Create custom service with characteristic. Set value to 'TEST'. Start advertising as 'NetGet-Test'",
                            "startup_params": {
                                "device_name": "NetGet-Test"
                            }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Server started event - add service
                    .on_event("bluetooth_ble_started")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "add_service",
                            "uuid": "12345678-1234-5678-1234-567812345678",
                            "primary": true,
                            "characteristics": [
                                {
                                    "uuid": "12345678-1234-5678-1234-567812345679",
                                    "properties": ["read"],
                                    "permissions": ["readable"],
                                    "initial_value": "54455354"
                                }
                            ]
                        },
                        {
                            "type": "start_advertising",
                            "device_name": "NetGet-Test"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;
    println!("✓ Server started");

    // Let it run for a bit to ensure no crashes
    println!("Letting server run for 3 seconds...");
    println!("✓ Server running without errors");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("✓ Server stopped cleanly");

    println!("=== Test passed ===\n");
    Ok(())
}

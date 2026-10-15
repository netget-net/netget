//! Bluetooth Low Energy (BLE) client E2E tests
//!
//! NOTE: These tests require real BLE hardware and are ignored by default.
//! Run manually with: cargo test --features bluetooth-ble --test client -- client::bluetooth::e2e_test --include-ignored
//!
//! Test device requirements:
//! - Bluetooth 4.0+ adapter (built-in or USB dongle)
//! - BLE peripheral device with known services (e.g., Nordic nRF52 dev kit, ESP32, or fitness tracker)
//! - Ollama running locally

#![cfg(all(unix, feature = "bluetooth"))]

use std::time::Duration;
use tokio::time::sleep;

/// Test that Bluetooth client can initialize and scan for devices
#[tokio::test]
#[ignore = "Requires real BLE hardware"]
async fn test_bluetooth_scan() {
    // This test is a placeholder for manual testing
    // To implement:
    // 1. Start NetGet with bluetooth client
    // 2. Prompt LLM: "Scan for BLE devices for 5 seconds"
    // 3. Verify: bluetooth_scan_complete event with at least 1 device
    // 4. Expected LLM calls: 1
    // 5. Expected runtime: ~7 seconds

    println!("Bluetooth scan test requires real BLE hardware");
    println!("Setup:");
    println!("  1. Ensure BLE device is powered on and advertising");
    println!("  2. Run: cargo test --features bluetooth --test client -- client::bluetooth::e2e_test --include-ignored --nocapture");
    println!("  3. Manual verification required");
}

/// Test that Bluetooth client can connect to a device by address
#[tokio::test]
#[ignore = "Requires real BLE hardware"]
async fn test_bluetooth_connect_by_address() {
    // This test is a placeholder for manual testing
    // To implement:
    // 1. Start NetGet with bluetooth client
    // 2. Prompt LLM: "Connect to BLE device at address AA:BB:CC:DD:EE:FF"
    // 3. Verify: bluetooth_connected event
    // 4. Expected LLM calls: 1
    // 5. Expected runtime: ~5 seconds

    println!("Bluetooth connect test requires real BLE hardware");
    println!("Replace AA:BB:CC:DD:EE:FF with your device address");
}

/// Test that Bluetooth client can discover GATT services
#[tokio::test]
#[ignore = "Requires real BLE hardware"]
async fn test_bluetooth_discover_services() {
    // This test is a placeholder for manual testing
    // To implement:
    // 1. Connect to device (previous test)
    // 2. Prompt LLM: "Discover GATT services"
    // 3. Verify: bluetooth_services_discovered event with service list
    // 4. Expected LLM calls: 2 (connect + discover)
    // 5. Expected runtime: ~10 seconds

    println!("Service discovery test requires connected BLE device");
}

/// Test that Bluetooth client can read a characteristic
#[tokio::test]
#[ignore = "Requires real BLE hardware with Battery Service"]
async fn test_bluetooth_read_battery_level() {
    // This test is a placeholder for manual testing
    // To implement:
    // 1. Connect to device with Battery Service (0x180F)
    // 2. Prompt LLM: "Read battery level from Battery Service"
    // 3. Verify: bluetooth_data_read event with battery percentage (0-100)
    // 4. Expected LLM calls: 3-4 (connect, discover, read)
    // 5. Expected runtime: ~12 seconds

    println!("Battery read test requires BLE device with Battery Service (0x180F)");
    println!("Devices with Battery Service:");
    println!("  - Fitness trackers");
    println!("  - Wireless headphones");
    println!("  - Nordic nRF52 dev kit with battery example");
}

/// Test that Bluetooth client can subscribe to notifications
#[tokio::test]
#[ignore = "Requires real BLE hardware with notify-capable characteristic"]
async fn test_bluetooth_subscribe_notifications() {
    // This test is a placeholder for manual testing
    // To implement:
    // 1. Connect to device with Heart Rate Service (0x180D)
    // 2. Prompt LLM: "Subscribe to heart rate notifications"
    // 3. Verify: bluetooth_notification_received event (multiple times)
    // 4. Expected LLM calls: 4-6 (connect, discover, subscribe, notifications)
    // 5. Expected runtime: ~20 seconds

    println!("Notification test requires BLE device with notify-capable characteristic");
    println!("Example: Heart Rate Monitor with Heart Rate Service (0x180D)");
}

/// Helper function to validate UUID format
#[test]
fn test_uuid_parsing() {
    use uuid::Uuid;

    // Standard 16-bit GATT UUIDs (expanded to 128-bit)
    let battery_service = Uuid::parse_str("0000180f-0000-1000-8000-00805f9b34fb");
    assert!(battery_service.is_ok());

    let battery_level = Uuid::parse_str("00002a19-0000-1000-8000-00805f9b34fb");
    assert!(battery_level.is_ok());

    // Custom vendor UUID
    let custom = Uuid::parse_str("12345678-1234-5678-1234-567812345678");
    assert!(custom.is_ok());

    // Invalid UUID
    let invalid = Uuid::parse_str("not-a-uuid");
    assert!(invalid.is_err());
}

/// Helper function to validate hex data encoding
#[test]
fn test_hex_encoding() {
    // Valid hex string
    let data = hex::decode("ff80").unwrap();
    assert_eq!(data, vec![255, 128]);

    // Invalid hex string (odd length)
    let invalid1 = hex::decode("fff");
    assert!(invalid1.is_err());

    // Invalid hex string (non-hex characters)
    let invalid2 = hex::decode("gg");
    assert!(invalid2.is_err());
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use netget::client::bluetooth::BluetoothClientProtocol;
    use netget::llm::actions::client_trait::Client;
    use serde_json::json;

    #[test]
    fn test_scan_devices_action_default_duration() {
        let protocol = BluetoothClientProtocol::new();
        let action = json!({
            "type": "scan_devices"
        });

        let result = protocol.execute_action(action);
        assert!(result.is_ok());

        if let Ok(netget::llm::actions::client_trait::ClientActionResult::Custom { name, data }) =
            result
        {
            assert_eq!(name, "scan_devices");
            assert_eq!(data["duration_secs"], 5); // Default
        } else {
            panic!("Expected Custom action result");
        }
    }

    #[test]
    fn test_scan_devices_action_custom_duration() {
        let protocol = BluetoothClientProtocol::new();
        let action = json!({
            "type": "scan_devices",
            "duration_secs": 10
        });

        let result = protocol.execute_action(action);
        assert!(result.is_ok());

        if let Ok(netget::llm::actions::client_trait::ClientActionResult::Custom { name, data }) =
            result
        {
            assert_eq!(name, "scan_devices");
            assert_eq!(data["duration_secs"], 10);
        } else {
            panic!("Expected Custom action result");
        }
    }

    #[test]
    fn test_connect_device_requires_address_or_name() {
        let protocol = BluetoothClientProtocol::new();
        let action = json!({
            "type": "connect_device"
        });

        let result = protocol.execute_action(action);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("address or device_name"));
    }

    #[test]
    fn test_connect_device_by_address() {
        let protocol = BluetoothClientProtocol::new();
        let action = json!({
            "type": "connect_device",
            "device_address": "AA:BB:CC:DD:EE:FF"
        });

        let result = protocol.execute_action(action);
        assert!(result.is_ok());

        if let Ok(netget::llm::actions::client_trait::ClientActionResult::Custom { name, data }) =
            result
        {
            assert_eq!(name, "connect_device");
            assert_eq!(data["device_address"], "AA:BB:CC:DD:EE:FF");
        } else {
            panic!("Expected Custom action result");
        }
    }

    #[test]
    fn test_connect_device_by_name() {
        let protocol = BluetoothClientProtocol::new();
        let action = json!({
            "type": "connect_device",
            "device_name": "Heart Rate Monitor"
        });

        let result = protocol.execute_action(action);
        assert!(result.is_ok());

        if let Ok(netget::llm::actions::client_trait::ClientActionResult::Custom { name, data }) =
            result
        {
            assert_eq!(name, "connect_device");
            assert_eq!(data["device_name"], "Heart Rate Monitor");
        } else {
            panic!("Expected Custom action result");
        }
    }

    #[test]
    fn test_write_characteristic_hex_parsing() {
        let protocol = BluetoothClientProtocol::new();
        let action = json!({
            "type": "write_characteristic",
            "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb",
            "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb",
            "value_hex": "ff80",
            "with_response": true
        });

        let result = protocol.execute_action(action);
        assert!(result.is_ok());

        if let Ok(netget::llm::actions::client_trait::ClientActionResult::Custom { name, data }) =
            result
        {
            assert_eq!(name, "write_characteristic");
            assert_eq!(data["value_bytes"].as_array().unwrap().len(), 2);
            assert_eq!(data["value_bytes"][0], 255);
            assert_eq!(data["value_bytes"][1], 128);
            assert_eq!(data["with_response"], true);
        } else {
            panic!("Expected Custom action result");
        }
    }

    #[test]
    fn test_write_characteristic_invalid_hex() {
        let protocol = BluetoothClientProtocol::new();
        let action = json!({
            "type": "write_characteristic",
            "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb",
            "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb",
            "value_hex": "gg",  // Invalid hex
            "with_response": true
        });

        let result = protocol.execute_action(action);
        assert!(result.is_err());
    }

    #[test]
    fn test_disconnect_action() {
        let protocol = BluetoothClientProtocol::new();
        let action = json!({
            "type": "disconnect"
        });

        let result = protocol.execute_action(action);
        assert!(result.is_ok());

        if let Ok(netget::llm::actions::client_trait::ClientActionResult::Disconnect) = result {
            // Success
        } else {
            panic!("Expected Disconnect action result");
        }
    }
}

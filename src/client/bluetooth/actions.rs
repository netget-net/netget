//! Bluetooth Low Energy (BLE) client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Bluetooth client scan complete event
pub static BLUETOOTH_SCAN_COMPLETE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bluetooth_scan_complete",
        "BLE device scan completed with list of discovered devices",
        json!({"type": "read_characteristic", "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb", "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb"}),
    )
    .with_parameters(vec![Parameter {
        name: "devices".to_string(),
        type_hint: "array".to_string(),
        description: "List of discovered BLE devices with address, name, and RSSI".to_string(),
        required: true,
    }])
});

/// Bluetooth client connected event
pub static BLUETOOTH_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bluetooth_connected",
        "Successfully connected to BLE device",
        json!({"type": "read_characteristic", "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb", "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "device_address".to_string(),
            type_hint: "string".to_string(),
            description: "MAC address of connected device".to_string(),
            required: true,
        },
        Parameter {
            name: "device_name".to_string(),
            type_hint: "string".to_string(),
            description: "Name of connected device".to_string(),
            required: false,
        },
    ])
});

/// Bluetooth client services discovered event
pub static BLUETOOTH_SERVICES_DISCOVERED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bluetooth_services_discovered",
        "GATT services and characteristics discovered",
        json!({"type": "read_characteristic", "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb", "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb"}),
    )
    .with_parameters(vec![Parameter {
        name: "services".to_string(),
        type_hint: "array".to_string(),
        description: "List of GATT services with their characteristics".to_string(),
        required: true,
    }])
});

/// Bluetooth client data read event
pub static BLUETOOTH_DATA_READ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bluetooth_data_read",
        "Data read from BLE characteristic",
        json!({"type": "placeholder", "event_id": "bluetooth_data_read"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "service_uuid".to_string(),
            type_hint: "string".to_string(),
            description: "UUID of the service".to_string(),
            required: true,
        },
        Parameter {
            name: "characteristic_uuid".to_string(),
            type_hint: "string".to_string(),
            description: "UUID of the characteristic".to_string(),
            required: true,
        },
        Parameter {
            name: "value".to_string(),
            type_hint: "string".to_string(),
            description: "Human-readable value (if applicable)".to_string(),
            required: false,
        },
        Parameter {
            name: "value_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Hex-encoded raw bytes".to_string(),
            required: true,
        },
    ])
});

/// Bluetooth client notification received event
pub static BLUETOOTH_NOTIFICATION_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bluetooth_notification_received",
        "Notification received from subscribed BLE characteristic",
        json!({"type": "write_characteristic", "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb", "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb", "value_hex": "01", "with_response": true}),
    )
    .with_parameters(vec![
        Parameter {
            name: "service_uuid".to_string(),
            type_hint: "string".to_string(),
            description: "UUID of the service".to_string(),
            required: true,
        },
        Parameter {
            name: "characteristic_uuid".to_string(),
            type_hint: "string".to_string(),
            description: "UUID of the characteristic".to_string(),
            required: true,
        },
        Parameter {
            name: "value".to_string(),
            type_hint: "string".to_string(),
            description: "Human-readable value (if applicable)".to_string(),
            required: false,
        },
        Parameter {
            name: "value_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Hex-encoded raw bytes".to_string(),
            required: true,
        },
    ])
});

/// Bluetooth client protocol action handler
pub struct BluetoothClientProtocol;

impl BluetoothClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for BluetoothClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "scan_devices".to_string(),
                description: "Scan for nearby BLE devices".to_string(),
                parameters: vec![Parameter {
                    name: "duration_secs".to_string(),
                    type_hint: "number".to_string(),
                    description: "How long to scan in seconds (default: 5)".to_string(),
                    required: false,
                }],
                example: json!({
                    "type": "scan_devices",
                    "duration_secs": 5
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "connect_device".to_string(),
                description: "Connect to a specific BLE device by address or name".to_string(),
                parameters: vec![
                    Parameter {
                        name: "device_address".to_string(),
                        type_hint: "string".to_string(),
                        description: "MAC address of device (e.g., 'AA:BB:CC:DD:EE:FF')"
                            .to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "device_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Name of device (if address not provided)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "connect_device",
                    "device_address": "AA:BB:CC:DD:EE:FF"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "discover_services".to_string(),
                description: "Discover GATT services and characteristics on connected device"
                    .to_string(),
                parameters: vec![],
                example: json!({
                    "type": "discover_services"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the BLE device".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "read_characteristic".to_string(),
                description: "Read value from a BLE characteristic".to_string(),
                parameters: vec![
                    Parameter {
                        name: "service_uuid".to_string(),
                        type_hint: "string".to_string(),
                        description:
                            "UUID of the service (e.g., '0000180f-0000-1000-8000-00805f9b34fb')"
                                .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "characteristic_uuid".to_string(),
                        type_hint: "string".to_string(),
                        description: "UUID of the characteristic".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "read_characteristic",
                    "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb",
                    "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "write_characteristic".to_string(),
                description: "Write value to a BLE characteristic".to_string(),
                parameters: vec![
                    Parameter {
                        name: "service_uuid".to_string(),
                        type_hint: "string".to_string(),
                        description: "UUID of the service".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "characteristic_uuid".to_string(),
                        type_hint: "string".to_string(),
                        description: "UUID of the characteristic".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "value_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Hex-encoded bytes to write".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "with_response".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "Whether to wait for write response (default: true)"
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "write_characteristic",
                    "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb",
                    "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb",
                    "value_hex": "01",
                    "with_response": true
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "subscribe_notifications".to_string(),
                description: "Subscribe to notifications from a BLE characteristic".to_string(),
                parameters: vec![
                    Parameter {
                        name: "service_uuid".to_string(),
                        type_hint: "string".to_string(),
                        description: "UUID of the service".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "characteristic_uuid".to_string(),
                        type_hint: "string".to_string(),
                        description: "UUID of the characteristic".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "subscribe_notifications",
                    "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb",
                    "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "unsubscribe_notifications".to_string(),
                description: "Unsubscribe from notifications from a BLE characteristic".to_string(),
                parameters: vec![
                    Parameter {
                        name: "service_uuid".to_string(),
                        type_hint: "string".to_string(),
                        description: "UUID of the service".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "characteristic_uuid".to_string(),
                        type_hint: "string".to_string(),
                        description: "UUID of the characteristic".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "unsubscribe_notifications",
                    "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb",
                    "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb"
                }),
                log_template: None,
            },
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Bluetooth (BLE)"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "bluetooth_scan_complete",
                "Triggered when BLE scan completes",
                json!({"type": "read_characteristic", "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb", "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb"}),
            ),
            EventType::new(
                "bluetooth_connected",
                "Triggered when connected to BLE device",
                json!({"type": "read_characteristic", "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb", "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb"}),
            ),
            EventType::new(
                "bluetooth_services_discovered",
                "Triggered when GATT services are discovered",
                json!({"type": "read_characteristic", "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb", "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb"}),
            ),
            EventType::new(
                "bluetooth_data_read",
                "Triggered when data is read from characteristic",
                json!({"type": "write_characteristic", "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb", "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb", "value_hex": "01", "with_response": true}),
            ),
            EventType::new(
                "bluetooth_notification_received",
                "Triggered when notification is received",
                json!({"type": "write_characteristic", "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb", "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb", "value_hex": "01", "with_response": true}),
            ),
            EventType::new(
                "bluetooth_disconnected",
                "Triggered when disconnected from device",
                json!({"type": "read_characteristic", "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb", "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb"}),
            ),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "BLE>GATT"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "bluetooth",
            "ble",
            "bluetooth low energy",
            "gatt",
            "connect to bluetooth",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("btleplug library for cross-platform BLE")
            .llm_control("Full control over scanning, connecting, service discovery, read/write/subscribe operations")
            .e2e_testing("Real BLE device or simulator required")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Bluetooth Low Energy (BLE) client for connecting to BLE devices (Classic Bluetooth not supported)"
    }

    fn example_prompt(&self) -> &'static str {
        "Scan for BLE devices, connect to 'Heart Rate Monitor', and read battery level"
    }

    fn group_name(&self) -> &'static str {
        "Wireless"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles Bluetooth BLE operations
            json!({
                "type": "open_client",
                "remote_addr": "ble:scan",
                "base_stack": "bluetooth",
                "instruction": "Scan for BLE devices, connect to heart rate monitor, and read battery level"
            }),
            // Script mode: Code-based BLE handling
            json!({
                "type": "open_client",
                "remote_addr": "ble:scan",
                "base_stack": "bluetooth",
                "event_handlers": [{
                    "event_pattern": "bluetooth_connected",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<bluetooth_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed BLE action
            json!({
                "type": "open_client",
                "remote_addr": "ble:scan",
                "base_stack": "bluetooth",
                "event_handlers": [
                    {
                        "event_pattern": "bluetooth_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "discover_services"
                            }]
                        }
                    },
                    {
                        "event_pattern": "bluetooth_services_discovered",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "read_characteristic",
                                "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb",
                                "characteristic_uuid": "00002a19-0000-1000-8000-00805f9b34fb"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for BluetoothClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::bluetooth::BluetoothClient;
            BluetoothClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "scan_devices" => {
                let duration_secs = action
                    .get("duration_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(5);

                Ok(ClientActionResult::Custom {
                    name: "scan_devices".to_string(),
                    data: json!({
                        "duration_secs": duration_secs,
                    }),
                })
            }
            "connect_device" => {
                let device_address = action
                    .get("device_address")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let device_name = action
                    .get("device_name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                if device_address.is_none() && device_name.is_none() {
                    return Err(anyhow::anyhow!(
                        "Either device_address or device_name must be provided"
                    ));
                }

                Ok(ClientActionResult::Custom {
                    name: "connect_device".to_string(),
                    data: json!({
                        "device_address": device_address,
                        "device_name": device_name,
                    }),
                })
            }
            "discover_services" => Ok(ClientActionResult::Custom {
                name: "discover_services".to_string(),
                data: json!({}),
            }),
            "read_characteristic" => {
                let service_uuid = action
                    .get("service_uuid")
                    .and_then(|v| v.as_str())
                    .context("Missing 'service_uuid' field")?
                    .to_string();

                let characteristic_uuid = action
                    .get("characteristic_uuid")
                    .and_then(|v| v.as_str())
                    .context("Missing 'characteristic_uuid' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "read_characteristic".to_string(),
                    data: json!({
                        "service_uuid": service_uuid,
                        "characteristic_uuid": characteristic_uuid,
                    }),
                })
            }
            "write_characteristic" => {
                let service_uuid = action
                    .get("service_uuid")
                    .and_then(|v| v.as_str())
                    .context("Missing 'service_uuid' field")?
                    .to_string();

                let characteristic_uuid = action
                    .get("characteristic_uuid")
                    .and_then(|v| v.as_str())
                    .context("Missing 'characteristic_uuid' field")?
                    .to_string();

                let value_hex = action
                    .get("value_hex")
                    .and_then(|v| v.as_str())
                    .context("Missing 'value_hex' field")?;

                let value_bytes =
                    hex::decode(value_hex).context("Invalid hex data in value_hex")?;

                let with_response = action
                    .get("with_response")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);

                Ok(ClientActionResult::Custom {
                    name: "write_characteristic".to_string(),
                    data: json!({
                        "service_uuid": service_uuid,
                        "characteristic_uuid": characteristic_uuid,
                        "value_bytes": value_bytes,
                        "with_response": with_response,
                    }),
                })
            }
            "subscribe_notifications" => {
                let service_uuid = action
                    .get("service_uuid")
                    .and_then(|v| v.as_str())
                    .context("Missing 'service_uuid' field")?
                    .to_string();

                let characteristic_uuid = action
                    .get("characteristic_uuid")
                    .and_then(|v| v.as_str())
                    .context("Missing 'characteristic_uuid' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "subscribe_notifications".to_string(),
                    data: json!({
                        "service_uuid": service_uuid,
                        "characteristic_uuid": characteristic_uuid,
                    }),
                })
            }
            "unsubscribe_notifications" => {
                let service_uuid = action
                    .get("service_uuid")
                    .and_then(|v| v.as_str())
                    .context("Missing 'service_uuid' field")?
                    .to_string();

                let characteristic_uuid = action
                    .get("characteristic_uuid")
                    .and_then(|v| v.as_str())
                    .context("Missing 'characteristic_uuid' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "unsubscribe_notifications".to_string(),
                    data: json!({
                        "service_uuid": service_uuid,
                        "characteristic_uuid": characteristic_uuid,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown Bluetooth client action: {}",
                action_type
            )),
        }
    }
}

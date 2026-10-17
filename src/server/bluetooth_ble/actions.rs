//! Bluetooth Low Energy (BLE) GATT server protocol actions
//!
//! Cross-platform BLE peripheral using ble-peripheral-rust

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Bluetooth server started event
pub static BLUETOOTH_BLE_STARTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bluetooth_ble_started",
        "Bluetooth Low Energy GATT server started and ready for configuration",
        json!({
            "type": "add_service",
            "uuid": "180D",
            "primary": true,
            "characteristics": [{
                "uuid": "2A37",
                "properties": ["read", "notify"],
                "permissions": ["readable"],
                "initial_value": "0048"
            }]
        }),
    )
    // The GATT server is empty at startup, so this event is answered by building it out:
    // add_service for each service, then start_advertising to become discoverable.
    // `call_llm` builds the model's tool list from the event type rather than from
    // get_sync_actions(), so before this the model was offered none of the BLE actions.
    .with_actions(vec![add_service_action(), start_advertising_action()])
    .with_parameters(vec![
        Parameter {
            name: "device_name".to_string(),
            type_hint: "string".to_string(),
            description: "Name of the BLE device for advertising".to_string(),
            required: true,
        },
        Parameter {
            name: "instruction".to_string(),
            type_hint: "string".to_string(),
            description: "User instruction for server behavior".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("BLE GATT server started: {device_name}")
            .with_debug("BLE GATT server started: device={device_name}")
            .with_trace("BLE started: {json_pretty(.)}"),
    )
});

/// Bluetooth adapter state changed event
pub static BLUETOOTH_STATE_CHANGED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bluetooth_state_changed",
        "Bluetooth adapter state changed (powered on/off, advertising started/stopped, etc.)",
        json!({
            "type": "start_advertising"
        }),
    )
    // Powering on is answered by advertising, powering off by standing down.
    .with_actions(vec![start_advertising_action(), stop_advertising_action()])
    .with_parameters(vec![Parameter {
        name: "state".to_string(),
        type_hint: "string".to_string(),
        description: "Current state description".to_string(),
        required: true,
    }])
    .with_log_template(
        LogTemplate::new()
            .with_info("BLE state: {state}")
            .with_debug("BLE adapter state changed: {state}"),
    )
});

/// Read request event
pub static BLUETOOTH_READ_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bluetooth_read_request",
        "Client is reading from a GATT characteristic - respond with data",
        json!({
            "type": "respond_to_read",
            "value": "0048"
        }),
    )
    // A read is answered with the characteristic's value and nothing else - the server sends
    // whatever respond_to_read carries straight back to the client on this request's responder.
    .with_actions(vec![respond_to_read_action()])
    .with_parameters(vec![
        Parameter {
            name: "characteristic_uuid".to_string(),
            type_hint: "string".to_string(),
            description: "UUID of the characteristic being read".to_string(),
            required: true,
        },
        Parameter {
            name: "offset".to_string(),
            type_hint: "number".to_string(),
            description: "Byte offset for long reads (usually 0)".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("BLE read: {characteristic_uuid}")
            .with_debug("BLE read request: char={characteristic_uuid}, offset={offset}")
            .with_trace("BLE read request: {json_pretty(.)}"),
    )
});

/// Write request event
pub static BLUETOOTH_WRITE_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bluetooth_write_request",
        "Client wrote data to a GATT characteristic",
        json!({
            "type": "respond_to_write"
        }),
    )
    // Acknowledge the write; send_notification lets a write also push the new value out to
    // anyone subscribed to the characteristic.
    .with_actions(vec![respond_to_write_action(), send_notification_action()])
    .with_parameters(vec![
        Parameter {
            name: "characteristic_uuid".to_string(),
            type_hint: "string".to_string(),
            description: "UUID of the characteristic written to".to_string(),
            required: true,
        },
        Parameter {
            name: "value".to_string(),
            type_hint: "string".to_string(),
            description: "Hex-encoded data written by client".to_string(),
            required: true,
        },
        Parameter {
            name: "offset".to_string(),
            type_hint: "number".to_string(),
            description: "Byte offset for long writes (usually 0)".to_string(),
            required: true,
        },
        Parameter {
            name: "with_response".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether client expects a response".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("BLE write: {characteristic_uuid}")
            .with_debug("BLE write request: char={characteristic_uuid}, value={value}")
            .with_trace("BLE write request: {json_pretty(.)}"),
    )
});

/// Subscribe/unsubscribe to notifications event
pub static BLUETOOTH_SUBSCRIBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bluetooth_subscribe",
        "Client subscribed or unsubscribed from characteristic notifications",
        json!({
            "type": "send_notification",
            "characteristic_uuid": "2A37",
            "value": "0048"
        }),
    )
    // A fresh subscriber is answered with an initial send_notification; an unsubscribe is
    // answered with no action at all.
    .with_actions(vec![send_notification_action()])
    .with_parameters(vec![
        Parameter {
            name: "characteristic_uuid".to_string(),
            type_hint: "string".to_string(),
            description: "UUID of the characteristic".to_string(),
            required: true,
        },
        Parameter {
            name: "subscribed".to_string(),
            type_hint: "boolean".to_string(),
            description: "true if subscribed, false if unsubscribed".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("BLE {subscribed} notify: {characteristic_uuid}")
            .with_debug("BLE subscribe: char={characteristic_uuid}, subscribed={subscribed}"),
    )
});

/// Bluetooth server protocol handler
pub struct BluetoothBleProtocol;

impl BluetoothBleProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for BluetoothBleProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "device_name".to_string(),
            type_hint: "string".to_string(),
            description: "Bluetooth device name for advertising (default: NetGet-BLE)".to_string(),
            required: false,
            example: json!("MyDevice"),
            default: None,
        }]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            add_service_action(),
            start_advertising_action(),
            stop_advertising_action(),
            send_notification_action(),
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![respond_to_read_action(), respond_to_write_action()]
    }

    fn protocol_name(&self) -> &'static str {
        "BLUETOOTH_BLE"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            BLUETOOTH_BLE_STARTED_EVENT.clone(),
            BLUETOOTH_STATE_CHANGED_EVENT.clone(),
            BLUETOOTH_READ_REQUEST_EVENT.clone(),
            BLUETOOTH_WRITE_REQUEST_EVENT.clone(),
            BLUETOOTH_SUBSCRIBE_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "BLUETOOTH_BLE"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["bluetooth", "ble", "gatt", "peripheral", "bluetooth_ble"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("ble-peripheral-rust (cross-platform: Windows/WinRT, macOS/CoreBluetooth, Linux/BlueZ)")
            .llm_control("Full GATT server control: services, characteristics, read/write/notify")
            .e2e_testing(
                "Split, and the split is the point. The decision logic is covered without a \
                 radio, because `BluetoothBle::run_event_loop_without_radio` runs the real event \
                 loop over an injected event stream: the ATT read/write fail-closed paths \
                 (tests/server/bluetooth_ble/llm_failure_test.rs), the stored-value fallback and \
                 its refusal to substitute an undecodable answer (read_default_value_test.rs), \
                 and characteristic routing across servers sharing the one radio \
                 (shared_peripheral_routing_test.rs). None of those is #[ignore]d. What needs \
                 hardware is everything that transmits — advertising, service registration and a \
                 real central completing a GATT exchange — and those tests \
                 (tests/server/bluetooth_ble/e2e_test.rs) are #[ignore]d because they claim the \
                 machine's single BLE adapter and would deadlock a --test-threads=100 run.",
            )
            .notes(
                "VERIFIED without a radio: that an LLM failure answers ATT Unlikely Error (0x0E) \
                 rather than inventing a characteristic value or acknowledging a write that never \
                 took effect; that an explicit 'error' status on respond_to_write is honoured; \
                 that a respond_to_read whose value will not decode fails closed instead of \
                 silently serving the stored value; and that every one of those outcomes is \
                 distinguishable in the log by its decision= tag, which is the only place ATT can \
                 carry the distinction. NOT VERIFIED: nothing in the automated suite has ever put \
                 a byte on a radio. Advertising, service registration and any real central's \
                 GATT exchange are exercised only by the #[ignore]d tests, run by hand on macOS \
                 (see docs/archive/MACOS_SUPPORT.md). A rating above Experimental would need \
                 those to be neither ignored nor hardware-bound, which the single-adapter \
                 constraint currently prevents.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Bluetooth Low Energy (BLE) GATT server - act as a Bluetooth peripheral device"
    }

    fn example_prompt(&self) -> &'static str {
        "Act as a BLE heart rate monitor. Create Heart Rate Service (0x180D) with Measurement characteristic (0x2A37). Start at 72 BPM, increase by 1 every 2 seconds, send notifications."
    }

    fn group_name(&self) -> &'static str {
        "Network"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: on startup, register a heart-rate service and begin
        // advertising, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "bluetooth_ble_started":
    actions = [{"type": "add_service", "uuid": "180D", "primary": True,
                "characteristics": [{"uuid": "2A37",
                                     "properties": ["read", "notify"],
                                     "permissions": ["readable"],
                                     "initial_value": "0048"}]},
               {"type": "start_advertising", "device_name": "NetGet"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles BLE GATT server
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble",
                "instruction": "Act as a BLE heart rate monitor with Heart Rate Service (0x180D)",
                "startup_params": {
                    "device_name": "NetGet-HeartRate"
                }
            }),
            // Script mode: Code-based BLE handling
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble",
                "startup_params": {
                    "device_name": "NetGet-BLE"
                },
                "event_handlers": [{
                    "event_pattern": "bluetooth_ble_started",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed BLE action
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble",
                "startup_params": {
                    "device_name": "NetGet-BLE"
                },
                "event_handlers": [
                    {
                        "event_pattern": "bluetooth_ble_started",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "add_service",
                                "uuid": "180D",
                                "primary": true,
                                "characteristics": [{
                                    "uuid": "2A37",
                                    "properties": ["read", "notify"],
                                    "permissions": ["readable"],
                                    "initial_value": "0048"
                                }]
                            }]
                        }
                    },
                    {
                        "event_pattern": "bluetooth_read_request",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "respond_to_read",
                                "value": "0048"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for BluetoothBleProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(async move {
            let device_name = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("device_name"))
                .transpose()?
                .flatten()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "NetGet-BLE".to_string());

            let instruction = "Act as a Bluetooth Low Energy GATT server".to_string();

            crate::server::bluetooth_ble::BluetoothBle::spawn_with_llm_actions(
                device_name,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                instruction,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Actions are executed directly in the server event loop
        // This is just for validation
        let action_type = action["type"]
            .as_str()
            .context("Action must have 'type' field")?;

        match action_type {
            "add_service" | "start_advertising" | "stop_advertising" | "send_notification"
            | "respond_to_read" | "respond_to_write" => Ok(ActionResult::Custom {
                name: action_type.to_string(),
                data: action,
            }),
            _ => Err(anyhow::anyhow!(
                "Unknown Bluetooth action type: {}",
                action_type
            )),
        }
    }
}

// Action definitions

fn add_service_action() -> ActionDefinition {
    ActionDefinition {
        name: "add_service".to_string(),
        description: "Add a GATT service with characteristics to the BLE server".to_string(),
        parameters: vec![
            Parameter {
                name: "uuid".to_string(),
                type_hint: "string".to_string(),
                description: "Service UUID (standard 16-bit like '180D' or full 128-bit UUID)"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "primary".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether this is a primary service (default: true)".to_string(),
                required: false,
            },
            Parameter {
                name: "characteristics".to_string(),
                type_hint: "array".to_string(),
                description: "Array of characteristic definitions".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "add_service",
            "uuid": "180D",
            "primary": true,
            "characteristics": [{
                "uuid": "2A37",
                "properties": ["read", "notify"],
                "permissions": ["readable"],
                "initial_value": "0048"
            }]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BLE add service: {uuid}")
                .with_debug("BLE add service: uuid={uuid}, chars={characteristics_len}"),
        ),
    }
}

fn start_advertising_action() -> ActionDefinition {
    ActionDefinition {
        name: "start_advertising".to_string(),
        description: "Start BLE advertising to make the device discoverable".to_string(),
        parameters: vec![
            Parameter {
                name: "device_name".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Device name to advertise (optional, uses server default if not specified)"
                        .to_string(),
                required: false,
            },
            // Read by execute_start_advertising and passed to the radio, but never declared,
            // so the model could not advertise which services this device offers - the field
            // centrals filter their scans on.
            Parameter {
                name: "service_uuids".to_string(),
                type_hint: "array".to_string(),
                description: "Service UUIDs to advertise, so centrals scanning for a service \
                    can find this device. 16-bit shorthand (\"180D\") or full 128-bit form. \
                    Defaults to advertising the name only."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "start_advertising",
            "device_name": "NetGet-HR",
            "service_uuids": ["180D"]
        }),
        log_template: Some(LogTemplate::new().with_info("-> BLE start advertising")),
    }
}

fn stop_advertising_action() -> ActionDefinition {
    ActionDefinition {
        name: "stop_advertising".to_string(),
        description: "Stop BLE advertising".to_string(),
        parameters: vec![],
        example: json!({
            "type": "stop_advertising"
        }),
        log_template: Some(LogTemplate::new().with_info("-> BLE stop advertising")),
    }
}

fn send_notification_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_notification".to_string(),
        description: "Send a notification to subscribed clients for a characteristic".to_string(),
        parameters: vec![
            Parameter {
                name: "characteristic_uuid".to_string(),
                type_hint: "string".to_string(),
                description: "UUID of the characteristic to update".to_string(),
                required: true,
            },
            Parameter {
                name: "value".to_string(),
                type_hint: "string".to_string(),
                description: "Hex-encoded value to send (e.g., '0048' for 72 in decimal)"
                    .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_notification",
            "characteristic_uuid": "example_characteristic_uuid",
            "value": "example_value"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BLE notify: {characteristic_uuid}")
                .with_debug("BLE send notification: char={characteristic_uuid}, value={value}"),
        ),
    }
}

fn respond_to_read_action() -> ActionDefinition {
    ActionDefinition {
        name: "respond_to_read".to_string(),
        description: "Respond to a client's read request with data (use in response to bluetooth_read_request event)".to_string(),
        parameters: vec![
            Parameter {
                name: "value".to_string(),
                type_hint: "string".to_string(),
                description: "Hex-encoded value to return to client".to_string(),
                required: true,
            },
        ],
    example: json!({
            "type": "respond_to_read",
            "value": "example_value"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BLE read response")
                .with_debug("BLE respond to read: value={value}"),
        ),
    }
}

fn respond_to_write_action() -> ActionDefinition {
    ActionDefinition {
        name: "respond_to_write".to_string(),
        description: "Acknowledge a client's write request (use in response to bluetooth_write_request event)".to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "string".to_string(),
                description: "Response status: 'success' or 'error' (default: success)".to_string(),
                required: false,
            },
        ],
    example: json!({
            "type": "respond_to_write"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BLE write response")
                .with_debug("BLE respond to write: status={status}"),
        ),
    }
}

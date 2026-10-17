//! BLE HID gamepad (0x1812) - HID-over-GATT game controller
//!
//! Profile wrapper over the `bluetooth-ble` base stack.
//!
//! The base server (`BluetoothBle::spawn_with_llm_actions`) hardcodes `BluetoothBleProtocol`
//! when it calls `call_llm`, so the events the model actually sees and the actions it may
//! answer with are always the base's. Declaring profile-specific actions or events here would
//! document a vocabulary that no code path can ever emit or execute, so this protocol forwards
//! the base's set verbatim - the same shape `doh`/`dot` use to forward `DnsProtocol`'s actions.
//! The profile identity lives in the instruction preamble and in the GATT layout suggested by
//! the startup examples below.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::server::bluetooth_ble::actions::BluetoothBleProtocol;
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::json;

/// BLE HID gamepad (0x1812) - HID-over-GATT game controller
pub struct BluetoothBleGamepadProtocol;

impl BluetoothBleGamepadProtocol {
    pub fn new() -> Self {
        Self
    }

    /// The base protocol this profile delegates its whole vocabulary to.
    fn base() -> BluetoothBleProtocol {
        BluetoothBleProtocol::new()
    }
}

impl Default for BluetoothBleGamepadProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for BluetoothBleGamepadProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "device_name".to_string(),
            type_hint: "string".to_string(),
            description: "Bluetooth device name to advertise (default: NetGet-Gamepad)".to_string(),
            required: false,
            example: json!("NetGet-Gamepad"),
            default: None,
        }]
    }

    /// Delegated: the base stack owns every action this server can execute.
    fn get_async_actions(&self, state: &AppState) -> Vec<ActionDefinition> {
        Self::base().get_async_actions(state)
    }

    /// Delegated: see `get_async_actions`. Returning `vec![]` here while the base emits
    /// events would leave the model with no way to answer a read or a write.
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        Self::base().get_sync_actions()
    }

    /// Delegated: the base's event types are the only ones ever emitted for this server, and
    /// they carry their own `.with_actions(...)` lists, which is what `call_llm` offers the
    /// model. An event id declared here but not emitted by the base would silently match an
    /// `event_handlers` pattern that can never fire.
    fn get_event_types(&self) -> Vec<EventType> {
        Self::base().get_event_types()
    }

    fn protocol_name(&self) -> &'static str {
        "BLUETOOTH_BLE_GAMEPAD"
    }

    fn stack_name(&self) -> &'static str {
        "BLUETOOTH_BLE_GAMEPAD"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["bluetooth", "ble", "gamepad", "hid", "controller"]
    }

    /// HID-over-GATT caveat: a host will only treat this as an input device once
    /// it bonds, and ble-peripheral-rust 0.2 exposes no pairing or bonding control.
    /// The GATT layout below is correct and readable; whether a given OS accepts it
    /// as a real HID device is platform dependent and untested.
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "bluetooth-ble base stack (ble-peripheral-rust) plus an instruction preamble for the HID Service (0x1812) in gamepad mode",
            )
            .llm_control(
                "Base BLE GATT control (add_service, start_advertising, stop_advertising, respond_to_read, respond_to_write, send_notification); the LLM builds the HID Service (0x1812) in gamepad mode itself.",
            )
            .e2e_testing(
                "tests/server/bluetooth_ble_gamepad/report_descriptor_test.rs pins the HID report descriptor and the GATT values in the startup examples against literal spec bytes; it is a pure unit test, so it claims no adapter and is not #[ignore]d. e2e_test.rs additionally starts the server against a mocked model, which proves startup and the bluetooth_ble_started round trip and nothing at all about HID. Whether a real host accepts this as an input device is untested and needs an adapter plus an independent central (nRF Connect, btleplug); until that exists the rating cannot rise above Experimental.",
            )
            .notes(
                "Thin profile wrapper over the bluetooth-ble base stack. It prepends an instruction describing the HID Service (0x1812) in gamepad mode and otherwise reuses the base entirely: the base hardcodes BluetoothBleProtocol when it calls the LLM, so the action vocabulary, the event types and the executor are the base's. This protocol deliberately declares no actions or events of its own - one that did would be documented to the model but never reachable at runtime.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "BLE HID gamepad (0x1812) - HID-over-GATT game controller"
    }

    fn example_prompt(&self) -> &'static str {
        "Act as a Bluetooth gamepad. When a host subscribes, hold the A button for one second."
    }

    fn group_name(&self) -> &'static str {
        "Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        use crate::server::bluetooth_ble_gamepad::{
            HID_GAMEPAD_INPUT_REPORT_LEN, HID_GAMEPAD_REPORT_DESCRIPTOR,
        };

        // The report map is hex-encoded from the descriptor const rather than written out
        // again here. A model copies these examples verbatim onto a real GATT table, so a
        // second hand-maintained copy is a report map that drifts from the one the profile
        // documents — which is exactly what happened: the literal that used to sit here
        // appended a one-bit constant pad to an already byte-aligned 16 bits, declaring a
        // 17-bit report against a two-byte initial value.
        let report_map = hex::encode(HID_GAMEPAD_REPORT_DESCRIPTOR);
        // An all-zeroes report of the exact length the descriptor declares: "no buttons
        // pressed". Sized from the const so it cannot disagree with the report map.
        let empty_report = hex::encode(vec![0u8; HID_GAMEPAD_INPUT_REPORT_LEN]);
        let read_script = format!(
            "actions = [{{'type': 'respond_to_read', 'value': '{}'}}]",
            empty_report
        );

        // Every event id and action name below is one the base stack really emits and really
        // executes. UUIDs are written in full 128-bit form because the base parses them with
        // `Uuid::parse_str`, which rejects the 16-bit shorthand.
        StartupExamples::new(
            // LLM mode: the model builds the GATT layout and answers reads itself.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble-gamepad",
                "instruction": "Act as a Bluetooth gamepad. When a host subscribes, hold the A button for one second.",
                "startup_params": {
                    "device_name": "NetGet-Gamepad"
                }
            }),
            // Script mode: a read is answered in-process, with no model call.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble-gamepad",
                "startup_params": {
                    "device_name": "NetGet-Gamepad"
                },
                "event_handlers": [
                    {
                        "event_pattern": "bluetooth_read_request",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": read_script
                        }
                    }
                ]
            }),
            // Static mode: fixed GATT layout and a fixed read response, with no model call.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble-gamepad",
                "startup_params": {
                    "device_name": "NetGet-Gamepad"
                },
                "event_handlers": [
                    {
                        "event_pattern": "bluetooth_ble_started",
                        "handler": {
                            "type": "static",
                            "actions": [
                                {
                                    "type": "add_service",
                                    "uuid": "00001812-0000-1000-8000-00805f9b34fb",
                                    "primary": true,
                                    "characteristics": [
                                        {
                                            "uuid": "00002a4a-0000-1000-8000-00805f9b34fb",
                                            "properties": [
                                                "read"
                                            ],
                                            "permissions": [
                                                "readable"
                                            ],
                                            // HID Information: bcdHID 0x0111 (v1.11) as a
                                            // little-endian uint16, then bCountryCode 0x00
                                            // and Flags 0x02 (NormallyConnectable). Every
                                            // GATT integer is little-endian, so the version
                                            // is `1101` and not `0111` — written the other
                                            // way round a host reads HID version 17.01.
                                            "initial_value": "11010002"
                                        },
                                        {
                                            "uuid": "00002a4b-0000-1000-8000-00805f9b34fb",
                                            "properties": [
                                                "read"
                                            ],
                                            "permissions": [
                                                "readable"
                                            ],
                                            "initial_value": report_map
                                        },
                                        {
                                            "uuid": "00002a4d-0000-1000-8000-00805f9b34fb",
                                            "properties": [
                                                "read",
                                                "notify"
                                            ],
                                            "permissions": [
                                                "readable"
                                            ],
                                            "initial_value": empty_report
                                        },
                                        {
                                            "uuid": "00002a4c-0000-1000-8000-00805f9b34fb",
                                            "properties": [
                                                "write_without_response"
                                            ],
                                            "permissions": [
                                                "writeable"
                                            ]
                                        }
                                    ]
                                },
                                {
                                    "type": "start_advertising",
                                    "device_name": "NetGet-Gamepad",
                                    "service_uuids": [
                                        "00001812-0000-1000-8000-00805f9b34fb"
                                    ]
                                }
                            ]
                        }
                    },
                    {
                        "event_pattern": "bluetooth_read_request",
                        "handler": {
                            "type": "static",
                            "actions": [
                                {
                                    "type": "respond_to_read",
                                    "value": empty_report
                                }
                            ]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for BluetoothBleGamepadProtocol {
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
                .unwrap_or_else(|| "NetGet-Gamepad".to_string());

            // The user's own instruction must reach the base stack; the profile preamble is
            // added there, not substituted for it.
            let instruction = ctx
                .state
                .get_server(ctx.server_id)
                .await
                .map(|s| s.instruction)
                .unwrap_or_default();

            crate::server::bluetooth_ble_gamepad::BluetoothBleGamepad::spawn_with_llm_actions(
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

    /// Delegated: the base's executor is what actually runs, so validation must accept exactly
    /// the base's action names and reject everything else rather than waving any action through.
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        Self::base().execute_action(action)
    }
}

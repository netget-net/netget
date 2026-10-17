//! BLE Heart Rate Service (0x180D) - heart rate measurement in BPM
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

/// BLE Heart Rate Service (0x180D) - heart rate measurement in BPM
pub struct BluetoothBleHeartRateProtocol;

impl BluetoothBleHeartRateProtocol {
    pub fn new() -> Self {
        Self
    }

    /// The base protocol this profile delegates its whole vocabulary to.
    fn base() -> BluetoothBleProtocol {
        BluetoothBleProtocol::new()
    }
}

impl Default for BluetoothBleHeartRateProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for BluetoothBleHeartRateProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "device_name".to_string(),
            type_hint: "string".to_string(),
            description: "Bluetooth device name to advertise (default: NetGet-HeartRate)"
                .to_string(),
            required: false,
            example: json!("NetGet-HeartRate"),
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
        "BLUETOOTH_BLE_HEART_RATE"
    }

    fn stack_name(&self) -> &'static str {
        "BLUETOOTH_BLE_HEART_RATE"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "bluetooth",
            "ble",
            "heart",
            "rate",
            "bluetooth_ble_heart_rate",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // Answers on failure: the base stack replies ATT Unlikely Error (0x0E) to a read it
            // cannot satisfy, which the central surfaces as a failed read. No value is invented.
            .answers_on_failure()
            .implementation(
                "bluetooth-ble base stack (ble-peripheral-rust) plus an instruction preamble for the Heart Rate Service (0x180D)",
            )
            .llm_control(
                "Base BLE GATT control (add_service, start_advertising, stop_advertising, respond_to_read, respond_to_write, send_notification); the LLM builds the Heart Rate Service (0x180D) itself.",
            )
            .e2e_testing(
                "Two automated suites, neither of which is evidence for a rating above Experimental. tests/server/bluetooth_ble_heart_rate/e2e_test.rs covers the wiring only: open_server reaches this protocol's spawn, the base brings the radio up, and a bluetooth_ble_started event is raised and answered - it builds no service and puts no byte on the wire, and it claims the machine's Bluetooth adapter. gatt_examples_test.rs needs no adapter and pins every UUID and value byte in the startup examples against the Bluetooth SIG layout, byte order included. Proving the profile works still needs a real central (nRF Connect, btleplug) completing a read or a subscription against a service this profile built; nothing in the tree does that.",
            )
            .notes(
                "Thin profile wrapper over the bluetooth-ble base stack. It prepends an instruction describing the Heart Rate Service (0x180D) and otherwise reuses the base entirely: the base hardcodes BluetoothBleProtocol when it calls the LLM, so the action vocabulary, the event types and the executor are the base's. This protocol deliberately declares no actions or events of its own - one that did would be documented to the model but never reachable at runtime.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "BLE Heart Rate Service (0x180D) - heart rate measurement in BPM"
    }

    fn example_prompt(&self) -> &'static str {
        "Act as a heart rate monitor. Start at 60 BPM and climb to 120 BPM during exercise."
    }

    fn group_name(&self) -> &'static str {
        "Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Every event id and action name below is one the base stack really emits and really
        // executes. UUIDs are written in full 128-bit form because the base parses them with
        // `Uuid::parse_str`, which rejects the 16-bit shorthand.
        StartupExamples::new(
            // LLM mode: the model builds the GATT layout and answers reads itself.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble-heart-rate",
                "instruction": "Act as a heart rate monitor. Start at 60 BPM and climb to 120 BPM during exercise.",
                "startup_params": {
                    "device_name": "NetGet-HeartRate"
                }
            }),
            // Script mode: a read is answered in-process, with no model call.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble-heart-rate",
                "startup_params": {
                    "device_name": "NetGet-HeartRate"
                },
                "event_handlers": [
                    {
                        "event_pattern": "bluetooth_read_request",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": "import json,sys\ne=json.load(sys.stdin)['event']\nv={'00002a38-0000-1000-8000-00805f9b34fb':'01'}.get(str(e.get('characteristic_uuid','')).lower())\nprint(json.dumps({'actions':[{'type':'respond_to_read','value':v}] if v else []}))"
                        }
                    }
                ]
            }),
            // Static mode: fixed GATT layout and a fixed read response, with no model call.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble-heart-rate",
                "startup_params": {
                    "device_name": "NetGet-HeartRate"
                },
                "event_handlers": [
                    {
                        "event_pattern": "bluetooth_ble_started",
                        "handler": {
                            "type": "static",
                            "actions": [
                                {
                                    "type": "add_service",
                                    "uuid": "0000180d-0000-1000-8000-00805f9b34fb",
                                    "primary": true,
                                    "characteristics": [
                                        {
                                            "uuid": "00002a37-0000-1000-8000-00805f9b34fb",
                                            "properties": [
                                                "notify"
                                            ],
                                            "permissions": [],
                                            "initial_value": "0048"
                                        },
                                        {
                                            "uuid": "00002a38-0000-1000-8000-00805f9b34fb",
                                            "properties": [
                                                "read"
                                            ],
                                            "permissions": [
                                                "readable"
                                            ],
                                            "initial_value": "01"
                                        }
                                    ]
                                },
                                {
                                    "type": "start_advertising",
                                    "device_name": "NetGet-HeartRate",
                                    "service_uuids": [
                                        "0000180d-0000-1000-8000-00805f9b34fb"
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
                                    "value": "01"
                                }
                            ]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for BluetoothBleHeartRateProtocol {
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
                .unwrap_or_else(|| "NetGet-HeartRate".to_string());

            // The user's own instruction must reach the base stack; the profile preamble is
            // added there, not substituted for it.
            let instruction = ctx
                .state
                .get_server(ctx.server_id)
                .await
                .map(|s| s.instruction)
                .unwrap_or_default();

            crate::server::bluetooth_ble_heart_rate::BluetoothBleHeartRate::spawn_with_llm_actions(
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

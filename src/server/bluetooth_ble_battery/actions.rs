//! BLE Battery Service (0x180F) - report battery level as a percentage
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

/// BLE Battery Service (0x180F) - report battery level as a percentage
pub struct BluetoothBleBatteryProtocol;

impl BluetoothBleBatteryProtocol {
    pub fn new() -> Self {
        Self
    }

    /// The base protocol this profile delegates its whole vocabulary to.
    fn base() -> BluetoothBleProtocol {
        BluetoothBleProtocol::new()
    }
}

impl Default for BluetoothBleBatteryProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for BluetoothBleBatteryProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "device_name".to_string(),
                type_hint: "string".to_string(),
                description: "Bluetooth device name to advertise (default: NetGet-Battery)".to_string(),
                required: false,
                example: json!("NetGet-Battery"),
                default: None,
            },
            ParameterDefinition {
                name: "initial_level".to_string(),
                type_hint: "number".to_string(),
                description: "Initial battery level as a percentage, 0-100, folded into the instruction given to the LLM (default: 100). A value above 100 is refused, not clamped: the Battery Level characteristic reserves everything past 100.".to_string(),
                required: false,
                example: json!(80),
                default: None,
            },
        ]
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
        "BLUETOOTH_BLE_BATTERY"
    }

    fn stack_name(&self) -> &'static str {
        "BLUETOOTH_BLE_BATTERY"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["bluetooth", "ble", "battery", "bluetooth_ble_battery"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // Answers on failure: the base stack replies ATT Unlikely Error (0x0E) to a read it
            // cannot satisfy, which the central surfaces as a failed read. No value is invented.
            .answers_on_failure()
            .implementation(
                "bluetooth-ble base stack (ble-peripheral-rust) plus an instruction preamble for the Battery Service (0x180F)",
            )
            .llm_control(
                "Base BLE GATT control (add_service, start_advertising, stop_advertising, respond_to_read, respond_to_write, send_notification); the LLM builds the Battery Service (0x180F) itself.",
            )
            .e2e_testing(
                "Two automated suites, neither of which is evidence for a rating above Experimental. tests/server/bluetooth_ble_battery/e2e_test.rs covers the wiring only: open_server reaches this protocol's spawn, the base brings the radio up, and a bluetooth_ble_started event is raised and answered - it builds no service and puts no byte on the wire, and it claims the machine's Bluetooth adapter. gatt_examples_test.rs needs no adapter and pins every UUID and value byte in the startup examples against the Bluetooth SIG layout, byte order included. Proving the profile works still needs a real central (nRF Connect, btleplug) completing a read or a subscription against a service this profile built; nothing in the tree does that.",
            )
            .notes(
                "Thin profile wrapper over the bluetooth-ble base stack. It prepends an instruction describing the Battery Service (0x180F) and otherwise reuses the base entirely: the base hardcodes BluetoothBleProtocol when it calls the LLM, so the action vocabulary, the event types and the executor are the base's. This protocol deliberately declares no actions or events of its own - one that did would be documented to the model but never reachable at runtime.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "BLE Battery Service (0x180F) - report battery level as a percentage"
    }

    fn example_prompt(&self) -> &'static str {
        "Act as a Bluetooth battery. Expose the Battery Service (0x180F) and report 100%, dropping by 10% every 5 seconds."
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
                "base_stack": "bluetooth-ble-battery",
                "instruction": "Act as a Bluetooth battery. Expose the Battery Service (0x180F) and report 100%, dropping by 10% every 5 seconds.",
                "startup_params": {
                    "device_name": "NetGet-Battery",
                    "initial_level": 80
                }
            }),
            // Script mode: a read is answered in-process, with no model call.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble-battery",
                "startup_params": {
                    "device_name": "NetGet-Battery"
                },
                "event_handlers": [
                    {
                        "event_pattern": "bluetooth_read_request",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": "import json,sys\ne=json.load(sys.stdin)['event']\nv={'00002a19-0000-1000-8000-00805f9b34fb':'64'}.get(str(e.get('characteristic_uuid','')).lower())\nprint(json.dumps({'actions':[{'type':'respond_to_read','value':v}] if v else []}))"
                        }
                    }
                ]
            }),
            // Static mode: fixed GATT layout and a fixed read response, with no model call.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble-battery",
                "startup_params": {
                    "device_name": "NetGet-Battery"
                },
                "event_handlers": [
                    {
                        "event_pattern": "bluetooth_ble_started",
                        "handler": {
                            "type": "static",
                            "actions": [
                                {
                                    "type": "add_service",
                                    "uuid": "0000180f-0000-1000-8000-00805f9b34fb",
                                    "primary": true,
                                    "characteristics": [
                                        {
                                            "uuid": "00002a19-0000-1000-8000-00805f9b34fb",
                                            "properties": [
                                                "read",
                                                "notify"
                                            ],
                                            "permissions": [
                                                "readable"
                                            ],
                                            "initial_value": "64"
                                        }
                                    ]
                                },
                                {
                                    "type": "start_advertising",
                                    "device_name": "NetGet-Battery",
                                    "service_uuids": [
                                        "0000180f-0000-1000-8000-00805f9b34fb"
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
                                    "value": "64"
                                }
                            ]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for BluetoothBleBatteryProtocol {
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
                .unwrap_or_else(|| "NetGet-Battery".to_string());

            // `initial_level` is a Battery Level percentage, so 0-100 is the whole of its
            // range and anything else is a caller error. Refuse it rather than narrow it:
            // this was `.unwrap_or(100).min(100) as u8`, which started a server claiming a
            // full battery when asked for 150 or 4000, with nothing in any log to say the
            // number had been changed. A clamped percentage is a lie that reads as a fact.
            let initial_level = match ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_u64("initial_level"))
                .transpose()?
                .flatten()
            {
                None => 100u8,
                // Range-checked before the conversion, and the conversion is checked too, so
                // no value can reach the wire by being truncated into one.
                Some(level) if level <= 100 => u8::try_from(level).unwrap_or(100),
                // Tagged: this is a terminal outcome the *protocol* decided, before any model
                // was consulted, so it must not read as either an LLM failure or a radio one.
                Some(level) => anyhow::bail!(
                    "initial_level is a Battery Level (0x2A19) percentage and must be 0-100; \
                     got {level} (decision=refused_invalid_startup_param). The Bluetooth SIG \
                     reserves every value above 100, so there is no battery level this server \
                     could honestly advertise."
                ),
            };

            // The user's own instruction must reach the base stack; the profile preamble is
            // added there, not substituted for it.
            let instruction = ctx
                .state
                .get_server(ctx.server_id)
                .await
                .map(|s| s.instruction)
                .unwrap_or_default();

            crate::server::bluetooth_ble_battery::BluetoothBleBattery::spawn_with_llm_actions(
                device_name,
                initial_level,
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

//! BLE presentation clicker - HID Service (0x1812) sending page up/down keys
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

/// BLE presentation clicker - HID Service (0x1812) sending page up/down keys
pub struct BluetoothBlePresenterProtocol;

impl BluetoothBlePresenterProtocol {
    pub fn new() -> Self {
        Self
    }

    /// The base protocol this profile delegates its whole vocabulary to.
    fn base() -> BluetoothBleProtocol {
        BluetoothBleProtocol::new()
    }
}

impl Default for BluetoothBlePresenterProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for BluetoothBlePresenterProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "device_name".to_string(),
            type_hint: "string".to_string(),
            description: "Bluetooth device name to advertise (default: NetGet-Presenter)"
                .to_string(),
            required: false,
            example: json!("NetGet-Presenter"),
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
        "BLUETOOTH_BLE_PRESENTER"
    }

    fn stack_name(&self) -> &'static str {
        "BLUETOOTH_BLE_PRESENTER"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["bluetooth", "ble", "presenter", "clicker", "hid"]
    }

    /// HID-over-GATT caveat: a host will only treat this as an input device once
    /// it bonds, and ble-peripheral-rust 0.2 exposes no pairing or bonding control.
    /// The GATT layout below is pinned byte-for-byte against the USB HID 1.11 item
    /// encoding and the SIG characteristic definitions by
    /// `tests/server/bluetooth_ble_presenter/report_descriptor_test.rs`; whether a
    /// given OS accepts it as a real input device is a separate question, needs an
    /// adapter and a real central, and is untested.
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "bluetooth-ble base stack (ble-peripheral-rust) plus an instruction preamble for the HID Service (0x1812) in keyboard mode, sending page up/down",
            )
            .llm_control(
                "Base BLE GATT control (add_service, start_advertising, stop_advertising, respond_to_read, respond_to_write, send_notification); the LLM builds the HID Service (0x1812) in keyboard mode, sending page up/down itself.",
            )
            .e2e_testing(
                "Three automated suites, none of which is evidence for a rating above \
                 Experimental. report_descriptor_test.rs walks the HID report descriptor as a \
                 host would and pins it, build_presenter_report's keycodes and the GATT values \
                 against literal spec bytes; gatt_examples_test.rs pins every UUID and value \
                 byte in the startup examples against the Bluetooth SIG layout, byte order \
                 included. Both are pure unit tests: no adapter, not #[ignore]d. e2e_test.rs \
                 covers the wiring only - open_server reaches this protocol's spawn, the base \
                 brings the radio up, and a bluetooth_ble_started event is raised and answered \
                 - and it claims the machine's Bluetooth adapter. Whether a real host accepts \
                 this as an input device is untested: it needs an independent central (nRF \
                 Connect, btleplug) completing a read or a subscription against a service this \
                 profile built, and HID-over-GATT additionally requires bonding, which \
                 ble-peripheral-rust 0.2 exposes no control over.",
            )
            .notes(
                "Thin profile wrapper over the bluetooth-ble base stack. It prepends an instruction describing the HID Service (0x1812) in keyboard mode, sending page up/down and otherwise reuses the base entirely: the base hardcodes BluetoothBleProtocol when it calls the LLM, so the action vocabulary, the event types and the executor are the base's. This protocol deliberately declares no actions or events of its own - one that did would be documented to the model but never reachable at runtime.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "BLE presentation clicker - HID Service (0x1812) sending page up/down keys"
    }

    fn example_prompt(&self) -> &'static str {
        "Act as a presentation clicker. Advance one slide every ten seconds."
    }

    fn group_name(&self) -> &'static str {
        "Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        use crate::server::bluetooth_ble_presenter::{
            HID_PRESENTER_INPUT_REPORT_LEN, HID_PRESENTER_REPORT_DESCRIPTOR,
        };

        // The report map is hex-encoded from the descriptor const rather than written out
        // again here. A model copies these examples verbatim onto a real GATT table, so a
        // second hand-maintained copy is a report map that drifts from the one the profile
        // documents — which is exactly what happened: the literal that used to sit here had
        // its padding item's two bytes transposed (`Usage Page (0x75)` where `Report Size (5)`
        // was meant), which left `Report Size` at 1 and made the whole report ten bits — not a
        // whole number of bytes, and four times shorter than the eight-byte initial value
        // published on the very same characteristic.
        // The three readable characteristics, in the full 128-bit form the base's
        // `Uuid::parse_str` requires, and the one value that is not derived from a const.
        const HID_INFORMATION_UUID: &str = "00002a4a-0000-1000-8000-00805f9b34fb";
        const HID_REPORT_MAP_UUID: &str = "00002a4b-0000-1000-8000-00805f9b34fb";
        const HID_REPORT_UUID: &str = "00002a4d-0000-1000-8000-00805f9b34fb";
        /// bcdHID 0x0111 (v1.11) as a little-endian uint16, then bCountryCode 0x00 and Flags
        /// 0x02 (NormallyConnectable). Every GATT integer is little-endian, so the version is
        /// `1101`; written the other way round a host reads HID version 17.01.
        const HID_INFORMATION_VALUE: &str = "11010002";

        let report_map = hex::encode(HID_PRESENTER_REPORT_DESCRIPTOR);
        // An all-zeroes report of the exact length the descriptor declares: "no key is held".
        // Sized from the const so it cannot disagree with the report map.
        let empty_report = hex::encode(vec![0u8; HID_PRESENTER_INPUT_REPORT_LEN]);
        // One script rather than a static handler, because this service has three readable
        // characteristics and a static handler cannot tell them apart - answering every read
        // with the Report's zero octets left a host unable to parse the Report Map, and so
        // unable to interpret any report that followed.
        //
        // It is built from the consts above with `format!` for the same reason the descriptor
        // is a const at all: a hex literal pasted in here is the thing that drifts.
        //
        // The body must PRINT one JSON value. Writing `actions = [...]` assigns a local and
        // prints nothing, so the executor records the handler as failed and the event falls
        // through to the model - the opposite of what a static layout is for, and silently.
        let read_script = format!(
            "import json,sys\n\
             e = json.load(sys.stdin)['event']\n\
             v = {{'{hid_info_uuid}': '{hid_info}',\n\
                  '{report_map_uuid}': '{report_map}',\n\
                  '{report_uuid}': '{empty_report}'}}.get(\n\
                 str(e.get('characteristic_uuid', '')).lower())\n\
             print(json.dumps({{'actions': [{{'type': 'respond_to_read', 'value': v}}] if v else []}}))",
            hid_info_uuid = HID_INFORMATION_UUID,
            hid_info = HID_INFORMATION_VALUE,
            report_map_uuid = HID_REPORT_MAP_UUID,
            report_map = report_map,
            report_uuid = HID_REPORT_UUID,
            empty_report = empty_report,
        );

        // Every event id and action name below is one the base stack really emits and really
        // executes. UUIDs are written in full 128-bit form because the base parses them with
        // `Uuid::parse_str`, which rejects the 16-bit shorthand.
        StartupExamples::new(
            // LLM mode: the model builds the GATT layout and answers reads itself.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble-presenter",
                "instruction": "Act as a presentation clicker. Advance one slide every ten seconds.",
                "startup_params": {
                    "device_name": "NetGet-Presenter"
                }
            }),
            // Script mode: a read is answered in-process, with no model call.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble-presenter",
                "startup_params": {
                    "device_name": "NetGet-Presenter"
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
            // Static mode: a fixed GATT layout, with no model call. The read itself goes to a
            // script rather than a static handler because this service has three readable
            // characteristics and a static handler cannot tell them apart.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble-presenter",
                "startup_params": {
                    "device_name": "NetGet-Presenter"
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
                                            "uuid": HID_INFORMATION_UUID,
                                            "properties": [
                                                "read"
                                            ],
                                            "permissions": [
                                                "readable"
                                            ],
                                            "initial_value": HID_INFORMATION_VALUE
                                        },
                                        {
                                            "uuid": HID_REPORT_MAP_UUID,
                                            "properties": [
                                                "read"
                                            ],
                                            "permissions": [
                                                "readable"
                                            ],
                                            "initial_value": report_map
                                        },
                                        {
                                            "uuid": HID_REPORT_UUID,
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
                                    "device_name": "NetGet-Presenter",
                                    "service_uuids": [
                                        "00001812-0000-1000-8000-00805f9b34fb"
                                    ]
                                }
                            ]
                        }
                    },
                    // This is the same dispatching script the script-mode example uses, and
                    // it is here rather than a static handler because a static one cannot
                    // tell this service's *three* readable characteristics apart. It used
                    // to be a fixed `respond_to_read` naming the eight-zero-octet Report
                    // value, so a host reading the Report Map (0x2A4B) got eight zeros
                    // where the HID report descriptor should be — and a host that cannot
                    // parse the descriptor cannot interpret any report the device later
                    // sends, so the whole profile is dead on arrival.
                    //
                    // A script costs no LLM call either, and an unrecognised
                    // characteristic answers with `[]` so the base serves that
                    // characteristic's own stored value. The layout above stays static.
                    {
                        "event_pattern": "bluetooth_read_request",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": read_script.clone()
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for BluetoothBlePresenterProtocol {
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
                .unwrap_or_else(|| "NetGet-Presenter".to_string());

            // The user's own instruction must reach the base stack; the profile preamble is
            // added there, not substituted for it.
            let instruction = ctx
                .state
                .get_server(ctx.server_id)
                .await
                .map(|s| s.instruction)
                .unwrap_or_default();

            crate::server::bluetooth_ble_presenter::BluetoothBlePresenter::spawn_with_llm_actions(
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

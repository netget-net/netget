//! BLE beacon (iBeacon / Eddystone) actions and events.
//!
//! # Structured parameters, not payload bytes
//!
//! Every action here takes the fields a beacon is *specified* in — a proximity UUID, a major and
//! a minor, a namespace, a URL, a calibrated power in dBm — and the protocol builds the
//! advertising octets from them in [`super::payload`]. The model never sees, produces or parses
//! a byte blob. That is the project rule, and here it is also the only workable design: the
//! iBeacon and Eddystone layouts have fixed-width big-endian fields and a compression table that
//! no model would apply reliably by hand.
//!
//! The two identifier fields that *are* hex strings — Eddystone's `namespace` (10 bytes) and
//! `instance` (6 bytes) — are hex because that is their published textual form, exactly as a
//! UUID is written in hex. They are decoded by [`super::payload::BeaconFrame::eddystone_uid`],
//! so the documented encoding and the executor agree.
//!
//! # Reachability
//!
//! This protocol used to forward the whole `bluetooth-ble` vocabulary, because
//! `BluetoothBle::spawn_with_llm_actions` hardcodes `BluetoothBleProtocol` when it calls
//! `call_llm`, which made any action declared here unreachable. It no longer goes through that
//! path at all: [`super::BluetoothBleBeacon::spawn_with_llm_actions`] calls `call_llm` with
//! *this* protocol, so these actions and this event are the ones the model is offered and the
//! ones that execute.
//!
//! Execution goes through [`Server::execute_action_with_state`], because an action has to reach
//! the live adapter and the registry's protocol object is zero-sized. The handle is
//! [`super::BeaconServer`], registered in `spawn`.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::bluetooth_ble_beacon::advertise::UNSUPPORTED_PLATFORM_MESSAGE;
use crate::server::bluetooth_ble_beacon::payload::BeaconFrame;
use crate::server::bluetooth_ble_beacon::BeaconServer;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Default iBeacon measured power: RSSI at 1 m, in dBm.
const DEFAULT_MEASURED_POWER: i64 = -59;
/// Default Eddystone ranging data: TX power at 0 m, in dBm.
const DEFAULT_TX_POWER: i64 = -20;

/// The one event this protocol emits.
///
/// Raised exactly once, from `spawn`, after the adapter is open and before anything is
/// broadcast. A beacon advertisement is one-way — nothing ever arrives — so there is no second
/// event, and declaring one would advertise actions to the model that could never fire.
pub static BEACON_STARTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "beacon_started",
        "BLE beacon server started and the adapter is ready. Respond with the beacon frame to \
         broadcast; until then nothing is advertised.",
        json!({
            "type": "start_ibeacon",
            "uuid": "e2c56db5-dffb-48d2-b060-d0f5a71096e0",
            "major": 1,
            "minor": 100,
            "measured_power": -59
        }),
    )
    .with_actions(beacon_actions())
    .with_alternative_example(json!({
        "type": "start_eddystone_url",
        "url": "https://example.com/",
        "tx_power": -20
    }))
    .with_alternative_example(json!({
        "type": "start_eddystone_uid",
        "namespace": "edd1ebeac04e5defa017",
        "instance": "000000000001",
        "tx_power": -20
    }))
    .with_parameters(vec![
        Parameter {
            name: "device_name".to_string(),
            type_hint: "string".to_string(),
            description:
                "Device name requested at startup. Only advertised if the chosen beacon frame \
                 leaves room in the 31-octet payload; an iBeacon never does."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "adapter".to_string(),
            type_hint: "string".to_string(),
            description: "Bluetooth adapter the beacon is bound to (e.g. 'hci0')".to_string(),
            required: true,
        },
        Parameter {
            name: "instruction".to_string(),
            type_hint: "string".to_string(),
            description: "User instruction describing the beacon to broadcast".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("BLE beacon ready on {adapter}")
            .with_debug("BLE beacon started: adapter={adapter}, device_name={device_name}")
            .with_trace("BLE beacon started: {json_pretty(.)}"),
    )
});

/// Every action this protocol offers, in the order the model should consider them.
fn beacon_actions() -> Vec<ActionDefinition> {
    vec![
        start_ibeacon_action(),
        start_eddystone_url_action(),
        start_eddystone_uid_action(),
        stop_beacon_action(),
    ]
}

fn start_ibeacon_action() -> ActionDefinition {
    ActionDefinition {
        name: "start_ibeacon".to_string(),
        description:
            "Broadcast an Apple iBeacon advertisement. Replaces any beacon already on air. The \
             proximity UUID identifies the deployment, major/minor identify the individual \
             beacon within it."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "uuid".to_string(),
                type_hint: "string".to_string(),
                description: "128-bit proximity UUID, e.g. 'e2c56db5-dffb-48d2-b060-d0f5a71096e0'"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "major".to_string(),
                type_hint: "number".to_string(),
                description: "Major value, 0-65535".to_string(),
                required: true,
            },
            Parameter {
                name: "minor".to_string(),
                type_hint: "number".to_string(),
                description: "Minor value, 0-65535".to_string(),
                required: true,
            },
            Parameter {
                name: "measured_power".to_string(),
                type_hint: "number".to_string(),
                description: format!(
                    "Calibrated RSSI in dBm measured 1 metre from the beacon, used by receivers \
                     to estimate distance. Negative; default {DEFAULT_MEASURED_POWER}."
                ),
                required: false,
            },
        ],
        example: json!({
            "type": "start_ibeacon",
            "uuid": "e2c56db5-dffb-48d2-b060-d0f5a71096e0",
            "major": 1,
            "minor": 100,
            "measured_power": -59
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> iBeacon {uuid} {major}/{minor}")
                .with_debug(
                    "iBeacon: uuid={uuid}, major={major}, minor={minor}, power={measured_power}",
                ),
        ),
    }
}

fn start_eddystone_uid_action() -> ActionDefinition {
    ActionDefinition {
        name: "start_eddystone_uid".to_string(),
        description:
            "Broadcast an Eddystone-UID frame. Replaces any beacon already on air. The namespace \
             identifies a group of beacons, the instance identifies one within it."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "namespace".to_string(),
                type_hint: "string".to_string(),
                description:
                    "10-byte namespace id written as 20 hex digits, or a 128-bit UUID whose \
                     first 10 bytes are used"
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "instance".to_string(),
                type_hint: "string".to_string(),
                description: "6-byte instance id written as 12 hex digits".to_string(),
                required: true,
            },
            Parameter {
                name: "tx_power".to_string(),
                type_hint: "number".to_string(),
                description: format!(
                    "Calibrated transmit power in dBm at 0 metres. Negative; default \
                     {DEFAULT_TX_POWER}."
                ),
                required: false,
            },
        ],
        example: json!({
            "type": "start_eddystone_uid",
            "namespace": "edd1ebeac04e5defa017",
            "instance": "000000000001",
            "tx_power": -20
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Eddystone-UID {namespace}/{instance}")
                .with_debug(
                    "Eddystone-UID: namespace={namespace}, instance={instance}, tx={tx_power}",
                ),
        ),
    }
}

fn start_eddystone_url_action() -> ActionDefinition {
    ActionDefinition {
        name: "start_eddystone_url".to_string(),
        description:
            "Broadcast an Eddystone-URL frame. Replaces any beacon already on air. The URL is \
             compressed with Eddystone's scheme and suffix tables and must fit in 17 octets \
             after compression, so keep it short."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "url".to_string(),
                type_hint: "string".to_string(),
                description:
                    "http:// or https:// URL. '.com/', '.org/', '.net/' and friends each cost \
                     one octet; anything outside printable ASCII cannot be encoded."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "tx_power".to_string(),
                type_hint: "number".to_string(),
                description: format!(
                    "Calibrated transmit power in dBm at 0 metres. Negative; default \
                     {DEFAULT_TX_POWER}."
                ),
                required: false,
            },
        ],
        example: json!({
            "type": "start_eddystone_url",
            "url": "https://example.com/",
            "tx_power": -20
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Eddystone-URL {url}")
                .with_debug("Eddystone-URL: url={url}, tx={tx_power}"),
        ),
    }
}

fn stop_beacon_action() -> ActionDefinition {
    ActionDefinition {
        name: "stop_beacon".to_string(),
        description: "Stop broadcasting. The server stays up and can start another beacon later."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "stop_beacon"}),
        log_template: Some(LogTemplate::new().with_info("-> Beacon stopped")),
    }
}

/// Turn one action object into the frame it describes.
///
/// Pure: it touches no adapter, so it is exercised by the payload tests on any platform.
/// Returns `Ok(None)` for `stop_beacon`, which names no frame.
pub fn frame_from_action(action: &serde_json::Value) -> Result<Option<BeaconFrame>> {
    let action_type = action
        .get("type")
        .and_then(|v| v.as_str())
        .context("action must have a 'type' field")?;

    match action_type {
        "start_ibeacon" => {
            let uuid = action
                .get("uuid")
                .and_then(|v| v.as_str())
                .context("start_ibeacon requires 'uuid'")?;
            let major = action
                .get("major")
                .and_then(|v| v.as_i64())
                .context("start_ibeacon requires 'major' (0-65535)")?;
            let minor = action
                .get("minor")
                .and_then(|v| v.as_i64())
                .context("start_ibeacon requires 'minor' (0-65535)")?;
            let power = action
                .get("measured_power")
                .and_then(|v| v.as_i64())
                .unwrap_or(DEFAULT_MEASURED_POWER);
            Ok(Some(BeaconFrame::ibeacon(uuid, major, minor, power)?))
        }
        "start_eddystone_uid" => {
            let namespace = action
                .get("namespace")
                .and_then(|v| v.as_str())
                .context("start_eddystone_uid requires 'namespace' (20 hex digits)")?;
            let instance = action
                .get("instance")
                .and_then(|v| v.as_str())
                .context("start_eddystone_uid requires 'instance' (12 hex digits)")?;
            let tx = action
                .get("tx_power")
                .and_then(|v| v.as_i64())
                .unwrap_or(DEFAULT_TX_POWER);
            Ok(Some(BeaconFrame::eddystone_uid(namespace, instance, tx)?))
        }
        "start_eddystone_url" => {
            let url = action
                .get("url")
                .and_then(|v| v.as_str())
                .context("start_eddystone_url requires 'url'")?;
            let tx = action
                .get("tx_power")
                .and_then(|v| v.as_i64())
                .unwrap_or(DEFAULT_TX_POWER);
            Ok(Some(BeaconFrame::eddystone_url(url, tx)?))
        }
        "stop_beacon" => Ok(None),
        other => Err(anyhow!(
            "unknown beacon action {other:?}; expected one of start_ibeacon, \
             start_eddystone_uid, start_eddystone_url, stop_beacon"
        )),
    }
}

/// BLE beacon (iBeacon / Eddystone) advertiser
pub struct BluetoothBleBeaconProtocol;

impl BluetoothBleBeaconProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BluetoothBleBeaconProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for BluetoothBleBeaconProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "device_name".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Device name to advertise alongside the beacon, when the frame leaves room \
                     in the 31-octet payload (default: NetGet-Beacon). An iBeacon fills the \
                     payload, so its name is always dropped."
                        .to_string(),
                required: false,
                example: json!("NetGet-Beacon"),
                default: None,
            },
            ParameterDefinition {
                name: "adapter".to_string(),
                type_hint: "string".to_string(),
                description: "Bluetooth adapter to advertise from, e.g. 'hci0'. Defaults to the \
                              system's default adapter."
                    .to_string(),
                required: false,
                example: json!("hci0"),
                default: None,
            },
        ]
    }

    /// Beacon frames can be changed at any time, not only in response to an event.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        beacon_actions()
    }

    /// The same set: `beacon_started` is answered by choosing a frame, which is exactly what
    /// these actions do. Returning an empty list here while the event carries actions would
    /// make `audit_event_action_declarations` blind to this protocol.
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        beacon_actions()
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![BEACON_STARTED_EVENT.clone()]
    }

    fn protocol_name(&self) -> &'static str {
        "BLUETOOTH_BLE_BEACON"
    }

    fn stack_name(&self) -> &'static str {
        "BLUETOOTH_BLE_BEACON"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "bluetooth",
            "ble",
            "beacon",
            "ibeacon",
            "eddystone",
            "advertising",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "Linux only: registers an org.bluez.LEAdvertisement1 object with ManufacturerData \
                 (iBeacon) or ServiceData (Eddystone) on org.bluez.LEAdvertisingManager1 via the \
                 bluer crate, which is already in the tree as ble-peripheral-rust's Linux backend. \
                 Advertising payloads are built from structured action parameters in payload.rs. \
                 On macOS and Windows spawn() returns an error instead of starting.",
            )
            .llm_control(
                "Chooses the beacon frame and its fields: start_ibeacon (uuid/major/minor/\
                 measured_power), start_eddystone_uid (namespace/instance/tx_power), \
                 start_eddystone_url (url/tx_power), stop_beacon. One event, beacon_started.",
            )
            .e2e_testing(
                "Payload construction is unit-tested against literal spec-derived bytes for \
                 iBeacon, Eddystone-UID and Eddystone-URL (tests/server/bluetooth_ble_beacon/\
                 payload_test.rs), and the non-Linux refusal is asserted. Advertising itself is \
                 not covered: it needs a Linux host with bluetoothd and a scanner.",
            )
            .notes(
                "VERIFIED: the iBeacon, Eddystone-UID and Eddystone-URL octets, including the \
                 Eddystone URL scheme/suffix compression tables, the 17-octet encoded-URL limit \
                 and the 31-octet advertising budget, are asserted byte-for-byte against the \
                 Apple and google/eddystone layouts; that macOS/Windows refuse to start with an \
                 explicit reason rather than reporting Running. NOT VERIFIED: nothing has ever \
                 been transmitted. The BlueZ path was written against bluer 0.17 and the \
                 LEAdvertisement1/LEAdvertisingManager1 D-Bus API but has not been compiled or \
                 run on Linux, and no scanner has confirmed a frame on air. Treat first use on \
                 Linux as bring-up. Experimental, not Beta, for exactly that reason.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "BLE beacon (iBeacon / Eddystone) advertiser - Linux/BlueZ only"
    }

    fn example_prompt(&self) -> &'static str {
        "Act as an iBeacon with UUID e2c56db5-dffb-48d2-b060-d0f5a71096e0, major 1, minor 100"
    }

    fn group_name(&self) -> &'static str {
        "Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: the model picks the frame from the instruction.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble-beacon",
                "instruction": "Act as an iBeacon with UUID e2c56db5-dffb-48d2-b060-d0f5a71096e0, major 1, minor 100",
                "startup_params": {
                    "device_name": "NetGet-Beacon"
                }
            }),
            // Script mode: the frame is computed in-process, with no model call.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble-beacon",
                "startup_params": {
                    "device_name": "NetGet-Beacon"
                },
                "event_handlers": [
                    {
                        "event_pattern": "beacon_started",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": "actions = [{'type': 'start_eddystone_url', 'url': 'https://example.com/', 'tx_power': -20}]"
                        }
                    }
                ]
            }),
            // Static mode: a fixed beacon, with no model call.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "bluetooth-ble-beacon",
                "startup_params": {
                    "device_name": "NetGet-Beacon",
                    "adapter": "hci0"
                },
                "event_handlers": [
                    {
                        "event_pattern": "beacon_started",
                        "handler": {
                            "type": "static",
                            "actions": [
                                {
                                    "type": "start_ibeacon",
                                    "uuid": "e2c56db5-dffb-48d2-b060-d0f5a71096e0",
                                    "major": 1,
                                    "minor": 100,
                                    "measured_power": -59
                                }
                            ]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for BluetoothBleBeaconProtocol {
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
                .unwrap_or_else(|| "NetGet-Beacon".to_string());

            let adapter = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("adapter"))
                .transpose()?
                .flatten();

            let instruction = ctx
                .state
                .get_server(ctx.server_id)
                .await
                .map(|s| s.instruction)
                .unwrap_or_default();

            crate::server::bluetooth_ble_beacon::BluetoothBleBeacon::spawn_with_llm_actions(
                device_name,
                adapter,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                instruction,
            )
            .await
        })
    }

    /// Never reached: [`Self::execute_action_with_state`] is overridden and does not delegate.
    ///
    /// It fails closed rather than returning a success that transmitted nothing. Every beacon
    /// action needs the live adapter handle, which this stateless object does not have, so if
    /// the executor ever stopped calling the state-aware variant the failure would be loud
    /// instead of silent.
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Still validate, so the error names the real problem when the action is also malformed.
        frame_from_action(&action)?;
        Err(anyhow!(
            "beacon actions require the running server's adapter handle and must be dispatched \
             through execute_action_with_state"
        ))
    }

    fn execute_action_with_state<'a>(
        &'a self,
        action: serde_json::Value,
        state: AppState,
        server_id: Option<crate::state::ServerId>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ActionResult>> + Send + 'a>>
    {
        Box::pin(async move {
            let frame = frame_from_action(&action)?;

            let server_id = server_id
                .context("beacon actions are server-scoped and cannot run without a server id")?;
            let server: std::sync::Arc<BeaconServer> =
                state.server_handle(server_id).await.ok_or_else(|| {
                    anyhow!(
                        "no running BLE beacon server for id {server_id:?}. {}",
                        UNSUPPORTED_PLATFORM_MESSAGE
                    )
                })?;

            match frame {
                Some(frame) => {
                    let described = server.start_beacon(frame).await?;
                    Ok(ActionResult::Custom {
                        name: "beacon_advertising".to_string(),
                        data: json!({
                            "advertising": true,
                            "beacon": described,
                            "adapter": server.adapter_name().await,
                        }),
                    })
                }
                None => {
                    let previous = server.stop_beacon().await;
                    Ok(ActionResult::Custom {
                        name: "beacon_stopped".to_string(),
                        data: json!({
                            "advertising": false,
                            "was_advertising": previous,
                        }),
                    })
                }
            }
        })
    }
}

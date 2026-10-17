//! What the model decides as a LoRaWAN network server: whether a device that sent a valid
//! Join Request may join, and what goes back down to a device after each uplink. Keys, MIC
//! checks, frame counters, encryption and downlink timing are Rust's and never reach it.
use super::{mac, region};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const ACCEPT_JOIN: &str = "lorawan_accept_join";
pub const REJECT_JOIN: &str = "lorawan_reject_join";
pub const SEND_DOWNLINK: &str = "lorawan_send_downlink";
pub const REQUEST_STATUS: &str = "lorawan_request_device_status";
pub const IGNORE: &str = "lorawan_ignore";

/// The application payload of one downlink is capped by the data rate it goes out at; this is
/// the largest any EU868 rate allows, checked before the rate is known.
pub const MAX_DOWNLINK_PAYLOAD: usize = 242;

pub fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
    }
}

fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
    log: &str,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(log)),
    }
}

pub fn accept_join_action() -> ActionDefinition {
    action(
        ACCEPT_JOIN,
        "Admit the device: NetGet assigns a DevAddr, derives the session keys from its AppKey and sends the Join Accept in the device's receive window.",
        vec![],
        json!({"type": ACCEPT_JOIN}),
        "-> LoRaWAN join accepted",
    )
}

pub fn reject_join_action() -> ActionDefinition {
    action(
        REJECT_JOIN,
        "Refuse the join. LoRaWAN has no rejection message: nothing is sent and the device keeps trying.",
        vec![],
        json!({"type": REJECT_JOIN}),
        "-> LoRaWAN join refused",
    )
}

/// The parameters of an application payload, shared with the gateway client's uplink.
pub fn payload_params(port_description: &str) -> Vec<Parameter> {
    vec![
        p("f_port", "number", port_description, true),
        p(
            "payload",
            "string",
            "The application payload: text, or hex digits when encoding is hex (may be empty)",
            true,
        ),
        p("encoding", "string", "utf8 (default) or hex", false),
        p(
            "confirmed",
            "boolean",
            "Ask the other side to acknowledge it (default false)",
            false,
        ),
    ]
}

pub fn send_downlink_action() -> ActionDefinition {
    action(
        SEND_DOWNLINK,
        "Send an application payload to the device. NetGet encrypts it with the session's AppSKey and sends it in the receive window that follows this uplink; a second one waits for the device's next uplink (FPending tells it more is waiting). Its size is bounded by the data rate (max_downlink_payload in the event).",
        payload_params("Application port, 1..223"),
        json!({"type": SEND_DOWNLINK, "f_port": 10, "payload": "0101", "encoding": "hex", "confirmed": false}),
        "-> LoRaWAN downlink port {f_port}",
    )
}

pub fn request_status_action() -> ActionDefinition {
    action(
        REQUEST_STATUS,
        "Ask the device for its battery level and link margin (DevStatusReq). The answer arrives in a later uplink's mac_commands as dev_status_ans.",
        vec![],
        json!({"type": REQUEST_STATUS}),
        "-> LoRaWAN DevStatusReq",
    )
}

pub fn ignore_action() -> ActionDefinition {
    action(
        IGNORE,
        "Send no application data. NetGet still acknowledges a confirmed uplink and answers a LinkCheckReq, as the network does whatever the application decides.",
        vec![],
        json!({"type": IGNORE}),
        "-> LoRaWAN no downlink",
    )
}

fn radio_params() -> Vec<Parameter> {
    vec![
        p(
            "gateway",
            "string",
            "EUI of the gateway that heard it first",
            true,
        ),
        p(
            "gateways",
            "number",
            "How many gateways heard it so far",
            true,
        ),
        p("rssi", "number", "Signal strength, dBm", true),
        p("snr", "number", "Signal to noise ratio, dB", true),
        p("frequency_mhz", "number", "Uplink frequency", true),
        p("data_rate", "string", "e.g. SF7BW125 (DR5)", true),
    ]
}

pub static JOIN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = vec![
        p("dev_eui", "string", "The device's EUI-64, hex", true),
        p(
            "app_eui",
            "string",
            "The JoinEUI/AppEUI it asked for, hex",
            true,
        ),
        p(
            "dev_nonce",
            "number",
            "Its DevNonce (already checked against the ones it used before)",
            true,
        ),
        p(
            "device",
            "string",
            "The name the operator gave the device, if any",
            false,
        ),
    ];
    params.extend(radio_params());
    EventType::new(
        "lorawan_join_request",
        "A configured OTAA device sent a Join Request whose MIC verified under its AppKey. Admit it with lorawan_accept_join or refuse with lorawan_reject_join; anything else admits nothing.",
        accept_join_action().example.clone(),
    )
    .with_parameters(params)
    .with_actions(vec![accept_join_action(), reject_join_action()])
});

pub static UPLINK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = vec![
        p("dev_addr", "string", "The session's DevAddr, hex", true),
        p(
            "dev_eui",
            "string",
            "The device's EUI-64, hex (null for an ABP device configured without one)",
            false,
        ),
        p(
            "device",
            "string",
            "The name the operator gave the device, if any",
            false,
        ),
        p(
            "confirmed",
            "boolean",
            "The device asked for an acknowledgement (NetGet sends it)",
            true,
        ),
        p(
            "f_cnt",
            "number",
            "The uplink frame counter (32 bits, checked: never a replay)",
            true,
        ),
        p(
            "f_port",
            "number",
            "Application port; null when the frame carries only MAC commands",
            false,
        ),
        p(
            "payload",
            "string",
            "The decrypted application payload, as text or hex per payload_encoding",
            true,
        ),
        p("payload_encoding", "string", "utf8 or hex", true),
        p(
            "mac_commands",
            "array",
            "MAC commands the device sent, decoded (e.g. link_check_req, dev_status_ans with battery and margin_db)",
            true,
        ),
        p(
            "ack",
            "boolean",
            "The device acknowledges the last confirmed downlink",
            true,
        ),
        p(
            "max_downlink_payload",
            "number",
            "The largest payload lorawan_send_downlink may carry in this receive window",
            true,
        ),
    ];
    params.extend(radio_params());
    EventType::new(
        "lorawan_uplink",
        "A data uplink from a joined or ABP device: MIC verified, frame counter checked, payload decrypted.",
        send_downlink_action().example.clone(),
    )
    .with_parameters(params)
    .with_actions(vec![
        send_downlink_action(),
        request_status_action(),
        ignore_action(),
    ])
});

/// A downlink payload the model described, as bytes.
pub fn payload_bytes(v: &Value) -> Result<Vec<u8>> {
    let payload = v["payload"]
        .as_str()
        .context("payload is a string (use \"\" for none)")?;
    let data = match v.get("encoding").and_then(Value::as_str) {
        None | Some("utf8") => payload.as_bytes().to_vec(),
        Some("hex") => hex::decode(payload).context("payload is not hex")?,
        Some(e) => bail!("encoding {e:?} is utf8 or hex"),
    };
    Ok(data)
}

pub fn port_of(v: &Value) -> Result<u8> {
    let port = v["f_port"].as_u64().context("f_port is a number 1..223")?;
    ensure!(
        (1..=223).contains(&port),
        "f_port {port} is not an application port (1..223)"
    );
    Ok(port as u8)
}

pub fn confirmed_of(v: &Value) -> Result<bool> {
    match v.get("confirmed").filter(|c| !c.is_null()) {
        None => Ok(false),
        Some(c) => c.as_bool().context("confirmed is true or false"),
    }
}

pub fn check_downlink(v: &Value) -> Result<()> {
    port_of(v)?;
    confirmed_of(v)?;
    let data = payload_bytes(v)?;
    ensure!(
        data.len() <= MAX_DOWNLINK_PAYLOAD,
        "a payload is at most {MAX_DOWNLINK_PAYLOAD} bytes at any EU868 data rate"
    );
    Ok(())
}

pub fn devices_param() -> ParameterDefinition {
    ParameterDefinition {
        name: "devices".into(),
        type_hint: "array".into(),
        description: format!(
            "The devices this network knows, at most {}. OTAA: {{\"dev_eui\", \"app_eui\" (JoinEUI, default all zeros), \"app_key\"}}. ABP: {{\"dev_addr\", \"nwk_s_key\", \"app_s_key\", \"dev_eui\" optional}}. Each may carry a \"name\". Hex, as printed on the device. Keys stay in Rust: the model sees names and EUIs, never a key.",
            super::MAX_DEVICES
        ),
        required: true,
        example: json!([
            {"name": "meter-1", "dev_eui": "0102030405060708", "app_eui": "0000000000000000", "app_key": "2b7e151628aed2a6abf7158809cf4f3c"},
            {"name": "abp-node", "dev_addr": "26011bda", "nwk_s_key": "000102030405060708090a0b0c0d0e0f", "app_s_key": "0f0e0d0c0b0a09080706050403020100"}
        ]),
        default: None,
    }
}

pub fn region_param() -> ParameterDefinition {
    ParameterDefinition {
        name: "region".into(),
        type_hint: "string".into(),
        description: "Regional parameters for data rates, payload sizes and receive windows. Only EU868 is implemented.".into(),
        required: false,
        example: json!("EU868"),
        default: Some(json!(region::REGION)),
    }
}

#[derive(Default)]
pub struct LorawanProtocol;
impl LorawanProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for LorawanProtocol {
    fn protocol_name(&self) -> &'static str {
        "LoRaWAN"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>SEMTECH-UDP>LORAWAN"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "lorawan",
            "lora",
            "lorawan network server",
            "semtech udp",
            "packet forwarder",
            "gwmp",
        ]
    }
    fn description(&self) -> &'static str {
        "LoRaWAN 1.0.x network server over the Semtech UDP packet-forwarder protocol: gateways push uplinks, NetGet checks and decrypts them, the model admits joins and answers with downlinks"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept_join_action(),
            reject_join_action(),
            send_downlink_action(),
            request_status_action(),
            ignore_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![JOIN_EVENT.clone(), UPLINK_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            devices_param(),
            ParameterDefinition {
                name: "net_id".into(),
                type_hint: "string".into(),
                description: "The network's 24-bit NetID, hex; its low 7 bits prefix every DevAddr NetGet assigns (type 0)".into(),
                required: false,
                example: json!("000013"),
                default: Some(json!(super::DEFAULT_NET_ID)),
            },
            region_param(),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(1700)
            .implementation("Hand-written Semtech UDP packet-forwarder protocol v1/v2 (src/server/lorawan/semtech.rs: PUSH_DATA/PUSH_ACK, PULL_DATA/PULL_ACK, PULL_RESP, TX_ACK with its error codes) and LoRaWAN 1.0.x MAC (src/server/lorawan/mac.rs): Join Request MIC, DevNonce reuse, Join Accept encryption and MIC, NwkSKey/AppSKey derivation, data MIC with 32-bit FCnt reconstruction and MAX_FCNT_GAP, FRMPayload encryption, LinkCheck and DevStatus MAC commands; EU868 data rates, payload limits and RX1/RX2 (src/server/lorawan/region.rs); aes for the block cipher, AES-CMAC by RFC 4493")
            .llm_control("Whether each OTAA device that proved its AppKey may join, and every application downlink: port, payload, confirmed, and whether to ask the device for its status")
            .e2e_testing("tests/server/lorawan: raw packet-forwarder datagrams for every bound, replay and fail-closed path, the LoRaTap pcap oracle (tshark's lorawan dissector verifying MICs and decrypting with the keys), and LWN Simulator (Go, brocaar/lorawan) as an independent gateway and device that joins, decrypts the Join Accept and checks downlink MICs")
            .notes("Experimental: one independent device implementation (LWN Simulator) and the pair job had not run in CI when it landed. EU868 only; LoRaWAN 1.0.x only (no 1.1 keys, no rejoin), class A only, no ADR, no FSK (DR7). No radio: NetGet speaks to packet forwarders, which own the radio. Downlinks are scheduled on the gateway's tmst in RX1, or RX2 when the model answered too late for RX1; an application payload that misses both waits for the next uplink, and a Join Accept that misses both is not sent. Fail-closed: a model that fails, answers invalidly or says nothing admits no device and sends no downlink at all. Bounds: datagrams ≤ 8 KiB, ≤ 16 rxpk per PUSH_DATA, JSON depth ≤ 8, PHYPayload by the data rate's maximum, ≤ 256 devices, ≤ 64 gateways, ≤ 8 queued downlinks per device, ≤ 16 model calls in flight.")
            .deliberately_silent()
            .max_inbound_bytes(super::semtech::MAX_DATAGRAM)
            // A device's uplinks are a session (FCnt, queued downlinks, a status asked for and
            // answered later), and each is read in the light of the last. The history is kept
            // on the gateway's connection — the peer NetGet actually talks to — so it holds
            // the recent uplinks of every device that gateway carries.
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "LoRaWAN network server on UDP 1700 for one OTAA meter; admit it and answer every uplink on port 10 with the text ok"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let devices = json!([{"name": "meter-1", "dev_eui": "0102030405060708", "app_eui": "0000000000000000", "app_key": "2b7e151628aed2a6abf7158809cf4f3c"}]);
        let llm = json!({"type": "open_server", "base_stack": "lorawan", "port": 1700,
            "startup_params": {"devices": devices},
            "instruction": "Admit meter-1. When it reports a reading, answer on port 10 with ok."});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "lorawan_join_request", "handler": {"type": "static", "actions": [{"type": ACCEPT_JOIN}]}},
            {"event_pattern": "lorawan_uplink", "handler": {"type": "static", "actions": [{"type": IGNORE}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin); e=i['event']\nif i['event_type_id']=='lorawan_join_request':\n  a=[{'type':'lorawan_accept_join'}]\nelse:\n  a=[{'type':'lorawan_send_downlink','f_port':10,'payload':'ok'}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "IoT"
    }
}

impl Server for LorawanProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let name = action["type"].as_str().unwrap_or_default().to_string();
        match name.as_str() {
            ACCEPT_JOIN | REJECT_JOIN | REQUEST_STATUS | IGNORE => {}
            SEND_DOWNLINK => check_downlink(&action)?,
            _ => bail!("Unknown LoRaWAN server action"),
        }
        Ok(ActionResult::Custom { name, data: action })
    }
}

/// The text-or-hex form of a payload for an event.
pub fn payload_field(data: &[u8]) -> (Value, &'static str) {
    match std::str::from_utf8(data) {
        Ok(s) if !crate::utils::sanitize::has_controls(s) => (json!(s), "utf8"),
        _ => (json!(hex::encode(data)), "hex"),
    }
}

/// A device's DevEUI as an event field.
pub fn eui_field(e: Option<&mac::Eui>) -> Value {
    e.map(|e| json!(mac::eui_hex(e))).unwrap_or(Value::Null)
}

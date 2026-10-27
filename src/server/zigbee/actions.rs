//! What the model decides as a Zigbee co-processor: which described devices join when the
//! host opens the network, and how a device answers the ZCL requests its description does not
//! cover (cluster commands, attribute writes, manufacturer-specific frames). Asked through the
//! dashboard or MCP `send_to_peer`, it also makes devices report attributes, press buttons,
//! join and leave. ASH, EZSP, descriptors, addresses, attribute reads and discovery are Rust's.
use super::device;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const JOIN_DEVICE: &str = "zigbee_join_device";
pub const IGNORE: &str = "zigbee_ignore";
pub const DEFAULT_RESPONSE: &str = "zigbee_default_response";
pub const SET_ATTRIBUTES: &str = "zigbee_set_attributes";
pub const CLUSTER_RESPONSE: &str = "zigbee_cluster_response";
pub const NO_RESPONSE: &str = "zigbee_no_response";
pub const REPORT_ATTRIBUTES: &str = "zigbee_report_attributes";
pub const SEND_COMMAND: &str = "zigbee_send_command";
pub const LEAVE_DEVICE: &str = "zigbee_leave_device";

/// Devices one permit-joining answer may admit.
pub const MAX_JOINS_PER_ANSWER: usize = 8;

fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
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

fn device_param() -> Parameter {
    p(
        "device",
        "string",
        "The device's name or IEEE address (\"00:12:4b:00:01:02:03:04\")",
        true,
    )
}

fn attributes_param(cluster_required: bool) -> Parameter {
    p(
        "attributes",
        "array",
        if cluster_required {
            "Attribute values: [{\"cluster\": \"on_off\" or 6, \"attribute\": 0, \"type\": \"bool\" (optional when the attribute is described), \"value\": true}]. Types: bool, uint8/16/24/32, int8/16/24/32, enum8/16, map8/16/32, single, string, octets (hex)"
        } else {
            "Attribute values: [{\"attribute\": 0, \"value\": true}] — cluster defaults to the request's; type is optional when the attribute is described. Types: bool, uint8/16/24/32, int8/16/24/32, enum8/16, map8/16/32, single, string, octets (hex)"
        },
        true,
    )
}

pub fn join_device_action() -> ActionDefinition {
    action(
        JOIN_DEVICE,
        "Make a device join the network while it is open: one of the devices described at startup by name or IEEE, or a new description ({\"name\", \"ieee\", \"type\": router|end_device|sleepy_end_device, \"manufacturer\", \"model\", \"endpoints\": [{\"id\", \"profile\", \"device_type\", \"in_clusters\", \"out_clusters\", \"attributes\"}]}). NetGet reports the trust-center join and the device's announcement; the host then interviews it, answered from the description.",
        vec![p(
            "device",
            "string",
            "A described device's name or IEEE address, or a full device description object",
            true,
        )],
        json!({"type": JOIN_DEVICE, "device": "kitchen-lamp"}),
        "-> Zigbee device {device} joins",
    )
}

pub fn ignore_action() -> ActionDefinition {
    action(
        IGNORE,
        "Let no device join this time.",
        vec![],
        json!({"type": IGNORE}),
        "-> Zigbee no join",
    )
}

pub fn default_response_action() -> ActionDefinition {
    action(
        DEFAULT_RESPONSE,
        "Answer the request with a ZCL status. For a cluster command this is its Default Response (not sent for success when the host disabled it); for an attribute write it is the Write Attributes Response, and success stores the values the host wrote.",
        vec![p(
            "status",
            "string",
            "success, failure, unsup_cluster_command, invalid_value, read_only, not_authorized, unsupported_attribute, invalid_field, … or the status byte",
            true,
        )],
        json!({"type": DEFAULT_RESPONSE, "status": "success"}),
        "-> Zigbee status {status}",
    )
}

pub fn set_attributes_action() -> ActionDefinition {
    action(
        SET_ATTRIBUTES,
        "Change the device's own attribute values (an On command turns on_off true), so later reads answer them; with report true the device also sends a Report Attributes to the coordinator.",
        vec![
            attributes_param(false),
            p(
                "report",
                "boolean",
                "Also report the new values to the coordinator (default false)",
                false,
            ),
        ],
        json!({"type": SET_ATTRIBUTES, "attributes": [{"attribute": 0, "value": true}], "report": true}),
        "-> Zigbee attributes set",
    )
}

pub fn cluster_response_action() -> ActionDefinition {
    action(
        CLUSTER_RESPONSE,
        "Answer with a cluster-specific response command (server to client), its payload as hex.",
        vec![
            p("command_id", "number", "The response command id", true),
            p(
                "payload",
                "string",
                "The command's payload as hex digits (may be empty)",
                true,
            ),
            p("encoding", "string", "hex (the only encoding)", true),
        ],
        json!({"type": CLUSTER_RESPONSE, "command_id": 0, "payload": "00", "encoding": "hex"}),
        "-> Zigbee cluster response {command_id}",
    )
}

pub fn no_response_action() -> ActionDefinition {
    action(
        NO_RESPONSE,
        "The device acknowledges the frame and sends nothing back; the host times out as it would on a real radio.",
        vec![],
        json!({"type": NO_RESPONSE}),
        "-> Zigbee device silent",
    )
}

pub fn report_attributes_action() -> ActionDefinition {
    action(
        REPORT_ATTRIBUTES,
        "A joined device reports attribute values to the coordinator (Report Attributes); the values are also stored as the device's own.",
        vec![
            device_param(),
            p("endpoint", "number", "The device endpoint reporting", true),
            attributes_param(true),
        ],
        json!({"type": REPORT_ATTRIBUTES, "device": "kitchen-lamp", "endpoint": 1,
               "attributes": [{"cluster": "on_off", "attribute": 0, "value": false}]}),
        "-> Zigbee report from {device}",
    )
}

pub fn send_command_action() -> ActionDefinition {
    action(
        SEND_COMMAND,
        "A joined device sends a cluster command to the coordinator as a client would: a button press (on_off toggle), a dimmer step.",
        vec![
            device_param(),
            p("endpoint", "number", "The device endpoint sending", true),
            p("cluster", "string", "Cluster name (on_off, level_control, …) or id", true),
            p(
                "command",
                "string",
                "Command name (toggle, on, off, step, move_to_level, …) or id",
                true,
            ),
            p(
                "payload",
                "string",
                "The command's arguments as hex digits (default empty)",
                false,
            ),
            p("encoding", "string", "hex (the only encoding)", false),
        ],
        json!({"type": SEND_COMMAND, "device": "wall-switch", "endpoint": 1, "cluster": "on_off", "command": "toggle"}),
        "-> Zigbee {device} sends {command}",
    )
}

pub fn leave_device_action() -> ActionDefinition {
    action(
        LEAVE_DEVICE,
        "A joined device leaves the network; the host is told it left.",
        vec![device_param()],
        json!({"type": LEAVE_DEVICE, "device": "kitchen-lamp"}),
        "-> Zigbee {device} leaves",
    )
}

pub static PERMIT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zigbee_permit_joining",
        "The host opened the network for joining. Answer with zigbee_join_device for each device that joins now, or zigbee_ignore; anything else admits nobody.",
        join_device_action().example.clone(),
    )
    .with_parameters(vec![
        p("duration_secs", "number", "How long the network stays open", true),
        p(
            "waiting_devices",
            "array",
            "Devices described and not in the network: name, ieee, type, endpoints",
            true,
        ),
        p(
            "joined_devices",
            "array",
            "Names of the devices already in the network",
            true,
        ),
        p("channel", "number", "The network's channel", true),
        p("pan_id", "string", "The network's PAN ID, hex", true),
    ])
    .with_actions(vec![join_device_action(), ignore_action()])
});

pub static ZCL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zigbee_zcl_request",
        "The host sent a device a ZCL frame its description does not answer: a cluster command, an attribute write or a manufacturer-specific frame. Answer as the device: zigbee_set_attributes for the state it changes, zigbee_default_response with a status, zigbee_cluster_response for a command with its own response, or zigbee_no_response. With no answer the device replies FAILURE.",
        default_response_action().example.clone(),
    )
    .with_parameters(vec![
        p("device", "string", "The device's name", true),
        p("ieee", "string", "The device's IEEE address", true),
        p("nwk", "string", "The device's network address, hex", true),
        p("endpoint", "number", "The device endpoint addressed", true),
        p("cluster", "string", "Cluster name, or hex id when NetGet has no name for it", true),
        p("kind", "string", "cluster_command, write_attributes or manufacturer_global", true),
        p("command", "string", "Command name, or hex id when NetGet has no name for it", true),
        p(
            "command_id",
            "number",
            "The ZCL command identifier byte the host sent (0-255)",
            true,
        ),
        p(
            "manufacturer_code",
            "number",
            "The frame's manufacturer code, null when not manufacturer specific",
            false,
        ),
        p(
            "default_response_disabled",
            "boolean",
            "The host asked for no Default Response on success",
            true,
        ),
        p(
            "fields",
            "object",
            "What NetGet decoded: the writes ({attribute, type, value, described}) or the command's arguments (level, transition_tenths, …)",
            true,
        ),
        p("payload", "string", "The frame's payload after the ZCL header, hex", true),
        p(
            "payload_encoding",
            "string",
            "How payload is written: always hex, two digits per byte",
            true,
        ),
        p(
            "current_attributes",
            "object",
            "The cluster's current attribute values on this endpoint, by id: {\"0x0000\": {\"type\": \"bool\", \"value\": false}}",
            true,
        ),
    ])
    .with_actions(vec![
        default_response_action(),
        set_attributes_action(),
        cluster_response_action(),
        no_response_action(),
    ])
});

/// Validate an action's shape; what it refers to (a device, an endpoint) is checked where it
/// is applied, against the network as it is then.
pub fn check(action: &Value) -> Result<()> {
    let kind = action["type"].as_str().unwrap_or_default();
    match kind {
        JOIN_DEVICE => {
            let d = action
                .get("device")
                .context("device names or describes the device")?;
            match d {
                Value::String(s) => ensure!(!s.trim().is_empty(), "device is not empty"),
                Value::Object(_) => {
                    device::parse_device(d, &[])?;
                }
                _ => bail!("device is a name, an IEEE address or a description object"),
            }
        }
        IGNORE | NO_RESPONSE => {}
        DEFAULT_RESPONSE => {
            device::zcl_status::parse(action.get("status").context("status is required")?)?;
        }
        SET_ATTRIBUTES => {
            let a = action["attributes"]
                .as_array()
                .context("attributes is a list")?;
            ensure!(
                !a.is_empty() && a.len() <= device::MAX_ATTRIBUTES,
                "attributes holds 1 to {} values",
                device::MAX_ATTRIBUTES
            );
            if let Some(r) = action.get("report").filter(|v| !v.is_null()) {
                ensure!(r.is_boolean(), "report is true or false");
            }
        }
        CLUSTER_RESPONSE => {
            let id = action["command_id"]
                .as_u64()
                .context("command_id is a number")?;
            ensure!(id <= 0xFF, "command_id is one byte");
            hex_payload(action)?;
        }
        REPORT_ATTRIBUTES => {
            name_of(action)?;
            endpoint_of(action)?;
            let a = action["attributes"]
                .as_array()
                .context("attributes is a list")?;
            ensure!(
                !a.is_empty() && a.len() <= device::MAX_ATTRIBUTES,
                "attributes holds 1 to {} values",
                device::MAX_ATTRIBUTES
            );
            for x in a {
                device::parse_cluster(
                    x.get("cluster")
                        .context("each attribute names its cluster")?,
                )?;
            }
        }
        SEND_COMMAND => {
            name_of(action)?;
            endpoint_of(action)?;
            let cluster = device::parse_cluster(&action["cluster"])?;
            device::parse_command(cluster, &action["command"])?;
            if action.get("payload").is_some_and(|v| !v.is_null()) {
                hex_payload(action)?;
            }
        }
        LEAVE_DEVICE => {
            name_of(action)?;
        }
        _ => bail!("Unknown Zigbee action"),
    }
    Ok(())
}

pub fn name_of(action: &Value) -> Result<&str> {
    action["device"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .context("device is a device's name or IEEE address")
}

pub fn endpoint_of(action: &Value) -> Result<u8> {
    let e = action["endpoint"]
        .as_u64()
        .context("endpoint is a number 1..240")?;
    ensure!((1..=240).contains(&e), "endpoint is 1..240");
    Ok(e as u8)
}

/// A payload the model wrote as hex, with the encoding it must name.
pub fn hex_payload(action: &Value) -> Result<Vec<u8>> {
    let payload = match action.get("payload") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(v) => v.as_str().context("payload is hex digits")?,
    };
    match action.get("encoding").and_then(Value::as_str) {
        Some("hex") | None if payload.is_empty() => {}
        Some("hex") => {}
        _ => bail!("encoding is hex"),
    }
    let b = hex::decode(payload).context("payload is not hex")?;
    ensure!(
        b.len() + 3 <= device::MAX_APS_PAYLOAD,
        "a payload is at most {} bytes",
        device::MAX_APS_PAYLOAD - 3
    );
    Ok(b)
}

fn param(
    name: &str,
    type_hint: &str,
    description: &str,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required: false,
        example,
        default,
    }
}

pub fn example_devices() -> Value {
    json!([{
        "name": "kitchen-lamp",
        "ieee": "00:12:4b:00:1c:a1:b2:01",
        "type": "router",
        "manufacturer": "NetGet",
        "model": "Lamp-1",
        "endpoints": [{
            "id": 1, "profile": 260, "device_type": 256,
            "in_clusters": ["basic", "identify", "on_off", "level_control"],
            "out_clusters": [],
            "attributes": [
                {"cluster": "on_off", "attribute": 0, "type": "bool", "value": false},
                {"cluster": "level_control", "attribute": 0, "type": "uint8", "value": 254}
            ]
        }]
    }])
}

#[derive(Default)]
pub struct ZigbeeProtocol;
impl ZigbeeProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for ZigbeeProtocol {
    fn protocol_name(&self) -> &'static str {
        "Zigbee"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ASH>EZSP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "zigbee",
            "ezsp",
            "zigbee coordinator",
            "zigbee ncp",
            "ember znet",
            "silicon labs ezsp",
            "znp",
            "z-stack",
            "ti z-stack",
            "zigbee mt",
        ]
    }
    fn description(&self) -> &'static str {
        "A Zigbee coordinator's network co-processor reached over TCP, as network-attached coordinators are, speaking Silicon Labs EZSP over ASH (bellows/ZHA, Zigbee2MQTT's ember adapter) or TI Z-Stack's MT API (zigpy-znp, Zigbee2MQTT's zstack adapter): the host runs its network through it, and the model decides the network's devices and how they answer"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![
            report_attributes_action(),
            send_command_action(),
            join_device_action(),
            leave_device_action(),
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            join_device_action(),
            ignore_action(),
            default_response_action(),
            set_attributes_action(),
            cluster_response_action(),
            no_response_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![PERMIT_EVENT.clone(), ZCL_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            param(
                "dialect",
                "string",
                "The co-processor's firmware, and so the host dialect: ezsp (Silicon Labs EmberZNet — EZSP over ASH, for bellows/ZHA and Zigbee2MQTT's ember adapter) or znp (TI Z-Stack 3.x.0 — the MT API, for zigpy-znp and Zigbee2MQTT's zstack adapter)",
                json!("znp"),
                Some(json!(super::Dialect::Ezsp.name())),
            ),
            param(
                "ezsp_version",
                "number",
                "The EZSP protocol version the co-processor speaks, 14 to 17 (dialect ezsp only); a host asking for another switches to it",
                json!(17),
                Some(json!(super::ezsp::DEFAULT_VERSION)),
            ),
            param(
                "ieee",
                "string",
                "The co-processor's own EUI-64, most significant byte first",
                json!("00:0d:6f:00:0a:1b:2c:3d"),
                Some(json!(device::eui_display(super::ncp::DEFAULT_EUI64))),
            ),
            param(
                "network",
                "object",
                "A network already formed in the co-processor's flash: {\"channel\": 11..26, \"pan_id\": \"0x1a62\", \"extended_pan_id\": \"dd:dd:dd:dd:dd:dd:dd:dd\" (most significant first)}. Omit it and the host forms one.",
                json!({"channel": 15, "pan_id": "0x1a62", "extended_pan_id": "dd:dd:dd:dd:dd:dd:dd:dd"}),
                None,
            ),
            param(
                "network_key",
                "string",
                "The formed network's key, 32 hex digits in transmission order (as zigpy and Zigbee2MQTT write it); random when a network is given without one. Never shown to the model.",
                json!("01030507090b0d0f00020406080a0c0d"),
                None,
            ),
            param(
                "devices",
                "array",
                &format!(
                    "Devices that can join, at most {}: {{\"name\", \"ieee\", \"nwk\" (optional), \"type\": router|end_device|sleepy_end_device, \"manufacturer\", \"model\", \"power_source\": mains|battery, \"manufacturer_code\", \"endpoints\": [{{\"id\", \"profile\" (default 260), \"device_type\", \"in_clusters\", \"out_clusters\", \"attributes\": [{{\"cluster\", \"attribute\", \"type\", \"value\"}}]}}]}}. ZDO requests and attribute reads are answered from it at no model cost.",
                    device::MAX_DEVICES
                ),
                example_devices(),
                None,
            ),
            param(
                "decision_timeout_secs",
                "number",
                "How long a device waits for the model before answering FAILURE",
                json!(10),
                Some(json!(super::DEFAULT_DECISION_TIMEOUT.as_secs())),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            // No IANA assignment; 6638 is the TCP port network-attached EZSP coordinators
            // (SMLIGHT SLZB-06/07, TubesZB) serve their serial bridge on, and the one ZHA's
            // and Zigbee2MQTT's documentation use in their socket:// and tcp:// examples.
            .well_known_port(6638)
            .implementation("Two host dialects over one network, chosen by the dialect startup parameter. EZSP (default): hand-written ASH (src/server/zigbee/ash.rs: flag/escape stuffing, CANCEL and SUBSTITUTE, data randomisation, CRC-CCITT, DATA/ACK/NAK frame and ack numbers, a 3-frame retransmit window with UG101's adaptive 0.4–3.2 s timer, RST/RSTACK and the ERROR frame after 4 acknowledgement timeouts) and EZSP versions 8–17 (src/server/zigbee/ezsp.rs, ncp.rs speak 14–17: the legacy-format version negotiation, the extended frame format, 63 commands including the energy scan, the stackStatus, messageSent, incomingMessage, trustCenterJoin, childJoin, energyScanResult and scanComplete callbacks, invalidCommand(ERROR_INVALID_FRAME_ID) for anything else; legacy.rs carries 8–13: one-byte EmberStatus/EzspStatus, the pre-14 layouts, getKey/getKeyTableEntry/addOrUpdateKeyTableEntry/addTransientLinkKey/becomeTrustCenter/getAddressTableRemoteEui64/NodeId). ZNP: TI Z-Stack 3.x.0 as Koenkk's CC2652 coordinator firmware builds it (SYS_VERSION product 1, 2.7.1, build 20240710) — MT framing (src/server/zigbee/mt.rs: SOF, length ≤ 250, cmd0/cmd1, XOR FCS, RPC error SRSP) and the command set both open Z-Stack hosts send (src/server/zigbee/znp.rs: SYS, AF, ZDO, UTIL and APP_CNF; OSAL and extended NV memory kept as Z-Stack keeps it, STARTUP_OPTION on reset, BDB formation from the commissioning items, the aligned 116-byte NIB as the source of the network; zstack.rs the session). The devices behind both (src/server/zigbee/device.rs, network.rs) answer ZDO descriptors, address, bind and management requests and ZCL attribute reads, discovery and reporting configuration from their descriptions")
            .llm_control("Which described devices join when the host permits joining; how a device answers cluster commands, attribute writes and manufacturer-specific frames (status, attribute changes and reports, cluster responses, silence); attribute reports, button presses, joins and leaves on request")
            .e2e_testing("tests/server/zigbee: ASH, EZSP and MT framing, every bound and the fail-closed path over raw TCP in both dialects, and the independent hosts of each — EZSP: zigpy's bellows (CLI info/form/permit/devices and a zigpy application that interviews, switches and reads a device, at every EZSP version from 8 to 17) and zigbee-herdsman's ember adapter (at 13 and 17); Z-Stack: zigpy-znp through zigpy's application and zigbee-herdsman's zstack adapter, each forming a network on an empty co-processor and resuming the one the model described, interviewing a joined device, switching it and receiving its report")
            .notes("Experimental: this tests the host-to-co-processor link (ASH/EZSP or MT over TCP), not Zigbee over the air — there is no radio, no 802.15.4 MAC, no NWK/APS security; devices are simulated behind the co-processor and every frame they send is built from their description or the model's answer; energy scans read every channel clear. Server only: no independent EZSP or ZNP firmware simulator exists to test a client against. No tshark dissector reads ASH, EZSP or MT/ZNP (checked in 4.2.2 and 4.6.9), so there is no pcap oracle. EZSP 8–17 (4–7 use other frame headers and are not spoken; herdsman refuses below 13). Z-Stack 3.x.0 only (not 1.2 or 3.0.x); commands neither Z-Stack host sends get the firmware's RPC error. Fail-closed: a ZCL request the model fails to answer (error, timeout, nothing usable) is answered with ZCL Default Response FAILURE (0x01) after the APS acknowledgement (EZSP messageSent SUCCESS, Z-Stack AF_DATA_CONFIRM SUCCESS), as a device whose application rejected the command; a permit-joining question it fails admits nobody. Bounds: one host connection at a time (the co-processor has one UART), ASH frames ≤ 223 bytes unstuffed, MT frames ≤ 250 data bytes, APS payloads ≤ 82 bytes, ≤ 32 devices, ≤ 8 endpoints, 32 clusters and 64 attributes each, ≤ 512 NV items of ≤ 1024 bytes, ≤ 8 model calls in flight, 64 queued callbacks.")
            .answers_on_failure()
            .max_inbound_bytes(super::MAX_INBOUND_FRAME)
            // A host's session with its co-processor is one long conversation: the devices it
            // interviewed, the commands it sent and the states they left.
            .history(HistoryMode::Last(SESSION_HISTORY_ENTRIES))
            .batching(BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Zigbee coordinator (EZSP) on TCP 6638 with one lamp that joins when the host permits joining and turns on and off when told"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_server", "base_stack": "zigbee", "port": 6638,
            "startup_params": {"devices": example_devices()},
            "instruction": "When the host permits joining, let kitchen-lamp join. When it is switched, set on_off and report it."});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "zigbee_permit_joining", "handler": {"type": "static", "actions": [{"type": JOIN_DEVICE, "device": "kitchen-lamp"}]}},
            {"event_pattern": "zigbee_zcl_request", "handler": {"type": "static", "actions": [{"type": DEFAULT_RESPONSE, "status": "success"}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin); e=i['event']\nif i['event_type_id']=='zigbee_permit_joining':\n  a=[{'type':'zigbee_join_device','device':'kitchen-lamp'}]\nelif e.get('cluster')=='on_off' and e.get('command') in ('on','off'):\n  a=[{'type':'zigbee_set_attributes','attributes':[{'attribute':0,'value':e['command']=='on'}],'report':True},{'type':'zigbee_default_response','status':'success'}]\nelse:\n  a=[{'type':'zigbee_default_response','status':'unsup_cluster_command'}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "IoT"
    }
}

impl Server for ZigbeeProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        check(&action)?;
        let name = action["type"].as_str().unwrap_or_default().to_string();
        Ok(ActionResult::Custom { name, data: action })
    }
}

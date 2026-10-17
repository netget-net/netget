//! What the model can do as an OpenFlow 1.3 switch: send packets up to the controller
//! (PACKET_IN), report port changes (PORT_STATUS) and flow removals (FLOW_REMOVED). Rust
//! answers everything a controller asks a switch — FEATURES, ECHO, BARRIER, GET_CONFIG, ROLE,
//! the multipart queries — from the switch the startup parameters describe and the flow table
//! the controller's FLOW_MODs built; the model sees each FLOW_MOD and PACKET_OUT as a
//! structured event.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::server::openflow::fields;
use crate::server::openflow::packet;
use crate::server::openflow::wire;
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// The most ports a described switch may have.
pub const MAX_PORTS: usize = 64;
pub const DEFAULT_N_TABLES: u64 = 254;
pub const DEFAULT_DATAPATH_ID: &str = "0000000000000001";

#[derive(Default)]
pub struct OpenFlowClientProtocol;

impl OpenFlowClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

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
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(format!(
            "-> openflow {}",
            name.trim_start_matches("openflow_")
        ))),
    }
}

fn packet_in_action() -> ActionDefinition {
    action(
        "openflow_packet_in",
        "Send a packet up to the controller as if it arrived on one of this switch's ports \
         (PACKET_IN). Describe it by its headers: eth_src, eth_dst (default broadcast), optional \
         vlan {vid,pcp}, and one of arp {op: request|reply, spa, tpa, sha, tha}, ipv4 \
         {src,dst,ttl} or ipv6 {src,dst,hop_limit}, with optional icmp/icmpv6 \
         {type,code,id,seq}, udp {src_port,dst_port} or tcp {src_port,dst_port,flags,seq,ack}, \
         and payload_text. NetGet builds the bytes and computes every checksum",
        vec![
            p(
                "in_port",
                "number",
                "The port it arrived on (one of the switch's ports)",
                true,
            ),
            p("packet", "object", "The packet's headers", true),
            p(
                "reason",
                "string",
                "no_match (default: no flow matched), action (a flow sent it) or invalid_ttl",
                false,
            ),
            p(
                "table_id",
                "number",
                "The table that sent it up (default 0)",
                false,
            ),
            p(
                "cookie",
                "string",
                "Cookie of the flow that sent it up, as hex (\"0x1f\") or decimal (default 0)",
                false,
            ),
        ],
        json!({
            "type": "openflow_packet_in",
            "in_port": 1,
            "packet": {
                "eth_src": "02:00:00:00:00:01",
                "eth_dst": "ff:ff:ff:ff:ff:ff",
                "arp": {"op": "request", "spa": "10.0.0.1", "tpa": "10.0.0.2"}
            }
        }),
    )
}

fn port_status_action() -> ActionDefinition {
    action(
        "openflow_port_status",
        "Tell the controller a port was added, deleted or changed (PORT_STATUS); the switch's \
         port list changes with it, so later port queries agree",
        vec![
            p("reason", "string", "add, delete or modify", true),
            p("port_no", "number", "The port number", true),
            p(
                "name",
                "string",
                "The port's name, for an added port (under 16 bytes)",
                false,
            ),
            p(
                "hw_addr",
                "string",
                "The port's MAC address, for an added port",
                false,
            ),
            p("link_down", "boolean", "True when the link is down", false),
            p(
                "admin_down",
                "boolean",
                "True when the port is administratively down",
                false,
            ),
        ],
        json!({"type": "openflow_port_status", "reason": "modify", "port_no": 2, "link_down": true}),
    )
}

fn flow_removed_action() -> ActionDefinition {
    action(
        "openflow_flow_removed",
        "Remove a flow the controller installed and tell it so (FLOW_REMOVED), as if it timed \
         out or was deleted. The flow is the one with this priority and exactly this match in \
         that table",
        vec![
            p("priority", "number", "The flow's priority, 0-65535", true),
            p(
                "match",
                "object",
                "The flow's match, as the controller installed it",
                true,
            ),
            p("table_id", "number", "Its table (default 0)", false),
            p(
                "reason",
                "string",
                "idle_timeout (default), hard_timeout or delete",
                false,
            ),
        ],
        json!({"type": "openflow_flow_removed", "priority": 1, "match": {"in_port": 1}, "reason": "idle_timeout"}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the connection to the controller",
        vec![],
        json!({"type": "disconnect"}),
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        packet_in_action(),
        port_status_action(),
        flow_removed_action(),
        disconnect_action(),
    ]
}

fn ev(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, packet_in_action().example.clone())
        .with_parameters(params)
        .with_actions(actions())
        .with_log_template(LogTemplate::new().with_info(format!("openflow: {id}")))
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "openflow_controller_connected",
        "The controller finished the handshake: it negotiated OpenFlow 1.3 and read the \
         switch's features.",
        vec![
            p("controller", "string", "The controller's address", true),
            p("version", "string", "Negotiated OpenFlow version", true),
            p("datapath_id", "string", "This switch's datapath id", true),
            p("ports", "array", "This switch's ports", true),
        ],
    )
});

pub static FLOW_MOD_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        ev(
        "openflow_flow_mod_received",
        "The controller added, changed or removed flows (FLOW_MOD). The switch's flow table has \
         already been updated.",
        vec![
            p(
                "command",
                "string",
                "add, modify, modify_strict, delete or delete_strict",
                true,
            ),
            p("table_id", "number", "The flow table the FLOW_MOD addressed", true),
            p("priority", "number", "The flow's priority, 0-65535", true),
            p("match", "object", "The flow's match, by field name", true),
            p("instructions", "array", "apply_actions, goto_table, … with their actions", true),
            p("idle_timeout", "number", "Seconds idle before expiry (0 = never)", true),
            p("hard_timeout", "number", "Seconds before expiry (0 = never)", true),
            p("cookie", "string", "The controller's cookie (hex)", true),
            p("flags", "array", "send_flow_rem, check_overlap, …", true),
            p("flows_affected", "number", "Flows added, changed or removed", true),
            p("flow_count", "number", "Flows now in the switch", true),
        ],
    )
    });

pub static PACKET_OUT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "openflow_packet_out_received",
        "The controller told the switch to send a packet (PACKET_OUT).",
        vec![
            p(
                "in_port",
                "number",
                "The port the packet is treated as arriving on",
                true,
            ),
            p(
                "actions",
                "array",
                "What to do with it, e.g. output to port 2 or flood",
                true,
            ),
            p(
                "packet",
                "object",
                "The packet's headers (eth_src, eth_dst, arp/ipv4/…)",
                true,
            ),
        ],
    )
});

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "openflow_error_received",
        "The controller sent an OpenFlow ERROR, usually about something this switch sent.",
        vec![
            p(
                "error_type",
                "string",
                "The OpenFlow error type, e.g. BAD_REQUEST",
                true,
            ),
            p(
                "error_code",
                "string",
                "The error code within that type, e.g. BAD_TYPE",
                true,
            ),
            p(
                "request",
                "object",
                "What it was about: type and xid",
                false,
            ),
        ],
    )
});

pub static DISCONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "openflow_disconnected",
        "The connection to the controller ended.",
        json!({"type": "disconnect"}),
    )
    .with_parameters(vec![p(
        "reason",
        "string",
        "Why the connection ended",
        true,
    )])
    .with_no_actions()
    .with_log_template(LogTemplate::new().with_info("openflow: disconnected ({reason})"))
});

/// A port of the switch, from the startup parameters or a port_status action.
pub fn port_from_json(v: &Value, defaults_from: Option<&wire::Port>) -> Result<wire::Port> {
    let port_no =
        fields::port_from_json(v.get("port_no").context("a port needs port_no")?, "port_no")?;
    ensure!(
        (1..wire::port::MAX).contains(&port_no),
        "port_no {port_no} is not a physical port (1-{})",
        wire::port::MAX - 1
    );
    let base = defaults_from.cloned();
    let name = match v.get("name").and_then(Value::as_str) {
        Some(n) => {
            ensure!(
                n.len() < wire::PORT_NAME_LEN && !crate::utils::sanitize::has_controls(n),
                "port name {n:?} must be under {} bytes without control characters",
                wire::PORT_NAME_LEN
            );
            n.to_string()
        }
        None => base
            .as_ref()
            .map(|b| b.name.clone())
            .unwrap_or_else(|| format!("p{port_no}")),
    };
    let hw_addr = match v.get("hw_addr").and_then(Value::as_str) {
        Some(m) => fields::parse_mac(m)?,
        None => base.as_ref().map(|b| b.hw_addr).unwrap_or([
            0x02,
            0x4e,
            0x47,
            0x00,
            (port_no >> 8) as u8,
            port_no as u8,
        ]),
    };
    let flag = |key: &str, current: bool| -> Result<bool> {
        match v.get(key) {
            None | Some(Value::Null) => Ok(current),
            Some(Value::Bool(b)) => Ok(*b),
            Some(other) => bail!("{key} is true or false, not {other}"),
        }
    };
    let admin_down = flag(
        "admin_down",
        base.as_ref()
            .is_some_and(|b| b.config & wire::PORT_CONFIG_DOWN != 0),
    )?;
    let link_down = flag(
        "link_down",
        base.as_ref()
            .is_some_and(|b| b.state & wire::PORT_STATE_LINK_DOWN != 0),
    )?;
    let speed = match v.get("curr_speed_kbps") {
        Some(s) if !s.is_null() => {
            let n = fields::number(s, "curr_speed_kbps")?;
            ensure!(n <= u32::MAX as u64, "curr_speed_kbps does not fit 32 bits");
            n as u32
        }
        _ => base.as_ref().map(|b| b.curr_speed).unwrap_or(10_000_000),
    };
    Ok(wire::Port {
        port_no,
        hw_addr,
        name,
        config: if admin_down {
            wire::PORT_CONFIG_DOWN
        } else {
            0
        },
        state: if link_down {
            wire::PORT_STATE_LINK_DOWN
        } else {
            wire::PORT_STATE_LIVE
        },
        curr: wire::PORT_FEATURES_DEFAULT,
        advertised: 0,
        supported: 0,
        peer: 0,
        curr_speed: speed,
        max_speed: speed,
    })
}

pub fn default_ports() -> Vec<wire::Port> {
    (1..=2)
        .filter_map(|n| port_from_json(&json!({"port_no": n}), None).ok())
        .collect()
}

/// The switch the startup parameters describe.
pub struct SwitchConfig {
    pub datapath_id: u64,
    pub ports: Vec<wire::Port>,
    pub n_tables: u8,
}

pub fn switch_config(
    ports: Option<&Vec<Value>>,
    dpid: Option<&str>,
    n_tables: Option<u64>,
) -> Result<SwitchConfig> {
    let datapath_id = fields::datapath_id_from_json(&json!(dpid.unwrap_or(DEFAULT_DATAPATH_ID)))
        .context("invalid datapath_id")?;
    let ports = match ports {
        None => default_ports(),
        Some(list) => {
            ensure!(!list.is_empty(), "a switch needs at least one port");
            ensure!(list.len() <= MAX_PORTS, "at most {MAX_PORTS} ports");
            let mut out: Vec<wire::Port> = Vec::new();
            for (i, v) in list.iter().enumerate() {
                let port = port_from_json(v, None).with_context(|| format!("port {i}"))?;
                ensure!(
                    !out.iter().any(|q| q.port_no == port.port_no),
                    "port {} is listed twice",
                    port.port_no
                );
                out.push(port);
            }
            out
        }
    };
    let n_tables = n_tables.unwrap_or(DEFAULT_N_TABLES);
    ensure!(
        (1..=254).contains(&n_tables),
        "n_tables is 1-254, not {n_tables}"
    );
    Ok(SwitchConfig {
        datapath_id,
        ports,
        n_tables: n_tables as u8,
    })
}

/// What an action asks for, validated.
pub enum Request {
    PacketIn {
        in_port: u32,
        frame: Vec<u8>,
        reason: u8,
        table_id: u8,
        cookie: u64,
    },
    PortStatus {
        reason: u8,
        spec: Value,
    },
    FlowRemoved {
        priority: u16,
        table_id: u8,
        matched: wire::Match,
        reason: u8,
    },
}

pub fn check(v: &Value) -> Result<Request> {
    let t = v
        .get("type")
        .and_then(Value::as_str)
        .context("an action needs a type")?;
    let num = |key: &str, default: u64, max: u64| -> Result<u64> {
        match v.get(key) {
            None | Some(Value::Null) => Ok(default),
            Some(x) => {
                let n = fields::number(x, key)?;
                ensure!(n <= max, "{key} is {n}, above {max}");
                Ok(n)
            }
        }
    };
    Ok(match t {
        "openflow_packet_in" => {
            let in_port = fields::port_from_json(
                v.get("in_port")
                    .context("openflow_packet_in needs in_port")?,
                "in_port",
            )?;
            let frame = packet::build(
                v.get("packet")
                    .context("openflow_packet_in needs a packet")?,
            )
            .context("invalid packet")?;
            let reason = match v
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("no_match")
            {
                "no_match" => wire::packet_in_reason::NO_MATCH,
                "action" => wire::packet_in_reason::ACTION,
                "invalid_ttl" => wire::packet_in_reason::INVALID_TTL,
                other => bail!("reason {other:?} is no_match, action or invalid_ttl"),
            };
            Request::PacketIn {
                in_port,
                frame,
                reason,
                table_id: num("table_id", 0, 254)? as u8,
                cookie: num("cookie", 0, u64::MAX)?,
            }
        }
        "openflow_port_status" => {
            let reason = match v.get("reason").and_then(Value::as_str) {
                Some("add") => 0,
                Some("delete") => 1,
                Some("modify") => 2,
                other => bail!("reason is add, delete or modify, not {other:?}"),
            };
            port_from_json(v, None)?;
            Request::PortStatus {
                reason,
                spec: v.clone(),
            }
        }
        "openflow_flow_removed" => {
            let reason = match v
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("idle_timeout")
            {
                "idle_timeout" => 0,
                "hard_timeout" => 1,
                "delete" => 2,
                other => bail!("reason {other:?} is idle_timeout, hard_timeout or delete"),
            };
            Request::FlowRemoved {
                priority: num("priority", 0x8000, 0xffff)? as u16,
                table_id: num("table_id", 0, 254)? as u8,
                matched: fields::match_from_json(v.get("match").unwrap_or(&Value::Null))?,
                reason,
            }
        }
        other => bail!(
            "unknown action {other:?}; actions are openflow_packet_in, openflow_port_status, \
             openflow_flow_removed, disconnect"
        ),
    })
}

impl Protocol for OpenFlowClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "OpenFlow"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>OPENFLOW"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["openflow", "openflow switch", "sdn switch", "openflow 1.3"]
    }
    fn description(&self) -> &'static str {
        "OpenFlow 1.3 switch that connects to a controller: answers its queries from a described datapath and ports, reports its FLOW_MODs and PACKET_OUTs, and sends packets up as the LLM describes them"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            FLOW_MOD_EVENT.clone(),
            PACKET_OUT_EVENT.clone(),
            ERROR_EVENT.clone(),
            DISCONNECTED_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "datapath_id".into(),
                type_hint: "string".into(),
                description: "The switch's 64-bit datapath id: 16 hex digits, 0x-prefixed hex, \
                              or eight colon-separated octets"
                    .into(),
                required: false,
                example: json!("00000000000000aa"),
                default: Some(json!(DEFAULT_DATAPATH_ID)),
            },
            ParameterDefinition {
                name: "ports".into(),
                type_hint: "array".into(),
                description: format!(
                    "The switch's ports (at most {MAX_PORTS}): objects with port_no, and \
                     optionally name, hw_addr, link_down, admin_down, curr_speed_kbps. Default: \
                     ports 1 and 2"
                ),
                required: false,
                example: json!([{"port_no": 1, "name": "eth1"}, {"port_no": 2, "name": "eth2", "hw_addr": "02:00:00:00:00:02"}]),
                default: None,
            },
            ParameterDefinition {
                name: "n_tables".into(),
                type_hint: "number".into(),
                description: "Flow tables the switch reports (1-254)".into(),
                required: false,
                example: json!(4),
                default: Some(json!(DEFAULT_N_TABLES)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-written OpenFlow 1.3 switch side, sharing the controller's codec (src/server/openflow/wire.rs): HELLO with a version bitmap, FEATURES_REPLY, ECHO both ways, BARRIER, GET_CONFIG/SET_CONFIG, ROLE, GET_ASYNC/SET_ASYNC, QUEUE_GET_CONFIG, and the DESC, PORT_DESC, FLOW, AGGREGATE, TABLE, PORT_STATS, GROUP and METER multipart queries (FLOW replies split into parts under the 64 KiB message limit). FLOW_MODs are validated (match prerequisites, duplicate fields, instruction and action lengths) and kept in a flow table of at most 4096 entries with add/modify/delete in strict and non-strict forms; a refused one is answered with the OpenFlow ERROR a switch sends")
            .llm_control("Which packets to send up (PACKET_IN, described by headers and built with checksums in Rust), port changes (PORT_STATUS) and flow removals (FLOW_REMOVED); it sees every FLOW_MOD, PACKET_OUT and ERROR the controller sends as a structured event")
            .e2e_testing("tests/client/openflow: os-ken (the OpenStack-maintained Ryu) running a learning-switch app and Open vSwitch's ovs-testcontroller; the table-miss flow each installs arrives as a FLOW_MOD event, a PACKET_IN the model injects is answered with the controller's PACKET_OUT (and a FLOW_MOD once the destination is learned), and the controller's own log shows the switch it saw; tshark's openflow_v4 dissector reads both directions")
            .notes("Experimental, though it meets the four conditions of the client bar (two independent controllers, os-ken and ovs-testcontroller, in tests that fail rather than skip; a real session; the model's PACKET_INs asserted from the controllers' side): its pair job had not run in CI when it landed, and nobody has reviewed it against the 1.3 spec line by line. No data plane — packets are what the model describes, PACKET_OUTs and flows are reported rather than forwarded, counters are zero. OpenFlow 1.3 only; no TLS, no groups or meters (queries answer empty, GROUP_MOD and METER_MOD are refused), no buffers (n_buffers 0), no auxiliary connections. Timeouts in installed flows are recorded, not enforced.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the OpenFlow controller at 127.0.0.1:6653 as a switch with two ports and send it an ARP request from port 1"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"OpenFlow","remote_addr":"127.0.0.1:6653",
            "startup_params":{"datapath_id":"00000000000000aa","ports":[{"port_no":1,"name":"eth1"},{"port_no":2,"name":"eth2"}]},
            "instruction":"Once the controller has installed its flows, send an ARP request for 10.0.0.2 from 10.0.0.1 in on port 1"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"openflow_controller_connected","handler":{"type":"static","actions":[packet_in_action().example]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0] = json!({"event_pattern":"openflow_flow_mod_received","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\na=[]\nif e['priority']==0:\n  a=[{'type':'openflow_packet_in','in_port':1,'packet':{'eth_src':'02:00:00:00:00:01','arp':{'op':'request','spa':'10.0.0.1','tpa':'10.0.0.2'}}}]\nprint(json.dumps({'actions':a}))"}});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
}

impl Client for OpenFlowClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}

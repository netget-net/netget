//! OpenFlow controller actions and events: what the model decides about a switch's traffic.
//!
//! Rust owns the OpenFlow 1.3 session (HELLO negotiation, FEATURES, SET_CONFIG, the port and
//! description queries, echo keepalive, xid matching, multipart reassembly) and every byte on
//! the wire. The model owns network policy: which flows to install, what to do with a packet
//! the switch did not know how to forward, and which statistics to ask for. It reads packets as
//! decoded headers and writes matches, instructions and actions as structured JSON
//! (`fields.rs`, `packet.rs`) — never as bytes.
//!
//! Six events, all raised in `src/server/openflow/mod.rs`:
//!
//! - `openflow_switch_connected` — a switch finished the handshake; install its table-miss flow
//! - `openflow_packet_in` — the switch sent a packet up
//! - `openflow_flow_removed` — a flow installed with `send_flow_rem` expired or was deleted
//! - `openflow_port_status` — a port was added, removed or changed
//! - `openflow_stats_reply` — the answer to `openflow_request_stats`
//! - `openflow_error` — the switch refused something, usually one of the model's own messages
use super::fields::{self, datapath_id_from_json};
use super::packet;
use super::wire::{self, mp, FlowMod, FlowStatsRequest, Match};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// How often a quiet switch is sent an ECHO_REQUEST, and how long it has to answer.
pub const DEFAULT_ECHO_INTERVAL_SECS: u64 = 15;
pub const MAX_ECHO_INTERVAL_SECS: u64 = 3600;

/// `Custom` result names shared with `mod.rs`.
pub const RESULT_FLOW_MOD: &str = "openflow_flow_mod";
pub const RESULT_PACKET_OUT: &str = "openflow_packet_out";
pub const RESULT_DROP: &str = "openflow_drop_packet";
pub const RESULT_STATS: &str = "openflow_request_stats";

#[derive(Clone, Default)]
pub struct OpenFlowProtocol;

impl OpenFlowProtocol {
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

fn table_miss_example() -> Value {
    json!({
        "type": "openflow_flow_mod",
        "command": "add",
        "priority": 0,
        "match": {},
        "actions": [{"type": "output", "port": "controller"}]
    })
}

fn flow_mod_action() -> ActionDefinition {
    ActionDefinition {
        name: "openflow_flow_mod".into(),
        description: format!(
            "Install, change or remove flow entries on this switch (FLOW_MOD). The match is an \
             object of field names to values — {fields} — where an address may be a CIDR \
             string (\"10.0.0.0/8\") and any maskable field may be {{\"value\": …, \"mask\": \
             …}}; prerequisites the fields imply are added for you (ipv4_dst adds eth_type \
             0x0800, tcp_dst adds ip_proto 6). An empty match matches everything, so priority \
             0 with an empty match and output to the controller is the table-miss flow. Give \
             either \"actions\" (applied immediately) or \"instructions\" ({instructions}). \
             Actions: {actions}; ports are numbers or controller, flood, all, in_port, local, \
             normal, table. An empty action list drops. Set packet_in_id to also release a \
             packet the switch buffered through the new flow",
            fields = fields::field_names(),
            instructions = fields::INSTRUCTION_TYPES,
            actions = fields::ACTION_TYPES,
        ),
        parameters: vec![
            p(
                "command",
                "string",
                "add (default), modify, modify_strict, delete or delete_strict",
                false,
            ),
            p(
                "match",
                "object",
                "Fields to match; {} matches everything",
                false,
            ),
            p(
                "actions",
                "array",
                "Actions to apply to matching packets, e.g. [{\"type\": \"output\", \"port\": 2}]",
                false,
            ),
            p(
                "instructions",
                "array",
                "Instead of actions: apply_actions, write_actions, clear_actions, goto_table, \
                 write_metadata, meter",
                false,
            ),
            p(
                "priority",
                "number",
                "0-65535, higher wins (default 32768)",
                false,
            ),
            p("table_id", "number", "Flow table (default 0)", false),
            p(
                "idle_timeout",
                "number",
                "Seconds without a match before the flow expires (0 = never)",
                false,
            ),
            p(
                "hard_timeout",
                "number",
                "Seconds before the flow expires regardless (0 = never)",
                false,
            ),
            p(
                "cookie",
                "string",
                "Opaque 64-bit value to tag the flow, as hex (\"0x1f\") or decimal; a string because a JSON number cannot carry every 64-bit value exactly",
                false,
            ),
            p(
                "cookie_mask",
                "string",
                "For modify/delete: which cookie bits must match, as hex (\"0xffff\") or decimal",
                false,
            ),
            p(
                "out_port",
                "number",
                "For delete: only flows that output to this port",
                false,
            ),
            p(
                "flags",
                "array",
                "send_flow_rem, check_overlap, reset_counts, no_pkt_counts, no_byt_counts",
                false,
            ),
            p(
                "packet_in_id",
                "string",
                "A packet_in_id from openflow_packet_in whose buffered packet the flow should \
                 also process",
                false,
            ),
        ],
        example: json!({
            "type": "openflow_flow_mod",
            "command": "add",
            "priority": 100,
            "idle_timeout": 60,
            "match": {"in_port": 1, "eth_dst": "02:00:00:00:00:02"},
            "actions": [{"type": "output", "port": 2}]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("OpenFlow FLOW_MOD queued")
                .with_debug("OpenFlow flow_mod: {json(.)}"),
        ),
    }
}

fn packet_out_action() -> ActionDefinition {
    ActionDefinition {
        name: "openflow_packet_out".into(),
        description: "Send a packet out of the switch (PACKET_OUT). By default it is the packet \
                      from the openflow_packet_in being answered; name another with \
                      packet_in_id, or describe a new one in \"packet\" (eth_src, eth_dst, \
                      optional vlan {vid,pcp}, and one of arp {op,spa,tpa,sha,tha}, ipv4 \
                      {src,dst,ttl} or ipv6 {src,dst,hop_limit} with optional icmp/icmpv6 \
                      {type,code,id,seq}, udp {src_port,dst_port} or tcp \
                      {src_port,dst_port,flags,seq,ack}, and payload_text). Actions are the \
                      same as in openflow_flow_mod; [{\"type\":\"output\",\"port\":\"flood\"}] \
                      floods it"
            .into(),
        parameters: vec![
            p(
                "actions",
                "array",
                "What to do with the packet, e.g. [{\"type\": \"output\", \"port\": 2}]; empty \
                 drops it",
                true,
            ),
            p(
                "packet_in_id",
                "string",
                "Which received packet to send (default: the one being answered)",
                false,
            ),
            p(
                "packet",
                "object",
                "A new packet described by its headers, instead of a received one",
                false,
            ),
            p(
                "in_port",
                "number",
                "The port the packet is treated as arriving on (default: where it arrived, or \
                 controller for a new packet)",
                false,
            ),
        ],
        example: json!({
            "type": "openflow_packet_out",
            "actions": [{"type": "output", "port": "flood"}]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("OpenFlow PACKET_OUT queued")
                .with_debug("OpenFlow packet_out: {json(.)}"),
        ),
    }
}

fn drop_action() -> ActionDefinition {
    ActionDefinition {
        name: "openflow_drop_packet".into(),
        description: "Do nothing with this packet: no PACKET_OUT and no flow. The switch \
                      discards it. Use this to decide 'drop' explicitly."
            .into(),
        parameters: vec![p("reason", "string", "Why, for the log", false)],
        example: json!({"type": "openflow_drop_packet", "reason": "not allowed"}),
        log_template: Some(LogTemplate::new().with_info("OpenFlow packet dropped by decision")),
    }
}

fn stats_action() -> ActionDefinition {
    ActionDefinition {
        name: "openflow_request_stats".into(),
        description: "Ask the switch for statistics (MULTIPART_REQUEST); the answer arrives as \
                      openflow_stats_reply. kind: flow (installed flows with counters; optional \
                      table_id, out_port, match), aggregate (totals over the same filter), \
                      table, port (counters; optional port_no), port_desc (the ports), desc \
                      (manufacturer and software)"
            .into(),
        parameters: vec![
            p(
                "kind",
                "string",
                "flow, aggregate, table, port, port_desc or desc",
                true,
            ),
            p(
                "table_id",
                "number",
                "flow/aggregate: one table (default all)",
                false,
            ),
            p(
                "out_port",
                "number",
                "flow/aggregate: only flows that output here",
                false,
            ),
            p(
                "match",
                "object",
                "flow/aggregate: only flows matching this",
                false,
            ),
            p("port_no", "number", "port: one port (default any)", false),
        ],
        example: json!({"type": "openflow_request_stats", "kind": "flow"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("OpenFlow {kind} statistics requested")
                .with_debug("OpenFlow stats request: {json(.)}"),
        ),
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "openflow_disconnect_switch".into(),
        description: "Close this switch's OpenFlow connection. The switch then falls back to its \
                      own fail mode and usually reconnects."
            .into(),
        parameters: vec![],
        example: json!({"type": "openflow_disconnect_switch"}),
        log_template: Some(
            LogTemplate::new().with_info("OpenFlow switch disconnected by decision"),
        ),
    }
}

pub static FLOW_MOD_ACTION: LazyLock<ActionDefinition> = LazyLock::new(flow_mod_action);
pub static PACKET_OUT_ACTION: LazyLock<ActionDefinition> = LazyLock::new(packet_out_action);
pub static DROP_ACTION: LazyLock<ActionDefinition> = LazyLock::new(drop_action);
pub static STATS_ACTION: LazyLock<ActionDefinition> = LazyLock::new(stats_action);
pub static DISCONNECT_ACTION: LazyLock<ActionDefinition> = LazyLock::new(disconnect_action);

fn control_actions() -> Vec<ActionDefinition> {
    vec![
        FLOW_MOD_ACTION.clone(),
        PACKET_OUT_ACTION.clone(),
        STATS_ACTION.clone(),
        DISCONNECT_ACTION.clone(),
    ]
}

pub static SWITCH_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "openflow_switch_connected",
        "An OpenFlow switch connected and finished the handshake. OpenFlow 1.3 switches drop \
         what matches no flow, so install a table-miss flow (priority 0, empty match, output to \
         controller) to see its traffic",
        table_miss_example(),
    )
    .with_parameters(vec![
        p("switch", "string", "The switch's address", true),
        p(
            "datapath_id",
            "string",
            "The switch's datapath id, 16 hex digits",
            true,
        ),
        p(
            "version",
            "string",
            "Negotiated OpenFlow version (1.3)",
            true,
        ),
        p("n_tables", "number", "Flow tables the switch has", true),
        p("n_buffers", "number", "Packets the switch can buffer", true),
        p(
            "capabilities",
            "array",
            "flow_stats, table_stats, port_stats, …",
            true,
        ),
        p(
            "ports",
            "array",
            "Ports: port_no, name, hw_addr, admin_down, link_down, live, curr_speed_kbps",
            true,
        ),
        p(
            "description",
            "object",
            "mfr_desc, hw_desc, sw_desc, serial_num, dp_desc",
            false,
        ),
    ])
    .with_actions(control_actions())
    .with_alternative_example(json!({"type": "openflow_request_stats", "kind": "port_desc"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("OpenFlow switch {datapath_id} connected from {switch}")
            .with_trace("OpenFlow switch connected: {json_pretty(.)}"),
    )
});

pub static PACKET_IN_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        EventType::new(
        "openflow_packet_in",
        "The switch sent a packet up (PACKET_IN): forward it with openflow_packet_out, install \
         a flow so the next ones are handled in the switch, or drop it",
        json!({
            "type": "openflow_packet_out",
            "actions": [{"type": "output", "port": "flood"}]
        }),
    )
    .with_parameters(vec![
        p(
            "packet_in_id",
            "string",
            "Names this packet for openflow_packet_out / openflow_flow_mod",
            true,
        ),
        p("datapath_id", "string", "The switch's datapath id, 16 hex digits", true),
        p("in_port", "number", "The port it arrived on (or a reserved name)", false),
        p("reason", "string", "no_match, action or invalid_ttl", true),
        p("table_id", "number", "The table that sent it up", true),
        p("cookie", "string", "Cookie of the flow that sent it up (hex)", true),
        p("buffered", "boolean", "True when the switch kept the packet in a buffer", true),
        p("total_len", "number", "The packet's full length", true),
        p("match", "object", "Pipeline fields the switch reported (in_port, …)", true),
        p(
            "packet",
            "object",
            "The packet's headers: eth_src, eth_dst, eth_type, vlans, and arp / ipv4 / ipv6 / \
             tcp / udp / icmp / icmpv6, payload_length and payload_text when printable",
            true,
        ),
    ])
    .with_actions(vec![
        PACKET_OUT_ACTION.clone(),
        FLOW_MOD_ACTION.clone(),
        DROP_ACTION.clone(),
        STATS_ACTION.clone(),
        DISCONNECT_ACTION.clone(),
    ])
    .with_alternative_example(json!({"type": "openflow_drop_packet", "reason": "policy"}))
    .with_alternative_example(json!({
        "type": "openflow_flow_mod",
        "priority": 10,
        "idle_timeout": 30,
        "match": {"eth_dst": "02:00:00:00:00:02"},
        "actions": [{"type": "output", "port": 2}]
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("OpenFlow packet-in {packet_in_id} on port {in_port} ({reason})")
            .with_debug("OpenFlow packet-in: {json(.)}"),
    )
    });

pub static FLOW_REMOVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "openflow_flow_removed",
        "A flow installed with the send_flow_rem flag was removed",
        json!({"type": "openflow_drop_packet", "reason": "nothing to do"}),
    )
    .with_parameters(vec![
        p(
            "datapath_id",
            "string",
            "The switch's datapath id, 16 hex digits",
            true,
        ),
        p(
            "reason",
            "string",
            "idle_timeout, hard_timeout, delete or group_delete",
            true,
        ),
        p("table_id", "number", "The flow table the flow was in", true),
        p("priority", "number", "The removed flow's priority", true),
        p(
            "cookie",
            "string",
            "The removed flow's cookie, in hex",
            true,
        ),
        p(
            "match",
            "object",
            "The removed flow's match, by field name",
            true,
        ),
        p("packet_count", "number", "Packets it matched", true),
        p("byte_count", "number", "Bytes it matched", true),
        p("duration_sec", "number", "How long it was installed", true),
    ])
    .with_actions(control_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("OpenFlow flow removed ({reason})")
            .with_debug("OpenFlow flow removed: {json(.)}"),
    )
});

pub static PORT_STATUS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "openflow_port_status",
        "A port on the switch was added, deleted or changed state",
        json!({"type": "openflow_request_stats", "kind": "port"}),
    )
    .with_parameters(vec![
        p(
            "datapath_id",
            "string",
            "The switch's datapath id, 16 hex digits",
            true,
        ),
        p("reason", "string", "add, delete or modify", true),
        p(
            "port",
            "object",
            "The port: port_no, name, hw_addr, admin_down, link_down, live",
            true,
        ),
    ])
    .with_actions(control_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("OpenFlow port status ({reason})")
            .with_debug("OpenFlow port status: {json(.)}"),
    )
});

pub static STATS_REPLY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "openflow_stats_reply",
        "The switch answered openflow_request_stats",
        json!({"type": "openflow_drop_packet", "reason": "statistics noted"}),
    )
    .with_parameters(vec![
        p(
            "datapath_id",
            "string",
            "The switch's datapath id, 16 hex digits",
            true,
        ),
        p(
            "kind",
            "string",
            "flow, aggregate, table, port, port_desc or desc",
            true,
        ),
        p(
            "entries",
            "array",
            "flow: match, instructions, priority, counters; table/port: counters; port_desc: \
             ports",
            false,
        ),
        p("summary", "object", "aggregate and desc answers", false),
        p(
            "truncated",
            "boolean",
            "True when entries were cut to the limit",
            false,
        ),
    ])
    .with_actions(control_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("OpenFlow {kind} statistics received")
            .with_trace("OpenFlow stats reply: {json_pretty(.)}"),
    )
});

pub static ERROR_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        EventType::new(
        "openflow_error",
        "The switch refused a message with an OpenFlow ERROR, usually one of yours: fix it and \
         send it again, or give up",
        json!({"type": "openflow_drop_packet", "reason": "giving up on that flow"}),
    )
    .with_parameters(vec![
        p("datapath_id", "string", "The switch's datapath id, 16 hex digits", true),
        p("error_type", "string", "The OpenFlow error type, e.g. BAD_MATCH", true),
        p("error_code", "string", "The error code within that type, e.g. BAD_PREREQ", true),
        p(
            "request",
            "object",
            "What it refused: the message type, its xid, and what NetGet sent it for",
            false,
        ),
    ])
    .with_actions(control_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("OpenFlow error {error_type}/{error_code}")
            .with_debug("OpenFlow error: {json(.)}"),
    )
    });

pub fn event_types() -> Vec<EventType> {
    vec![
        SWITCH_CONNECTED_EVENT.clone(),
        PACKET_IN_EVENT.clone(),
        FLOW_REMOVED_EVENT.clone(),
        PORT_STATUS_EVENT.clone(),
        STATS_REPLY_EVENT.clone(),
        ERROR_EVENT.clone(),
    ]
}

fn opt_num(v: &Value, key: &str, default: u64, max: u64) -> Result<u64> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(x) => {
            let n = fields::number(x, key)?;
            ensure!(n <= max, "{key} is {n}, above {max}");
            Ok(n)
        }
    }
}

/// A FLOW_MOD from the model's action. Its buffer id is `NO_BUFFER`; `mod.rs` substitutes the
/// buffer a `packet_in_id` names.
pub fn flow_mod_from_json(v: &Value) -> Result<FlowMod> {
    let c = v.get("command").and_then(Value::as_str).unwrap_or("add");
    let command = wire::flow_cmd::NAMES
        .iter()
        .position(|n| *n == c)
        .with_context(|| {
            format!(
                "command {c:?} is one of {}",
                wire::flow_cmd::NAMES.join(", ")
            )
        })? as u8;
    let deleting = matches!(
        command,
        wire::flow_cmd::DELETE | wire::flow_cmd::DELETE_STRICT
    );
    let table_id = match v.get("table_id") {
        Some(Value::String(s)) if s == "all" => wire::TABLE_ALL,
        _ => opt_num(v, "table_id", 0, 255)? as u8,
    };
    ensure!(
        table_id != wire::TABLE_ALL || deleting,
        "table_id all is only for delete"
    );
    let matched =
        fields::match_from_json(v.get("match").unwrap_or(&Value::Null)).context("invalid match")?;
    let instructions = fields::instructions_from_action(v).context("invalid instructions")?;
    let out_port = match v.get("out_port") {
        Some(x) if !x.is_null() => fields::port_from_json(x, "out_port")?,
        _ => wire::port::ANY,
    };
    Ok(FlowMod {
        cookie: opt_num(v, "cookie", 0, u64::MAX)?,
        cookie_mask: opt_num(v, "cookie_mask", 0, u64::MAX)?,
        table_id,
        command,
        idle_timeout: opt_num(v, "idle_timeout", 0, 0xffff)? as u16,
        hard_timeout: opt_num(v, "hard_timeout", 0, 0xffff)? as u16,
        priority: opt_num(v, "priority", 0x8000, 0xffff)? as u16,
        buffer_id: wire::NO_BUFFER,
        out_port,
        out_group: wire::GROUP_ANY,
        flags: fields::flow_flags_from_json(v.get("flags"))?,
        matched,
        instructions,
    })
}

/// What a PACKET_OUT sends.
pub enum PacketSource {
    /// A received packet: the named one, or (None) the one being answered.
    Received(Option<String>),
    /// A packet the model described, built here.
    Built(Vec<u8>),
}

pub struct PacketOutSpec {
    pub actions: Vec<wire::Action>,
    pub source: PacketSource,
    pub in_port: Option<u32>,
}

pub fn packet_out_from_json(v: &Value) -> Result<PacketOutSpec> {
    let actions = fields::actions_from_json(
        v.get("actions")
            .context("openflow_packet_out needs \"actions\" ([] drops the packet)")?,
    )
    .context("invalid actions")?;
    let source = match (
        v.get("packet").filter(|x| !x.is_null()),
        v.get("packet_in_id"),
    ) {
        (Some(_), Some(id)) if !id.is_null() => {
            bail!("give packet_in_id or packet, not both")
        }
        (Some(spec), _) => PacketSource::Built(packet::build(spec).context("invalid packet")?),
        (None, Some(Value::String(id))) => PacketSource::Received(Some(id.clone())),
        (None, Some(Value::Null)) | (None, None) => PacketSource::Received(None),
        (None, Some(other)) => bail!("packet_in_id is a string, not {other}"),
    };
    let in_port = match v.get("in_port") {
        Some(x) if !x.is_null() => Some(fields::port_from_json(x, "in_port")?),
        _ => None,
    };
    Ok(PacketOutSpec {
        actions,
        source,
        in_port,
    })
}

/// A multipart request (type, body) for `openflow_request_stats`.
pub fn stats_request_from_json(v: &Value) -> Result<(u16, Vec<u8>)> {
    let kind = v
        .get("kind")
        .and_then(Value::as_str)
        .context("openflow_request_stats needs a \"kind\"")?;
    let flow_filter = || -> Result<Vec<u8>> {
        let table_id = match v.get("table_id") {
            None | Some(Value::Null) => wire::TABLE_ALL,
            Some(Value::String(s)) if s == "all" => wire::TABLE_ALL,
            Some(x) => {
                let t = fields::number(x, "table_id")?;
                ensure!(t <= 255, "table_id is 0-254 or all");
                t as u8
            }
        };
        let out_port = match v.get("out_port") {
            Some(x) if !x.is_null() => fields::port_from_json(x, "out_port")?,
            _ => wire::port::ANY,
        };
        Ok(FlowStatsRequest {
            table_id,
            out_port,
            out_group: wire::GROUP_ANY,
            cookie: 0,
            cookie_mask: 0,
            matched: match v.get("match") {
                Some(m) if !m.is_null() => fields::match_from_json(m)?,
                _ => Match::default(),
            },
        }
        .encode())
    };
    Ok(match kind {
        "flow" => (mp::FLOW, flow_filter()?),
        "aggregate" => (mp::AGGREGATE, flow_filter()?),
        "table" => (mp::TABLE, Vec::new()),
        "port" => {
            let port = match v.get("port_no") {
                Some(x) if !x.is_null() => fields::port_from_json(x, "port_no")?,
                _ => wire::port::ANY,
            };
            let mut b = port.to_be_bytes().to_vec();
            b.extend_from_slice(&[0; 4]);
            (mp::PORT_STATS, b)
        }
        "port_desc" => (mp::PORT_DESC, Vec::new()),
        "desc" => (mp::DESC, Vec::new()),
        other => bail!("kind {other:?} is one of flow, aggregate, table, port, port_desc, desc"),
    })
}

/// A port as the model reads it.
pub fn port_json(port: &wire::Port) -> Value {
    json!({
        "port_no": fields::port_to_json(port.port_no),
        "name": port.name,
        "hw_addr": fields::mac_str(&port.hw_addr),
        "admin_down": port.config & wire::PORT_CONFIG_DOWN != 0,
        "link_down": port.state & wire::PORT_STATE_LINK_DOWN != 0,
        "live": port.state & wire::PORT_STATE_LIVE != 0,
        "curr_speed_kbps": port.curr_speed,
    })
}

impl Protocol for OpenFlowProtocol {
    fn protocol_name(&self) -> &'static str {
        "OpenFlow"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>OPENFLOW"
    }
    fn description(&self) -> &'static str {
        "OpenFlow 1.3 SDN controller: switches connect to it, and the LLM decides which flows to install and what to do with each packet a switch sends up"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an OpenFlow controller on port 6653 that acts as a learning switch: flood unknown destinations and install a flow once a MAC address is known"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "openflow",
            "openflow controller",
            "sdn controller",
            "openflow 1.3",
        ]
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(6653)
            // Every message a controller can send a switch is an instruction: a PACKET_OUT
            // forwards, a FLOW_MOD installs. With no answer from the model the packet is left
            // unforwarded — what the switch's own table miss does — and nothing is installed;
            // a default "flood" would be a forwarding decision nobody made.
            .deliberately_silent()
            .max_inbound_bytes(wire::MAX_MESSAGE_LEN)
            .implementation(
                "Hand-written OpenFlow 1.3 (wire version 0x04; no crate — rust_ofp is \
                 unmaintained and 1.0-only): HELLO with a version bitmap (1.4/1.5 negotiate \
                 down; 1.0-1.2 are refused with HELLO_FAILED), FEATURES, SET_CONFIG for whole \
                 packets, DESC and PORT_DESC multipart queries, ECHO keepalive both ways, xid \
                 matching of every reply, multipart reassembly, OXM matches with masks and \
                 prerequisites, all six instruction types and the action set of 1.3 \
                 (output, set-field, push/pop VLAN/MPLS/PBB, TTLs, group, queue), PACKET_IN, \
                 PACKET_OUT, FLOW_MOD, FLOW_REMOVED, PORT_STATUS and ERROR. Packets are decoded \
                 to Ethernet/VLAN/ARP/IPv4/IPv6/TCP/UDP/SCTP/ICMP/ICMPv6 headers and built back \
                 with checksums computed in Rust",
            )
            .llm_control(
                "Network policy: flows to install on connect, PACKET_OUT / FLOW_MOD / drop for \
                 each PACKET_IN, statistics queries, and reactions to FLOW_REMOVED, PORT_STATUS \
                 and the switch's ERRORs",
            )
            .e2e_testing(
                "tests/server/openflow: Open vSwitch (ovs-vswitchd with the userspace dummy \
                 datapath, unprivileged in a temp dir) connects as the switch; the model's \
                 table-miss and forwarding flows are read back with ovs-ofctl dump-flows, a \
                 packet injected with netdev-dummy/receive reaches the model as a PACKET_IN and \
                 its PACKET_OUT leaves the dummy port into a pcap; tshark's openflow_v4 \
                 dissector reads both directions. In-process: bounds, xid matching and the \
                 fail-closed paths from a raw socket",
            )
            .notes(
                "Experimental: one independent switch implementation (Open vSwitch); no second \
                 switch implementation is packaged for Ubuntu or Homebrew (CPqD's ofsoftswitch13 \
                 is source-only and was not attempted), no fuzz corpus has been run at length, and its pair job had not \
                 run in CI when it landed. OpenFlow 1.3 only — no 1.0 (POX- and NOX-era \
                 switches), no TLS (ssl: connections), no auxiliary connections, no \
                 GROUP_MOD/METER_MOD/TABLE_MOD/PORT_MOD actions for the model, no role \
                 (master/slave) management, no table-features query. Packets are described, \
                 never handed to the model as bytes; buffered packets are released by \
                 packet_in_id. On LLM failure nothing is sent and the packet is not forwarded \
                 (decision=fail_closed_llm_error).",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "echo_interval_secs".into(),
            type_hint: "number".into(),
            description: format!(
                "Seconds a switch may be silent before it is sent an ECHO_REQUEST; a switch \
                 that does not answer within the same time is disconnected (1-{MAX_ECHO_INTERVAL_SECS})"
            ),
            required: false,
            example: json!(10),
            default: Some(json!(DEFAULT_ECHO_INTERVAL_SECS)),
        }]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            flow_mod_action(),
            packet_out_action(),
            drop_action(),
            stats_action(),
            disconnect_action(),
        ]
    }

    fn get_event_types(&self) -> Vec<EventType> {
        event_types()
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 6653,
                "base_stack": "openflow",
                "instruction": "Be a learning switch. When a switch connects, install a \
                                table-miss flow to the controller. For each packet, remember \
                                which port its source MAC came from; if the destination is \
                                known install a flow to that port and send the packet there, \
                                otherwise flood it."
            }),
            json!({
                "type": "open_server",
                "port": 6653,
                "base_stack": "openflow",
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='openflow_switch_connected': a=[{'type':'openflow_flow_mod','priority':0,'match':{},'actions':[{'type':'output','port':'controller'}]}]\nelif t=='openflow_packet_in': a=[{'type':'openflow_packet_out','actions':[{'type':'output','port':'flood'}]}]\nprint(json.dumps({'actions':a}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 6653,
                "base_stack": "openflow",
                "event_handlers": [
                    {"event_pattern": "openflow_switch_connected", "handler": {"type": "static", "actions": [table_miss_example()]}},
                    {"event_pattern": "openflow_packet_in", "handler": {"type": "static", "actions": [
                        {"type": "openflow_packet_out", "actions": [{"type": "output", "port": "flood"}]}
                    ]}},
                    {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
                ]
            }),
        )
    }
}

impl Server for OpenFlowProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let echo = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_u64("echo_interval_secs"))
                .transpose()?
                .flatten()
                .unwrap_or(DEFAULT_ECHO_INTERVAL_SECS);
            ensure!(
                (1..=MAX_ECHO_INTERVAL_SECS).contains(&echo),
                "echo_interval_secs must be between 1 and {MAX_ECHO_INTERVAL_SECS}, got {echo}"
            );
            super::OpenFlowServer::spawn(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                std::time::Duration::from_secs(echo),
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let kind = action
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Missing 'type' field in action"))?;
        let custom = |name: &str| ActionResult::Custom {
            name: name.to_string(),
            data: action.clone(),
        };
        match kind {
            "openflow_flow_mod" => {
                flow_mod_from_json(&action)?;
                Ok(custom(RESULT_FLOW_MOD))
            }
            "openflow_packet_out" => {
                packet_out_from_json(&action)?;
                Ok(custom(RESULT_PACKET_OUT))
            }
            "openflow_drop_packet" => Ok(custom(RESULT_DROP)),
            "openflow_request_stats" => {
                stats_request_from_json(&action)?;
                Ok(custom(RESULT_STATS))
            }
            "openflow_disconnect_switch" | "close_connection" => Ok(ActionResult::CloseConnection),
            other => Err(anyhow!(
                "Unknown OpenFlow action '{other}'. Valid actions: openflow_flow_mod, \
                 openflow_packet_out, openflow_drop_packet, openflow_request_stats, \
                 openflow_disconnect_switch"
            )),
        }
    }
}

/// Parse a datapath id for the switch side's startup parameter (shared helper).
pub fn parse_datapath_id(v: &Value) -> Result<u64> {
    datapath_id_from_json(v)
}

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct BmpProtocol;
impl BmpProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn parameter(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}

pub fn action(
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
        log_template: Some(LogTemplate::new().with_info(format!("BMP {name}"))),
    }
}

fn continue_action() -> ActionDefinition {
    action(
        "bmp_continue",
        "Keep monitoring this router: the collector reads its next BMP message (a collector never writes to the router)",
        vec![],
        json!({"type": "bmp_continue"}),
    )
}

fn close_action() -> ActionDefinition {
    action(
        "bmp_close",
        "Stop monitoring this router: the collector closes the BMP session (the router will usually reconnect and resend its tables)",
        vec![parameter("reason", "string", "Why, for the log", false)],
        json!({"type": "bmp_close", "reason": "unknown router"}),
    )
}

fn answers() -> Vec<ActionDefinition> {
    vec![continue_action(), close_action()]
}

fn peer_parameter() -> Parameter {
    parameter(
        "peer",
        "object",
        "The monitored BGP peer: {type: global|rd_instance|local_instance|loc_rib, address, asn, bgp_id, distinguisher, post_policy, adj_rib_out, four_octet_as, timestamp}",
        true,
    )
}

fn router_parameter() -> Parameter {
    parameter(
        "router",
        "string",
        "The router's sysName from its Initiation message, or its address",
        true,
    )
}

fn event(id: &str, description: &str, mut params: Vec<Parameter>) -> EventType {
    params.insert(0, router_parameter());
    EventType::new(id, description, continue_action().example.clone())
        .with_parameters(params)
        .with_actions(answers())
}

pub static INITIATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bmp_initiation",
        "A router opened a BMP session and identified itself; continue to monitor it or close",
        continue_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("sys_name", "string", "The router's sysName", false),
        parameter("sys_descr", "string", "The router's sysDescr", false),
        parameter("strings", "array", "Free-form information strings", true),
    ])
    .with_actions(answers())
});
pub static PEER_UP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "bmp_peer_up",
        "A BGP session on the router came up",
        vec![
            peer_parameter(),
            parameter(
                "local_address",
                "string",
                "The router's address on the session",
                true,
            ),
            parameter("local_port", "number", "The router's TCP port", true),
            parameter("remote_port", "number", "The peer's TCP port", true),
            parameter(
                "sent_open",
                "object",
                "The OPEN the router sent: {asn, hold_time, bgp_id, capabilities}",
                true,
            ),
            parameter("received_open", "object", "The OPEN the peer sent", true),
            parameter(
                "information",
                "array",
                "Information TLVs: [{type, value}]",
                true,
            ),
        ],
    )
});
pub static ROUTE_MONITORING_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "bmp_route_monitoring",
        "Routes the router received from (or advertised to) a peer: one BGP UPDATE",
        vec![
            peer_parameter(),
            parameter("update", "object", "The UPDATE: {nlri, withdrawn_routes, origin, next_hop, as_path, path_attributes, end_of_rib}", false),
            parameter("decode_error", "string", "Why the embedded BGP message could not be decoded", false),
        ],
    )
});
pub static STATISTICS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "bmp_statistics",
        "Counters the router keeps for a peer",
        vec![
            peer_parameter(),
            parameter(
                "counters",
                "array",
                "[{type (IANA name), type_code, value, afi, safi}]",
                true,
            ),
        ],
    )
});
pub static PEER_DOWN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "bmp_peer_down",
        "A BGP session on the router went down",
        vec![
            peer_parameter(),
            parameter("reason", "string", "local_notification, local_no_notification, remote_notification, remote_no_data, peer_deconfigured or local_system_closed", true),
            parameter("reason_code", "number", "The reason's code", true),
            parameter("notification", "object", "The NOTIFICATION: {code, subcode, name, subcode_name}", false),
            parameter("fsm_event", "number", "The BGP FSM event that closed the session", false),
        ],
    )
});
pub static TERMINATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "bmp_termination",
        "The router is ending the BMP session; the collector closes it after the handler answers",
        vec![
            parameter("reason", "string", "administratively_closed, unspecified, out_of_resources, redundant_connection or permanently_administratively_closed", false),
            parameter("strings", "array", "Free-form information strings", true),
        ],
    )
});
pub static ROUTE_MIRRORING_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "bmp_route_mirroring",
        "Verbatim BGP messages the router mirrored from a peer",
        vec![
            peer_parameter(),
            parameter("messages", "array", "[{update} | {bgp_message} | {information: errored_pdu|messages_lost} | {decode_error}]", true),
        ],
    )
});

pub fn all_events() -> Vec<EventType> {
    vec![
        INITIATION_EVENT.clone(),
        PEER_UP_EVENT.clone(),
        ROUTE_MONITORING_EVENT.clone(),
        STATISTICS_EVENT.clone(),
        PEER_DOWN_EVENT.clone(),
        TERMINATION_EVENT.clone(),
        ROUTE_MIRRORING_EVENT.clone(),
    ]
}

impl Protocol for BmpProtocol {
    fn protocol_name(&self) -> &'static str {
        "BMP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>BMP"
    }
    fn description(&self) -> &'static str {
        "BGP Monitoring Protocol collector (RFC 7854): routers report peer up/down, routes and statistics"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "bmp",
            "bgp monitoring",
            "rfc7854",
            "bmp collector",
            "route monitoring",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        answers()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        all_events()
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Native BMP v3 framing, per-peer header and TLVs (RFC 7854, RFC 8671 Adj-RIB-Out, RFC 9069 Loc-RIB); embedded BGP OPEN/UPDATE/NOTIFICATION decoded by netgauze through the bgp feature's wire module")
            .llm_control("Whether to keep monitoring each router after every message it reports")
            .e2e_testing("tests/server/bmp: GoBGP 4.9.0 (independent, Go) peers with a second GoBGP and exports Initiation, Peer Up, Route Monitoring, Statistics and Peer Down to NetGet")
            .notes("A collector never writes: the handler's only decision is to keep or close a session, and no answer closes it. IPv4 and IPv6 peers; UPDATE attributes beyond origin, AS path, next hop, MED, local preference and communities are named only. 256 KiB per message, a started message must finish within 60 s, 256 connections. No storage: persist with memory or SQLite.")
            .request_only("BMP is one-way: a collector never writes to the router")
            // BMP defines no collector-to-router message, so there is nothing to answer with:
            // a failure closes the session, which is the only signal the router can see.
            .deliberately_silent()
            .max_inbound_bytes(super::codec::MAX_MESSAGE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "BMP collector on port 11019 that logs every route my routers learn"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"bmp","port":11019,"instruction":"Monitor routers; close any whose sysName does not start with edge-"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"static","actions":[{"type":"bmp_continue"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python","code":"import json,sys\ni=json.load(sys.stdin)\ne=i['event']\nok=i['event_type_id']!='bmp_initiation' or str(e.get('sys_name','')).startswith('edge-')\nprint(json.dumps({'actions':[{'type':'bmp_continue'} if ok else {'type':'bmp_close','reason':'unknown router'}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Routing"
    }
}

impl Server for BmpProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("bmp_continue") => {}
            Some("bmp_close") => {
                if let Some(r) = v.get("reason").filter(|r| !r.is_null()) {
                    ensure!(
                        r.as_str().is_some_and(|r| r.len() <= 256),
                        "reason is text up to 256 bytes"
                    );
                }
            }
            _ => bail!("Unknown BMP collector action"),
        }
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

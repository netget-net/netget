use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::bmp::actions::{action, parameter};
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct BmpClientProtocol;
impl BmpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn peer_address() -> Parameter {
    parameter(
        "peer_address",
        "string",
        "The monitored peer, as announced by bmp_peer_up",
        true,
    )
}

fn peer_up() -> ActionDefinition {
    action(
        "bmp_peer_up",
        "Report that a BGP session came up; Rust builds both OPEN messages (four-octet AS capability) from the ASNs and identifiers",
        vec![
            parameter("peer", "object", "{address, asn, bgp_id, type: global|rd_instance|local_instance|loc_rib (default global), distinguisher (e.g. 65000:1), post_policy, adj_rib_out, four_octet_as (default true)}", true),
            parameter("local_address", "string", "This router's address on the session", true),
            parameter("local_asn", "number", "This router's AS number", true),
            parameter("local_bgp_id", "string", "This router's BGP identifier (IPv4 form)", true),
            parameter("local_port", "number", "This router's TCP port (default 179)", false),
            parameter("remote_port", "number", "The peer's TCP port (default 179)", false),
            parameter("hold_time", "number", "Hold time in both OPENs (default 90)", false),
        ],
        json!({"type": "bmp_peer_up", "peer": {"address": "192.0.2.2", "asn": 65002, "bgp_id": "192.0.2.2"}, "local_address": "192.0.2.1", "local_asn": 65001, "local_bgp_id": "192.0.2.1"}),
    )
}

fn route_monitoring() -> ActionDefinition {
    action(
        "bmp_route_monitoring",
        "Report routes received from a peer as one BGP UPDATE built by Rust: IPv4 announcements with their attributes and/or withdrawals",
        vec![
            peer_address(),
            parameter("announce", "array", "IPv4 prefixes announced, e.g. [\"203.0.113.0/24\"]", false),
            parameter("withdraw", "array", "IPv4 prefixes withdrawn", false),
            parameter("next_hop", "string", "Next hop for the announcements (required with announce)", false),
            parameter("as_path", "array", "AS numbers, nearest first", false),
            parameter("origin", "string", "IGP (default), EGP or INCOMPLETE", false),
            parameter("med", "number", "MULTI_EXIT_DISC metric for the announcements (lower is preferred)", false),
            parameter("local_pref", "number", "LOCAL_PREF for the announcements (higher is preferred)", false),
            parameter("communities", "array", "Communities as \"asn:value\"", false),
        ],
        json!({"type": "bmp_route_monitoring", "peer_address": "192.0.2.2", "announce": ["203.0.113.0/24"], "next_hop": "192.0.2.2", "as_path": [65002], "communities": ["65002:100"]}),
    )
}

fn statistics() -> ActionDefinition {
    action(
        "bmp_statistics",
        "Report counters for a peer: each by IANA name, with afi and safi for the per-AFI/SAFI gauges",
        vec![
            peer_address(),
            parameter("counters", "array", "[{type: e.g. rejected_prefixes | adj_rib_in_routes | loc_rib_routes_per_afi_safi, value, afi, safi}]", true),
        ],
        json!({"type": "bmp_statistics", "peer_address": "192.0.2.2", "counters": [{"type": "rejected_prefixes", "value": 3}, {"type": "adj_rib_in_routes", "value": 1200}]}),
    )
}

fn peer_down() -> ActionDefinition {
    action(
        "bmp_peer_down",
        "Report that a peer's BGP session went down, with the reason and its NOTIFICATION or FSM event",
        vec![
            peer_address(),
            parameter("reason", "string", "local_notification, local_no_notification, remote_notification, remote_no_data, peer_deconfigured or local_system_closed", true),
            parameter("notification", "object", "{code, subcode} for a *_notification reason", false),
            parameter("fsm_event", "number", "The FSM event for local_no_notification", false),
        ],
        json!({"type": "bmp_peer_down", "peer_address": "192.0.2.2", "reason": "remote_notification", "notification": {"code": 6, "subcode": 2}}),
    )
}

fn termination() -> ActionDefinition {
    action(
        "bmp_termination",
        "End the BMP session with a Termination message and close the connection",
        vec![
            parameter("reason", "string", "administratively_closed (default), unspecified, out_of_resources, redundant_connection or permanently_administratively_closed", false),
            parameter("message", "string", "A free-form string", false),
        ],
        json!({"type": "bmp_termination", "reason": "administratively_closed", "message": "maintenance"}),
    )
}

fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Close the connection without a Termination message",
        vec![],
        json!({"type": "disconnect"}),
    )
}

pub fn all_actions() -> Vec<ActionDefinition> {
    vec![
        peer_up(),
        route_monitoring(),
        statistics(),
        peer_down(),
        termination(),
        disconnect(),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bmp_connected",
        "Connected to the collector and sent the Initiation message; report peers and routes",
        peer_up().example.clone(),
    )
    .with_parameters(vec![
        parameter("collector", "string", "The collector's address", true),
        parameter("sys_name", "string", "The sysName this exporter sent", true),
    ])
    .with_actions(all_actions())
});

pub static CLOSED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bmp_collector_closed",
        "The collector closed the connection",
        json!({"type": "disconnect"}),
    )
    .with_parameters(vec![parameter(
        "reported",
        "number",
        "How many messages this exporter sent",
        true,
    )])
    .with_no_actions()
});

impl Protocol for BmpClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "BMP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>BMP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["bmp", "bmp exporter", "bgp monitoring", "rfc7854"]
    }
    fn description(&self) -> &'static str {
        "BGP Monitoring Protocol exporter: reports peers, routes and statistics to a BMP collector"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        all_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), CLOSED_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let p =
            |name: &str, description: &str, example: Value, default: Value| ParameterDefinition {
                name: name.into(),
                type_hint: "string".into(),
                description: description.into(),
                required: false,
                example,
                default: Some(default),
            };
        vec![
            p(
                "sys_name",
                "sysName sent in the Initiation message",
                json!("edge-1"),
                json!(super::DEFAULT_SYS_NAME),
            ),
            p(
                "sys_descr",
                "sysDescr sent in the Initiation message",
                json!("lab router"),
                json!(super::DEFAULT_SYS_DESCR),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The collector's BMP codec as an exporter; OPEN and UPDATE PDUs built by netgauze through the bgp feature's wire module")
            .llm_control("Which peers come up and go down, the routes and counters reported for them, and when the session ends")
            .e2e_testing("tests/client/bmp: gobmp 1.1.0 (independent, Go) collects and parses every message type the exporter sends")
            .notes("IPv4 unicast routes only; no Route Mirroring; peers are remembered by address from bmp_peer_up until bmp_peer_down.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Report to the BMP collector at 127.0.0.1:11019 that peer 192.0.2.2 came up and announced 203.0.113.0/24"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"bmp","remote_addr":"127.0.0.1:11019","instruction":"Bring peer 192.0.2.2 (AS65002) up and report 203.0.113.0/24 from it"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"bmp_connected","handler":{"type":"static","actions":[peer_up().example, route_monitoring().example]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"bmp_connected","handler":{"type":"script","language":"python","code":"import json\npeer={'address':'192.0.2.2','asn':65002,'bgp_id':'192.0.2.2'}\nprint(json.dumps({'actions':[{'type':'bmp_peer_up','peer':peer,'local_address':'192.0.2.1','local_asn':65001,'local_bgp_id':'192.0.2.1'},{'type':'bmp_route_monitoring','peer_address':'192.0.2.2','announce':['203.0.113.0/24'],'next_hop':'192.0.2.2','as_path':[65002]}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Routing"
    }
}

impl Client for BmpClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        ensure!(
            crate::utils::json_budget::within_budget(&v, 1024 * 1024, 100_000, 16),
            "action exceeds the BMP bounds"
        );
        match v["type"].as_str() {
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            Some(
                t @ ("bmp_peer_up"
                | "bmp_route_monitoring"
                | "bmp_statistics"
                | "bmp_peer_down"
                | "bmp_termination"),
            ) => {
                // Build the message now so a malformed action is refused before anything is sent.
                super::Peers::default().validate(t, &v)?;
            }
            _ => bail!("Unknown BMP client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition,
};
use crate::protocol::{EventType, SpawnContext};
use crate::server::p2p_support::{action, parameter};
use crate::state::AppState;
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, LazyLock},
};

#[derive(Default)]
pub struct GnutellaProtocol;
impl GnutellaProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn reply() -> ActionDefinition {
    action(
        "gnutella_reply",
        "Ping/pong discovery, query/query-hit search and push descriptors",
        vec![
            parameter("ip", "string", "Advertised IPv4 endpoint", false),
            parameter("port", "number", "Advertised port", false),
            parameter("files", "number", "Shared file count", false),
            parameter(
                "kilobytes",
                "number",
                "Total advertised shared content size in unsigned 32-bit kilobytes",
                false,
            ),
            parameter("speed", "number", "Declared transfer speed", false),
            parameter(
                "results",
                "array",
                "Search hits (index,size,name,urn)",
                false,
            ),
        ],
        json!({"type":"gnutella_reply","ip":"127.0.0.1","port":6346,"results":[{"index":1,"size":5,"name":"hello.txt"}]}),
    )
}
impl Protocol for GnutellaProtocol {
    fn protocol_name(&self) -> &'static str {
        "Gnutella"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Gnutella"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["gnutella", "gnutella"]
    }
    fn description(&self) -> &'static str {
        "Selected Gnutella hub and peer operations listening role"
    }
    fn example_prompt(&self) -> &'static str {
        "Listen on Gnutella port 6346; supply protocol decisions with handlers"
    }
    fn group_name(&self) -> &'static str {
        "Peer-to-peer"
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        crate::server::p2p_support::tls_parameters(true)
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_server","base_stack":"gnutella","port":6346,"instruction":"Serve selected Gnutella operations"});
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"gnutella_request","handler":{"type":"static","actions":[reply().example]}}]);
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"gnutella_request","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'gnutella_reply','error':'denied'}]}))"}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![action(
            "disconnect",
            "Close this peer",
            vec![],
            json!({"type":"disconnect"}),
        )]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![reply()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        EVENTS.clone()
    }
    fn metadata(&self) -> crate::protocol::ProtocolMetadataV2 {
        crate::protocol::ProtocolMetadataV2::builder().state(crate::protocol::metadata::DevelopmentState::Experimental).implementation("Native bounded Gnutella selected codec; TCP and optional implicit TLS").llm_control("Ping/pong discovery, query/query-hit search and push descriptors").e2e_testing("Independent peer exchanges, malformed input, owner shutdown and standalone feature builds").notes("Selected Gnutella 0.6 TCP peer simulator. No public network crawling, ultrapeer routing, QRP/GGEP, DHT, HTTP file downloads or push connection dialing. Handler-supplied endpoint and search results, TTL/hops limited to 16, 64 KiB descriptor payload, 32 query hits. 256 connections, 30 s first frame, 600 s idle, 10 s handshake/exchange. No persistent protocol data; handlers supply content and decisions.").max_inbound_bytes(super::codec::MAX_COMMAND).well_known_port(6346).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
}
impl Server for GnutellaProtocol {
    fn spawn(&self, ctx: SpawnContext) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(crate::server::p2p_support::spawn(
            ctx,
            Arc::new(Self),
            super::codec::Device::default,
            &EVENTS,
        ))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ActionResult::CloseConnection);
        }
        ensure!(v["type"] == "gnutella_reply", "unknown action");
        Ok(ActionResult::Custom {
            name: "gnutella_reply".into(),
            data: v,
        })
    }
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![EventType::new(
        "gnutella_request",
        "Ping/pong discovery, query/query-hit search and push descriptors",
        reply().example,
    )
    .with_actions(vec![reply()])
    .with_parameters(vec![
        parameter("operation", "string", "Selected protocol operation", true),
        parameter(
            "identifier",
            "string",
            "Requested object, message or file identifier",
            false,
        ),
    ])]
});

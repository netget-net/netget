use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::p2p_support::{action, parameter};
use crate::state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::LazyLock};

#[derive(Default)]
pub struct GnutellaClientProtocol;
impl GnutellaClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn requests() -> Vec<ActionDefinition> {
    vec![
        action(
            "gnutella_ping",
            "Send discovery ping",
            vec![],
            json!({"type":"gnutella_ping"}),
        ),
        action(
            "gnutella_query",
            "Send search query",
            vec![parameter(
                "query",
                "string",
                "UTF-8 filename search query announced to connected peers",
                true,
            )],
            json!({"type":"gnutella_query","query":"example"}),
        ),
        action(
            "gnutella_push",
            "Request a push descriptor",
            vec![
                parameter(
                    "servent_id",
                    "string",
                    "Destination servent GUID encoded as exactly 32 hexadecimal digits",
                    true,
                ),
                parameter(
                    "index",
                    "number",
                    "Unsigned index of the requested file from a received query hit",
                    true,
                ),
                parameter("ip", "string", "IPv4 destination", true),
                parameter("port", "number", "Destination port", true),
            ],
            json!({"type":"gnutella_push","servent_id":"00000000000000000000000000000000","index":1,"ip":"127.0.0.1","port":6346}),
        ),
        action(
            "disconnect",
            "Close this peer",
            vec![],
            json!({"type":"disconnect"}),
        ),
    ]
}
impl Protocol for GnutellaClientProtocol {
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
        "Selected Gnutella hub and peer operations connecting role"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to Gnutella on 127.0.0.1:6346"
    }
    fn group_name(&self) -> &'static str {
        "Peer-to-peer"
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        crate::server::p2p_support::tls_parameters(false)
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_client","protocol":"gnutella","remote_addr":"127.0.0.1:6346","instruction":"Use selected Gnutella operations"});
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"gnutella_connected","handler":{"type":"static","actions":[requests()[0].example]}}]);
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"gnutella_connected","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'disconnect'}]}))"}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        requests()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        EVENTS.clone()
    }
    fn metadata(&self) -> crate::protocol::ProtocolMetadataV2 {
        crate::protocol::ProtocolMetadataV2::builder().state(crate::protocol::metadata::DevelopmentState::Experimental).implementation("Native bounded Gnutella selected codec; TCP and optional implicit TLS").llm_control("Ping/pong discovery, query/query-hit search and push descriptors").e2e_testing("Independent peer exchanges, malformed input, owner shutdown and standalone feature builds").notes("Selected Gnutella 0.6 TCP peer simulator. No public network crawling, ultrapeer routing, QRP/GGEP, DHT, HTTP file downloads or push connection dialing. Handler-supplied endpoint and search results, TTL/hops limited to 16, 64 KiB descriptor payload, 32 query hits. 256 connections, 30 s first frame, 600 s idle, 10 s handshake/exchange. No persistent protocol data; handlers supply content and decisions.").max_inbound_bytes(crate::server::gnutella::codec::MAX_COMMAND).well_known_port(6346).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
}
impl Client for GnutellaClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        crate::server::gnutella::codec::validate(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().expect("validated type").into(),
            data: v,
        })
    }
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![
        EventType::new(
            "gnutella_connected",
            "Peer negotiation completed",
            json!({"type":"disconnect"}),
        )
        .with_actions(requests()),
        EventType::new(
            "gnutella_response",
            "Protocol response or incoming message",
            json!({"type":"disconnect"}),
        )
        .with_actions(requests()),
    ]
});

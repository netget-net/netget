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
pub struct SoulseekPeerProtocol;
impl SoulseekPeerProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn reply() -> ActionDefinition {
    action(
        "soulseek_peer_reply",
        "Handler-supplied shared directory listings and user information",
        vec![
            parameter(
                "directories",
                "array",
                "Directory objects with name and files (name,size,extension)",
                false,
            ),
            parameter("description", "string", "Peer description", false),
            parameter("upload_slots", "number", "Declared upload slots", false),
            parameter("queue_size", "number", "Declared queue size", false),
            parameter("has_slots_free", "boolean", "Declared availability", false),
        ],
        json!({"type":"soulseek_peer_reply","directories":[],"description":"NetGet"}),
    )
}
impl Protocol for SoulseekPeerProtocol {
    fn protocol_name(&self) -> &'static str {
        "Soulseek Peer"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Soulseek Peer"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["soulseek_peer", "soulseek peer"]
    }
    fn description(&self) -> &'static str {
        "Selected Soulseek Peer hub and peer operations listening role"
    }
    fn example_prompt(&self) -> &'static str {
        "Listen on Soulseek Peer port 2234; supply protocol decisions with handlers"
    }
    fn group_name(&self) -> &'static str {
        "Peer-to-peer"
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        crate::server::p2p_support::tls_parameters(true)
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_server","base_stack":"soulseek_peer","port":2234,"instruction":"Serve selected Soulseek Peer operations"});
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"soulseek_peer_request","handler":{"type":"static","actions":[reply().example]}}]);
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"soulseek_peer_request","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'soulseek_peer_reply','error':'denied'}]}))"}}]);
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
        crate::protocol::ProtocolMetadataV2::builder().state(crate::protocol::metadata::DevelopmentState::Experimental).implementation("Native bounded Soulseek Peer selected codec; TCP and optional implicit TLS").llm_control("Handler-supplied shared directory listings and user information").e2e_testing("Independent peer exchanges, malformed input, owner shutdown and standalone feature builds").notes("Selected Soulseek P connections with PeerInit, zlib share listings and user information. No F file transfer, D distributed search, picture uploads or obfuscation. 1 MiB decoded listing, 128 directories/files per collection. 256 connections, 30 s first frame, 600 s idle, 10 s handshake/exchange. No persistent protocol data; handlers supply content and decisions.").max_inbound_bytes(super::codec::MAX_COMMAND).well_known_port(2234).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
}
impl Server for SoulseekPeerProtocol {
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
        ensure!(v["type"] == "soulseek_peer_reply", "unknown action");
        Ok(ActionResult::Custom {
            name: "soulseek_peer_reply".into(),
            data: v,
        })
    }
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![EventType::new(
        "soulseek_peer_request",
        "Handler-supplied shared directory listings and user information",
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

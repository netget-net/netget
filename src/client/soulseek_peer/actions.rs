use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::p2p_support::action;
use crate::state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::LazyLock};

#[derive(Default)]
pub struct SoulseekPeerClientProtocol;
impl SoulseekPeerClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn requests() -> Vec<ActionDefinition> {
    vec![
        action(
            "soulseek_peer_shares",
            "Browse shared directories",
            vec![],
            json!({"type":"soulseek_peer_shares"}),
        ),
        action(
            "soulseek_peer_info",
            "Read peer information",
            vec![],
            json!({"type":"soulseek_peer_info"}),
        ),
        action(
            "disconnect",
            "Close this peer",
            vec![],
            json!({"type":"disconnect"}),
        ),
    ]
}
impl Protocol for SoulseekPeerClientProtocol {
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
        "Selected Soulseek Peer hub and peer operations connecting role"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to Soulseek Peer on 127.0.0.1:2234"
    }
    fn group_name(&self) -> &'static str {
        "Peer-to-peer"
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        crate::server::p2p_support::tls_parameters(false)
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_client","protocol":"soulseek_peer","remote_addr":"127.0.0.1:2234","instruction":"Use selected Soulseek Peer operations"});
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"soulseek_peer_connected","handler":{"type":"static","actions":[requests()[0].example]}}]);
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"soulseek_peer_connected","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'disconnect'}]}))"}}]);
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
        crate::protocol::ProtocolMetadataV2::builder().state(crate::protocol::metadata::DevelopmentState::Experimental).implementation("Native bounded Soulseek Peer selected codec; TCP and optional implicit TLS").llm_control("Handler-supplied shared directory listings and user information").e2e_testing("Independent peer exchanges, malformed input, owner shutdown and standalone feature builds").notes("Selected Soulseek P connections with PeerInit, zlib share listings and user information. No F file transfer, D distributed search, picture uploads or obfuscation. 1 MiB decoded listing, 128 directories/files per collection. 256 connections, 30 s first frame, 600 s idle, 10 s handshake/exchange. No persistent protocol data; handlers supply content and decisions.").max_inbound_bytes(crate::server::soulseek_peer::codec::MAX_COMMAND).well_known_port(2234).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        // Replies queue on the shared p2p_support::connect runner; what arrives while the
        // model answers is answered together (call_llm_for_client_batch).
        .batching(crate::protocol::metadata::BatchingMode::On)
        .build()
    }
}
impl Client for SoulseekPeerClientProtocol {
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
        crate::server::soulseek_peer::codec::validate(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().expect("validated type").into(),
            data: v,
        })
    }
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![
        EventType::new(
            "soulseek_peer_connected",
            "Peer negotiation completed",
            json!({"type":"disconnect"}),
        )
        .with_actions(requests()),
        EventType::new(
            "soulseek_peer_response",
            "Protocol response or incoming message",
            json!({"type":"disconnect"}),
        )
        .with_actions(requests()),
    ]
});

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
pub struct SoulseekProtocol;
impl SoulseekProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn reply() -> ActionDefinition {
    action("soulseek_reply","Login decisions, public room lists, room membership/chat, user status/address and search announcements",vec![parameter("accepted","boolean","Accept login or selected operation",false),parameter("rooms","array","Public room names",false),parameter("status","number","0 offline, 1 away, 2 online",false),parameter("ip","string","Peer IPv4 address",false),parameter("port","number","TCP listening port advertised for the requested Soulseek peer",false),parameter("greeting","string","Human-readable greeting returned after an accepted Soulseek login",false),parameter("error","string","Login rejection reason",false)],json!({"type":"soulseek_reply","accepted":true,"rooms":["NetGet"]}))
}
impl Protocol for SoulseekProtocol {
    fn protocol_name(&self) -> &'static str {
        "Soulseek"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Soulseek"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["soulseek", "soulseek"]
    }
    fn description(&self) -> &'static str {
        "Selected Soulseek hub and peer operations listening role"
    }
    fn example_prompt(&self) -> &'static str {
        "Listen on Soulseek port 2242; supply protocol decisions with handlers"
    }
    fn group_name(&self) -> &'static str {
        "Peer-to-peer"
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        crate::server::p2p_support::tls_parameters(true)
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_server","base_stack":"soulseek","port":2242,"instruction":"Serve selected Soulseek operations"});
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"soulseek_request","handler":{"type":"static","actions":[reply().example]}}]);
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"soulseek_request","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'soulseek_reply','error':'denied'}]}))"}}]);
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
        crate::protocol::ProtocolMetadataV2::builder().state(crate::protocol::metadata::DevelopmentState::Experimental).implementation("Native bounded Soulseek selected codec; TCP and optional implicit TLS").llm_control("Login decisions, public room lists, room membership/chat, user status/address and search announcements").e2e_testing("Independent peer exchanges, malformed input, owner shutdown and standalone feature builds").notes("Experimental local central-server simulator using legacy Soulseek framing. Selected messages only; no public service account database, distributed topology, obfuscation or automatic peer dialing. Peer browsing is the separate soulseek_peer feature. 256 connections, 30 s first frame, 600 s idle, 10 s handshake/exchange. No persistent protocol data; handlers supply content and decisions.").max_inbound_bytes(super::codec::MAX_COMMAND).well_known_port(2242).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
}
impl Server for SoulseekProtocol {
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
        ensure!(v["type"] == "soulseek_reply", "unknown action");
        Ok(ActionResult::Custom {
            name: "soulseek_reply".into(),
            data: v,
        })
    }
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![EventType::new("soulseek_request","Login decisions, public room lists, room membership/chat, user status/address and search announcements",reply().example).with_actions(vec![reply()]).with_parameters(vec![parameter("operation","string","Selected protocol operation",true),parameter("identifier","string","Requested object, message or file identifier",false)])]
});

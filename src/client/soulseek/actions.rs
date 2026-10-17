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
pub struct SoulseekClientProtocol;
impl SoulseekClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn requests() -> Vec<ActionDefinition> {
    vec![
        action(
            "soulseek_login",
            "Authenticate with the central server",
            vec![
                parameter(
                    "username",
                    "string",
                    "Soulseek username identifying the account or queried peer",
                    true,
                ),
                parameter(
                    "password",
                    "string",
                    "Account password used for the selected Soulseek login exchange",
                    true,
                ),
            ],
            json!({"type":"soulseek_login","username":"netget","password":"test"}),
        ),
        action(
            "soulseek_rooms",
            "List public rooms",
            vec![],
            json!({"type":"soulseek_rooms"}),
        ),
        action(
            "soulseek_join",
            "Join a public room",
            vec![parameter(
                "room",
                "string",
                "Public Soulseek room name to join, leave or send chat to",
                true,
            )],
            json!({"type":"soulseek_join","room":"NetGet"}),
        ),
        action(
            "soulseek_leave",
            "Leave the named public Soulseek room",
            vec![parameter(
                "room",
                "string",
                "Public Soulseek room name to join, leave or send chat to",
                true,
            )],
            json!({"type":"soulseek_leave","room":"NetGet"}),
        ),
        action(
            "soulseek_chat",
            "Send a chat message to the named public Soulseek room",
            vec![
                parameter(
                    "room",
                    "string",
                    "Public Soulseek room name to join, leave or send chat to",
                    true,
                ),
                parameter(
                    "message",
                    "string",
                    "UTF-8 message text to send to the named public Soulseek room",
                    true,
                ),
            ],
            json!({"type":"soulseek_chat","room":"NetGet","message":"Hello"}),
        ),
        action(
            "soulseek_status",
            "Read user status",
            vec![parameter(
                "username",
                "string",
                "Soulseek username identifying the account or queried peer",
                true,
            )],
            json!({"type":"soulseek_status","username":"netget"}),
        ),
        action(
            "soulseek_address",
            "Read user peer endpoint",
            vec![parameter(
                "username",
                "string",
                "Soulseek username identifying the account or queried peer",
                true,
            )],
            json!({"type":"soulseek_address","username":"netget"}),
        ),
        action(
            "soulseek_search",
            "Send a search announcement",
            vec![
                parameter("ticket", "number", "Unsigned 32 bit correlation ID", true),
                parameter(
                    "query",
                    "string",
                    "UTF-8 filename search query announced to connected peers",
                    true,
                ),
            ],
            json!({"type":"soulseek_search","ticket":1,"query":"example"}),
        ),
        action(
            "disconnect",
            "Close this peer",
            vec![],
            json!({"type":"disconnect"}),
        ),
    ]
}
impl Protocol for SoulseekClientProtocol {
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
        "Selected Soulseek hub and peer operations connecting role"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to Soulseek on 127.0.0.1:2242"
    }
    fn group_name(&self) -> &'static str {
        "Peer-to-peer"
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        crate::server::p2p_support::tls_parameters(false)
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_client","protocol":"soulseek","remote_addr":"127.0.0.1:2242","instruction":"Use selected Soulseek operations"});
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"soulseek_connected","handler":{"type":"static","actions":[requests()[0].example]}}]);
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"soulseek_connected","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'disconnect'}]}))"}}]);
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
        crate::protocol::ProtocolMetadataV2::builder().state(crate::protocol::metadata::DevelopmentState::Experimental).implementation("Native bounded Soulseek selected codec; TCP and optional implicit TLS").llm_control("Login decisions, public room lists, room membership/chat, user status/address and search announcements").e2e_testing("Independent peer exchanges, malformed input, owner shutdown and standalone feature builds").notes("Experimental local central-server simulator using legacy Soulseek framing. Selected messages only; no public service account database, distributed topology, obfuscation or automatic peer dialing. Peer browsing is the separate soulseek_peer feature. 256 connections, 30 s first frame, 600 s idle, 10 s handshake/exchange. No persistent protocol data; handlers supply content and decisions.").max_inbound_bytes(crate::server::soulseek::codec::MAX_COMMAND).well_known_port(2242).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
}
impl Client for SoulseekClientProtocol {
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
        crate::server::soulseek::codec::validate(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().expect("validated type").into(),
            data: v,
        })
    }
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![
        EventType::new(
            "soulseek_connected",
            "Peer negotiation completed",
            json!({"type":"disconnect"}),
        )
        .with_actions(requests()),
        EventType::new(
            "soulseek_response",
            "Protocol response or incoming message",
            json!({"type":"disconnect"}),
        )
        .with_actions(requests()),
    ]
});

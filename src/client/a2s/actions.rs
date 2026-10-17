use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::a2s::{
    actions::{action, parameter},
    wire::{self, Kind},
};
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct A2sClientProtocol;
impl A2sClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn query_action() -> ActionDefinition {
    action(
        "a2s_query",
        "Query the game server; the decoded answer arrives as a2s_response. Challenges and split responses are handled for you.",
        vec![parameter("query", "string", "info, players or rules", true)],
        json!({"type":"a2s_query","query":"info"}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Stop this A2S client",
        vec![],
        json!({"type":"disconnect"}),
    )
}

fn actions() -> Vec<ActionDefinition> {
    vec![query_action(), disconnect_action()]
}

pub static READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "a2s_ready",
        "Ready to query the game server over UDP.",
        query_action().example.clone(),
    )
    .with_parameters(vec![parameter(
        "remote_addr",
        "string",
        "Address of the game server's query port",
        true,
    )])
    .with_actions(actions())
});

pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("a2s_response", "The server's decoded answer to one query.", query_action().example.clone())
        .with_parameters(vec![
            parameter("query", "string", "info, players or rules", true),
            parameter("info", "object", "For info: name, map, folder, game, app_id, players, max_players, bots, server_type, environment, private, vac, version and any extra data", false),
            parameter("players", "array", "For players: [{index, name, score, duration_secs}]", false),
            parameter("rules", "object", "For rules: rule names to values", false),
            parameter("packets", "number", "Datagrams the answer arrived in", true),
        ])
        .with_actions(actions())
});

pub fn kind(v: &Value) -> Result<Kind> {
    Kind::parse(
        v["query"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("query must be a string"))?,
    )
}

impl Protocol for A2sClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "A2S"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>A2S"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["a2s", "steam query", "source query", "server browser"]
    }
    fn description(&self) -> &'static str {
        "Steam/Source server query client: info, players and rules"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![READY_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(27015)
            .implementation("Tokio UDP: A2S requests, challenge retry, Source split reassembly and decoding")
            .llm_control("Which queries to send and what to do with each answer")
            .e2e_testing("tests/client/a2s: scripted fixture with challenges and splits; woozymasta/a2s's server (Go) as the independent peer")
            .notes("Uncompressed Source responses only (no GoldSource, no bzip2 splits). Each reply datagram has a 5 s deadline, a challenge is retried once, and responses are bounded to 64 KiB in at most 64 packets.")
            .max_inbound_bytes(wire::MAX_RESPONSE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Query the game server at 127.0.0.1:27015 for its info and players"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"a2s","remote_addr":"127.0.0.1:27015","instruction":"Report the server's map and player count"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"a2s_ready","handler":{"type":"static","actions":[{"type":"a2s_query","query":"info"}]}},
            {"event_pattern":"a2s_response","handler":{"type":"static","actions":[{"type":"disconnect"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'a2s_query','query':'players'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for A2sClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("a2s_query") => {
                kind(&v)?;
                Ok(ClientActionResult::Custom {
                    name: "a2s_query".into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown A2S client action"),
        }
    }
}

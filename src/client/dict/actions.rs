use super::wire::Request;
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct DictClientProtocol;
impl DictClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
fn parameter(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}
fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
    log_template: &str,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(log_template)),
    }
}
fn request_action() -> ActionDefinition {
    action(
        "dict_request",
        "Send a structured RFC 2229 dictionary request",
        vec![
            parameter(
                "operation",
                "string",
                "define/match/databases/strategies/info/server/status/help/client/quit",
                true,
            ),
            parameter(
                "database",
                "string",
                "Database name; define/match default to * (all databases)",
                false,
            ),
            parameter("word", "string", "Word to define or match", false),
            parameter(
                "strategy",
                "string",
                "Match strategy, default . (server default)",
                false,
            ),
            parameter(
                "name",
                "string",
                "Client identification for operation client",
                false,
            ),
        ],
        json!({"type":"dict_request","operation":"databases"}),
        "Request DICT operation {operation}",
    )
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the DICT connection",
        vec![],
        json!({"type":"disconnect"}),
        "Disconnect DICT server",
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![request_action(), disconnect_action()]
}
pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dict_connected",
        "Connected to DICT; send a request",
        request_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("remote_addr", "string", "DICT server address", true),
        parameter(
            "greeting",
            "string",
            "Server greeting, capabilities and message ID",
            true,
        ),
    ])
    .with_actions(actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dict_response",
        "Complete, validated dictionary response including protocol refusals.",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("request", "object", "Structured request", true),
        parameter(
            "response",
            "object",
            "code plus definitions, entries, text, message or protocol error",
            true,
        ),
    ])
    .with_actions(actions())
});
impl Protocol for DictClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "DICT"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>DICT"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["dict", "dictionary", "definitions", "lookup"]
    }
    fn description(&self) -> &'static str {
        "DICT dictionary client with structured definitions and search results"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).well_known_port(2628)
        .implementation("Tokio TCP with RFC 2229 status lines, dot-stuffed blocks and bounded complete responses")
        .llm_control("Dictionary definitions, match searches, database and strategy discovery, information and session commands")
        .e2e_testing("tests/client/dict: independent dictd daemon, NetGet server pair, malformed framing, command injection and cleanup")
        .notes("Plain UTF-8 DICT. No AUTH/SASL or MIME negotiation. Connect/write/greeting/response deadlines30s; commands1024 bytes, response lines64KiB, total response1MiB, entries4096. Tracked tasks; injected disconnect interrupts greeting and pending replies.")
        .max_inbound_bytes(super::wire::MAX_RESPONSE_BYTES).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to DICT at localhost:2628 and discover dictionary databases"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"dict","remote_addr":"127.0.0.1:2628","instruction":"Discover dictionary databases"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"dict_connected","handler":{"type":"static","actions":[{"type":"dict_request","operation":"databases"}]}},{"event_pattern":"dict_response","handler":{"type":"static","actions":[]}}]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"respond([{'type':'dict_request','operation':'databases'}])"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Discovery"
    }
}
impl Client for DictClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("dict_request") => {
                Request::from_action(&v)?;
                Ok(ClientActionResult::Custom {
                    name: "dict_request".into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown DICT client action"),
        }
    }
}

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::nut::{
    actions::{action, parameter},
    wire::Request,
};
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct NutClientProtocol;
impl NutClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
fn request_action() -> ActionDefinition {
    action("nut_request", "Send a structured NUT operation. Requests are serialized and replies are correlated before raising nut_response.", vec![
        parameter("operation","string","list_ups/list_var/list_rw/list_cmd/list_enum/get_var/get_desc/get_cmddesc/get_upsdesc/get_type/set_var/instcmd/username/password/logout",true),
        parameter("ups","string","UPS identifier except list_ups and credentials/logout",false),parameter("name","string","Variable or command name",false),parameter("value","string","Value for set_var, username or password",false),
    ],json!({"type":"nut_request","operation":"list_ups"}))
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the NUT connection",
        vec![],
        json!({"type":"disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![request_action(), disconnect_action()]
}
pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nut_connected",
        "Connected to NUT; send a request",
        request_action().example.clone(),
    )
    .with_parameters(vec![parameter(
        "remote_addr",
        "string",
        "NUT server address",
        true,
    )])
    .with_actions(actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("nut_response","Complete, validated NUT response, or a NUT server error. Credentials are redacted from request.",disconnect_action().example.clone()).with_parameters(vec![parameter("request","object","Structured request",true),parameter("response","object","entries, value, types, ok or error",true)]).with_actions(actions())
});
impl Protocol for NutClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "NUT"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>NUT"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["nut", "ups", "upsc", "rfc9271"]
    }
    fn description(&self) -> &'static str {
        "NUT UPS management client with structured queries and authenticated commands"
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
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).well_known_port(3493)
        .implementation("Tokio TCP with bounded ASCII parser, serialized request/reply correlation, structured lists")
        .llm_control("UPS/variable queries, authentication, SET and instant commands; response events and injected actions")
        .e2e_testing("tests/client/nut: independent wire fixture, malformed/mismatched replies, command injection and event handlers; see CLAUDE.md for real upsd evidence")
        .notes("Plain TCP only; no TLS negotiation, attachment/primary/FSD or command tracking. Connect/response/write deadlines 30s, 8192-byte lines, 1 MiB/4096-entry replies. All tasks are registered and event/request queues are bounded at 16.")
        .max_inbound_bytes(crate::server::nut::wire::MAX_RESPONSE_BYTES).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to NUT at localhost:3493 and read ups.status"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"nut","remote_addr":"127.0.0.1:3493","instruction":"List UPS devices"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"nut_connected","handler":{"type":"static","actions":[{"type":"nut_request","operation":"list_ups"}]}},{"event_pattern":"nut_response","handler":{"type":"static","actions":[]}}]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"respond([{'type':'nut_request','operation':'list_ups'}])"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Monitoring"
    }
}
impl Client for NutClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("nut_request") => Ok(ClientActionResult::Custom {
                name: "nut_request".into(),
                data: json!(Request::from_action(&v)?),
            }),
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown NUT client action"),
        }
    }
}

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
pub struct GeminiClientProtocol;
impl GeminiClientProtocol {
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
    action("gemini_request", "Fetch a Gemini URL on this client's endpoint; redirects and input prompts are returned for an explicit next action", vec![
        parameter("url","string","Absolute gemini:// URL, maximum1024 bytes; host/port must match the configured endpoint",true),
        parameter("input","string","Optional response to an input prompt; UTF-8 percent-encoded as the URL query",false),
    ],json!({"type":"gemini_request","url":"gemini://localhost:1965/"}), "Request Gemini capsule response")
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the Gemini connection",
        vec![],
        json!({"type":"disconnect"}),
        "Disconnect Gemini capsule",
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![request_action(), disconnect_action()]
}
pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "gemini_connected",
        "Connected to Gemini; send a request",
        request_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("remote_addr", "string", "Gemini server address", true),
        parameter("server_name", "string", "Verified TLS server name", true),
    ])
    .with_actions(actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "gemini_response",
        "Complete, validated Gemini response including protocol refusals.",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("request", "object", "Structured request", true),
        parameter(
            "response",
            "object",
            "status/meta/kind plus text, structured gemtext, redirect target or input prompt",
            true,
        ),
    ])
    .with_actions(actions())
});
impl Protocol for GeminiClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Gemini"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>GEMINI"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["gemini", "gemini://", "gemtext", "capsule"]
    }
    fn description(&self) -> &'static str {
        "Gemini capsule client with verified TLS and structured gemtext"
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
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).well_known_port(1965)
        .implementation("rustls TLS1.2/1.3; bounded Gemini framing and structured gemtext")
        .llm_control("URLs, explicit input replies and redirect decisions; parsed status/meta/text/links")
        .e2e_testing("tests/client/gemini: independent Agate server, NetGet pair, certificate rejection, wire bounds and lifecycle")
        .notes("Text MIME bodies only, UTF-8/US-ASCII; no binary downloads or client certificate authentication. TLS verified with Mozilla roots or explicit custom CA, no hidden TOFU state. Fresh TLS connection per request;30s complete transaction deadline, body1MiB, header1029 bytes, gemtext8192 lines. Redirects never followed automatically.")
        .max_inbound_bytes(super::wire::MAX_BODY_BYTES).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        [("server_name", "TLS server name and required URL hostname; derived from remote_addr when omitted",json!("localhost")),
         ("custom_ca_cert_pem", "PEM trust anchors instead of Mozilla roots; supply the capsule certificate for a self-signed server",json!("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"))]
         .into_iter().map(|(name,description,example)| crate::llm::actions::ParameterDefinition{name:name.into(),type_hint:"string".into(),description:description.into(),required:false,example,default:None}).collect()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to Gemini at localhost:1965 and read the home capsule"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"gemini","remote_addr":"localhost:1965","instruction":"Read the capsule home page"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"gemini_connected","handler":{"type":"static","actions":[{"type":"gemini_request","url":"gemini://localhost:1965/"}]}},{"event_pattern":"gemini_response","handler":{"type":"static","actions":[]}}]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"respond([{'type':'gemini_request','url':'gemini://localhost:1965/'}])"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Discovery"
    }
}
impl Client for GeminiClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("gemini_request") => {
                Request::from_action(&v)?;
                Ok(ClientActionResult::Custom {
                    name: "gemini_request".into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown Gemini client action"),
        }
    }
}

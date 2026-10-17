use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::icap::actions::{action, parameter, HEADERS_HELP};
use crate::server::icap::wire;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct IcapClientProtocol;
impl IcapClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn request_action() -> ActionDefinition {
    action(
        "icap_request",
        "Send one ICAP request on the persistent connection. Rust frames the head, Encapsulated offsets and chunked body, sends a preview when asked and continues it on 100 Continue.",
        vec![
            parameter("method", "string", "OPTIONS, REQMOD or RESPMOD", true),
            parameter("service", "string", "ICAP service name, e.g. avscan", true),
            parameter("http_request", "object", &format!("REQMOD (required) / RESPMOD (optional): {{method, uri, version, headers: {HEADERS_HELP}}}"), false),
            parameter("http_response", "object", &format!("RESPMOD: {{status, reason, version, headers: {HEADERS_HELP}}}"), false),
            parameter("body_text", "string", "Encapsulated body as UTF-8 text", false),
            parameter("preview", "number", "Send only the first N body bytes first (Preview header); Rust sends the rest if the server answers 100 Continue", false),
            parameter("allow_204", "boolean", "Offer Allow: 204 (default true)", false),
        ],
        json!({"type":"icap_request","method":"RESPMOD","service":"avscan","http_request":{"method":"GET","uri":"http://example.com/"},"http_response":{"status":200,"reason":"OK","headers":[["Content-Type","text/plain"]]},"body_text":"hello"}),
    )
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the ICAP connection",
        vec![],
        json!({"type":"disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![request_action(), disconnect_action()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "icap_connected",
        "Connected to the ICAP server",
        json!({"type":"icap_request","method":"OPTIONS","service":"avscan"}),
    )
    .with_parameters(vec![parameter(
        "remote_addr",
        "string",
        "ICAP server address",
        true,
    )])
    .with_actions(actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "icap_response",
        "The ICAP server's answer to the last request",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("method", "string", "The request's method", true),
        parameter("service", "string", "The request's service", true),
        parameter(
            "status",
            "number",
            "ICAP status: 200 adapted, 204 unmodified, 4xx/5xx errors",
            true,
        ),
        parameter("reason", "string", "ICAP reason phrase", true),
        parameter(
            "icap_headers",
            "array",
            "ICAP response headers as [[name, value]] (OPTIONS: Methods, Preview, ISTag, ...)",
            true,
        ),
        parameter(
            "http_request",
            "object",
            "Adapted HTTP request, when returned",
            false,
        ),
        parameter(
            "http_response",
            "object",
            "Adapted or substituted HTTP response, when returned",
            false,
        ),
        parameter(
            "body_text",
            "string",
            "Returned body when it is UTF-8",
            false,
        ),
        parameter("body_bytes", "number", "Returned body size", false),
        parameter(
            "continued",
            "boolean",
            "true when the server asked for the rest of a preview",
            false,
        ),
    ])
    .with_actions(actions())
});

impl Protocol for IcapClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "ICAP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ICAP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["icap", "rfc3507", "content adaptation", "antivirus client"]
    }
    fn description(&self) -> &'static str {
        "ICAP client sending OPTIONS, REQMOD and RESPMOD with preview over a persistent connection"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
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
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(1344)
            .implementation("Shared RFC 3507 framing (src/server/icap/wire.rs); preview with 100 Continue; one request at a time on a persistent connection")
            .llm_control("Which requests to send and how to act on each adaptation verdict")
            .e2e_testing("tests/client/icap: c-icap 0.6.5's echo service (independent server) answers OPTIONS, REQMOD and RESPMOD with preview; NetGet pair and malformed-server refusals")
            .notes("Bodies are text (UTF-8) in actions and events, bounded at 1 MiB; binary response bodies are reported by size. No ICAP over TLS, no 206.")
            .max_inbound_bytes(wire::MAX_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Ask the ICAP server at 127.0.0.1:1344 for its OPTIONS and scan a test response"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"icap","remote_addr":"127.0.0.1:1344","instruction":"Scan a sample response with the avscan service"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"icap_connected","handler":{"type":"static","actions":[{"type":"icap_request","method":"OPTIONS","service":"avscan"}]}},
            {"event_pattern":"icap_response","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'icap_request','method':'OPTIONS','service':'avscan'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Security"
    }
}

impl Client for IcapClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("icap_request") => {
                let method = v["method"].as_str().context("method is required")?;
                ensure!(
                    matches!(method, "OPTIONS" | "REQMOD" | "RESPMOD"),
                    "method must be OPTIONS, REQMOD or RESPMOD"
                );
                let service = v["service"].as_str().context("service is required")?;
                ensure!(
                    !service.is_empty()
                        && service.len() <= 64
                        && service
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
                    "service must be letters, digits, '-', '_' or '.'"
                );
                if method == "REQMOD" {
                    wire::request_head(&v["http_request"])?;
                }
                if method == "RESPMOD" {
                    wire::response_head(&v["http_response"])?;
                    if !v["http_request"].is_null() {
                        wire::request_head(&v["http_request"])?;
                    }
                }
                if let Some(b) = v["body_text"].as_str() {
                    ensure!(b.len() <= wire::MAX_BODY_BYTES, "body_text exceeds 1 MiB");
                    ensure!(method != "OPTIONS", "OPTIONS carries no body");
                }
                Ok(ClientActionResult::Custom {
                    name: "icap_request".into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown ICAP client action"),
        }
    }
}

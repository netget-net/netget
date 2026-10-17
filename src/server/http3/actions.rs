use super::wire::*;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::AppState;
use crate::utils::quic::*;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
pub fn field(name: &str, hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: hint.into(),
        description: description.into(),
        required,
    }
}
pub static HTTP3_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "http3_request_received",
        "Complete HTTP/3 request",
        json!({"type":"send_http3_response","status":200,"body":"hello"}),
    )
    .with_parameters(vec![
        field(
            "method",
            "string",
            "HTTP request method, such as GET or POST",
            true,
        ),
        field(
            "path",
            "string",
            "Request path and optional query string",
            true,
        ),
        field(
            "headers",
            "object",
            "Headers; repeated values are arrays",
            true,
        ),
        field(
            "body",
            "string",
            "Complete UTF-8 request body, at most 8 MiB",
            true,
        ),
        field("trailers", "object", "Request trailers", true),
        field("stream_id", "number", "QUIC stream index", true),
        field("peer_addr", "string", "Remote IP and UDP port", true),
    ])
    .with_actions(Http3Protocol.get_sync_actions())
});
#[derive(Default)]
pub struct Http3Protocol;
impl Http3Protocol {
    pub fn new() -> Self {
        Self
    }
}
impl Protocol for Http3Protocol {
    fn protocol_name(&self) -> &'static str {
        "HTTP3"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>QUIC>HTTP3"
    }
    fn description(&self) -> &'static str {
        "HTTP/3 requests and responses over authenticated QUIC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["http3", "http/3", "h3"]
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn example_prompt(&self) -> &'static str {
        "Serve HTTP/3 on UDP 4433 and answer requests with hello"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_http3_response".into(),
                description: "Send a final HTTP/3 response on the requesting stream".into(),
                parameters: vec![
                    field("status", "number", "Final status code, 200..599", true),
                    field("headers", "object", "Response headers", false),
                    field(
                        "body",
                        "string",
                        "UTF-8 response body, at most 8 MiB",
                        false,
                    ),
                    field("trailers", "object", "Trailing headers", false),
                ],
                example: json!({"type":"send_http3_response","status":200,"headers":{"content-type":"text/plain"},"body":"hello"}),
                log_template: Some(
                    LogTemplate::new().with_info("-> HTTP3 status={status} body_bytes={body_len}"),
                ),
            },
            ActionDefinition {
                name: "cancel_http3_request".into(),
                description: "Reset this request with H3_REQUEST_CANCELLED".into(),
                parameters: vec![],
                example: json!({"type":"cancel_http3_request"}),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("HTTP3 request cancelled with H3_REQUEST_CANCELLED"),
                ),
            },
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![HTTP3_REQUEST_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            parameter(
                "cert_path",
                "PEM certificate chain; requires key_path",
                json!("cert.pem"),
                None,
            ),
            parameter(
                "key_path",
                "PEM key; requires cert_path",
                json!("key.pem"),
                None,
            ),
            parameter(
                "handshake_timeout_secs",
                "TLS handshake deadline, 1..60 seconds",
                json!(10),
                Some(json!(HANDSHAKE_TIMEOUT.as_secs())),
            ),
            parameter(
                "exchange_timeout_secs",
                "Request headers/body, handler and response deadline, 1..300 seconds",
                json!(30),
                Some(json!(EXCHANGE_TIMEOUT.as_secs())),
            ),
            parameter(
                "idle_timeout_secs",
                "QUIC idle deadline, 1..3600 seconds",
                json!(300),
                Some(json!(IDLE_TIMEOUT.as_secs())),
            ),
            parameter(
                "max_connections",
                "Simultaneous connections including pending TLS, 1..256",
                json!(64),
                Some(json!(MAX_CONNECTIONS)),
            ),
            parameter(
                "max_streams",
                "Active requests per connection, 1..32",
                json!(32),
                Some(json!(MAX_STREAMS)),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).max_inbound_bytes(MAX_INBOUND_BYTES).privilege_requirement(PrivilegeRequirement::PrivilegedPort(443)).well_known_udp_port(443).implementation("h3 0.0.8, h3-quinn 0.0.10 with local cancellation fix, quinn 0.11 and rustls 0.23; RFC 9114 HEADERS/DATA/QPACK/control streams").llm_control("Structured status, headers, UTF-8 body and trailers per request; explicit cancellation").e2e_testing("Loopback aioquic 1.3.0 clients and servers, NetGet pair, authentication, bounds and removal regressions in tests/server/http3 and tests/client/http3").notes("32 KiB fields, 8 MiB UTF-8 bodies; 64 connections, 32 requests per connection; no server push, DATAGRAM, WebTransport, migration or 0-RTT. TLS certificates require explicit client trust.").history(crate::protocol::metadata::HistoryMode::Off)
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_server","base_stack":"http3","port":4433,"instruction":"Answer HTTP/3 requests with status 200 and the UTF-8 body hello"}),
            json!({"type":"open_server","base_stack":"http3","port":4433,"event_handlers":[{"event_pattern":"http3_request_received","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'send_http3_response','status':200,'body':'hello'}]}))"}}]}),
            json!({"type":"open_server","base_stack":"http3","port":4433,"event_handlers":[{"event_pattern":"http3_request_received","handler":{"type":"static","actions":[{"type":"send_http3_response","status":200,"body":"hello"}]}}]}),
        )
    }
}
impl Server for Http3Protocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::Http3Server::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        match action["type"].as_str().unwrap_or("") {
            "send_http3_response" => {
                let status = action["status"]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("Missing integer status"))?;
                ensure!(
                    (200..=599).contains(&status),
                    "Final status must be 200..599"
                );
                let body = action
                    .get("body")
                    .map(|b| {
                        b.as_str()
                            .ok_or_else(|| anyhow::anyhow!("body must be a string"))
                    })
                    .transpose()?
                    .unwrap_or("");
                ensure!(body.len() <= MAX_BODY, "HTTP3 response body exceeds 8 MiB");
                let headers = parse_headers(&action["headers"])?;
                check_field_section(
                    &headers,
                    &[(
                        ":status",
                        http::StatusCode::from_u16(status as u16)?.as_str(),
                    )],
                )?;
                validate_length(&headers, body.len())?;
                parse_headers(&action["trailers"])?;
                ensure!(
                    !matches!(status, 204 | 205 | 304) || body.is_empty(),
                    "This status forbids a response body"
                );
                Ok(ActionResult::Custom {
                    name: "http3_response".into(),
                    data: action,
                })
            }
            "cancel_http3_request" => Ok(ActionResult::CloseConnection),
            _ => bail!("Unknown HTTP3 action"),
        }
    }
}

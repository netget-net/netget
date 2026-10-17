use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::fastcgi::actions::{action, parameter};
use crate::server::fastcgi::record;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct FastcgiClientProtocol;
impl FastcgiClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn request_action() -> ActionDefinition {
    action(
        "fastcgi_request",
        "Send one Responder request to the FastCGI application, as a web server would: Rust builds the CGI params (REQUEST_METHOD, SCRIPT_NAME, SCRIPT_FILENAME, QUERY_STRING, CONTENT_*, HTTP_*), the PARAMS and STDIN streams, and waits for END_REQUEST (sending ABORT_REQUEST after the request timeout).",
        vec![
            parameter("method", "string", "HTTP method to report, e.g. GET or POST (default GET)", false),
            parameter("path", "string", "Script path starting with /, e.g. /index.php; SCRIPT_FILENAME is document_root plus this", true),
            parameter("query", "string", "Query string without the leading ?", false),
            parameter("headers", "object", "HTTP request headers as name → value; each becomes an HTTP_* param", false),
            parameter("body", "string", "Request body (STDIN) as text, or hex when body_encoding is hex", false),
            parameter("body_encoding", "string", "utf8 (default) or hex", false),
            parameter("params", "object", "Extra CGI params, or overrides of the ones Rust sets, as name → value", false),
        ],
        json!({"type":"fastcgi_request","method":"GET","path":"/index.php","query":"page=1"}),
    )
}
fn values_action() -> ActionDefinition {
    action(
        "fastcgi_get_values",
        "Ask the application for its management values (FCGI_GET_VALUES)",
        vec![parameter(
            "names",
            "array",
            "Variable names to ask for (default FCGI_MAX_CONNS, FCGI_MAX_REQS, FCGI_MPXS_CONNS)",
            false,
        )],
        json!({"type":"fastcgi_get_values"}),
    )
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Stop this FastCGI client",
        vec![],
        json!({"type":"disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![request_action(), values_action(), disconnect_action()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "fastcgi_connected",
        "Connected to the FastCGI application",
        request_action().example.clone(),
    )
    .with_parameters(vec![parameter(
        "remote_addr",
        "string",
        "Application address",
        true,
    )])
    .with_actions(actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "fastcgi_response",
        "The application's answer to the last request",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("request_id", "number", "FastCGI request id used", true),
        parameter(
            "status",
            "number",
            "HTTP status from the CGI Status header (200 when absent, 302 with Location)",
            false,
        ),
        parameter(
            "headers",
            "object",
            "CGI response headers, lower-case names",
            false,
        ),
        parameter(
            "body",
            "string",
            "Response body as text, or hex when body_encoding is hex",
            false,
        ),
        parameter(
            "body_encoding",
            "string",
            "How body is written: utf8 when the bytes were valid UTF-8 text, hex otherwise",
            false,
        ),
        parameter(
            "stderr",
            "string",
            "Everything the application wrote to FCGI_STDERR",
            false,
        ),
        parameter(
            "app_status",
            "number",
            "END_REQUEST application status",
            false,
        ),
        parameter(
            "protocol_status",
            "string",
            "request_complete, cant_mpx_conn, overloaded or unknown_role",
            false,
        ),
        parameter(
            "aborted",
            "boolean",
            "True when the client sent ABORT_REQUEST after its timeout",
            false,
        ),
        parameter(
            "error",
            "string",
            "Set when the output was not a CGI response or the connection failed",
            false,
        ),
    ])
    .with_actions(actions())
});
pub static VALUES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "fastcgi_values",
        "The application's FCGI_GET_VALUES_RESULT",
        request_action().example.clone(),
    )
    .with_parameters(vec![parameter(
        "values",
        "object",
        "Variable name → value as the application reported them",
        true,
    )])
    .with_actions(actions())
});

impl Protocol for FastcgiClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "FastCGI"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>FastCGI"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["fastcgi", "fcgi", "php-fpm client", "cgi"]
    }
    fn description(&self) -> &'static str {
        "FastCGI 1.0 client: sends Responder requests to an application such as php-fpm, as a web server does"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            RESPONSE_EVENT.clone(),
            VALUES_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "document_root".into(),
                type_hint: "string".into(),
                description: "Directory reported as DOCUMENT_ROOT and prefixed to each path for SCRIPT_FILENAME".into(),
                required: false,
                example: json!("/var/www/html"),
                default: Some(json!(super::DEFAULT_DOCUMENT_ROOT)),
            },
            ParameterDefinition {
                name: "request_timeout_secs".into(),
                type_hint: "integer".into(),
                description: "Seconds to wait for END_REQUEST before sending ABORT_REQUEST".into(),
                required: false,
                example: json!(10),
                default: Some(json!(super::DEFAULT_REQUEST_TIMEOUT.as_secs())),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Shared FastCGI 1.0 record codec; Responder requests with KEEP_CONN over one connection (reconnecting when the application closes it), GET_VALUES, ABORT_REQUEST on timeout; CGI response parsed by Rust")
            .llm_control("Which requests to send, with which method, path, headers and body, and what to do with each response")
            .e2e_testing("tests/client/fastcgi: flup 1.0.3 (independent WSGI FastCGI server) answers GET, POST, large and stderr-writing requests, GET_VALUES and an aborted slow request")
            .notes("Responder role only; one request at a time. Response output 1 MiB, stderr 64 KiB.")
            .max_inbound_bytes(record::MAX_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Request /index.php from the php-fpm pool at 127.0.0.1:9000"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"fastcgi","remote_addr":"127.0.0.1:9000","instruction":"Fetch /index.php and report the status"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"fastcgi_connected","handler":{"type":"static","actions":[request_action().example]}},
            {"event_pattern":"fastcgi_response","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Client for FastcgiClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("fastcgi_request") => {
                let path = v["path"].as_str().context("path is required")?;
                ensure!(
                    path.starts_with('/')
                        && path.len() <= 2048
                        && !crate::utils::sanitize::has_controls(&path),
                    "path must start with / and contain no control characters"
                );
                if let Some(m) = v.get("method").filter(|m| !m.is_null()) {
                    ensure!(
                        m.as_str().is_some_and(|m| !m.is_empty()
                            && m.len() <= 32
                            && m.bytes().all(|b| b.is_ascii_uppercase())),
                        "method must be an upper-case token"
                    );
                }
                if let Some(q) = v.get("query").filter(|q| !q.is_null()) {
                    ensure!(
                        q.as_str().is_some_and(
                            |q| q.len() <= 8192 && !crate::utils::sanitize::has_controls(&q)
                        ),
                        "query must be text without control characters"
                    );
                }
                record::check_headers(v.get("headers"))?;
                record::check_headers(v.get("params")).context("params")?;
                record::decode_body(&v)?;
            }
            Some("fastcgi_get_values") => {
                if let Some(n) = v.get("names").filter(|n| !n.is_null()) {
                    let list = n.as_array().context("names must be an array")?;
                    ensure!(
                        list.len() <= 16
                            && list.iter().all(|x| x.as_str().is_some_and(|s| !s.is_empty()
                                && s.len() <= 64
                                && s.bytes().all(|b| b.is_ascii_graphic()))),
                        "names must be up to 16 printable names"
                    );
                }
            }
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown FastCGI client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

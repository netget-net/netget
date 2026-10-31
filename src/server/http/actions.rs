//! HTTP protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// HTTP protocol action handler
pub struct HttpProtocol;

impl Default for HttpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for HttpProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        let mut params = crate::server::tls_cert_manager::get_tls_startup_parameters();
        params.extend(crate::server::http_common::handler::request_handling_startup_parameters());
        params
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // HTTP has no async actions - it's purely request-response
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![send_http_response_action()]
    }
    fn protocol_name(&self) -> &'static str {
        "HTTP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_http_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["http", "http server", "http stack", "via http", "hyper"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            // Default HTTP port is privileged; the preflight check only fires
            // when the requested port is actually < 1024.
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(80))
            .well_known_port(80)
            .implementation("hyper v1.0 HTTP/1.1 server, optional TLS via rustls")
            .llm_control("Response content (status, headers, text body) — one response per request")
            .e2e_testing(
                "THREE independent clients, none #[ignore]d and none able to skip. \
                 (1) reqwest (hyper) in tests/server/http/test.rs, 7 scenarios. \
                 (2) the real curl binary and (3) Python's http.client, both in \
                 tests/server/http/real_client_test.rs, which FAILS naming the install when \
                 either is missing. curl is libcurl, C, and parses the status line itself -- \
                 `--fail` on a 404 is asserted, so a 200 carrying the words `no such thing` \
                 would not pass. http.client is a third implementation in Python's standard \
                 library, needing no install anywhere, and it exposes the raw header list and \
                 the reason phrase, neither of which reqwest surfaces here: a custom header, a \
                 case-insensitive lookup of it, the Content-Type and a non-empty reason phrase \
                 are all asserted. Verified by changing the header value the model sets, which \
                 the test then reports. \
                 The rating rested on reqwest ALONE until September 2026, which is the shape \
                 that turned out to be hiding a total failure in etcd, grpc and mysql. \
                 Note the generic-HTTP-client caveat in the project CLAUDE.md does NOT apply \
                 here: it is about protocols layered OVER http, where reqwest proves only that \
                 an HTTP server answered. Here HTTP is the protocol. \
                 UNPROVEN: TLS (the server supports it; no test drives a real client through \
                 it), the h2c upgrade path, chunked or streaming responses, and binary bodies.",
            )
            .notes(
                "Text bodies only: no binary response bodies, no chunked/streaming responses, \
                 and request bodies are fully buffered before the LLM sees them",
            )
            .max_inbound_bytes(crate::server::http_common::MAX_REQUEST_BODY_BYTES)
            .request_only(
                "HTTP only answers requests; a server cannot send a peer anything unprompted",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Web server serving HTTP traffic"
    }
    fn example_prompt(&self) -> &'static str {
        "Pretend to be a sassy HTTP server on port 8080 serving cooking recipes"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic path routing: a canned health check and a 404 for
        // everything else, with no LLM call. Reads the event from stdin and
        // switches on event_type_id, as every handler should.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "http_request":
    if event.get("path", "/") == "/health":
        actions = [{"type": "send_http_response", "status": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"status": "ok"}'}]
    else:
        actions = [{"type": "send_http_response", "status": 404,
                    "headers": {"Content-Type": "text/plain"},
                    "body": "Not Found"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: dynamic reasoning per request path.
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "http",
                "instruction": "Serve a REST API for a blog. For GET /posts return a JSON array of posts; for GET /posts/{id} return that single post, inventing a plausible title and body from the id; return 404 with a JSON error object for any unknown path. Reason about the method and path of each request."
            }),
            // Script mode: deterministic canned response + routing (no LLM call).
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "http",
                "event_handlers": [{
                    "event_pattern": "http_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "http",
                "event_handlers": [{
                    "event_pattern": "http_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_http_response",
                            "status": 200,
                            "headers": {"Content-Type": "text/plain"},
                            "body": "Hello World"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for HttpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::http::HttpServer;

            // Parse TLS configuration from startup_params
            let tls_config = if let Some(ref params) = ctx.startup_params {
                match crate::server::tls_cert_manager::extract_tls_config_from_params(params) {
                    Ok(config) => config,
                    Err(e) => {
                        return Err(anyhow::anyhow!("Failed to create TLS config: {}", e));
                    }
                }
            } else {
                None
            };

            HttpServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                tls_config,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_http_response" => self.execute_send_http_response(action),
            _ => Err(anyhow::anyhow!("Unknown HTTP action: {action_type}")),
        }
    }
}

impl HttpProtocol {
    /// Execute send_http_response sync action
    fn execute_send_http_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Use shared action execution logic
        crate::server::http_common::execute_http_response_action(action)
    }
}

/// Action definition for send_http_response (sync)
fn send_http_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_http_response".to_string(),
        description: "Respond to the HTTP request that triggered this event. This is the ONLY \
            action that produces an HTTP response - do NOT use generic 'send_data' or \
            'show_message' for that. ALWAYS emit exactly one send_http_response for every request \
            — never return an empty action list, or the client gets a 500 error. \
            HONOR THE CLIENT'S `Accept` REQUEST HEADER (in the event's headers.accept): return a \
            `Content-Type` the client accepts, and a body in that format. If Accept is \
            `text/html`, return HTML; `application/json`, return JSON; `text/plain`, return text. \
            If the client asks ONLY for a type you cannot produce — most commonly an image \
            (`Accept: image/*`, e.g. a browser fetching /favicon.ico) or any other binary type — \
            respond `404` (or `204`) rather than sending text mislabeled as an image: the body is \
            UTF-8 text only, so binary payloads (images, gzip, protobuf) cannot be produced at \
            all. The response is sent complete, in one piece, as soon as you return; there is no \
            way to stream or chunk it, to send it in parts, or to keep the request open."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description:
                    "HTTP status code as a number between 100 and 599 (e.g. 200, 404, 500)."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "headers".to_string(),
                type_hint: "object".to_string(),
                description: "Optional response headers as a flat name->value object (e.g. \
                    {\"Content-Type\": \"text/html\"}). Set Content-Type yourself; Content-Length \
                    and Date are added automatically and must not be set here. Headers whose name \
                    or value is not legal HTTP (for example one containing a newline) are dropped."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "Response body as text (HTML, JSON, plain text). Optional: omit it \
                    for an empty body, which is what 204 and 304 require. A JSON object or array \
                    is serialized to compact JSON text. Bytes cannot be sent - text only."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_http_response",
            "status": 200,
            "headers": {
                "Content-Type": "text/html"
            },
            "body": "<html><body>Hello World</body></html>"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> {status} ({output_bytes}B)")
                .with_debug("HTTP response: status={status}, body={output_bytes}B")
                .with_trace("HTTP response: {json_pretty(.)}"),
        ),
    }
}

// ============================================================================
// HTTP Action Constants
// ============================================================================

pub static SEND_HTTP_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_http_response_action);

// ============================================================================
// HTTP Event Type Constants
// ============================================================================

/// HTTP request event - triggered when client sends an HTTP request
pub static HTTP_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "http_request",
        "HTTP request received from client. Always answer with exactly one send_http_response, \
         and match the response Content-Type to the client's Accept header (headers.accept): \
         HTML for text/html, JSON for application/json; if the client only accepts an image or \
         other binary type you cannot produce (e.g. a browser fetching /favicon.ico with \
         Accept: image/*), answer 404 rather than sending text as an image.",
        serde_json::json!({
            "type": "send_http_response",
            "status": 200,
            "headers": {
                "Content-Type": "text/html"
            },
            "body": "<html><body>Hello World</body></html>"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP method (GET, POST, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Request path without query string (e.g., '/api/users')".to_string(),
            required: true,
        },
        Parameter {
            name: "query_string".to_string(),
            type_hint: "string".to_string(),
            description: "Raw query string if present (e.g., 'x=5&y=3')".to_string(),
            required: false,
        },
        Parameter {
            name: "query".to_string(),
            type_hint: "object".to_string(),
            description:
                "Parsed query parameters as key-value pairs (e.g., {\"x\": \"5\", \"y\": \"3\"})"
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "Request headers as key-value pairs".to_string(),
            required: true,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description:
                "Request body decoded as UTF-8 text (empty string when there is no body). \
                Bytes that are not valid UTF-8 are replaced with U+FFFD, so when body_is_binary is \
                true this field is lossy and must not be treated as the exact request payload."
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "body_bytes".to_string(),
            type_hint: "number".to_string(),
            description: "Size of the request body in bytes, before UTF-8 decoding.".to_string(),
            required: false,
        },
        Parameter {
            name: "body_is_binary".to_string(),
            type_hint: "boolean".to_string(),
            description: "Present and true only when the request body is not valid UTF-8. The \
                body field is then a lossy decoding; the raw bytes are not available to you."
                .to_string(),
            required: false,
        },
    ])
    .with_actions(vec![SEND_HTTP_RESPONSE_ACTION.clone()])
    .with_alternative_example(serde_json::json!({
        "type": "send_http_response",
        "status": 404,
        "headers": {
            "Content-Type": "text/plain"
        },
        "body": "Not Found"
    }))
    .with_alternative_example(serde_json::json!({
        "type": "send_http_response",
        "status": 201,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": "{\"status\": \"created\"}"
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info(
                "{client_ip} {method} {path} -> {status} ({response_bytes}B, {duration_ms}ms)",
            )
            .with_debug("HTTP {method} {path} from {client_ip}:{client_port}")
            .with_trace("HTTP request: {json_pretty(.)}"),
    )
});

/// Get HTTP event types
pub fn get_http_event_types() -> Vec<EventType> {
    vec![HTTP_REQUEST_EVENT.clone()]
}

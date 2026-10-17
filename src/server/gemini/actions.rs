//! Gemini protocol actions: what the model is told, and how its answers become responses.
//!
//! Every action is rendered by [`super::wire`], so the model chooses a status and supplies
//! text; it never writes a header, a CRLF or a gemtext prefix.

use super::wire;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub struct GeminiProtocol;

impl GeminiProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GeminiProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for GeminiProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "cert_path".to_string(),
                type_hint: "string".to_string(),
                description: "Path to a PEM certificate for the capsule. Give key_path with it. \
                              Without both, a self-signed certificate for localhost is \
                              generated at startup - which is normal for Gemini, whose clients \
                              trust on first use rather than through a CA."
                    .to_string(),
                required: false,
                example: json!("/etc/gemini/cert.pem"),
                default: None,
            },
            ParameterDefinition {
                name: "key_path".to_string(),
                type_hint: "string".to_string(),
                description: "Path to the PEM private key for cert_path".to_string(),
                required: false,
                example: json!("/etc/gemini/key.pem"),
                default: None,
            },
            ParameterDefinition {
                name: "handshake_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a peer has to complete the TLS handshake after \
                              connecting. Default 60; a real client finishes in one round trip."
                    .to_string(),
                required: false,
                example: json!(60),
                default: Some(serde_json::json!(super::HANDSHAKE_TIMEOUT.as_secs())),
            },
            ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a peer that completed the handshake has to send its \
                              request line. Default 300, the window a `manual` rule gives a \
                              human - the peer may be NetGet's own TLS client waiting on its \
                              operator. Lower it for a public capsule."
                    .to_string(),
                required: false,
                example: json!(300),
                default: Some(serde_json::json!(super::FIRST_BYTE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_gemtext_action(),
            send_gemini_response_action(),
            send_gemini_input_action(),
            send_gemini_redirect_action(),
            close_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Gemini"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![GEMINI_REQUEST_EVENT.clone()]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>GEMINI"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["gemini", "gemini://", "gemtext", "capsule", "smolweb"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            // 1965 is unprivileged.
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(1965)
            .implementation(
                "tokio-rustls TLS 1.2/1.3 with an rcgen self-signed certificate (or \
                 cert_path/key_path); hand-written request validation, response header and \
                 gemtext rendering",
            )
            .llm_control(
                "The whole capsule: which status each URL gets, gemtext pages, input prompts, \
                 redirects and failures",
            )
            .e2e_testing(
                "tests/server/gemini/real_client_test.rs drives the Python Gemini client \
                 library ignition (pip ignition-gemini, independent of rustls: CPython's ssl \
                 module over OpenSSL) through TLS, TOFU pinning into a temporary known-hosts \
                 file, and response parsing, asserting on the status, meta and body it parsed. \
                 It fails, never skips, when python3 or ignition is absent. The same test relays \
                 the connection through a recorder and runs the pcap oracle (Wireshark's TLS \
                 dissector) over the captured bytes.",
            )
            .notes(
                "Implements the request/response protocol: one absolute gemini:// URL (at most \
                 1024 bytes) per connection, a <status> <meta> header, a body only after 2x, \
                 then close_notify and close. Refused by NetGet without the model: over-long, \
                 relative or malformed URLs, a BOM, userinfo or a fragment (59); another scheme \
                 (53, no proxying). The host is passed to the model and not checked against the \
                 certificate. No client-certificate handling: the model may answer 60-62, but \
                 no client certificate is requested or read. On backend failure the client gets \
                 41 (overloaded) or 40 (any other failure), and on a model that answered \
                 nothing, 40.",
            )
            .max_inbound_bytes(wire::MAX_REQUEST_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Gemini capsule (gemini://) over TLS - the model writes the pages"
    }
    fn example_prompt(&self) -> &'static str {
        "Gemini capsule on port 1965 - a small personal site with a home page and a guestbook"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 1965,
                "base_stack": "gemini",
                "instruction": "A small personal Gemini capsule: a home page linking to /about \
                                and /guestbook; /guestbook asks for input and thanks the visitor"
            }),
            json!({
                "type": "open_server",
                "port": 1965,
                "base_stack": "gemini",
                "event_handlers": [{
                    "event_pattern": "gemini_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json, sys\ne = json.load(sys.stdin)['event']\nif e.get('path') == '/search' and e.get('query') is None:\n    a = [{'type': 'send_gemini_input', 'prompt': 'Search for'}]\nelse:\n    a = [{'type': 'send_gemtext', 'lines': [{'type': 'heading1', 'text': 'You asked for ' + e.get('path', '/')}, {'type': 'link', 'url': '/search', 'text': 'Search'}]}]\nprint(json.dumps({'actions': a}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 1965,
                "base_stack": "gemini",
                "event_handlers": [{
                    "event_pattern": "gemini_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_gemtext",
                            "lines": [
                                {"type": "heading1", "text": "Welcome"},
                                {"type": "text", "text": "This capsule is served by NetGet."},
                                {"type": "link", "url": "gemini://geminiprotocol.net/", "text": "About Gemini"}
                            ]
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for GeminiProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let string = |name: &str| -> anyhow::Result<Option<String>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_string(name))
                    .transpose()?
                    .flatten())
            };
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            // Library callers do not necessarily install a process TLS provider.
            // File-backed certificates must work even when both providers are compiled.
            let _ = rustls::crypto::ring::default_provider().install_default();
            let tls_config = match (string("cert_path")?, string("key_path")?) {
                (Some(cert), Some(key)) => {
                    crate::server::tls_cert_manager::load_tls_config_from_files(&cert, &key)?
                }
                (None, None) => crate::server::tls_cert_manager::generate_custom_tls_config(
                    Some("localhost".to_string()),
                    Some(vec!["localhost".to_string()]),
                    Some(365),
                    Some("NetGet".to_string()),
                    Some("Gemini capsule".to_string()),
                )?,
                _ => {
                    return Err(anyhow!(
                        "cert_path and key_path must be given together (or neither, for a \
                         generated self-signed certificate)"
                    ))
                }
            };
            let deadlines = crate::server::gemini::Deadlines::new(
                secs("handshake_timeout_secs")?,
                secs("first_byte_timeout_secs")?,
            );

            crate::server::gemini::GeminiServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                tls_config,
                deadlines,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        let rendered = match action_type {
            "send_gemini_response" => {
                let status = status_of(&action)?;
                let meta = action.get("meta").and_then(Value::as_str).unwrap_or("");
                let body = action.get("body").and_then(Value::as_str);
                let (rendered, dropped) =
                    wire::render_response(status, meta, body).map_err(|e| anyhow!("{e}"))?;
                if dropped {
                    tracing::warn!(
                        "Gemini: dropped the body of a status-{status} response - only 2x \
                         responses carry one"
                    );
                }
                rendered
            }
            "send_gemtext" => {
                let items = action
                    .get("lines")
                    .and_then(Value::as_array)
                    .context("send_gemtext needs 'lines', an array of {type, text, url?, alt?}")?;
                let mut lines = Vec::with_capacity(items.len());
                for item in items {
                    let kind = item.get("type").and_then(Value::as_str).unwrap_or("text");
                    let text = item.get("text").and_then(Value::as_str).unwrap_or("");
                    let url = item.get("url").and_then(Value::as_str);
                    let alt = item.get("alt").and_then(Value::as_str);
                    lines.push(
                        wire::GemtextLine::from_parts(kind, text, url, alt)
                            .map_err(|e| anyhow!("{e}"))?,
                    );
                }
                let mime = wire::gemtext_mime(action.get("lang").and_then(Value::as_str));
                let body = wire::render_gemtext(&lines);
                wire::render_response(20, &mime, Some(&body))
                    .map_err(|e| anyhow!("{e}"))?
                    .0
            }
            "send_gemini_input" => {
                let prompt = action.get("prompt").and_then(Value::as_str).unwrap_or("");
                let sensitive = action
                    .get("sensitive")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                wire::render_response(if sensitive { 11 } else { 10 }, prompt, None)
                    .map_err(|e| anyhow!("{e}"))?
                    .0
            }
            "send_gemini_redirect" => {
                let url = action
                    .get("url")
                    .and_then(Value::as_str)
                    .filter(|u| !u.trim().is_empty())
                    .context("send_gemini_redirect needs 'url'")?;
                let permanent = action
                    .get("permanent")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                wire::render_response(if permanent { 31 } else { 30 }, url, None)
                    .map_err(|e| anyhow!("{e}"))?
                    .0
            }
            "close_connection" => return Ok(ActionResult::CloseConnection),
            _ => return Err(anyhow!("Unknown Gemini action: {}", action_type)),
        };
        Ok(ActionResult::Output(rendered.into_bytes()))
    }
}

fn status_of(action: &Value) -> Result<u16> {
    let status = action
        .get("status")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
        })
        .context("Missing or non-numeric 'status' parameter")?;
    u16::try_from(status).map_err(|_| anyhow!("status {status} is not a Gemini status"))
}

fn send_gemtext_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gemtext".to_string(),
        description: "Answer with a gemtext page (status 20, text/gemini). Give the page as \
                      structured lines; NetGet writes the gemtext syntax, so text never turns \
                      into a link or heading by accident. The titles, text and links are the \
                      ones your instructions give the page, word for word; the example's are \
                      placeholders for the shape, never data. Not for a page that asks the \
                      visitor something first - that is send_gemini_input."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "lines".to_string(),
                type_hint: "array".to_string(),
                description: "Array of {type, text, url?, alt?}. type is text, link (needs \
                              url; text is its label), heading1, heading2, heading3, list, \
                              quote or preformatted (alt is its caption). text may span \
                              several lines for text, quote and preformatted."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "lang".to_string(),
                type_hint: "string".to_string(),
                description: "Optional BCP 47 language tag for the page, e.g. en or fr".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_gemtext",
            "lines": [
                {"type": "heading1", "text": "<page title>"},
                {"type": "text", "text": "<a paragraph>"},
                {"type": "link", "url": "/<path>", "text": "<link label>"},
                {"type": "list", "text": "<a list item>"},
                {"type": "preformatted", "alt": "<caption>", "text": "<preformatted text>"}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Gemini 20 gemtext")
                .with_debug("Gemini send_gemtext"),
        ),
    }
}

fn send_gemini_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gemini_response".to_string(),
        description: "Answer with any Gemini status. 20 = success (meta is the MIME type, \
                      body is the content; prefer send_gemtext for pages), 40-44 temporary \
                      failure (44 meta = seconds to wait), 50 permanent failure, 51 not found, \
                      52 gone, 53 proxy refused, 59 bad request, 60-62 client certificate. \
                      A body is sent only with a 2x status."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "10, 11, 20, 30, 31, 40, 41, 42, 43, 44, 50, 51, 52, 53, 59, 60, \
                              61 or 62"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "meta".to_string(),
                type_hint: "string".to_string(),
                description: "One line, at most 1024 bytes: the MIME type for 20, the URL for \
                              30/31, the prompt for 10/11, an error message otherwise. Empty \
                              uses a sensible default."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "The content, for a 2x status only".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_gemini_response",
            "status": 51,
            "meta": "No such page"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Gemini {status} {meta}")
                .with_debug("Gemini send_gemini_response: status={status}"),
        ),
    }
}

fn send_gemini_input_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gemini_input".to_string(),
        description: "Ask the visitor for a line of input (status 10, or 11 for sensitive \
                      input such as a password), instead of a page: a page that asks for a \
                      name, a search term or a password before showing anything answers its \
                      first request (no query) with this alone. The client re-requests the same \
                      URL with the answer as the query."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "prompt".to_string(),
                type_hint: "string".to_string(),
                description: "The question shown to the visitor".to_string(),
                required: true,
            },
            Parameter {
                name: "sensitive".to_string(),
                type_hint: "boolean".to_string(),
                description: "true for status 11 (input is not echoed)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_gemini_input",
            "prompt": "Sign the guestbook",
            "sensitive": false
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Gemini input: {prompt}")
                .with_debug("Gemini send_gemini_input: {prompt}"),
        ),
    }
}

fn send_gemini_redirect_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_gemini_redirect".to_string(),
        description: "Redirect the visitor (status 30, or 31 for a permanent move)".to_string(),
        parameters: vec![
            Parameter {
                name: "url".to_string(),
                type_hint: "string".to_string(),
                description: "Where to go: an absolute gemini:// URL or a path on this capsule"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "permanent".to_string(),
                type_hint: "boolean".to_string(),
                description: "true for 31 (permanent)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_gemini_redirect",
            "url": "/new-home",
            "permanent": true
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Gemini redirect {url}")
                .with_debug("Gemini send_gemini_redirect: {url}"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the connection. Every Gemini response already ends the \
                      connection, so this is only for hanging up without answering."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "close_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("Gemini connection closed")
                .with_debug("Gemini close_connection"),
        ),
    }
}

/// The `answer_with` field of `gemini_request`: which single response this request takes.
///
/// Two failures in the real-model eval (llama3.1:8b, seed 42) shaped it. Told "the page
/// /guestbook asks the visitor for their name before showing anything", the model answered
/// with a page reading "What is your name?" followed by `send_gemini_input` - and only the
/// first response is ever sent, so the visitor got a page and never a prompt, five runs in
/// five. Told "serve a home page titled Welcome to the NetGet capsule", it sent the example
/// page ("Welcome", "A capsule served by NetGet.") first and the right page after it, four
/// runs in five. The request now says the prompt comes alone and first, and where a page's
/// words come from. It names the path against the home page and leads with the 51 as a literal
/// action: without that, told "only the home page exists", the model served the home page for
/// /nowhere 4 runs in 5.
pub fn answer_with_for_request(path: &str, query: Option<&str>) -> String {
    match query {
        Some(answer) => format!(
            "the visitor answered the prompt at {path} with \"{answer}\": answer with the \
             page that follows (send_gemtext), as your instructions describe it. One action \
             only"
        ),
        None => {
            let which = if path.is_empty() || path == "/" {
                " (the home page)"
            } else {
                " (not the home page, which is /)"
            };
            format!(
                "the visitor asked for {path}{which}. Exactly one action - only the first is \
                 sent. First look in your instructions for a page at {path}: if they give none \
                 there - including when they say only other pages exist - answer exactly \
                 {{\"type\": \"send_gemini_response\", \"status\": 51, \"meta\": \"Not \
                 found\"}} and nothing else. If that page asks the visitor for something (a \
                 name, a search term, a password) before showing anything, answer \
                 send_gemini_input with that question and nothing else - no page before it. \
                 Otherwise send_gemtext whose lines carry exactly the titles, text and links \
                 they give that page, word for word"
            )
        }
    }
}

/// One request: an absolute gemini:// URL.
pub static GEMINI_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "gemini_request",
        "A client requested a gemini:// URL. Answer with exactly one response - only the \
         first is sent: a page (send_gemtext), an input prompt (send_gemini_input), a \
         redirect, or a status. answer_with says which fits this request.",
        json!({
            "type": "send_gemtext",
            "lines": [
                {"type": "heading1", "text": "<page title>"},
                {"type": "link", "url": "/<path>", "text": "<link label>"}
            ]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "url".to_string(),
            type_hint: "string".to_string(),
            description: "The URL exactly as requested".to_string(),
            required: true,
        },
        Parameter {
            name: "host".to_string(),
            type_hint: "string".to_string(),
            description: "The host part of the URL".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "The path, as it appears in the URL; / when empty".to_string(),
            required: true,
        },
        Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "The percent-decoded query (the visitor's input after a 10/11), or \
                          null when the URL has none"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "Which single response this request takes: an input prompt, a page, \
                          or 51, by what the instructions say about this path and whether \
                          the visitor has answered a prompt"
                .to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Gemini {url}")
            .with_debug("Gemini gemini_request: host={host} path={path}"),
    )
    .with_actions(vec![
        send_gemtext_action(),
        send_gemini_response_action(),
        send_gemini_input_action(),
        send_gemini_redirect_action(),
        close_connection_action(),
    ])
    .with_alternative_example(json!({
        "type": "send_gemini_response",
        "status": 51,
        "meta": "Not found"
    }))
});

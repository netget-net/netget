//! PyPI protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::sync::LazyLock;

use crate::protocol::log_template::LogTemplate;

/// PyPI protocol action handler
pub struct PypiProtocol;

impl PypiProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for PypiProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // PyPI has no async actions - it's purely request-response like HTTP
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![send_pypi_response_action()]
    }
    fn protocol_name(&self) -> &'static str {
        "PyPI"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_pypi_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>PyPI"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "pypi",
            "python repository",
            "python package index",
            "pip server",
            "via pypi",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("PEP 503 Simple Repository API on hyper HTTP server")
            .llm_control("Package availability, version lists, and file serving")
            .e2e_testing(
                "Mocked E2E only. tests/server/pypi/ asserts the PEP 503 index and project \
                 pages carry the anchors and #sha256= fragments pip parses, and that a \
                 project the index does not serve comes back 404 rather than a 200 carrying \
                 the index. One step drives the real `pip index versions` and asserts it \
                 reached the index and named the project - but it SKIPS LOUDLY when pip is \
                 absent rather than failing, so it is not evidence and PyPI is rated as if \
                 it did not exist. No third-party client has installed a distribution from \
                 this server: that needs a real wheel, which the model cannot author",
            )
            .max_inbound_bytes(crate::server::http_common::MAX_REQUEST_BODY_BYTES)
            .request_only(
                "PyPI is HTTP request/response; a server cannot send a peer anything unprompted",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Python Package Index (PyPI) repository server implementing PEP 503"
    }
    fn example_prompt(&self) -> &'static str {
        "Act as a PyPI server on port 8080. Serve a package called 'hello-world' with version 1.0.0 containing a simple wheel file with setup metadata."
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "pypi",
                "instruction": "PyPI repository server. Serve package 'hello-world' version 1.0.0. Return HTML package listings for /simple/ and package files for downloads."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "pypi",
                "event_handlers": [{
                    "event_pattern": "pypi_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json,sys\nevent = json.load(sys.stdin)['event']\nhtml = {'Content-Type': 'text/html'}\nif event['request_type'] == 'list_packages':\n    action = {'type': 'send_pypi_response', 'status': 200, 'headers': html, 'body': '<!DOCTYPE html><html><body><a href=\"hello-world/\">hello-world</a></body></html>'}\nelif event['request_type'] == 'list_files':\n    action = {'type': 'send_pypi_response', 'status': 200, 'headers': html, 'body': '<!DOCTYPE html><html><body><a href=\"../../packages/hello-world/hello_world-1.0.0-py3-none-any.whl\">hello_world-1.0.0-py3-none-any.whl</a></body></html>'}\nelse:\n    action = {'type': 'send_pypi_response', 'status': 404, 'headers': {'Content-Type': 'text/plain'}, 'body': 'Not found'}\nprint(json.dumps({'actions': [action]}))"
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "pypi",
                "event_handlers": [{
                    "event_pattern": "pypi_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_pypi_response",
                            "status": 200,
                            "headers": {"Content-Type": "text/html"},
                            "body": "<!DOCTYPE html>\n<html>\n<body>\n<a href=\"hello-world/\">hello-world</a>\n</body>\n</html>"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for PypiProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::pypi::PypiServer;
            PypiServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
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
            "send_pypi_response" => self.execute_send_pypi_response(action),
            _ => Err(anyhow::anyhow!("Unknown PyPI action: {action_type}")),
        }
    }
}

impl PypiProtocol {
    /// Execute send_pypi_response sync action
    fn execute_send_pypi_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let status = match action
            .get("status")
            .and_then(|v| v.as_u64())
            .context("Missing or invalid 'status' parameter")?
        {
            status if (100..=599).contains(&status) => status as u16,
            status => anyhow::bail!("Invalid 'status' {status}: HTTP status codes are 100-599"),
        };

        let headers = action
            .get("headers")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<HashMap<String, String>>()
            })
            .unwrap_or_default();

        // The body is either UTF-8 text (PEP 503 HTML, PKG-INFO, JSON) or
        // base64-encoded bytes for a real distribution file. Exactly one of the
        // two must be present: guessing would make any hex-looking string
        // ambiguous between text and encoded bytes.
        let body = action.get("body").and_then(|v| v.as_str());
        let body_base64 = action.get("body_base64").and_then(|v| v.as_str());

        let response_data = match (body, body_base64) {
            (Some(_), Some(_)) => {
                anyhow::bail!("Provide either 'body' or 'body_base64', not both")
            }
            (None, None) => {
                anyhow::bail!("Missing 'body' parameter (or 'body_base64' for binary files)")
            }
            (Some(text), None) => json!({
                "status": status,
                "headers": headers,
                "body": text
            }),
            (None, Some(encoded)) => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .context("'body_base64' is not valid base64")?;
                json!({
                    "status": status,
                    "headers": headers,
                    "body_base64": encoded
                })
            }
        };

        Ok(ActionResult::Output(
            serde_json::to_vec(&response_data).context("Failed to serialize PyPI response")?,
        ))
    }
}

/// Action definition for send_pypi_response (sync)
fn send_pypi_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_pypi_response".to_string(),
        description: "Send a PyPI HTTP response to the current request".to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (e.g., 200, 404, 500)".to_string(),
                required: true,
            },
            Parameter {
                name: "headers".to_string(),
                type_hint: "object".to_string(),
                description: "Response headers as key-value pairs (must include Content-Type for HTML: text/html)".to_string(),
                required: false,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "Response body as UTF-8 text: the PEP 503 HTML for /simple/ endpoints, or text file content. Sent byte for byte. Required unless body_base64 is given".to_string(),
                required: false,
            },
            Parameter {
                name: "body_base64".to_string(),
                type_hint: "string".to_string(),
                description: "Response body as base64-encoded bytes, decoded before sending. Only for a real distribution file a script or static handler already holds; do not try to write wheel (ZIP) bytes by hand - pip rejects a malformed archive".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_pypi_response",
            "status": 200,
            "headers": {
                "Content-Type": "text/html"
            },
            "body": "<!DOCTYPE html>\n<html>\n<body>\n<a href=\"hello-world/\">hello-world</a>\n</body>\n</html>"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> PyPI {status} ({body_len}B)")
                .with_debug("PyPI send_pypi_response: status={status}"),
        ),
    }
}

// ============================================================================
// PyPI Action Constants
// ============================================================================

pub static SEND_PYPI_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| send_pypi_response_action());

// ============================================================================
// PyPI Event Type Constants
// ============================================================================

/// PyPI request event - triggered when client sends a PyPI HTTP request
pub static PYPI_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "pypi_request",
        "PyPI HTTP request received from client (pip, twine, etc.)",
        json!({
            "type": "send_pypi_response",
            "status": 200,
            "headers": {"Content-Type": "text/html"},
            "body": "<!DOCTYPE html>\n<html>\n<body>\n<a href=\"hello-world/\">hello-world</a>\n</body>\n</html>"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP method (usually GET for pip)".to_string(),
            required: true,
        },
        Parameter {
            name: "uri".to_string(),
            type_hint: "string".to_string(),
            description: "Request URI".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Request path (e.g., /simple/, /simple/package-name/, /packages/...)".to_string(),
            required: true,
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
            description: "Request body (usually empty for GET requests)".to_string(),
            required: false,
        },
        Parameter {
            name: "request_type".to_string(),
            type_hint: "string".to_string(),
            description: "Type of PyPI request: 'list_packages' (/simple/), 'list_files' (/simple/package/), 'download_file' (/packages/...), or 'unknown'".to_string(),
            required: true,
        },
        Parameter {
            name: "package_name".to_string(),
            type_hint: "string".to_string(),
            description: "Package name when request_type is 'list_files'; the requested file name when request_type is 'download_file'. Empty otherwise".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        SEND_PYPI_RESPONSE_ACTION.clone(),
    ])
});

/// Get PyPI event types
pub fn get_pypi_event_types() -> Vec<EventType> {
    vec![PYPI_REQUEST_EVENT.clone()]
}

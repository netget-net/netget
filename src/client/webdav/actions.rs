//! WebDAV client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// WebDAV client connected event
pub static WEBDAV_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "webdav_connected",
        "WebDAV client initialized and ready to send requests",
        json!({
            "type": "propfind",
            "path": "/dav/",
            "depth": "1"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "base_url".to_string(),
        type_hint: "string".to_string(),
        description: "Base URL for WebDAV requests".to_string(),
        required: true,
    }])
});

/// WebDAV client response received event
pub static WEBDAV_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "webdav_response_received",
        "WebDAV response received from server",
        json!({
            "type": "propfind",
            "path": "/dav/documents/",
            "depth": "1"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "status_code".to_string(),
            type_hint: "number".to_string(),
            description: "HTTP status code".to_string(),
            required: true,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "Response headers".to_string(),
            required: true,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description: "Response body (typically XML)".to_string(),
            required: true,
        },
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "WebDAV method used in request".to_string(),
            required: true,
        },
    ])
});

/// WebDAV client protocol action handler
pub struct WebdavClientProtocol;

impl WebdavClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for WebdavClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "default_headers".to_string(),
                description: "Default headers to include in all requests".to_string(),
                type_hint: "object".to_string(),
                required: false,
                example: json!({
                    "User-Agent": "NetGet/1.0",
                    "Accept": "application/xml"
                }),
                default: None,
            },
            ParameterDefinition {
                name: "auth".to_string(),
                description: "Authentication credentials (username:password)".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("username:password"),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
                ActionDefinition {
                    name: "propfind".to_string(),
                    description: "Retrieve properties of a resource (WebDAV PROPFIND)".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "path".to_string(),
                            type_hint: "string".to_string(),
                            description: "Resource path (e.g., /dav/folder/), resolved against the client's base URL. An absolute URL is accepted only on that same origin; another host needs its own client".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "depth".to_string(),
                            type_hint: "string".to_string(),
                            description: "Depth header: 0 (resource only), 1 (resource + children), infinity (all)".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "properties".to_string(),
                            type_hint: "array".to_string(),
                            description: "Specific properties to request (default: allprop)".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "propfind",
                        "path": "/dav/documents/",
                        "depth": "1"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "mkcol".to_string(),
                    description: "Create a new collection (directory)".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "path".to_string(),
                            type_hint: "string".to_string(),
                            description: "Path for new collection".to_string(),
                            required: true,
                        },
                    ],
                    example: json!({
                        "type": "mkcol",
                        "path": "/dav/newfolder/"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "copy".to_string(),
                    description: "Copy a resource to a new location".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "source".to_string(),
                            type_hint: "string".to_string(),
                            description: "Source resource path".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "destination".to_string(),
                            type_hint: "string".to_string(),
                            description: "Destination path".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "overwrite".to_string(),
                            type_hint: "boolean".to_string(),
                            description: "Whether to overwrite existing resource (default: true)".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "depth".to_string(),
                            type_hint: "string".to_string(),
                            description: "Depth for copying collections (0 or infinity)".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "copy",
                        "source": "/dav/file.txt",
                        "destination": "/dav/backup/file.txt",
                        "overwrite": true
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "move".to_string(),
                    description: "Move a resource to a new location".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "source".to_string(),
                            type_hint: "string".to_string(),
                            description: "Source resource path".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "destination".to_string(),
                            type_hint: "string".to_string(),
                            description: "Destination path".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "overwrite".to_string(),
                            type_hint: "boolean".to_string(),
                            description: "Whether to overwrite existing resource (default: true)".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "move",
                        "source": "/dav/old/file.txt",
                        "destination": "/dav/new/file.txt"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "delete".to_string(),
                    description: "Delete a resource".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "path".to_string(),
                            type_hint: "string".to_string(),
                            description: "Path to resource to delete".to_string(),
                            required: true,
                        },
                    ],
                    example: json!({
                        "type": "delete",
                        "path": "/dav/file.txt"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "put".to_string(),
                    description: "Upload a file (HTTP PUT)".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "path".to_string(),
                            type_hint: "string".to_string(),
                            description: "Path for the file".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "content".to_string(),
                            type_hint: "string".to_string(),
                            description: "File content".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "content_type".to_string(),
                            type_hint: "string".to_string(),
                            description: "Content-Type header (default: application/octet-stream)".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "put",
                        "path": "/dav/file.txt",
                        "content": "Hello, WebDAV!",
                        "content_type": "text/plain"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "get".to_string(),
                    description: "Download a file (HTTP GET)".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "path".to_string(),
                            type_hint: "string".to_string(),
                            description: "Path to file to download".to_string(),
                            required: true,
                        },
                    ],
                    example: json!({
                        "type": "get",
                        "path": "/dav/file.txt"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "disconnect".to_string(),
                    description: "Disconnect from the WebDAV server".to_string(),
                    parameters: vec![],
                    example: json!({
                        "type": "disconnect"
                    }),
                log_template: None,
                },
            ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        // Sync actions (response to events) - similar to async actions
        vec![
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Do nothing and wait for the next WebDAV response. The \
                    correct answer when what arrived needs no follow-up -- without it the \
                    model has to invent an action it does not want."
                    .to_string(),
                parameters: vec![],
                example: json!({ "type": "wait_for_more" }),
                log_template: None,
            },
            ActionDefinition {
                name: "propfind".to_string(),
                description: "Send another PROPFIND in response to received data".to_string(),
                parameters: vec![
                    Parameter {
                        name: "path".to_string(),
                        type_hint: "string".to_string(),
                        description: "Resource path, resolved against the client's base URL. An absolute URL is accepted only on that same origin; another host needs its own client".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "depth".to_string(),
                        type_hint: "string".to_string(),
                        description: "Depth header".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "propfind",
                    "path": "/dav/folder/",
                    "depth": "1"
                }),
                log_template: Some(
                    LogTemplate::new()
                        .with_info("-> WebDAV propfind {path}")
                        .with_debug("WebDAV propfind: path={path} depth={depth}"),
                ),
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "WebDAV"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "webdav_connected",
                "Triggered when WebDAV client is initialized",
                json!({"type": "placeholder", "event_id": "webdav_connected"}),
            ),
            EventType::new(
                "webdav_response_received",
                "Triggered when WebDAV client receives a response",
                json!({"type": "placeholder", "event_id": "webdav_response_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>WebDAV"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["webdav", "webdav client", "connect to webdav", "dav"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("reqwest HTTP client with WebDAV methods")
            .llm_control("Full control over WebDAV operations (PROPFIND, MKCOL, COPY, MOVE, etc.)")
            .e2e_testing("Local WebDAV server or public WebDAV endpoint")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "WebDAV client for remote file management"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to http://webdav.example.com/dav and list the contents of the root directory"
    }
    fn group_name(&self) -> &'static str {
        "File & Print"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls WebDAV operations
            json!({
                "type": "open_client",
                "remote_addr": "webdav.example.com:80",
                "base_stack": "webdav",
                "instruction": "List the contents of /dav/ and upload a test file"
            }),
            // Script mode: Code-based file operations
            json!({
                "type": "open_client",
                "remote_addr": "webdav.example.com:80",
                "base_stack": "webdav",
                "event_handlers": [{
                    "event_pattern": "webdav_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<webdav_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed directory listing
            json!({
                "type": "open_client",
                "remote_addr": "webdav.example.com:80",
                "base_stack": "webdav",
                "event_handlers": [
                    {
                        "event_pattern": "webdav_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "propfind",
                                "path": "/dav/",
                                "depth": "1"
                            }]
                        }
                    },
                    {
                        "event_pattern": "webdav_response_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "disconnect"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for WebdavClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::webdav::WebdavClient;
            WebdavClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                ctx.startup_params,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "propfind" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path' field")?
                    .to_string();

                let depth = action
                    .get("depth")
                    .and_then(|v| v.as_str())
                    .unwrap_or("1")
                    .to_string();

                let properties = action.get("properties").and_then(|v| v.as_array()).cloned();

                Ok(ClientActionResult::Custom {
                    name: "webdav_request".to_string(),
                    data: json!({
                        "method": "PROPFIND",
                        "path": path,
                        "depth": depth,
                        "properties": properties,
                    }),
                })
            }
            "mkcol" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "webdav_request".to_string(),
                    data: json!({
                        "method": "MKCOL",
                        "path": path,
                    }),
                })
            }
            "copy" => {
                let source = action
                    .get("source")
                    .and_then(|v| v.as_str())
                    .context("Missing 'source' field")?
                    .to_string();

                let destination = action
                    .get("destination")
                    .and_then(|v| v.as_str())
                    .context("Missing 'destination' field")?
                    .to_string();

                let overwrite = action
                    .get("overwrite")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);

                let depth = action
                    .get("depth")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "webdav_request".to_string(),
                    data: json!({
                        "method": "COPY",
                        "path": source,
                        "destination": destination,
                        "overwrite": overwrite,
                        "depth": depth,
                    }),
                })
            }
            "move" => {
                let source = action
                    .get("source")
                    .and_then(|v| v.as_str())
                    .context("Missing 'source' field")?
                    .to_string();

                let destination = action
                    .get("destination")
                    .and_then(|v| v.as_str())
                    .context("Missing 'destination' field")?
                    .to_string();

                let overwrite = action
                    .get("overwrite")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);

                Ok(ClientActionResult::Custom {
                    name: "webdav_request".to_string(),
                    data: json!({
                        "method": "MOVE",
                        "path": source,
                        "destination": destination,
                        "overwrite": overwrite,
                    }),
                })
            }
            "delete" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "webdav_request".to_string(),
                    data: json!({
                        "method": "DELETE",
                        "path": path,
                    }),
                })
            }
            "put" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path' field")?
                    .to_string();

                let content = action
                    .get("content")
                    .and_then(|v| v.as_str())
                    .context("Missing 'content' field")?
                    .to_string();

                let content_type = action
                    .get("content_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("application/octet-stream")
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "webdav_request".to_string(),
                    data: json!({
                        "method": "PUT",
                        "path": path,
                        "content": content,
                        "content_type": content_type,
                    }),
                })
            }
            "get" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "webdav_request".to_string(),
                    data: json!({
                        "method": "GET",
                        "path": path,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            // Declared in get_sync_actions, so it has to be executable here too --
            // advertising a name the executor rejects shows the model a tool it is
            // then punished for using.
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown WebDAV client action: {}",
                action_type
            )),
        }
    }
}

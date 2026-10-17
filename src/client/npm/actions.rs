//! NPM Registry client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// NPM client connected event
pub static NPM_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "npm_connected",
        "NPM Registry client initialized and ready to query packages",
        json!({
            "type": "get_package_info",
            "package_name": "express"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "registry_url".to_string(),
        type_hint: "string".to_string(),
        description: "NPM registry URL".to_string(),
        required: true,
    }])
});

/// NPM client package info received event
pub static NPM_CLIENT_PACKAGE_INFO_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "npm_package_info_received",
        "Package information received from NPM registry",
        json!({
            "type": "search_packages",
            "query": "express middleware"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "package_name".to_string(),
            type_hint: "string".to_string(),
            description: "Package name".to_string(),
            required: true,
        },
        Parameter {
            name: "version".to_string(),
            type_hint: "string".to_string(),
            description: "Package version (latest or specific)".to_string(),
            required: false,
        },
        Parameter {
            name: "description".to_string(),
            type_hint: "string".to_string(),
            description: "Package description".to_string(),
            required: false,
        },
        Parameter {
            name: "versions".to_string(),
            type_hint: "array".to_string(),
            description: "Available versions".to_string(),
            required: false,
        },
        Parameter {
            name: "dist".to_string(),
            type_hint: "object".to_string(),
            description: "Distribution metadata (tarball URL, shasum)".to_string(),
            required: false,
        },
    ])
});

/// NPM client search results received event
pub static NPM_CLIENT_SEARCH_RESULTS_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "npm_search_results_received",
        "Search results received from NPM registry",
        json!({
            "type": "get_package_info",
            "package_name": "express"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "Search query".to_string(),
            required: true,
        },
        Parameter {
            name: "results".to_string(),
            type_hint: "array".to_string(),
            description: "Array of matching packages".to_string(),
            required: true,
        },
        Parameter {
            name: "total".to_string(),
            type_hint: "number".to_string(),
            description: "Total number of results".to_string(),
            required: false,
        },
    ])
});

/// NPM client protocol action handler
pub struct NpmClientProtocol;

impl NpmClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for NpmClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "registry_url".to_string(),
            description: "NPM registry URL, overriding remote_addr. There is no default: \
                          with neither, the client refuses to start rather than reaching the \
                          public npm registry by omission. Name it explicitly to use it."
                .to_string(),
            type_hint: "string".to_string(),
            required: false,
            example: json!("https://registry.npmjs.org"),
            default: None,
        }]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "get_package_info".to_string(),
                description: "Get information about a specific package".to_string(),
                parameters: vec![
                    Parameter {
                        name: "package_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "NPM package name (e.g., 'express', '@types/node')"
                            .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "version".to_string(),
                        type_hint: "string".to_string(),
                        description: "Specific version or 'latest' (default: latest)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "get_package_info",
                    "package_name": "express",
                    "version": "latest"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "search_packages".to_string(),
                description: "Search for packages by keyword".to_string(),
                parameters: vec![
                    Parameter {
                        name: "query".to_string(),
                        type_hint: "string".to_string(),
                        description: "Search query".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "limit".to_string(),
                        type_hint: "number".to_string(),
                        description: "Maximum number of results (default: 20)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "search_packages",
                    "query": "http server",
                    "limit": 10
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "download_tarball".to_string(),
                description: "Download package tarball to local file".to_string(),
                parameters: vec![
                    Parameter {
                        name: "package_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "NPM package name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "version".to_string(),
                        type_hint: "string".to_string(),
                        description: "Package version (default: latest)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "output_path".to_string(),
                        type_hint: "string".to_string(),
                        description: "Local file path to save tarball".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "download_tarball",
                    "package_name": "lodash",
                    "version": "4.17.21",
                    "output_path": "./lodash.tgz"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the NPM registry".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "get_package_info".to_string(),
                description: "Get information about another package in response to received data"
                    .to_string(),
                parameters: vec![
                    Parameter {
                        name: "package_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "NPM package name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "version".to_string(),
                        type_hint: "string".to_string(),
                        description: "Specific version or 'latest'".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "get_package_info",
                    "package_name": "express"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "search_packages".to_string(),
                description: "Search for related packages in response to received data".to_string(),
                parameters: vec![Parameter {
                    name: "query".to_string(),
                    type_hint: "string".to_string(),
                    description: "Search query".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "search_packages",
                    "query": "express middleware"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "NPM"
    }
    /// Clones of the `LazyLock` statics the client actually raises, so the catalog the
    /// model is shown and the events it receives cannot diverge.
    ///
    /// This used to hand-build a second set of `EventType`s with the same ids, no
    /// parameters, and `{"type": "placeholder", "event_id": ...}` as the response
    /// example. `EventType::effective_response_example` cannot repair a placeholder
    /// without an attached action, so it fell through to `show_message` — which this
    /// protocol's own `execute_action` rejects as unknown. The model was being taught an
    /// answer its own client refuses.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            NPM_CLIENT_CONNECTED_EVENT.clone(),
            NPM_CLIENT_PACKAGE_INFO_RECEIVED_EVENT.clone(),
            NPM_CLIENT_SEARCH_RESULTS_RECEIVED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>HTTP>NPM"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "npm",
            "npm client",
            "npm registry",
            "package manager",
            "nodejs",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("reqwest HTTP client for NPM Registry API")
            .llm_control("Full control over package queries, searches, and downloads")
            .e2e_testing("Public NPM registry (registry.npmjs.org)")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "NPM Registry client for package information and downloads"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to NPM registry and search for express packages"
    }
    fn group_name(&self) -> &'static str {
        "Package Managers"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls NPM queries
            json!({
                "type": "open_client",
                "remote_addr": "registry.npmjs.org",
                "base_stack": "npm",
                "instruction": "Search for express packages and get info on the most popular one"
            }),
            // Script mode: Code-based package handling
            json!({
                "type": "open_client",
                "remote_addr": "registry.npmjs.org",
                "base_stack": "npm",
                "event_handlers": [{
                    "event_pattern": "npm_package_info_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<npm_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed package query
            json!({
                "type": "open_client",
                "remote_addr": "registry.npmjs.org",
                "base_stack": "npm",
                "event_handlers": [
                    {
                        "event_pattern": "npm_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "get_package_info",
                                "package_name": "express"
                            }]
                        }
                    },
                    {
                        "event_pattern": "npm_package_info_received",
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
impl Client for NpmClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::npm::NpmClient;
            // The declared startup parameter, honoured. `registry_url` has been in
            // `get_startup_parameters()` since this client was written and nothing
            // read it: `connect()` forwarded `ctx.remote_addr` and dropped
            // `ctx.startup_params` on the floor, so the advertised knob did nothing
            // when turned. `?`, never `unwrap()` - an undeclared or wrong-typed key
            // must produce a clean error naming it, not a panic in the connect task.
            let remote_addr = match ctx.startup_params.as_ref() {
                Some(params) => params
                    .get_optional_string("registry_url")?
                    .unwrap_or(ctx.remote_addr),
                None => ctx.remote_addr,
            };
            NpmClient::connect_with_llm_actions(
                remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
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
            "get_package_info" => {
                let package_name = action
                    .get("package_name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'package_name' field")?
                    .to_string();

                let version = action
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "latest".to_string());

                Ok(ClientActionResult::Custom {
                    name: "npm_get_package".to_string(),
                    data: json!({
                        "package_name": package_name,
                        "version": version,
                    }),
                })
            }
            "search_packages" => {
                let query = action
                    .get("query")
                    .and_then(|v| v.as_str())
                    .context("Missing 'query' field")?
                    .to_string();

                let limit = action.get("limit").and_then(|v| v.as_u64()).unwrap_or(20);

                Ok(ClientActionResult::Custom {
                    name: "npm_search".to_string(),
                    data: json!({
                        "query": query,
                        "limit": limit,
                    }),
                })
            }
            "download_tarball" => {
                let package_name = action
                    .get("package_name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'package_name' field")?
                    .to_string();

                let version = action
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "latest".to_string());

                let output_path = action
                    .get("output_path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'output_path' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "npm_download_tarball".to_string(),
                    data: json!({
                        "package_name": package_name,
                        "version": version,
                        "output_path": output_path,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown NPM client action: {}",
                action_type
            )),
        }
    }
}

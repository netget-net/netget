//! PyPI client protocol actions implementation

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

/// PyPI client connected event
pub static PYPI_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "pypi_connected",
        "PyPI client initialized and ready to interact with Python Package Index",
        json!({
            "type": "get_package_info",
            "package_name": "requests"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "index_url".to_string(),
        type_hint: "string".to_string(),
        description: "PyPI index URL".to_string(),
        required: true,
    }])
});

/// PyPI package info received event
pub static PYPI_PACKAGE_INFO_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "pypi_package_info_received",
        "Package information received from PyPI",
        json!({
            "type": "get_package_info",
            "package_name": "numpy"
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
            name: "info".to_string(),
            type_hint: "object".to_string(),
            description: "Package metadata".to_string(),
            required: true,
        },
    ])
});

/// PyPI search results received event
pub static PYPI_SEARCH_RESULTS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "pypi_search_results_received",
        "Search results received from PyPI",
        json!({
            "type": "get_package_info",
            "package_name": "numpy"
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
            description: "Search results".to_string(),
            required: true,
        },
    ])
});

/// PyPI file downloaded event
pub static PYPI_FILE_DOWNLOADED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "pypi_file_downloaded",
        "Package file downloaded from PyPI",
        // A real answer, not `{"type": "placeholder"}`. This event *is* raised, and with
        // a placeholder example and no attached actions the model was steered to
        // `show_message`, which `execute_action` rejects.
        json!({"type": "get_package_info", "package_name": "requests"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "filename".to_string(),
            type_hint: "string".to_string(),
            description: "Downloaded filename".to_string(),
            required: true,
        },
        Parameter {
            name: "size".to_string(),
            type_hint: "number".to_string(),
            description: "File size in bytes".to_string(),
            required: true,
        },
    ])
});

/// PyPI client protocol action handler
#[derive(Default)]
pub struct PypiClientProtocol;

impl PypiClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for PypiClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "index_url".to_string(),
            description: "PyPI index URL, overriding remote_addr. There is no default: with \
                          neither, the client refuses to start rather than reaching the public \
                          Python package index by omission. Name it explicitly to use it."
                .to_string(),
            type_hint: "string".to_string(),
            required: false,
            example: json!("https://pypi.org"),
            default: None,
        }]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "get_package_info".to_string(),
                description: "Get information about a package from PyPI".to_string(),
                parameters: vec![Parameter {
                    name: "package_name".to_string(),
                    type_hint: "string".to_string(),
                    description: "Name of the package to query".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "get_package_info",
                    "package_name": "requests"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "search_packages".to_string(),
                description: "Search for packages on PyPI".to_string(),
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
                    "query": "web framework",
                    "limit": 10
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "download_package".to_string(),
                description: "Download a package file (wheel or sdist) from PyPI".to_string(),
                parameters: vec![
                    Parameter {
                        name: "package_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Package name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "version".to_string(),
                        type_hint: "string".to_string(),
                        description: "Package version (latest if not specified)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "filename".to_string(),
                        type_hint: "string".to_string(),
                        description: "Specific filename to download".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "download_package",
                    "package_name": "requests",
                    "version": "2.31.0"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "list_package_files".to_string(),
                description: "List available files for a package version".to_string(),
                parameters: vec![
                    Parameter {
                        name: "package_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Package name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "version".to_string(),
                        type_hint: "string".to_string(),
                        description: "Package version (latest if not specified)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "list_package_files",
                    "package_name": "requests",
                    "version": "2.31.0"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from PyPI".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![ActionDefinition {
            name: "get_package_info".to_string(),
            description: "Get package info in response to received data".to_string(),
            parameters: vec![Parameter {
                name: "package_name".to_string(),
                type_hint: "string".to_string(),
                description: "Package name".to_string(),
                required: true,
            }],
            example: json!({
                "type": "get_package_info",
                "package_name": "numpy"
            }),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> PyPI get package {package_name}")
                    .with_debug("PyPI get_package_info: package_name={package_name}"),
            ),
        }]
    }
    fn protocol_name(&self) -> &'static str {
        "PyPI"
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
            PYPI_CLIENT_CONNECTED_EVENT.clone(),
            PYPI_PACKAGE_INFO_EVENT.clone(),
            PYPI_SEARCH_RESULTS_EVENT.clone(),
            PYPI_FILE_DOWNLOADED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>PyPI"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["pypi", "pip", "python", "package", "python package index"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("reqwest HTTP client with PyPI JSON API")
            .llm_control("Search, download packages, query metadata via JSON API")
            .e2e_testing("Real PyPI API (pypi.org)")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "PyPI client for interacting with Python Package Index"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to PyPI and search for web framework packages"
    }
    fn group_name(&self) -> &'static str {
        "Package Registries"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls PyPI queries
            json!({
                "type": "open_client",
                "remote_addr": "pypi.org",
                "base_stack": "pypi",
                "instruction": "Get information about the requests package"
            }),
            // Script mode: Code-based package handling
            json!({
                "type": "open_client",
                "remote_addr": "pypi.org",
                "base_stack": "pypi",
                "event_handlers": [{
                    "event_pattern": "pypi_package_info_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<pypi_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed package query
            json!({
                "type": "open_client",
                "remote_addr": "pypi.org",
                "base_stack": "pypi",
                "event_handlers": [
                    {
                        "event_pattern": "pypi_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "get_package_info",
                                "package_name": "requests"
                            }]
                        }
                    },
                    {
                        "event_pattern": "pypi_package_info_received",
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
impl Client for PypiClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::pypi::PypiClient;
            // The declared startup parameter, honoured. `index_url` has been in
            // `get_startup_parameters()` since this client was written and nothing
            // read it: `connect()` forwarded `ctx.remote_addr` and dropped
            // `ctx.startup_params` on the floor, so the advertised knob did nothing
            // when turned. `?`, never `unwrap()` - an undeclared or wrong-typed key
            // must produce a clean error naming it, not a panic in the connect task.
            let remote_addr = match ctx.startup_params.as_ref() {
                Some(params) => params
                    .get_optional_string("index_url")?
                    .unwrap_or(ctx.remote_addr),
                None => ctx.remote_addr,
            };
            PypiClient::connect_with_llm_actions(
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

                Ok(ClientActionResult::Custom {
                    name: "pypi_get_package_info".to_string(),
                    data: json!({
                        "package_name": package_name,
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
                    name: "pypi_search_packages".to_string(),
                    data: json!({
                        "query": query,
                        "limit": limit,
                    }),
                })
            }
            "download_package" => {
                let package_name = action
                    .get("package_name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'package_name' field")?
                    .to_string();

                let version = action
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let filename = action
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "pypi_download_package".to_string(),
                    data: json!({
                        "package_name": package_name,
                        "version": version,
                        "filename": filename,
                    }),
                })
            }
            "list_package_files" => {
                let package_name = action
                    .get("package_name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'package_name' field")?
                    .to_string();

                let version = action
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "pypi_list_package_files".to_string(),
                    data: json!({
                        "package_name": package_name,
                        "version": version,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown PyPI client action: {}",
                action_type
            )),
        }
    }
}

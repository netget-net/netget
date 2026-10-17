//! NPM protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;
use tracing::debug;

use crate::protocol::log_template::LogTemplate;

// NPM event type constants. `get_npm_event_types()` returns clones of these, so the docs, the
// event-handler action catalog and the list `call_llm` advertises to the model can never drift.
//
// Every event carries the reply action(s) that endpoint can actually produce, plus `npm_error`:
// `call_llm` prompts the model with the *event's* action list, so an event that declares none
// leaves the model with only set_memory/show_message and every npm action it returns is rejected.
pub static NPM_PACKAGE_REQUEST: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "NPM_PACKAGE_REQUEST",
        "Triggered when a client requests package metadata (GET /{package})",
        json!({
            "type": "npm_package_metadata",
            "metadata": {"name": "express", "version": "4.18.2", "description": "Fast web framework"}
        }),
    )
    .with_actions(vec![package_metadata_action(), npm_error_action()])
});

pub static NPM_TARBALL_REQUEST: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "NPM_TARBALL_REQUEST",
        "A client is downloading a package tarball (GET /{package}/-/{tarball}). Answer with \
         npm_package_tarball only if the base64-encoded .tgz was given to you — it is binary \
         and cannot be invented. Otherwise answer npm_error with 404.",
        json!({
            "type": "npm_package_tarball",
            "tarball_data": "H4sIAI0lgmoC/+3NvQrCMBSG4cxehZxZYxJrB+8myKHUn7Q0tYt470YdBGcRwfdZ3sO3nD7uDrHRVf+s3ecumQ9zRV1VjxbvdW7jX/d9974Owcyd+YJzHuNQ3pv/dJEUTypbSTo2Oi6P7aSykEmH3Hap7N4Gu5brzAAAAAAAAAAAAAAAAAAAfskNxBOA2gAoAAA="
        }),
    )
    .with_actions(vec![package_tarball_action(), npm_error_action()])
});

pub static NPM_LIST_REQUEST: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "NPM_LIST_REQUEST",
        "Triggered when a client requests the package listing (GET /-/all)",
        json!({"type": "npm_package_list", "packages": {"express": {"version": "4.18.2"}}}),
    )
    .with_actions(vec![package_list_action(), npm_error_action()])
});

pub static NPM_SEARCH_REQUEST: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "NPM_SEARCH_REQUEST",
        "Triggered when a client searches for packages (GET /-/v1/search?text=...)",
        json!({"type": "npm_package_search", "results": {"objects": [], "total": 0}}),
    )
    .with_actions(vec![package_search_action(), npm_error_action()])
});

/// NPM protocol action handler
pub struct NpmProtocol {}

impl NpmProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for NpmProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            package_metadata_action(),
            package_tarball_action(),
            package_list_action(),
            package_search_action(),
            npm_error_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "NPM"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_npm_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>NPM"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["npm"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
                .state(DevelopmentState::Beta)
                .implementation("hyper HTTP server with NPM registry endpoints")
                .llm_control("LLM controls package metadata, tarballs, listings, and search results")
                .e2e_testing("The real npm CLI, in tests/server/npm/e2e_test.rs::test_npm_with_real_cli, which is not #[ignore]d: `npm view --json` resolves netget-test-pkg@1.0.0 from the packument this server serves, and `npm install` then downloads the tarball, verifies its integrity and unpacks it into node_modules/. Both are asserted; the test also fails rather than skipping if the npm CLI is absent.")
                .notes("Implements NPM registry protocol: package metadata (GET /{package}), tarballs (GET /{package}/-/{tarball}), listing (GET /-/all), and search (GET /-/v1/search). Beta because npm itself completes both a metadata resolution and a full install against it - not merely that an HTTP client got a 200.")
                .request_only("The npm registry is HTTP request/response; a server cannot send a peer anything unprompted")
                .history(crate::protocol::metadata::HistoryMode::Off)
                .batching(crate::protocol::metadata::BatchingMode::Unsupported)
                .build()
    }
    fn description(&self) -> &'static str {
        "NPM registry server with LLM-controlled package responses"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an NPM registry on port 4873 that serves express package"
    }
    fn group_name(&self) -> &'static str {
        "Package Management"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 4873,
                "base_stack": "npm",
                "instruction": "NPM registry server. Serve 'express' package with version 4.18.2. Return package metadata for GET /{package} and search results for /-/v1/search."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 4873,
                "base_stack": "npm",
                "event_handlers": [{
                    "event_pattern": "NPM_PACKAGE_REQUEST",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "return {type='npm_package_metadata', metadata={name='express', version='4.18.2', description='Fast web framework', versions={['4.18.2']={name='express', version='4.18.2'}}}}"
                    }
                }, {
                    "event_pattern": "NPM_SEARCH_REQUEST",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "return {type='npm_package_search', results={objects={{package={name='express', version='4.18.2'}}}, total=1}}"
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 4873,
                "base_stack": "npm",
                "event_handlers": [{
                    "event_pattern": "NPM_PACKAGE_REQUEST",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "npm_package_metadata",
                            "metadata": {
                                "name": "express",
                                "version": "4.18.2",
                                "description": "Fast, unopinionated, minimalist web framework"
                            }
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for NpmProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::npm::NpmServer;
            NpmServer::spawn_with_llm_actions(
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
            "npm_package_metadata" => self.execute_package_metadata(action),
            "npm_package_tarball" => self.execute_package_tarball(action),
            "npm_package_list" => self.execute_package_list(action),
            "npm_package_search" => self.execute_package_search(action),
            "npm_error" => self.execute_npm_error(action),
            _ => Err(anyhow::anyhow!("Unknown NPM action: {}", action_type)),
        }
    }
}

impl NpmProtocol {
    fn execute_package_metadata(&self, action: serde_json::Value) -> Result<ActionResult> {
        let metadata = action.get("metadata").context("Missing 'metadata' field")?;

        debug!("NPM package metadata response");

        Ok(ActionResult::Custom {
            name: "npm_package_metadata".to_string(),
            data: json!({
                "metadata": metadata
            }),
        })
    }

    fn execute_package_tarball(&self, action: serde_json::Value) -> Result<ActionResult> {
        let tarball_data = action
            .get("tarball_data")
            .and_then(|v| v.as_str())
            .context("Missing 'tarball_data' field")?;

        debug!("NPM package tarball response");

        Ok(ActionResult::Custom {
            name: "npm_package_tarball".to_string(),
            data: json!({
                "tarball_data": tarball_data
            }),
        })
    }

    fn execute_package_list(&self, action: serde_json::Value) -> Result<ActionResult> {
        let packages = action.get("packages").context("Missing 'packages' field")?;

        debug!("NPM package list response");

        Ok(ActionResult::Custom {
            name: "npm_package_list".to_string(),
            data: json!({
                "packages": packages
            }),
        })
    }

    fn execute_package_search(&self, action: serde_json::Value) -> Result<ActionResult> {
        let results = action.get("results").context("Missing 'results' field")?;

        debug!("NPM package search response");

        Ok(ActionResult::Custom {
            name: "npm_package_search".to_string(),
            data: json!({
                "results": results
            }),
        })
    }

    fn execute_npm_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        let error_message = action
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");

        // `as u16` wraps: a `status_code` of 65736 is 200, so `npm_error` — the model's only
        // way to refuse a request — told the client the fetch had succeeded. Refuse the
        // out-of-range value rather than clamping it, and name the range for the repair loop.
        let status_code = match action.get("status_code") {
            None => 500,
            Some(v) if v.is_null() => 500,
            Some(v) => {
                let raw = v.as_u64().ok_or_else(|| {
                    anyhow::anyhow!("npm_error 'status_code' must be a number, got {v}")
                })?;
                if !(100..=599).contains(&raw) {
                    return Err(anyhow::anyhow!(
                        "npm_error 'status_code' {raw} is not an HTTP status code; use 100-599 \
                         (404 for an unknown package, 403 for a forbidden one, 500 for a \
                         registry fault)"
                    ));
                }
                raw as u16
            }
        };

        debug!("NPM error response: {} ({})", error_message, status_code);

        Ok(ActionResult::Custom {
            name: "npm_error".to_string(),
            data: json!({
                "error": error_message,
                "status_code": status_code
            }),
        })
    }
}

// Action definitions
fn package_metadata_action() -> ActionDefinition {
    ActionDefinition {
        name: "npm_package_metadata".to_string(),
        description: "Return NPM package metadata (package.json manifest)".to_string(),
        parameters: vec![Parameter {
            name: "metadata".to_string(),
            type_hint: "object".to_string(),
            description:
                "Package metadata JSON object with name, version, description, dependencies, etc."
                    .to_string(),
            required: true,
        }],
        example: json!({
            "type": "npm_package_metadata",
            "metadata": {
                "name": "express",
                "version": "4.18.2",
                "description": "Fast, unopinionated, minimalist web framework"
            }
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NPM package metadata")
                .with_debug("NPM npm_package_metadata: returned package info"),
        ),
    }
}

fn package_tarball_action() -> ActionDefinition {
    ActionDefinition {
        name: "npm_package_tarball".to_string(),
        description: "Return the package tarball (.tgz). A tarball is binary, so base64 is the \
                      only faithful form — but that also makes it the one npm response you \
                      cannot invent: send it only when the encoded bytes were given to you. \
                      With no tarball to serve, answer npm_error (404) instead."
            .to_string(),
        parameters: vec![Parameter {
            name: "tarball_data".to_string(),
            type_hint: "string".to_string(),
            description: "The complete .tgz contents, base64-encoded. It is decoded before it \
                          reaches the client, so it must be valid base64 in full: an \
                          abbreviation ending in \"...\" is refused with a 500, not sent."
                .to_string(),
            required: true,
        }],
        // A real, decodable base64 string (a 32-byte gzip stream), not an elided one.
        // The previous "H4sIAAAAAAAAA..." example was itself undecodable, so a model
        // that copied its shape produced exactly the malformed answer that used to be
        // served as an empty 200.
        example: json!({
            "type": "npm_package_tarball",
            "tarball_data": "H4sIAI0lgmoC/+3NvQrCMBSG4cxehZxZYxJrB+8myKHUn7Q0tYt470YdBGcRwfdZ3sO3nD7uDrHRVf+s3ecumQ9zRV1VjxbvdW7jX/d9974Owcyd+YJzHuNQ3pv/dJEUTypbSTo2Oi6P7aSykEmH3Hap7N4Gu5brzAAAAAAAAAAAAAAAAAAAfskNxBOA2gAoAAA="
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NPM tarball ({tarball_data_len}B)")
                .with_debug("NPM npm_package_tarball: sending tarball data"),
        ),
    }
}

fn package_list_action() -> ActionDefinition {
    ActionDefinition {
        name: "npm_package_list".to_string(),
        description: "Return list of all available NPM packages".to_string(),
        parameters: vec![Parameter {
            name: "packages".to_string(),
            type_hint: "object".to_string(),
            description: "JSON object mapping package names to their metadata".to_string(),
            required: true,
        }],
        example: json!({
            "type": "npm_package_list",
            "packages": {
                "express": {"version": "4.18.2"},
                "lodash": {"version": "4.17.21"}
            }
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NPM package list")
                .with_debug("NPM npm_package_list: listing packages"),
        ),
    }
}

fn package_search_action() -> ActionDefinition {
    ActionDefinition {
        name: "npm_package_search".to_string(),
        description: "Return NPM package search results".to_string(),
        parameters: vec![Parameter {
            name: "results".to_string(),
            type_hint: "object".to_string(),
            description: "Search results JSON object with objects array and total count"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "npm_package_search",
            "results": {
                "objects": [
                    {"package": {"name": "express", "version": "4.18.2"}}
                ],
                "total": 1
            }
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NPM search results")
                .with_debug("NPM npm_package_search: returning search results"),
        ),
    }
}

fn npm_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "npm_error".to_string(),
        description: "Return an NPM error response".to_string(),
        parameters: vec![
            Parameter {
                name: "error".to_string(),
                type_hint: "string".to_string(),
                description: "Error message".to_string(),
                required: true,
            },
            Parameter {
                name: "status_code".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (default: 500)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "npm_error",
            "error": "Package not found",
            "status_code": 404
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NPM error {status_code}: {error}")
                .with_debug("NPM npm_error: status={status_code} error={error}"),
        ),
    }
}

/// Get NPM-specific event types
///
/// These are clones of the constants `mod.rs` passes to `call_llm`, so the documented event
/// catalog and the action list the model is actually offered cannot diverge.
fn get_npm_event_types() -> Vec<EventType> {
    vec![
        NPM_PACKAGE_REQUEST.clone(),
        NPM_TARBALL_REQUEST.clone(),
        NPM_LIST_REQUEST.clone(),
        NPM_SEARCH_REQUEST.clone(),
    ]
}

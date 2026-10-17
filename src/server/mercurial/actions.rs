//! Mercurial HTTP protocol actions
//!
//! Defines the action system for the Mercurial protocol server. The LLM controls
//! capabilities, heads, branch maps and bookmark namespaces; the server owns the wire
//! framing and refuses to advertise anything it cannot honour.

use crate::llm::actions::protocol_trait::{ActionResult, Protocol, Server};
use crate::llm::actions::{ActionDefinition, Parameter};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::LazyLock;
use tracing::warn;

/// Wire commands this server actually implements.
///
/// `capabilities` is answered by the LLM, but a capability the server cannot honour is worse
/// than a missing one: advertising `unbundle` invites a push that gets a 403, and advertising
/// `bundle2` makes the client negotiate a format this server never speaks. Anything outside
/// this list is dropped with a warning.
const SUPPORTED_CAPABILITIES: &[&str] = &["branchmap", "getbundle", "listkeys"];

/// Filter a model-supplied capability list down to what this server can honour.
///
/// Always returns at least the supported set, so a client is never left with nothing to do.
pub fn sanitize_capabilities(requested: &[String]) -> Vec<String> {
    for capability in requested {
        let base = capability.split('=').next().unwrap_or(capability);
        if !SUPPORTED_CAPABILITIES.contains(&base) {
            warn!(
                "Mercurial: dropping advertised capability {:?} - this server does not implement it",
                capability
            );
        }
    }
    SUPPORTED_CAPABILITIES
        .iter()
        .map(|c| c.to_string())
        .collect()
}

/// Build an empty bundle1 changegroup.
///
/// `HG10UN` (uncompressed) followed by three empty chunk groups: no changesets, no manifests,
/// no filelogs. This is a well-formed bundle that a client accepts, and it produces an empty
/// repository. Generating a *non-empty* changegroup would mean emitting revlog deltas and
/// manifest entries, which is not implemented - see `CLAUDE.md`.
pub fn empty_bundle(bundle_type: &str) -> Vec<u8> {
    if bundle_type != "HG10UN" {
        warn!(
            "Mercurial: bundle_type {:?} is not supported, sending HG10UN (uncompressed)",
            bundle_type
        );
    }
    let mut bundle = b"HG10UN".to_vec();
    // End-of-changesets, end-of-manifests, end-of-files.
    bundle.extend_from_slice(&[0u8; 12]);
    bundle
}

/// Mercurial HTTP protocol implementation
#[derive(Clone)]
pub struct MercurialProtocol {
    _phantom: (),
}

impl MercurialProtocol {
    /// Create a new Mercurial protocol instance
    pub fn new() -> Self {
        Self { _phantom: () }
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for MercurialProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // None. create_hg_repository / delete_hg_repository / list_hg_repositories used to be
        // advertised here; there is no repository store for them to act on (protocols must not
        // implement storage) and their results were discarded, so calling them did nothing.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            hg_capabilities_action(),
            hg_heads_action(),
            hg_branchmap_action(),
            hg_listkeys_action(),
            hg_send_bundle_action(),
            hg_error_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Mercurial"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_mercurial_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Mercurial"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["mercurial", "hg", "hg server", "via mercurial", "via hg"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(8000)
            .implementation("Hand-rolled Mercurial HTTP wire protocol v1 on hyper")
            .llm_control("Capabilities, heads, branch map, bookmark namespaces")
            .e2e_testing(
                "REAL THIRD-PARTY CLIENT, for the handshake only: the real `hg` 7.2.4 in \
                 tests/server/mercurial/real_client_test.rs. NOT #[ignore]d and NOT skip-gated \
                 — it FAILS, naming `brew install mercurial`, when hg is absent. \
                 `hg debugcapabilities` runs Mercurial's own wire-protocol handshake \
                 (httppeer.performhandshake), which requires the reply to carry \
                 `Content-Type: application/mercurial-*` before it will treat us as a \
                 repository at all — something no reqwest assertion in this tree checks. The \
                 test also asserts, through hg's parser, that sanitize_capabilities STRIPPED \
                 the lookup/known/batch/unbundle/pushkey the model asked for, since advertising \
                 any of them makes hg issue a request this server 404s. \
                 THIS IS NOT A BETA CASE and the reason is the openvpn precedent, not a missing \
                 test: the server implements only the FRONT of the protocol, so no real hg \
                 command that does work can complete. MEASURED: `hg id` aborts with 'remote \
                 repository does not support the lookup capability' — and lookup CANNOT be \
                 advertised, because sanitize_capabilities substitutes a hardcoded three-entry \
                 list. `hg clone` dies one step later in discovery, where \
                 setdiscovery.findcommonheads issues `known`, which is not capability-gated so \
                 there is no way to opt out of being asked, and which this server 404s. \
                 Everything else here is reqwest, which the root CLAUDE.md rules out on its own.",
            )
            .notes(
                "Read-only and metadata-only: getbundle always answers with an EMPTY \
                 changegroup, so a clone produces an empty repository. No changegroup \
                 generation, no bundle2, no batch/known/lookup commands, no push. A real `hg` \
                 can complete the capabilities handshake and nothing beyond it: `hg id` needs \
                 `lookup` and `hg clone` needs `known`, and neither is implemented.",
            )
            .max_inbound_bytes(crate::server::mercurial::MAX_REQUEST_BODY_BYTES)
            .request_only("Mercurial is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Mercurial HTTP server for serving virtual repositories"
    }

    fn example_prompt(&self) -> &'static str {
        "listen on port 8000 via mercurial. Serve repository 'hello-world' with one head on the default branch."
    }

    fn group_name(&self) -> &'static str {
        "Web & File"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 8000,
                "base_stack": "mercurial",
                "instruction": "Mercurial HTTP server for repository 'hello-world'. Answer hg_heads with one 40-character hex node, hg_branchmap with a 'default' branch pointing at it, and hg_listkeys with no bookmarks."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 8000,
                "base_stack": "mercurial",
                "event_handlers": [{
                    "event_pattern": "hg_heads",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "respond([{'type': 'hg_heads', 'heads': ['1234567890abcdef1234567890abcdef12345678']}])"
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 8000,
                "base_stack": "mercurial",
                "event_handlers": [
                    {
                        "event_pattern": "hg_capabilities",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "hg_capabilities", "capabilities": ["branchmap", "getbundle", "listkeys"]}]
                        }
                    },
                    {
                        "event_pattern": "hg_heads",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "hg_heads", "heads": ["1234567890abcdef1234567890abcdef12345678"]}]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for MercurialProtocol {
    fn spawn(&self, ctx: SpawnContext) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(async move {
            crate::server::mercurial::MercurialServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing action type"))?;

        match action_type {
            "hg_capabilities" => {
                let capabilities = action
                    .get("capabilities")
                    .ok_or_else(|| anyhow!("Missing capabilities"))?;

                Ok(ActionResult::Custom {
                    name: "hg_capabilities_response".to_string(),
                    data: json!({ "capabilities": capabilities }),
                })
            }
            "hg_heads" => {
                let heads = action
                    .get("heads")
                    .ok_or_else(|| anyhow!("Missing heads"))?;

                Ok(ActionResult::Custom {
                    name: "hg_heads_response".to_string(),
                    data: json!({ "heads": heads }),
                })
            }
            "hg_branchmap" => {
                let branches = action
                    .get("branches")
                    .ok_or_else(|| anyhow!("Missing branches"))?;

                Ok(ActionResult::Custom {
                    name: "hg_branchmap_response".to_string(),
                    data: json!({ "branches": branches }),
                })
            }
            "hg_listkeys" => {
                let keys = action.get("keys").ok_or_else(|| anyhow!("Missing keys"))?;

                Ok(ActionResult::Custom {
                    name: "hg_listkeys_response".to_string(),
                    data: json!({ "keys": keys }),
                })
            }
            "hg_send_bundle" => Ok(ActionResult::Custom {
                name: "hg_bundle_response".to_string(),
                data: json!({
                    "bundle_type": action
                        .get("bundle_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("HG10UN")
                }),
            }),
            "hg_error" => {
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Missing error message"))?;
                let code = action.get("code").and_then(|v| v.as_u64()).unwrap_or(500);

                Ok(ActionResult::Custom {
                    name: "hg_error_response".to_string(),
                    data: json!({ "message": message, "code": code }),
                })
            }
            _ => Err(anyhow!("Unknown Mercurial action: {}", action_type)),
        }
    }
}

fn hg_capabilities_action() -> ActionDefinition {
    ActionDefinition {
        name: "hg_capabilities".to_string(),
        description: format!(
            "Advertise Mercurial server capabilities. Only {} are implemented; anything else \
             is dropped before it reaches the client.",
            SUPPORTED_CAPABILITIES.join(", ")
        ),
        parameters: vec![Parameter {
            name: "capabilities".to_string(),
            type_hint: "array".to_string(),
            description: "Array of capability strings".to_string(),
            required: true,
        }],
        example: json!({
            "type": "hg_capabilities",
            "capabilities": ["branchmap", "getbundle", "listkeys"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> {capabilities_len} capabilities")
                .with_debug("Mercurial capabilities: {capabilities}"),
        ),
    }
}

fn hg_heads_action() -> ActionDefinition {
    ActionDefinition {
        name: "hg_heads".to_string(),
        description: "Provide repository heads (changeset node IDs)".to_string(),
        parameters: vec![Parameter {
            name: "heads".to_string(),
            type_hint: "array".to_string(),
            description: "Array of node IDs, each exactly 40 hex characters. Entries that are not \
                 40-character hex are dropped, so write them out in full rather than as \
                 'abc123...'. An empty array means an empty repository."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "hg_heads",
            "heads": ["1234567890abcdef1234567890abcdef12345678"]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> {heads_len} heads")
                .with_debug("Mercurial heads: {heads_len} nodes"),
        ),
    }
}

fn hg_branchmap_action() -> ActionDefinition {
    ActionDefinition {
        name: "hg_branchmap".to_string(),
        description: "Provide branch name to node ID mappings".to_string(),
        parameters: vec![Parameter {
            name: "branches".to_string(),
            type_hint: "object".to_string(),
            description: "Object mapping branch names to arrays of 40-character hex node IDs"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "hg_branchmap",
            "branches": {
                "default": ["1234567890abcdef1234567890abcdef12345678"]
            }
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> branchmap sent")
                .with_debug("Mercurial branchmap: {branches}"),
        ),
    }
}

fn hg_listkeys_action() -> ActionDefinition {
    ActionDefinition {
        name: "hg_listkeys".to_string(),
        description: "Provide key-value mappings for a namespace (bookmarks, tags, etc.)"
            .to_string(),
        parameters: vec![Parameter {
            name: "keys".to_string(),
            type_hint: "object".to_string(),
            description: "Object mapping keys to values; use {} for an empty namespace".to_string(),
            required: true,
        }],
        example: json!({
            "type": "hg_listkeys",
            "keys": {
                "@": "1234567890abcdef1234567890abcdef12345678"
            }
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> listkeys sent")
                .with_debug("Mercurial listkeys: {keys}"),
        ),
    }
}

fn hg_send_bundle_action() -> ActionDefinition {
    ActionDefinition {
        name: "hg_send_bundle".to_string(),
        description:
            "Answer a getbundle request. NOTE: this server can only send an EMPTY changegroup - \
             a clone against it produces a repository with no changesets. There is no parameter \
             for changeset data because generating a Mercurial changegroup (revlog deltas, \
             manifests, filelogs) is not implemented."
                .to_string(),
        parameters: vec![Parameter {
            name: "bundle_type".to_string(),
            type_hint: "string".to_string(),
            description: "Bundle format; only \"HG10UN\" (uncompressed) is supported".to_string(),
            required: false,
        }],
        example: json!({
            "type": "hg_send_bundle",
            "bundle_type": "HG10UN"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> empty bundle ({bundle_type})")
                .with_debug("Mercurial send bundle: type={bundle_type}"),
        ),
    }
}

fn hg_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "hg_error".to_string(),
        description: "Refuse the request with an HTTP error (e.g. repository not found)"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message".to_string(),
                required: true,
            },
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (default: 500)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "hg_error",
            "message": "Repository not found",
            "code": 404
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> error {code}: {message}")
                .with_debug("Mercurial error: code={code}, message={message}"),
        ),
    }
}

fn repository_parameter() -> Parameter {
    Parameter {
        name: "repository".to_string(),
        type_hint: "string".to_string(),
        description: "Repository name taken from the URL path".to_string(),
        required: true,
    }
}

fn client_ip_parameter() -> Parameter {
    Parameter {
        name: "client_ip".to_string(),
        type_hint: "string".to_string(),
        description: "Address of the connecting client".to_string(),
        required: false,
    }
}

fn error_alternative() -> Value {
    json!({
        "type": "hg_error",
        "message": "Repository not found",
        "code": 404
    })
}

/// `GET /?cmd=capabilities` - the first request of any hg operation.
pub static HG_CAPABILITIES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hg_capabilities",
        "Mercurial client asked which capabilities the server supports",
        json!({
            "type": "hg_capabilities",
            "capabilities": ["branchmap", "getbundle", "listkeys"]
        }),
    )
    .with_parameters(vec![repository_parameter(), client_ip_parameter()])
    .with_actions(vec![hg_capabilities_action(), hg_error_action()])
    .with_alternative_example(error_alternative())
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} hg capabilities {repository}")
            .with_debug("Mercurial capabilities: repository={repository}"),
    )
});

/// `GET /?cmd=heads`
pub static HG_HEADS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hg_heads",
        "Mercurial client asked for the repository heads",
        json!({
            "type": "hg_heads",
            "heads": ["1234567890abcdef1234567890abcdef12345678"]
        }),
    )
    .with_parameters(vec![repository_parameter(), client_ip_parameter()])
    .with_actions(vec![hg_heads_action(), hg_error_action()])
    .with_alternative_example(error_alternative())
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} hg heads {repository}")
            .with_debug("Mercurial heads: repository={repository}"),
    )
});

/// `GET /?cmd=branchmap`
pub static HG_BRANCHMAP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hg_branchmap",
        "Mercurial client asked for the branch map",
        json!({
            "type": "hg_branchmap",
            "branches": {"default": ["1234567890abcdef1234567890abcdef12345678"]}
        }),
    )
    .with_parameters(vec![repository_parameter(), client_ip_parameter()])
    .with_actions(vec![hg_branchmap_action(), hg_error_action()])
    .with_alternative_example(error_alternative())
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} hg branchmap {repository}")
            .with_debug("Mercurial branchmap: repository={repository}"),
    )
});

/// `GET /?cmd=listkeys&namespace=...`
pub static HG_LISTKEYS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hg_listkeys",
        "Mercurial client asked for the keys of a namespace (bookmarks, tags, phases)",
        json!({
            "type": "hg_listkeys",
            "keys": {}
        }),
    )
    .with_parameters(vec![
        repository_parameter(),
        Parameter {
            name: "namespace".to_string(),
            type_hint: "string".to_string(),
            description: "Namespace requested: bookmarks, tags, phases or namespaces".to_string(),
            required: true,
        },
        client_ip_parameter(),
    ])
    .with_actions(vec![hg_listkeys_action(), hg_error_action()])
    .with_alternative_example(error_alternative())
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} hg listkeys {namespace}")
            .with_debug("Mercurial listkeys: repository={repository}, namespace={namespace}"),
    )
});

/// `GET|POST /?cmd=getbundle`
pub static HG_GETBUNDLE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hg_getbundle",
        "Mercurial client asked for changesets (clone or pull). Only an empty changegroup can \
         be sent.",
        json!({
            "type": "hg_send_bundle",
            "bundle_type": "HG10UN"
        }),
    )
    .with_parameters(vec![
        repository_parameter(),
        Parameter {
            name: "heads".to_string(),
            type_hint: "string".to_string(),
            description: "Heads the client asked for, as sent in the request arguments".to_string(),
            required: false,
        },
        Parameter {
            name: "common".to_string(),
            type_hint: "string".to_string(),
            description: "Nodes the client already has, as sent in the request arguments"
                .to_string(),
            required: false,
        },
        client_ip_parameter(),
    ])
    .with_actions(vec![hg_send_bundle_action(), hg_error_action()])
    .with_alternative_example(error_alternative())
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} hg getbundle {repository}")
            .with_debug("Mercurial getbundle: repository={repository}, heads={heads}"),
    )
});

pub fn get_mercurial_event_types() -> Vec<EventType> {
    vec![
        HG_CAPABILITIES_EVENT.clone(),
        HG_HEADS_EVENT.clone(),
        HG_BRANCHMAP_EVENT.clone(),
        HG_LISTKEYS_EVENT.clone(),
        HG_GETBUNDLE_EVENT.clone(),
    ]
}

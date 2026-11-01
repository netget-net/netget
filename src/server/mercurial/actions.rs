//! Mercurial HTTP protocol actions
//!
//! Defines the action system for the Mercurial protocol server. The LLM controls
//! capabilities, heads, branch maps and bookmark namespaces; the server owns the wire
//! framing and refuses to advertise anything it cannot honour.

use super::changegroup;
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
/// than a missing one: advertising `unbundle` or `pushkey` invites a push that gets a 403, and
/// advertising `bundle2` makes the client negotiate a format this server never speaks. Anything
/// outside this list is dropped with a warning.
const SUPPORTED_CAPABILITIES: &[&str] = &[
    "batch",
    "branchmap",
    "getbundle",
    "known",
    "listkeys",
    "lookup",
];

/// Filter a model-supplied capability list down to what this server can honour.
///
/// Always returns the whole supported set, so a client is never left with nothing to do.
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

/// The capabilities this server advertises, in the order it advertises them.
pub fn supported_capabilities() -> Vec<String> {
    sanitize_capabilities(&[])
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
            hg_repository_action(),
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
            .implementation(
                "Hand-rolled Mercurial HTTP wire protocol v1 on hyper; histories become revlog \
                 nodes and a version-1 changegroup in changegroup.rs",
            )
            .llm_control(
                "The whole repository history (hg_repository: commits with author, date, \
                 message, parents, branch and text files), or per-command metadata \
                 (capabilities, heads, branch map, listkeys)",
            )
            .e2e_testing(
                "REAL THIRD-PARTY CLIENT: the real `hg` 7.2.4 in \
                 tests/server/mercurial/real_client_test.rs, NOT #[ignore]d and NOT skip-gated \
                 - it FAILS, naming `brew install mercurial`, when hg is absent. A static \
                 hg_repository handler serves five commits (a named branch, a merge, a removal, \
                 an executable, an empty file, a file starting with filelog's metadata marker); \
                 `hg clone` runs discovery (heads and known, batched) and getbundle, `hg verify` recomputes \
                 every changelog, manifest and filelog node, and `hg cat`, `hg log` and \
                 `hg manifest -v` assert the exact bytes and history described. `hg id <url>` \
                 resolves tip through lookup, and `hg clone -r 1` + `hg pull` exercise lookup, \
                 a non-empty known and a partial changegroup whose deltas start from revisions \
                 the client already holds. A refused history reaches hg as `abort: remote \
                 error:` with the reason kept in the log. `hg debugcapabilities` asserts the \
                 handshake and that unbundle/pushkey/bundle2 are never advertised. \
                 tests/server/mercurial/changegroup_test.rs covers every MAX_* bound. One \
                 client only, no pcap oracle (Wireshark has no Mercurial dissector) and no \
                 fuzz target.",
            )
            .notes(
                "Read-only: clone and pull work, push does not (unbundle/pushkey refused). \
                 Bundle1 only - getbundle answers a zlib-compressed cg1 changegroup, which hg \
                 7.x still pulls from a server that does not advertise bundle2. Every node is \
                 derived from the described history on every request, so the model must \
                 describe the same history each time. No bookmarks or tags (hg reads listkeys \
                 only from a pushkey server), no stream clone, no \
                 authentication, no SSH transport. Files are text only.",
            )
            .max_inbound_bytes(crate::server::mercurial::MAX_REQUEST_BODY_BYTES)
            .request_only("Mercurial is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Mercurial HTTP server that serves a described commit history to hg clone and pull"
    }

    fn example_prompt(&self) -> &'static str {
        "listen on port 8000 via mercurial. Serve repository 'hello-world' with two commits: a README, then a change to it."
    }

    fn group_name(&self) -> &'static str {
        "Web & File"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Every mode answers with one history, so a real `hg clone` completes. The static and
        // script modes answer every event (`*`) with the same `hg_repository`, which is what
        // keeps the nodes the client sees in `heads` and the changesets `getbundle` sends in
        // agreement.
        let history = json!({
            "type": "hg_repository",
            "commits": [
                {
                    "id": "init",
                    "author": "NetGet <netget@localhost>",
                    "date": "2026-10-01T09:00:00+00:00",
                    "message": "Initial commit",
                    "files": [{"path": "README", "content": "Hello from NetGet\n"}]
                },
                {
                    "id": "docs",
                    "date": "2026-10-02T09:00:00+00:00",
                    "message": "Expand the README",
                    "files": [{"path": "README", "content": "Hello from NetGet\nServed over hg.\n"}]
                }
            ]
        });
        let script = format!("respond([{}])", history);

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 8000,
                "base_stack": "mercurial",
                "instruction": "Mercurial HTTP server for repository 'hello-world'. Answer every request with hg_repository describing the same two commits, dated 2026-10-01T09:00:00+00:00 and 2026-10-02T09:00:00+00:00: 'Initial commit' adding README with the text 'Hello from NetGet', then 'Expand the README' adding a second line 'Served over hg.'."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 8000,
                "base_stack": "mercurial",
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 8000,
                "base_stack": "mercurial",
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {"type": "static", "actions": [history]}
                }]
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
            "hg_repository" => {
                // Only the shape is checked here. The history itself is built - and refused
                // with an hg error naming nothing internal - by the command handler, which is
                // the one place that knows which command it is answering.
                let commits = action
                    .get("commits")
                    .ok_or_else(|| anyhow!("Missing commits"))?;
                if !commits.is_array() {
                    return Err(anyhow!("commits must be an array of commit objects"));
                }
                Ok(ActionResult::Custom {
                    name: REPOSITORY_RESPONSE.to_string(),
                    data: json!({ "commits": commits }),
                })
            }
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
                data: json!({}),
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
        description: "Answer a getbundle request with an EMPTY changegroup: the client receives \
             no changesets. To serve real history, answer with hg_repository instead."
            .to_string(),
        parameters: vec![],
        example: json!({
            "type": "hg_send_bundle"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> empty changegroup")
                .with_debug("Mercurial send empty changegroup"),
        ),
    }
}

/// `Custom` result name of an `hg_repository` action.
pub const REPOSITORY_RESPONSE: &str = "hg_repository_response";

/// The example history every `hg_repository` example shows: two commits on `default`.
fn example_repository() -> Value {
    json!({
        "type": "hg_repository",
        "commits": [
            {
                "id": "init",
                "author": "Ada Lovelace <ada@example.com>",
                "date": "2026-10-01T09:00:00+00:00",
                "message": "Initial commit",
                "files": [
                    {"path": "README", "content": "Hello from NetGet\n"},
                    {"path": "src/main.py", "content": "print('hello')\n"}
                ]
            },
            {
                "id": "docs",
                "parents": ["init"],
                "author": "Ada Lovelace <ada@example.com>",
                "date": "2026-10-02T09:00:00+00:00",
                "message": "Expand the README",
                "files": [
                    {"path": "README", "content": "Hello from NetGet\nServed over hg.\n"}
                ]
            }
        ]
    })
}

fn hg_repository_action() -> ActionDefinition {
    ActionDefinition {
        name: "hg_repository".to_string(),
        description: format!(
            "Describe the whole repository as a history of commits; the server derives every \
             changeset id, manifest and file revision from it and answers any command \
             (capabilities, heads, branchmap, known, lookup, getbundle) from it, so a real \
             `hg clone` receives exactly these commits. You never write node ids: they are \
             SHA-1 hashes the server computes. Describe the SAME history, with the same dates, \
             every time - a different description is a different repository. List parents \
             before children. Limits: {} commits, {} files+removals per commit, {} distinct \
             paths, {} bytes per file, {} bytes of file content in total.",
            changegroup::MAX_COMMITS,
            changegroup::MAX_CHANGES_PER_COMMIT,
            changegroup::MAX_PATHS,
            changegroup::MAX_FILE_BYTES,
            changegroup::MAX_TOTAL_CONTENT_BYTES
        ),
        parameters: vec![Parameter {
            name: "commits".to_string(),
            type_hint: "array".to_string(),
            description: "Commits oldest first. Each is an object: `message` (required); \
                 `id` (a label of your choice, used only to name parents); `parents` (array of \
                 up to two earlier ids; omitted means the previous commit, [] means a root); \
                 `author` (\"Name <email>\", default \"NetGet <netget@localhost>\"); `date` \
                 (RFC 3339 such as \"2026-10-31T12:00:00+01:00\", or Unix seconds; default \
                 1700000000); `branch` (default \"default\"); `files` (array of {\"path\", \
                 \"content\" as text, optional \"executable\": true} - the files this commit \
                 adds or changes); `removed` (array of paths this commit deletes). Each commit \
                 starts from its first parent's files; a merge also keeps paths only its second \
                 parent has. An empty array is an empty repository."
                .to_string(),
            required: true,
        }],
        example: example_repository(),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> repository of {commits_len} commits")
                .with_debug("Mercurial repository: {commits_len} commits"),
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
            "capabilities": ["batch", "branchmap", "getbundle", "known", "listkeys", "lookup"]
        }),
    )
    .with_parameters(vec![repository_parameter(), client_ip_parameter()])
    .with_actions(vec![
        hg_capabilities_action(),
        hg_repository_action(),
        hg_error_action(),
    ])
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
        example_repository(),
    )
    .with_parameters(vec![repository_parameter(), client_ip_parameter()])
    .with_actions(vec![
        hg_repository_action(),
        hg_heads_action(),
        hg_error_action(),
    ])
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
        example_repository(),
    )
    .with_parameters(vec![repository_parameter(), client_ip_parameter()])
    .with_actions(vec![
        hg_repository_action(),
        hg_branchmap_action(),
        hg_error_action(),
    ])
    .with_alternative_example(error_alternative())
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} hg branchmap {repository}")
            .with_debug("Mercurial branchmap: repository={repository}"),
    )
});

/// `GET /?cmd=listkeys&namespace=...`
///
/// hg asks for listkeys only from a server advertising `pushkey`, which this one does not
/// (push is refused), so a real client never raises it; it is answered for anything that asks.
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
    .with_actions(vec![
        hg_listkeys_action(),
        hg_repository_action(),
        hg_error_action(),
    ])
    .with_alternative_example(error_alternative())
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} hg listkeys {namespace}")
            .with_debug("Mercurial listkeys: repository={repository}, namespace={namespace}"),
    )
});

/// `GET /?cmd=known&nodes=...` - discovery asking which of the client's changesets the server
/// has. Raised only when the client sends at least one node: an empty question (every clone
/// into an empty repository asks one) is answered with an empty answer without asking anyone.
pub static HG_KNOWN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hg_known",
        "Mercurial client asked which of its changesets this repository has (pull discovery)",
        example_repository(),
    )
    .with_parameters(vec![
        repository_parameter(),
        Parameter {
            name: "nodes".to_string(),
            type_hint: "string".to_string(),
            description: "Space-separated changeset ids the client holds".to_string(),
            required: true,
        },
        client_ip_parameter(),
    ])
    .with_actions(vec![hg_repository_action(), hg_error_action()])
    .with_alternative_example(error_alternative())
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} hg known {repository}")
            .with_debug("Mercurial known: repository={repository}, nodes={nodes}"),
    )
});

/// `GET /?cmd=lookup&key=...` - resolve a revision symbol (`hg id <url>`, `hg clone -r`).
pub static HG_LOOKUP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hg_lookup",
        "Mercurial client asked to resolve a revision (tip, a branch, a revision number or \
         id prefix)",
        example_repository(),
    )
    .with_parameters(vec![
        repository_parameter(),
        Parameter {
            name: "key".to_string(),
            type_hint: "string".to_string(),
            description: "The revision symbol to resolve".to_string(),
            required: true,
        },
        client_ip_parameter(),
    ])
    .with_actions(vec![hg_repository_action(), hg_error_action()])
    .with_alternative_example(error_alternative())
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} hg lookup {key}")
            .with_debug("Mercurial lookup: repository={repository}, key={key}"),
    )
});

/// `GET|POST /?cmd=getbundle`
pub static HG_GETBUNDLE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hg_getbundle",
        "Mercurial client asked for changesets (clone or pull). Answer with hg_repository: the \
         server sends every changeset the client asked for and does not already have.",
        example_repository(),
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
    .with_actions(vec![
        hg_repository_action(),
        hg_send_bundle_action(),
        hg_error_action(),
    ])
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
        HG_KNOWN_EVENT.clone(),
        HG_LOOKUP_EVENT.clone(),
        HG_GETBUNDLE_EVENT.clone(),
    ]
}

//! Git Smart HTTP protocol actions
//!
//! The model describes a repository as structured data - branch, commit message, and a list
//! of `{path, content}` files - and the server compiles that into real Git objects
//! (`super::pack`). It never asks the model for object IDs or pack bytes: SHA-1s are derived
//! from the content, so the refs advertised by `GET /info/refs` and the objects in the pack
//! returned by `POST /git-upload-pack` agree and `git clone` can actually complete.

use crate::llm::actions::protocol_trait::{ActionResult, Protocol, Server};
use crate::llm::actions::{ActionDefinition, Parameter, ParameterDefinition};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::LazyLock;

/// Commit timestamp used when the action does not supply one.
///
/// Fixed, not "now": a clone is two HTTP requests, each answered separately, and the commit
/// timestamp is part of the commit object. A wall-clock default would give the two requests
/// different commit SHAs and the clone would fail with "did not send all necessary objects".
pub const DEFAULT_COMMIT_TIMESTAMP: i64 = 1_700_000_000;

/// Branch used when neither the action nor the `default_branch` startup parameter says.
pub const FALLBACK_BRANCH: &str = "main";

/// Git Smart HTTP protocol implementation
#[derive(Clone)]
pub struct GitProtocol {
    _phantom: (),
}

impl GitProtocol {
    /// Create a new Git protocol instance
    pub fn new() -> Self {
        Self { _phantom: () }
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for GitProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "default_branch".to_string(),
            type_hint: "string".to_string(),
            description:
                "Branch name used when a git_repository action does not name one (default: main)"
                    .to_string(),
            required: false,
            example: json!("main"),
            default: None,
        }]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // None. This protocol used to advertise create_git_repository / delete_git_repository /
        // list_git_repositories; there is no repository store for them to act on (protocols
        // must not implement storage), and their results were discarded, so they were three
        // actions the model could call that did nothing at all. The repository is described
        // per-request by git_repository instead.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![git_repository_action(), git_error_action()]
    }

    fn protocol_name(&self) -> &'static str {
        "Git"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_git_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Git"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["git", "git server", "via git"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .implementation("Hand-rolled Git Smart HTTP v0 (pkt-line + pack v2) on hyper")
            .llm_control("Branch, commit metadata and file contents; object IDs are computed")
            .e2e_testing(
                "The real `git` binary is the client: `git clone http://127.0.0.1:PORT/test-repo` \
                 completes a Smart HTTP v0 fetch, then `git fsck --full` validates the pack we \
                 sent, `git log -1 --format=%s` and `git show HEAD:README.md` assert the commit \
                 subject and exact blob bytes, `git branch --show-current` asserts the branch, \
                 and the checked-out tree is compared byte-for-byte including a nested path and \
                 the executable bit (tests/server/git/e2e_test.rs, not #[ignore]d)",
            )
            .notes(
                "Read-only (clone/fetch), single commit, no history, no push. A clone needs \
                 the same snapshot from both the info/refs and the git-upload-pack event; a \
                 static or script handler guarantees that, an LLM answering twice does not.",
            )
            .max_inbound_bytes(crate::server::git::MAX_UPLOAD_PACK_BYTES)
            .request_only("Git smart HTTP is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Git Smart HTTP server for serving virtual repositories"
    }

    fn example_prompt(&self) -> &'static str {
        "listen on port 9418 via git. Serve repository 'hello-world' on branch main with README.md containing '# Hello World'"
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
                "port": 9418,
                "base_stack": "git",
                "instruction": "Git HTTP server. Serve repository 'hello-world' on branch main containing README.md with the text '# Hello World'. Answer git_info_refs and git_upload_pack with exactly the same git_repository action every time."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 9418,
                "base_stack": "git",
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "respond([{'type': 'git_repository', 'branch': 'main', 'files': [{'path': 'README.md', 'content': '# ' + event['repository'] + '\\n'}]}])"
                    }
                }]
            }),
            // Static mode - the deterministic path, and the one a clone is guaranteed to work on
            json!({
                "type": "open_server",
                "port": 9418,
                "base_stack": "git",
                "event_handlers": [{
                    // One handler for both git_info_refs and git_upload_pack: the same
                    // snapshot must answer both requests of a clone.
                    "event_pattern": "*",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "git_repository",
                            "branch": "main",
                            "commit_message": "Initial commit",
                            "files": [{"path": "README.md", "content": "# Hello World\n"}]
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for GitProtocol {
    fn spawn(&self, ctx: SpawnContext) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(async move {
            let default_branch = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("default_branch"))
                .transpose()?
                .flatten()
                .unwrap_or_else(|| FALLBACK_BRANCH.to_string());

            crate::server::git::GitServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                default_branch,
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
            "git_repository" => {
                let files = action
                    .get("files")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| {
                        anyhow!("git_repository requires a 'files' array (it may be empty)")
                    })?;

                // Validate here so a bad path is reported as an action failure the model can
                // see, rather than surfacing later as an opaque HTTP 500.
                for file in files {
                    let path = file
                        .get("path")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow!("Every entry of 'files' needs a 'path' string"))?;
                    if file.get("content").map(|c| !c.is_string()).unwrap_or(false) {
                        return Err(anyhow!(
                            "File {path:?}: 'content' must be a string (text only)"
                        ));
                    }
                }

                Ok(ActionResult::Custom {
                    name: "git_repository_response".to_string(),
                    data: json!({
                        "branch": action.get("branch").and_then(|v| v.as_str()),
                        "files": files,
                        "commit_message": action.get("commit_message").and_then(|v| v.as_str()),
                        "author_name": action.get("author_name").and_then(|v| v.as_str()),
                        "author_email": action.get("author_email").and_then(|v| v.as_str()),
                        "timestamp": action.get("timestamp").and_then(|v| v.as_i64()),
                    }),
                })
            }
            "git_error" => {
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Missing error message"))?;
                let code = action.get("code").and_then(|v| v.as_u64()).unwrap_or(500);

                Ok(ActionResult::Custom {
                    name: "git_error_response".to_string(),
                    data: json!({
                        "message": message,
                        "code": code
                    }),
                })
            }
            _ => Err(anyhow!("Unknown Git action: {}", action_type)),
        }
    }
}

fn git_repository_action() -> ActionDefinition {
    ActionDefinition {
        name: "git_repository".to_string(),
        description:
            "Describe the repository to serve. The server turns this into real Git objects and \
             computes every SHA itself, so do NOT invent commit or blob hashes. Answer both \
             git_info_refs and git_upload_pack with this action, and with the SAME content each \
             time - a clone fetches refs and objects in two separate requests, and if the second \
             answer differs from the first the client rejects the result."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "files".to_string(),
                type_hint: "array".to_string(),
                description:
                    "Files in the repository. Each entry: path (string, relative, no '..' or \
                     '.git'), content (string, UTF-8 text), executable (boolean, optional). An \
                     empty array serves a repository whose single commit has no files."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "branch".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Branch name to publish, e.g. 'main' (default: the server's default_branch)"
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "commit_message".to_string(),
                type_hint: "string".to_string(),
                description: "Commit message (default: 'Initial commit')".to_string(),
                required: false,
            },
            Parameter {
                name: "author_name".to_string(),
                type_hint: "string".to_string(),
                description: "Commit author name (default: 'NetGet')".to_string(),
                required: false,
            },
            Parameter {
                name: "author_email".to_string(),
                type_hint: "string".to_string(),
                description: "Commit author email (default: 'netget@localhost')".to_string(),
                required: false,
            },
            Parameter {
                name: "timestamp".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Commit time as seconds since the Unix epoch. Defaults to a fixed value; \
                     pass one only if you will pass the identical value on every request for \
                     this repository, since it changes the commit hash."
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "git_repository",
            "branch": "main",
            "commit_message": "Initial commit",
            "files": [
                {"path": "README.md", "content": "# Hello World\n"},
                {"path": "src/main.rs", "content": "fn main() { println!(\"hi\"); }\n"}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> git repo {branch} ({files_len} files)")
                .with_debug("Git repository: branch={branch}, files={files_len}"),
        ),
    }
}

fn git_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "git_error".to_string(),
        description: "Refuse the request with an HTTP error (e.g. repository not found)"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message shown to the git client".to_string(),
                required: true,
            },
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (default: 500; use 404 for a missing repository)"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "git_error",
            "message": "Repository not found",
            "code": 404
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> git error {code}: {message}")
                .with_debug("Git error: code={code}, message={message}"),
        ),
    }
}

/// Reference discovery: `GET /<repo>/info/refs?service=git-upload-pack`.
pub static GIT_INFO_REFS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "git_info_refs",
        "Git client asked which branches a repository has (first request of a clone or fetch)",
        json!({
            "type": "git_repository",
            "branch": "main",
            "commit_message": "Initial commit",
            "files": [{"path": "README.md", "content": "# Hello World\n"}]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "repository".to_string(),
            type_hint: "string".to_string(),
            description: "Repository name taken from the URL path".to_string(),
            required: true,
        },
        Parameter {
            name: "user_agent".to_string(),
            type_hint: "string".to_string(),
            description: "User-Agent header of the git client, if it sent one".to_string(),
            required: false,
        },
        Parameter {
            name: "client_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Address of the connecting client".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![git_repository_action(), git_error_action()])
    .with_alternative_example(json!({
        "type": "git_error",
        "message": "Repository not found",
        "code": 404
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} git info/refs {repository}")
            .with_debug("Git info/refs: repository={repository}, agent={user_agent}")
            .with_trace("Git info/refs: {json_pretty(.)}"),
    )
});

/// Object transfer: `POST /<repo>/git-upload-pack`.
pub static GIT_UPLOAD_PACK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "git_upload_pack",
        "Git client asked for the objects of a repository (second request of a clone or fetch)",
        json!({
            "type": "git_repository",
            "branch": "main",
            "commit_message": "Initial commit",
            "files": [{"path": "README.md", "content": "# Hello World\n"}]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "repository".to_string(),
            type_hint: "string".to_string(),
            description: "Repository name taken from the URL path".to_string(),
            required: true,
        },
        Parameter {
            name: "wants".to_string(),
            type_hint: "array".to_string(),
            description: "Object IDs the client asked for, as advertised by git_info_refs"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "haves".to_string(),
            type_hint: "array".to_string(),
            description: "Object IDs the client already has (empty for a fresh clone)".to_string(),
            required: false,
        },
        Parameter {
            name: "capabilities".to_string(),
            type_hint: "array".to_string(),
            description: "Protocol capabilities the client selected".to_string(),
            required: false,
        },
        Parameter {
            name: "client_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Address of the connecting client".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![git_repository_action(), git_error_action()])
    .with_alternative_example(json!({
        "type": "git_error",
        "message": "Repository not found",
        "code": 404
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} git upload-pack {repository}")
            .with_debug("Git upload-pack: repository={repository}, wants={wants}")
            .with_trace("Git upload-pack: {json_pretty(.)}"),
    )
});

pub fn get_git_event_types() -> Vec<EventType> {
    vec![GIT_INFO_REFS_EVENT.clone(), GIT_UPLOAD_PACK_EVENT.clone()]
}

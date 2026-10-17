//! Git client protocol actions implementation

use crate::client::git::sandbox;
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

/// Git client connected event
pub static GIT_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "git_connected",
        "Git client initialized and ready for operations",
        json!({
            "type": "git_status"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "repository_path".to_string(),
        type_hint: "string".to_string(),
        description: "Local path to the Git repository".to_string(),
        required: true,
    }])
});

/// Raised after every Git verb that ran, carrying what it produced.
///
/// This and [`GIT_OPERATION_ERROR_EVENT`] used to be declared inside `get_event_types()` as
/// throwaway `EventType`s with a `{"type": "placeholder"}` example, and **nothing raised
/// either of them**. The model therefore got exactly one turn — the connected event — and
/// then went deaf: it could ask for a log and never see one. `CLAUDE.md` records this shape
/// ("event declared and never emitted") as one of the three ways a client throws the model's
/// answer away.
pub static GIT_OPERATION_COMPLETED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "git_operation_completed",
        "A Git operation finished; `output` carries what it produced",
        json!({ "type": "disconnect" }),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "The action that ran, e.g. 'git_clone' or 'git_log'".to_string(),
            required: true,
        },
        Parameter {
            name: "detail".to_string(),
            type_hint: "string".to_string(),
            description: "One-line summary of what the operation did".to_string(),
            required: true,
        },
        Parameter {
            name: "output".to_string(),
            type_hint: "string".to_string(),
            description:
                "What the operation produced - the commit log, the diff, the branch list, the \
                 status. Truncated if very long. Absent for operations that produce no text."
                    .to_string(),
            required: false,
        },
    ])
});

/// Raised when a Git verb failed, carrying the reason.
pub static GIT_OPERATION_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "git_operation_error",
        "A Git operation failed",
        json!({ "type": "disconnect" }),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "The action that failed, e.g. 'git_clone'".to_string(),
            required: true,
        },
        Parameter {
            name: "error".to_string(),
            type_hint: "string".to_string(),
            description: "Why it failed, as reported by git".to_string(),
            required: true,
        },
    ])
});

/// Git client protocol action handler
pub struct GitClientProtocol;

impl GitClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for GitClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "local_path".to_string(),
                // Read by `GitClient::connect_with_llm_actions`: it seeds the session when it
                // names a repository that already exists, and is the default destination for
                // a `git_clone` that omits `path`. It was declared and read by nothing at all
                // — an advertised knob that did nothing when turned — while all three startup
                // examples told the model to set it.
                description: "Local path for Git operations: opened as the working repository \
                              if it already is one, and used as the clone destination when \
                              git_clone omits 'path'. Must be inside allowed_root; a relative \
                              path is taken relative to it"
                    .to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("./my-repo"),
                default: None,
            },
            ParameterDefinition {
                // Read by `GitClient::connect_with_llm_actions`, which builds a
                // `sandbox::GitSandbox` from it before any path is accepted. Every
                // model-supplied path -- `local_path`, `remote_addr`, `git_clone`'s `path`
                // and a local `git_clone` `url` -- is canonicalised and refused if it lands
                // outside. See `src/client/git/sandbox.rs`.
                name: sandbox::ALLOWED_ROOT_PARAM.to_string(),
                description:
                    "Directory this client may read and write. Every path the model supplies \
                     is resolved and REFUSED (never relocated) if it falls outside, and a \
                     relative path is taken relative to this root. Defaults to a NetGet-owned \
                     workspace under the platform's local-data directory (on macOS \
                     ~/Library/Application Support/netget/git-workspace; on Linux \
                     ~/.local/share/netget/git-workspace). Point it at a wider directory only \
                     if you intend this client to reach there."
                        .to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("/Users/you/netget-git-sandbox"),
                default: None,
            },
            ParameterDefinition {
                // Read by `GitClient::connect_with_llm_actions` and enforced in
                // `run_git_operation` via `GitSandbox::require_remote_writes`.
                name: sandbox::ALLOW_REMOTE_WRITES_PARAM.to_string(),
                description: "Permit operations that write to a REMOTE repository: git_push, and \
                     git_delete_branch when a 'remote' is given. Defaults to false. These are \
                     gated separately from allowed_root because no local directory boundary \
                     can bound where a push goes -- the remote URL comes from the cloned \
                     repository's own config and the push uses this client's credentials, so \
                     it can publish to or delete a branch on a real forge. Local-only \
                     destructive verbs (git_checkout, git_delete_branch with force and no \
                     remote) are NOT gated: their damage is confined to allowed_root."
                    .to_string(),
                type_hint: "boolean".to_string(),
                required: false,
                example: json!(false),
                default: None,
            },
            ParameterDefinition {
                name: "username".to_string(),
                description: "Git username for authentication".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("git-user"),
                default: None,
            },
            ParameterDefinition {
                name: "password".to_string(),
                description: "Git password or personal access token".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("ghp_xxxxxxxxxxxxx"),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
                ActionDefinition {
                    name: "git_clone".to_string(),
                    description: "Clone a Git repository".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "url".to_string(),
                            type_hint: "string".to_string(),
                            description: "Repository URL to clone".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "path".to_string(),
                            type_hint: "string".to_string(),
                            description:
                                "Local path to clone into (default: the client's local_path \
                                 startup parameter, if one was given)"
                                    .to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "git_clone",
                        "url": "https://github.com/user/repo.git",
                        "path": "./repo"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "git_fetch".to_string(),
                    description: "Fetch updates from remote repository".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "remote".to_string(),
                            type_hint: "string".to_string(),
                            description: "Remote name (default: origin)".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "git_fetch",
                        "remote": "origin"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "git_pull".to_string(),
                    description: "Pull and merge updates from remote repository".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "remote".to_string(),
                            type_hint: "string".to_string(),
                            description: "Remote name (default: origin)".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "branch".to_string(),
                            type_hint: "string".to_string(),
                            description: "Branch name (default: current branch)".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "git_pull",
                        "remote": "origin",
                        "branch": "main"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "git_push".to_string(),
                    description: "Push commits to remote repository".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "remote".to_string(),
                            type_hint: "string".to_string(),
                            description: "Remote name (default: origin)".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "branch".to_string(),
                            type_hint: "string".to_string(),
                            description: "Branch name (default: current branch)".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "git_push",
                        "remote": "origin",
                        "branch": "main"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "git_checkout".to_string(),
                    description: "Checkout a branch or commit".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "target".to_string(),
                            type_hint: "string".to_string(),
                            description: "Branch name or commit hash to checkout".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "create".to_string(),
                            type_hint: "boolean".to_string(),
                            description: "Create new branch if it doesn't exist".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "git_checkout",
                        "target": "feature-branch",
                        "create": false
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "git_list_branches".to_string(),
                    description: "List all branches in the repository".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "remote".to_string(),
                            type_hint: "boolean".to_string(),
                            description: "Include remote branches".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "git_list_branches",
                        "remote": true
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "git_log".to_string(),
                    description: "Get commit history".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "max_count".to_string(),
                            type_hint: "number".to_string(),
                            description: "Maximum number of commits to retrieve".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "git_log",
                        "max_count": 10
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "git_status".to_string(),
                    description: "Get current repository status".to_string(),
                    parameters: vec![],
                    example: json!({
                        "type": "git_status"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "git_delete_branch".to_string(),
                    description: "Delete a local or remote branch".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "branch".to_string(),
                            type_hint: "string".to_string(),
                            description: "Branch name to delete".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "force".to_string(),
                            type_hint: "boolean".to_string(),
                            description: "Force delete even if not fully merged".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "remote".to_string(),
                            type_hint: "string".to_string(),
                            description: "Remote name to delete from (e.g., 'origin'). If not specified, deletes local branch only.".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "git_delete_branch",
                        "branch": "feature-branch",
                        "force": false,
                        "remote": "origin"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "git_list_tags".to_string(),
                    description: "List all tags in the repository".to_string(),
                    parameters: vec![],
                    example: json!({
                        "type": "git_list_tags"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "git_create_tag".to_string(),
                    description: "Create a new tag".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "name".to_string(),
                            type_hint: "string".to_string(),
                            description: "Tag name".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "target".to_string(),
                            type_hint: "string".to_string(),
                            description: "Commit hash or branch name to tag (default: HEAD)".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "message".to_string(),
                            type_hint: "string".to_string(),
                            description: "Tag message (for annotated tags)".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "git_create_tag",
                        "name": "v1.0.0",
                        "target": "HEAD",
                        "message": "Release version 1.0.0"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "git_diff".to_string(),
                    description: "View differences in the repository".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "target".to_string(),
                            type_hint: "string".to_string(),
                            description: "Commit, branch, or file to diff against (default: working directory vs index)".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "staged".to_string(),
                            type_hint: "boolean".to_string(),
                            description: "Show staged changes (index vs HEAD)".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "git_diff",
                        "staged": true
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "disconnect".to_string(),
                    description: "Close the Git client".to_string(),
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
            // Git client operations are typically async (user-initiated)
            // Sync actions would be for responding to events, but Git doesn't have
            // server-initiated events like TCP does
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Git"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        // The statics the client actually raises. This used to build three throwaway
        // `EventType`s whose example action was `{"type": "placeholder"}` — a shape
        // `execute_action` rejects, rendered verbatim into the documentation the model
        // reads — and whose `git_connected` was a *different* value from the one
        // `GitClient::connect_with_llm_actions` raises.
        vec![
            GIT_CLIENT_CONNECTED_EVENT.clone(),
            GIT_OPERATION_COMPLETED_EVENT.clone(),
            GIT_OPERATION_ERROR_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "APP>Git"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "git",
            "git client",
            "version control",
            "clone",
            "fetch",
            "pull",
            "push",
            "branch",
            "tag",
            "diff",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("git2 library (libgit2 wrapper)")
            .llm_control("Full control over Git operations")
            .e2e_testing("Local Git repository testing")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Git client for version control operations"
    }
    fn example_prompt(&self) -> &'static str {
        "Clone the repository https://github.com/user/repo.git to ./repo"
    }
    fn group_name(&self) -> &'static str {
        "Version Control"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls Git operations
            json!({
                "type": "open_client",
                "remote_addr": "github.com",
                "base_stack": "git",
                "startup_params": {
                    "local_path": "./my-repo"
                },
                "instruction": "Clone the repository and show the last 5 commits"
            }),
            // Script mode: Code-based Git operations
            json!({
                "type": "open_client",
                "remote_addr": "github.com",
                "base_stack": "git",
                "startup_params": {
                    "local_path": "./my-repo"
                },
                "event_handlers": [{
                    "event_pattern": "git_operation_completed",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<git_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed git status check
            json!({
                "type": "open_client",
                "remote_addr": "github.com",
                "base_stack": "git",
                "startup_params": {
                    "local_path": "./my-repo"
                },
                "event_handlers": [
                    {
                        "event_pattern": "git_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "git_status"
                            }]
                        }
                    },
                    {
                        "event_pattern": "git_operation_completed",
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
impl Client for GitClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::git::GitClient;
            GitClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                // The declared startup parameters have to be handed over explicitly.
                // `ClientInstance::protocol_data` — which `read_field` consults — is left
                // `Value::Null` by `client_startup.rs` and is only ever populated by a
                // client that writes to it itself, so a parameter read *only* from there
                // is never actually delivered. `ctx.startup_params` is the channel that
                // carries what the caller passed.
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
            "git_clone" => {
                let url = action
                    .get("url")
                    .and_then(|v| v.as_str())
                    .context("Missing 'url' field")?
                    .to_string();
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "git_clone".to_string(),
                    data: json!({
                        "url": url,
                        "path": path,
                    }),
                })
            }
            "git_fetch" => {
                let remote = action
                    .get("remote")
                    .and_then(|v| v.as_str())
                    .unwrap_or("origin")
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "git_fetch".to_string(),
                    data: json!({
                        "remote": remote,
                    }),
                })
            }
            "git_pull" => {
                let remote = action
                    .get("remote")
                    .and_then(|v| v.as_str())
                    .unwrap_or("origin")
                    .to_string();
                let branch = action
                    .get("branch")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "git_pull".to_string(),
                    data: json!({
                        "remote": remote,
                        "branch": branch,
                    }),
                })
            }
            "git_push" => {
                let remote = action
                    .get("remote")
                    .and_then(|v| v.as_str())
                    .unwrap_or("origin")
                    .to_string();
                let branch = action
                    .get("branch")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "git_push".to_string(),
                    data: json!({
                        "remote": remote,
                        "branch": branch,
                    }),
                })
            }
            "git_checkout" => {
                let target = action
                    .get("target")
                    .and_then(|v| v.as_str())
                    .context("Missing 'target' field")?
                    .to_string();
                let create = action
                    .get("create")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                Ok(ClientActionResult::Custom {
                    name: "git_checkout".to_string(),
                    data: json!({
                        "target": target,
                        "create": create,
                    }),
                })
            }
            "git_list_branches" => {
                let remote = action
                    .get("remote")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                Ok(ClientActionResult::Custom {
                    name: "git_list_branches".to_string(),
                    data: json!({
                        "remote": remote,
                    }),
                })
            }
            "git_log" => {
                let max_count = action
                    .get("max_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(10) as usize;

                Ok(ClientActionResult::Custom {
                    name: "git_log".to_string(),
                    data: json!({
                        "max_count": max_count,
                    }),
                })
            }
            "git_status" => Ok(ClientActionResult::Custom {
                name: "git_status".to_string(),
                data: json!({}),
            }),
            "git_delete_branch" => {
                let branch = action
                    .get("branch")
                    .and_then(|v| v.as_str())
                    .context("Missing 'branch' field")?
                    .to_string();
                let force = action
                    .get("force")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let remote = action
                    .get("remote")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "git_delete_branch".to_string(),
                    data: json!({
                        "branch": branch,
                        "force": force,
                        "remote": remote,
                    }),
                })
            }
            "git_list_tags" => Ok(ClientActionResult::Custom {
                name: "git_list_tags".to_string(),
                data: json!({}),
            }),
            "git_create_tag" => {
                let name = action
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'name' field")?
                    .to_string();
                let target = action
                    .get("target")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "git_create_tag".to_string(),
                    data: json!({
                        "name": name,
                        "target": target,
                        "message": message,
                    }),
                })
            }
            "git_diff" => {
                let target = action
                    .get("target")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let staged = action
                    .get("staged")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                Ok(ClientActionResult::Custom {
                    name: "git_diff".to_string(),
                    data: json!({
                        "target": target,
                        "staged": staged,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown Git client action: {}",
                action_type
            )),
        }
    }
}

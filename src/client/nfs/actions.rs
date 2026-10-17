//! NFS client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// NFS client connected event
pub static NFS_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nfs_connected",
        "NFS client successfully mounted an NFS export. This is your one turn before the \
         client goes idle: issue an operation, or wait_for_more to do nothing.",
        json!({"type": "nfs_list_dir", "path": "/"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "export_path".to_string(),
            type_hint: "string".to_string(),
            description: "NFS export path that was mounted".to_string(),
            required: true,
        },
        Parameter {
            name: "root_fh".to_string(),
            type_hint: "string".to_string(),
            description: "Root file handle (hex-encoded)".to_string(),
            required: true,
        },
    ])
});

/// NFS client file operation result event
pub static NFS_CLIENT_OPERATION_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nfs_operation_result",
        "Result of an NFS file operation. `success` is false when the server refused or the \
         path does not exist; `error` then carries the NFS status. Follow up with another \
         operation, or wait_for_more if there is nothing more to do.",
        // `EventType::response_example` is rendered into the model's prompt and is
        // documented as having to be a real protocol action. This used to be
        // `{"type": "placeholder", ...}`, which `execute_action` rejects as an unknown
        // action — so after every completed operation the model was handed an example that
        // could not be executed.
        json!({"type": "nfs_list_dir", "path": "/"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "The operation performed (lookup, read, write, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "result".to_string(),
            type_hint: "object".to_string(),
            description: "Operation result data".to_string(),
            required: true,
        },
    ])
});

/// NFS client protocol action handler
pub struct NfsClientProtocol;

impl NfsClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for NfsClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "nfs_lookup".to_string(),
                description: "Look up a file or directory by path".to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "Path to file or directory (relative to root)".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "nfs_lookup",
                    "path": "/documents/readme.txt"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nfs_read_file".to_string(),
                description: "Read contents of a file".to_string(),
                parameters: vec![
                    Parameter {
                        name: "path".to_string(),
                        type_hint: "string".to_string(),
                        description: "Path to file to read".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "offset".to_string(),
                        type_hint: "number".to_string(),
                        description: "Byte offset to start reading from (default: 0)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "count".to_string(),
                        type_hint: "number".to_string(),
                        description: "Number of bytes to read (default: 4096)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "nfs_read_file",
                    "path": "/readme.txt",
                    "offset": 0,
                    "count": 4096
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nfs_write_file".to_string(),
                description: "Write data to a file".to_string(),
                parameters: vec![
                    Parameter {
                        name: "path".to_string(),
                        type_hint: "string".to_string(),
                        description: "Path to file to write".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "data".to_string(),
                        type_hint: "string".to_string(),
                        description: "Data to write".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "offset".to_string(),
                        type_hint: "number".to_string(),
                        description: "Byte offset to start writing at (default: 0)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "nfs_write_file",
                    "path": "/data.txt",
                    "data": "Hello, World!",
                    "offset": 0
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nfs_list_dir".to_string(),
                description: "List contents of a directory".to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "Path to directory to list (default: /)".to_string(),
                    required: false,
                }],
                example: json!({
                    "type": "nfs_list_dir",
                    "path": "/documents"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nfs_get_attr".to_string(),
                description: "Get file or directory attributes".to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "Path to file or directory".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "nfs_get_attr",
                    "path": "/readme.txt"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nfs_create_file".to_string(),
                description: "Create a new file".to_string(),
                parameters: vec![
                    Parameter {
                        name: "path".to_string(),
                        type_hint: "string".to_string(),
                        description: "Path to new file".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "mode".to_string(),
                        type_hint: "number".to_string(),
                        description: "File permissions in octal (default: 0644)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "nfs_create_file",
                    "path": "/newfile.txt",
                    "mode": 0o644
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nfs_mkdir".to_string(),
                description: "Create a new directory".to_string(),
                parameters: vec![
                    Parameter {
                        name: "path".to_string(),
                        type_hint: "string".to_string(),
                        description: "Path to new directory".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "mode".to_string(),
                        type_hint: "number".to_string(),
                        description: "Directory permissions in octal (default: 0755)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "nfs_mkdir",
                    "path": "/newdir",
                    "mode": 0o755
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nfs_remove".to_string(),
                description: "Remove a file from the mounted export by path. Unlinks a regular \
                              file only — a directory needs the server's own rmdir and is \
                              refused here — and the removal is immediate and not reversible."
                    .to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "Path to file to remove".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "nfs_remove",
                    "path": "/oldfile.txt"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nfs_rmdir".to_string(),
                description: "Remove a directory".to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "Path to directory to remove".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "nfs_rmdir",
                    "path": "/olddir"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the NFS server".to_string(),
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
            name: "wait_for_more".to_string(),
            description: "Wait for more operations before responding".to_string(),
            parameters: vec![],
            example: json!({
                "type": "wait_for_more"
            }),
            log_template: None,
        }]
    }

    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "portmapper_port".to_string(),
                description: "Port to ask for the MOUNT and NFS ports on (default 111). \
                              Override it when the server multiplexes all three RPC programs \
                              on one port, as NetGet's own NFS server does"
                    .to_string(),
                type_hint: "number".to_string(),
                required: false,
                example: json!(111),
                default: None,
            },
            ParameterDefinition {
                name: "mount_port".to_string(),
                description: "MOUNT program port. Skips the portmapper lookup for MOUNT"
                    .to_string(),
                type_hint: "number".to_string(),
                required: false,
                example: json!(2049),
                default: None,
            },
            ParameterDefinition {
                name: "nfs_port".to_string(),
                description: "NFS program port (normally 2049). Skips the portmapper lookup \
                              for NFS"
                    .to_string(),
                type_hint: "number".to_string(),
                required: false,
                example: json!(2049),
                default: None,
            },
            ParameterDefinition {
                name: "privileged_source_port".to_string(),
                description: "Bind the local end to a port below 1024, which many real NFS \
                              servers demand and which requires root. Default true"
                    .to_string(),
                type_hint: "boolean".to_string(),
                required: false,
                example: json!(false),
                default: None,
            },
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "NFS"
    }

    /// The two events this client actually raises.
    ///
    /// These used to be freshly-built `EventType`s declaring the same two ids with **no
    /// parameters** and a `{"type": "placeholder"}` example, while `mod.rs` emitted the
    /// `LazyLock` statics above. So the registry, the TUI and handler validation saw a
    /// different shape from the one that fires, and both advertised an example the executor
    /// rejects. Clone the statics instead, so there is exactly one declaration of each.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            NFS_CLIENT_CONNECTED_EVENT.clone(),
            NFS_CLIENT_OPERATION_RESULT_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>RPC>NFS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["nfs", "nfs client", "connect to nfs"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("nfs3_client crate for NFSv3 protocol")
            .llm_control("Full control over file operations (read, write, create, delete)")
            .e2e_testing("NetGet NFS server as test target")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "NFS client for mounting and accessing network file systems"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to NFS server at 192.168.1.100:/export/data and read /readme.txt"
    }

    fn group_name(&self) -> &'static str {
        "File Sharing"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls NFS operations
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.100:/export/data",
                "base_stack": "nfs",
                "instruction": "Read /readme.txt and list the root directory"
            }),
            // Script mode: Code-based file operations
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.100:/export/data",
                "base_stack": "nfs",
                "event_handlers": [{
                    "event_pattern": "nfs_operation_result",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<nfs_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed file read
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.100:/export/data",
                "base_stack": "nfs",
                "event_handlers": [
                    {
                        "event_pattern": "nfs_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "nfs_list_dir",
                                "path": "/"
                            }]
                        }
                    },
                    {
                        "event_pattern": "nfs_operation_result",
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

impl Client for NfsClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::nfs::NfsClient;
            NfsClient::connect_with_llm_actions(
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
            "nfs_lookup" | "nfs_read_file" | "nfs_write_file" | "nfs_list_dir" | "nfs_get_attr"
            | "nfs_create_file" | "nfs_mkdir" | "nfs_remove" | "nfs_rmdir" => {
                // These operations are handled asynchronously in the main loop
                Ok(ClientActionResult::Custom {
                    name: action_type.to_string(),
                    data: action,
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown NFS client action: {}",
                action_type
            )),
        }
    }
}

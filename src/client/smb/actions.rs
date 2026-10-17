//! SMB client protocol actions implementation

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

/// SMB client connected event
pub static SMB_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smb_connected",
        "SMB client successfully connected to server",
        json!({
            "type": "list_directory",
            "path": "smb://server/share"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "share_url".to_string(),
        type_hint: "string".to_string(),
        description: "SMB share URL (smb://server/share)".to_string(),
        required: true,
    }])
});

/// SMB client directory listed event
pub static SMB_CLIENT_DIR_LISTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smb_dir_listed",
        "SMB directory listing received",
        json!({"type": "placeholder", "event_id": "smb_dir_listed"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Directory path".to_string(),
            required: true,
        },
        Parameter {
            name: "entries".to_string(),
            type_hint: "array".to_string(),
            description: "Array of directory entries".to_string(),
            required: true,
        },
    ])
});

/// SMB client file read event
pub static SMB_CLIENT_FILE_READ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smb_file_read",
        "SMB file content read from server",
        json!({"type": "placeholder", "event_id": "smb_file_read"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "File path".to_string(),
            required: true,
        },
        Parameter {
            name: "content".to_string(),
            type_hint: "string".to_string(),
            description: "File content (text or base64 for binary)".to_string(),
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

/// SMB client file written event
pub static SMB_CLIENT_FILE_WRITTEN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smb_file_written",
        "SMB file successfully written to server",
        json!({
            "type": "read_file",
            "path": "smb://server/share/file.txt"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "File path".to_string(),
            required: true,
        },
        Parameter {
            name: "bytes_written".to_string(),
            type_hint: "number".to_string(),
            description: "Number of bytes written".to_string(),
            required: true,
        },
    ])
});

/// SMB client error event
pub static SMB_CLIENT_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smb_error",
        "SMB operation error",
        json!({"type": "placeholder", "event_id": "smb_error"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "error".to_string(),
            type_hint: "string".to_string(),
            description: "Error message".to_string(),
            required: true,
        },
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "Operation that failed".to_string(),
            required: true,
        },
    ])
});

/// SMB client protocol action handler
pub struct SmbClientProtocol;

impl SmbClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SmbClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "username".to_string(),
                description: "SMB username for authentication".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("guest"),
                default: None,
            },
            ParameterDefinition {
                name: "password".to_string(),
                description: "SMB password for authentication".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!(""),
                default: None,
            },
            ParameterDefinition {
                name: "domain".to_string(),
                description: "SMB domain (optional)".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("WORKGROUP"),
                default: None,
            },
            ParameterDefinition {
                name: "workgroup".to_string(),
                description: "SMB workgroup (optional)".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("WORKGROUP"),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "list_directory".to_string(),
                description: "List contents of an SMB directory".to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "Directory path (e.g., smb://server/share/dir)".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "list_directory",
                    "path": "smb://server/share/mydir"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "read_file".to_string(),
                description: "Read a file from SMB share".to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "File path (e.g., smb://server/share/file.txt)".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "read_file",
                    "path": "smb://server/share/readme.txt"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "write_file".to_string(),
                description: "Write a file to SMB share".to_string(),
                parameters: vec![
                    Parameter {
                        name: "path".to_string(),
                        type_hint: "string".to_string(),
                        description: "File path (e.g., smb://server/share/file.txt)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "content".to_string(),
                        type_hint: "string".to_string(),
                        description: "File content to write. Plain text is written as-is; to \
                            write binary, prefix base64 with \"base64:\" - the same form \
                            smb_file_read reports it in, so content read from one file can be \
                            written straight to another."
                            .to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "write_file",
                    "path": "smb://server/share/output.txt",
                    "content": "Hello from NetGet"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "create_directory".to_string(),
                description: "Create a directory on SMB share".to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "Directory path (e.g., smb://server/share/newdir)".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "create_directory",
                    "path": "smb://server/share/newdir"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "delete_file".to_string(),
                description: "Delete a file from SMB share".to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "File path (e.g., smb://server/share/file.txt)".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "delete_file",
                    "path": "smb://server/share/oldfile.txt"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "delete_directory".to_string(),
                description: "Delete a directory from SMB share".to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "Directory path (e.g., smb://server/share/dir)".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "delete_directory",
                    "path": "smb://server/share/olddir"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the SMB server".to_string(),
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
                name: "list_directory".to_string(),
                description: "List directory in response to previous operation".to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "Directory path".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "list_directory",
                    "path": "smb://server/share"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "read_file".to_string(),
                description: "Read file in response to previous operation".to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "File path".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "read_file",
                    "path": "smb://server/share/file.txt"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more data before responding".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "SMB"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "smb_connected",
                "Triggered when SMB client connects to server",
                json!({"type": "placeholder", "event_id": "smb_connected"}),
            ),
            EventType::new(
                "smb_dir_listed",
                "Triggered when directory listing is received",
                json!({"type": "placeholder", "event_id": "smb_dir_listed"}),
            ),
            EventType::new(
                "smb_file_read",
                "Triggered when file content is read",
                json!({"type": "placeholder", "event_id": "smb_file_read"}),
            ),
            EventType::new(
                "smb_file_written",
                "Triggered when file is written",
                json!({"type": "placeholder", "event_id": "smb_file_written"}),
            ),
            EventType::new(
                "smb_error",
                "Triggered when an SMB operation fails",
                json!({"type": "placeholder", "event_id": "smb_error"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>SMB"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "smb",
            "smb client",
            "connect to smb",
            "cifs",
            "windows share",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("pavao library (libsmbclient wrapper)")
            .llm_control("Full control over file operations (list, read, write, delete)")
            .e2e_testing("Samba server container")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "SMB/CIFS client for accessing Windows file shares"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to SMB at //server/share and list the contents"
    }
    fn group_name(&self) -> &'static str {
        "File & Print"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls SMB file operations
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.100:445",
                "base_stack": "smb",
                "startup_params": {
                    "username": "guest",
                    "password": ""
                },
                "instruction": "List the root directory and read any readme files"
            }),
            // Script mode: Code-based SMB file handling
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.100:445",
                "base_stack": "smb",
                "startup_params": {
                    "username": "guest",
                    "password": ""
                },
                "event_handlers": [{
                    "event_pattern": "smb_dir_listed",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<smb_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed directory listing
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.100:445",
                "base_stack": "smb",
                "startup_params": {
                    "username": "guest",
                    "password": ""
                },
                "event_handlers": [
                    {
                        "event_pattern": "smb_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "list_directory",
                                "path": "smb://192.168.1.100/share"
                            }]
                        }
                    },
                    {
                        "event_pattern": "smb_dir_listed",
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
impl Client for SmbClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::smb::SmbClient;
            SmbClient::connect_with_llm_actions(
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
            "list_directory" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "smb_list_dir".to_string(),
                    data: json!({
                        "path": path,
                    }),
                })
            }
            "read_file" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "smb_read_file".to_string(),
                    data: json!({
                        "path": path,
                    }),
                })
            }
            "write_file" => {
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

                Ok(ClientActionResult::Custom {
                    name: "smb_write_file".to_string(),
                    data: json!({
                        "path": path,
                        "content": content,
                    }),
                })
            }
            "create_directory" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "smb_create_dir".to_string(),
                    data: json!({
                        "path": path,
                    }),
                })
            }
            "delete_file" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "smb_delete_file".to_string(),
                    data: json!({
                        "path": path,
                    }),
                })
            }
            "delete_directory" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "smb_delete_dir".to_string(),
                    data: json!({
                        "path": path,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown SMB client action: {}",
                action_type
            )),
        }
    }
}

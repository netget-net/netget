//! DC (Direct Connect) client protocol actions implementation

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

/// DC client connected event - received Lock challenge
pub static DC_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dc_client_connected",
        "DC client connected to hub and received Lock challenge",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "lock".to_string(),
            type_hint: "string".to_string(),
            description: "Lock challenge from hub".to_string(),
            required: true,
        },
        Parameter {
            name: "pk".to_string(),
            type_hint: "string".to_string(),
            description: "Hub PK name from Lock".to_string(),
            required: false,
        },
    ])
});

/// DC client authenticated event
pub static DC_CLIENT_AUTHENTICATED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dc_client_authenticated",
        "DC client successfully authenticated with hub",
        json!({"type": "send_dc_chat", "message": "Hello everyone!"}),
    )
    .with_parameters(vec![Parameter {
        name: "nickname".to_string(),
        type_hint: "string".to_string(),
        description: "Accepted nickname".to_string(),
        required: true,
    }])
});

/// DC client message received event
pub static DC_CLIENT_MESSAGE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dc_client_message_received",
        "Received chat message from hub or user",
        json!({"type": "send_dc_chat", "message": "Hello everyone!"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "source".to_string(),
            type_hint: "string".to_string(),
            description: "Message source (nickname or hub)".to_string(),
            required: true,
        },
        Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Message text".to_string(),
            required: true,
        },
        Parameter {
            name: "is_private".to_string(),
            type_hint: "boolean".to_string(),
            description: "True if private message".to_string(),
            required: true,
        },
        Parameter {
            name: "target".to_string(),
            type_hint: "string".to_string(),
            description: "Target nickname (for private messages)".to_string(),
            required: false,
        },
    ])
});

/// DC client search result received event
pub static DC_CLIENT_SEARCH_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dc_client_search_result",
        "Received search result from hub",
        json!({"type": "placeholder", "event_id": "dc_client_search_result"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "source".to_string(),
            type_hint: "string".to_string(),
            description: "User who has the file".to_string(),
            required: true,
        },
        Parameter {
            name: "filename".to_string(),
            type_hint: "string".to_string(),
            description: "File name".to_string(),
            required: true,
        },
        Parameter {
            name: "size".to_string(),
            type_hint: "number".to_string(),
            description: "File size in bytes".to_string(),
            required: true,
        },
        Parameter {
            name: "free_slots".to_string(),
            type_hint: "number".to_string(),
            description: "Available download slots".to_string(),
            required: true,
        },
        Parameter {
            name: "total_slots".to_string(),
            type_hint: "number".to_string(),
            description: "Total download slots".to_string(),
            required: true,
        },
        Parameter {
            name: "hub_name".to_string(),
            type_hint: "string".to_string(),
            description: "Hub name where file is located".to_string(),
            required: false,
        },
    ])
});

/// DC client user list received event
pub static DC_CLIENT_USERLIST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dc_client_userlist_received",
        "Received list of connected users",
        json!({"type": "send_dc_chat", "message": "Hello everyone!"}),
    )
    .with_parameters(vec![Parameter {
        name: "users".to_string(),
        type_hint: "array".to_string(),
        description: "Array of nicknames".to_string(),
        required: true,
    }])
});

/// DC client hub info received event
pub static DC_CLIENT_HUBINFO_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dc_client_hubinfo_received",
        "Received hub information",
        json!({"type": "placeholder", "event_id": "dc_client_hubinfo_received"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "hub_name".to_string(),
            type_hint: "string".to_string(),
            description: "Hub name".to_string(),
            required: false,
        },
        Parameter {
            name: "hub_topic".to_string(),
            type_hint: "string".to_string(),
            description: "Hub topic/description".to_string(),
            required: false,
        },
    ])
});

/// DC client kicked event
pub static DC_CLIENT_KICKED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dc_client_kicked",
        "Client was kicked from hub",
        json!({"type": "placeholder", "event_id": "dc_client_kicked"}),
    )
    .with_parameters(vec![Parameter {
        name: "nickname".to_string(),
        type_hint: "string".to_string(),
        description: "Nickname that was kicked".to_string(),
        required: true,
    }])
});

/// DC client redirect event
pub static DC_CLIENT_REDIRECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dc_client_redirect",
        "Client redirected to another hub",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![Parameter {
        name: "address".to_string(),
        type_hint: "string".to_string(),
        description: "New hub address to connect to".to_string(),
        required: true,
    }])
});

/// DC client disconnected event
pub static DC_CLIENT_DISCONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dc_client_disconnected",
        "DC client disconnected from hub",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Disconnection reason".to_string(),
            required: true,
        },
        Parameter {
            name: "will_reconnect".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether auto-reconnect will attempt to reconnect".to_string(),
            required: true,
        },
        Parameter {
            name: "reconnect_attempt".to_string(),
            type_hint: "number".to_string(),
            description: "Current reconnection attempt number (0 if first disconnect)".to_string(),
            required: false,
        },
    ])
});

/// DC client protocol action handler
pub struct DcClientProtocol;

impl DcClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DcClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for DcClientProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "nickname".to_string(),
                type_hint: "string".to_string(),
                description: "Nickname to use on the hub".to_string(),
                required: true,
                example: json!("alice"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "description".to_string(),
                type_hint: "string".to_string(),
                description: "Client description".to_string(),
                required: false,
                example: json!("NetGet DC Client"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "email".to_string(),
                type_hint: "string".to_string(),
                description: "Email address advertised in the client's MyINFO line, which every \
                              other user on the hub can read. Optional; hubs rarely \
                              require it and many users leave it empty."
                    .to_string(),
                required: false,
                example: json!("user@example.com"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "share_size".to_string(),
                type_hint: "number".to_string(),
                description: "Total bytes shared (fake for testing)".to_string(),
                required: false,
                example: json!(1073741824u64),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "use_tls".to_string(),
                type_hint: "boolean".to_string(),
                description: "Use TLS encryption (DCCS protocol, port 412)".to_string(),
                required: false,
                example: json!(false),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "auto_reconnect".to_string(),
                type_hint: "boolean".to_string(),
                description: "Automatically reconnect if disconnected".to_string(),
                required: false,
                example: json!(false),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "max_reconnect_attempts".to_string(),
                type_hint: "number".to_string(),
                description: "Maximum reconnection attempts (0 = unlimited)".to_string(),
                required: false,
                example: json!(5),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "initial_reconnect_delay_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Initial delay before reconnecting (exponential backoff)".to_string(),
                required: false,
                example: json!(2),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            send_dc_chat_action(),
            send_dc_private_message_action(),
            send_dc_search_action(),
            send_dc_myinfo_action(),
            send_dc_get_nicklist_action(),
            send_dc_filelist_action(),
            send_dc_raw_command_action(),
            disconnect_action(),
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_dc_chat_action(),
            send_dc_private_message_action(),
            send_dc_filelist_action(),
            send_dc_raw_command_action(),
            wait_for_more_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "DC"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            DC_CLIENT_CONNECTED_EVENT.clone(),
            DC_CLIENT_AUTHENTICATED_EVENT.clone(),
            DC_CLIENT_MESSAGE_RECEIVED_EVENT.clone(),
            DC_CLIENT_SEARCH_RESULT_EVENT.clone(),
            DC_CLIENT_USERLIST_EVENT.clone(),
            DC_CLIENT_HUBINFO_EVENT.clone(),
            DC_CLIENT_KICKED_EVENT.clone(),
            DC_CLIENT_REDIRECT_EVENT.clone(),
            DC_CLIENT_DISCONNECTED_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>DC"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["dc", "direct connect", "dc++", "nmdc", "dc client"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Manual NMDC protocol implementation with Lock/Key authentication")
            .llm_control("Connect, authenticate, chat, search, user list management")
            .e2e_testing("Uses local DC server from src/server/dc/")
            .notes("NMDC protocol only (no ADC). No P2P file transfers. Hub interaction only. 64 KiB inbound pipe-delimited frames; 600 s whole-frame deadline; truncated frames are refused. Binary Lock/Key escaping follows NMDC.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "DC (Direct Connect) client - peer-to-peer file sharing protocol client"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to DC hub at localhost:411 as 'alice' and say hello in chat"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls DC hub interaction
            json!({
                "type": "open_client",
                "remote_addr": "localhost:411",
                "base_stack": "dc",
                "instruction": "Connect as alice and say hello in chat",
                "startup_params": {
                    "nickname": "alice",
                    "description": "NetGet DC Client"
                }
            }),
            // Script mode: Code-based DC message handling
            json!({
                "type": "open_client",
                "remote_addr": "localhost:411",
                "base_stack": "dc",
                "startup_params": {
                    "nickname": "alice"
                },
                "event_handlers": [{
                    "event_pattern": "dc_client_message_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<dc_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed DC chat message
            json!({
                "type": "open_client",
                "remote_addr": "localhost:411",
                "base_stack": "dc",
                "startup_params": {
                    "nickname": "alice"
                },
                "event_handlers": [
                    {
                        "event_pattern": "dc_client_authenticated",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_dc_chat",
                                "message": "Hello everyone!"
                            }]
                        }
                    },
                    {
                        "event_pattern": "dc_client_message_received",
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
impl Client for DcClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::dc::DcClient;
            DcClient::connect_with_llm_actions(
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
            "send_dc_chat" => {
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .context("Missing 'message' field")?;

                Ok(ClientActionResult::Custom {
                    name: "dc_chat".to_string(),
                    data: json!({
                        "message": message,
                    }),
                })
            }
            "send_dc_private_message" => {
                let target = action
                    .get("target")
                    .and_then(|v| v.as_str())
                    .context("Missing 'target' field")?;
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .context("Missing 'message' field")?;

                Ok(ClientActionResult::Custom {
                    name: "dc_private_message".to_string(),
                    data: json!({
                        "target": target,
                        "message": message,
                    }),
                })
            }
            "send_dc_search" => {
                let query = action
                    .get("query")
                    .and_then(|v| v.as_str())
                    .context("Missing 'query' field")?;
                let size_restricted = action
                    .get("size_restricted")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let min_size = action.get("min_size").and_then(|v| v.as_u64()).unwrap_or(0);

                Ok(ClientActionResult::Custom {
                    name: "dc_search".to_string(),
                    data: json!({
                        "query": query,
                        "size_restricted": size_restricted,
                        "min_size": min_size,
                    }),
                })
            }
            "send_dc_myinfo" => {
                let description = action
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("NetGet DC Client");
                let email = action.get("email").and_then(|v| v.as_str()).unwrap_or("");
                let share_size = action
                    .get("share_size")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                Ok(ClientActionResult::Custom {
                    name: "dc_myinfo".to_string(),
                    data: json!({
                        "description": description,
                        "email": email,
                        "share_size": share_size,
                    }),
                })
            }
            "send_dc_get_nicklist" => Ok(ClientActionResult::Custom {
                name: "dc_get_nicklist".to_string(),
                data: json!({}),
            }),
            "send_dc_filelist" => {
                let files = action
                    .get("files")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                Ok(ClientActionResult::Custom {
                    name: "dc_filelist".to_string(),
                    data: json!({
                        "files": files,
                    }),
                })
            }
            "send_dc_raw_command" => {
                let command = action
                    .get("command")
                    .and_then(|v| v.as_str())
                    .context("Missing 'command' field")?;

                Ok(ClientActionResult::Custom {
                    name: "dc_raw_command".to_string(),
                    data: json!({
                        "command": command,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!("Unknown DC client action: {}", action_type)),
        }
    }
}

// Action definitions

fn send_dc_chat_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_chat".to_string(),
        description: "Send public chat message to hub".to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Message text".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_dc_chat",
            "message": "Hello everyone!"
        }),
        log_template: None,
    }
}

fn send_dc_private_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_private_message".to_string(),
        description: "Send private message to specific user".to_string(),
        parameters: vec![
            Parameter {
                name: "target".to_string(),
                type_hint: "string".to_string(),
                description: "Target nickname".to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Message text".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_dc_private_message",
            "target": "bob",
            "message": "Hey Bob!"
        }),
        log_template: None,
    }
}

fn send_dc_search_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_search".to_string(),
        description: "Search for files in the hub".to_string(),
        parameters: vec![
            Parameter {
                name: "query".to_string(),
                type_hint: "string".to_string(),
                description: "Search query".to_string(),
                required: true,
            },
            Parameter {
                name: "size_restricted".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether to restrict by size".to_string(),
                required: false,
            },
            Parameter {
                name: "min_size".to_string(),
                type_hint: "number".to_string(),
                description: "Minimum file size (if size_restricted)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dc_search",
            "query": "ubuntu iso"
        }),
        log_template: None,
    }
}

fn send_dc_myinfo_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_myinfo".to_string(),
        description: "Send client information to hub".to_string(),
        parameters: vec![
            Parameter {
                name: "description".to_string(),
                type_hint: "string".to_string(),
                description: "Client description".to_string(),
                required: false,
            },
            Parameter {
                name: "email".to_string(),
                type_hint: "string".to_string(),
                description: "Email address advertised in the client's MyINFO line, which every \
                              other user on the hub can read. Optional; hubs rarely \
                              require it and many users leave it empty."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "share_size".to_string(),
                type_hint: "number".to_string(),
                description: "Total bytes shared".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dc_myinfo",
            "description": "NetGet DC Client",
            "email": "user@example.com",
            "share_size": 10737418240u64
        }),
        log_template: None,
    }
}

fn send_dc_get_nicklist_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_get_nicklist".to_string(),
        description: "Request list of connected users from hub".to_string(),
        parameters: vec![],
        example: json!({
            "type": "send_dc_get_nicklist"
        }),
        log_template: None,
    }
}

fn send_dc_filelist_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_filelist".to_string(),
        description: "Configure and send file list in response to hub request. File list is XML format with fake/empty entries.".to_string(),
        parameters: vec![
            Parameter {
                name: "files".to_string(),
                type_hint: "array".to_string(),
                description: "Array of file objects with name, size, and optional TTH hash".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_dc_filelist",
            "files": [
                {
                    "name": "example.txt",
                    "size": 1024,
                    "tth": "ABCD1234567890"
                }
            ]
        }),
        log_template: None,
    }
}

fn send_dc_raw_command_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dc_raw_command".to_string(),
        description: "Send raw NMDC command to hub (for advanced use)".to_string(),
        parameters: vec![Parameter {
            name: "command".to_string(),
            type_hint: "string".to_string(),
            description: "Raw NMDC command (will auto-add | if missing)".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_dc_raw_command",
            "command": "$Version 1,0091"
        }),
        log_template: None,
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description: "Disconnect from the DC hub".to_string(),
        parameters: vec![],
        example: json!({
            "type": "disconnect"
        }),
        log_template: None,
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Wait for more messages before responding".to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: None,
    }
}

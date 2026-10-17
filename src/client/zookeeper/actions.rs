//! ZooKeeper client protocol actions

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::sync::LazyLock;

// Event type constants
pub static ZOOKEEPER_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zookeeper_connected",
        "ZooKeeper client connected to server",
        json!({
            "type": "wait_for_more"
        }),
    )
});

pub static ZOOKEEPER_CLIENT_DATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zookeeper_data_received",
        "ZooKeeper client received data from server",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "ZNode path".to_string(),
            required: true,
        },
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "ZNode data".to_string(),
            required: true,
        },
        Parameter {
            name: "version".to_string(),
            type_hint: "integer".to_string(),
            description: "Data version".to_string(),
            required: true,
        },
    ])
});

/// Raised after a write verb (`create_znode`, `set_data`, `delete_znode`) completes.
///
/// The read verbs have their own events - `zookeeper_data_received` for `get_data`,
/// `zookeeper_children_received` for `get_children` - and neither fits a write: there is no
/// data and no child list to report, only the fact that ZooKeeper accepted the change and
/// the version it now holds. Without this the three write verbs completed silently and the
/// model was never told whether its own write landed.
pub static ZOOKEEPER_CLIENT_OPERATION_COMPLETE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zookeeper_operation_complete",
        "A ZooKeeper write (create/set_data/delete) completed",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "The verb that completed: create, set_data or delete".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "ZNode path the operation was requested for".to_string(),
            required: true,
        },
        Parameter {
            name: "created_path".to_string(),
            type_hint: "string".to_string(),
            description: "Path ZooKeeper actually created (create only; a sequential node                           gets a suffix)"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "version".to_string(),
            type_hint: "integer".to_string(),
            description: "Data version after the write (set_data only)".to_string(),
            required: false,
        },
    ])
});

pub static ZOOKEEPER_CLIENT_CHILDREN_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zookeeper_children_received",
        "ZooKeeper client received children list",
        json!({
            "type": "disconnect"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "ZNode path".to_string(),
            required: true,
        },
        Parameter {
            name: "children".to_string(),
            type_hint: "array".to_string(),
            description: "Array of child node names".to_string(),
            required: true,
        },
    ])
});

/// ZooKeeper client protocol implementation
pub struct ZookeeperClientProtocol;

impl ZookeeperClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for ZookeeperClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "create_znode".to_string(),
                description: "Create a ZNode at the specified path".to_string(),
                parameters: vec![
                    Parameter {
                        name: "path".to_string(),
                        type_hint: "string".to_string(),
                        description: "ZNode path".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "data".to_string(),
                        type_hint: "string".to_string(),
                        description: "ZNode data".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "create_znode",
                    "path": "/myapp/config",
                    "data": "configuration_data"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_data".to_string(),
                description: "Get data from a ZNode".to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "ZNode path".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "get_data",
                    "path": "/myapp/config"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "set_data".to_string(),
                description: "Set data for a ZNode".to_string(),
                parameters: vec![
                    Parameter {
                        name: "path".to_string(),
                        type_hint: "string".to_string(),
                        description: "ZNode path".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "data".to_string(),
                        type_hint: "string".to_string(),
                        description: "New ZNode data".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "set_data",
                    "path": "/myapp/config",
                    "data": "new_configuration_data"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "delete_znode".to_string(),
                description: "Delete a ZNode at the given path. ZooKeeper refuses to delete a \
                              node that still has children, so remove those first; watches \
                              registered on the node fire as a result."
                    .to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "ZNode path".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "delete_znode",
                    "path": "/myapp/config"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_children".to_string(),
                description: "Get children of a ZNode".to_string(),
                parameters: vec![Parameter {
                    name: "path".to_string(),
                    type_hint: "string".to_string(),
                    description: "ZNode path".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "get_children",
                    "path": "/myapp"
                }),
                log_template: None,
            },
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more events from ZooKeeper".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the ZooKeeper server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "ZooKeeper"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "zookeeper_connected",
                "Triggered when ZooKeeper client connects",
                json!({"type": "placeholder", "event_id": "zookeeper_connected"}),
            ),
            EventType::new(
                "zookeeper_data_received",
                "Triggered when ZooKeeper client receives data",
                json!({"type": "placeholder", "event_id": "zookeeper_data_received"}),
            ),
            EventType::new(
                "zookeeper_children_received",
                "Triggered when ZooKeeper client receives children list",
                json!({"type": "placeholder", "event_id": "zookeeper_children_received"}),
            ),
            EventType::new(
                "zookeeper_operation_complete",
                "Triggered when a ZooKeeper write (create/set_data/delete) completes",
                json!({"type": "placeholder", "event_id": "zookeeper_operation_complete"}),
            ),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ZooKeeper"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "zookeeper",
            "zk",
            "zookeeper client",
            "connect to zookeeper",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("zookeeper-async v5.0 client library")
            .llm_control("ZNode operations (create, get, set, delete, getChildren)")
            .e2e_testing(
                "tests/client/zookeeper/command_channel_test.rs drives a real zookeeper-async \
                 session against NetGet's own ZooKeeper server on 127.0.0.1",
            )
            .notes(
                "Real zookeeper-async session: create/get_data/set_data/delete/get_children \
                 run against the server and raise events. No watch mechanism - watches are \
                 registered as `false` on every call, so the client polls rather than being \
                 notified.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "ZooKeeper client for distributed coordination"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to ZooKeeper at localhost:2181 and read /config/database"
    }

    fn group_name(&self) -> &'static str {
        "Database"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls ZooKeeper operations
            json!({
                "type": "open_client",
                "remote_addr": "localhost:2181",
                "base_stack": "zookeeper",
                "instruction": "Read configuration from /myapp/config and list its children"
            }),
            // Script mode: Code-based znode operations
            json!({
                "type": "open_client",
                "remote_addr": "localhost:2181",
                "base_stack": "zookeeper",
                "event_handlers": [{
                    "event_pattern": "zookeeper_data_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<zookeeper_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed znode operations
            json!({
                "type": "open_client",
                "remote_addr": "localhost:2181",
                "base_stack": "zookeeper",
                "event_handlers": [
                    {
                        "event_pattern": "zookeeper_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "get_data",
                                "path": "/myapp/config"
                            }]
                        }
                    },
                    {
                        "event_pattern": "zookeeper_data_received",
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
impl Client for ZookeeperClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::zookeeper::ZookeeperClient;

            ZookeeperClient::connect_with_llm_actions(
                ctx.remote_addr,
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
            "create_znode" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing path")?;
                let data = action
                    .get("data")
                    .and_then(|v| v.as_str())
                    .context("Missing data")?;

                Ok(ClientActionResult::Custom {
                    name: "create_znode".to_string(),
                    data: json!({
                        "path": path,
                        "data": data
                    }),
                })
            }
            "get_data" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing path")?;

                Ok(ClientActionResult::Custom {
                    name: "get_data".to_string(),
                    data: json!({
                        "path": path
                    }),
                })
            }
            "set_data" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing path")?;
                let data = action
                    .get("data")
                    .and_then(|v| v.as_str())
                    .context("Missing data")?;

                Ok(ClientActionResult::Custom {
                    name: "set_data".to_string(),
                    data: json!({
                        "path": path,
                        "data": data
                    }),
                })
            }
            "delete_znode" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing path")?;

                Ok(ClientActionResult::Custom {
                    name: "delete_znode".to_string(),
                    data: json!({
                        "path": path
                    }),
                })
            }
            "get_children" => {
                let path = action
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing path")?;

                Ok(ClientActionResult::Custom {
                    name: "get_children".to_string(),
                    data: json!({
                        "path": path
                    }),
                })
            }
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow!("Unknown action type: {}", action_type)),
        }
    }
}

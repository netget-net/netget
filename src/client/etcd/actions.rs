//! etcd client protocol actions implementation

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

/// etcd client connected event
pub static ETCD_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "etcd_connected",
        "etcd client successfully connected to server",
        json!({
            "type": "etcd_get",
            "key": "/config/database"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "etcd server address".to_string(),
        required: true,
    }])
});

/// etcd client response received event
pub static ETCD_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "etcd_response_received",
        "Response received from etcd server",
        json!({
            "type": "etcd_put",
            "key": "/config/database",
            "value": "postgresql://localhost:5432/mydb"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "The operation type (get, put, delete)".to_string(),
            required: true,
        },
        Parameter {
            name: "key".to_string(),
            type_hint: "string".to_string(),
            description: "The key that was operated on".to_string(),
            required: true,
        },
    ])
});

/// etcd client protocol action handler
pub struct EtcdClientProtocol;

impl EtcdClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for EtcdClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "etcd_get".to_string(),
                description: "Get a key-value pair from etcd".to_string(),
                parameters: vec![Parameter {
                    name: "key".to_string(),
                    type_hint: "string".to_string(),
                    description: "Key to retrieve".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "etcd_get",
                    "key": "/config/database"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "etcd_put".to_string(),
                description: "Put a key-value pair into etcd".to_string(),
                parameters: vec![
                    Parameter {
                        name: "key".to_string(),
                        type_hint: "string".to_string(),
                        description: "Key to set".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "value".to_string(),
                        type_hint: "string".to_string(),
                        description: "Value to set".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "etcd_put",
                    "key": "/config/database",
                    "value": "postgresql://localhost:5432/mydb"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "etcd_delete".to_string(),
                description: "Delete a key from etcd".to_string(),
                parameters: vec![Parameter {
                    name: "key".to_string(),
                    type_hint: "string".to_string(),
                    description: "Key to delete".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "etcd_delete",
                    "key": "/config/database"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the etcd server".to_string(),
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
                name: "etcd_get".to_string(),
                description: "Get a key in response to received data".to_string(),
                parameters: vec![Parameter {
                    name: "key".to_string(),
                    type_hint: "string".to_string(),
                    description: "Key to retrieve".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "etcd_get",
                    "key": "/config/database"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "etcd_put".to_string(),
                description: "Put a key in response to received data".to_string(),
                parameters: vec![
                    Parameter {
                        name: "key".to_string(),
                        type_hint: "string".to_string(),
                        description: "Key to set".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "value".to_string(),
                        type_hint: "string".to_string(),
                        description: "Value to set".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "etcd_put",
                    "key": "/config/database",
                    "value": "postgresql://localhost:5432/mydb"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "etcd"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "etcd_connected",
                "Triggered when etcd client connects to server",
                json!({"type": "placeholder", "event_id": "etcd_connected"}),
            ),
            EventType::new(
                "etcd_response_received",
                "Triggered when etcd client receives a response",
                json!({"type": "placeholder", "event_id": "etcd_response_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>gRPC>etcd"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["etcd", "etcd client", "connect to etcd"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .implementation("etcd-client crate for gRPC-based KV operations")
            .llm_control("Full control over get/put/delete operations")
            .e2e_testing(
                "tests/client/etcd/real_server_test.rs, 6 LLM calls, against the official Go \
                 etcd (grpc-go; NetGet's client is etcd-client on tonic, so no code is shared) \
                 read back with etcdctl. The model puts a key, gets it, puts a second value \
                 built from the kvs entry etcd returned, and deletes the first; etcdctl must \
                 find exactly that value and the deleted key gone. Checked against etcd 3.5.17 \
                 and 3.7.1. Not #[ignore]d, and a missing etcd or etcdctl fails the test rather \
                 than skipping it.",
            )
            .notes(
                "Single-key get, put and delete only: no range or prefix reads, transactions, \
                 watches, leases, authentication or TLS.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "etcd client for distributed key-value operations"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to etcd at localhost:2379 and get the value of '/config/database'"
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls etcd operations
            json!({
                "type": "open_client",
                "remote_addr": "localhost:2379",
                "base_stack": "etcd",
                "instruction": "Store a configuration key and retrieve it back"
            }),
            // Script mode: Code-based key-value operations
            json!({
                "type": "open_client",
                "remote_addr": "localhost:2379",
                "base_stack": "etcd",
                "event_handlers": [{
                    "event_pattern": "etcd_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<etcd_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed get/put operations
            json!({
                "type": "open_client",
                "remote_addr": "localhost:2379",
                "base_stack": "etcd",
                "event_handlers": [
                    {
                        "event_pattern": "etcd_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "etcd_put",
                                "key": "/config/app",
                                "value": "production"
                            }]
                        }
                    },
                    {
                        "event_pattern": "etcd_response_received",
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
impl Client for EtcdClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::etcd::EtcdClient;
            EtcdClient::connect_with_llm_actions(
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
            "etcd_get" => {
                let key = action
                    .get("key")
                    .and_then(|v| v.as_str())
                    .context("Missing 'key' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "etcd_get".to_string(),
                    data: json!({
                        "key": key,
                    }),
                })
            }
            "etcd_put" => {
                let key = action
                    .get("key")
                    .and_then(|v| v.as_str())
                    .context("Missing 'key' field")?
                    .to_string();

                let value = action
                    .get("value")
                    .and_then(|v| v.as_str())
                    .context("Missing 'value' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "etcd_put".to_string(),
                    data: json!({
                        "key": key,
                        "value": value,
                    }),
                })
            }
            "etcd_delete" => {
                let key = action
                    .get("key")
                    .and_then(|v| v.as_str())
                    .context("Missing 'key' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "etcd_delete".to_string(),
                    data: json!({
                        "key": key,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown etcd client action: {}",
                action_type
            )),
        }
    }
}

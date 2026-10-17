//! DynamoDB client protocol actions implementation

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

/// DynamoDB client connected event
pub static DYNAMODB_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dynamodb_connected",
        "DynamoDB client initialized and ready to send requests",
        json!({"type": "put_item", "table_name": "Users", "item": {"id": {"S": "user456"}, "name": {"S": "Bob"}}}),
    )
    .with_parameters(vec![
        Parameter {
            name: "region".to_string(),
            type_hint: "string".to_string(),
            description: "AWS region for DynamoDB".to_string(),
            required: true,
        },
        Parameter {
            name: "endpoint".to_string(),
            type_hint: "string".to_string(),
            description: "DynamoDB endpoint URL".to_string(),
            required: false,
        },
    ])
});

/// DynamoDB client response received event
pub static DYNAMODB_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dynamodb_response_received",
        "DynamoDB response received from server",
        json!({"type": "query", "table_name": "Users", "key_condition_expression": "id = :id"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "DynamoDB operation performed".to_string(),
            required: true,
        },
        Parameter {
            name: "success".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether the operation succeeded".to_string(),
            required: true,
        },
        Parameter {
            name: "data".to_string(),
            type_hint: "object".to_string(),
            description: "Response data from DynamoDB".to_string(),
            required: false,
        },
        Parameter {
            name: "error".to_string(),
            type_hint: "string".to_string(),
            description: "Error message if operation failed".to_string(),
            required: false,
        },
    ])
});

/// DynamoDB client protocol action handler
pub struct DynamoDbClientProtocol;

impl DynamoDbClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for DynamoDbClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
                ParameterDefinition {
                    name: "region".to_string(),
                    description: "AWS region (e.g., us-east-1). Defaults to us-east-1".to_string(),
                    type_hint: "string".to_string(),
                    required: false,
                    example: json!("us-east-1"),
                    default: None,
                },
                ParameterDefinition {
                    name: "endpoint_url".to_string(),
                    description: "Custom DynamoDB endpoint URL (for local testing with DynamoDB Local or LocalStack)".to_string(),
                    type_hint: "string".to_string(),
                    required: false,
                    example: json!("http://localhost:8000"),
                    default: None,
                },
                ParameterDefinition {
                    name: "access_key_id".to_string(),
                    description: "AWS access key ID (defaults to environment variable)".to_string(),
                    type_hint: "string".to_string(),
                    required: false,
                    example: json!("AKIAIOSFODNN7EXAMPLE"),
                    default: None,
                },
                ParameterDefinition {
                    name: "secret_access_key".to_string(),
                    description: "AWS secret access key (defaults to environment variable)".to_string(),
                    type_hint: "string".to_string(),
                    required: false,
                    example: json!("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
                    default: None,
                },
            ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "put_item".to_string(),
                description: "Put an item into a DynamoDB table".to_string(),
                parameters: vec![
                    Parameter {
                        name: "table_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Name of the DynamoDB table".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "item".to_string(),
                        type_hint: "object".to_string(),
                        description: "Item to put (map of attribute names to values with types)"
                            .to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "put_item",
                    "table_name": "Users",
                    "item": {
                        "id": {"S": "user123"},
                        "name": {"S": "Alice"},
                        "age": {"N": "30"}
                    }
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_item".to_string(),
                description: "Get an item from a DynamoDB table by primary key".to_string(),
                parameters: vec![
                    Parameter {
                        name: "table_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Name of the DynamoDB table".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "key".to_string(),
                        type_hint: "object".to_string(),
                        description:
                            "Primary key of the item (map of attribute names to values with types)"
                                .to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "get_item",
                    "table_name": "Users",
                    "key": {
                        "id": {"S": "user123"}
                    }
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "query".to_string(),
                description: "Query items from a DynamoDB table".to_string(),
                parameters: vec![
                    Parameter {
                        name: "table_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Name of the DynamoDB table".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "key_condition_expression".to_string(),
                        type_hint: "string".to_string(),
                        description: "Query condition expression".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "expression_attribute_values".to_string(),
                        type_hint: "object".to_string(),
                        description: "Values for the expression".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "query",
                    "table_name": "Users",
                    "key_condition_expression": "id = :id",
                    "expression_attribute_values": {
                        ":id": {"S": "user123"}
                    }
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "scan".to_string(),
                description: "Scan all items in a DynamoDB table".to_string(),
                parameters: vec![
                    Parameter {
                        name: "table_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Name of the DynamoDB table".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "filter_expression".to_string(),
                        type_hint: "string".to_string(),
                        description: "Optional filter expression".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "expression_attribute_values".to_string(),
                        type_hint: "object".to_string(),
                        description: "Values for the filter expression".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "scan",
                    "table_name": "Users",
                    "filter_expression": "age > :min_age",
                    "expression_attribute_values": {
                        ":min_age": {"N": "21"}
                    }
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "update_item".to_string(),
                description: "Update an item in a DynamoDB table".to_string(),
                parameters: vec![
                    Parameter {
                        name: "table_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Name of the DynamoDB table".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "key".to_string(),
                        type_hint: "object".to_string(),
                        description: "Primary key of the item to update".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "update_expression".to_string(),
                        type_hint: "string".to_string(),
                        description: "Update expression".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "expression_attribute_values".to_string(),
                        type_hint: "object".to_string(),
                        description: "Values for the update expression".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "update_item",
                    "table_name": "Users",
                    "key": {
                        "id": {"S": "user123"}
                    },
                    "update_expression": "SET age = :age",
                    "expression_attribute_values": {
                        ":age": {"N": "31"}
                    }
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "delete_item".to_string(),
                description: "Delete an item from a DynamoDB table".to_string(),
                parameters: vec![
                    Parameter {
                        name: "table_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Name of the DynamoDB table".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "key".to_string(),
                        type_hint: "object".to_string(),
                        description: "Primary key of the item to delete".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "delete_item",
                    "table_name": "Users",
                    "key": {
                        "id": {"S": "user123"}
                    }
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from DynamoDB".to_string(),
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
                name: "put_item".to_string(),
                description: "Put another item in response to received data".to_string(),
                parameters: vec![
                    Parameter {
                        name: "table_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Name of the DynamoDB table".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "item".to_string(),
                        type_hint: "object".to_string(),
                        description: "Item to put".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "put_item",
                    "table_name": "Users",
                    "item": {
                        "id": {"S": "user456"},
                        "name": {"S": "Bob"}
                    }
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "query".to_string(),
                description: "Query items in response to received data".to_string(),
                parameters: vec![
                    Parameter {
                        name: "table_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Name of the DynamoDB table".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "key_condition_expression".to_string(),
                        type_hint: "string".to_string(),
                        description: "Query condition expression".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "query",
                    "table_name": "Users",
                    "key_condition_expression": "id = :id"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "DynamoDB"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "dynamodb_connected",
                "Triggered when DynamoDB client is initialized",
                json!({"type": "put_item", "table_name": "Users", "item": {"id": {"S": "user456"}, "name": {"S": "Bob"}}}),
            ),
            EventType::new(
                "dynamodb_response_received",
                "Triggered when DynamoDB client receives a response",
                json!({"type": "query", "table_name": "Users", "key_condition_expression": "id = :id"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>HTTP>DynamoDB"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["dynamodb", "dynamo", "aws dynamodb", "connect to dynamodb"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
                .state(DevelopmentState::Experimental)
                .implementation("AWS SDK for DynamoDB client library")
                .llm_control("Full control over DynamoDB operations (PutItem, GetItem, Query, Scan, UpdateItem, DeleteItem)")
                .e2e_testing("DynamoDB Local or LocalStack")
                .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
                .batching(crate::protocol::metadata::BatchingMode::Unsupported)
                .build()
    }
    fn description(&self) -> &'static str {
        "DynamoDB client for interacting with AWS DynamoDB or local instances"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to DynamoDB and put an item in the Users table"
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // A custom endpoint is refused without explicit credentials (`client::aws_support`),
        // so every example names a dummy pair, which is what DynamoDB Local accepts.
        StartupExamples::new(
            // LLM mode: LLM controls DynamoDB operations
            json!({
                "type": "open_client",
                "remote_addr": "localhost:8000",
                "base_stack": "dynamodb",
                "startup_params": {
                    "access_key_id": "local",
                    "secret_access_key": "local"
                },
                "instruction": "Scan the Users table and report all items with age greater than 21"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "localhost:8000",
                "base_stack": "dynamodb",
                "startup_params": {
                    "access_key_id": "local",
                    "secret_access_key": "local"
                },
                "event_handlers": [{
                    "event_pattern": "dynamodb_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<dynamodb_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed DynamoDB scan on connect
            json!({
                "type": "open_client",
                "remote_addr": "localhost:8000",
                "base_stack": "dynamodb",
                "startup_params": {
                    "access_key_id": "local",
                    "secret_access_key": "local"
                },
                "event_handlers": [
                    {
                        "event_pattern": "dynamodb_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "scan",
                                "table_name": "Users"
                            }]
                        }
                    },
                    {
                        "event_pattern": "dynamodb_response_received",
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
impl Client for DynamoDbClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::dynamodb::DynamoDbClient;
            DynamoDbClient::connect_with_llm_actions(
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
            "put_item" => {
                let table_name = action
                    .get("table_name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'table_name' field")?
                    .to_string();

                let item = action
                    .get("item")
                    .and_then(|v| v.as_object())
                    .context("Missing 'item' field")?
                    .clone();

                Ok(ClientActionResult::Custom {
                    name: "put_item".to_string(),
                    data: json!({
                        "table_name": table_name,
                        "item": item,
                    }),
                })
            }
            "get_item" => {
                let table_name = action
                    .get("table_name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'table_name' field")?
                    .to_string();

                let key = action
                    .get("key")
                    .and_then(|v| v.as_object())
                    .context("Missing 'key' field")?
                    .clone();

                Ok(ClientActionResult::Custom {
                    name: "get_item".to_string(),
                    data: json!({
                        "table_name": table_name,
                        "key": key,
                    }),
                })
            }
            "query" => {
                let table_name = action
                    .get("table_name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'table_name' field")?
                    .to_string();

                let key_condition_expression = action
                    .get("key_condition_expression")
                    .and_then(|v| v.as_str())
                    .context("Missing 'key_condition_expression' field")?
                    .to_string();

                let expression_attribute_values = action
                    .get("expression_attribute_values")
                    .and_then(|v| v.as_object())
                    .cloned();

                Ok(ClientActionResult::Custom {
                    name: "query".to_string(),
                    data: json!({
                        "table_name": table_name,
                        "key_condition_expression": key_condition_expression,
                        "expression_attribute_values": expression_attribute_values,
                    }),
                })
            }
            "scan" => {
                let table_name = action
                    .get("table_name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'table_name' field")?
                    .to_string();

                let filter_expression = action
                    .get("filter_expression")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let expression_attribute_values = action
                    .get("expression_attribute_values")
                    .and_then(|v| v.as_object())
                    .cloned();

                Ok(ClientActionResult::Custom {
                    name: "scan".to_string(),
                    data: json!({
                        "table_name": table_name,
                        "filter_expression": filter_expression,
                        "expression_attribute_values": expression_attribute_values,
                    }),
                })
            }
            "update_item" => {
                let table_name = action
                    .get("table_name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'table_name' field")?
                    .to_string();

                let key = action
                    .get("key")
                    .and_then(|v| v.as_object())
                    .context("Missing 'key' field")?
                    .clone();

                let update_expression = action
                    .get("update_expression")
                    .and_then(|v| v.as_str())
                    .context("Missing 'update_expression' field")?
                    .to_string();

                let expression_attribute_values = action
                    .get("expression_attribute_values")
                    .and_then(|v| v.as_object())
                    .cloned();

                Ok(ClientActionResult::Custom {
                    name: "update_item".to_string(),
                    data: json!({
                        "table_name": table_name,
                        "key": key,
                        "update_expression": update_expression,
                        "expression_attribute_values": expression_attribute_values,
                    }),
                })
            }
            "delete_item" => {
                let table_name = action
                    .get("table_name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'table_name' field")?
                    .to_string();

                let key = action
                    .get("key")
                    .and_then(|v| v.as_object())
                    .context("Missing 'key' field")?
                    .clone();

                Ok(ClientActionResult::Custom {
                    name: "delete_item".to_string(),
                    data: json!({
                        "table_name": table_name,
                        "key": key,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown DynamoDB client action: {}",
                action_type
            )),
        }
    }
}

//! SQS client protocol actions implementation

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

/// SQS client connected event
pub static SQS_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sqs_connected",
        "SQS client initialized and ready to interact with queue",
        json!({
            "type": "send_message",
            "message_body": "Processed successfully"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "queue_url".to_string(),
        type_hint: "string".to_string(),
        description: "SQS queue URL".to_string(),
        required: true,
    }])
});

/// SQS message received event
pub static SQS_MESSAGE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sqs_message_received",
        "Messages received from SQS queue. An empty `messages` array means the poll returned \
         nothing, which is the normal case for short polling — answer with `receive_messages` \
         to keep waiting, or stop.",
        // A real action, not `{"type": "placeholder"}`: this is the response example the
        // model is prompted with, so a placeholder here taught it a verb that does not exist.
        json!({"type": "delete_message", "receipt_handle": "AQEBw...=="}),
    )
    .with_parameters(vec![Parameter {
        name: "messages".to_string(),
        type_hint: "array".to_string(),
        description: "Array of received messages".to_string(),
        required: true,
    }])
});

/// SQS message sent event
pub static SQS_MESSAGE_SENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sqs_message_sent",
        "Message successfully sent to SQS queue",
        json!({"type": "receive_messages", "max_messages": 5}),
    )
    .with_parameters(vec![Parameter {
        name: "message_id".to_string(),
        type_hint: "string".to_string(),
        description: "ID of the sent message".to_string(),
        required: true,
    }])
});

/// SQS client protocol action handler
pub struct SqsClientProtocol;

impl SqsClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SqsClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "queue_url".to_string(),
                description: "SQS queue URL to interact with".to_string(),
                type_hint: "string".to_string(),
                required: true,
                example: json!("https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue"),
                default: None,
            },
            ParameterDefinition {
                name: "region".to_string(),
                description: "AWS region (e.g., us-east-1, eu-west-1)".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("us-east-1"),
                default: None,
            },
            ParameterDefinition {
                name: "endpoint_url".to_string(),
                description: "Custom endpoint URL for local testing (e.g., http://localhost:9324)"
                    .to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("http://localhost:9324"),
                default: None,
            },
            // Without these the SDK falls back to its default chain — environment,
            // ~/.aws/credentials, then IMDS — so a client the model created would sign with
            // the operator's real AWS identity and there was no way to scope it. Supplying
            // them installs a static provider instead.
            ParameterDefinition {
                name: "access_key_id".to_string(),
                description: "AWS access key ID. When this and secret_access_key are given, \
                              they are used instead of the ambient AWS credential chain \
                              (environment, ~/.aws/credentials, instance role)."
                    .to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("AKIAIOSFODNN7EXAMPLE"),
                default: None,
            },
            ParameterDefinition {
                name: "secret_access_key".to_string(),
                description: "AWS secret access key, used with access_key_id.".to_string(),
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
                name: "send_message".to_string(),
                description: "Send a message to the SQS queue".to_string(),
                parameters: vec![
                    Parameter {
                        name: "message_body".to_string(),
                        type_hint: "string".to_string(),
                        description: "The message content to send".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "message_attributes".to_string(),
                        type_hint: "object".to_string(),
                        description: "Optional message attributes (key-value pairs)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "delay_seconds".to_string(),
                        type_hint: "number".to_string(),
                        description: "Delay in seconds before message becomes available"
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_message",
                    "message_body": "Hello from NetGet",
                    "message_attributes": {
                        "priority": "high",
                        "source": "netget"
                    }
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "receive_messages".to_string(),
                description: "Receive messages from the SQS queue".to_string(),
                parameters: vec![
                    Parameter {
                        name: "max_messages".to_string(),
                        type_hint: "number".to_string(),
                        description: "Maximum number of messages to receive (1-10)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "wait_time_seconds".to_string(),
                        type_hint: "number".to_string(),
                        description: "Long polling wait time in seconds (0-20)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "visibility_timeout".to_string(),
                        type_hint: "number".to_string(),
                        description: "Visibility timeout in seconds for received messages"
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "receive_messages",
                    "max_messages": 5,
                    "wait_time_seconds": 10
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "delete_message".to_string(),
                description: "Delete a message from the queue using its receipt handle".to_string(),
                parameters: vec![Parameter {
                    name: "receipt_handle".to_string(),
                    type_hint: "string".to_string(),
                    description: "Receipt handle of the message to delete".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "delete_message",
                    "receipt_handle": "AQEBwJnKyrHigUMZj6rY..."
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "purge_queue".to_string(),
                description: "Delete all messages in the queue".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "purge_queue"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_queue_attributes".to_string(),
                description: "Get attributes of the queue (message count, etc.)".to_string(),
                parameters: vec![Parameter {
                    name: "attribute_names".to_string(),
                    type_hint: "array".to_string(),
                    description: "List of attribute names to retrieve".to_string(),
                    required: false,
                }],
                example: json!({
                    "type": "get_queue_attributes",
                    "attribute_names": ["ApproximateNumberOfMessages", "QueueArn"]
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the SQS queue".to_string(),
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
                name: "send_message".to_string(),
                description: "Send a message to the queue in response to received messages"
                    .to_string(),
                parameters: vec![Parameter {
                    name: "message_body".to_string(),
                    type_hint: "string".to_string(),
                    description: "The message content to send".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_message",
                    "message_body": "Processed successfully"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "delete_message".to_string(),
                description: "Delete a received message".to_string(),
                parameters: vec![Parameter {
                    name: "receipt_handle".to_string(),
                    type_hint: "string".to_string(),
                    description: "Receipt handle from received message".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "delete_message",
                    "receipt_handle": "AQEBwJnKyrHigUMZj6rY..."
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "SQS"
    }
    /// The three statics themselves, not rebuilt copies.
    ///
    /// This used to construct three fresh `EventType`s with different descriptions, no
    /// parameters and `{"type": "placeholder"}` response examples — so the documentation and
    /// registry surfaces described one thing while the events actually raised at runtime
    /// (the `LazyLock` statics above) described another.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            SQS_CLIENT_CONNECTED_EVENT.clone(),
            SQS_MESSAGE_RECEIVED_EVENT.clone(),
            SQS_MESSAGE_SENT_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>SQS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["sqs", "sqs client", "connect to sqs", "aws sqs", "queue"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("AWS SDK for SQS with HTTP/JSON protocol")
            .llm_control("Full control over queue operations")
            .e2e_testing("LocalStack SQS container")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "AWS SQS client for queue-based messaging"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to SQS queue MyQueue and receive messages"
    }
    fn group_name(&self) -> &'static str {
        "Cloud"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // A custom endpoint is refused without explicit credentials (`client::aws_support`),
        // so every example names a dummy pair, which is what a local emulator accepts.
        StartupExamples::new(
            // LLM mode: LLM controls SQS operations
            json!({
                "type": "open_client",
                "remote_addr": "localhost:9324",
                "base_stack": "sqs",
                "startup_params": {
                    "queue_url": "http://localhost:9324/000000000000/MyQueue",
                    "endpoint_url": "http://localhost:9324",
                    "access_key_id": "local",
                    "secret_access_key": "local"
                },
                "instruction": "Send a test message and receive messages from the queue"
            }),
            // Script mode: Code-based message processing
            json!({
                "type": "open_client",
                "remote_addr": "localhost:9324",
                "base_stack": "sqs",
                "startup_params": {
                    "queue_url": "http://localhost:9324/000000000000/MyQueue",
                    "endpoint_url": "http://localhost:9324",
                    "access_key_id": "local",
                    "secret_access_key": "local"
                },
                "event_handlers": [{
                    "event_pattern": "sqs_message_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<sqs_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed message operations
            json!({
                "type": "open_client",
                "remote_addr": "localhost:9324",
                "base_stack": "sqs",
                "startup_params": {
                    "queue_url": "http://localhost:9324/000000000000/MyQueue",
                    "endpoint_url": "http://localhost:9324",
                    "access_key_id": "local",
                    "secret_access_key": "local"
                },
                "event_handlers": [
                    {
                        "event_pattern": "sqs_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_message",
                                "message_body": "Test message from NetGet"
                            }]
                        }
                    },
                    {
                        "event_pattern": "sqs_message_sent",
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
impl Client for SqsClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::sqs::SqsClient;
            SqsClient::connect_with_llm_actions(
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
            "send_message" => {
                let message_body = action
                    .get("message_body")
                    .and_then(|v| v.as_str())
                    .context("Missing 'message_body' field")?
                    .to_string();

                let message_attributes = action.get("message_attributes").cloned();

                let delay_seconds = action.get("delay_seconds").and_then(|v| v.as_i64());

                Ok(ClientActionResult::Custom {
                    name: "send_message".to_string(),
                    data: json!({
                        "message_body": message_body,
                        "message_attributes": message_attributes,
                        "delay_seconds": delay_seconds,
                    }),
                })
            }
            "receive_messages" => {
                let max_messages = action.get("max_messages").and_then(|v| v.as_i64());

                let wait_time_seconds = action.get("wait_time_seconds").and_then(|v| v.as_i64());

                let visibility_timeout = action.get("visibility_timeout").and_then(|v| v.as_i64());

                Ok(ClientActionResult::Custom {
                    name: "receive_messages".to_string(),
                    data: json!({
                        "max_messages": max_messages,
                        "wait_time_seconds": wait_time_seconds,
                        "visibility_timeout": visibility_timeout,
                    }),
                })
            }
            "delete_message" => {
                let receipt_handle = action
                    .get("receipt_handle")
                    .and_then(|v| v.as_str())
                    .context("Missing 'receipt_handle' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "delete_message".to_string(),
                    data: json!({
                        "receipt_handle": receipt_handle,
                    }),
                })
            }
            "purge_queue" => Ok(ClientActionResult::Custom {
                name: "purge_queue".to_string(),
                data: json!({}),
            }),
            "get_queue_attributes" => {
                let attribute_names = action
                    .get("attribute_names")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    });

                Ok(ClientActionResult::Custom {
                    name: "get_queue_attributes".to_string(),
                    data: json!({
                        "attribute_names": attribute_names,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown SQS client action: {}",
                action_type
            )),
        }
    }
}

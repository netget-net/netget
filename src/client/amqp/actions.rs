//! AMQP client protocol actions

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::LazyLock;

/// AMQP client connected event
pub static AMQP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "amqp_connected",
        "AMQP client connected to broker",
        json!({"type": "placeholder", "event_id": "amqp_connected"}),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "Remote broker address".to_string(),
        required: true,
    }])
});

/// AMQP client channel opened event
pub static AMQP_CLIENT_CHANNEL_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "amqp_channel_opened",
        "AMQP channel opened",
        json!({"type": "placeholder", "event_id": "amqp_channel_opened"}),
    )
    .with_parameters(vec![Parameter {
        name: "channel_id".to_string(),
        type_hint: "number".to_string(),
        description: "Channel ID".to_string(),
        required: true,
    }])
});

/// AMQP client message received event
pub static AMQP_CLIENT_MESSAGE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "amqp_message_received",
        "Message received from queue",
        json!({"type": "placeholder", "event_id": "amqp_message_received"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "queue_name".to_string(),
            type_hint: "string".to_string(),
            description: "Queue name".to_string(),
            required: true,
        },
        Parameter {
            name: "message_body".to_string(),
            type_hint: "string".to_string(),
            description: "Message content".to_string(),
            required: true,
        },
    ])
});

/// AMQP client protocol
pub struct AmqpClientProtocol;

impl AmqpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for AmqpClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "open_channel".to_string(),
                description: "Open a new AMQP channel".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "open_channel"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "publish".to_string(),
                description:
                    "Publish a message to an exchange. Opens a channel first if none is open \
                     yet, so this works immediately after connecting."
                        .to_string(),
                parameters: vec![
                    Parameter {
                        name: "routing_key".to_string(),
                        type_hint: "string".to_string(),
                        description:
                            "Routing key. With the default exchange (\"\") this is the queue \
                            name the message is delivered to."
                                .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "payload".to_string(),
                        type_hint: "string".to_string(),
                        description: "Message body, sent as UTF-8. Put serialised JSON here as a \
                            string."
                            .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "exchange".to_string(),
                        type_hint: "string".to_string(),
                        description:
                            "Exchange to publish to. Defaults to \"\", the default exchange, \
                            which routes by queue name."
                                .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "publish",
                    "exchange": "",
                    "routing_key": "tasks",
                    "payload": "hello"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the AMQP broker".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "consume".to_string(),
                description: "Subscribe to a queue. Each delivery raises \
                    `amqp_message_received`, which is otherwise unreachable: without a \
                    consumer nothing can ever arrive."
                    .to_string(),
                parameters: vec![Parameter {
                    name: "queue_name".to_string(),
                    type_hint: "string".to_string(),
                    description: "Queue to consume from".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "consume",
                    "queue_name": "task_queue"
                }),
                log_template: None,
            },
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        // Declared, not just accepted. `execute_action` now rejects unknown names, so anything
        // it can run has to be advertised or the model can only reach it by guessing.
        vec![ActionDefinition {
            name: "wait_for_more".to_string(),
            description: "Do nothing and wait for the next AMQP frame. Correct when what \
                arrived needs no reply."
                .to_string(),
            parameters: vec![],
            example: json!({
                "type": "wait_for_more"
            }),
            log_template: None,
        }]
    }

    fn protocol_name(&self) -> &'static str {
        "AMQP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            AMQP_CLIENT_CONNECTED_EVENT.clone(),
            AMQP_CLIENT_CHANNEL_OPENED_EVENT.clone(),
            AMQP_CLIENT_MESSAGE_RECEIVED_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>AMQP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["amqp", "rabbitmq", "client"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("lapin AMQP client library")
            .llm_control("Queue/exchange operations, message publishing/consuming")
            .e2e_testing("NetGet AMQP server or RabbitMQ")
            .notes("AMQP 0.9.1 client for RabbitMQ compatibility")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "AMQP 0.9.1 client for connecting to RabbitMQ"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to RabbitMQ at localhost:5672 and publish messages"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls AMQP operations
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5672",
                "base_stack": "amqp",
                "instruction": "Open a channel and declare a queue named 'tasks' for message processing"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5672",
                "base_stack": "amqp",
                "event_handlers": [{
                    "event_pattern": "amqp_message_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<amqp_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed AMQP channel open on connect
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5672",
                "base_stack": "amqp",
                "event_handlers": [
                    {
                        "event_pattern": "amqp_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "open_channel"
                            }]
                        }
                    },
                    {
                        "event_pattern": "amqp_channel_opened",
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
impl Client for AmqpClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(async move {
            crate::client::amqp::AmqpClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        let action_type = action["type"].as_str().context("Missing action type")?;

        match action_type {
            "open_channel" => Ok(ClientActionResult::Custom {
                name: "open_channel".to_string(),
                data: json!({}),
            }),
            "consume" => {
                let queue = action["queue_name"]
                    .as_str()
                    .context("Missing 'queue_name' for consume")?;
                Ok(ClientActionResult::Custom {
                    name: "consume".to_string(),
                    data: json!({ "queue_name": queue }),
                })
            }
            "publish" => {
                let routing_key = action["routing_key"]
                    .as_str()
                    .context("Missing 'routing_key' for publish")?;
                let payload = action["payload"]
                    .as_str()
                    .context("Missing 'payload' for publish")?;
                let exchange = action["exchange"].as_str().unwrap_or("");
                Ok(ClientActionResult::Custom {
                    name: "publish".to_string(),
                    data: json!({
                        "exchange": exchange,
                        "routing_key": routing_key,
                        "payload": payload,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            // Reject rather than swallow. This used to be `_ => WaitForMore`, so *any* name -
            // a typo, an action from another protocol, or a common action this client cannot
            // run - was silently turned into "wait", and the model was told nothing. Returning
            // Ok also stops the repair loop from ever firing, so the mistake could not be
            // corrected; the client simply waited forever for a message it never asked for.
            other => Err(anyhow::anyhow!(
                "Unknown AMQP client action '{}'. Valid actions: open_channel, publish, \
                 disconnect, wait_for_more",
                other
            )),
        }
    }
}

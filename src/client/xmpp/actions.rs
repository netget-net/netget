//! XMPP client protocol actions implementation

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

/// XMPP client connected event
pub static XMPP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "xmpp_connected",
        "XMPP client successfully connected and authenticated",
        json!({
            "type": "send_message",
            "to": "friend@example.com",
            "body": "Hello!"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "jid".to_string(),
        type_hint: "string".to_string(),
        description: "The JID (Jabber ID) of the connected client".to_string(),
        required: true,
    }])
});

/// XMPP client message received event
pub static XMPP_CLIENT_MESSAGE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "xmpp_message_received",
        "XMPP message received from another user",
        json!({
            "type": "send_message",
            "to": "friend@example.com",
            "body": "Thanks for your message!"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "from".to_string(),
            type_hint: "string".to_string(),
            description: "JID of the message sender".to_string(),
            required: true,
        },
        Parameter {
            name: "to".to_string(),
            type_hint: "string".to_string(),
            description: "JID of the message recipient".to_string(),
            required: true,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description: "Message body text".to_string(),
            required: true,
        },
        Parameter {
            name: "message_type".to_string(),
            type_hint: "string".to_string(),
            description: "Type of message (Chat, Groupchat, etc.)".to_string(),
            required: true,
        },
    ])
});

/// XMPP client presence received event
pub static XMPP_CLIENT_PRESENCE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "xmpp_presence_received",
        "XMPP presence update received from a contact",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "from".to_string(),
            type_hint: "string".to_string(),
            description: "JID of the contact".to_string(),
            required: true,
        },
        Parameter {
            name: "presence_type".to_string(),
            type_hint: "string".to_string(),
            description: "Type of presence (Available, Unavailable, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "show".to_string(),
            type_hint: "string".to_string(),
            description: "Availability indicator (away, chat, dnd, xa)".to_string(),
            required: false,
        },
        Parameter {
            name: "status".to_string(),
            type_hint: "string".to_string(),
            description: "Status message".to_string(),
            required: false,
        },
    ])
});

/// XMPP client protocol action handler
pub struct XmppClientProtocol;

impl XmppClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for XmppClientProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "jid".to_string(),
                type_hint: "string".to_string(),
                description: "JID (Jabber ID) to connect as (e.g., user@example.com). Names \
                              the account only: the client connects to remote_addr, never to \
                              a server looked up from the JID's domain"
                    .to_string(),
                required: true,
                example: serde_json::json!("alice@example.com"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "password".to_string(),
                type_hint: "string".to_string(),
                description: "Password for authentication".to_string(),
                required: true,
                example: serde_json::json!("secret"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "session_timeout_secs".to_string(),
                type_hint: "integer".to_string(),
                description: format!(
                    "Seconds to wait for the server to accept the session (TCP connect, \
                     STARTTLS, SASL authentication, resource binding) before the client fails, \
                     1..{}",
                    super::MAX_SESSION_TIMEOUT_SECS
                ),
                required: false,
                example: serde_json::json!(30),
                default: Some(serde_json::json!(super::SESSION_TIMEOUT.as_secs())),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_message".to_string(),
                description: "Send a message to a JID".to_string(),
                parameters: vec![
                    Parameter {
                        name: "to".to_string(),
                        type_hint: "string".to_string(),
                        description: "JID of the recipient".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "body".to_string(),
                        type_hint: "string".to_string(),
                        description: "Message body text".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_message",
                    "to": "friend@example.com",
                    "body": "Hello from NetGet!"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_presence".to_string(),
                description: "Send presence update".to_string(),
                parameters: vec![
                    Parameter {
                        name: "show".to_string(),
                        type_hint: "string".to_string(),
                        description: "Availability (away, chat, dnd, xa)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "status".to_string(),
                        type_hint: "string".to_string(),
                        description: "Status message".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_presence",
                    "show": "away",
                    "status": "Out for lunch"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the XMPP server".to_string(),
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
                description: "Send a message in response to a received message or event"
                    .to_string(),
                parameters: vec![
                    Parameter {
                        name: "to".to_string(),
                        type_hint: "string".to_string(),
                        description: "JID of the recipient".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "body".to_string(),
                        type_hint: "string".to_string(),
                        description: "Message body text".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_message",
                    "to": "friend@example.com",
                    "body": "Thanks for your message!"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more events before responding".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "XMPP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "xmpp_connected",
                "Triggered when XMPP client connects and authenticates",
                json!({"type": "placeholder", "event_id": "xmpp_connected"}),
            ),
            EventType::new(
                "xmpp_message_received",
                "Triggered when XMPP message is received",
                json!({"type": "placeholder", "event_id": "xmpp_message_received"}),
            ),
            EventType::new(
                "xmpp_presence_received",
                "Triggered when presence update is received",
                json!({"type": "placeholder", "event_id": "xmpp_presence_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>XMPP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "xmpp",
            "xmpp client",
            "jabber",
            "connect to xmpp",
            "connect to jabber",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("tokio-xmpp library for async XMPP client")
            .llm_control("Send messages, presence updates, respond to incoming stanzas")
            .e2e_testing(
                "Loopback listeners pin the connect target, the pending-session status and the \
                 command channel; a session against a real prosody/ejabberd exists only in \
                 #[ignore]d tests",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "XMPP/Jabber client for instant messaging"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to XMPP as user@example.com and respond to incoming messages"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls XMPP messaging
            json!({
                "type": "open_client",
                "remote_addr": "xmpp.example.com:5222",
                "base_stack": "xmpp",
                "startup_params": {"jid": "alice@example.com", "password": "secret"},
                "instruction": "Send presence and auto-reply to all incoming messages"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "xmpp.example.com:5222",
                "base_stack": "xmpp",
                "startup_params": {"jid": "alice@example.com", "password": "secret"},
                "event_handlers": [{
                    "event_pattern": "xmpp_message_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<xmpp_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed XMPP presence on connect
            json!({
                "type": "open_client",
                "remote_addr": "xmpp.example.com:5222",
                "base_stack": "xmpp",
                "startup_params": {"jid": "alice@example.com", "password": "secret"},
                "event_handlers": [
                    {
                        "event_pattern": "xmpp_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_presence",
                                "show": "chat",
                                "status": "Available"
                            }]
                        }
                    },
                    {
                        "event_pattern": "xmpp_message_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "wait_for_more"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for XmppClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::xmpp::XmppClientConnection;
            XmppClientConnection::connect_with_llm_actions(
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
                let to = action
                    .get("to")
                    .and_then(|v| v.as_str())
                    .context("Missing 'to' field")?;

                let body = action
                    .get("body")
                    .and_then(|v| v.as_str())
                    .context("Missing 'body' field")?;

                Ok(ClientActionResult::Custom {
                    name: "send_message".to_string(),
                    data: json!({
                        "to": to,
                        "body": body,
                    }),
                })
            }
            "send_presence" => {
                let show = action.get("show").and_then(|v| v.as_str());
                let status = action.get("status").and_then(|v| v.as_str());

                Ok(ClientActionResult::Custom {
                    name: "send_presence".to_string(),
                    data: json!({
                        "show": show,
                        "status": status,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown XMPP client action: {}",
                action_type
            )),
        }
    }
}

//! IMAP client protocol actions implementation

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

/// IMAP client connected event
pub static IMAP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "imap_connected",
        "IMAP client successfully connected and authenticated",
        json!({
            "type": "select_mailbox",
            "mailbox": "INBOX"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "IMAP server address".to_string(),
            required: true,
        },
        Parameter {
            name: "capabilities".to_string(),
            type_hint: "array".to_string(),
            description: "Server capabilities".to_string(),
            required: false,
        },
    ])
});

/// Raised once a mailbox is selected, so the model learns how many messages are there
/// and can decide what to ask for next.
pub static IMAP_MAILBOX_SELECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "imap_mailbox_selected",
        "A mailbox was selected; reports its message counts",
        json!({
            "type": "search_messages",
            "criteria": "ALL"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "mailbox".to_string(),
            type_hint: "string".to_string(),
            description: "Name of the selected mailbox".to_string(),
            required: true,
        },
        Parameter {
            name: "exists".to_string(),
            type_hint: "number".to_string(),
            description: "Total messages in the mailbox".to_string(),
            required: true,
        },
        Parameter {
            name: "recent".to_string(),
            type_hint: "number".to_string(),
            description: "Messages flagged \\Recent".to_string(),
            required: true,
        },
    ])
});

/// Raised with the ids a SEARCH matched.
pub static IMAP_SEARCH_RESULTS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "imap_search_results",
        "A SEARCH completed; reports the matching message ids",
        json!({
            "type": "fetch_message",
            "message_id": "1"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "criteria".to_string(),
            type_hint: "string".to_string(),
            description: "The search criteria that was issued".to_string(),
            required: true,
        },
        Parameter {
            name: "message_ids".to_string(),
            type_hint: "array".to_string(),
            description: "Sequence numbers of matching messages".to_string(),
            required: true,
        },
    ])
});

/// Raised for each message a FETCH returned.
pub static IMAP_MESSAGE_FETCHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "imap_message_fetched",
        "A message was fetched; reports its envelope and body",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "message_id".to_string(),
            type_hint: "string".to_string(),
            description: "The message id or range that was fetched".to_string(),
            required: true,
        },
        Parameter {
            name: "messages".to_string(),
            type_hint: "array".to_string(),
            description: "One entry per message, each with subject, from and body".to_string(),
            required: true,
        },
    ])
});

/// IMAP client protocol action handler
pub struct ImapClientProtocol;

impl ImapClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for ImapClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
                ActionDefinition {
                    name: "select_mailbox".to_string(),
                    description: "Select a mailbox (e.g., INBOX, Sent, Drafts)".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "mailbox".to_string(),
                            type_hint: "string".to_string(),
                            description: "Mailbox name (e.g., 'INBOX')".to_string(),
                            required: true,
                        },
                    ],
                    example: json!({
                        "type": "select_mailbox",
                        "mailbox": "INBOX"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "search_messages".to_string(),
                    description: "Search for messages using IMAP search criteria".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "criteria".to_string(),
                            type_hint: "string".to_string(),
                            description: "Search criteria (e.g., 'UNSEEN', 'FROM sender@example.com', 'SUBJECT test')".to_string(),
                            required: true,
                        },
                    ],
                    example: json!({
                        "type": "search_messages",
                        "criteria": "UNSEEN"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "fetch_message".to_string(),
                    description: "Fetch a message by sequence number or UID".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "message_id".to_string(),
                            type_hint: "string".to_string(),
                            description: "Message sequence number or UID".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "parts".to_string(),
                            type_hint: "string".to_string(),
                            description: "What to fetch (e.g., 'BODY[]', 'BODY[HEADER]', 'FLAGS')".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "fetch_message",
                        "message_id": "1",
                        "parts": "BODY[]"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "mark_as_read".to_string(),
                    description: "Mark a message as read (seen)".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "message_id".to_string(),
                            type_hint: "string".to_string(),
                            description: "Message sequence number or UID".to_string(),
                            required: true,
                        },
                    ],
                    example: json!({
                        "type": "mark_as_read",
                        "message_id": "1"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "mark_as_unread".to_string(),
                    description: "Mark a message as unread".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "message_id".to_string(),
                            type_hint: "string".to_string(),
                            description: "Message sequence number or UID".to_string(),
                            required: true,
                        },
                    ],
                    example: json!({
                        "type": "mark_as_unread",
                        "message_id": "1"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "delete_message".to_string(),
                    description: "Delete a message (mark for deletion and expunge)".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "message_id".to_string(),
                            type_hint: "string".to_string(),
                            description: "Message sequence number or UID".to_string(),
                            required: true,
                        },
                    ],
                    example: json!({
                        "type": "delete_message",
                        "message_id": "1"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "list_mailboxes".to_string(),
                    description: "List all available mailboxes".to_string(),
                    parameters: vec![],
                    example: json!({
                        "type": "list_mailboxes"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "disconnect".to_string(),
                    description: "Disconnect from the IMAP server".to_string(),
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
                name: "fetch_message".to_string(),
                description: "Fetch a message in response to search results".to_string(),
                parameters: vec![Parameter {
                    name: "message_id".to_string(),
                    type_hint: "string".to_string(),
                    description: "Message sequence number or UID".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "fetch_message",
                    "message_id": "1"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more events without taking action".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "IMAP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        // Clones of the statics the client actually emits, so a declaration cannot drift
        // from what is raised. These four used to be hand-written duplicates carrying a
        // `"placeholder"` example action, and three of them named events nothing ever
        // raised -- the model got one turn on connect and then went deaf.
        vec![
            IMAP_CLIENT_CONNECTED_EVENT.clone(),
            IMAP_MAILBOX_SELECTED_EVENT.clone(),
            IMAP_SEARCH_RESULTS_EVENT.clone(),
            IMAP_MESSAGE_FETCHED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>IMAP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["imap", "imap client", "email", "mail", "connect to imap"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("async-imap library with TLS support")
            .llm_control("Full control over mailbox operations, search, and message management")
            .e2e_testing("Docker IMAP container or public test servers")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // Nothing can arrive during a call: async_imap owns the socket and every event is the
            // result of the client's own verb, reported before the next one runs (no IDLE).
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "IMAP client for email retrieval and management"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to IMAP server at imap.example.com:993 and fetch unread messages from INBOX"
    }
    fn group_name(&self) -> &'static str {
        "Email & Messaging"
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "username".to_string(),
                type_hint: "string".to_string(),
                description: "IMAP username for authentication".to_string(),
                required: true,
                example: json!("user@example.com"),
                default: None,
            },
            ParameterDefinition {
                name: "password".to_string(),
                type_hint: "string".to_string(),
                description: "IMAP password for authentication".to_string(),
                required: true,
                example: json!("secret123"),
                default: None,
            },
            ParameterDefinition {
                name: "use_tls".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether to use TLS (default: true for port 993)".to_string(),
                required: false,
                example: json!(false),
                default: None,
            },
        ]
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls email retrieval
            json!({
                "type": "open_client",
                "remote_addr": "imap.example.com:993",
                "base_stack": "imap",
                "instruction": "Select INBOX, search for unread messages, and fetch the first one"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "imap.example.com:993",
                "base_stack": "imap",
                "event_handlers": [{
                    "event_pattern": "imap_message_fetched",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<imap_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed IMAP operations on connect
            json!({
                "type": "open_client",
                "remote_addr": "imap.example.com:993",
                "base_stack": "imap",
                "event_handlers": [
                    {
                        "event_pattern": "imap_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "select_mailbox",
                                "mailbox": "INBOX"
                            }]
                        }
                    },
                    {
                        "event_pattern": "imap_mailbox_selected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "search_messages",
                                "criteria": "UNSEEN"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for ImapClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::imap::ImapClient;

            ImapClient::connect_with_llm_actions(
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
            "select_mailbox" => {
                let mailbox = action
                    .get("mailbox")
                    .and_then(|v| v.as_str())
                    .context("Missing 'mailbox' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "select_mailbox".to_string(),
                    data: json!({ "mailbox": mailbox }),
                })
            }
            "search_messages" => {
                let criteria = action
                    .get("criteria")
                    .and_then(|v| v.as_str())
                    .context("Missing 'criteria' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "search_messages".to_string(),
                    data: json!({ "criteria": criteria }),
                })
            }
            "fetch_message" => {
                let message_id = action
                    .get("message_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'message_id' field")?
                    .to_string();

                let parts = action
                    .get("parts")
                    .and_then(|v| v.as_str())
                    .unwrap_or("BODY[]")
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "fetch_message".to_string(),
                    data: json!({
                        "message_id": message_id,
                        "parts": parts,
                    }),
                })
            }
            "mark_as_read" => {
                let message_id = action
                    .get("message_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'message_id' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "mark_as_read".to_string(),
                    data: json!({ "message_id": message_id }),
                })
            }
            "mark_as_unread" => {
                let message_id = action
                    .get("message_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'message_id' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "mark_as_unread".to_string(),
                    data: json!({ "message_id": message_id }),
                })
            }
            "delete_message" => {
                let message_id = action
                    .get("message_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'message_id' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "delete_message".to_string(),
                    data: json!({ "message_id": message_id }),
                })
            }
            "list_mailboxes" => Ok(ClientActionResult::Custom {
                name: "list_mailboxes".to_string(),
                data: json!({}),
            }),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown IMAP client action: {}",
                action_type
            )),
        }
    }
}

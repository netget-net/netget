//! NNTP (Network News Transfer Protocol) client actions implementation

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

/// NNTP client connected event
pub static NNTP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nntp_connected",
        "NNTP client successfully connected to server",
        json!({
            "type": "nntp_group",
            "group_name": "comp.lang.rust"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "NNTP server address".to_string(),
            required: true,
        },
        Parameter {
            name: "welcome_message".to_string(),
            type_hint: "string".to_string(),
            description: "Server welcome banner (200 or 201 response)".to_string(),
            required: false,
        },
    ])
});

/// NNTP client response received event
pub static NNTP_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nntp_response_received",
        "Response received from NNTP server",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "status_code".to_string(),
            type_hint: "number".to_string(),
            description: "NNTP response status code (e.g., 211, 220, 221)".to_string(),
            required: true,
        },
        Parameter {
            name: "response".to_string(),
            type_hint: "string".to_string(),
            description: "Full response text from server".to_string(),
            required: true,
        },
        Parameter {
            name: "command".to_string(),
            type_hint: "string".to_string(),
            description: "The command that triggered this response".to_string(),
            required: false,
        },
    ])
});

/// NNTP client protocol action handler
pub struct NntpClientProtocol;

impl NntpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for NntpClientProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        crate::server::p2p_support::tls_parameters(false)
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        let mut actions = vec![
            ActionDefinition {
                name: "nntp_group".to_string(),
                description: "Select a newsgroup (GROUP command)".to_string(),
                parameters: vec![Parameter {
                    name: "group_name".to_string(),
                    type_hint: "string".to_string(),
                    description: "Name of the newsgroup to select (e.g., comp.lang.rust)"
                        .to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "nntp_group",
                    "group_name": "comp.lang.rust"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nntp_article".to_string(),
                description: "Retrieve a full article (ARTICLE command)".to_string(),
                parameters: vec![Parameter {
                    name: "article_id".to_string(),
                    type_hint: "string".to_string(),
                    description:
                        "Article number or message-id (e.g., '123' or '<msg@example.com>')"
                            .to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "nntp_article",
                    "article_id": "123"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nntp_head".to_string(),
                description: "Retrieve article headers only (HEAD command)".to_string(),
                parameters: vec![Parameter {
                    name: "article_id".to_string(),
                    type_hint: "string".to_string(),
                    description: "Article number or message-id".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "nntp_head",
                    "article_id": "123"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nntp_body".to_string(),
                description: "Retrieve article body only (BODY command)".to_string(),
                parameters: vec![Parameter {
                    name: "article_id".to_string(),
                    type_hint: "string".to_string(),
                    description: "Article number or message-id".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "nntp_body",
                    "article_id": "123"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nntp_list".to_string(),
                description: "List available newsgroups (LIST command)".to_string(),
                parameters: vec![Parameter {
                    name: "keyword".to_string(),
                    type_hint: "string".to_string(),
                    description: "Optional LIST variant (e.g., 'ACTIVE', 'NEWSGROUPS')".to_string(),
                    required: false,
                }],
                example: json!({
                    "type": "nntp_list",
                    "keyword": "ACTIVE"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nntp_xover".to_string(),
                description: "Get overview information for articles (XOVER command)".to_string(),
                parameters: vec![Parameter {
                    name: "range".to_string(),
                    type_hint: "string".to_string(),
                    description: "Article range (e.g., '1-100', '50-', '75')".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "nntp_xover",
                    "range": "1-100"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nntp_post".to_string(),
                description: "Post a new article (POST command)".to_string(),
                parameters: vec![
                    Parameter {
                        name: "headers".to_string(),
                        type_hint: "object".to_string(),
                        description: "Article headers (From, Newsgroups, Subject, etc.)"
                            .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "body".to_string(),
                        type_hint: "string".to_string(),
                        description: "Article body content".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "nntp_post",
                    "headers": {
                        "From": "user@example.com",
                        "Newsgroups": "comp.lang.rust",
                        "Subject": "Test post"
                    },
                    "body": "This is a test post."
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nntp_stat".to_string(),
                description: "Get article status without retrieving content (STAT command)"
                    .to_string(),
                parameters: vec![Parameter {
                    name: "article_id".to_string(),
                    type_hint: "string".to_string(),
                    description: "Article number or message-id".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "nntp_stat",
                    "article_id": "123"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "nntp_quit".to_string(),
                description: "Disconnect from the server (QUIT command)".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "nntp_quit"
                }),
                log_template: None,
            },
        ];
        actions.extend(crate::server::nntp::extensions::client_actions());
        actions
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "nntp_group".to_string(),
                description: "Select newsgroup in response to server data".to_string(),
                parameters: vec![Parameter {
                    name: "group_name".to_string(),
                    type_hint: "string".to_string(),
                    description: "Newsgroup name".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "nntp_group",
                    "group_name": "comp.lang.rust"
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
        "NNTP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "nntp_connected",
                "Triggered when NNTP client connects to server",
                json!({"type": "placeholder", "event_id": "nntp_connected"}),
            ),
            EventType::new(
                "nntp_response_received",
                "Triggered when NNTP client receives a response",
                json!({"type": "placeholder", "event_id": "nntp_response_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>NNTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["nntp", "nntp client", "usenet", "news", "newsgroup"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Bounded sequential NNTP transactions with optional verified implicit TLS")
            .llm_control("Selected reader commands, POST, AUTHINFO USER/PASS and sequential article-feed transactions")
            .e2e_testing("Independent nntpserver posting and TLS authentication, nntplib server tests, negative/lifecycle checks")
            .max_inbound_bytes(crate::server::nntp::extensions::MAX_ARTICLE)
            .notes("No STARTTLS, SASL, compression or persistent article spool. Credentials require TLS; certificate verification is mandatory. MODE STREAM/CHECK/TAKETHIS are sequential transactions.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            // Replies queue on the shared p2p_support::connect runner; what arrives while the
            // model answers is answered together (call_llm_for_client_batch).
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }
    fn description(&self) -> &'static str {
        "NNTP (Usenet) client for reading and posting newsgroup articles"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to NNTP at news.example.com:119 and list newsgroups"
    }
    fn group_name(&self) -> &'static str {
        "Messaging"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls NNTP operations
            json!({
                "type": "open_client",
                "remote_addr": "news.example.com:119",
                "base_stack": "nntp",
                "instruction": "List available newsgroups and select comp.lang.rust to view recent articles"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "news.example.com:119",
                "base_stack": "nntp",
                "event_handlers": [{
                    "event_pattern": "nntp_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<nntp_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed NNTP group selection on connect
            json!({
                "type": "open_client",
                "remote_addr": "news.example.com:119",
                "base_stack": "nntp",
                "event_handlers": [
                    {
                        "event_pattern": "nntp_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "nntp_group",
                                "group_name": "comp.lang.rust"
                            }]
                        }
                    },
                    {
                        "event_pattern": "nntp_response_received",
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
impl Client for NntpClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        if let Some(action) = crate::server::nntp::extensions::client_action(&action)? {
            return Ok(action);
        }
        match action_type {
            "nntp_group" => {
                let group_name = action
                    .get("group_name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'group_name' field")?;

                Ok(ClientActionResult::Custom {
                    name: "nntp_command".to_string(),
                    data: json!({
                        "command": format!("GROUP {}", group_name),
                    }),
                })
            }
            "nntp_article" => {
                let article_id = action
                    .get("article_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'article_id' field")?;

                Ok(ClientActionResult::Custom {
                    name: "nntp_command".to_string(),
                    data: json!({
                        "command": format!("ARTICLE {}", article_id),
                    }),
                })
            }
            "nntp_head" => {
                let article_id = action
                    .get("article_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'article_id' field")?;

                Ok(ClientActionResult::Custom {
                    name: "nntp_command".to_string(),
                    data: json!({
                        "command": format!("HEAD {}", article_id),
                    }),
                })
            }
            "nntp_body" => {
                let article_id = action
                    .get("article_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'article_id' field")?;

                Ok(ClientActionResult::Custom {
                    name: "nntp_command".to_string(),
                    data: json!({
                        "command": format!("BODY {}", article_id),
                    }),
                })
            }
            "nntp_list" => {
                let keyword = action.get("keyword").and_then(|v| v.as_str());

                let command = if let Some(kw) = keyword {
                    format!("LIST {}", kw)
                } else {
                    "LIST".to_string()
                };

                Ok(ClientActionResult::Custom {
                    name: "nntp_command".to_string(),
                    data: json!({
                        "command": command,
                    }),
                })
            }
            "nntp_xover" => {
                let range = action
                    .get("range")
                    .and_then(|v| v.as_str())
                    .context("Missing 'range' field")?;

                Ok(ClientActionResult::Custom {
                    name: "nntp_command".to_string(),
                    data: json!({
                        "command": format!("XOVER {}", range),
                    }),
                })
            }
            "nntp_post" => {
                crate::server::nntp::extensions::article(&action)?;
                let headers = action
                    .get("headers")
                    .and_then(|v| v.as_object())
                    .context("Missing or invalid 'headers' field")?;
                let body = action
                    .get("body")
                    .and_then(|v| v.as_str())
                    .context("Missing 'body' field")?;

                Ok(ClientActionResult::Custom {
                    name: "nntp_post".to_string(),
                    data: json!({
                        "headers": headers,
                        "body": body,
                    }),
                })
            }
            "nntp_stat" => {
                let article_id = action
                    .get("article_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'article_id' field")?;

                Ok(ClientActionResult::Custom {
                    name: "nntp_command".to_string(),
                    data: json!({
                        "command": format!("STAT {}", article_id),
                    }),
                })
            }
            "nntp_quit" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown NNTP client action: {}",
                action_type
            )),
        }
    }
}

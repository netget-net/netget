//! IRC client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::server::irc::wire::{reject_line_breaks, reject_not_a_word};
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// IRC client connected event
pub static IRC_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "irc_connected",
        "IRC client successfully connected to server",
        json!({"type": "send_privmsg", "target": "#channel", "message": "Hello!"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Remote IRC server address".to_string(),
            required: true,
        },
        Parameter {
            name: "nickname".to_string(),
            type_hint: "string".to_string(),
            description: "Nickname registered with the server".to_string(),
            required: true,
        },
    ])
});

/// IRC message received event
pub static IRC_CLIENT_MESSAGE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "irc_message_received",
        "IRC message received from server or channel",
        json!({"type": "send_privmsg", "target": "#channel", "message": "Response message"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "source".to_string(),
            type_hint: "string".to_string(),
            description: "Source of the message (nick!user@host or server)".to_string(),
            required: false,
        },
        Parameter {
            name: "command".to_string(),
            type_hint: "string".to_string(),
            description: "IRC command (e.g., PRIVMSG, JOIN, NOTICE, 001, 433)".to_string(),
            required: true,
        },
        Parameter {
            name: "target".to_string(),
            type_hint: "string".to_string(),
            description: "Target of the message (channel or user)".to_string(),
            required: false,
        },
        Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "The message text".to_string(),
            required: false,
        },
        Parameter {
            name: "raw_message".to_string(),
            type_hint: "string".to_string(),
            description: "The raw IRC message line".to_string(),
            required: true,
        },
    ])
});

/// IRC client protocol action handler
pub struct IrcClientProtocol;

impl IrcClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for IrcClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "join_channel".to_string(),
                description: "Join an IRC channel".to_string(),
                parameters: vec![Parameter {
                    name: "channel".to_string(),
                    type_hint: "string".to_string(),
                    description: "Channel name (e.g., '#rust'). One word - no spaces, no line \
                                  breaks."
                        .to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "join_channel",
                    "channel": "#rust"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "part_channel".to_string(),
                description: "Leave an IRC channel".to_string(),
                parameters: vec![
                    Parameter {
                        name: "channel".to_string(),
                        type_hint: "string".to_string(),
                        description: "Channel name to leave".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "message".to_string(),
                        type_hint: "string".to_string(),
                        description: "Optional part message".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "part_channel",
                    "channel": "#rust",
                    "message": "Goodbye!"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "change_nick".to_string(),
                description: "Change the client's nickname".to_string(),
                parameters: vec![Parameter {
                    name: "new_nick".to_string(),
                    type_hint: "string".to_string(),
                    description: "New nickname to use".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "change_nick",
                    "new_nick": "newname"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the IRC server".to_string(),
                parameters: vec![Parameter {
                    name: "quit_message".to_string(),
                    type_hint: "string".to_string(),
                    description: "Optional quit message".to_string(),
                    required: false,
                }],
                example: json!({
                    "type": "disconnect",
                    "quit_message": "Leaving"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_privmsg".to_string(),
                description: "Send a PRIVMSG to a channel or user".to_string(),
                parameters: vec![
                    Parameter {
                        name: "target".to_string(),
                        type_hint: "string".to_string(),
                        description: "Target channel or user. One word - a space here would \
                                      shift every later parameter."
                            .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "message".to_string(),
                        type_hint: "string".to_string(),
                        description: "Message text to send. Must not contain CR or LF: IRC \
                                      messages are CRLF-terminated, so a line break would \
                                      forge a second command from this client rather than \
                                      continuing the message. Truncated at the RFC 1459 \
                                      512-byte line limit."
                            .to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_privmsg",
                    "target": "#rust",
                    "message": "Hello, channel!"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_notice".to_string(),
                description: "Send a NOTICE to a channel or user".to_string(),
                parameters: vec![
                    Parameter {
                        name: "target".to_string(),
                        type_hint: "string".to_string(),
                        description: "Target channel or user. One word - a space here would \
                                      shift every later parameter."
                            .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "message".to_string(),
                        type_hint: "string".to_string(),
                        description: "Notice text to send. Must not contain CR or LF, and is \
                                      truncated at the RFC 1459 512-byte line limit."
                            .to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_notice",
                    "target": "#rust",
                    "message": "Bot notification"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_raw".to_string(),
                description: "Send one raw IRC command, for a verb the other actions do not \
                              cover. Exactly one command: the CRLF is added for you and the \
                              text must not contain CR or LF."
                    .to_string(),
                parameters: vec![Parameter {
                    name: "command".to_string(),
                    type_hint: "string".to_string(),
                    description: "One raw IRC command without its line ending, e.g. \
                                  \"MODE #rust +m\". Must not contain CR or LF - use one \
                                  action per command."
                        .to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_raw",
                    "command": "MODE #rust +m"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more messages before responding".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "IRC"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        // The two statics, not fresh copies. This used to build a second, parameterless pair
        // with the same ids, so everything reading `get_event_types()` - the model's docs, the
        // dashboard's routing editor - was told these events carry no fields, while the events
        // the read loop actually raises carry five. Two declarations of one event drift; there
        // is only one now.
        vec![
            IRC_CLIENT_CONNECTED_EVENT.clone(),
            IRC_CLIENT_MESSAGE_RECEIVED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>IRC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["irc", "irc client", "chat", "connect to irc"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "Hand-rolled line-based IRC over plain TCP - no TLS, no SASL, no CTCP. The \
                 `irc` crate is a declared dependency of this feature and is used by nothing; \
                 this file used to claim otherwise. Registration is NICK + USER, and the \
                 connected event fires on numeric 001.",
            )
            .llm_control("Join/part channels, send messages and notices, change nick, quit")
            .e2e_testing(
                "tests/client/irc/e2e_test.rs drives this client against NetGet's own IRC \
                 *server* with both sides mocked, so it proves the two halves agree and \
                 nothing about a real ircd. No test has ever run against ngircd, inspircd or \
                 any other independent server, which is why this is Experimental rather than \
                 Beta.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "IRC client for connecting to IRC servers and chat channels"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to IRC at irc.libera.chat:6667 with nick testbot, join #test and say hello"
    }
    fn group_name(&self) -> &'static str {
        "Messaging"
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "nickname".to_string(),
                type_hint: "string".to_string(),
                description: "IRC nickname (default: netget_user)".to_string(),
                required: false,
                example: json!("mybot"),
                default: None,
            },
            ParameterDefinition {
                name: "username".to_string(),
                type_hint: "string".to_string(),
                description: "IRC username (default: netget)".to_string(),
                required: false,
                example: json!("botuser"),
                default: None,
            },
            ParameterDefinition {
                name: "realname".to_string(),
                type_hint: "string".to_string(),
                description: "IRC real name (default: NetGet IRC Client)".to_string(),
                required: false,
                example: json!("My IRC Bot"),
                default: None,
            },
        ]
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls IRC chat
            json!({
                "type": "open_client",
                "remote_addr": "irc.libera.chat:6667",
                "base_stack": "irc",
                "instruction": "Join #rust channel and say hello, respond to any messages mentioning 'help'"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "irc.libera.chat:6667",
                "base_stack": "irc",
                "event_handlers": [{
                    "event_pattern": "irc_message_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<irc_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed IRC join on connect
            json!({
                "type": "open_client",
                "remote_addr": "irc.libera.chat:6667",
                "base_stack": "irc",
                "event_handlers": [
                    {
                        "event_pattern": "irc_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "join_channel",
                                "channel": "#test"
                            }]
                        }
                    },
                    {
                        "event_pattern": "irc_message_received",
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
/// Every wire verb validates its fields here rather than at the point of writing, because
/// this is the one gate both callers pass through: `handle_llm_call` and the injected-command
/// loop each run `execute_action` before `apply_action`. Validating here means a refusal
/// arrives as a `Rejected` outcome the dashboard can show, instead of as a channel error that
/// reads like the plumbing broke - and it means the model's own answer is refused before any
/// byte of it reaches the socket.
impl Client for IrcClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::irc::IrcClient;
            IrcClient::connect_with_llm_actions(
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
            "join_channel" => {
                let channel = action
                    .get("channel")
                    .and_then(|v| v.as_str())
                    .context("Missing 'channel' field")?;
                reject_not_a_word("channel", channel)?;

                Ok(ClientActionResult::Custom {
                    name: "join_channel".to_string(),
                    data: json!({ "channel": channel }),
                })
            }
            "part_channel" => {
                let channel = action
                    .get("channel")
                    .and_then(|v| v.as_str())
                    .context("Missing 'channel' field")?;
                reject_not_a_word("channel", channel)?;
                let message = action.get("message").and_then(|v| v.as_str());
                if let Some(message) = message {
                    reject_line_breaks("message", message)?;
                }

                Ok(ClientActionResult::Custom {
                    name: "part_channel".to_string(),
                    data: json!({ "channel": channel, "message": message }),
                })
            }
            "change_nick" => {
                let new_nick = action
                    .get("new_nick")
                    .and_then(|v| v.as_str())
                    .context("Missing 'new_nick' field")?;
                reject_not_a_word("new_nick", new_nick)?;

                Ok(ClientActionResult::Custom {
                    name: "change_nick".to_string(),
                    data: json!({ "new_nick": new_nick }),
                })
            }
            "send_privmsg" => {
                let target = action
                    .get("target")
                    .and_then(|v| v.as_str())
                    .context("Missing 'target' field")?;
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .context("Missing 'message' field")?;
                reject_not_a_word("target", target)?;
                reject_line_breaks("message", message)?;

                Ok(ClientActionResult::Custom {
                    name: "send_privmsg".to_string(),
                    data: json!({ "target": target, "message": message }),
                })
            }
            "send_notice" => {
                let target = action
                    .get("target")
                    .and_then(|v| v.as_str())
                    .context("Missing 'target' field")?;
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .context("Missing 'message' field")?;
                reject_not_a_word("target", target)?;
                reject_line_breaks("message", message)?;

                Ok(ClientActionResult::Custom {
                    name: "send_notice".to_string(),
                    data: json!({ "target": target, "message": message }),
                })
            }
            "send_raw" => {
                let command = action
                    .get("command")
                    .and_then(|v| v.as_str())
                    .context("Missing 'command' field")?;
                // Raw means "a verb this vocabulary does not name", not "several commands":
                // the CRLF is added when the line is written, so one already in the text is an
                // extra command.
                let command = command.trim_end_matches('\n').trim_end_matches('\r');
                reject_line_breaks("command", command)?;

                Ok(ClientActionResult::Custom {
                    name: "send_raw".to_string(),
                    data: json!({ "command": command }),
                })
            }
            "disconnect" => {
                let quit_message = action.get("quit_message").and_then(|v| v.as_str());
                if let Some(quit_message) = quit_message {
                    reject_line_breaks("quit_message", quit_message)?;
                }
                Ok(ClientActionResult::Custom {
                    name: "disconnect".to_string(),
                    data: json!({ "quit_message": quit_message }),
                })
            }
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown IRC client action: {}",
                action_type
            )),
        }
    }
}

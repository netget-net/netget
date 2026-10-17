//! SSH Agent client protocol actions

use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::{
    protocol_trait::Protocol, ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::LazyLock;

// Event type constants
pub static SSH_AGENT_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssh_agent_client_connected",
        "SSH Agent client connected to agent socket",
        json!({"type": "request_identities"}),
    )
    .with_parameter(Parameter {
        name: "socket_path".to_string(),
        type_hint: "string".to_string(),
        description: "Path to agent socket".to_string(),
        required: true,
    })
});

pub static SSH_AGENT_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ssh_agent_client_response_received",
        "SSH Agent client received response from agent",
        json!({"type": "sign_request", "public_key_blob_hex": "...", "data_hex": "...", "flags": 0})
    )
    .with_parameters(vec![
        Parameter {
            name: "response_type".to_string(),
            type_hint: "string".to_string(),
            description: "Type of response (identities, signature, success, failure)".to_string(),
            required: true,
        },
        Parameter {
            name: "response_data".to_string(),
            type_hint: "object".to_string(),
            description: "Response data".to_string(),
            required: true,
        },
    ])
});

/// SSH Agent client protocol implementation
pub struct SshAgentClientProtocol;

impl SshAgentClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SshAgentClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "socket_path".to_string(),
            type_hint: "string".to_string(),
            description: "Path to the SSH Agent Unix socket. Defaults to ./netget-ssh-agent.sock, \
                 which is NetGet's own agent server. It deliberately does NOT default to \
                 $SSH_AUTH_SOCK: that would attach this client to the operator's real \
                 running agent and let it sign with their real private keys. Give the path \
                 explicitly if that is genuinely what you want."
                .to_string(),
            required: false,
            example: json!("./netget-ssh-agent.sock"),
            default: None,
        }]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // `modify_instruction` used to be advertised here. Nothing could run it: this
        // protocol's `execute_action` rejects the name, `handle_custom_action` has no branch
        // for it, and no generic client-side instruction plumbing exists — clients read
        // `instruction` once at connect and never re-read it. So the model was shown a tool
        // that always came back "Unknown action type: modify_instruction", burning a retry.
        // The server's SSH-Agent protocol does implement it; the client never did.
        vec![ActionDefinition {
            name: "disconnect".to_string(),
            description: "Disconnect from SSH Agent".to_string(),
            parameters: vec![],
            example: json!({"type": "disconnect"}),
            log_template: None,
        }]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "request_identities".to_string(),
                description: "Request list of identities from agent".to_string(),
                parameters: vec![],
                example: json!({"type": "request_identities"}),
                log_template: None,
            },
            ActionDefinition {
                name: "sign_request".to_string(),
                description: "Request to sign data with a key".to_string(),
                parameters: vec![
                    Parameter {
                        name: "public_key_blob_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Hex-encoded public key blob to sign with".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "data_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Hex-encoded data to sign".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "flags".to_string(),
                        type_hint: "integer".to_string(),
                        description: "Signature flags".to_string(),
                        required: false,
                    },
                ],
                example: json!({"type": "sign_request", "public_key_blob_hex": "...", "data_hex": "...", "flags": 0}),
                log_template: None,
            },
            ActionDefinition {
                name: "add_identity".to_string(),
                description: "Add an identity to the agent".to_string(),
                parameters: vec![
                    Parameter {
                        name: "key_type".to_string(),
                        type_hint: "string".to_string(),
                        description: "SSH key type".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "public_key_blob_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Hex-encoded public key blob".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "private_key_blob_hex".to_string(),
                        type_hint: "string".to_string(),
                        description: "Hex-encoded private key blob".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "comment".to_string(),
                        type_hint: "string".to_string(),
                        description: "Key comment".to_string(),
                        required: false,
                    },
                ],
                example: json!({"type": "add_identity", "key_type": "ssh-ed25519", "public_key_blob_hex": "...", "private_key_blob_hex": "...", "comment": "my-key"}),
                log_template: None,
            },
            ActionDefinition {
                name: "remove_identity".to_string(),
                description: "Remove an identity from the agent".to_string(),
                parameters: vec![Parameter {
                    name: "public_key_blob_hex".to_string(),
                    type_hint: "string".to_string(),
                    description: "Hex-encoded public key blob to remove".to_string(),
                    required: true,
                }],
                example: json!({"type": "remove_identity", "public_key_blob_hex": "..."}),
                log_template: None,
            },
            ActionDefinition {
                name: "remove_all_identities".to_string(),
                description: "Remove all identities from the agent".to_string(),
                parameters: vec![],
                example: json!({"type": "remove_all_identities"}),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more data".to_string(),
                parameters: vec![],
                example: json!({"type": "wait_for_more"}),
                log_template: None,
            },
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "SSH Agent"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            (*SSH_AGENT_CLIENT_CONNECTED_EVENT).clone(),
            (*SSH_AGENT_CLIENT_RESPONSE_RECEIVED_EVENT).clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "UNIX Socket > SSH Agent"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["ssh-agent", "agent", "key-agent", "ssh keys"]
    }

    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("SSH Agent client using custom protocol implementation")
            .llm_control("Full control over agent operations and key management")
            .e2e_testing(
                "tests/client/ssh_agent/command_channel_test.rs runs; the e2e suite in \
                 tests/client/ssh_agent/CLAUDE.md is aspirational and no third-party agent \
                 drives this client in an automated test.",
            )
            .notes(
                "Speaks to any agent on a Unix socket. Defaults to ./netget-ssh-agent.sock, \
                 NOT $SSH_AUTH_SOCK: pointed at a real agent this client can enumerate the \
                 operator's identities and have them sign model-chosen bytes, so reaching a \
                 live agent has to be asked for by path.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "SSH Agent client for connecting to and managing SSH keys via agents"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to the SSH Agent on ./netget-ssh-agent.sock; list all identities; use the first key to sign 'Hello World'"
    }

    fn group_name(&self) -> &'static str {
        "Security"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls SSH agent operations
            json!({
                "type": "open_client",
                "remote_addr": "./netget-ssh-agent.sock",
                "base_stack": "ssh-agent",
                "instruction": "List all identities and sign 'Hello World' with the first key"
            }),
            // Script mode: Code-based agent operations
            json!({
                "type": "open_client",
                "remote_addr": "./netget-ssh-agent.sock",
                "base_stack": "ssh-agent",
                "event_handlers": [{
                    "event_pattern": "ssh_agent_client_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<ssh_agent_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed identity request
            json!({
                "type": "open_client",
                "remote_addr": "./netget-ssh-agent.sock",
                "base_stack": "ssh-agent",
                "event_handlers": [
                    {
                        "event_pattern": "ssh_agent_client_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "request_identities"
                            }]
                        }
                    },
                    {
                        "event_pattern": "ssh_agent_client_response_received",
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
impl Client for SshAgentClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(async move {
            // `socket_path` was declared here and read by nothing: `connect` used
            // `remote_addr` alone, so a caller that put the path in the parameter it was
            // told to use had it silently dropped and connected somewhere else entirely.
            // An advertised knob that does nothing when turned is worse than no knob.
            let socket_path = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("socket_path"))
                .transpose()?
                .flatten()
                .filter(|s| !s.is_empty());

            let target = match socket_path {
                Some(path) => path,
                None => ctx.remote_addr,
            };

            crate::client::ssh_agent::SshAgentClient::connect_with_llm_actions(
                target,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        let action_type = action["type"]
            .as_str()
            .context("Missing 'type' field in action")?;

        match action_type {
            "request_identities" => Ok(ClientActionResult::Custom {
                name: "request_identities".to_string(),
                data: json!({}),
            }),
            "sign_request" => {
                let public_key_blob_hex = action["public_key_blob_hex"]
                    .as_str()
                    .context("Missing 'public_key_blob_hex' field")?;
                let data_hex = action["data_hex"]
                    .as_str()
                    .context("Missing 'data_hex' field")?;
                let flags = match action.get("flags") {
                    None => 0,
                    Some(value) => u32::try_from(
                        value
                            .as_u64()
                            .context("flags must be an unsigned integer")?,
                    )
                    .context("flags exceed u32")?,
                };

                Ok(ClientActionResult::Custom {
                    name: "sign_request".to_string(),
                    data: json!({
                        "public_key_blob_hex": public_key_blob_hex,
                        "data_hex": data_hex,
                        "flags": flags,
                    }),
                })
            }
            "add_identity" => {
                let key_type = action["key_type"]
                    .as_str()
                    .context("Missing 'key_type' field")?;
                let public_key_blob_hex = action["public_key_blob_hex"]
                    .as_str()
                    .context("Missing 'public_key_blob_hex' field")?;
                let private_key_blob_hex = action["private_key_blob_hex"]
                    .as_str()
                    .context("Missing 'private_key_blob_hex' field")?;
                let comment = action["comment"].as_str().unwrap_or("");

                Ok(ClientActionResult::Custom {
                    name: "add_identity".to_string(),
                    data: json!({
                        "key_type": key_type,
                        "public_key_blob_hex": public_key_blob_hex,
                        "private_key_blob_hex": private_key_blob_hex,
                        "comment": comment,
                    }),
                })
            }
            "remove_identity" => {
                let public_key_blob_hex = action["public_key_blob_hex"]
                    .as_str()
                    .context("Missing 'public_key_blob_hex' field")?;

                Ok(ClientActionResult::Custom {
                    name: "remove_identity".to_string(),
                    data: json!({ "public_key_blob_hex": public_key_blob_hex }),
                })
            }
            "remove_all_identities" => Ok(ClientActionResult::Custom {
                name: "remove_all_identities".to_string(),
                data: json!({}),
            }),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => anyhow::bail!("Unknown action type: {}", action_type),
        }
    }
}

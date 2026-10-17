//! STUN client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// STUN client connected event
pub static STUN_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stun_connected",
        "STUN client initialized and ready to query external address",
        json!({
            "type": "send_binding_request"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "local_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Local UDP socket address".to_string(),
            required: true,
        },
        Parameter {
            name: "stun_server".to_string(),
            type_hint: "string".to_string(),
            description: "STUN server address".to_string(),
            required: true,
        },
    ])
});

/// STUN binding response event
pub static STUN_CLIENT_BINDING_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "stun_binding_response",
        "STUN binding response received with external address information",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "external_ip".to_string(),
            type_hint: "string".to_string(),
            description: "External IP address discovered via STUN".to_string(),
            required: true,
        },
        Parameter {
            name: "external_port".to_string(),
            type_hint: "number".to_string(),
            description: "External port number discovered via STUN".to_string(),
            required: true,
        },
        Parameter {
            name: "external_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Full external address (IP:port)".to_string(),
            required: true,
        },
        Parameter {
            name: "local_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Local UDP socket address".to_string(),
            required: true,
        },
        Parameter {
            name: "stun_server".to_string(),
            type_hint: "string".to_string(),
            description: "STUN server that provided the response".to_string(),
            required: true,
        },
    ])
});

/// STUN client protocol action handler
pub struct StunClientProtocol;

impl StunClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl crate::llm::actions::protocol_trait::Protocol for StunClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_binding_request".to_string(),
                description: "Send a STUN binding request to discover external IP/port".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "send_binding_request"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the STUN server".to_string(),
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
                name: "send_binding_request".to_string(),
                description: "Send another STUN binding request to refresh external address"
                    .to_string(),
                parameters: vec![],
                example: json!({
                    "type": "send_binding_request"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait before sending another binding request".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "STUN"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "stun_connected",
                "Triggered when STUN client is initialized",
                json!({"type": "placeholder", "event_id": "stun_connected"}),
            ),
            EventType::new(
                "stun_binding_response",
                "Triggered when STUN client receives binding response",
                json!({"type": "placeholder", "event_id": "stun_binding_response"}),
            ),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>STUN"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "stun",
            "stun client",
            "nat traversal",
            "external ip",
            "public ip",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("stunclient library for NAT traversal discovery")
            .llm_control("Control when to send binding requests and interpret external address")
            .e2e_testing("Google STUN servers (stun.l.google.com:19302)")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "STUN client for discovering external IP address and port behind NAT"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to stun.l.google.com:19302 and discover my external IP address"
    }

    fn group_name(&self) -> &'static str {
        "Network Infrastructure"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls STUN client interactions
            json!({
                "type": "open_client",
                "remote_addr": "stun.l.google.com:19302",
                "base_stack": "stun",
                "instruction": "Discover external IP address via STUN binding request"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "stun.l.google.com:19302",
                "base_stack": "stun",
                "event_handlers": [{
                    "event_pattern": "stun_binding_response",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<stun_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_client",
                "remote_addr": "stun.l.google.com:19302",
                "base_stack": "stun",
                "event_handlers": [
                    {
                        "event_pattern": "stun_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_binding_request"
                            }]
                        }
                    },
                    {
                        "event_pattern": "stun_binding_response",
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

impl Client for StunClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::stun::StunClient;
            StunClient::connect_with_llm_actions(
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
            "send_binding_request" => Ok(ClientActionResult::Custom {
                name: "send_binding_request".to_string(),
                data: json!({}),
            }),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown STUN client action: {}",
                action_type
            )),
        }
    }
}

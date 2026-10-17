//! RIP client protocol actions implementation

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

/// One place each action is defined, so the async list, the sync list and the event
/// vocabularies below cannot drift apart.
fn send_rip_request_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_rip_request".to_string(),
        description: "Send a RIP Request asking the router for its whole routing table".to_string(),
        parameters: vec![Parameter {
            name: "version".to_string(),
            type_hint: "number".to_string(),
            description: "RIP version: 1 (RFC 1058) or 2 (RFC 2453). No other value is accepted."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_rip_request",
            "version": 2
        }),
        log_template: None,
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description: "Stop listening and release the socket. RIP is UDP and has no wire close, \
                      so this ends the session locally."
            .to_string(),
        parameters: vec![],
        example: json!({
            "type": "disconnect"
        }),
        log_template: None,
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "The routing table was split across several datagrams; wait for the rest \
                      before deciding."
            .to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: None,
    }
}

/// RIP client connected event
pub static RIP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rip_connected",
        "RIP client connected to router",
        // The example is what the model copies, so it has to be an action the executor
        // accepts. It used to be `{"type": "placeholder"}`, which `execute_action` rejects.
        json!({"type": "send_rip_request", "version": 2}),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "RIP router address".to_string(),
        required: true,
    }])
    .with_actions(vec![send_rip_request_action(), disconnect_action()])
});

/// RIP client response received event
pub static RIP_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rip_response_received",
        "RIP response received from router",
        json!({"type": "disconnect"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "version".to_string(),
            type_hint: "number".to_string(),
            description: "RIP version (1 or 2)".to_string(),
            required: true,
        },
        Parameter {
            name: "command".to_string(),
            type_hint: "string".to_string(),
            description: "RIP command (request or response)".to_string(),
            required: true,
        },
        Parameter {
            name: "route_count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of routes in response".to_string(),
            required: true,
        },
        Parameter {
            name: "routes".to_string(),
            type_hint: "array".to_string(),
            description:
                "Array of route entries with ip_address, subnet_mask, next_hop, and metric"
                    .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        send_rip_request_action(),
        wait_for_more_action(),
        disconnect_action(),
    ])
});

/// RIP client protocol action handler
pub struct RipClientProtocol;

impl Default for RipClientProtocol {
    fn default() -> Self {
        Self
    }
}

impl RipClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for RipClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![send_rip_request_action(), disconnect_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![send_rip_request_action(), wait_for_more_action()]
    }
    fn protocol_name(&self) -> &'static str {
        "RIP"
    }
    // The events the client actually raises, not re-declared copies of them. These used to be
    // freshly-built `EventType`s with the same two ids but no parameters, so everything reading
    // the declared surface — the model's event documentation, the registry audits — saw a
    // stripped version of what `mod.rs` really emits.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            RIP_CLIENT_CONNECTED_EVENT.clone(),
            RIP_CLIENT_RESPONSE_RECEIVED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>RIP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["rip", "rip client", "routing information protocol"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("UDP socket with RIPv1/v2 packet parsing")
            .llm_control("Query routing tables, analyze routes")
            .e2e_testing("Mock RIP router or real router in test network")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "RIP client for querying routing tables from RIP routers"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to RIP router at 192.168.1.1:520 and query routing table"
    }
    fn group_name(&self) -> &'static str {
        "Routing"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls RIP routing table queries
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:520",
                "base_stack": "rip",
                "instruction": "Query routing table using RIPv2 and analyze routes"
            }),
            // Script mode: Code-based RIP response handling
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:520",
                "base_stack": "rip",
                "event_handlers": [{
                    "event_pattern": "rip_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<rip_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed RIP routing table request
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:520",
                "base_stack": "rip",
                "event_handlers": [
                    {
                        "event_pattern": "rip_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_rip_request",
                                "version": 2
                            }]
                        }
                    },
                    {
                        "event_pattern": "rip_response_received",
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
impl Client for RipClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::rip::RipClient;
            RipClient::connect_with_llm_actions(
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
            "send_rip_request" => {
                let version = action
                    .get("version")
                    .and_then(|v| v.as_u64())
                    .context("Missing 'version' field")?;
                // RFC 1058 defines version 1 and RFC 2453 version 2; there is no third. Refuse
                // anything else here rather than in the transport, so the operator and the model
                // both get a `Rejected` naming the problem instead of a silently-downgraded
                // datagram.
                if version != 1 && version != 2 {
                    return Err(anyhow::anyhow!(
                        "Invalid RIP 'version' {}: must be 1 (RFC 1058) or 2 (RFC 2453)",
                        version
                    ));
                }

                Ok(ClientActionResult::Custom {
                    name: "send_rip_request".to_string(),
                    data: json!({
                        "version": version
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown RIP client action: {}",
                action_type
            )),
        }
    }
}

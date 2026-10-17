//! NTP client protocol actions implementation

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

/// NTP client connected event
pub static NTP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ntp_connected",
        "NTP client ready to query time servers",
        json!({"type": "placeholder", "event_id": "ntp_connected"}),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "NTP server address".to_string(),
        required: true,
    }])
});

/// NTP client response received event
pub static NTP_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ntp_response_received",
        "NTP time response received from server",
        json!({"type": "analyze_response"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "origin_timestamp".to_string(),
            type_hint: "number".to_string(),
            description: "Origin timestamp (Unix epoch)".to_string(),
            required: true,
        },
        Parameter {
            name: "receive_timestamp".to_string(),
            type_hint: "number".to_string(),
            description: "Server receive timestamp (Unix epoch)".to_string(),
            required: true,
        },
        Parameter {
            name: "transmit_timestamp".to_string(),
            type_hint: "number".to_string(),
            description: "Server transmit timestamp (Unix epoch)".to_string(),
            required: true,
        },
        Parameter {
            name: "stratum".to_string(),
            type_hint: "number".to_string(),
            description: "Server stratum level (0-15)".to_string(),
            required: true,
        },
        Parameter {
            name: "precision".to_string(),
            type_hint: "number".to_string(),
            description: "Server precision (log2 seconds)".to_string(),
            required: true,
        },
    ])
});

/// NTP client protocol action handler
pub struct NtpClientProtocol;

impl NtpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NtpClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for NtpClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "query_time".to_string(),
                description: "Query NTP server for current time".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "query_time"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Close NTP client".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![ActionDefinition {
            name: "analyze_response".to_string(),
            description: "Analyze NTP response (no action needed, just for LLM understanding)"
                .to_string(),
            parameters: vec![],
            example: json!({
                "type": "analyze_response"
            }),
            log_template: None,
        }]
    }
    fn protocol_name(&self) -> &'static str {
        "NTP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "ntp_connected",
                "Triggered when NTP client is ready",
                json!({"type": "placeholder", "event_id": "ntp_connected"}),
            ),
            EventType::new(
                "ntp_response_received",
                "Triggered when NTP response is received",
                json!({"type": "placeholder", "event_id": "ntp_response_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>NTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["ntp", "ntp client", "time sync", "network time"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("UDP-based NTP client with manual packet construction")
            .llm_control("Query time servers and interpret timestamps, stratum, precision")
            .e2e_testing("Public NTP servers (pool.ntp.org)")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "NTP client for querying network time servers"
    }
    fn example_prompt(&self) -> &'static str {
        "Query time.google.com:123 and show the time offset"
    }
    fn group_name(&self) -> &'static str {
        "Network Infrastructure"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls NTP queries
            json!({
                "type": "open_client",
                "remote_addr": "time.google.com:123",
                "base_stack": "ntp",
                "instruction": "Query the time server and report the current time offset and stratum level"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "pool.ntp.org:123",
                "base_stack": "ntp",
                "event_handlers": [{
                    "event_pattern": "ntp_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<ntp_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed NTP query on connect
            json!({
                "type": "open_client",
                "remote_addr": "time.google.com:123",
                "base_stack": "ntp",
                "event_handlers": [
                    {
                        "event_pattern": "ntp_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "query_time"
                            }]
                        }
                    },
                    {
                        "event_pattern": "ntp_response_received",
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
impl Client for NtpClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::ntp::NtpClient;
            NtpClient::connect_with_llm_actions(
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
            "query_time" => Ok(ClientActionResult::Custom {
                name: "ntp_query".to_string(),
                data: json!({}),
            }),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "analyze_response" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown NTP client action: {}",
                action_type
            )),
        }
    }
}

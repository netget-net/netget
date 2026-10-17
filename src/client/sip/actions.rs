//! SIP client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::LazyLock;

pub struct SipClientProtocol;

impl SipClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SipClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            // User-triggered actions
            sip_register_action(),
            sip_invite_action(),
            sip_ack_action(),
            sip_bye_action(),
            sip_options_action(),
            sip_cancel_action(),
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            // Response actions
            disconnect_action(),
            wait_for_more_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            SIP_CLIENT_CONNECTED_EVENT.clone(),
            SIP_CLIENT_RESPONSE_RECEIVED_EVENT.clone(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "SIP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>SIP"
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![]
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["sip", "voip", "session initiation"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Manual SIP client - RFC 3261 compliant request generation")
            .llm_control("REGISTER, INVITE, BYE, OPTIONS, CANCEL methods")
            .e2e_testing("Self-testing against NetGet SIP server - < 10 LLM calls")
            .notes("VoIP signaling, no RTP media streams")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "SIP client for VoIP signaling"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to 192.168.1.100:5060 via SIP and register as alice@example.com"
    }
    fn group_name(&self) -> &'static str {
        "VoIP & Multimedia"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls SIP registration and call flow
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.100:5060",
                "base_stack": "sip",
                "instruction": "Register as alice@example.com and query server capabilities with OPTIONS"
            }),
            // Script mode: Code-based SIP message handling
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.100:5060",
                "base_stack": "sip",
                "event_handlers": [{
                    "event_pattern": "sip_client_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<sip_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed SIP registration flow
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.100:5060",
                "base_stack": "sip",
                "event_handlers": [
                    {
                        "event_pattern": "sip_client_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "sip_register",
                                "from": "sip:alice@example.com",
                                "to": "sip:alice@example.com",
                                "request_uri": "sip:example.com",
                                "contact": "sip:alice@192.0.2.1:5060",
                                "expires": 3600
                            }]
                        }
                    },
                    {
                        "event_pattern": "sip_client_response_received",
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
impl Client for SipClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(async move {
            crate::client::sip::SipClient::connect_with_llm_actions(
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
            "sip_register" => {
                let from = action["from"]
                    .as_str()
                    .context("Missing 'from' field")?
                    .to_string();
                let to = action["to"]
                    .as_str()
                    .context("Missing 'to' field")?
                    .to_string();
                let request_uri = action["request_uri"]
                    .as_str()
                    .context("Missing 'request_uri' field")?
                    .to_string();
                let contact = action["contact"]
                    .as_str()
                    .context("Missing 'contact' field")?
                    .to_string();
                let expires = action["expires"].as_u64().unwrap_or(3600);

                Ok(ClientActionResult::Custom {
                    name: "sip_register".to_string(),
                    data: json!({
                        "from": from,
                        "to": to,
                        "request_uri": request_uri,
                        "contact": contact,
                        "expires": expires,
                    }),
                })
            }
            "sip_invite" => {
                let from = action["from"]
                    .as_str()
                    .context("Missing 'from' field")?
                    .to_string();
                let to = action["to"]
                    .as_str()
                    .context("Missing 'to' field")?
                    .to_string();
                let request_uri = action["request_uri"]
                    .as_str()
                    .context("Missing 'request_uri' field")?
                    .to_string();
                let sdp = action["sdp"]
                    .as_str()
                    .context("Missing 'sdp' field")?
                    .to_string();
                let contact = action["contact"].as_str().unwrap_or("sip:user@127.0.0.1");

                Ok(ClientActionResult::Custom {
                    name: "sip_invite".to_string(),
                    data: json!({
                        "from": from,
                        "to": to,
                        "request_uri": request_uri,
                        "contact": contact,
                        "sdp": sdp,
                    }),
                })
            }
            "sip_bye" => {
                let from = action["from"]
                    .as_str()
                    .context("Missing 'from' field")?
                    .to_string();
                let to = action["to"]
                    .as_str()
                    .context("Missing 'to' field")?
                    .to_string();
                let request_uri = action["request_uri"]
                    .as_str()
                    .context("Missing 'request_uri' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "sip_bye".to_string(),
                    data: json!({
                        "from": from,
                        "to": to,
                        "request_uri": request_uri,
                    }),
                })
            }
            "sip_options" => {
                let from = action["from"]
                    .as_str()
                    .context("Missing 'from' field")?
                    .to_string();
                let to = action["to"]
                    .as_str()
                    .context("Missing 'to' field")?
                    .to_string();
                let request_uri = action["request_uri"]
                    .as_str()
                    .context("Missing 'request_uri' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "sip_options".to_string(),
                    data: json!({
                        "from": from,
                        "to": to,
                        "request_uri": request_uri,
                    }),
                })
            }
            "sip_ack" => {
                let from = action["from"]
                    .as_str()
                    .context("Missing 'from' field")?
                    .to_string();
                let to = action["to"]
                    .as_str()
                    .context("Missing 'to' field")?
                    .to_string();
                let request_uri = action["request_uri"]
                    .as_str()
                    .context("Missing 'request_uri' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "sip_ack".to_string(),
                    data: json!({
                        "from": from,
                        "to": to,
                        "request_uri": request_uri,
                    }),
                })
            }
            "sip_cancel" => {
                let from = action["from"]
                    .as_str()
                    .context("Missing 'from' field")?
                    .to_string();
                let to = action["to"]
                    .as_str()
                    .context("Missing 'to' field")?
                    .to_string();
                let request_uri = action["request_uri"]
                    .as_str()
                    .context("Missing 'request_uri' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "sip_cancel".to_string(),
                    data: json!({
                        "from": from,
                        "to": to,
                        "request_uri": request_uri,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown SIP client action: {}",
                action_type
            )),
        }
    }
}

// Event type constants
pub static SIP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sip_client_connected",
        "SIP client connected to server",
        json!({"type": "placeholder", "event_id": "sip_client_connected"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Remote SIP server address".to_string(),
            required: true,
        },
        Parameter {
            name: "local_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Local client address".to_string(),
            required: true,
        },
    ])
});

pub static SIP_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sip_client_response_received",
        "SIP response received from server",
        json!({
            "type": "disconnect"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "status_code".to_string(),
            type_hint: "number".to_string(),
            description: "SIP status code (200=OK, 403=Forbidden, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "reason_phrase".to_string(),
            type_hint: "string".to_string(),
            description: "Response reason phrase".to_string(),
            required: true,
        },
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "SIP method from CSeq (REGISTER, INVITE, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "call_id".to_string(),
            type_hint: "string".to_string(),
            description: "SIP Call-ID header".to_string(),
            required: true,
        },
        Parameter {
            name: "from".to_string(),
            type_hint: "string".to_string(),
            description: "SIP From header".to_string(),
            required: true,
        },
        Parameter {
            name: "to".to_string(),
            type_hint: "string".to_string(),
            description: "SIP To header".to_string(),
            required: true,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description: "Response body (SDP if present)".to_string(),
            required: false,
        },
    ])
});

// Action definitions
fn sip_register_action() -> ActionDefinition {
    ActionDefinition {
        name: "sip_register".to_string(),
        description: "Send SIP REGISTER request to register with server".to_string(),
        parameters: vec![
            Parameter {
                name: "from".to_string(),
                type_hint: "string".to_string(),
                description: "From SIP URI (e.g., sip:alice@example.com)".to_string(),
                required: true,
            },
            Parameter {
                name: "to".to_string(),
                type_hint: "string".to_string(),
                description: "To SIP URI (e.g., sip:alice@example.com)".to_string(),
                required: true,
            },
            Parameter {
                name: "request_uri".to_string(),
                type_hint: "string".to_string(),
                description: "Request URI (e.g., sip:example.com)".to_string(),
                required: true,
            },
            Parameter {
                name: "contact".to_string(),
                type_hint: "string".to_string(),
                description: "Contact URI with IP:port (e.g., sip:alice@192.0.2.1:5060)"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "expires".to_string(),
                type_hint: "number".to_string(),
                description: "Registration expiration in seconds (default 3600)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "sip_register",
            "from": "sip:alice@example.com",
            "to": "sip:alice@example.com",
            "request_uri": "sip:example.com",
            "contact": "sip:alice@192.0.2.1:5060",
            "expires": 3600
        }),
        log_template: None,
    }
}

fn sip_invite_action() -> ActionDefinition {
    ActionDefinition {
        name: "sip_invite".to_string(),
        description: "Send SIP INVITE request to initiate a call".to_string(),
        parameters: vec![
            Parameter {
                name: "from".to_string(),
                type_hint: "string".to_string(),
                description: "Caller SIP URI".to_string(),
                required: true,
            },
            Parameter {
                name: "to".to_string(),
                type_hint: "string".to_string(),
                description: "Callee SIP URI".to_string(),
                required: true,
            },
            Parameter {
                name: "request_uri".to_string(),
                type_hint: "string".to_string(),
                description: "Request URI (usually same as 'to')".to_string(),
                required: true,
            },
            Parameter {
                name: "contact".to_string(),
                type_hint: "string".to_string(),
                description: "Contact URI with IP:port".to_string(),
                required: false,
            },
            Parameter {
                name: "sdp".to_string(),
                type_hint: "string".to_string(),
                description: "Session Description Protocol body (media offer)".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "sip_invite",
            "from": "sip:alice@example.com",
            "to": "sip:bob@example.com",
            "request_uri": "sip:bob@example.com",
            "sdp": "v=0\no=alice 2890844526 2890844526 IN IP4 192.0.2.1\ns=Call\nc=IN IP4 192.0.2.1\nt=0 0\nm=audio 49170 RTP/AVP 0\na=rtpmap:0 PCMU/8000\n"
        }),
        log_template: None,
    }
}

fn sip_ack_action() -> ActionDefinition {
    ActionDefinition {
        name: "sip_ack".to_string(),
        description: "Send SIP ACK request to acknowledge INVITE 200 OK (usually automatic)"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "from".to_string(),
                type_hint: "string".to_string(),
                description: "Caller SIP URI".to_string(),
                required: true,
            },
            Parameter {
                name: "to".to_string(),
                type_hint: "string".to_string(),
                description: "Callee SIP URI".to_string(),
                required: true,
            },
            Parameter {
                name: "request_uri".to_string(),
                type_hint: "string".to_string(),
                description: "Request URI (usually same as 'to')".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "sip_ack",
            "from": "sip:alice@example.com",
            "to": "sip:bob@example.com",
            "request_uri": "sip:bob@example.com"
        }),
        log_template: None,
    }
}

fn sip_bye_action() -> ActionDefinition {
    ActionDefinition {
        name: "sip_bye".to_string(),
        description: "Send SIP BYE request to terminate a call".to_string(),
        parameters: vec![
            Parameter {
                name: "from".to_string(),
                type_hint: "string".to_string(),
                description: "Caller SIP URI".to_string(),
                required: true,
            },
            Parameter {
                name: "to".to_string(),
                type_hint: "string".to_string(),
                description: "Callee SIP URI".to_string(),
                required: true,
            },
            Parameter {
                name: "request_uri".to_string(),
                type_hint: "string".to_string(),
                description: "Request URI (usually same as 'to')".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "sip_bye",
            "from": "sip:alice@example.com",
            "to": "sip:bob@example.com",
            "request_uri": "sip:bob@example.com"
        }),
        log_template: None,
    }
}

fn sip_options_action() -> ActionDefinition {
    ActionDefinition {
        name: "sip_options".to_string(),
        description: "Send SIP OPTIONS request to query server capabilities".to_string(),
        parameters: vec![
            Parameter {
                name: "from".to_string(),
                type_hint: "string".to_string(),
                description: "Caller SIP URI".to_string(),
                required: true,
            },
            Parameter {
                name: "to".to_string(),
                type_hint: "string".to_string(),
                description: "Target SIP URI".to_string(),
                required: true,
            },
            Parameter {
                name: "request_uri".to_string(),
                type_hint: "string".to_string(),
                description: "Request URI (usually same as 'to')".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "sip_options",
            "from": "sip:alice@example.com",
            "to": "sip:bob@example.com",
            "request_uri": "sip:bob@example.com"
        }),
        log_template: None,
    }
}

fn sip_cancel_action() -> ActionDefinition {
    ActionDefinition {
        name: "sip_cancel".to_string(),
        description: "Send SIP CANCEL request to cancel a pending INVITE".to_string(),
        parameters: vec![
            Parameter {
                name: "from".to_string(),
                type_hint: "string".to_string(),
                description: "Caller SIP URI".to_string(),
                required: true,
            },
            Parameter {
                name: "to".to_string(),
                type_hint: "string".to_string(),
                description: "Callee SIP URI".to_string(),
                required: true,
            },
            Parameter {
                name: "request_uri".to_string(),
                type_hint: "string".to_string(),
                description: "Request URI (usually same as 'to')".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "sip_cancel",
            "from": "sip:alice@example.com",
            "to": "sip:bob@example.com",
            "request_uri": "sip:bob@example.com"
        }),
        log_template: None,
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description: "Close SIP client connection".to_string(),
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
        description: "Wait for more SIP responses before taking action".to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: None,
    }
}

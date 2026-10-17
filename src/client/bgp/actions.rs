//! BGP client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// BGP client connected event
///
/// Fires when the session reaches Established, i.e. after the peer's OPEN *and* its KEEPALIVE
/// have both been seen. It used to fire on the OPEN alone, which announced a session the peer
/// had not yet confirmed.
pub static BGP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bgp_connected",
        "BGP session with the peer reached Established (OPEN and KEEPALIVE both exchanged). \
         This client announces no routes; reply with wait_for_more to keep monitoring, or \
         send_notification to tear the session down.",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Remote BGP peer address".to_string(),
            required: true,
        },
        Parameter {
            name: "peer_as".to_string(),
            type_hint: "number".to_string(),
            description: "Peer AS number. Taken from the peer's four-octet-AS capability when \
                          it advertised one, so values above 65535 are reported truthfully."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "peer_router_id".to_string(),
            type_hint: "string".to_string(),
            description: "Peer BGP router ID".to_string(),
            required: true,
        },
        Parameter {
            name: "hold_time".to_string(),
            type_hint: "number".to_string(),
            description: "Negotiated hold time in seconds (the smaller of the two proposals; \
                          0 means both timers are disabled)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "peer_supports_four_octet_as".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether the peer advertised RFC 6793 four-octet AS support".to_string(),
            required: true,
        },
    ])
    .with_actions(bgp_client_response_actions())
});

/// BGP UPDATE message received event
///
/// The body is decoded field by field. It used to be delivered as `update_data_hex`, a raw hex
/// blob no model can act on and which the root CLAUDE.md forbids in event data.
pub static BGP_CLIENT_UPDATE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bgp_update_received",
        "BGP UPDATE received from the peer, decoded into withdrawn_routes, nlri, origin, \
         next_hop, as_path and the full path_attributes list. This client announces no routes, \
         so there is no way to answer an UPDATE with one — but the session verbs do reach the \
         wire: reply with wait_for_more to keep monitoring, or send_notification / disconnect \
         to tear the peering down over what the peer just advertised.",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "nlri".to_string(),
            type_hint: "array".to_string(),
            description: "Announced prefixes in CIDR form, e.g. [\"10.0.0.0/24\"]".to_string(),
            required: true,
        },
        Parameter {
            name: "withdrawn_routes".to_string(),
            type_hint: "array".to_string(),
            description: "Withdrawn prefixes in CIDR form".to_string(),
            required: true,
        },
        Parameter {
            name: "next_hop".to_string(),
            type_hint: "string".to_string(),
            description: "NEXT_HOP attribute, or null when the UPDATE only withdraws".to_string(),
            required: false,
        },
        Parameter {
            name: "as_path".to_string(),
            type_hint: "array".to_string(),
            description: "AS_PATH as a list of AS numbers".to_string(),
            required: false,
        },
        Parameter {
            name: "origin".to_string(),
            type_hint: "string".to_string(),
            description: "ORIGIN attribute: IGP, EGP or Incomplete".to_string(),
            required: false,
        },
        Parameter {
            name: "path_attributes".to_string(),
            type_hint: "array".to_string(),
            description: "Every path attribute, each with its type_name and flags".to_string(),
            required: true,
        },
        Parameter {
            name: "end_of_rib".to_string(),
            type_hint: "boolean".to_string(),
            description: "True when this is an End-of-RIB marker (RFC 4724)".to_string(),
            required: true,
        },
        Parameter {
            name: "peer_as".to_string(),
            type_hint: "number".to_string(),
            description: "AS number of the peer that sent this UPDATE".to_string(),
            required: false,
        },
    ])
    .with_actions(bgp_client_response_actions())
});

/// BGP NOTIFICATION message received event
pub static BGP_CLIENT_NOTIFICATION_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bgp_notification_received",
        "BGP NOTIFICATION received from the peer. RFC 4271 forbids answering one, so the \
         session closes regardless of what is returned and nothing is written to the socket.",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "error_code".to_string(),
            type_hint: "number".to_string(),
            description: "BGP error code (RFC 4271 section 6)".to_string(),
            required: true,
        },
        Parameter {
            name: "error_name".to_string(),
            type_hint: "string".to_string(),
            description: "Human-readable error name, e.g. \"OPEN Message Error\"".to_string(),
            required: true,
        },
        Parameter {
            name: "error_subcode".to_string(),
            type_hint: "number".to_string(),
            description: "BGP error subcode".to_string(),
            required: true,
        },
        Parameter {
            name: "error_subcode_name".to_string(),
            type_hint: "string".to_string(),
            description: "Human-readable subcode name, e.g. \"Bad Peer AS\"".to_string(),
            required: true,
        },
        Parameter {
            name: "peer_as".to_string(),
            type_hint: "number".to_string(),
            description: "AS number of the peer, if its OPEN was seen".to_string(),
            required: false,
        },
    ])
    .with_no_actions()
});

/// Everything a BGP client handler can answer a session event with.
///
/// One list, used for both the async and the sync set. A client cannot narrow its vocabulary
/// per event even if it wanted to: `client_llm_action_set`
/// (`src/llm/actions/client_trait.rs`) offers the model `get_async_actions` ∪ `get_sync_actions`
/// ∪ the firing event's own actions, because `call_llm_for_client` serves both the initial
/// instruction and every network event through one entry point. Declaring the same list twice
/// is therefore redundant rather than load-bearing — but it is also what keeps the declaration
/// honest about what the model will actually be offered.
///
/// The corollary matters for [`BGP_CLIENT_NOTIFICATION_RECEIVED_EVENT`]: its `with_no_actions()`
/// does *not* stop these verbs being offered, so the read loop still has to log anything the
/// model returns for it as discarded rather than assume it cannot happen.
fn bgp_client_response_actions() -> Vec<ActionDefinition> {
    vec![
        ActionDefinition {
            name: "send_keepalive".to_string(),
            description: "Send a BGP KEEPALIVE to the peer. Routine keepalives are already \
                          sent automatically at a third of the negotiated hold time; use this \
                          only to send an extra one."
                .to_string(),
            parameters: vec![],
            example: json!({
                "type": "send_keepalive"
            }),
            log_template: None,
        },
        ActionDefinition {
            name: "send_notification".to_string(),
            description: "Send a BGP NOTIFICATION. RFC 4271 requires the peer to close the \
                          session on receipt, so this ends the peering."
                .to_string(),
            parameters: vec![
                Parameter {
                    name: "error_code".to_string(),
                    type_hint: "number".to_string(),
                    description: "BGP error code, 1-6 (1 Message Header, 2 OPEN, 3 UPDATE, \
                                  4 Hold Timer Expired, 5 FSM, 6 Cease)"
                        .to_string(),
                    required: true,
                },
                Parameter {
                    name: "error_subcode".to_string(),
                    type_hint: "number".to_string(),
                    description: "BGP error subcode (default 0 = unspecified)".to_string(),
                    required: false,
                },
            ],
            example: json!({
                "type": "send_notification",
                "error_code": 6,
                "error_subcode": 2
            }),
            log_template: None,
        },
        ActionDefinition {
            name: "disconnect".to_string(),
            description: "Close the session gracefully: send NOTIFICATION 6/2 (Cease / \
                          Administrative Shutdown), then close the TCP connection."
                .to_string(),
            parameters: vec![],
            example: json!({
                "type": "disconnect"
            }),
            log_template: None,
        },
        ActionDefinition {
            name: "wait_for_more".to_string(),
            description: "Do nothing and keep monitoring the session".to_string(),
            parameters: vec![],
            example: json!({
                "type": "wait_for_more"
            }),
            log_template: None,
        },
    ]
}

/// BGP client protocol action handler
pub struct BgpClientProtocol;

impl BgpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BgpClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for BgpClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        bgp_client_response_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        bgp_client_response_actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            BGP_CLIENT_CONNECTED_EVENT.clone(),
            BGP_CLIENT_UPDATE_RECEIVED_EVENT.clone(),
            BGP_CLIENT_NOTIFICATION_RECEIVED_EVENT.clone(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "BGP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>BGP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["bgp", "border gateway"]
    }
    fn description(&self) -> &'static str {
        "BGP routing client (query mode)"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to BGP peer at 192.168.1.1:179 and query routing table"
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "local_as".to_string(),
                type_hint: "integer".to_string(),
                description: "Local BGP AS number (can be fake for monitoring)".to_string(),
                required: false,
                example: json!(65000),
                default: None,
            },
            ParameterDefinition {
                name: "router_id".to_string(),
                type_hint: "string".to_string(),
                description: "BGP router ID in IPv4 format".to_string(),
                required: false,
                example: json!("192.168.1.100"),
                default: None,
            },
            ParameterDefinition {
                name: "hold_time".to_string(),
                type_hint: "integer".to_string(),
                description: "BGP hold time in seconds (default 180)".to_string(),
                required: false,
                example: json!(180),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "BGP-4 query client (RFC 4271, RFC 6793) over netgauze-bgp-pkt, \
                             sharing src/server/bgp/wire.rs with the BGP server",
            )
            .llm_control("Session establishment, route monitoring")
            .e2e_testing("NetGet BGP server")
            .notes(
                "Query mode only, no active route announcement, no RIB. Four-octet ASNs \
                    are advertised and parsed. Keepalives go at a third of the negotiated hold \
                    time and the hold timer is enforced: a peer that sends nothing for the \
                    negotiated hold time earns NOTIFICATION 4/0 and the session closes, proven \
                    end to end in tests/client/bgp/hold_timer_test.rs. Never peered against a \
                    real BGP daemon.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn group_name(&self) -> &'static str {
        "VPN & Routing"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls BGP session and route monitoring
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:179",
                "base_stack": "bgp",
                "instruction": "Establish BGP session and monitor routing updates",
                "startup_params": {
                    "local_as": 65000,
                    "router_id": "192.168.1.100"
                }
            }),
            // Script mode: Code-based BGP update handling
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:179",
                "base_stack": "bgp",
                "startup_params": {
                    "local_as": 65000,
                    "router_id": "192.168.1.100"
                },
                "event_handlers": [{
                    "event_pattern": "bgp_update_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<bgp_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed BGP keepalive response
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:179",
                "base_stack": "bgp",
                "startup_params": {
                    "local_as": 65000,
                    "router_id": "192.168.1.100",
                    "hold_time": 180
                },
                "event_handlers": [
                    {
                        "event_pattern": "bgp_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_keepalive"
                            }]
                        }
                    },
                    {
                        "event_pattern": "bgp_update_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_keepalive"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for BgpClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(async move {
            use crate::client::bgp::BgpClient;
            BgpClient::connect_with_llm_actions(
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
    /// Turn an action into bytes.
    ///
    /// Every message is built by [`crate::server::bgp::wire`], the same codec the BGP server
    /// uses, rather than by assembling a marker and a length by hand here.
    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        use crate::server::bgp::wire;

        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_keepalive" => Ok(ClientActionResult::SendData(wire::encode_keepalive())),
            "send_notification" => {
                // No default. A NOTIFICATION ends the session, and inventing a Cease for an
                // action that forgot to say why would make an unusable answer look deliberate.
                let error_code_raw = action
                    .get("error_code")
                    .and_then(|v| v.as_u64())
                    .context("send_notification requires error_code (1-6, see RFC 4271 §6)")?;
                let error_code = u8::try_from(error_code_raw)
                    .ok()
                    .filter(|c| (1..=6).contains(c))
                    .with_context(|| {
                        format!("send_notification error_code must be 1-6, got {error_code_raw}")
                    })?;

                let error_subcode_raw = action
                    .get("error_subcode")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let error_subcode = u8::try_from(error_subcode_raw).with_context(|| {
                    format!(
                        "send_notification error_subcode must be 0-255, got {error_subcode_raw}"
                    )
                })?;

                Ok(ClientActionResult::SendData(wire::encode_notification(
                    error_code,
                    error_subcode,
                    &[],
                )?))
            }
            // RFC 4271 §6.7: a peer that is going away says so. Closing the socket without a
            // NOTIFICATION leaves the peer to discover it from the TCP FIN. The description
            // has always promised the Cease; only now is it actually sent.
            "disconnect" => Ok(ClientActionResult::Multiple(vec![
                ClientActionResult::SendData(wire::encode_notification(
                    wire::ERR_CEASE,
                    2, // Administrative Shutdown
                    &[],
                )?),
                ClientActionResult::Disconnect,
            ])),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown BGP client action: {}",
                action_type
            )),
        }
    }
}

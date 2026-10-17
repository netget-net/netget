//! WebRTC Signaling Server protocol actions implementation
//!
//! The signaling server relays SDP offers/answers and ICE candidates between registered
//! peers. Relay is automatic and happens *before* any event fires: putting a model
//! round-trip in front of every ICE candidate would break any real browser peer. The LLM's
//! role here is observation, plus the ability to speak to a peer directly at registration
//! time.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Actions available while a signaling connection is open.
fn signaling_actions() -> Vec<ActionDefinition> {
    vec![
        ActionDefinition {
            name: "send_signaling_message".to_string(),
            description: "Send one JSON signaling message to the peer this event came                           from. Must be a valid signaling message: register, registered,                           offer, answer, ice_candidate, relay or error."
                .to_string(),
            parameters: vec![Parameter {
                name: "message".to_string(),
                type_hint: "object".to_string(),
                description: "The message object, including its `type` field".to_string(),
                required: true,
            }],
            example: json!({
                "type": "send_signaling_message",
                "message": {"type": "error", "message": "Registration rejected"}
            }),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> signaling message to {peer_id}")
                    .with_debug("WebRTC-Signaling send_signaling_message"),
            ),
        },
        ActionDefinition {
            name: "disconnect_peer".to_string(),
            description: "Close this peer's signaling connection".to_string(),
            parameters: vec![],
            example: json!({"type": "disconnect_peer"}),
            log_template: Some(
                LogTemplate::new()
                    .with_info("-> signaling disconnect")
                    .with_debug("WebRTC-Signaling disconnect_peer"),
            ),
        },
    ]
}

/// WebRTC signaling peer connected event
pub static WEBRTC_SIGNALING_PEER_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "webrtc_signaling_peer_connected",
        "A peer registered a peer ID with the signaling server. The server has already          acknowledged it with a `registered` message.",
        // A literal peer id, not "{{event.peer_id}}". Handler substitution runs for a static
        // or script handler; this is the template for the model's own reply, where nothing
        // substitutes and the braces would reach the wire verbatim.
        json!({
            "type": "send_signaling_message",
            "message": {
                "type": "relay",
                "from": "netget",
                "to": "peer-a1b2c3",
                "data": {"welcome": true}
            }
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "peer_id".to_string(),
            type_hint: "string".to_string(),
            description: "Peer ID the client chose. Nothing authenticates it; any \
                          client may claim any unused ID."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Remote address of the signaling connection".to_string(),
            required: true,
        },
        Parameter {
            name: "peer_count".to_string(),
            type_hint: "number".to_string(),
            description: "How many peers are registered, including this one".to_string(),
            required: true,
        },
    ])
    .with_actions(signaling_actions())
    .with_alternative_example(json!({"type": "disconnect_peer"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("signaling peer {peer_id} registered ({peer_count} online)")
            .with_debug("WebRTC-Signaling register peer_id={peer_id} from {remote_addr}")
            .with_trace("WebRTC-Signaling register: {json_pretty(.)}"),
    )
});

/// WebRTC signaling peer disconnected event
pub static WEBRTC_SIGNALING_PEER_DISCONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "webrtc_signaling_peer_disconnected",
        "A registered peer's signaling connection closed. Informational: the socket is          already gone, so there is nothing protocol-specific left to send.",
        json!({
            "type": "append_to_log",
            "message": "signaling peer peer-a1b2c3 went away"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "peer_id".to_string(),
            type_hint: "string".to_string(),
            description: "Peer ID that went away".to_string(),
            required: true,
        },
        Parameter {
            name: "peer_count".to_string(),
            type_hint: "number".to_string(),
            description: "How many peers remain registered".to_string(),
            required: true,
        },
    ])
    .with_no_actions()
    .with_log_template(
        LogTemplate::new()
            .with_info("signaling peer {peer_id} disconnected ({peer_count} online)")
            .with_debug("WebRTC-Signaling disconnect peer_id={peer_id}"),
    )
});

/// WebRTC signaling message received event
pub static WEBRTC_SIGNALING_MESSAGE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "webrtc_signaling_message_received",
        "An offer, answer, ICE candidate or relay message passed through the server. It          has already been forwarded (or found undeliverable) by the time this fires, so          this event is for observation and memory only.",
        json!({
            "type": "append_memory",
            "memory": "peer-a1b2c3 sent an offer to peer-d4e5f6"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "peer_id".to_string(),
            type_hint: "string".to_string(),
            description: "Sender, taken from the message's own `from` field".to_string(),
            required: true,
        },
        Parameter {
            name: "message_type".to_string(),
            type_hint: "string".to_string(),
            description: "\"offer\", \"answer\", \"ice_candidate\" or \"relay\"".to_string(),
            required: true,
        },
        Parameter {
            name: "target_peer".to_string(),
            type_hint: "string".to_string(),
            description: "Recipient, from the message's `to` field".to_string(),
            required: true,
        },
        Parameter {
            name: "delivered".to_string(),
            type_hint: "boolean".to_string(),
            description: "False when no peer with that ID was registered; the \
                          message was dropped and the sender was sent an error."
                .to_string(),
            required: true,
        },
    ])
    .with_no_actions()
    .with_log_template(
        LogTemplate::new()
            .with_info("signaling {message_type} {peer_id} -> {target_peer}")
            .with_debug("WebRTC-Signaling {message_type} from={peer_id} to={target_peer} delivered={delivered}")
            .with_trace("WebRTC-Signaling message: {json_pretty(.)}"),
    )
});

/// WebRTC Signaling Server protocol action handler
pub struct WebRtcSignalingProtocol;

impl WebRtcSignalingProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WebRtcSignalingProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for WebRtcSignalingProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "idle_timeout_secs".to_string(),
            type_hint: "integer".to_string(),
            description: "Seconds a signaling WebSocket may carry no frame at all before the \
                          server closes it (default 600). The server pings at half of it and \
                          every WebSocket client answers automatically, so a registered peer \
                          waiting for an offer is never closed."
                .to_string(),
            required: false,
            example: json!(600),
            default: Some(serde_json::json!(super::IDLE_TIMEOUT.as_secs())),
        }]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Deliberately empty. `list_signaling_peers` and `broadcast_message` were
        // advertised here; both built an `ActionResult::Custom` that nothing in this
        // protocol consumed, so invoking either did nothing while reporting success.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        signaling_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "WebRTC Signaling"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        // These used to be three *fresh* EventTypes with `{"type": "placeholder"}`
        // response examples, unrelated to the statics the server actually fires.
        vec![
            WEBRTC_SIGNALING_PEER_CONNECTED_EVENT.clone(),
            WEBRTC_SIGNALING_PEER_DISCONNECTED_EVENT.clone(),
            WEBRTC_SIGNALING_MESSAGE_RECEIVED_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>WebSocket"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "webrtc signaling",
            "signaling server",
            "sdp relay",
            "websocket signaling",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // tungstenite's max_message_size/max_frame_size, set from this constant. Tested in
            // tests/server/webrtc_signaling/inbound_limit_test.rs.
            .max_inbound_bytes(crate::server::webrtc_signaling::SIGNALING_MAX_MESSAGE_BYTES)
            .implementation(
                "tokio-tungstenite WebSocket relay: peers register a peer ID, then \
                 offer/answer/ice_candidate/relay messages are forwarded by their `to` field",
            )
            .llm_control(
                "Observe registrations and message flow; speak to or disconnect a peer at \
                 registration time. Relay itself is automatic and not gated on the model.",
            )
            .e2e_testing(
                "Two tokio-tungstenite clients exchanging an offer and an answer. Deliberately \
                 NOT counted as Beta evidence: this server frames with tokio-tungstenite too, so \
                 driving it with the same crate proves the crate agrees with itself. The layer \
                 NetGet actually authors is an ad-hoc JSON relay schema, and no third-party \
                 implementation of it exists or could — which is why this stays Experimental \
                 despite a non-#[ignore]d test that connects real WebSocket peers.",
            )
            .notes(
                "No authentication: any client may claim any unused peer ID, first come \
                 first served, and there is no way for a peer to verify who it is talking \
                 to. A sender MUST have registered before it may relay — an unregistered \
                 socket used to be able to inject offers, answers, ICE candidates and \
                 arbitrary 'relay' JSON at any registered peer — and the 'from' field is \
                 overwritten with the sender's registered id, because taking it from the \
                 frame let any peer forge a message from any other. Limits: 1024 registered \
                 peers, 128-byte peer IDs, 256 KiB per WebSocket message, 10s to complete \
                 the upgrade. There is NO rate limit on relayed messages and the \
                 per-connection writer queue is unbounded, so a peer that stops reading \
                 accumulates whatever others send it — put this behind something that \
                 limits connections on an untrusted network. Relay is never gated on the \
                 model: the only lever the LLM has is disconnecting a peer at registration \
                 time. Undeliverable messages are dropped and the sender gets an error; \
                 nothing is queued. Plain ws:// only, no TLS.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "WebRTC signaling server for automatic SDP and ICE candidate exchange via WebSocket"
    }

    fn example_prompt(&self) -> &'static str {
        "Open WebRTC signaling server to help WebRTC peers exchange SDP offers and answers"
    }

    fn group_name(&self) -> &'static str {
        "Real-time"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: welcome each new peer, no LLM call.
        //
        // It handles `webrtc_signaling_peer_connected` and nothing else, on
        // purpose. This example used to carry a second arm for
        // `webrtc_signaling_message_received` that was wrong three ways at once
        // and would have taught every operator who copied it the same three
        // mistakes: that event is declared `.with_no_actions()` so nothing it
        // returns is ever executed; `target_peer` is not a parameter of
        // `send_signaling_message` and the executor ignores it, so even on a
        // usable event it would have written back to the *originating* peer; and
        // the event carries no `message` key at all, so `.get("message", {})`
        // yields `{}`, which passes the executor's `is_object()` check and puts a
        // literal empty object on the wire.
        //
        // Forwarding is not something a handler needs to do in any case: the relay
        // happens in Rust, before any handler is consulted.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "webrtc_signaling_peer_connected":
    actions = [{"type": "send_signaling_message",
                "message": {"type": "relay", "from": "netget",
                            "to": event.get("peer_id", ""),
                            "data": {"welcome": True}}}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "WebRTC Signaling",
                "instruction": "WebRTC signaling server. Relay SDP offers and answers between peers. Log all peer connections and signaling messages."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "WebRTC Signaling",
                "event_handlers": [{
                    "event_pattern": "webrtc_signaling_peer_connected",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }, {
                    "event_pattern": "webrtc_signaling_message_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "WebRTC Signaling",
                "event_handlers": [{
                    "event_pattern": "webrtc_signaling_peer_connected",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_signaling_message",
                            "message": {
                                "type": "relay",
                                "from": "netget",
                                "to": "{{event.peer_id}}",
                                "data": {"welcome": true}
                            }
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for WebRtcSignalingProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::webrtc_signaling::WebRtcSignalingServer;
            let idle_timeout = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_u64("idle_timeout_secs"))
                .transpose()?
                .flatten()
                .map(std::time::Duration::from_secs)
                .unwrap_or(crate::server::webrtc_signaling::IDLE_TIMEOUT);
            WebRtcSignalingServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                idle_timeout,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_signaling_message" => {
                let message = action
                    .get("message")
                    .context("Missing 'message' field")?
                    .clone();
                if !message.is_object() {
                    anyhow::bail!("'message' must be a JSON object");
                }
                // The description promises "a valid signaling message: register,
                // registered, offer, answer, ice_candidate, relay or error", and
                // only `is_object()` enforced it — so any JSON at all went on the
                // wire and a model following the description got no feedback when
                // it produced something a peer cannot parse. Round-trip it through
                // the same enum the server parses inbound frames with, so the
                // promise and the check are the same statement.
                let peer_id = message
                    .get("peer_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                serde_json::from_value::<crate::server::webrtc_signaling::SignalingMessage>(
                    message.clone(),
                )
                .with_context(|| {
                    format!(
                        "'message' is not a signaling message (peer_id {:?}); expected a \
                         'type' of register, registered, offer, answer, ice_candidate, relay \
                         or error, with that variant's fields",
                        peer_id
                    )
                })?;
                // Output is written to this peer's WebSocket as a text frame by
                // WebRtcSignalingServer::apply_results.
                Ok(ActionResult::Output(
                    serde_json::to_vec(&message).context("message is not serialisable")?,
                ))
            }
            "disconnect_peer" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!(
                "Unknown WebRTC Signaling action: {}",
                action_type
            )),
        }
    }
}

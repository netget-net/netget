//! IPSec/IKEv2 protocol actions implementation
//!
//! Defines LLM-controllable actions for the IPSec/IKEv2 parse-and-log honeypot.
//!
//! **All actions here are classification/logging decisions.** None of them put a
//! byte on the wire, negotiate a Security Association, or create a tunnel - the
//! honeypot is receive-only by design. See `src/server/ipsec/mod.rs`.
//!
//! **Status**: Experimental (manual IKE header + payload-chain parsing)

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// IPSec/IKEv2 handshake initiation event
pub static IPSEC_HANDSHAKE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ipsec_handshake",
        "An IKE handshake datagram (IKEv2 IKE_SA_INIT/IKE_AUTH or IKEv1 Identity \
         Protection/Aggressive Mode) was received and parsed. The honeypot sends no \
         reply; respond with log_handshake, accept_connection or reject_connection to \
         record how this attempt should be classified.",
        json!({"type": "log_handshake", "details": "IKE handshake observed"}),
    )
    // The three actions the description above tells the model to use. They transmit nothing -
    // each returns NoAction - but they are recorded against the event in the access log, which
    // is the whole point of a honeypot classification. Before this list existed `call_llm`
    // offered the model none of them (it builds the tool list from the event type, not from
    // get_sync_actions()), so the very responses the description asked for were rejected as
    // unknown actions and the call failed after two retries.
    .with_actions(vec![
        log_handshake_action(),
        accept_connection_action(),
        reject_connection_action(),
    ])
    // The sender is named from `peer_addr`, which the event data always carries. The
    // `client_ip` enrichment comes from a registered connection, and IKE here is
    // connectionless: `call_llm` is given no connection id for this event.
    .with_log_template(
        LogTemplate::new()
            .with_info("{peer_addr} IKE {exchange_type} ({duration_ms}ms)")
            .with_debug("IKE handshake from {peer_addr}: {ike_version} {exchange_type}")
            .with_trace("IKE handshake: {json_pretty(.)}"),
    )
});

/// Get all IPSec event types.
///
/// Only `ipsec_handshake` is emitted. An `ipsec_data` (ESP) event used to be
/// declared here, but the honeypot never establishes a Security Association so
/// no ESP traffic can ever be attributed to one - it was removed rather than
/// left as an event that handlers could subscribe to but that would never fire.
pub fn get_ipsec_event_types() -> Vec<EventType> {
    vec![IPSEC_HANDSHAKE_EVENT.clone()]
}

/// IPSec protocol implementation
pub struct IpsecProtocol;

impl IpsecProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for IpsecProtocol {
    /// No user-triggered actions are advertised.
    ///
    /// `list_connections` and `close_connection` were previously listed, but IKE
    /// here is connectionless and no Security Associations exist, so both were
    /// unconditional no-ops that promised the LLM state it could never get. They
    /// remain accepted by `execute_action` for backwards compatibility.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    /// Classification actions only.
    ///
    /// `send_notify` and `inspect_traffic` were removed from this list: the
    /// honeypot never transmits (so no NOTIFY can be sent) and never decrypts ESP
    /// (so there is no traffic to inspect). Their names promised wire behaviour
    /// the executor does not implement.
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept_connection_action(),
            reject_connection_action(),
            log_handshake_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "IPSec/IKEv2"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_ipsec_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>IPSEC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["ipsec", "ikev2", "ike"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            .state(DevelopmentState::Experimental)
            // Deliberately silent: An IKE response asserts a negotiated security association.
            // Fabricating one is worse than any timeout.
            .deliberately_silent()
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(500))
            .well_known_udp_port(500)
            .implementation(
                "Receive-only IKE honeypot: manual 28-byte header parsing plus payload-chain \
                 walk. No cryptography, no Security Associations, no tunnel interface, and \
                 no packets are ever transmitted back to the peer.",
            )
            .llm_control(
                "Classification of observed IKE attempts only (accept/reject/log labels \
                 recorded in the log). The LLM cannot influence what is sent on the wire, \
                 because nothing is sent.",
            )
            .e2e_testing("Crafted IKEv1/IKEv2 datagrams over UDP (detection only)")
            .notes(
                "NOT A VPN. Detects and analyses IKE reconnaissance; use WireGuard for a \
                 working tunnel. A real IKEv2 responder would need SA negotiation, DH, \
                 auth, ESP and kernel XFRM programming - deliberately out of scope.",
            )
            .max_inbound_bytes(crate::server::ipsec::MAX_PACKET_SIZE)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "IPSec/IKEv2 honeypot - parses and logs IKE handshakes, never replies (not a VPN)"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an IPSec/IKEv2 honeypot on port 500 to analyze VPN reconnaissance attempts"
    }
    fn group_name(&self) -> &'static str {
        "VPN & Routing"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: log every IKE handshake attempt, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "ipsec_handshake":
    actions = [{"type": "log_handshake", "details": "IKE handshake observed"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM analyzes IKE reconnaissance attempts
            json!({
                "type": "open_server",
                "port": 500,
                "base_stack": "ipsec",
                "instruction": "IPSec/IKEv2 honeypot. Log all IKE handshake attempts with detailed protocol analysis. Extract SPIs, exchange types, and payload information."
            }),
            // Script mode: Scripted IKE analysis
            json!({
                "type": "open_server",
                "port": 500,
                "base_stack": "ipsec",
                "event_handlers": [{
                    "event_pattern": "ipsec_handshake",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed logging response
            json!({
                "type": "open_server",
                "port": 500,
                "base_stack": "ipsec",
                "event_handlers": [{
                    "event_pattern": "ipsec_handshake",
                    "handler": {
                        "type": "static",
                        "actions": [{"type": "log_handshake", "details": "IKE handshake detected"}]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for IpsecProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::ipsec::IpsecServer;
            use std::sync::Arc;
            IpsecServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                Arc::new(ctx.llm_client),
                ctx.state,
                ctx.server_id,
                ctx.status_tx,
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
            "accept_connection" => self.execute_accept_connection(action),
            "reject_connection" => self.execute_reject_connection(action),
            "log_handshake" => self.execute_log_handshake(action),
            "send_notify" => self.execute_send_notify(action),
            "inspect_traffic" => self.execute_inspect_traffic(action),
            "list_connections" => Ok(ActionResult::NoAction), // Async action
            "close_connection" => Ok(ActionResult::NoAction), // Async action
            _ => Err(anyhow::anyhow!("Unknown IPSec action: {}", action_type)),
        }
    }
}

impl IpsecProtocol {
    /// Execute accept_connection action - allow IKE handshake to proceed
    fn execute_accept_connection(&self, action: serde_json::Value) -> Result<ActionResult> {
        let _message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Connection accepted");

        // In a full implementation, this would generate IKE response
        // For honeypot, just log the decision (logged via tracing in server)
        Ok(ActionResult::NoAction)
    }

    /// Execute reject_connection action - deny IKE handshake
    fn execute_reject_connection(&self, action: serde_json::Value) -> Result<ActionResult> {
        let _reason = action
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("Unauthorized");

        // In full implementation, send NOTIFY with error or drop packet
        // For honeypot, just log (logged via tracing in server)
        Ok(ActionResult::NoAction)
    }

    /// Execute log_handshake action - capture IKE handshake details for honeypot
    fn execute_log_handshake(&self, action: serde_json::Value) -> Result<ActionResult> {
        let _details = action
            .get("details")
            .and_then(|v| v.as_str())
            .unwrap_or("Handshake logged");

        // Logged via tracing in server
        Ok(ActionResult::NoAction)
    }

    /// Execute send_notify action - send IKE NOTIFY message
    fn execute_send_notify(&self, action: serde_json::Value) -> Result<ActionResult> {
        let _notify_type = action
            .get("notify_type")
            .and_then(|v| v.as_str())
            .unwrap_or("NO_PROPOSAL_CHOSEN");

        // For honeypot, just log (logged via tracing in server)
        Ok(ActionResult::NoAction)
    }

    /// Execute inspect_traffic action - log decrypted ESP packet info
    fn execute_inspect_traffic(&self, action: serde_json::Value) -> Result<ActionResult> {
        let _inspect = action
            .get("inspect")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // Logged via tracing in server
        Ok(ActionResult::NoAction)
    }
}

/// Action: Accept IKE connection handshake
fn accept_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "accept_connection".to_string(),
        description: "Classify this IKE attempt as legitimate and record it in the log. No SA \
                      is established and no IKE response is sent - the honeypot is \
                      receive-only. Use this to label benign/expected VPN clients."
            .to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Optional message to log".to_string(),
            required: false,
        }],
        example: json!({
            "type": "accept_connection",
            "message": "Legitimate VPN connection accepted"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IKE accept")
                .with_debug("IKE connection accepted: {message}"),
        ),
    }
}

/// Action: Reject IKE connection handshake
fn reject_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "reject_connection".to_string(),
        description: "Classify this IKE attempt as unwanted (scan, probe, misconfigured client) \
                      and record the reason. The packet is silently dropped either way - no \
                      rejection is transmitted, because the honeypot never replies."
            .to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Reason for rejection".to_string(),
            required: false,
        }],
        example: json!({
            "type": "reject_connection",
            "reason": "Suspicious reconnaissance attempt"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IKE reject: {reason}")
                .with_debug("IKE connection rejected: {reason}"),
        ),
    }
}

/// Action: Log IKE handshake details
fn log_handshake_action() -> ActionDefinition {
    ActionDefinition {
        name: "log_handshake".to_string(),
        description: "Record an analyst note about this IKE handshake (what it looks like, why \
                      it matters). This is the primary action for this protocol."
            .to_string(),
        parameters: vec![Parameter {
            name: "details".to_string(),
            type_hint: "string".to_string(),
            description: "Additional details to log".to_string(),
            required: false,
        }],
        example: json!({
            "type": "log_handshake",
            "details": "VPN scan attempt detected"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IKE logged: {details}")
                .with_debug("IKE handshake logged: {details}"),
        ),
    }
}

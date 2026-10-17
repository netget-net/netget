//! OpenVPN control channel: events and actions.
//!
//! The server owns the wire format, the reliability layer, the TLS session and
//! the key-method-2 encoding; the model owns the two policy decisions in the
//! handshake, and both are enforced:
//!
//! 1. **`openvpn_peer_reset`** — answer the session reset, or stay silent.
//!    `accept_peer` is the only thing that causes a
//!    `P_CONTROL_HARD_RESET_SERVER_V2` to be sent.
//! 2. **`openvpn_client_key_exchange`** — the client has completed the TLS
//!    handshake and sent its options string and `--auth-user-pass` credentials.
//!    `accept_key_exchange` is the only thing that causes the server's own key
//!    method 2 message to be sent.
//!
//! For both, `reject_*`, an empty answer, and an LLM error all leave the peer
//! with nothing, under distinct `decision=` tokens in the log.
//!
//! Nothing here promises a tunnel, because this server cannot build one: it
//! answers no `PUSH_REQUEST`, derives no data channel keys and has no TUN
//! device. See `src/server/openvpn/mod.rs`.

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

/// Name of the `ActionResult::Custom` the server looks for when deciding
/// whether to answer a peer. Kept next to the actions that produce it so the
/// producer and the consumer cannot drift apart.
pub const PEER_DECISION_RESULT: &str = "openvpn_peer_decision";

/// Name of the `ActionResult::Custom` the server looks for when deciding whether
/// to answer the client's key-method-2 message. Distinct from
/// [`PEER_DECISION_RESULT`] so a decision about one stage of the handshake can
/// never be read as a decision about the other.
pub const KEY_EXCHANGE_DECISION_RESULT: &str = "openvpn_key_exchange_decision";

/// A client began an OpenVPN handshake. The one point where policy applies.
pub static OPENVPN_PEER_RESET_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "openvpn_peer_reset",
        "An OpenVPN client sent a session reset (P_CONTROL_HARD_RESET_CLIENT_V1/V2) - the \
         first packet of a handshake. Decide whether to answer it. Reply with accept_peer to \
         send P_CONTROL_HARD_RESET_SERVER_V2 and begin tracking the peer, or reject_peer to \
         stay silent and drop it. If you reply with neither, the peer is left unanswered. \
         Answering starts a real TLS control channel, and the client's credentials arrive \
         next as an openvpn_client_key_exchange event. Even an accepted peer never gets a \
         tunnel: this server answers no PUSH_REQUEST and has no data channel.",
        json!({
            "type": "accept_peer",
            "reason": "Answer the handshake and observe what the client sends next"
        }),
    )
    .with_actions(vec![accept_peer_action(), reject_peer_action()])
    // The sender is named from `peer_addr`, which the event data always carries. The
    // `client_ip` enrichment comes from a connection registered in AppState, and a peer is
    // registered only once `accept_peer` answers this event.
    .with_log_template(
        LogTemplate::new()
            .with_info("{peer_addr} OpenVPN reset (session {client_session_id})")
            .with_debug(
                "OpenVPN {reset_type} from {peer_addr}, session {client_session_id}, \
                 key_id {key_id}",
            )
            .with_trace("OpenVPN peer reset: {json_pretty(.)}"),
    )
});

/// The client finished the control-channel TLS handshake and sent key method 2.
///
/// This is where the credentials are: the message carries the client's OCC
/// options string, its `--auth-user-pass` username and password, and its `IV_*`
/// peer info (OpenVPN version, platform, supported data ciphers). The key
/// material itself is deliberately not in the event — it is 112 secret random
/// bytes and no decision can be made from it.
pub static OPENVPN_KEY_EXCHANGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "openvpn_client_key_exchange",
        "An OpenVPN client completed the control-channel TLS handshake and sent its key \
         method 2 message: its options string, its username and password if it is using \
         --auth-user-pass, and its IV_* peer info. Decide whether to answer. Reply with \
         accept_key_exchange to send this server's own key method 2 message, or \
         reject_key_exchange to stay silent and drop the session. If you reply with neither, \
         the client is left unanswered. Note that even an accepted client never gets a \
         tunnel: this server does not answer PUSH_REQUEST and derives no data channel keys.",
        json!({
            "type": "accept_key_exchange",
            "reason": "Answer so the client reveals what it asks for next"
        }),
    )
    .with_actions(vec![
        accept_key_exchange_action(),
        reject_key_exchange_action(),
    ])
    // Named from `peer_addr` like the reset event: the event data always carries it, while
    // `client_ip` depends on the peer's connection entry still being in AppState.
    .with_log_template(
        LogTemplate::new()
            .with_info("{peer_addr} OpenVPN key exchange (user {username})")
            .with_debug("OpenVPN key method 2 from {peer_addr}: user {username}, {options}")
            .with_trace("OpenVPN key exchange: {json_pretty(.)}"),
    )
});

/// Get all OpenVPN event types.
///
/// Two events, one per policy decision in the handshake. Individual control
/// packets are acknowledged by the server without consulting the model: a client
/// retransmits them, so an event per packet would spend model calls on
/// duplicates while changing nothing.
pub fn get_openvpn_event_types() -> Vec<EventType> {
    vec![
        OPENVPN_PEER_RESET_EVENT.clone(),
        OPENVPN_KEY_EXCHANGE_EVENT.clone(),
    ]
}

/// OpenVPN protocol implementation.
pub struct OpenvpnProtocol;

impl OpenvpnProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OpenvpnProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for OpenvpnProtocol {
    /// No user-triggered actions.
    ///
    /// The action executor builds a stateless `OpenvpnProtocol` with no handle
    /// to the running server, so anything listed here could only return
    /// `NoAction`. Listing peer management the executor cannot perform would be
    /// a promise the protocol cannot keep.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept_peer_action(),
            reject_peer_action(),
            accept_key_exchange_action(),
            reject_key_exchange_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "OpenVPN"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_openvpn_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>OPENVPN"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["openvpn"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // Deliberately NOT `.connectionless()`. The flag drives
            // `AppState::cleanup_old_connections`, which evicts any connection idle for 10
            // seconds - and an OpenVPN peer is the opposite of connectionless: it holds a
            // reliability window, a TLS session and a key-exchange state machine, and every
            // packet it sends has to be read in the light of its last one. Ten seconds is
            // less than a single accept_peer decision takes, so the flag deleted live
            // handshakes out from under themselves. Idle peers are this server's own job:
            // `sweep_loop` forgets them after 120s and closes their connection then.
            // Experimental, not Beta. A real openvpn client now completes the
            // control-channel TLS handshake and the key method 2 exchange
            // against this server, which is genuinely more than "the front of
            // the protocol" - but Beta means "works against real clients", and
            // no client can use this as a VPN: PUSH_REQUEST is unanswered and
            // there is no data channel. Promoting it for a handshake that ends
            // in a timeout would repeat the mistake wireguard was demoted for.
            .state(DevelopmentState::Experimental)
            // Deliberately silent: The only pre-TLS server message is
            // P_CONTROL_HARD_RESET_SERVER_V2, and sending it IS admitting the peer - answering
            // on LLM failure would turn a backend outage into an authentication bypass.
            .deliberately_silent()
            // No TUN device and no privileged port by default (1194 is
            // unprivileged), so nothing here needs elevation. Declaring Root, as
            // this protocol used to, made it unstartable for no benefit.
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(1194)
            .implementation(
                "Control channel only. Decodes the OpenVPN UDP wire format (P_CONTROL_*, \
                 P_ACK_V1, P_DATA_V1/V2); implements the reliability layer (packet ids, ACK \
                 arrays, ordered delivery, retransmission with backoff); answers \
                 P_CONTROL_HARD_RESET_CLIENT_V1/V2 with P_CONTROL_HARD_RESET_SERVER_V2; runs \
                 a real rustls TLS session whose records are fragmented across P_CONTROL_V1 \
                 packets, using a self-signed P-256 certificate generated per run whose \
                 SHA-256 fingerprint is logged for --peer-fingerprint; and reads and answers \
                 the client's key method 2 message (options string, username, password, IV_* \
                 peer info). There is NO PUSH_REPLY, NO data channel key derivation, NO data \
                 channel and NO TUN device, so no tunnel is ever established and no traffic \
                 is carried. --tls-auth, --tls-crypt and --tls-crypt-v2 clients are detected \
                 and refused rather than mis-parsed.",
            )
            .llm_control(
                "Two events, one per policy decision. openvpn_peer_reset: accept_peer sends \
                 the reset reply, reject_peer stays silent. openvpn_client_key_exchange \
                 carries the client's username, password, options and IV_* peer info; \
                 accept_key_exchange sends the server's key method 2 answer, \
                 reject_key_exchange stays silent. Both decisions are enforced and both fail \
                 closed: no decision means nothing is sent.",
            )
            .e2e_testing(
                "Wire format pinned to frames captured from OpenVPN 2.7.4 and decoded by a \
                 hand-written decoder in the test, not by this codec. A live openvpn 2.7 \
                 client is driven against the server with --peer-fingerprint set from the \
                 fingerprint the server logs, and must log 'Control Channel: TLSv1.x' (the \
                 TLS handshake completed over the reliability layer) and 'Peer Connection \
                 Initiated' (its key method 2 message was answered acceptably). The same test \
                 asserts the client never logs 'Initialization Sequence Completed', because \
                 the server answers no PUSH_REQUEST.",
            )
            .notes(
                "NOT A VPN - it never carries traffic; a real client stalls at PUSH_REQUEST. \
                 Useful as an OpenVPN honeypot and protocol observatory: because the TLS \
                 session is real, it captures the client's OpenVPN version and platform \
                 (IV_* peer info), its expected options, and the username and password it \
                 was going to authenticate with. Use WireGuard for a working tunnel.",
            )
            .max_inbound_bytes(crate::server::openvpn::packet::MAX_PACKET_SIZE)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "OpenVPN control-plane responder / honeypot (answers the session reset; no tunnel)"
    }

    fn example_prompt(&self) -> &'static str {
        "Start an OpenVPN honeypot on port 1194 and log everyone who probes it"
    }

    fn group_name(&self) -> &'static str {
        "VPN & Routing"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: the model decides per peer.
            json!({
                "type": "open_server",
                "port": 1194,
                "base_stack": "openvpn",
                "instruction": "OpenVPN honeypot. Answer every handshake with accept_peer and record the peer address and session id so the probe is logged."
            }),
            // Script mode: deterministic accept, no model call per peer.
            json!({
                "type": "open_server",
                "port": 1194,
                "base_stack": "openvpn",
                "event_handlers": [{
                    "event_pattern": "openvpn_peer_reset",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "return {'type': 'accept_peer', 'reason': 'honeypot'}"
                    }
                }]
            }),
            // Static mode: fixed decision.
            json!({
                "type": "open_server",
                "port": 1194,
                "base_stack": "openvpn",
                "event_handlers": [{
                    "event_pattern": "openvpn_peer_reset",
                    "handler": {
                        "type": "static",
                        "actions": [{"type": "accept_peer"}]
                    }
                }]
            }),
        )
    }
}

impl Server for OpenvpnProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::openvpn::OpenvpnServer;
            use std::sync::Arc;
            OpenvpnServer::spawn_with_llm_actions(
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

        let reason = action
            .get("reason")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        match action_type {
            "accept_peer" => Ok(decision_result(PEER_DECISION_RESULT, true, reason)),
            "reject_peer" => Ok(decision_result(PEER_DECISION_RESULT, false, reason)),
            "accept_key_exchange" => {
                Ok(decision_result(KEY_EXCHANGE_DECISION_RESULT, true, reason))
            }
            "reject_key_exchange" => {
                Ok(decision_result(KEY_EXCHANGE_DECISION_RESULT, false, reason))
            }
            _ => Err(anyhow::anyhow!("Unknown OpenVPN action: {}", action_type)),
        }
    }
}

/// Encode a decision for the server loop to act on.
fn decision_result(name: &str, accept: bool, reason: Option<String>) -> ActionResult {
    ActionResult::Custom {
        name: name.to_string(),
        data: json!({ "accept": accept, "reason": reason }),
    }
}

/// Action: answer the handshake.
fn accept_peer_action() -> ActionDefinition {
    ActionDefinition {
        name: "accept_peer".to_string(),
        description: "Answer this peer's session reset with P_CONTROL_HARD_RESET_SERVER_V2 and \
                      start tracking it, acknowledging the control packets it sends next. This \
                      is enforced: without it, nothing is sent to the peer. An accepted peer \
                      goes on to complete a real TLS handshake over the control channel and \
                      send its key method 2 message, which arrives as \
                      openvpn_client_key_exchange - but it never gets a tunnel: this server \
                      answers no PUSH_REQUEST and has no data channel, so the client stalls \
                      there."
            .to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Why this peer is being answered (recorded in the log)".to_string(),
            required: false,
        }],
        example: json!({
            "type": "accept_peer",
            "reason": "Observe what the client sends after the reset"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OpenVPN answer reset ({reason})")
                .with_debug("OpenVPN accept_peer: {reason}"),
        ),
    }
}

/// Action: stay silent.
fn reject_peer_action() -> ActionDefinition {
    ActionDefinition {
        name: "reject_peer".to_string(),
        description: "Refuse this peer: send nothing at all and drop it. This is enforced. \
                      OpenVPN has no reject packet at reset time, so silence is the refusal; \
                      the client will retry and then give up."
            .to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Why this peer is being refused (recorded in the log)".to_string(),
            required: false,
        }],
        example: json!({
            "type": "reject_peer",
            "reason": "Source address is not on the allow list"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OpenVPN refuse peer ({reason})")
                .with_debug("OpenVPN reject_peer: {reason}"),
        ),
    }
}

/// Action: answer the client's key method 2 message.
fn accept_key_exchange_action() -> ActionDefinition {
    ActionDefinition {
        name: "accept_key_exchange".to_string(),
        description: "Answer this client's key method 2 message with this server's own, so the \
                      handshake continues and the client reveals what it asks for next \
                      (PUSH_REQUEST and its option requirements). This is enforced: without it, \
                      nothing is sent. It still does not create a tunnel - PUSH_REQUEST is never \
                      answered and no data channel keys are derived, so the client stalls there."
            .to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Why this client is being answered (recorded in the log)".to_string(),
            required: false,
        }],
        example: json!({
            "type": "accept_key_exchange",
            "reason": "Credentials captured; let it continue so it reveals its push requirements"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OpenVPN answer key exchange ({reason})")
                .with_debug("OpenVPN accept_key_exchange: {reason}"),
        ),
    }
}

/// Action: stay silent after the key exchange.
fn reject_key_exchange_action() -> ActionDefinition {
    ActionDefinition {
        name: "reject_key_exchange".to_string(),
        description: "Refuse this client after its key method 2 message: send nothing and drop \
                      the control session. This is enforced. OpenVPN's AUTH_FAILED is only read \
                      by a client that has already received the server's key method 2 answer, so \
                      before that point silence is the only refusal the peer can understand."
            .to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Why this client is being refused (recorded in the log)".to_string(),
            required: false,
        }],
        example: json!({
            "type": "reject_key_exchange",
            "reason": "Username is not on the allow list"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OpenVPN refuse key exchange ({reason})")
                .with_debug("OpenVPN reject_key_exchange: {reason}"),
        ),
    }
}

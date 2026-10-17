//! Wake-on-LAN protocol actions.
//!
//! # The action set is small on purpose
//!
//! Wake-on-LAN defines no response (see `mod.rs`), so there is no reply for the model to
//! author and no wire verb to offer it. Padding the list with invented verbs would hand the
//! model a vocabulary that does not correspond to anything on the network.
//!
//! What is left is real, though, and it is what the event actually needs answering with:
//!
//! * `record_wake_request` — this packet is for a host I know about; keep it, with a label.
//! * `ignore_magic_packet` — it is not; drop it, and say why.
//! * `announce_host_awake` — **not part of Wake-on-LAN**, off unless the operator turns it on.
//!
//! Every one of them is attached to `wol_magic_packet_received` with `.with_actions(...)`, so
//! the model is never asked a question it has no vocabulary to answer.
//!
//! There are **no async actions**. An async action is a user-triggered verb that needs no
//! network context, and a listener that never transmits has none: `announce_host_awake` needs
//! both the per-server gate and the magic packet's source address, neither of which exists
//! outside the receive loop.

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

/// Action name: keep this packet.
pub const RECORD_WAKE_REQUEST: &str = "record_wake_request";

/// Action name: drop this packet.
pub const IGNORE_MAGIC_PACKET: &str = "ignore_magic_packet";

/// Action name: the non-standard announcement. Off by default.
pub const ANNOUNCE_HOST_AWAKE: &str = "announce_host_awake";

/// Startup parameter gating [`ANNOUNCE_HOST_AWAKE`].
pub const ALLOW_NON_STANDARD_ACK: &str = "allow_non_standard_ack";

/// Wake-on-LAN protocol action handler.
pub struct WolProtocol;

impl WolProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WolProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for WolProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: ALLOW_NON_STANDARD_ACK.to_string(),
            type_hint: "boolean".to_string(),
            description: "Allow the announce_host_awake action to actually send a datagram. \
                          Wake-on-LAN has no response of any kind, so this is a NetGet \
                          extension for lab and honeypot use, not part of the protocol. \
                          Defaults to false, in which case announce_host_awake is refused \
                          and logged and nothing is transmitted."
                .to_string(),
            required: false,
            example: json!(false),
            default: None,
        }]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Deliberately empty: see the module docs. A listener that never transmits has no
        // user-triggered verb, and the one action that does transmit needs the receive
        // loop's context.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            record_wake_request_action(),
            ignore_magic_packet_action(),
            announce_host_awake_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Wake-on-LAN"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_wol_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>WOL"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["wol", "wakeonlan", "wake-on-lan", "magic packet"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // Every sender is a fresh UDP peer that nothing ever closes, so the 10-second
            // idle sweep is what removes them. Without this flag they accumulate until the
            // server stops.
            .connectionless()
            // Deliberately silent: Wake-on-LAN has no reply of any kind. A magic packet is a one-way
            // broadcast, so there is nothing to answer with, and the model is only deciding what the
            // server does about it.
            .deliberately_silent()
            .state(DevelopmentState::Experimental)
            // Port 9 really is below 1024, so this preflight really fires. It is checked
            // against the requested port, so a test on a high port needs no privileges.
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(9))
            .well_known_udp_port(9)
            .implementation(
                "Hand-written magic packet decoder (no dependency): scans the datagram for \
                 6x0xFF followed by the same MAC 16 times, at any offset, with an optional \
                 4- or 6-byte SecureON trailer",
            )
            .llm_control(
                "Which target MACs are recognised, what is recorded about each packet, and \
                 (off by default) whether a non-standard awake announcement is sent",
            )
            .e2e_testing(
                "REAL THIRD-PARTY SENDER: the `wakeonlan` Perl script (0.50), in \
                 tests/server/wol/real_client_test.rs. NOT #[ignore]d and NOT skip-gated — the \
                 test FAILS, naming `brew install wakeonlan`, when the binary is absent. It \
                 asserts the server decoded wakeonlan's own 102 bytes as target_mac \
                 00:11:22:33:44:55, transport=udp, sync_offset=0, password_length=0, with the \
                 mock echoing the EVENT's fields back so a misdecode produces a wrong record \
                 rather than passing quietly. Alongside it, decode_test.rs covers the decoder \
                 exhaustively against packets assembled from AMD's Magic Packet specification \
                 (offsets 1/7/20/137, a false sync stream, 4- and 6-byte SecureON trailers, \
                 near-misses at 15 repetitions and single flipped bytes), and e2e_test.rs covers \
                 the four byte-identical silences and the announce_host_awake gate. \
                 THIS IS STILL NOT A BETA CASE, deliberately: Wake-on-LAN is one-way and defines \
                 no reply, so wakeonlan sends and exits and NOTHING NetGet produces is ever \
                 judged by a third-party implementation. That makes this a codec test with a \
                 real generator rather than a session, and it cannot catch the failure that \
                 matters most here — a decoder wrong by being too PERMISSIVE passes every test \
                 in this directory. NOT PROVEN: the EtherType 0x0842 transport (no raw socket is \
                 bound, so nothing can receive one), and that any real NIC would wake, NetGet \
                 not being a NIC.",
            )
            .notes(
                "UDP only. The EtherType 0x0842 form is NOT received off the wire - that \
                 needs a raw socket and this feature carries no packet-capture dependency; \
                 transport='ethernet' means the UDP payload was itself an encapsulated \
                 Ethernet frame. Wake-on-LAN defines no response, so nothing is ever sent \
                 back except the explicitly non-standard, off-by-default announce_host_awake. \
                 Experimental NOT for want of a third-party sender - the real `wakeonlan` \
                 script now drives the decoder in tests/server/wol/real_client_test.rs - but \
                 because a one-way protocol admits no session to be evidence of: nothing this \
                 server emits is ever read by an independent implementation, so 'works against \
                 real clients' cannot be established here in the direction Beta means it",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Wake-on-LAN magic packet listener (UDP 9). Receive-only: nothing is sent back"
    }

    fn example_prompt(&self) -> &'static str {
        "Wake-on-LAN on port 9. Record magic packets for 00:11:22:33:44:55 as 'lab-nas' and \
         ignore every other MAC"
    }

    fn group_name(&self) -> &'static str {
        "Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: recognise one MAC, drop everything else, with no LLM call at all.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
known = {"00:11:22:33:44:55": "lab-nas"}
mac = str(event.get("target_mac", "")).upper()
if data["event_type_id"] == "wol_magic_packet_received" and mac in known:
    actions = [{"type": "record_wake_request",
                "target_mac": mac,
                "host": known[mac],
                "note": "from %s" % event.get("source_address", "?")}]
else:
    actions = [{"type": "ignore_magic_packet", "reason": "unknown target MAC"}]
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 9,
                "base_stack": "wol",
                "instruction": "Wake-on-LAN listener. Record magic packets for hosts in the \
                                00:11:22 range and ignore all others"
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 9,
                "base_stack": "wol",
                "event_handlers": [{
                    "event_pattern": "wol_magic_packet_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: record every magic packet, no LLM call.
            json!({
                "type": "open_server",
                "port": 9,
                "base_stack": "wol",
                "event_handlers": [{
                    "event_pattern": "wol_magic_packet_received",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "record_wake_request",
                            "target_mac": "{{event.target_mac}}",
                            "host": "unidentified"
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for WolProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::wol::WolServer;
            WolServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ctx.startup_params,
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
            RECORD_WAKE_REQUEST => execute_record_wake_request(&action),
            IGNORE_MAGIC_PACKET => execute_ignore_magic_packet(&action),
            ANNOUNCE_HOST_AWAKE => execute_announce_host_awake(&action),
            _ => Err(anyhow::anyhow!(
                "Unknown Wake-on-LAN action: {}",
                action_type
            )),
        }
    }
}

/// Record the packet: validate what the model claims and let the access log keep it.
///
/// NetGet protocols do not implement storage (see the root `CLAUDE.md`). The durable record
/// is the access log entry written for every handled event, which already contains this action
/// verbatim and is readable with `list_access_logs` / `get_access_log`. Nothing is written to
/// disk or to a database here, and — Wake-on-LAN having no response — nothing goes on the wire
/// either.
fn execute_record_wake_request(action: &serde_json::Value) -> Result<ActionResult> {
    let target_mac = action
        .get("target_mac")
        .and_then(|v| v.as_str())
        .context("Missing 'target_mac' parameter (expected \"00:11:22:33:44:55\")")?;

    validate_mac(target_mac)?;

    let host = action.get("host").and_then(|v| v.as_str()).unwrap_or("");
    tracing::debug!(
        "Wake-on-LAN wake request recorded for {} ({})",
        target_mac,
        if host.is_empty() { "unlabelled" } else { host }
    );

    Ok(ActionResult::NoAction)
}

/// Drop the packet. The `reason` is what makes this distinguishable, in the access log, from
/// the model having said nothing at all.
fn execute_ignore_magic_packet(action: &serde_json::Value) -> Result<ActionResult> {
    let reason = action
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("no reason given");
    tracing::debug!("Wake-on-LAN magic packet ignored: {}", reason);
    Ok(ActionResult::NoAction)
}

/// Validate a non-standard announcement without sending it.
///
/// The datagram is sent by the receive loop (`WolServer::process_announcements`), which owns
/// both the `allow_non_standard_ack` gate and the magic packet's source address. This arm
/// exists so the advertised action is executable — returning `NoAction` here means the send
/// happens exactly once, in the one place that can decide whether it is allowed at all.
fn execute_announce_host_awake(action: &serde_json::Value) -> Result<ActionResult> {
    let target_mac = action
        .get("target_mac")
        .and_then(|v| v.as_str())
        .context("Missing 'target_mac' parameter (expected \"00:11:22:33:44:55\")")?;

    validate_mac(target_mac)?;

    // Fail here rather than in the loop: an unparseable destination should be reported to
    // whoever produced the action, not buried in the server log.
    if let Some(target) = action.get("announce_to").and_then(|v| v.as_str()) {
        resolve_announce_target(target)?;
    }

    tracing::debug!(
        "Wake-on-LAN announce_host_awake accepted for {}; the send is gated on \
         allow_non_standard_ack and performed by the receive loop",
        target_mac
    );

    Ok(ActionResult::NoAction)
}

/// Accept `00:11:22:33:44:55` and `00-11-22-33-44-55`, reject anything else.
///
/// The MAC crosses the boundary to the model as a formatted string in both directions, so it
/// is worth checking that what comes back is one — a model that answers with `unknown` or a
/// partial address should be told, not silently recorded.
fn validate_mac(mac: &str) -> Result<()> {
    let octets: Vec<&str> = if mac.contains(':') {
        mac.split(':').collect()
    } else {
        mac.split('-').collect()
    };

    let well_formed = octets.len() == 6
        && octets
            .iter()
            .all(|o| o.len() == 2 && o.chars().all(|c| c.is_ascii_hexdigit()));

    if well_formed {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Invalid 'target_mac' {mac:?}: expected six colon-separated hex octets, \
             e.g. \"00:11:22:33:44:55\""
        ))
    }
}

/// Resolve an `announce_to` value ("HOST:PORT") to one socket address.
pub fn resolve_announce_target(target: &str) -> Result<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;

    target
        .to_socket_addrs()
        .with_context(|| {
            format!(
                "Invalid 'announce_to' {target:?}: expected \"HOST:PORT\", \
                 e.g. \"192.168.1.10:9000\""
            )
        })?
        .next()
        .with_context(|| format!("'announce_to' {target:?} did not resolve to any address"))
}

// ============================================================================
// Action definitions
// ============================================================================

fn record_wake_request_action() -> ActionDefinition {
    ActionDefinition {
        name: RECORD_WAKE_REQUEST.to_string(),
        description: "Treat this magic packet as a wake request for a host you recognise. \
                      Nothing is sent back - Wake-on-LAN has no response - and nothing is \
                      written to disk. The action and its fields become part of the server's \
                      access log entry for this event, readable later with list_access_logs \
                      / get_access_log, and the operator sees it on the dashboard."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "target_mac".to_string(),
                type_hint: "string".to_string(),
                description: "The MAC the packet is for, copied from the event's 'target_mac' \
                              field. Six colon-separated hex octets, e.g. '00:11:22:33:44:55'"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "host".to_string(),
                type_hint: "string".to_string(),
                description: "Your name for the machine this MAC belongs to, e.g. 'lab-nas'. \
                              Free text; it is a label for the operator, not a lookup"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "note".to_string(),
                type_hint: "string".to_string(),
                description: "Anything else worth recording about this packet - who sent it, \
                              whether a SecureON password was present, why it looks legitimate \
                              or suspicious"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": RECORD_WAKE_REQUEST,
            "target_mac": "00:11:22:33:44:55",
            "host": "lab-nas",
            "note": "expected nightly wake from the backup host"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> WoL recorded wake request for {target_mac}")
                .with_debug("WoL record_wake_request: target_mac={target_mac} host={host}"),
        ),
    }
}

fn ignore_magic_packet_action() -> ActionDefinition {
    ActionDefinition {
        name: IGNORE_MAGIC_PACKET.to_string(),
        description: "Drop this magic packet: it is not for a host you know about, or you do \
                      not want it acted on. Give a reason - on a protocol with no response, \
                      the log is the only place a deliberate drop can be told apart from \
                      NetGet having failed to decide anything."
            .to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Why this packet is being dropped, e.g. 'MAC not in the managed \
                          range' or 'no SecureON password'"
                .to_string(),
            required: false,
        }],
        example: json!({
            "type": IGNORE_MAGIC_PACKET,
            "reason": "target MAC is not one of the hosts this server manages"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> WoL ignored the magic packet")
                .with_debug("WoL ignore_magic_packet: reason={reason}"),
        ),
    }
}

fn announce_host_awake_action() -> ActionDefinition {
    ActionDefinition {
        name: ANNOUNCE_HOST_AWAKE.to_string(),
        description: "NOT PART OF WAKE-ON-LAN. Wake-on-LAN is one-way: a real NIC that wakes \
                      its machine sends nothing back, and no sender waits for anything. This \
                      action sends a plain UDP text datagram claiming the host is now awake, \
                      for lab and honeypot setups that want a visible effect. It does nothing \
                      unless the server was started with allow_non_standard_ack=true, in \
                      which case the refusal is logged. Prefer record_wake_request."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "target_mac".to_string(),
                type_hint: "string".to_string(),
                description: "The MAC being claimed awake, e.g. '00:11:22:33:44:55'".to_string(),
                required: true,
            },
            Parameter {
                name: "announce_to".to_string(),
                type_hint: "string".to_string(),
                description: "Where to send the datagram, as 'HOST:PORT'. Omit it to answer \
                              the machine that sent the magic packet (the event's \
                              'source_address')"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Text of the datagram. Defaults to 'netget-wol: host <mac> is \
                              awake'. Plain text only - no encoded bytes"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": ANNOUNCE_HOST_AWAKE,
            "target_mac": "00:11:22:33:44:55",
            "message": "netget-wol: host 00:11:22:33:44:55 is awake"
        }),
        log_template: Some(
            // Deliberately "requested", not "announced": this template fires when the action
            // is accepted, and the send happens later in the receive loop only if the gate
            // allows it. Claiming the announcement went out here would be a lie whenever
            // allow_non_standard_ack is false, which is the default.
            LogTemplate::new()
                .with_info(
                    "-> WoL announce_host_awake requested for {target_mac} (NON-STANDARD; sent \
                     only when allow_non_standard_ack is set)",
                )
                .with_debug("WoL announce_host_awake: target_mac={target_mac} to={announce_to}"),
        ),
    }
}

// ============================================================================
// Event types
// ============================================================================

/// The only event this protocol raises, and the only thing there is to raise: a magic packet
/// arrived.
///
/// A datagram that is *not* a magic packet raises nothing. Port 9 is the discard port and
/// attracts scanners; there is no decision for the model to make about a stray datagram, so
/// making it pay for an LLM call would be pure cost. Those are logged at DEBUG instead.
pub static WOL_MAGIC_PACKET_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "wol_magic_packet_received",
        "A valid Wake-on-LAN magic packet arrived: 6 bytes of 0xFF followed by the target MAC \
         repeated 16 times. Wake-on-LAN defines NO response - a real NIC wakes its machine and \
         sends nothing - so there is nothing to reply with. What you decide is whether this \
         packet is for a host you recognise (record_wake_request) or not \
         (ignore_magic_packet). Answering with neither is recorded as decision=model_silent",
        json!({
            "type": RECORD_WAKE_REQUEST,
            "target_mac": "00:11:22:33:44:55",
            "host": "lab-nas"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "target_mac".to_string(),
            type_hint: "string".to_string(),
            description: "The MAC the packet asks to wake, formatted as six uppercase \
                          colon-separated hex octets, e.g. '00:11:22:33:44:55'. This is the \
                          MAC that appeared 16 times in the payload"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "source_address".to_string(),
            type_hint: "string".to_string(),
            description: "IP:port the datagram was received from. Magic packets are normally \
                          broadcast, so this is whoever sent it, not the machine being woken"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "has_password".to_string(),
            type_hint: "boolean".to_string(),
            description: "True when a SecureON password followed the 102-byte payload. The \
                          password bytes themselves are deliberately not exposed"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "password_length".to_string(),
            type_hint: "number".to_string(),
            description: "0 when there was no SecureON password, otherwise 4 or 6 - the two \
                          lengths the extension defines"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "transport".to_string(),
            type_hint: "string".to_string(),
            description: "'udp' when the magic packet was the UDP payload (the ordinary \
                          case), or 'ethernet' when the payload was itself a complete \
                          Ethernet frame with EtherType 0x0842 carrying the packet. NetGet \
                          binds a UDP socket in both cases; it does not capture raw frames"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "sync_offset".to_string(),
            type_hint: "number".to_string(),
            description: "Byte offset within the datagram at which the six 0xFF bytes were \
                          found. 0 for a bare magic packet, 14 for one inside an Ethernet \
                          frame, anything else when the sender wrapped or padded it"
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        record_wake_request_action(),
        ignore_magic_packet_action(),
        announce_host_awake_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("WoL magic packet for {target_mac} from {source_address}")
            .with_debug(
                "WoL magic packet for {target_mac} from {source_address} transport={transport} \
                 offset={sync_offset} password={has_password}",
            )
            .with_trace("WoL: {json_pretty(.)}"),
    )
});

pub fn get_wol_event_types() -> Vec<EventType> {
    vec![WOL_MAGIC_PACKET_RECEIVED_EVENT.clone()]
}

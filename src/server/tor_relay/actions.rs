//! Tor Relay protocol actions implementation

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
use tracing::debug;

/// Tor Relay protocol action handler
pub struct TorRelayProtocol;

impl TorRelayProtocol {
    pub fn new() -> Self {
        Self
    }

    fn execute_detect_relay_cell(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .context("Missing 'message' parameter")?;

        debug!("Tor Relay: {}", message);

        Ok(ActionResult::Custom {
            name: "tor_relay_log".to_string(),
            data: json!({
                "logged": true,
                "message": message
            }),
        })
    }

    /// Build a DESTROY cell (tor-spec 5.4).
    ///
    /// Layout is CircID(4) | Command(4) | Reason(1), padded to the 514-byte v4 cell size.
    /// The result is written straight to the TLS stream, so it has to be a whole cell -
    /// a short write desynchronises the peer's cell framing for the rest of the connection.
    fn execute_send_destroy(&self, action: serde_json::Value) -> Result<ActionResult> {
        let circuit_id = action
            .get("circuit_id")
            .and_then(|v| v.as_str())
            .context("Missing 'circuit_id' parameter")?;

        let circuit_id = u32::from_str_radix(circuit_id.trim_start_matches("0x"), 16)
            .with_context(|| format!("circuit_id '{}' is not a hex circuit ID", circuit_id))?;

        let reason = action
            .get("reason")
            .and_then(|v| v.as_u64())
            .unwrap_or(1 /* PROTOCOL */) as u8;

        debug!(
            "Tor Relay sending DESTROY for circuit 0x{:08x} (reason {})",
            circuit_id, reason
        );

        let mut cell = Vec::with_capacity(CELL_LEN);
        cell.extend_from_slice(&circuit_id.to_be_bytes());
        cell.push(CELL_COMMAND_DESTROY);
        cell.push(reason);
        cell.resize(CELL_LEN, 0);

        Ok(ActionResult::Output(cell))
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for TorRelayProtocol {
    /// No async actions.
    ///
    /// Seven used to be declared here - set_relay_type, configure_exit_policy,
    /// list_active_circuits, disconnect_circuit, list_active_streams, close_stream and
    /// get_relay_statistics. None of them did anything: execute_action returned a Custom
    /// result reading "implementation in server logic" and no such server logic existed.
    /// Relay state lives in the per-server CircuitManager, which execute_action (sync) cannot
    /// reach and could not await if it could. They were removed rather than left advertised.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        tor_relay_response_actions()
    }
    fn protocol_name(&self) -> &'static str {
        "Tor Relay"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_tor_relay_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>TorRelay"
    }
    fn description(&self) -> &'static str {
        "Partial Tor OR-protocol relay (not interoperable with real Tor clients)"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a Tor exit relay on port 9001 allowing connections to localhost"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "tor_relay",
            "tor-relay",
            "onion router",
            "guard",
            "exit",
            "middle",
            "circuit",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(9001)
            .implementation("Custom partial Tor OR protocol: TLS 1.3, ntor server handshake (Curve25519/HMAC-SHA256/HKDF), per-circuit AES-128-CTR, stream multiplexing to TCP targets, SENDME windows. Cells are framed by length, so VERSIONS and other variable-length cells no longer desynchronise the reader, and VERSIONS is answered - but the rest of the link handshake (CERTS/AUTH_CHALLENGE/NETINFO) is still neither sent nor parsed. The relay logs its identity fingerprint and onion public key at startup, which a peer needs to run ntor at all.")
            .llm_control("Two events: circuit created, and RELAY commands the relay does not implement. Actions: log, DESTROY a circuit, close the connection. Everything on the data path - BEGIN, DATA, END, SENDME, exit policy - is decided in Rust with no LLM involvement.")
            .e2e_testing("tests/server/tor_relay/e2e_test.rs, 2 LLM calls, not #[ignore]d. A Tor client written from tor-spec in the test file (independent of the server's own circuit.rs) runs VERSIONS, then a full ntor CREATE2/CREATED2 whose server AUTH value it recomputes and checks, then RELAY/BEGIN to a localhost HTTP server, then RELAY/DATA out and back - asserting the HTTP body decrypts correctly with the backward key. Not tested: a real tor or Arti binary, which still cannot use this relay because the link handshake stops after VERSIONS; cell digests; EXTEND; multi-hop.")
            .notes("OPEN EXIT BY DESIGN, AND UNRESTRICTED: the destination of every RELAY/BEGIN is chosen by the peer, and there is no exit policy, allow-list, deny-list or network restriction of any kind. Loopback, link-local (including 169.254.169.254, the cloud instance-metadata endpoint) and every RFC 1918 range are all reachable, so anyone who completes a circuit can reach whatever this host can -- an SSRF pivot into the operator's private network, and an exit someone else's traffic can be laundered through. The model is not consulted about it either: BEGIN, DATA, END, SENDME and exit target selection are all decided in Rust, so `filter_mode`-style gating does not exist here even in the weak form socks5 and proxy have. Two bounds do apply, and they are on resources rather than on destination: a BEGIN's connect is abandoned after 10s (it is awaited inline in the cell loop, so an unbounded one froze the whole session for the OS timeout), and a circuit may hold at most 64 streams, answered past that with END/RESOURCE_LIMIT. Do not expose this to an untrusted network. Separately, it is NOT interoperable with real Tor and is not a usable relay: the link handshake stops after VERSIONS (no CERTS/AUTH_CHALLENGE/NETINFO); the relay cell digest field is never computed or verified (tor-spec wants a running SHA-1, and no SHA-1 dependency is available here); no EXTEND, so it can only ever be a single-hop endpoint. Was rated Stable and 'production-ready' - it is neither.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: note every relay cell seen on a circuit, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "tor_relay_relay_cell":
    actions = [{"type": "detect_relay_cell", "message": "relay cell observed"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles Tor relay operations
            json!({
                "type": "open_server",
                "port": 9001,
                "base_stack": "tor-relay",
                "instruction": "Act as Tor exit relay allowing connections to localhost"
            }),
            // Script mode: Code-based Tor relay handling
            json!({
                "type": "open_server",
                "port": 9001,
                "base_stack": "tor-relay",
                "event_handlers": [{
                    "event_pattern": "tor_relay_relay_cell",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed Tor relay responses
            json!({
                "type": "open_server",
                "port": 9001,
                "base_stack": "tor-relay",
                "event_handlers": [{
                    "event_pattern": "tor_relay_relay_cell",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "detect_relay_cell",
                            "message": "Cell detected and logged"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for TorRelayProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::tor_relay::TorRelayServer;
            TorRelayServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
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
            "detect_relay_cell" => self.execute_detect_relay_cell(action),
            "send_destroy" => self.execute_send_destroy(action),
            "close_connection" => Ok(ActionResult::CloseConnection),
            // Writes nothing to the wire — that is the point of it. The doc comment on
            // `tor_relay_log_action` claimed "`execute_action` has always handled it"; it did
            // not, so advertising the verb handed the model a name it was then rejected for
            // using. `NoAction` is the honest result: the observation is already in the access
            // log by the time this runs.
            "tor_relay_log" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown Tor Relay action: {}", action_type)),
        }
    }
}

// ============================================================================
// Cell constants (tor-spec 3, "Cell Packet format")
// ============================================================================

/// Fixed-length cell size for link protocol v4 (CircID 4 + Command 1 + payload 509).
pub const CELL_LEN: usize = 514;
/// DESTROY command byte.
pub const CELL_COMMAND_DESTROY: u8 = 4;

// ============================================================================
// Action Definitions
// ============================================================================

fn detect_relay_cell_action() -> ActionDefinition {
    ActionDefinition {
        name: "detect_relay_cell".to_string(),
        description: "Record an observation about this cell. Logs only - sends nothing on the \
                      wire."
            .to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Log message describing the cell".to_string(),
            required: true,
        }],
        example: json!({
            "type": "detect_relay_cell",
            "message": "RELAY cell detected from circuit 0x12345"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Tor RELAY cell")
                .with_debug("Tor detect_relay_cell: {message}"),
        ),
    }
}

fn send_destroy_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_destroy".to_string(),
        description: "Tear down a circuit by sending it a DESTROY cell".to_string(),
        parameters: vec![
            Parameter {
                name: "circuit_id".to_string(),
                type_hint: "string".to_string(),
                description: "Circuit ID to destroy, hex (e.g. '0x00000005'). Use the \
                              circuit_id from the event."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "reason".to_string(),
                type_hint: "number".to_string(),
                description: "tor-spec destroy reason: 1 PROTOCOL, 2 INTERNAL, 3 REQUESTED, \
                              5 HIBERNATING, 8 FINISHED, 9 TIMEOUT (default 1)"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_destroy",
            "circuit_id": "0x00000005",
            "reason": 3
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Tor DESTROY {circuit_id}")
                .with_debug("Tor send_destroy: circuit={circuit_id} reason={reason}"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the whole TLS connection immediately, dropping every circuit on it"
            .to_string(),
        parameters: vec![],
        example: json!({
            "type": "close_connection"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Tor close connection")
                .with_debug("Tor close_connection: closing immediately"),
        ),
    }
}

/// The actions every Tor relay event accepts.
///
/// `call_llm` advertises `EventType::actions`, not `get_sync_actions()`, so each event below
/// must carry this list or the model is offered nothing.
fn tor_relay_response_actions() -> Vec<ActionDefinition> {
    vec![
        detect_relay_cell_action(),
        send_destroy_action(),
        close_connection_action(),
        tor_relay_log_action(),
    ]
}

/// `tor_relay_log`: the only verb this relay has that writes nothing to the wire.
///
/// The comment here used to say "`execute_action` has always handled it". It did not — there
/// was no match arm — so advertising the verb was the *advertised-but-unexecutable* bug rather
/// than the fix for its mirror. The arm exists now, returning `NoAction`.
///
/// It is the only verb this relay has that
/// writes nothing to the wire -- so it is the answer for a circuit event that needs
/// observing rather than acting on. Leaving it undeclared meant the model could not ask
/// for it and had to choose between send_destroy, detect_relay_cell and inventing
/// something: the mirror of the advertised-but-unexecutable bug, and equally invisible.
fn tor_relay_log_action() -> ActionDefinition {
    ActionDefinition {
        name: "tor_relay_log".to_string(),
        description: "Record an observation about the circuit without sending anything. \
                      The correct answer when a cell needs noting rather than answering."
            .to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "What to record".to_string(),
            required: true,
        }],
        example: json!({
            "type": "tor_relay_log",
            "message": "circuit created"
        }),
        log_template: None,
    }
}

// ============================================================================
// Event Type Constants
// ============================================================================

/// Circuit created event - emitted after a CREATE2 cell completes the ntor handshake.
pub static TOR_RELAY_CIRCUIT_CREATED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tor_relay_circuit_created",
        "Tor circuit created via ntor handshake",
        json!({
            "type": "detect_relay_cell",
            "message": "Circuit created successfully"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "circuit_id".to_string(),
            type_hint: "string".to_string(),
            description: "Circuit ID (hex format)".to_string(),
            required: true,
        },
        Parameter {
            name: "client_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Client IP address".to_string(),
            required: true,
        },
    ])
    .with_actions(tor_relay_response_actions())
});

/// RELAY cell event - emitted for relay commands the relay does not handle itself
/// (EXTEND, TRUNCATE, RESOLVE, DROP and anything unrecognised). BEGIN, BEGIN_DIR, DATA,
/// END and SENDME are handled natively and do not raise this event.
pub static TOR_RELAY_RELAY_CELL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tor_relay_relay_cell",
        "Tor RELAY cell received carrying a command the relay does not implement",
        json!({
            "type": "detect_relay_cell",
            "message": "EXTEND cell on circuit 0x00000005 - not supported, ignoring"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "circuit_id".to_string(),
            type_hint: "string".to_string(),
            description: "Circuit ID (hex format)".to_string(),
            required: true,
        },
        Parameter {
            name: "relay_command".to_string(),
            type_hint: "string".to_string(),
            description: "RELAY command name (EXTEND, TRUNCATE, RESOLVE, DROP, UNKNOWN, ...)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "stream_id".to_string(),
            type_hint: "number".to_string(),
            description: "Stream ID within the circuit".to_string(),
            required: true,
        },
        Parameter {
            name: "length".to_string(),
            type_hint: "number".to_string(),
            description: "Length of RELAY cell data".to_string(),
            required: true,
        },
        Parameter {
            name: "client_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Client IP address".to_string(),
            required: true,
        },
    ])
    .with_actions(tor_relay_response_actions())
});

pub fn get_tor_relay_event_types() -> Vec<EventType> {
    vec![
        TOR_RELAY_CIRCUIT_CREATED_EVENT.clone(),
        TOR_RELAY_RELAY_CELL_EVENT.clone(),
    ]
}

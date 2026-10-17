//! CAN bus actions and events — what the model sees, and what it can do about it.
//!
//! # Structured fields, and one honest hex field
//!
//! Everything about a frame that has meaning as a *value* is a named field: `id`, `extended`,
//! `rtr`, `fd`, `brs`, `dlc`. None of it is a bit position the model has to compute.
//!
//! The payload is different, and it is the one place in this protocol where a hex string is the
//! right answer rather than a shortcut. **CAN data is genuinely opaque.** Eight octets mean
//! whatever a DBC file says they mean — engine speed as a 16-bit big-endian value scaled by 0.25
//! starting at bit 24, say — and NetGet does not have the DBC file. There is no structure to
//! expose because the structure is not in the protocol; it is in a database owned by whoever
//! built the vehicle. So `data` is hex, `encoding` says so, and `"hex"` is the **default**, which
//! is unusual in this codebase and deliberate here: there is no text interpretation to fall back
//! to. `"text"` is offered because ASCII payloads do occur — a VIN in a UDS response, some
//! telematics gateways — and writing `"484921"` for `"HI!"` helps nobody.
//!
//! [`crate::server::can::frame::CanFrame::from_action`] **really decodes what `encoding` says**
//! and never sniffs. `"48656c6c6f"` is simultaneously valid text and valid hex and only the
//! sender knows which it meant; the root `CLAUDE.md` records `send_tcp_data` documenting hex in
//! three places while its executor called `as_bytes()`, which put literal ASCII on the wire.
//!
//! # There is no action that emits an error frame, and that is a safety property
//!
//! A CAN error frame is not a message. It is six dominant bits transmitted *on top of* a frame
//! in flight, which destroys that frame and forces every node to discard it; the transmitter
//! then increments its error counter, and enough of them drive it error-passive and then bus-off.
//! Emitting one to signal "NetGet's backend is down" would corrupt somebody else's traffic and
//! could take a node off the bus. So the vocabulary here cannot express one, and an LLM failure
//! transmits nothing at all. See this protocol's `CLAUDE.md`.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::can::frame::CanFrame;
use anyhow::{anyhow, Result};
use serde_json::json;
use std::sync::LazyLock;

/// The action that says "say nothing", as a real decision rather than an absence.
pub const NO_RESPONSE_ACTION: &str = "no_response";
/// The action that puts a frame on the bus.
pub const SEND_CAN_FRAME_ACTION: &str = "send_can_frame";

/// Default CAN interface. `can0` is the conventional first hardware interface; `vcan0` is the
/// conventional virtual one, and is what a test on Linux would use.
pub const DEFAULT_INTERFACE: &str = "can0";

// =================================================================================================
// Events
// =================================================================================================

/// A data or remote frame arrived. The ordinary case, and the one an ECU simulator answers.
pub static CAN_FRAME_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "can_frame_received",
        "A CAN frame arrived on the bus. There is no addressing: this frame reached every node, \
         and every node decides for itself whether the identifier is one it answers. Reply with \
         send_can_frame if this identifier is one the ECU you are simulating owns, or with \
         no_response if it is not - saying nothing is the normal case on a CAN bus, not a \
         failure.",
        json!({
            "type": "send_can_frame",
            "id": "0x7E8",
            "extended": false,
            "data": "0341050f",
            "encoding": "hex"
        }),
    )
    .with_actions(can_actions())
    .with_alternative_example(json!({"type": "no_response"}))
    .with_parameters(vec![
        Parameter {
            name: "id".to_string(),
            type_hint: "string".to_string(),
            description: "Identifier in hex, e.g. '0x7DF' (11-bit) or '0x18DAF110' (29-bit)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "extended".to_string(),
            type_hint: "boolean".to_string(),
            description: "True for a 29-bit identifier, false for 11-bit. Never inferred from \
                          the identifier's magnitude - 0x123 is legal in both formats and they \
                          are different frames."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "rtr".to_string(),
            type_hint: "boolean".to_string(),
            description: "Remote transmission request: another node is asking for this \
                          identifier's data and sent none of its own. The dlc says how many \
                          bytes it wants."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "dlc".to_string(),
            type_hint: "number".to_string(),
            description: "Data length code. Equal to the byte count for classic CAN; for CAN FD \
                          it is a length CODE, where 9..15 mean 12, 16, 20, 24, 32, 48 and 64 \
                          bytes."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The payload, hex-encoded (data_encoding is always 'hex' on receive). \
                          CAN payloads are opaque: their meaning lives in a DBC file."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "fd".to_string(),
            type_hint: "boolean".to_string(),
            description: "True for a CAN FD frame (up to 64 bytes), false for classic CAN 2.0"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "brs".to_string(),
            type_hint: "boolean".to_string(),
            description: "CAN FD bit-rate switch: the data phase ran at the faster bit rate"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "interface".to_string(),
            type_hint: "string".to_string(),
            description: "CAN interface the frame arrived on, e.g. 'can0' or 'vcan0'".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("CAN {interface} rx {id} dlc={dlc}")
            .with_debug("CAN rx: id={id} ext={extended} rtr={rtr} fd={fd} dlc={dlc} data={data}")
            .with_trace("CAN rx: {json_pretty(.)}"),
    )
});

/// The controller reported an error condition on the bus.
pub static CAN_ERROR_FRAME_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "can_error_frame",
        "The CAN controller delivered an error frame. This is a report from the local controller \
         about the state of the bus - a lost arbitration, a missing acknowledgement, a protocol \
         violation - and NOT a message any node sent you. You cannot reply to it with an error \
         frame: NetGet has no action that emits one, because an error frame corrupts whatever is \
         in flight and repeated ones drive nodes off the bus. Answer with no_response unless the \
         condition means the ECU you simulate should transmit something.",
        json!({"type": "no_response"}),
    )
    .with_actions(can_actions())
    .with_alternative_example(json!({
        "type": "send_can_frame",
        "id": "0x7E8",
        "data": "03410c1aF8",
        "encoding": "hex"
    }))
    .with_parameters(vec![
        Parameter {
            name: "error_classes".to_string(),
            type_hint: "array".to_string(),
            description: "Decoded error classes, e.g. ['no_acknowledgement'], \
                          ['arbitration_lost'], ['controller_problem'], ['bus_off']"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "id_decimal".to_string(),
            type_hint: "number".to_string(),
            description: "The raw error class bitmask, for anyone who wants the bits".to_string(),
            required: true,
        },
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The eight controller detail octets, hex-encoded".to_string(),
            required: true,
        },
        Parameter {
            name: "interface".to_string(),
            type_hint: "string".to_string(),
            description: "CAN interface reporting the error".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("CAN {interface} error frame {error_classes}")
            .with_debug("CAN error frame: classes={error_classes} detail={data}")
            .with_trace("CAN error frame: {json_pretty(.)}"),
    )
});

/// The controller crossed an error-confinement boundary.
pub static CAN_BUS_STATE_CHANGED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "can_bus_state_changed",
        "The local CAN controller changed error-confinement state. The ladder is error_active -> \
         error_warning -> error_passive -> bus_off, driven by the controller's own error \
         counters. At bus_off the controller has disconnected itself: nothing you transmit will \
         reach the bus until it is restarted. Usually the right answer is no_response; \
         transmitting into a degrading bus makes it worse.",
        json!({"type": "no_response"}),
    )
    .with_actions(can_actions())
    .with_parameters(vec![
        Parameter {
            name: "bus_state".to_string(),
            type_hint: "string".to_string(),
            description: "One of 'error_active', 'error_warning', 'error_passive', 'bus_off'"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "previous_state".to_string(),
            type_hint: "string".to_string(),
            description: "The state being left".to_string(),
            required: true,
        },
        Parameter {
            name: "error_classes".to_string(),
            type_hint: "array".to_string(),
            description: "Error classes of the frame that reported the change".to_string(),
            required: true,
        },
        Parameter {
            name: "interface".to_string(),
            type_hint: "string".to_string(),
            description: "CAN interface whose state changed".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("CAN {interface} bus state {previous_state} -> {bus_state}")
            .with_debug("CAN bus state change: {previous_state} -> {bus_state} ({error_classes})")
            .with_trace("CAN bus state: {json_pretty(.)}"),
    )
});

// =================================================================================================
// Actions
// =================================================================================================

/// Everything the model may do, in the order it should consider them.
///
/// The same set is returned by `get_sync_actions`, `get_async_actions` and every event's
/// `.with_actions(...)`. A CAN bus has no request/response pairing at the protocol level, so
/// there is no narrowing to express: anything that can be sent unprompted can be sent in reply.
pub fn can_actions() -> Vec<ActionDefinition> {
    vec![send_can_frame_action(), no_response_action()]
}

fn send_can_frame_action() -> ActionDefinition {
    ActionDefinition {
        name: SEND_CAN_FRAME_ACTION.to_string(),
        description:
            "Transmit one CAN frame. It reaches every node on the bus - there is no addressing \
             and no authentication, so the identifier alone decides who treats it as theirs. \
             Diagnostic convention: a tester requests on 0x7DF (broadcast) or 0x7E0+n, and ECU n \
             answers on 0x7E8+n."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "id".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Identifier, hex with or without the 0x prefix ('0x7E8', '7E8') or a decimal \
                     number. 11 bits (max 0x7FF) unless 'extended' is true, then 29 (max \
                     0x1FFFFFFF)."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "extended".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "True for a 29-bit identifier. Default false. State it explicitly: it is NOT \
                     inferred from the identifier's size, because 0x123 is a legal identifier in \
                     both formats and they are different frames that different nodes answer."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description:
                    "The payload (see 'encoding'). 0-8 bytes for classic CAN; 0-8, 12, 16, 20, \
                     24, 32, 48 or 64 for CAN FD - no other FD length exists, and one that is not \
                     encodable is refused rather than padded. Omit for a zero-length frame."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "encoding".to_string(),
                type_hint: "string".to_string(),
                description:
                    "How 'data' is written: 'hex' (the default - CAN payloads are opaque bytes \
                     whose meaning lives in a DBC file) or 'text' for ASCII. This is read, not \
                     guessed: '48656c6c6f' is valid hex AND valid text and only you know which \
                     you meant."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "rtr".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "Send a remote transmission request instead of data: ask whichever node owns \
                     this identifier to transmit it. Carries no payload; 'dlc' says how many \
                     bytes are being requested. Not available on CAN FD."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "dlc".to_string(),
                type_hint: "number".to_string(),
                description: "Bytes requested by a remote frame, 0-8. Ignored on a data frame, \
                              whose length comes from 'data'."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "fd".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "Send a CAN FD frame (payloads up to 64 bytes). Default false. The bus and \
                     every listening node must support FD; a classic-only node sees an error."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "brs".to_string(),
                type_hint: "boolean".to_string(),
                description: "CAN FD bit-rate switch: run the data phase at the faster bit rate. \
                              Requires 'fd'."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_can_frame",
            "id": "0x7E8",
            "extended": false,
            "data": "0341050f",
            "encoding": "hex"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> CAN {id} {data}")
                .with_debug("CAN tx: id={id} ext={extended} rtr={rtr} fd={fd} data={data}"),
        ),
    }
}

fn no_response_action() -> ActionDefinition {
    ActionDefinition {
        name: NO_RESPONSE_ACTION.to_string(),
        description:
            "Transmit nothing, deliberately. On a CAN bus this is the normal outcome: every frame \
             reaches every node and almost every node ignores almost every frame. Use it whenever \
             the identifier is not one the ECU you are simulating owns. It is a real decision and \
             is logged as one (decision=model_reject), distinct from failing to answer."
                .to_string(),
        parameters: vec![],
        example: json!({"type": "no_response"}),
        log_template: Some(LogTemplate::new().with_info("-> CAN silent (no_response)")),
    }
}

// =================================================================================================
// The protocol
// =================================================================================================

/// CAN bus (SocketCAN) server
pub struct CanProtocol;

impl CanProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CanProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for CanProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "interface".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "CAN interface to bind, e.g. 'can0' or 'vcan0' (default: {DEFAULT_INTERFACE}). \
                     It must already exist and be up. A virtual bus needs no hardware: `sudo \
                     modprobe vcan && sudo ip link add dev vcan0 type vcan && sudo ip link set up \
                     vcan0`."
                ),
                required: false,
                example: json!("vcan0"),
                default: None,
            },
            ParameterDefinition {
                name: "transport".to_string(),
                type_hint: "string".to_string(),
                description:
                    "'socketcan' (default) for a real AF_CAN socket, which exists only on Linux; \
                     'udp' for the unprivileged TEST transport, which carries SocketCAN frame \
                     structs as UDP datagram payloads and which no real CAN node speaks."
                        .to_string(),
                required: false,
                example: json!("socketcan"),
                default: None,
            },
            ParameterDefinition {
                name: "udp_peer".to_string(),
                type_hint: "string".to_string(),
                description:
                    "HOST:PORT to transmit to on the 'udp' test transport when nothing has been \
                     received yet. Rejected with transport 'socketcan', where it would do nothing."
                        .to_string(),
                required: false,
                example: json!("127.0.0.1:34567"),
                default: None,
            },
        ]
    }

    /// A frame can be transmitted at any time, not only in reply to one.
    ///
    /// A CAN bus is a broadcast medium with no sessions: an ECU simulator sending a periodic
    /// status frame is doing exactly what a real one does.
    fn get_async_actions(
        &self,
        _state: &crate::state::app_state::AppState,
    ) -> Vec<ActionDefinition> {
        can_actions()
    }

    /// The same set. There is nothing a reply may do that an unprompted transmission may not.
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        can_actions()
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CAN_FRAME_RECEIVED_EVENT.clone(),
            CAN_ERROR_FRAME_EVENT.clone(),
            CAN_BUS_STATE_CHANGED_EVENT.clone(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "CAN"
    }

    fn stack_name(&self) -> &'static str {
        "CAN"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "can",
            "canbus",
            "socketcan",
            "automotive",
            "ecu",
            "obd",
            "obd2",
            "j1939",
            "vcan",
            "canfd",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // Binding an AF_CAN socket needs no privilege. Bringing the *interface* up does, and
            // so does creating a vcan device, but those are done before NetGet runs and spawn()
            // fails with the `ip link` command to run if they were not. Declaring Root here would
            // refuse to start for every user who can in fact open the socket - the "don't claim
            // more than you need" rule that ospf got wrong.
            .privilege_requirement(PrivilegeRequirement::None)
            // A CAN bus is a broadcast medium with no connections at all. The per-identifier
            // bookkeeping entries exist only so the dashboard can show traffic, and the
            // 10-second idle sweep is exactly what should reap them.
            .connectionless()
            // Deliberately silent: CAN has no error reply. An error frame destroys the frame in
            // flight for every node and drives controllers toward bus-off, and a data frame asserts
            // a value or command to the whole bus. Nodes ignoring frames is the normal state.
            .deliberately_silent()
            .implementation(
                "Frame representation, validation and the SocketCAN struct can_frame / \
                 canfd_frame wire encoding are a pure module (src/server/can/frame.rs) with no \
                 socket, no cfg and no state. Two transports sit on it: a real AF_CAN socket via \
                 the socketcan crate on Linux, and a UDP test transport carrying the same frame \
                 structs in datagrams. On macOS and Windows the socketcan transport returns an \
                 error naming the reason instead of starting.",
            )
            .llm_control(
                "The model is the ECU. It sees can_frame_received (id, extended, rtr, error, \
                 dlc, hex data, fd, brs, interface), can_error_frame (decoded error classes) and \
                 can_bus_state_changed (the error-confinement ladder), and answers with \
                 send_can_frame or no_response. There is no action that emits a CAN error frame, \
                 deliberately: an error frame corrupts traffic in flight and repeated ones drive \
                 nodes bus-off.",
            )
            .e2e_testing(
                "The codec is asserted against literal values - both DLC tables in both \
                 directions, all sixteen CAN FD length codes, standard vs extended identifiers, \
                 RTR, error-class decoding, the 16- and 72-octet struct layouts, and an \
                 over-length payload being refused rather than truncated. The whole event -> \
                 handler/LLM -> action -> frame path runs in-process over the UDP test transport \
                 (tests/server/can/e2e_test.rs), including the assertion that an LLM failure puts \
                 nothing on the bus. The AF_CAN transport is covered by none of it.",
            )
            .notes(
                "VERIFIED: frame construction, validation and the SocketCAN wire layout, against \
                 literal values; that the CAN FD DLC is treated as a length CODE and not a byte \
                 count; that an unencodable FD length is refused; that macOS/Windows refuse to \
                 start with an explicit reason rather than reporting Running; and the full \
                 event/action path over the UDP test transport. NOT VERIFIED: the SocketCAN \
                 transport has never been compiled or run. AF_CAN exists only in the Linux \
                 kernel, the machine this was written on is macOS, and no frame this code \
                 produced has reached a real CAN bus or a real CAN peer. Treat first use on Linux \
                 as bring-up. Experimental, not Beta, for exactly that reason - the path to Beta \
                 is cheap and is written down in src/server/can/CLAUDE.md: Linux vcan needs no \
                 hardware and can-utils' cansend/candump are real third-party peers.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "CAN bus (SocketCAN) ECU simulator - Linux only, or a UDP test transport"
    }

    fn example_prompt(&self) -> &'static str {
        "Act as an engine ECU on the CAN bus: answer OBD-II requests on 0x7DF from 0x7E8, \
         reporting 2400 rpm and 88 degrees coolant temperature"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: the model is the ECU and reasons about each request.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "can",
                "instruction": "You are an engine control unit on a vehicle CAN bus. Answer \
                                OBD-II mode 01 requests addressed to 0x7DF or 0x7E0 by \
                                transmitting from 0x7E8. Ignore every other identifier.",
                "startup_params": {"interface": "vcan0"}
            }),
            // Script mode: a deterministic ECU, computed in-process with no model call.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "can",
                "startup_params": {"interface": "vcan0"},
                "event_handlers": [
                    {
                        "event_pattern": "can_frame_received",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": "actions = [{'type': 'send_can_frame', 'id': '0x7E8', 'data': '0341051e', 'encoding': 'hex'}] if event['data'].startswith('024105') else [{'type': 'no_response'}]"
                        }
                    }
                ]
            }),
            // Static mode: one fixed frame in reply to anything, with no model call.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "can",
                "startup_params": {"interface": "vcan0"},
                "event_handlers": [
                    {
                        "event_pattern": "can_*",
                        "handler": {
                            "type": "static",
                            "actions": [
                                {
                                    "type": "send_can_frame",
                                    "id": "0x7E8",
                                    "data": "0341050f",
                                    "encoding": "hex"
                                }
                            ]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for CanProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(async move {
            let listen_addr = ctx
                .socket_addr()
                .unwrap_or_else(|| ctx.legacy_listen_addr());
            crate::server::can::CanServer::spawn_with_llm_actions(
                listen_addr,
                ctx.interface.clone(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ctx.startup_params,
            )
            .await
        })
    }

    /// Turn one action into bytes the transport can put on the bus.
    ///
    /// `send_can_frame` returns the SocketCAN wire struct — 16 octets for a classic frame, 72 for
    /// an FD one — which is what both transports write. Building it here rather than in the
    /// server loop means the encoder runs at the action, so a bad identifier, an impossible CAN
    /// FD length or an `rtr` + `fd` combination is refused with the model watching instead of
    /// producing a frame the bus silently drops.
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("action must have a 'type' field"))?;

        match action_type {
            SEND_CAN_FRAME_ACTION => {
                let frame = CanFrame::from_action(&action)?;
                Ok(ActionResult::Output(frame.to_wire_bytes()?))
            }
            NO_RESPONSE_ACTION => Ok(ActionResult::NoAction),
            other => Err(anyhow!(
                "unknown CAN action {other:?}; expected one of {SEND_CAN_FRAME_ACTION}, \
                 {NO_RESPONSE_ACTION}"
            )),
        }
    }
}

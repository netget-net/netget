//! Actions, events and metadata for the generic raw IP protocol-N server.
//!
//! Nothing here is keyed on the operator's protocol number. There is one event and two
//! actions, and they read the same whether the socket is bound to GRE, ESP, SCTP or a number
//! IANA has never assigned — which is the point: this protocol is the generic home for IP
//! protocols that have no other, and the moment it grows a `match protocol_number` it has
//! stopped being that.

use std::sync::LazyLock;

use anyhow::{Context, Result};
use serde_json::json;

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::metadata::{DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2};
use crate::protocol::EventType;
use crate::server::rawip::{decode_payload, PayloadEncoding};
use crate::state::app_state::AppState;

/// Action name for "say nothing", so the executor and the server loop cannot disagree on it.
pub const NO_RESPONSE: &str = "no_response";

/// `ActionResult::Custom` name the server loop looks for when deciding what to emit.
pub const RAWIP_PACKET_RESULT: &str = "rawip_packet";

/// Generic raw IP protocol-N action handler.
pub struct RawIpProtocol;

impl Default for RawIpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl RawIpProtocol {
    pub fn new() -> Self {
        Self
    }

    /// Validate a `send_rawip_packet` action and turn its payload into real bytes.
    ///
    /// The decoding happens **here**, in the executor, not somewhere further down that might
    /// or might not be reached. `send_tcp_data` documented hex in three places and its
    /// executor called `as_bytes()`, so a model following the documentation put the ASCII of
    /// the hex digits on the wire (root `CLAUDE.md`, action & event design rules). The result
    /// carries `payload_hex` — the *decoded* bytes, hex-encoded once, unambiguously — so the
    /// server loop has nothing left to interpret.
    fn execute_send_packet(&self, action: serde_json::Value) -> Result<ActionResult> {
        let payload_text = action
            .get("payload")
            .and_then(|v| v.as_str())
            .context("send_rawip_packet requires a 'payload' string")?;

        let encoding = match action.get("encoding").and_then(|v| v.as_str()) {
            Some(e) => PayloadEncoding::parse(e)?,
            None => PayloadEncoding::Utf8,
        };
        let payload = decode_payload(payload_text, encoding)?;

        let destination = action
            .get("destination")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        if let Some(dest) = &destination {
            dest.parse::<std::net::IpAddr>().with_context(|| {
                format!("send_rawip_packet 'destination' is not an IP address: {dest:?}")
            })?;
        }

        let ttl = match action.get("ttl").and_then(|v| v.as_u64()) {
            Some(t) if t <= 255 => Some(t),
            Some(t) => {
                return Err(anyhow::anyhow!(
                    "send_rawip_packet 'ttl' must be 0..=255 (it is the IPv4 TTL or the IPv6 \
                     hop limit), got {t}"
                ))
            }
            None => None,
        };

        Ok(ActionResult::Custom {
            name: RAWIP_PACKET_RESULT.to_string(),
            data: json!({
                "destination": destination,
                "ttl": ttl,
                "payload_hex": hex::encode(&payload),
                "payload_length": payload.len(),
            }),
        })
    }
}

// ============================================================================
// Action definitions
//
// `call_llm` builds the model's tool list from `EventType::actions`, not from
// `get_sync_actions()`, so the event below must list both of these.
// ============================================================================

fn send_rawip_packet_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_rawip_packet".to_string(),
        description:
            "Send an IP packet carrying this payload, on the protocol number this server is \
             bound to. The payload is opaque to netget — it is whatever the protocol above IP \
             defines, and netget does not parse it. Say which encoding you are using: it is \
             never guessed."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "destination".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Destination IP address (IPv4 or IPv6, matching the server's ip_version). \
                     Normally the 'source' from the event you are answering — a raw socket has \
                     no connection to reply on, so the address has to be named."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "payload".to_string(),
                type_hint: "string".to_string(),
                description:
                    "The bytes to place after the IP header, written in the encoding named by \
                     'encoding'."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "encoding".to_string(),
                type_hint: "string".to_string(),
                description:
                    "How 'payload' is written: \"utf8\" (default — the text itself is the bytes) \
                     or \"hex\" (an even-length string of hex digits). This is never inferred: \
                     \"48656c6c6f\" is valid text and valid hex at once, and only you know \
                     which you meant. The event you are answering states the encoding it used \
                     for the payload it showed you."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "ttl".to_string(),
                type_hint: "number".to_string(),
                description:
                    "0-255. The IPv4 TTL, or the IPv6 hop limit — the same field under two \
                     names. Omit to use the socket's current value."
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_rawip_packet",
            "destination": "192.0.2.10",
            "payload": "0000",
            "encoding": "hex",
            "ttl": 64
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> raw IP packet to {destination}")
                .with_debug(
                    "rawip send_rawip_packet: dest={destination} ttl={ttl} encoding={encoding}",
                ),
        ),
    }
}

fn no_response_action() -> ActionDefinition {
    ActionDefinition {
        name: NO_RESPONSE.to_string(),
        description:
            "Say nothing. Use this when the right answer is silence — an observed packet that \
             needs no reply, or a protocol whose exchange you do not want to continue. It is a \
             decision, and it is logged as one (decision=model_reject), which is what makes it \
             different from answering nothing at all."
                .to_string(),
        parameters: vec![],
        example: json!({ "type": NO_RESPONSE }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> raw IP: no response")
                .with_debug("rawip no_response: deliberate silence"),
        ),
    }
}

fn rawip_actions() -> Vec<ActionDefinition> {
    vec![send_rawip_packet_action(), no_response_action()]
}

// ============================================================================
// Events
// ============================================================================

/// Raised for every packet whose IP header decodes. A packet that does not decode is dropped
/// and logged rather than surfaced: the event's contract is that its header fields are real.
pub static RAWIP_PACKET_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rawip_packet_received",
        "An IP packet arrived on the protocol number this server is bound to. The IP header is \
         decoded for you — version, addresses, ttl/hop_limit, fragmentation, and the protocol \
         number with its IANA name where one exists. The payload is NOT parsed: netget does \
         not implement the protocol above IP here, which is the whole reason this generic \
         server exists. 'payload_encoding' says whether 'payload' is the text itself (\"utf8\") \
         or hex digits (\"hex\"); echo the same convention back in your action. Answer with \
         send_rawip_packet to put bytes on the wire, or no_response to stay silent.",
        json!({
            "type": "send_rawip_packet",
            "destination": "192.0.2.10",
            "payload": "0000",
            "encoding": "hex",
            "ttl": 64
        }),
    )
    .with_actions(rawip_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("raw IP {protocol}/{protocol_name} from {source} ({payload_length} bytes)")
            .with_debug(
                "rawip packet: IPv{ip_version} {source} -> {destination} proto={protocol} \
                 ttl={ttl} payload={payload_length}",
            )
            .with_trace("rawip packet: {json_pretty(.)}"),
    )
});

// ============================================================================
// Protocol
// ============================================================================

impl Protocol for RawIpProtocol {
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        // A raw IP socket has no port. The host/port pair is carried anyway because the
        // flexible binding system needs a value: the host names the local address the raw
        // socket reports, and the port is what the UDP test transport binds.
        Some(crate::protocol::BindingDefaults::port_based("127.0.0.1", 0))
    }

    /// Deliberately empty. Every verb this protocol has needs the running server's socket,
    /// which the stateless registry object cannot reach — an async action would execute and
    /// put nothing on the wire, which is worse than not offering it.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        rawip_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "Raw IP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![RAWIP_PACKET_RECEIVED_EVENT.clone()]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP(N)"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "rawip",
            "raw ip",
            "ip protocol",
            "protocol number",
            "gre",
            "esp",
            "ah",
            "sctp",
        ]
    }

    fn startup_privilege_requirement(
        &self,

        startup_params: Option<&serde_json::Value>,
    ) -> crate::protocol::metadata::PrivilegeRequirement {
        // The UDP test transport carries the same frames over an ordinary socket.

        crate::llm::actions::protocol_trait::unless_udp_transport(
            self.metadata().privilege_requirement,
            startup_params,
        )
    }

    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // SOCK_RAW on an operator-chosen protocol number. CAP_NET_RAW is enough on
            // Linux, so Root would refuse a capability-only process that could in fact run.
            .privilege_requirement(PrivilegeRequirement::RawSockets)
            // Per-remote bookkeeping entries with no lifecycle, exactly like the UDP and raw
            // servers: nothing ever closes them, so the idle sweep must reap them.
            .connectionless()
            // Deliberately silent: this server carries an arbitrary IP protocol it does not
            // understand, so there is no error frame to send - any bytes would be a guess at a
            // protocol NetGet does not implement, and a guess a peer parses is worse than silence.
            .deliberately_silent()
            .implementation(
                "Generic SOCK_RAW listener on one operator-chosen IP protocol number \
                 (startup parameter `protocol_number`, IPv4 or IPv6). Hand-written IPv4 (RFC \
                 791) and IPv6 (RFC 8200) fixed-header decoders; the payload is surfaced \
                 opaquely with an explicit utf8/hex encoding and is never parsed. There is no \
                 per-protocol branching anywhere in the module and there must not be: a \
                 protocol worth parsing deserves its own module. IPv6 extension headers are \
                 not walked. Also carries an unprivileged `transport: \"udp\"` test transport \
                 that reads whole IP packets out of UDP datagrams.",
            )
            .llm_control(
                "Everything above the IP header. The model sees the decoded header fields plus \
                 the opaque payload and answers with send_rawip_packet (destination, ttl/hop \
                 limit, payload with an explicit encoding) or no_response. netget contributes \
                 no protocol semantics of its own, because by construction it has none for an \
                 arbitrary protocol number.",
            )
            .e2e_testing(
                "The IP header decoder is tested against literal packet bytes: IPv4 with and \
                 without options, a fragmented IPv4 packet, IPv6, and truncated/malformed \
                 inputs that must be refused rather than panic. The full event -> LLM -> action \
                 path, including the hex payload round trip and the silent LLM-failure path, \
                 runs over the unprivileged UDP test transport against a mock model. The raw \
                 socket itself is never opened by any test.",
            )
            .notes(
                "PROVEN: the IP header decoder, against literal RFC 791 / RFC 8200 bytes, \
                 including refusal of truncated and malformed headers; the executor's hex \
                 decoding (a payload sent as hex arrives as those bytes, not as that ASCII \
                 text); and the deliberate silence on LLM failure. NOT PROVEN: the raw socket \
                 transport, which has never been executed — opening SOCK_RAW needs root or \
                 CAP_NET_RAW, so no test in this repo has bound one, sent on one, or received \
                 on one. Nothing about outgoing TTL/hop-limit handling, the kernel's own IP \
                 header construction, or IPv6 raw-socket behaviour (where the kernel strips \
                 the header on receive, so the decoder would see only the payload) has been \
                 observed. Note also that the privilege gate in server_startup is driven by \
                 this static metadata, so `transport: \"udp\"` does NOT make the protocol \
                 startable unprivileged through the normal path — the test transport is \
                 reached by calling RawIpServer::spawn_with_llm_actions directly. PATH TO \
                 BETA: run it under sudo against a real peer sending a real protocol — GRE \
                 (47) from a Linux `ip tunnel` endpoint is the obvious case — and assert both \
                 directions.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Generic raw IP listener for any protocol number (GRE, ESP, AH, SCTP, ...)"
    }

    fn example_prompt(&self) -> &'static str {
        "Listen for IP protocol 47 (GRE) packets and show me the header of everything that arrives"
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        // All three are read by `RawIpConfig::from_startup_params` in mod.rs, which is the
        // only place any of them is consulted.
        vec![
            ParameterDefinition {
                name: "protocol_number".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "The IP protocol number to bind the raw socket to, 0-255. This is the only \
                     thing that makes the server specific: 47 = GRE, 50 = ESP, 51 = AH, \
                     132 = SCTP, and anything else IANA has assigned or not. 6 (TCP) and 17 \
                     (UDP) are refused — netget implements those properly as the 'tcp' and \
                     'udp' protocols, and a raw socket would fight the kernel for the packets."
                        .to_string(),
                required: true,
                example: json!(47),
                default: None,
            },
            ParameterDefinition {
                name: "ip_version".to_string(),
                type_hint: "string".to_string(),
                description:
                    "\"ipv4\" (default) or \"ipv6\". Selects the socket domain and which header \
                     format the decoder expects."
                        .to_string(),
                required: false,
                example: json!("ipv4"),
                default: None,
            },
            ParameterDefinition {
                name: "transport".to_string(),
                type_hint: "string".to_string(),
                description: "\"raw\" (default) opens the real SOCK_RAW socket and needs root or \
                     CAP_NET_RAW. \"udp\" is a TEST transport: it binds a UDP socket and reads \
                     each datagram as a whole IP packet, so the decode/event/action path can \
                     run unprivileged. Never use \"udp\" in production — nothing on a real \
                     network sends IP packets inside UDP datagrams."
                    .to_string(),
                required: false,
                example: json!("raw"),
                default: None,
            },
        ]
    }

    fn group_name(&self) -> &'static str {
        "VPN & Routing"
    }

    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "rawip",
                "startup_params": { "protocol_number": 47 },
                "instruction": "Listen for GRE (IP protocol 47). Report the IP header of every \
                                packet and stay silent unless I tell you to answer."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "rawip",
                "startup_params": { "protocol_number": 50 },
                "event_handlers": [{
                    "event_pattern": "rawip_packet_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "return {type='send_rawip_packet', destination=event.source, payload=event.payload, encoding=event.payload_encoding}"
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "rawip",
                "startup_params": { "protocol_number": 132 },
                "event_handlers": [{
                    "event_pattern": "rawip_packet_received",
                    "handler": {
                        "type": "static",
                        "actions": [{ "type": NO_RESPONSE }]
                    }
                }]
            }),
        )
    }
}

impl Server for RawIpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::rawip::RawIpServer;
            let listen_addr = ctx
                .socket_addr()
                .unwrap_or_else(|| ctx.legacy_listen_addr());
            RawIpServer::spawn_with_llm_actions(
                listen_addr,
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
            .context("Missing action type")?;

        match action_type {
            "send_rawip_packet" => self.execute_send_packet(action),
            NO_RESPONSE => Ok(ActionResult::NoAction),
            other => Err(anyhow::anyhow!("Unknown Raw IP action type: {other}")),
        }
    }
}

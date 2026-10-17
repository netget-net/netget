//! TUN/TAP endpoint: action, event and metadata declarations.
//!
//! The wire work is in [`super::packet`]; the pipeline is in [`super`]. This file is the
//! contract with the model: which packets it can be told about, what it may say back, and what
//! the operator may configure.
//!
//! Two rules shape everything here, and both are recorded in `src/server/tuntap/CLAUDE.md`:
//!
//! 1. **Nothing raw crosses this boundary.** Events carry decoded header fields; `send_packet`
//!    takes fields and NetGet builds the bytes. The one opaque thing — a payload — travels as a
//!    short preview with an explicit `payload_encoding`, and the executor really decodes what
//!    that field names.
//! 2. **Silence is the failure.** There is no action that means "answer with an error", because
//!    a fabricated packet on a real interface is indistinguishable from a spoof.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;
use tracing::debug;

use super::packet;

/// A packet arrived on the interface and passed the deterministic filter.
pub static TUNTAP_PACKET_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tuntap_packet_received",
        "A packet was routed to the TUN/TAP interface and passed the server's packet_filter. \
         All header fields are decoded; the payload appears only as a short preview whose \
         encoding is named by payload_encoding. Most packets never reach this event - the \
         filter and the escalation budget drop them deterministically, which is what keeps an \
         interface endpoint usable at all.",
        json!({
            "type": "send_packet",
            "source": "10.7.0.2",
            "destination": "10.7.0.1",
            "protocol": "icmp",
            "icmp_type": "echo_reply",
            "icmp_id": 4660,
            "icmp_sequence": 1,
            "payload": "netget",
            "payload_encoding": "utf8"
        }),
    )
    .with_actions(vec![
        send_packet_action(),
        drop_packet_action(),
        no_response_action(),
    ])
    .with_parameters(vec![
        Parameter {
            name: "direction".to_string(),
            type_hint: "string".to_string(),
            description: "Always \"inbound\": the host routed this packet into the interface, so it is arriving at NetGet.".to_string(),
            required: true,
        },
        Parameter {
            name: "ip_version".to_string(),
            type_hint: "number".to_string(),
            description: "4 or 6.".to_string(),
            required: true,
        },
        Parameter {
            name: "source".to_string(),
            type_hint: "string".to_string(),
            description: "Source IP address.".to_string(),
            required: true,
        },
        Parameter {
            name: "destination".to_string(),
            type_hint: "string".to_string(),
            description: "Destination IP address.".to_string(),
            required: true,
        },
        Parameter {
            name: "protocol".to_string(),
            type_hint: "string".to_string(),
            description: "Protocol name, e.g. \"tcp\", \"udp\", \"icmp\", \"icmpv6\". \"unknown\" when the number has no name here.".to_string(),
            required: true,
        },
        Parameter {
            name: "protocol_number".to_string(),
            type_hint: "number".to_string(),
            description: "IANA IP protocol number, so nothing is lost when the name is \"unknown\".".to_string(),
            required: true,
        },
        Parameter {
            name: "ttl".to_string(),
            type_hint: "number".to_string(),
            description: "IPv4 time-to-live. IPv6 packets carry \"hop_limit\" instead.".to_string(),
            required: false,
        },
        Parameter {
            name: "hop_limit".to_string(),
            type_hint: "number".to_string(),
            description: "IPv6 hop limit. IPv4 packets carry \"ttl\" instead.".to_string(),
            required: false,
        },
        Parameter {
            name: "total_length".to_string(),
            type_hint: "number".to_string(),
            description: "Total IP packet length in bytes, as the header declares it.".to_string(),
            required: true,
        },
        Parameter {
            name: "source_port".to_string(),
            type_hint: "number".to_string(),
            description: "TCP/UDP source port. Absent for other protocols.".to_string(),
            required: false,
        },
        Parameter {
            name: "destination_port".to_string(),
            type_hint: "number".to_string(),
            description: "TCP/UDP destination port. Absent for other protocols.".to_string(),
            required: false,
        },
        Parameter {
            name: "tcp_flags".to_string(),
            type_hint: "array".to_string(),
            description: "TCP flags set, as names: fin, syn, rst, psh, ack, urg, ece, cwr. A [\"syn\"] with no \"ack\" is a new connection attempt.".to_string(),
            required: false,
        },
        Parameter {
            name: "seq".to_string(),
            type_hint: "number".to_string(),
            description: "TCP sequence number.".to_string(),
            required: false,
        },
        Parameter {
            name: "ack".to_string(),
            type_hint: "number".to_string(),
            description: "TCP acknowledgement number.".to_string(),
            required: false,
        },
        Parameter {
            name: "window".to_string(),
            type_hint: "number".to_string(),
            description: "TCP advertised window.".to_string(),
            required: false,
        },
        Parameter {
            name: "icmp_type".to_string(),
            type_hint: "string".to_string(),
            description: "ICMP type name, e.g. \"echo_request\", \"time_exceeded\".".to_string(),
            required: false,
        },
        Parameter {
            name: "icmp_type_number".to_string(),
            type_hint: "number".to_string(),
            description: "ICMP type number, for types with no name here.".to_string(),
            required: false,
        },
        Parameter {
            name: "icmp_code".to_string(),
            type_hint: "number".to_string(),
            description: "ICMP code.".to_string(),
            required: false,
        },
        Parameter {
            name: "icmp_id".to_string(),
            type_hint: "number".to_string(),
            description: "Echo identifier. Copy it into the reply or the sender will ignore it.".to_string(),
            required: false,
        },
        Parameter {
            name: "icmp_sequence".to_string(),
            type_hint: "number".to_string(),
            description: "Echo sequence number. Copy it into the reply.".to_string(),
            required: false,
        },
        Parameter {
            name: "ethernet".to_string(),
            type_hint: "object".to_string(),
            description: "TAP mode only: {source_mac, destination_mac, ethertype}. Absent in TUN mode, which has no link layer.".to_string(),
            required: false,
        },
        Parameter {
            name: "payload_length".to_string(),
            type_hint: "number".to_string(),
            description: "True length of the transport payload in bytes, whatever the preview shows.".to_string(),
            required: true,
        },
        Parameter {
            name: "payload_preview".to_string(),
            type_hint: "string".to_string(),
            description: "At most 64 bytes of the payload, encoded as payload_encoding says. A preview, not the payload - use payload_length for the real size.".to_string(),
            required: true,
        },
        Parameter {
            name: "payload_encoding".to_string(),
            type_hint: "string".to_string(),
            description: "\"utf8\" when the previewed bytes were all printable ASCII, otherwise \"hex\". NetGet decides once and states the answer here; never guess.".to_string(),
            required: true,
        },
        Parameter {
            name: "summary".to_string(),
            type_hint: "string".to_string(),
            description: "One-line human-readable rendering of the packet.".to_string(),
            required: true,
        },
    ])
    .with_alternative_example(json!({
        "type": "drop_packet",
        "reason": "not addressed to a service this endpoint answers for"
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("TUN/TAP packet {summary}")
            .with_debug("TUN/TAP {protocol} {source} > {destination} len={total_length}")
            .with_trace("TUN/TAP {summary} payload({payload_encoding})={payload_preview}"),
    )
});

/// The interface was created and is carrying traffic.
pub static TUNTAP_INTERFACE_UP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tuntap_interface_up",
        "The TUN/TAP interface is up and NetGet is now the far end of it. Raised once per \
         server. The configured packet_filter and escalation budget are reported so the answer \
         can be written knowing how much traffic will actually be seen.",
        json!({"type": "no_response"}),
    )
    .with_actions(vec![send_packet_action(), no_response_action()])
    .with_parameters(vec![
        Parameter {
            name: "interface".to_string(),
            type_hint: "string".to_string(),
            description: "Interface name the operating system assigned, e.g. \"utun7\" or \"tun0\".".to_string(),
            required: true,
        },
        Parameter {
            name: "mode".to_string(),
            type_hint: "string".to_string(),
            description: "\"tun\" (layer 3, bare IP) or \"tap\" (layer 2, Ethernet).".to_string(),
            required: true,
        },
        Parameter {
            name: "address".to_string(),
            type_hint: "string".to_string(),
            description: "Local address assigned to the interface.".to_string(),
            required: true,
        },
        Parameter {
            name: "netmask".to_string(),
            type_hint: "string".to_string(),
            description: "Netmask of the interface.".to_string(),
            required: true,
        },
        Parameter {
            name: "mtu".to_string(),
            type_hint: "number".to_string(),
            description: "Interface MTU.".to_string(),
            required: true,
        },
        Parameter {
            name: "packet_filter".to_string(),
            type_hint: "string".to_string(),
            description: "The filter expression deciding which packets become events at all.".to_string(),
            required: true,
        },
        Parameter {
            name: "llm_escalation".to_string(),
            type_hint: "string".to_string(),
            description: "\"never\" or \"unhandled\" - whether a packet no handler answered may reach the model.".to_string(),
            required: true,
        },
        Parameter {
            name: "llm_max_per_minute".to_string(),
            type_hint: "number".to_string(),
            description: "Ceiling on model consultations per minute. Packets over it are dropped, not queued.".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new().with_info("TUN/TAP interface {interface} up ({mode}, {address}/{netmask}, mtu {mtu})"),
    )
});

/// The interface stopped carrying traffic.
pub static TUNTAP_INTERFACE_DOWN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "tuntap_interface_down",
        "The TUN/TAP interface stopped carrying traffic - the server was stopped or the device \
         closed. Informational: the interface is already gone, so no packet can be sent in \
         reply. The packet counters for the whole run are included.",
        json!({"type": "no_response"}),
    )
    .with_actions(vec![no_response_action()])
    .with_parameters(vec![
        Parameter {
            name: "interface".to_string(),
            type_hint: "string".to_string(),
            description: "Interface name that went down.".to_string(),
            required: true,
        },
        Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Why the interface stopped: \"stopped\", \"closed\" or an error description.".to_string(),
            required: true,
        },
        Parameter {
            name: "packets_received".to_string(),
            type_hint: "number".to_string(),
            description: "Packets read from the interface over the run.".to_string(),
            required: true,
        },
        Parameter {
            name: "packets_escalated".to_string(),
            type_hint: "number".to_string(),
            description: "Of those, how many became an event. The gap between this and packets_received is what the deterministic filter absorbed.".to_string(),
            required: true,
        },
        Parameter {
            name: "packets_sent".to_string(),
            type_hint: "number".to_string(),
            description: "Packets NetGet wrote back to the interface.".to_string(),
            required: true,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("TUN/TAP interface {interface} down: {reason}")
            .with_debug("TUN/TAP {interface} down: {reason}, received={packets_received} escalated={packets_escalated} sent={packets_sent}"),
    )
});

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// `send_packet` — the only action that puts anything on the interface.
///
/// Structured by construction: the model names the fields and NetGet lays out the headers and
/// computes every checksum. There is no byte-blob parameter, and there is no way to ask for a
/// packet NetGet cannot account for field by field.
pub fn send_packet_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_packet".to_string(),
        description:
            "Write one packet to the interface, described by its header fields. NetGet builds \
             the IP header, the transport header and every checksum. IPv4 and IPv6 are chosen \
             from the addresses, which must be the same family. For TAP (layer 2) interfaces \
             supply source_mac and destination_mac as well; for TUN supply neither. Anything \
             the model does not name takes a documented default - it is never guessed from the \
             packet being answered, so an echo reply must copy icmp_id and icmp_sequence \
             itself or the sender will ignore it."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "source".to_string(),
                type_hint: "string".to_string(),
                description: "Source IP address. Same family as destination.".to_string(),
                required: true,
            },
            Parameter {
                name: "destination".to_string(),
                type_hint: "string".to_string(),
                description: "Destination IP address. Same family as source.".to_string(),
                required: true,
            },
            Parameter {
                name: "protocol".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Protocol name (\"icmp\", \"icmpv6\", \"tcp\", \"udp\", \"gre\", \"esp\", \
                     \"ospf\", \"sctp\", \"vrrp\", \"igmp\", \"ah\") or an IANA number 0-255. \
                     \"icmp\" is IPv4-only and \"icmpv6\" IPv6-only; mixing them is refused."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "ip_version".to_string(),
                type_hint: "number".to_string(),
                description:
                    "4 or 6. Optional - it is derived from the addresses. Supplying one that \
                     contradicts them is refused rather than silently ignored."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "ttl".to_string(),
                type_hint: "number".to_string(),
                description: "IPv4 time-to-live, 0-255. Default 64.".to_string(),
                required: false,
            },
            Parameter {
                name: "hop_limit".to_string(),
                type_hint: "number".to_string(),
                description: "IPv6 hop limit, 0-255. Default 64. Synonym of ttl.".to_string(),
                required: false,
            },
            Parameter {
                name: "identification".to_string(),
                type_hint: "number".to_string(),
                description: "IPv4 identification field, 0-65535. Default 0.".to_string(),
                required: false,
            },
            Parameter {
                name: "source_port".to_string(),
                type_hint: "number".to_string(),
                description: "TCP/UDP source port. Required for tcp and udp.".to_string(),
                required: false,
            },
            Parameter {
                name: "destination_port".to_string(),
                type_hint: "number".to_string(),
                description: "TCP/UDP destination port. Required for tcp and udp.".to_string(),
                required: false,
            },
            Parameter {
                name: "flags".to_string(),
                type_hint: "array".to_string(),
                description: "TCP flags as names: fin, syn, rst, psh, ack, urg, ece, cwr. Default \
                     [\"ack\"]. An unknown name is refused rather than dropped."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "seq".to_string(),
                type_hint: "number".to_string(),
                description: "TCP sequence number. Default 0.".to_string(),
                required: false,
            },
            Parameter {
                name: "ack".to_string(),
                type_hint: "number".to_string(),
                description: "TCP acknowledgement number. Default 0.".to_string(),
                required: false,
            },
            Parameter {
                name: "window".to_string(),
                type_hint: "number".to_string(),
                description: "TCP window. Default 65535.".to_string(),
                required: false,
            },
            Parameter {
                name: "icmp_type".to_string(),
                type_hint: "string".to_string(),
                description: "ICMP type name (\"echo_request\", \"echo_reply\", \
                     \"destination_unreachable\", \"time_exceeded\", \"packet_too_big\", \
                     \"neighbor_advertisement\", ...) or a number. Required for icmp/icmpv6."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "icmp_code".to_string(),
                type_hint: "number".to_string(),
                description: "ICMP code, 0-255. Default 0.".to_string(),
                required: false,
            },
            Parameter {
                name: "icmp_id".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Echo identifier for echo_request/echo_reply. Copy the one from the packet \
                     being answered; the sender matches on it."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "icmp_sequence".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Echo sequence for echo_request/echo_reply. Copy the one from the packet \
                     being answered."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "source_mac".to_string(),
                type_hint: "string".to_string(),
                description:
                    "TAP only: source MAC, aa:bb:cc:dd:ee:ff. Must be supplied together with \
                     destination_mac, and only on a layer-2 interface."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "destination_mac".to_string(),
                type_hint: "string".to_string(),
                description: "TAP only: destination MAC. See source_mac.".to_string(),
                required: false,
            },
            Parameter {
                name: "payload".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Transport payload as text, or as hex digits when payload_encoding is \
                     \"hex\". Omit for a header-only packet."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "payload_encoding".to_string(),
                type_hint: "string".to_string(),
                description: "How to read \"payload\": \"utf8\" (default) or \"hex\". It is never \
                     guessed - \"48656c6c6f\" is both valid text and valid hex, and only the \
                     sender knows which was meant. Invalid hex is refused, not sent as text."
                    .to_string(),
                required: false,
            }
            .with_choices(["utf8", "hex"]),
        ],
        example: json!({
            "type": "send_packet",
            "source": "10.7.0.2",
            "destination": "10.7.0.1",
            "protocol": "icmp",
            "icmp_type": "echo_reply",
            "icmp_code": 0,
            "icmp_id": 4660,
            "icmp_sequence": 1,
            "ttl": 64,
            "payload": "netget",
            "payload_encoding": "utf8"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("TUN/TAP send {protocol} {source} > {destination}")
                .with_debug("TUN/TAP send {protocol} {source} > {destination} ttl={ttl}"),
        ),
    }
}

/// `drop_packet` — the explicit, and correct, default.
pub fn drop_packet_action() -> ActionDefinition {
    ActionDefinition {
        name: "drop_packet".to_string(),
        description:
            "Discard this packet and send nothing. This is the right answer far more often \
             than not: the interface is real, and a packet NetGet cannot justify field by \
             field is a packet the host will treat as genuine. Dropping is also what happens \
             on any failure, so saying it explicitly is a way to record the decision in the \
             log rather than to change the outcome."
                .to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Why, for the log. Optional but worth writing.".to_string(),
            required: false,
        }],
        example: json!({
            "type": "drop_packet",
            "reason": "no service listens on this port"
        }),
        log_template: Some(LogTemplate::new().with_info("TUN/TAP drop: {reason}")),
    }
}

/// `no_response` — acknowledge without acting.
pub fn no_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "no_response".to_string(),
        description: "Acknowledge the event without writing anything to the interface. Use it for \
             lifecycle events, where there is nothing to answer. For a packet, drop_packet \
             says the same thing more precisely."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "no_response"}),
        log_template: None,
    }
}

/// TUN/TAP protocol declarations.
pub struct TunTapProtocol;

impl TunTapProtocol {
    /// Create the (stateless) protocol description the registry holds.
    pub fn new() -> Self {
        Self
    }
}

impl Default for TunTapProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for TunTapProtocol {
    /// Deliberately empty.
    ///
    /// Every verb this protocol has is an answer to a packet or a lifecycle event, and the
    /// sync list carries all of them. An async `send_packet` would need the live interface
    /// handle, which the stateless registry struct does not have - and advertising a verb the
    /// executor cannot fulfil is the "advertised but unexecutable" bug the whole-tree ratchets
    /// exist to catch.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_packet_action(),
            drop_packet_action(),
            no_response_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "TUN/TAP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            TUNTAP_PACKET_RECEIVED_EVENT.clone(),
            TUNTAP_INTERFACE_UP_EVENT.clone(),
            TUNTAP_INTERFACE_DOWN_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "TUN/TAP>IP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "tun",
            "tap",
            "tuntap",
            "tun/tap",
            "utun",
            "virtual interface",
            "network interface",
            "layer 3 interface",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // Creating a TUN or TAP device needs root on every platform this builds for:
            // /dev/net/tun on Linux, the utun control socket on macOS. Not CAP_NET_RAW, not
            // BPF access - the device does not exist until a privileged process asks for it.
            .privilege_requirement(PrivilegeRequirement::Root)
            .connectionless()
            // Deliberately silent: a packet written to a real TUN/TAP interface is indistinguishable
            // from a spoof, and NetGet does not know what the host expected, so a failure drops the
            // packet. There is no error frame at the IP layer that would not assert something.
            .deliberately_silent()
            .implementation("tun 0.8 (Linux /dev/net/tun, macOS utun) with a hand-written decoder and builder in packet.rs. Every packet routed to the interface is decoded to structured header fields - IPv4/IPv6, TCP, UDP, ICMP, ICMPv6, Ethernet for TAP - and tested against a deterministic packet_filter before anything else happens. send_packet builds IPv4/IPv6, TCP, UDP and ICMP/ICMPv6 headers from named fields and computes the header, ICMP and pseudo-header checksums. The transport and the pipeline are separated: the pipeline runs over a pair of in-process channels, so it is exercised in full without root.")
            .llm_control("Deliberately bounded, because a per-packet LLM call is unusable - one ping is a call per second and a TCP handshake three in milliseconds. Three gates in order: packet_filter (native code, every packet, default \"icmp\"); the server's own event_handlers, which are the primary answer path and cost no model call; and only then llm_escalation/llm_max_per_minute, which lets an unhandled packet reach the model at most llm_max_per_minute times a minute (default 6). The model answers with send_packet, drop_packet or no_response, described by header fields - never raw bytes.")
            .e2e_testing("The packet layer is tested against literal packet bytes: real IPv4/IPv6 headers, TCP with flags, UDP, ICMP echo, an Ethernet-framed TAP packet, and the macOS 4-byte AF prefix and Linux flags+EtherType prefix both explicitly. Built packets are re-decoded and their checksums verified to zero. The event -> handler -> action pipeline runs over an in-process channel transport against a mock model, including the escalation bound: 40 packets are injected and exactly the intended few reach the model. The real interface is never created - that needs root, which the suite does not have.")
            .notes("PROVEN: the decoder and builder, against literal bytes; the filter grammar; the escalation bound, measured as LLM call counts against a recording mock; that a failure sends nothing. NOT PROVEN: interface creation and the real transport, which have never been executed - no test in this suite has root, so tun::create() has never run and no packet has ever crossed a real utun or /dev/net/tun. Treat the transport as unexercised code. TAP is refused on macOS: utun is layer 3 only and CoreBluetooth-style third-party kexts are out of scope, so spawn() returns a clear Err naming the reason rather than pretending. PATH TO BETA: run it under sudo on this machine with a real utun - `ping 10.7.0.2` for ICMP and `nc` for TCP - and confirm the host accepts the replies NetGet builds; that has not been done and must not be claimed until it is. On any failure - LLM error, a refused action, an over-budget packet - the packet is dropped and nothing is written. That is not a fallback, it is the design: a fabricated packet on a real interface is indistinguishable from a spoof, and NetGet does not know what the host expected. The log distinguishes decision=handler_send / handler_drop / handler_silent / model_send / model_drop / model_silent / fail_closed_llm_error / fail_closed_build_error / fail_closed_rate_limited / llm_disabled so silence is never ambiguous - in particular \"the model said drop\" and \"the model said nothing\" are different tokens.")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "TUN/TAP interface endpoint - NetGet becomes a network interface and every routed packet becomes an event"
    }

    fn example_prompt(&self) -> &'static str {
        "Become a TUN interface on 10.7.0.1/24 and answer every ping to 10.7.0.2 with an echo reply"
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        // Every one of these nine is read by TunTapConfig::from_params in mod.rs. The three
        // that bound LLM involvement - packet_filter, llm_escalation, llm_max_per_minute - are
        // the reason this protocol is usable at all; see src/server/tuntap/CLAUDE.md.
        vec![
            ParameterDefinition {
                name: "interface_name".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Name to request for the interface. Linux: anything, e.g. \"tun0\". macOS: \
                     must be \"utunN\" for a number N, and the kernel may hand back a \
                     different one. Omit to let the platform choose."
                        .to_string(),
                required: false,
                example: json!("utun7"),
                default: None,
            },
            ParameterDefinition {
                name: "mode".to_string(),
                type_hint: "string".to_string(),
                description:
                    "\"tun\" (layer 3, bare IP packets; the default) or \"tap\" (layer 2, \
                     Ethernet frames). TAP is Linux-only: macOS utun has no layer-2 mode and \
                     no TAP device without a third-party kext, so \"tap\" is refused there \
                     with a clear error rather than silently downgraded."
                        .to_string(),
                required: false,
                example: json!("tun"),
                default: None,
            },
            ParameterDefinition {
                name: "address".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Local address assigned to the interface. Default 10.7.0.1. The host routes \
                     the rest of the subnet to NetGet, so this is the address the host sees as \
                     the near end."
                        .to_string(),
                required: false,
                example: json!("10.7.0.1"),
                default: None,
            },
            ParameterDefinition {
                name: "netmask".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Netmask for the interface address. Default 255.255.255.0, which routes \
                     the whole /24 into NetGet."
                        .to_string(),
                required: false,
                example: json!("255.255.255.0"),
                default: None,
            },
            ParameterDefinition {
                name: "mtu".to_string(),
                type_hint: "integer".to_string(),
                description: "Interface MTU, 576-65535. Default 1500.".to_string(),
                required: false,
                example: json!(1500),
                default: None,
            },
            ParameterDefinition {
                name: "packet_filter".to_string(),
                type_hint: "string".to_string(),
                description:
                    "WHICH PACKETS BECOME EVENTS AT ALL. Everything else is decoded, counted \
                     and dropped in native code with no handler and no model call - which is \
                     what makes an interface endpoint usable, since anything real is thousands \
                     of packets. Default \"icmp\": only pings are surfaced, because a ping is \
                     one packet a second and is the one thing you can watch by hand. Grammar: \
                     \"all\", \"none\", or comma-separated alternatives (OR) of \
                     plus-separated terms (AND). Terms: v4, v6, a protocol name (icmp, tcp, \
                     udp, ...), ip-proto-<n>, tcp:<port>, udp:<port>, port:<n>, from:<addr>, \
                     to:<addr>, host:<addr>, and tcp-syn - which matches only a SYN without an \
                     ACK, so a whole TCP connection costs one event instead of one per packet. \
                     Example: \"tcp-syn+to:10.7.0.2, icmp\"."
                        .to_string(),
                required: false,
                example: json!("icmp"),
                default: None,
            },
            ParameterDefinition {
                name: "llm_escalation".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Whether a packet that no event handler answered may reach the model. \
                     \"unhandled\" (default) lets it, subject to llm_max_per_minute. \"never\" \
                     forbids it outright, so the server is purely deterministic: handlers \
                     answer, everything else is dropped, and no LLM budget is ever spent. \
                     Script and static handlers are the intended answer path either way - the \
                     model is the last resort, not the default."
                        .to_string(),
                required: false,
                example: json!("unhandled"),
                default: None,
            },
            ParameterDefinition {
                name: "llm_max_per_minute".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Hard ceiling on model consultations per rolling minute, 0-3600. Default \
                     6. Packets over the ceiling are DROPPED, not queued - queueing a packet \
                     is meaningless once the sender has moved on. 0 has the same effect as \
                     llm_escalation \"never\". At the default, a ping arriving once a second \
                     produces six model calls in the first minute and then silence, which is \
                     intentional: the filter is how you decide what is interesting, not this."
                        .to_string(),
                required: false,
                example: json!(6),
                default: None,
            },
            ParameterDefinition {
                name: "packet_information".to_string(),
                type_hint: "string".to_string(),
                description:
                    "How to read the platform's 4-byte per-packet prefix - the single most \
                     common source of \"why is every packet off by four bytes\". \"auto\" \
                     (default) trusts the tun crate, which strips and re-adds it itself. \
                     \"macos_utun\" is four bytes of big-endian address family (AF_INET=2, \
                     AF_INET6=30), which macOS utun always prepends. \"linux_pi\" is two bytes \
                     of flags plus a big-endian EtherType, which Linux prepends unless the \
                     device was opened with IFF_NO_PI. \"none\" is a bare packet. The prefix is \
                     validated, not skipped: a mismatch is an error rather than four bytes of \
                     silent misalignment."
                        .to_string(),
                required: false,
                example: json!("auto"),
                default: None,
            },
        ]
    }

    fn group_name(&self) -> &'static str {
        "VPN & Routing"
    }

    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            // LLM mode. Note the filter: even here the model only ever sees pings, and at most
            // six a minute. Anything wider needs the operator to say so.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "tuntap",
                "instruction": "You are the far end of a TUN interface at 10.7.0.1/24. When a ping arrives for any address in that subnet, answer it with an ICMP echo reply that copies the request's icmp_id and icmp_sequence and swaps source and destination. Drop anything else.",
                "startup_params": {
                    "address": "10.7.0.1",
                    "netmask": "255.255.255.0",
                    "packet_filter": "icmp",
                    "llm_escalation": "unhandled",
                    "llm_max_per_minute": 6
                }
            }),
            // Script mode. This is the shape to copy for anything with real traffic: the
            // script answers every ping in-process with no model call at all, so the filter
            // can be widened without cost.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "tuntap",
                "startup_params": {
                    "address": "10.7.0.1",
                    "packet_filter": "icmp, tcp-syn",
                    "llm_escalation": "never"
                },
                "event_handlers": [{
                    "event_pattern": "tuntap_packet_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "if event['protocol'] == 'icmp' and event['icmp_type'] == 'echo_request':\n    return [{'type': 'send_packet', 'source': event['destination'], 'destination': event['source'], 'protocol': 'icmp', 'icmp_type': 'echo_reply', 'icmp_id': event['icmp_id'], 'icmp_sequence': event['icmp_sequence']}]\nreturn [{'type': 'drop_packet', 'reason': 'only pings are answered'}]"
                    }
                }]
            }),
            // Static mode. A fixed answer plus interpolation of the fields that must be echoed
            // back - no model call, and the correlation the sender matches on is preserved.
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "tuntap",
                "startup_params": {
                    "address": "10.7.0.1",
                    "packet_filter": "icmp",
                    "llm_escalation": "never"
                },
                "event_handlers": [{
                    "event_pattern": "tuntap_packet_received",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_packet",
                            "source": "{{event.destination}}",
                            "destination": "{{event.source}}",
                            "protocol": "icmp",
                            "icmp_type": "echo_reply",
                            "icmp_id": "{{event.icmp_id}}",
                            "icmp_sequence": "{{event.icmp_sequence}}"
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for TunTapProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move { super::TunTapServer::spawn_with_llm_actions(ctx).await })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing action type")?;

        match action_type {
            "send_packet" => {
                let bytes = packet::build_packet(&action)
                    .map_err(|e| anyhow::anyhow!("send_packet refused: {e}"))?;
                debug!("TUN/TAP built a {}-byte packet", bytes.len());
                Ok(ActionResult::Output(bytes))
            }
            "drop_packet" => {
                let reason = action
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("no reason given");
                debug!("TUN/TAP drop_packet: {}", reason);
                Ok(ActionResult::NoAction)
            }
            "no_response" => Ok(ActionResult::NoAction),
            other => Err(anyhow::anyhow!("Unknown TUN/TAP action type: {}", other)),
        }
    }
}

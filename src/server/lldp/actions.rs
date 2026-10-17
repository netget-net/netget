//! LLDP protocol actions, events and metadata.
//!
//! What makes LLDP interesting to drive from a model is that **the model authors the identity**:
//! NetGet impersonates a switch to its neighbour, and the chassis ID, system description and
//! capability set are its to choose. Everything below is therefore expressed as structured
//! fields the model can reason about — names, addresses, descriptions — and never as octets.
//!
//! The one rule that shapes the rest of this file: **an advertisement is a positive assertion.**
//! A neighbour writes what it receives into its topology table and shows it to an operator, so
//! there is no such thing as an error advertisement. When there is nothing to say, LLDP says
//! nothing. See `no_advertisement`, and the failure handling in `mod.rs`.

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

use super::codec;

/// Interface a capture is opened on when the caller names none. LLDP is not observable on
/// loopback — nothing speaks it there and libpcap rejects an Ethernet-only filter on a link
/// type with no Ethernet header — so this default exists to produce a clear refusal rather than
/// to be useful. Point the server at a real NIC.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub const DEFAULT_LOOPBACK_INTERFACE: &str = "lo0";
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
pub const DEFAULT_LOOPBACK_INTERFACE: &str = "lo";

/// Locally-administered address used as the Ethernet source when nothing better is known.
///
/// The `x2` in the first octet marks it locally administered, so it cannot collide with a real
/// vendor assignment. Overridable with the `source_mac` startup parameter, and by the action.
pub const DEFAULT_SOURCE_MAC: &str = "02:00:00:00:00:01";

pub struct LldpProtocol;

impl Default for LldpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl LldpProtocol {
    pub fn new() -> Self {
        Self
    }

    /// Validate a `send_lldp_advertisement` action by *building the frame it describes*.
    ///
    /// The bytes are thrown away here — `mod.rs` owns the transport and rebuilds them with the
    /// server's own source address — but running the encoder is what makes this a validation
    /// rather than a hope. A chassis ID that does not match its subtype, a capability name with
    /// a typo, or a system description past the 255-octet TLV limit fails at the action, where
    /// the model can be told, instead of producing a frame a neighbour discards in silence.
    fn execute_send_advertisement(&self, action: serde_json::Value) -> Result<ActionResult> {
        let request = codec::AdvertisementRequest::from_action(&action)
            .context("send_lldp_advertisement was refused")?;

        // A frame is only transmitted by the running server, which knows its interface's
        // address; the action carries the *description* onwards.
        Ok(ActionResult::Custom {
            name: LLDP_ADVERTISEMENT_RESULT.to_string(),
            data: json!({
                "chassis_id": request.lldpdu.chassis_id,
                "port_id": request.lldpdu.port_id,
                "ttl": request.lldpdu.ttl,
                "action": action,
            }),
        })
    }
}

/// The `ActionResult::Custom` name `mod.rs` looks for when deciding what to transmit.
pub const LLDP_ADVERTISEMENT_RESULT: &str = "lldp_advertisement";

/// The action name that means "deliberately say nothing".
pub const NO_ADVERTISEMENT_ACTION: &str = "no_advertisement";

impl Protocol for LldpProtocol {
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        // LLDP is interface-based, but the UDP test transport needs a host and port, so both
        // sets of defaults are supplied and `transport` decides which are used.
        Some(crate::protocol::BindingDefaults {
            mac_address: None,
            interface: Some(DEFAULT_LOOPBACK_INTERFACE.to_string()),
            host: Some("127.0.0.1".to_string()),
            port: Some(0),
        })
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        // Every one of these is read by `LldpServer::spawn_with_llm_actions`.
        vec![
            ParameterDefinition {
                name: "transport".to_string(),
                type_hint: "string".to_string(),
                description:
                    "How frames reach the wire. \"raw\" (the default) captures and injects real \
                     Ethernet frames through libpcap on the chosen interface and needs \
                     root/CAP_NET_RAW. \"udp\" is a TESTING transport: it carries complete \
                     Ethernet frames as UDP datagram payloads on the bound host/port so the \
                     whole event -> handler -> frame path can be exercised without privileges. \
                     It is not LLDP as any real neighbour speaks it — no switch will ever send \
                     or receive these datagrams."
                        .to_string(),
                required: false,
                example: json!("raw"),
                default: None,
            },
            ParameterDefinition {
                name: "udp_peer".to_string(),
                type_hint: "string".to_string(),
                description:
                    "TESTING only, and only with transport=\"udp\": HOST:PORT that advertisements \
                     are sent to. Without it, frames go back to the last peer heard from, which \
                     is enough to answer a neighbour but not to start a periodic advertisement \
                     before anyone has spoken."
                        .to_string(),
                required: false,
                example: json!("127.0.0.1:34567"),
                default: None,
            },
            ParameterDefinition {
                name: "advertise_interval_secs".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Seconds between lldp_advertise_due events, which is how NetGet advertises \
                     itself rather than only answering neighbours. 0 (the default) disables the \
                     timer entirely and the server is a pure listener. IEEE 802.1AB's default is \
                     30, with a TTL of 120."
                        .to_string(),
                required: false,
                example: json!(30),
                default: None,
            },
            ParameterDefinition {
                name: "source_mac".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "Ethernet source address for frames this server transmits, used when the \
                     action does not name one. Defaults to the interface's own address where it \
                     can be read, and to {DEFAULT_SOURCE_MAC} (locally administered) otherwise — \
                     which is always the case for transport=\"udp\", where there is no interface."
                ),
                required: false,
                example: json!("02:00:00:00:00:01"),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // LLDP has no user-triggered verbs of its own: transmitting is driven either by a
        // received advertisement or by the advertise timer, and both are network events.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![send_lldp_advertisement_action(), no_advertisement_action()]
    }

    fn protocol_name(&self) -> &'static str {
        "LLDP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_lldp_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>LLDP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["lldp", "link layer discovery", "802.1ab"]
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

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // libpcap capture/injection, never a SOCK_RAW. RawSockets would refuse to start on
            // a host with /dev/bpf* access but no root - the "don't claim more than you need"
            // rule that ospf got wrong by declaring Root when it wanted CAP_NET_RAW.
            .privilege_requirement(PrivilegeRequirement::PacketCapture)
            .connectionless()
            // Deliberately silent: LLDP has no error frame. An LLDPDU asserts chassis, port and
            // system identity to every neighbour, which stores it in its MIB for the TTL, so a
            // fabricated one is a false neighbour entry on every station that hears it.
            .deliberately_silent()
            .implementation(
                "Hand-written IEEE 802.1AB TLV codec (src/server/lldp/codec.rs), pure and \
                 transport-free; libpcap capture/injection on EtherType 0x88CC for the real \
                 transport, plus a UDP test transport that carries whole Ethernet frames.",
            )
            .llm_control(
                "The entire advertised identity: chassis ID and subtype, port ID and subtype, \
                 TTL, port/system descriptions, system capabilities and management address. \
                 NetGet impersonates whatever device the model describes.",
            )
            .e2e_testing(
                "tests/server/lldp/codec_test.rs encodes against hand-computed IEEE 802.1AB \
                 bytes and decodes literal frames, including the mandatory/capability/management \
                 TLVs of a real-world Extreme Summit300-48 capture. \
                 tests/server/lldp/e2e_test.rs drives the full event -> handler/LLM -> frame \
                 path over the UDP test transport in-process, including the silence case. \
                 Nothing has ever run the pcap transport. \
                 NO THIRD-PARTY PEER, and this was investigated rather than assumed \
                 (September 2026): `lldpcli` is installed on this machine and CANNOT be \
                 pointed at NetGet. It is not an LLDP speaker at all — lldpcli(8) is the \
                 control program for a local `lldpd` daemon and reaches it over the unix \
                 socket /opt/homebrew/var/run/lldpd.socket, which is its only transport (-u \
                 changes the socket path; there is no host or port option, because there is no \
                 wire protocol on that side). The real peer would have to be `lldpd` itself, \
                 which needs root, a real Ethernet interface and NetGet's libpcap transport — \
                 and a test needing root could only be #[ignore]d or skip-gated, neither of \
                 which is evidence. See src/server/lldp/CLAUDE.md for the feth-pair experiment \
                 that would earn Beta.",
            )
            .notes(
                "PROVEN: the TLV codec, against literal IEEE 802.1AB-2016 byte layouts and a \
                 real-world capture, in both directions. NOT PROVEN: the raw-Ethernet transport, \
                 which needs root/CAP_NET_RAW and has never been executed anywhere — no frame \
                 this code produced has reached a real LLDP neighbour, and no third-party LLDP \
                 peer is runnable in the environment that tests it. Deliberately silent on LLM \
                 failure: every LLDP frame asserts that a device with a given identity exists on \
                 this link, so a fabricated one poisons a neighbour's topology table. The \
                 failure is recorded with a decision= tag in the log instead. See \
                 src/server/lldp/CLAUDE.md for the feth-pair experiment that would earn Beta.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "LLDP (IEEE 802.1AB) link-layer discovery — advertise a device identity to neighbours"
    }

    fn example_prompt(&self) -> &'static str {
        "Be an LLDP agent on en0 impersonating a Cisco Catalyst switch: answer every neighbour \
         advertisement with our own on port GigabitEthernet0/1"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            // LLM-driven: the model invents the identity per neighbour.
            json!({
                "type": "open_server",
                "base_stack": "lldp",
                "interface": "en0",
                "instruction": "You are an LLDP agent impersonating an Extreme Summit300-48 \
                                switch. Answer each neighbour advertisement with our own on \
                                port 1/1, capabilities bridge and router, TTL 120."
            }),
            // Script: a deterministic identity, no LLM call per neighbour.
            json!({
                "type": "open_server",
                "base_stack": "lldp",
                "interface": "en0",
                "startup_params": {"advertise_interval_secs": 30},
                "event_handlers": [{
                    "event_pattern": "lldp_*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "respond([{'type': 'send_lldp_advertisement', 'chassis_id': '02:00:00:00:00:01', 'chassis_id_subtype': 'mac_address', 'port_id': 'ge-0/0/1', 'port_id_subtype': 'interface_name', 'ttl': 120, 'system_name': 'netget-lab', 'capabilities': ['bridge', 'router']}])"
                    }
                }]
            }),
            // Static: one fixed identity, and explicit silence for the timer.
            json!({
                "type": "open_server",
                "base_stack": "lldp",
                "interface": "en0",
                "event_handlers": [{
                    "event_pattern": "lldp_neighbor_advertisement",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_lldp_advertisement",
                            "chassis_id": "02:00:00:00:00:01",
                            "chassis_id_subtype": "mac_address",
                            "port_id": "1/1",
                            "port_id_subtype": "interface_name",
                            "ttl": 120,
                            "system_name": "netget-lab",
                            "system_description": "NetGet LLDP agent",
                            "capabilities": ["bridge", "router"]
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for LldpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use super::LldpServer;
            let listen_addr = ctx
                .socket_addr()
                .unwrap_or_else(|| ctx.legacy_listen_addr());
            LldpServer::spawn_with_llm_actions(
                ctx.interface.clone(),
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
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_lldp_advertisement" => self.execute_send_advertisement(action),
            // Silence, explicitly chosen. It is a real answer and is logged as
            // `decision=model_reject`, which is what distinguishes it from a model that said
            // nothing and from a backend that failed.
            NO_ADVERTISEMENT_ACTION => Ok(ActionResult::NoAction),
            other => Err(anyhow::anyhow!("Unknown LLDP action: {}", other)),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Action definitions
// ---------------------------------------------------------------------------------------------

fn subtype_list(kind: codec::IdKind) -> String {
    let table = match kind {
        codec::IdKind::Chassis => codec::CHASSIS_ID_SUBTYPES,
        codec::IdKind::Port => codec::PORT_ID_SUBTYPES,
    };
    table
        .iter()
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(" | ")
}

fn capability_list() -> String {
    codec::SYSTEM_CAPABILITIES
        .iter()
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(", ")
}

fn send_lldp_advertisement_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_lldp_advertisement".to_string(),
        description:
            "Transmit one LLDP advertisement describing the device NetGet is impersonating. \
             Every field is structured — there is no way to send raw TLV octets, deliberately. \
             Remember what an advertisement means: the neighbour records this identity in its \
             topology table and shows it to an operator, so send one only when you intend to \
             claim that a device with these details exists on this link. Use no_advertisement \
             otherwise."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "chassis_id".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Identifier of the whole device: a MAC address (00:1b:21:3c:4d:5e), an IP \
                     address, or free text, matching chassis_id_subtype."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "chassis_id_subtype".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "How chassis_id should be read: {}. Defaults to mac_address or \
                     network_address when the value looks like one, and to 'local' otherwise. \
                     Note the numbering differs from port_id_subtype.",
                    subtype_list(codec::IdKind::Chassis)
                ),
                required: false,
            },
            Parameter {
                name: "port_id".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Identifier of the port this advertisement is sent from: an interface name \
                     (GigabitEthernet0/1), a MAC address, or free text."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "port_id_subtype".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "How port_id should be read: {}. Same defaulting as chassis_id_subtype.",
                    subtype_list(codec::IdKind::Port)
                ),
                required: false,
            },
            Parameter {
                name: "ttl".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Seconds the neighbour should keep this entry, 0-65535 (default 120). 0 is a \
                     shutdown notice: it tells the neighbour to delete us immediately."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "port_description".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable port description, up to 255 octets.".to_string(),
                required: false,
            },
            Parameter {
                name: "system_name".to_string(),
                type_hint: "string".to_string(),
                description: "The device's administratively assigned name (its hostname)."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "system_description".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Free text describing the device — typically vendor, model and firmware \
                     version. This is the field network reconnaissance reads, so choose it as \
                     deliberately as the rest."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "capabilities".to_string(),
                type_hint: "array".to_string(),
                description: format!(
                    "Capabilities the device supports, as names: {}. Used for capabilities_enabled \
                     too when that is omitted.",
                    capability_list()
                ),
                required: false,
            },
            Parameter {
                name: "capabilities_enabled".to_string(),
                type_hint: "array".to_string(),
                description: "Subset of 'capabilities' currently switched on. Omit to claim that \
                     everything supported is enabled."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "management_address".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Address the device is managed on: an IPv4, IPv6 or MAC address. The family \
                     is deduced from the notation."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "management_interface_number".to_string(),
                type_hint: "integer".to_string(),
                description: "ifIndex the management address lives on (default 0).".to_string(),
                required: false,
            },
            Parameter {
                name: "source_mac".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Ethernet source address of the frame. Defaults to the server's interface \
                     address; set it only to impersonate a specific device at layer 2."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "destination_mac".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Ethernet destination (default 01:80:c2:00:00:0e, the nearest-bridge group \
                     address every LLDP agent transmits to). Change it only for a directed \
                     frame to one neighbour."
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_lldp_advertisement",
            "chassis_id": "00:1b:21:3c:4d:5e",
            "chassis_id_subtype": "mac_address",
            "port_id": "GigabitEthernet0/1",
            "port_id_subtype": "interface_name",
            "ttl": 120,
            "port_description": "Uplink to core",
            "system_name": "edge-sw-01",
            "system_description": "Cisco IOS Software, C2960 Software, Version 15.0(2)SE11",
            "capabilities": ["bridge", "router"],
            "capabilities_enabled": ["bridge"],
            "management_address": "192.0.2.10"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> LLDP {system_name} chassis={chassis_id} port={port_id} ttl={ttl}")
                .with_debug(
                    "LLDP send_lldp_advertisement: chassis={chassis_id} ({chassis_id_subtype}) \
                     port={port_id} ({port_id_subtype}) ttl={ttl}",
                )
                .with_trace("LLDP advertisement: {json_pretty(.)}"),
        ),
    }
}

fn no_advertisement_action() -> ActionDefinition {
    ActionDefinition {
        name: NO_ADVERTISEMENT_ACTION.to_string(),
        description:
            "Say nothing. LLDP has no error or refusal frame — every frame it defines asserts \
             that a device exists — so this is how a decision not to advertise is expressed. It \
             is recorded in the log as decision=model_reject, which is what distinguishes it \
             from having produced no answer at all."
                .to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Why nothing is being advertised. Logged, never transmitted.".to_string(),
            required: false,
        }],
        example: json!({
            "type": "no_advertisement",
            "reason": "This neighbour is not on a link we advertise to"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("LLDP staying silent: {reason}")
                .with_debug("LLDP no_advertisement: {reason}"),
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------------------------

/// A neighbour's advertisement arrived and has been decoded.
pub static LLDP_NEIGHBOR_ADVERTISEMENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lldp_neighbor_advertisement",
        "An LLDP neighbour advertised itself on this link. Every field is already decoded from \
         its TLVs.",
        json!({
            "type": "send_lldp_advertisement",
            "chassis_id": "02:00:00:00:00:01",
            "chassis_id_subtype": "mac_address",
            "port_id": "1/1",
            "port_id_subtype": "interface_name",
            "ttl": 120,
            "system_name": "netget-lab",
            "capabilities": ["bridge", "router"]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "source_mac".to_string(),
            type_hint: "string".to_string(),
            description: "Ethernet source address the advertisement came from".to_string(),
            required: true,
        },
        Parameter {
            name: "chassis_id".to_string(),
            type_hint: "string".to_string(),
            description: "The neighbour's chassis identifier, in the notation its subtype implies"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "chassis_id_subtype".to_string(),
            type_hint: "string".to_string(),
            description: "How to read chassis_id (mac_address, network_address, local, ...)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "port_id".to_string(),
            type_hint: "string".to_string(),
            description: "The neighbour's port identifier".to_string(),
            required: true,
        },
        Parameter {
            name: "port_id_subtype".to_string(),
            type_hint: "string".to_string(),
            description: "How to read port_id".to_string(),
            required: true,
        },
        Parameter {
            name: "ttl".to_string(),
            type_hint: "integer".to_string(),
            description: "Seconds the neighbour asks us to keep its entry; 0 means it is leaving"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "system_name".to_string(),
            type_hint: "string".to_string(),
            description: "The neighbour's hostname, if it sent one".to_string(),
            required: false,
        },
        Parameter {
            name: "system_description".to_string(),
            type_hint: "string".to_string(),
            description: "Vendor/model/firmware text, if it sent any".to_string(),
            required: false,
        },
        Parameter {
            name: "capabilities".to_string(),
            type_hint: "array".to_string(),
            description: "Capability names the neighbour supports".to_string(),
            required: false,
        },
        Parameter {
            name: "capabilities_enabled".to_string(),
            type_hint: "array".to_string(),
            description: "Capability names the neighbour has switched on".to_string(),
            required: false,
        },
        Parameter {
            name: "management_address".to_string(),
            type_hint: "string".to_string(),
            description: "Address the neighbour says it is managed on".to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("LLDP neighbour {system_name} ({chassis_id}) on port {port_id}")
            .with_debug(
                "LLDP advertisement from {source_mac}: chassis={chassis_id} port={port_id} \
                 ttl={ttl}",
            )
            .with_trace("LLDP neighbour: {json_pretty(.)}"),
    )
    .with_actions(vec![
        send_lldp_advertisement_action(),
        no_advertisement_action(),
    ])
    .with_alternative_example(json!({
        "type": "no_advertisement",
        "reason": "Listening only; this link is not one we advertise on"
    }))
});

/// The advertise timer fired: it is time to announce ourselves, unprompted.
pub static LLDP_ADVERTISE_DUE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lldp_advertise_due",
        "The periodic advertise timer fired (advertise_interval_secs). This is how NetGet \
         announces itself rather than only answering neighbours; nothing was received.",
        json!({
            "type": "send_lldp_advertisement",
            "chassis_id": "02:00:00:00:00:01",
            "chassis_id_subtype": "mac_address",
            "port_id": "1/1",
            "port_id_subtype": "interface_name",
            "ttl": 120,
            "system_name": "netget-lab",
            "system_description": "NetGet LLDP agent",
            "capabilities": ["bridge", "router"]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "interval_secs".to_string(),
            type_hint: "integer".to_string(),
            description: "The configured interval between these events".to_string(),
            required: true,
        },
        Parameter {
            name: "sequence".to_string(),
            type_hint: "integer".to_string(),
            description: "How many times the timer has fired since the server started".to_string(),
            required: true,
        },
        Parameter {
            name: "interface".to_string(),
            type_hint: "string".to_string(),
            description: "Interface the advertisement would be transmitted on".to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("LLDP advertise timer #{sequence}")
            .with_debug("LLDP advertise_due: sequence={sequence} interval={interval_secs}s"),
    )
    .with_actions(vec![
        send_lldp_advertisement_action(),
        no_advertisement_action(),
    ])
    .with_alternative_example(json!({
        "type": "no_advertisement",
        "reason": "Nothing to announce yet"
    }))
});

pub fn get_lldp_event_types() -> Vec<EventType> {
    vec![
        LLDP_NEIGHBOR_ADVERTISEMENT_EVENT.clone(),
        LLDP_ADVERTISE_DUE_EVENT.clone(),
    ]
}

//! NDP protocol actions, events and metadata.
//!
//! What the model decides here is **what a peer's IPv6 stack will believe**. A Neighbour
//! Advertisement writes an entry into its neighbour cache; a Router Advertisement writes its
//! prefix, its default route and — through RDNSS — its DNS resolvers. Both are accepted from
//! anybody on the link, unauthenticated. That is the protocol, not a defect in this
//! implementation, and it is the reason `mitm6` works.
//!
//! Two rules shape everything below:
//!
//! 1. **Every field is structured.** Addresses are IPv6 strings, link-layer addresses are
//!    `"00:11:22:33:44:55"`, flags are booleans, lifetimes are seconds. There is no parameter
//!    that accepts octets and there never should be.
//! 2. **Every message is a positive assertion, so there is no error message to send.** When
//!    there is nothing to say, NDP says nothing — see `no_response`, and the failure handling in
//!    `mod.rs`.

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

/// Link-local address transmitted messages are sourced from when nothing else is configured.
///
/// `fe80::1` is the conventional "the router on this link" address and is what a host expects to
/// see as the next hop in a Router Advertisement.
pub const DEFAULT_LINK_LOCAL: &str = "fe80::1";

/// Link-layer address used in Source/Target Link-Layer Address options when neither the action
/// nor the startup parameters name one. The `02` marks it locally administered, so it cannot
/// collide with a real vendor assignment.
pub const DEFAULT_LINK_LAYER_ADDRESS: &str = "02:00:00:00:00:01";

/// Interface a raw ICMPv6 socket reports itself on when the caller names none.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub const DEFAULT_INTERFACE: &str = "lo0";
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
pub const DEFAULT_INTERFACE: &str = "lo";

/// The `ActionResult::Custom` name `mod.rs` looks for when deciding what to transmit.
pub const NDP_MESSAGE_RESULT: &str = "ndp_message";

/// The action name that means "deliberately say nothing".
pub const NO_RESPONSE_ACTION: &str = "no_response";

pub struct NdpProtocol;

impl Default for NdpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl NdpProtocol {
    pub fn new() -> Self {
        Self
    }

    /// Validate a `send_*` action by *building the message it describes*.
    ///
    /// The bytes are thrown away here — `mod.rs` owns the transport, knows the addresses and
    /// rebuilds them with a real checksum — but running the encoder is what makes this a
    /// validation rather than a hope. An autonomous prefix that is not a `/64`, a preferred
    /// lifetime longer than its valid lifetime, an MTU below IPv6's 1280 floor: each fails here,
    /// where the model can be told, instead of producing a message a host discards in silence.
    fn execute_send(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("send")
            .to_string();
        let request = codec::SendRequest::from_action(&action)
            .with_context(|| format!("{action_type} was refused"))?;

        Ok(ActionResult::Custom {
            name: NDP_MESSAGE_RESULT.to_string(),
            data: json!({
                "message_type": request.message.type_name(),
                "icmpv6_type": request.message.message_type(),
                "action": action,
            }),
        })
    }
}

impl Protocol for NdpProtocol {
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        // NDP is interface-based and has no port, but the UDP test transport needs a host and a
        // port, so both sets of defaults are supplied and `transport` decides which are used.
        Some(crate::protocol::BindingDefaults {
            mac_address: None,
            interface: Some(DEFAULT_INTERFACE.to_string()),
            host: Some("127.0.0.1".to_string()),
            port: Some(0),
        })
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        // Every one of these is read by `NdpServer::spawn_with_llm_actions`.
        vec![
            ParameterDefinition {
                name: "transport".to_string(),
                type_hint: "string".to_string(),
                description:
                    "How messages reach the wire. \"raw\" (the default) opens a raw ICMPv6 socket \
                     and needs root or CAP_NET_RAW. \"udp\" is a TESTING transport: each datagram \
                     carries a 16-octet IPv6 source address, a 16-octet destination address and \
                     then the ICMPv6 message, so the whole event -> handler -> message path \
                     (including the pseudo-header checksum, which needs both addresses) can be \
                     exercised without privileges. No real IPv6 stack speaks it."
                        .to_string(),
                required: false,
                example: json!("raw"),
                default: None,
            },
            ParameterDefinition {
                name: "udp_peer".to_string(),
                type_hint: "string".to_string(),
                description:
                    "TESTING only, and only with transport=\"udp\": HOST:PORT that transmitted \
                     messages are sent to. Without it they go back to the last peer heard from."
                        .to_string(),
                required: false,
                example: json!("127.0.0.1:34567"),
                default: None,
            },
            ParameterDefinition {
                name: "link_local_address".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "The IPv6 address this server sends from, and therefore the address a host \
                     will install as its default router when it accepts a Router Advertisement. \
                     Defaults to {DEFAULT_LINK_LOCAL}. It is also half of the pseudo-header the \
                     ICMPv6 checksum is computed over, so it must be the address the message \
                     really travels from."
                ),
                required: false,
                example: json!("fe80::1"),
                default: None,
            },
            ParameterDefinition {
                name: "link_layer_address".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "Our own link-layer (MAC) address, used to fill in the Source or Target \
                     Link-Layer Address option when an action names none — RFC 4861 requires it \
                     on a solicited Neighbour Advertisement and recommends it on a Router \
                     Advertisement. Defaults to the interface's own address where it can be read, \
                     and to {DEFAULT_LINK_LAYER_ADDRESS} (locally administered) otherwise."
                ),
                required: false,
                example: json!("02:00:00:00:00:01"),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // NDP has no user-triggered verbs of its own: every transmission is a reaction to a
        // received message, and this server deliberately runs no advertisement timer of its own
        // (see `mod.rs` — an unsolicited periodic RA would reconfigure a link nobody asked it
        // to). Everything is therefore a sync action, reachable from an event.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_router_advertisement_action(),
            send_neighbor_advertisement_action(),
            send_neighbor_solicitation_action(),
            no_response_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "NDP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_ndp_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "IPv6>ICMPv6>NDP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "ndp",
            "neighbor discovery",
            "neighbour discovery",
            "icmpv6",
            "router advertisement",
            "ipv6",
            "rfc4861",
            "slaac",
            "rdnss",
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

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::RawSockets)
            .connectionless()
            // Deliberately silent: Neighbor Discovery has no error reply. A Neighbor or Router
            // Advertisement is written into the requester's neighbour or default-router cache, so a
            // fabricated one poisons it; an unanswered solicitation is ordinary on a link.
            .deliberately_silent()
            .implementation(
                "Hand-written RFC 4861 codec (src/server/ndp/codec.rs), pure and transport-free: \
                 all five message types, TLV options with 8-octet length units, and the ICMPv6 \
                 checksum over the RFC 8200 IPv6 pseudo-header. Transport is a raw ICMPv6 socket \
                 via socket2, plus a UDP test transport carrying source address, destination \
                 address and message so the checksum path runs unprivileged.",
            )
            .llm_control(
                "Everything a peer will believe: whether to answer a Neighbour Solicitation at \
                 all and with which link-layer address, and the entire contents of a Router \
                 Advertisement — hop limit, M/O flags, router lifetime, prefixes with their \
                 on-link and autonomous flags and lifetimes, link MTU, and the RDNSS resolver \
                 list. Nothing is advertised that the model did not author.",
            )
            .e2e_testing(
                "tests/server/ndp/codec_test.rs asserts encoded messages byte-for-byte against \
                 literal RFC 4861 / RFC 4443 / RFC 8106 layouts, including every option's \
                 8-octet length unit and checksums computed independently over the IPv6 \
                 pseudo-header. tests/server/ndp/e2e_test.rs drives event -> handler/LLM -> \
                 action -> message over the UDP test transport in-process, verifies the checksum \
                 of what comes back, and asserts that an LLM failure emits nothing at all. \
                 Nothing has ever run the raw ICMPv6 transport.",
            )
            .notes(
                "PROVEN: the packet codec, against literal specification bytes in both \
                 directions, including the pseudo-header checksum and the 8-octet option length \
                 units; and the full event -> action -> message path over the UDP test \
                 transport. NOT PROVEN: the raw ICMPv6 transport, which needs root or \
                 CAP_NET_RAW and has never been executed anywhere — no message this code \
                 produced has reached a real IPv6 stack, and no third-party NDP peer is runnable \
                 in the environment that tests it. Note also that on a raw ICMPv6 socket the \
                 kernel recomputes the checksum itself (RFC 3542 3.1), so on that path our own \
                 calculation is overwritten; it is load-bearing on the UDP transport and in the \
                 codec tests. Deliberately silent on LLM failure: an NDP answer writes a binding \
                 into a peer's neighbour cache and a Router Advertisement rewrites its whole \
                 routing and DNS configuration, so a fabricated one is cache poisoning at best \
                 and a full traffic redirect at worst. The failure is recorded with a decision= \
                 tag in the log instead. See src/server/ndp/CLAUDE.md for the feth-pair \
                 experiment that would earn Beta.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "IPv6 Neighbour Discovery (RFC 4861) — answer solicitations and author Router \
         Advertisements over ICMPv6"
    }

    fn example_prompt(&self) -> &'static str {
        "Be an IPv6 router on this link: answer every router solicitation with an advertisement \
         for 2001:db8:1::/64, RDNSS 2001:db8:1::53, MTU 1500, and answer neighbour solicitations \
         for addresses inside that prefix"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            // LLM-driven: the model decides which solicitations deserve an answer.
            json!({
                "type": "open_server",
                "base_stack": "ndp",
                "interface": "en0",
                "instruction": "You are an IPv6 router on this link. Answer router solicitations \
                                with a /64 out of 2001:db8:1::/48 and RDNSS 2001:db8:1::53. \
                                Answer neighbour solicitations only for addresses in that prefix; \
                                use no_response for anything else."
            }),
            // Script: a deterministic router, no LLM call per solicitation.
            json!({
                "type": "open_server",
                "base_stack": "ndp",
                "interface": "en0",
                "event_handlers": [{
                    "event_pattern": "ndp_router_solicitation",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "respond([{'type': 'send_router_advertisement', 'router_lifetime': 1800, 'prefixes': [{'prefix': '2001:db8:1::', 'length': 64}], 'rdnss': ['2001:db8:1::53'], 'mtu': 1500}])"
                    }
                }]
            }),
            // Static: one fixed advertisement, and explicit silence for everything else.
            json!({
                "type": "open_server",
                "base_stack": "ndp",
                "interface": "en0",
                "event_handlers": [
                    {
                        "event_pattern": "ndp_router_solicitation",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_router_advertisement",
                                "hop_limit": 64,
                                "router_lifetime": 1800,
                                "prefixes": [{
                                    "prefix": "2001:db8:1::",
                                    "length": 64,
                                    "on_link": true,
                                    "autonomous": true,
                                    "valid_lifetime": 2592000,
                                    "preferred_lifetime": 604800
                                }],
                                "rdnss": ["2001:db8:1::53"],
                                "mtu": 1500
                            }]
                        }
                    },
                    {
                        "event_pattern": "ndp_*",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "no_response", "reason": "observe only"}]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for NdpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use super::NdpServer;
            let listen_addr = ctx
                .socket_addr()
                .unwrap_or_else(|| ctx.legacy_listen_addr());
            NdpServer::spawn_with_llm_actions(
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
            "send_router_advertisement"
            | "send_neighbor_advertisement"
            | "send_neighbor_solicitation" => self.execute_send(action),
            // Silence, explicitly chosen. It is a real answer and is logged as
            // `decision=model_reject`, which is what distinguishes it from a model that said
            // nothing and from a backend that failed.
            NO_RESPONSE_ACTION => Ok(ActionResult::NoAction),
            other => Err(anyhow::anyhow!("Unknown NDP action: {}", other)),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Action definitions
// ---------------------------------------------------------------------------------------------

fn send_router_advertisement_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_router_advertisement".to_string(),
        description:
            "Transmit an ICMPv6 Router Advertisement (type 134). This is the highest-impact \
             message in IPv6: a host that accepts it installs us as a default router, builds \
             addresses out of the prefixes we give it, and uses the DNS resolvers we name. It is \
             unauthenticated and every host on the link will believe it, so send one only when \
             you intend that whole configuration to take effect. Use no_response otherwise."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "hop_limit".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Default Hop Limit hosts should use for outgoing packets, 0-255 (default 64). \
                     0 means 'unspecified — keep your own'."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "managed".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "The M flag: hosts should get their addresses from DHCPv6 rather than from \
                     the prefixes below (default false)."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "other".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "The O flag: hosts should get other configuration (DNS, NTP) from DHCPv6 \
                     (default false)."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "router_lifetime".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Seconds hosts should keep us as a default router, 0-65535 (default 1800). \
                     **0 means 'I am not a default router'** and is how a router withdraws \
                     itself — the prefixes and RDNSS below are still honoured."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "reachable_time".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Milliseconds a neighbour is assumed reachable after a confirmation; 0 (the \
                     default) means unspecified."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "retrans_timer".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Milliseconds between retransmitted Neighbour Solicitations; 0 (the default) \
                     means unspecified."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "prefixes".to_string(),
                type_hint: "array".to_string(),
                description:
                    "Prefix Information options, each an object: prefix (IPv6 address, or CIDR \
                     like '2001:db8::/64'), length (0-128, default 64), on_link (default true — \
                     'you can reach this without a router'), autonomous (default true — 'build \
                     yourself an address from it'; requires length 64, because SLAAC appends a \
                     64-bit interface identifier), valid_lifetime seconds (default 2592000) and \
                     preferred_lifetime seconds (default 604800, and it must not exceed \
                     valid_lifetime)."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "rdnss".to_string(),
                type_hint: "array".to_string(),
                description:
                    "Recursive DNS server addresses (RFC 8106), as IPv6 address strings. A host \
                     that accepts these resolves every name through them, which is why a rogue \
                     Router Advertisement is a complete traffic redirect and not merely a routing \
                     change."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "rdnss_lifetime".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Seconds the RDNSS list stays valid (default 600). 0 withdraws the servers."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "mtu".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Link MTU option in octets, at least 1280 (IPv6's minimum). Omit to send no \
                     MTU option."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "source_link_layer".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Our link-layer address as '00:11:22:33:44:55'. Defaults to the server's own; \
                     set it only to impersonate a specific node at layer 2."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "source_address".to_string(),
                type_hint: "string".to_string(),
                description:
                    "IPv6 source address, which is the address hosts will install as their \
                     default router. Defaults to the server's configured link-local address."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "destination_address".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Where to send it. Defaults to the soliciting host, or to ff02::1 (all nodes \
                     on the link) when nothing solicited it."
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_router_advertisement",
            "hop_limit": 64,
            "managed": false,
            "other": false,
            "router_lifetime": 1800,
            "prefixes": [{
                "prefix": "2001:db8:1::",
                "length": 64,
                "on_link": true,
                "autonomous": true,
                "valid_lifetime": 2592000,
                "preferred_lifetime": 604800
            }],
            "rdnss": ["2001:db8:1::53"],
            "rdnss_lifetime": 600,
            "mtu": 1500
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NDP router advertisement lifetime={router_lifetime}s")
                .with_debug(
                    "NDP send_router_advertisement: hop_limit={hop_limit} \
                     lifetime={router_lifetime} mtu={mtu}",
                )
                .with_trace("NDP router advertisement: {json_pretty(.)}"),
        ),
    }
}

fn send_neighbor_advertisement_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_neighbor_advertisement".to_string(),
        description:
            "Transmit an ICMPv6 Neighbour Advertisement (type 136) — IPv6's answer to an ARP \
             reply. It tells the peer 'this IPv6 address is at this link-layer address', and the \
             peer writes exactly that into its neighbour cache and sends the address's traffic \
             there. Answer only for addresses you intend to receive traffic for."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "target".to_string(),
                type_hint: "string".to_string(),
                description:
                    "The IPv6 address being advertised — normally the target_address from the \
                     solicitation that provoked this."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "router".to_string(),
                type_hint: "boolean".to_string(),
                description: "The R flag: this node is a router (default false).".to_string(),
                required: false,
            },
            Parameter {
                name: "solicited".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "The S flag: this answers a specific solicitation (default true). It is what \
                     confirms reachability, and it must be false on an unsolicited advertisement \
                     sent to a multicast address."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "override".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "The O flag: overwrite any cached link-layer address the peer already has \
                     (default true). False leaves an existing entry alone, which is the polite \
                     setting when you are not authoritative."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "target_link_layer".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Link-layer address the target is at, as '00:11:22:33:44:55'. Defaults to the \
                     server's own — this is the field that decides where the peer sends traffic."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "source_address".to_string(),
                type_hint: "string".to_string(),
                description:
                    "IPv6 source address. Defaults to the server's configured link-local address."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "destination_address".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Where to send it. Defaults to the soliciting node, or ff02::1 when the \
                     solicitation came from the unspecified address (a node doing duplicate \
                     address detection, which has no address to receive a unicast reply on)."
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_neighbor_advertisement",
            "target": "2001:db8:1::1",
            "router": true,
            "solicited": true,
            "override": true,
            "target_link_layer": "02:00:00:00:00:01"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NDP neighbour advertisement {target} at {target_link_layer}")
                .with_debug(
                    "NDP send_neighbor_advertisement: target={target} router={router} \
                     solicited={solicited} override={override}",
                )
                .with_trace("NDP neighbour advertisement: {json_pretty(.)}"),
        ),
    }
}

fn send_neighbor_solicitation_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_neighbor_solicitation".to_string(),
        description:
            "Transmit an ICMPv6 Neighbour Solicitation (type 135) — ask which link-layer address \
             an IPv6 address is at. Unlike the advertisements this is a question, not an \
             assertion: it asserts only that we exist and are asking. It goes to the target's \
             solicited-node multicast group unless you name a destination."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "target".to_string(),
                type_hint: "string".to_string(),
                description: "The IPv6 address being asked about.".to_string(),
                required: true,
            },
            Parameter {
                name: "source_link_layer".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Our link-layer address, so the target can answer without soliciting us back. \
                     Defaults to the server's own."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "source_address".to_string(),
                type_hint: "string".to_string(),
                description:
                    "IPv6 source address. Defaults to the server's configured link-local address."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "destination_address".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Where to send it. Defaults to the target's solicited-node multicast address \
                     (ff02::1:ffXX:XXXX), which is what a node that does not yet know the target \
                     must use."
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_neighbor_solicitation",
            "target": "2001:db8:1::53"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NDP neighbour solicitation for {target}")
                .with_debug("NDP send_neighbor_solicitation: target={target}")
                .with_trace("NDP neighbour solicitation: {json_pretty(.)}"),
        ),
    }
}

fn no_response_action() -> ActionDefinition {
    ActionDefinition {
        name: NO_RESPONSE_ACTION.to_string(),
        description:
            "Say nothing. Neighbour Discovery has no error or refusal message — every message it \
             defines is a positive assertion about addressing on this link — so this is how a \
             decision not to answer is expressed. It is recorded in the log as \
             decision=model_reject, which is what distinguishes it from having produced no answer \
             at all. Silence is the correct answer for any address we are not authoritative for: \
             the peer simply retries or times out, which its stack already handles."
                .to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Why nothing is being sent. Logged, never transmitted.".to_string(),
            required: false,
        }],
        example: json!({
            "type": "no_response",
            "reason": "that address is not one we are authoritative for"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("NDP staying silent: {reason}")
                .with_debug("NDP no_response: {reason}"),
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------------------------

/// The actions offered on every event. NDP's whole vocabulary is small enough that narrowing it
/// per event would only hide a legitimate answer — a Redirect, for instance, is a reasonable
/// prompt to solicit the new next hop.
fn all_actions() -> Vec<ActionDefinition> {
    vec![
        send_router_advertisement_action(),
        send_neighbor_advertisement_action(),
        send_neighbor_solicitation_action(),
        no_response_action(),
    ]
}

fn common_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "source_address".to_string(),
            type_hint: "string".to_string(),
            description: "IPv6 address the message came from. '::' means the sender has no \
                          address yet (duplicate address detection) and cannot receive a unicast \
                          reply."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "destination_address".to_string(),
            type_hint: "string".to_string(),
            description: "IPv6 address it was sent to — usually a multicast group".to_string(),
            required: false,
        },
        Parameter {
            name: "source_link_layer".to_string(),
            type_hint: "string".to_string(),
            description: "The sender's link-layer address, if it included the option".to_string(),
            required: false,
        },
    ]
}

/// A host is asking for a router (RFC 4861 §4.1). This is the opening for the whole protocol.
pub static NDP_ROUTER_SOLICITATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ndp_router_solicitation",
        "A host solicited a router on this link. Answering with send_router_advertisement hands \
         it a prefix, a default route and (with rdnss) its DNS resolvers — the single \
         highest-impact thing this protocol can do.",
        json!({
            "type": "send_router_advertisement",
            "hop_limit": 64,
            "router_lifetime": 1800,
            "prefixes": [{"prefix": "2001:db8:1::", "length": 64}],
            "rdnss": ["2001:db8:1::53"],
            "mtu": 1500
        }),
    )
    .with_parameters(common_parameters())
    .with_log_template(
        LogTemplate::new()
            .with_info("NDP router solicitation from {source_address}")
            .with_debug("NDP router solicitation: from={source_address} to={destination_address}")
            .with_trace("NDP router solicitation: {json_pretty(.)}"),
    )
    .with_actions(all_actions())
    .with_alternative_example(json!({
        "type": "no_response",
        "reason": "we are not a router on this link"
    }))
});

/// Somebody wants to know where an IPv6 address lives (RFC 4861 §4.3). IPv6's ARP request.
pub static NDP_NEIGHBOR_SOLICITATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ndp_neighbor_solicitation",
        "A node asked which link-layer address an IPv6 address is at. Answering claims that \
         address: the peer will send its traffic to the link-layer address in the reply.",
        json!({
            "type": "send_neighbor_advertisement",
            "target": "2001:db8:1::1",
            "solicited": true,
            "override": true
        }),
    )
    .with_parameters({
        let mut p = common_parameters();
        p.insert(
            0,
            Parameter {
                name: "target_address".to_string(),
                type_hint: "string".to_string(),
                description: "The IPv6 address being asked about".to_string(),
                required: true,
            },
        );
        p.push(Parameter {
            name: "solicited_node_multicast".to_string(),
            type_hint: "string".to_string(),
            description: "The solicited-node multicast group derived from the target".to_string(),
            required: false,
        });
        p
    })
    .with_log_template(
        LogTemplate::new()
            .with_info("NDP who has {target_address}? (from {source_address})")
            .with_debug(
                "NDP neighbour solicitation: target={target_address} from={source_address} \
                 sll={source_link_layer}",
            )
            .with_trace("NDP neighbour solicitation: {json_pretty(.)}"),
    )
    .with_actions(all_actions())
    .with_alternative_example(json!({
        "type": "no_response",
        "reason": "that address is not one we are authoritative for"
    }))
});

/// Somebody answered — or announced themselves unsolicited (RFC 4861 §4.4).
pub static NDP_NEIGHBOR_ADVERTISEMENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ndp_neighbor_advertisement",
        "A node advertised which link-layer address an IPv6 address is at. An unsolicited one \
         (solicited=false) is how a node announces a change — and how an attacker overwrites a \
         neighbour cache entry.",
        json!({"type": "no_response", "reason": "noted; nothing to answer"}),
    )
    .with_parameters({
        let mut p = common_parameters();
        p.insert(
            0,
            Parameter {
                name: "target_address".to_string(),
                type_hint: "string".to_string(),
                description: "The IPv6 address being advertised".to_string(),
                required: true,
            },
        );
        p.push(Parameter {
            name: "target_link_layer".to_string(),
            type_hint: "string".to_string(),
            description: "The link-layer address the target claims to be at".to_string(),
            required: false,
        });
        p.push(Parameter {
            name: "router".to_string(),
            type_hint: "boolean".to_string(),
            description: "The R flag: the sender says it is a router".to_string(),
            required: true,
        });
        p.push(Parameter {
            name: "solicited".to_string(),
            type_hint: "boolean".to_string(),
            description: "The S flag: this answers a solicitation rather than being unprompted"
                .to_string(),
            required: true,
        });
        p.push(Parameter {
            name: "override".to_string(),
            type_hint: "boolean".to_string(),
            description: "The O flag: the sender is asking receivers to overwrite what they have"
                .to_string(),
            required: true,
        });
        p
    })
    .with_log_template(
        LogTemplate::new()
            .with_info("NDP {target_address} is at {target_link_layer}")
            .with_debug(
                "NDP neighbour advertisement: target={target_address} tll={target_link_layer} \
                 solicited={solicited} override={override}",
            )
            .with_trace("NDP neighbour advertisement: {json_pretty(.)}"),
    )
    .with_actions(all_actions())
    .with_alternative_example(json!({
        "type": "send_neighbor_solicitation",
        "target": "2001:db8:1::53"
    }))
});

/// A router advertised itself. Somebody else is configuring this link.
pub static NDP_ROUTER_ADVERTISEMENT_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ndp_router_advertisement_received",
        "Another router advertised itself on this link, with its prefixes, MTU and DNS servers \
         already decoded. Every host that heard it has just been configured by it.",
        json!({"type": "no_response", "reason": "observing another router"}),
    )
    .with_parameters({
        let mut p = common_parameters();
        p.push(Parameter {
            name: "cur_hop_limit".to_string(),
            type_hint: "integer".to_string(),
            description: "Default hop limit the router tells hosts to use".to_string(),
            required: true,
        });
        p.push(Parameter {
            name: "managed".to_string(),
            type_hint: "boolean".to_string(),
            description: "The M flag: addresses come from DHCPv6".to_string(),
            required: true,
        });
        p.push(Parameter {
            name: "other".to_string(),
            type_hint: "boolean".to_string(),
            description: "The O flag: other configuration comes from DHCPv6".to_string(),
            required: true,
        });
        p.push(Parameter {
            name: "router_lifetime".to_string(),
            type_hint: "integer".to_string(),
            description: "Seconds it should be used as a default router; 0 means it is not one"
                .to_string(),
            required: true,
        });
        p.push(Parameter {
            name: "prefixes".to_string(),
            type_hint: "array".to_string(),
            description: "Prefix Information options: prefix, length, on_link, autonomous and \
                          both lifetimes"
                .to_string(),
            required: false,
        });
        p.push(Parameter {
            name: "rdnss".to_string(),
            type_hint: "array".to_string(),
            description: "Recursive DNS servers the router is handing out (RFC 8106)".to_string(),
            required: false,
        });
        p.push(Parameter {
            name: "mtu".to_string(),
            type_hint: "integer".to_string(),
            description: "Link MTU the router advertises, if it sent the option".to_string(),
            required: false,
        });
        p
    })
    .with_log_template(
        LogTemplate::new()
            .with_info("NDP router advertisement from {source_address} lifetime={router_lifetime}s")
            .with_debug(
                "NDP router advertisement: from={source_address} lifetime={router_lifetime} \
                 managed={managed} other={other} mtu={mtu}",
            )
            .with_trace("NDP router advertisement: {json_pretty(.)}"),
    )
    .with_actions(all_actions())
    .with_alternative_example(json!({
        "type": "send_router_advertisement",
        "router_lifetime": 1800,
        "prefixes": [{"prefix": "2001:db8:1::", "length": 64}]
    }))
});

/// A router said "use somebody else for that destination" (RFC 4861 §4.5).
pub static NDP_REDIRECT_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ndp_redirect_received",
        "A router told us to use a different first hop for a destination. A host that believes \
         it rewrites one route in its destination cache.",
        json!({"type": "no_response", "reason": "not following an unverified redirect"}),
    )
    .with_parameters({
        let mut p = common_parameters();
        p.insert(
            0,
            Parameter {
                name: "target_address".to_string(),
                type_hint: "string".to_string(),
                description: "The better first hop being suggested (or the destination itself, \
                              meaning 'it is on-link')"
                    .to_string(),
                required: true,
            },
        );
        p.insert(
            1,
            Parameter {
                name: "destination_address".to_string(),
                type_hint: "string".to_string(),
                description: "The destination the redirect is about".to_string(),
                required: true,
            },
        );
        p.push(Parameter {
            name: "target_link_layer".to_string(),
            type_hint: "string".to_string(),
            description: "Link-layer address of the suggested first hop, if included".to_string(),
            required: false,
        });
        p
    })
    .with_log_template(
        LogTemplate::new()
            .with_info("NDP redirect: {destination_address} via {target_address}")
            .with_debug(
                "NDP redirect: destination={destination_address} target={target_address} \
                 from={source_address}",
            )
            .with_trace("NDP redirect: {json_pretty(.)}"),
    )
    .with_actions(all_actions())
    .with_alternative_example(json!({
        "type": "send_neighbor_solicitation",
        "target": "fe80::1"
    }))
});

pub fn get_ndp_event_types() -> Vec<EventType> {
    vec![
        NDP_ROUTER_SOLICITATION_EVENT.clone(),
        NDP_ROUTER_ADVERTISEMENT_RECEIVED_EVENT.clone(),
        NDP_NEIGHBOR_SOLICITATION_EVENT.clone(),
        NDP_NEIGHBOR_ADVERTISEMENT_EVENT.clone(),
        NDP_REDIRECT_RECEIVED_EVENT.clone(),
    ]
}

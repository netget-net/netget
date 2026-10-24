//! What the model answers as the hosts behind a GRE tunnel endpoint on IP protocol 47: who has
//! an IP (ARP, gretap only), echo replies, and UDP replies. The packet is built here from the
//! request it answers, mirrored into the request's tunnel (the same key; a checksum and a
//! sequence number when the request had them), so the model supplies only what a host would
//! decide: its MAC, and what its service says.
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::server::vxlan::frame::{self, Frame, Mac, Payload};
use crate::state::app_state::AppState;
use crate::utils::gre;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, LazyLock, Mutex};

/// Packets per second that may reach the model (or be reflected as keepalives) when the
/// operator names no rate. Packets beyond it are dropped before anything else is done.
pub const DEFAULT_MAX_PACKETS_PER_SECOND: u64 = 100;
/// The highest `max_packets_per_second` accepted.
pub const MAX_PACKETS_PER_SECOND_LIMIT: u64 = 10_000;
/// The largest payload one GRE packet may carry (a jumbo frame). Larger is refused before it
/// is parsed. The receive buffer holds a whole IPv4 packet, so nothing is cut short to fit.
pub const MAX_INNER_BYTES: usize = 9_216;
/// The largest inbound IP packet: a whole IPv4 datagram.
pub const MAX_INBOUND_BYTES: usize = super::raw::MAX_IP_PACKET;
/// Answers being worked on at once; a packet arriving beyond it is dropped.
pub const MAX_IN_FLIGHT: usize = 64;
/// IPs whose MAC the model has given in an ARP reply; past it, new IPs use `overlay_mac`.
pub const MAX_REMEMBERED_HOSTS: usize = 4_096;

/// What a GRE packet carries: Ethernet (a Linux `gretap`, protocol type 0x6558) or IPv4 (a
/// Linux `gre`, protocol type 0x0800).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tunnel {
    Gretap,
    Gre,
}

impl Tunnel {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "gretap" => Ok(Tunnel::Gretap),
            "gre" => Ok(Tunnel::Gre),
            other => bail!("tunnel {other:?} is not gre (IPv4 in GRE) or gretap (Ethernet in GRE)"),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Tunnel::Gretap => "gretap",
            Tunnel::Gre => "gre",
        }
    }
    pub fn protocol(self) -> u16 {
        match self {
            Tunnel::Gretap => gre::PROTO_TEB,
            Tunnel::Gre => gre::PROTO_IPV4,
        }
    }
}

/// `key 42` or `no key`, for logs.
pub fn key_str(key: Option<u32>) -> String {
    key.map_or_else(|| "no key".into(), |k| format!("key {k}"))
}

/// The packet an answer answers, and what the server knows about its hosts.
#[derive(Clone)]
pub struct PacketContext {
    pub tunnel: Tunnel,
    /// The request's GRE header, which the reply mirrors.
    pub header: gre::Header,
    /// The inner packet. For `gre` its MACs are zero.
    pub frame: Frame,
    pub default_mac: Mac,
    /// The MAC each IP was given in an ARP reply, used as the source of that IP's frames.
    pub macs: Arc<Mutex<HashMap<Ipv4Addr, Mac>>>,
}

#[derive(Default, Clone)]
pub struct GreProtocol {
    request: Option<PacketContext>,
}

impl GreProtocol {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn for_packet(ctx: PacketContext) -> Self {
        Self { request: Some(ctx) }
    }
}

pub fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
    }
}

pub fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(
            LogTemplate::new().with_info(format!("-> GRE {}", name.trim_start_matches("gre_"))),
        ),
    }
}

pub fn arp_reply_action() -> ActionDefinition {
    action(
        "gre_arp_reply",
        "Answer the ARP request (gretap only): the target IP is one of your hosts, at this MAC. To say no host has it, answer nothing.",
        vec![p("mac", "string", "The host's MAC, e.g. 02:4e:47:00:00:02 (default: the server's overlay_mac)", false)],
        json!({"type":"gre_arp_reply","mac":"02:4e:47:00:00:02"}),
    )
}

pub fn echo_reply_action() -> ActionDefinition {
    action(
        "gre_icmp_echo_reply",
        "Answer the ping: an echo reply with the request's identifier, sequence and data, back through the tunnel.",
        vec![],
        json!({"type":"gre_icmp_echo_reply"}),
    )
}

pub fn data_params() -> Vec<Parameter> {
    vec![
        p(
            "data",
            "string",
            "The payload, as text (or hex with encoding hex)",
            true,
        ),
        p("encoding", "string", "utf8 (default) or hex", false),
    ]
}

pub fn udp_reply_action() -> ActionDefinition {
    action(
        "gre_udp_reply",
        "Answer the UDP datagram from the port it was sent to, back to its sender through the tunnel.",
        data_params(),
        json!({"type":"gre_udp_reply","data":"pong","encoding":"utf8"}),
    )
}

fn common_params() -> Vec<Parameter> {
    vec![
        p(
            "tunnel",
            "string",
            "gretap (the packet carried an Ethernet frame) or gre (it carried an IPv4 packet)",
            true,
        ),
        p(
            "key",
            "number",
            "The GRE key the packet carried (null when it had none)",
            false,
        ),
        p(
            "peer",
            "string",
            "The tunnel endpoint the packet came from (its outer source IP)",
            true,
        ),
        p(
            "src_mac",
            "string",
            "The sending host's MAC (gretap; null for gre)",
            false,
        ),
    ]
}

pub static ARP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = common_params();
    params.push(p("sender_ip", "string", "The asking host's IP", true));
    params.push(p("target_ip", "string", "The IP it is looking for", true));
    EventType::new(
        "gre_arp_request",
        "A host behind a gretap tunnel asks who has target_ip. Answer gre_arp_reply if one of your hosts does, or nothing.",
        arp_reply_action().example.clone(),
    )
    .with_parameters(params)
    .with_actions(vec![arp_reply_action()])
});

pub static ECHO_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = common_params();
    params.extend([
        p("src_ip", "string", "The pinging host's IP", true),
        p("dst_ip", "string", "The IP being pinged", true),
        p("identifier", "number", "The echo identifier", true),
        p("sequence", "number", "The echo sequence number", true),
        p(
            "data",
            "string",
            "The echo payload (text, or hex per encoding)",
            true,
        ),
        p(
            "encoding",
            "string",
            "utf8 or hex, as data is written",
            true,
        ),
    ]);
    EventType::new(
        "gre_icmp_echo_request",
        "A host through the tunnel pings dst_ip. Answer gre_icmp_echo_reply if that host is up, or nothing.",
        echo_reply_action().example.clone(),
    )
    .with_parameters(params)
    .with_actions(vec![echo_reply_action()])
});

pub static UDP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = common_params();
    params.extend([
        p("src_ip", "string", "The sending host's IP", true),
        p("src_port", "number", "The sender's UDP port", true),
        p("dst_ip", "string", "The IP it was sent to", true),
        p("dst_port", "number", "The UDP port it was sent to", true),
        p(
            "data",
            "string",
            "The payload (text, or hex per encoding)",
            true,
        ),
        p(
            "encoding",
            "string",
            "utf8 or hex, as data is written",
            true,
        ),
    ]);
    EventType::new(
        "gre_udp_datagram",
        "A host through the tunnel sent a UDP datagram to dst_ip:dst_port. Answer gre_udp_reply, or nothing.",
        udp_reply_action().example.clone(),
    )
    .with_parameters(params)
    .with_actions(vec![udp_reply_action()])
});

pub fn mac_param(v: &Value, default: Mac) -> Result<Mac> {
    match v["mac"].as_str() {
        Some(s) => frame::parse_mac(s),
        None => Ok(default),
    }
}

impl PacketContext {
    fn our_mac(&self, ip: Option<Ipv4Addr>) -> Mac {
        ip.and_then(|ip| {
            self.macs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&ip)
                .copied()
        })
        .unwrap_or(self.default_mac)
    }
    /// Into the request's tunnel: the same key, a checksum and a sequence number when the
    /// request had them. The sequence number is a placeholder here; the server writes the
    /// real one as the reply leaves.
    fn wrap(&self, inner: Vec<u8>) -> ActionResult {
        let header = gre::Header {
            protocol: self.tunnel.protocol(),
            sequence: self.header.sequence.map(|_| 0),
            ..self.header
        };
        ActionResult::Output(gre::encode(&header, &inner))
    }
    /// An IPv4 reply to the request's sender, from the address it was sent to: in an Ethernet
    /// frame for gretap, bare for gre.
    fn ip_reply(&self, protocol: u8, payload: &[u8]) -> Result<ActionResult> {
        let (src, dst) = (
            self.frame.dst_ip.context("not an IPv4 request")?,
            self.frame.src_ip.context("not an IPv4 request")?,
        );
        let packet = frame::ipv4(src, dst, protocol, rand::random(), payload);
        Ok(self.wrap(match self.tunnel {
            Tunnel::Gre => packet,
            Tunnel::Gretap => frame::ethernet(
                self.frame.src_mac,
                self.our_mac(Some(src)),
                frame::ETHERTYPE_IPV4,
                &packet,
            ),
        }))
    }
    fn remember(&self, ip: Ipv4Addr, mac: Mac) {
        let mut macs = self.macs.lock().unwrap_or_else(|e| e.into_inner());
        if macs.len() < MAX_REMEMBERED_HOSTS || macs.contains_key(&ip) {
            macs.insert(ip, mac);
        }
    }
}

/// The remote tunnel endpoints a server answers: every one, or those named.
pub fn parse_peers(v: Option<&Vec<Value>>) -> Result<Option<Vec<Ipv4Addr>>> {
    let Some(list) = v else { return Ok(None) };
    ensure!(
        !list.is_empty(),
        "peers is empty, so no tunnel endpoint would be answered; leave it out to answer every one"
    );
    ensure!(list.len() <= 1024, "peers names more than 1024 endpoints");
    list.iter()
        .map(|p| {
            p.as_str()
                .context("each of peers is an IPv4 address as a string")?
                .parse::<Ipv4Addr>()
                .with_context(|| format!("peer {p} is not an IPv4 address"))
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

impl Protocol for GreProtocol {
    fn protocol_name(&self) -> &'static str {
        "GRE"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>GRE"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "gre",
            "gretap",
            "generic routing encapsulation",
            "ip protocol 47",
            "gre tunnel",
            "rfc 2784",
        ]
    }
    fn description(&self) -> &'static str {
        "GRE tunnel endpoint on IP protocol 47 whose hosts the model plays: answers ARP, ping and UDP arriving through a gretap (Ethernet) or gre (IPv4) tunnel from Linux, a router or a firewall, and reflects Cisco-style keepalives"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![arp_reply_action(), echo_reply_action(), udp_reply_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![ARP_EVENT.clone(), ECHO_EVENT.clone(), UDP_EVENT.clone()]
    }
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        // A raw socket has no port: the host is the local address the tunnel's peers send to.
        Some(crate::protocol::BindingDefaults::port_based("127.0.0.1", 0))
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "peers".into(),
                type_hint: "array".into(),
                description: "The remote tunnel endpoints (IPv4 addresses) to answer; packets from any other source are dropped before the model (default: every endpoint that sends to this address)".into(),
                required: false,
                example: json!(["198.18.0.2"]),
                default: None,
            },
            ParameterDefinition {
                name: "key".into(),
                type_hint: "number".into(),
                description: "Answer only packets carrying this GRE key (0-4294967295); keyless packets are dropped too (default: every key, and packets without one)".into(),
                required: false,
                example: json!(42),
                default: None,
            },
            ParameterDefinition {
                name: "overlay_mac".into(),
                type_hint: "string".into(),
                description: "gretap: the MAC of the hosts when an ARP reply names none".into(),
                required: false,
                example: json!("02:4e:47:00:00:02"),
                default: Some(json!(frame::DEFAULT_MAC)),
            },
            ParameterDefinition {
                name: "max_packets_per_second".into(),
                type_hint: "number".into(),
                description: "How many packets a second may reach the model or be reflected as keepalives (1-10000); the rest are dropped".into(),
                required: false,
                example: json!(50),
                default: Some(json!(DEFAULT_MAX_PACKETS_PER_SECOND)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::RawSockets)
            .connectionless()
            .deliberately_silent()
            .implementation("A raw IPv4 socket for IP protocol 47 (root, or CAP_NET_RAW on Linux), bound to the server's host address. GRE per RFC 2784 with RFC 2890's key and sequence number (src/utils/gre.rs, shared with vxlan's GRE-in-UDP): version, RFC 1701 bits, field lengths and the checksum are checked before anything else. Payloads: Transparent Ethernet Bridging (0x6558, a Linux gretap) and IPv4 (0x0800, a Linux gre), with the Ethernet, ARP, IPv4, ICMP echo and UDP framing of src/server/vxlan/frame.rs; Cisco-style keepalives (an inner IPv4 GRE packet addressed back to the sender) are reflected in Rust. Replies mirror the request's key, checksum and sequence flags; the sequence number is the server's own counter, written as each reply leaves. Bounds: a peer allowlist, a key filter, a packet rate, 9216 bytes of payload, 64 answers in flight")
            .llm_control("Which IPs behind the tunnel exist and at which MAC (ARP, gretap), which hosts answer ping, and what each UDP service replies")
            .e2e_testing("tests/server/gre: the Linux kernel's ip_gre driver in a network namespace, as a gre link (IPv4) and a gretap link (Ethernet), each with key, checksums and sequence numbers on, which it demands on input: ping, arping and the neighbour table, and nc -u through the tunnel, with tshark reading the GRE on the veth. scapy as a second, independent GRE implementation: checksum, key and sequence on NetGet's replies, a keepalive reflected, and every refusal and bound (bad checksum, other key, other peer, version 1, routing bit, truncation, packet size, rate) before the model. Linux only, as root")
            .notes("DELIBERATELY SILENT: a host that does not exist is silence, never a reply, because every ARP, echo or UDP reply asserts that a host is there (logged decision=model_silent / fail_closed_*). GRE has no error message of its own to send instead. Experimental: both peers are Linux-run and the pair job had not run in CI when this landed. Unix only (a raw socket); the macOS path (XNU has no in-kernel GRE, so raw sockets get every protocol-47 packet) compiles but has not been run as root here. Not built: IPv6 outer or inner packets, PPTP's enhanced GRE (version 1), WCCP and ERSPAN payloads, TCP, IP fragmentation, MAC learning, and originating keepalives (the client does).")
            .max_inbound_bytes(MAX_INBOUND_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Be a GRE tunnel endpoint on 198.18.0.1 for the router at 198.18.0.2, key 42, where 10.99.0.2 answers ping and echoes UDP"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_server","base_stack":"gre","host":"198.18.0.1",
            "startup_params":{"peers":["198.18.0.2"],"key":42},
            "instruction":"You are host 10.99.0.2 (MAC 02:4e:47:00:00:02) behind the tunnel. Answer ARP for 10.99.0.2, answer pings to it, and echo UDP back."});
        let mut static_example = base.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"gre_arp_request","handler":{"type":"static","actions":[arp_reply_action().example]}},
            {"event_pattern":"gre_icmp_echo_request","handler":{"type":"static","actions":[echo_reply_action().example]}}
        ]);
        let mut scripted = base.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='gre_arp_request' and e['target_ip']=='10.99.0.2': a=[{'type':'gre_arp_reply','mac':'02:4e:47:00:00:02'}]\nelif t=='gre_icmp_echo_request' and e['dst_ip']=='10.99.0.2': a=[{'type':'gre_icmp_echo_reply'}]\nelif t=='gre_udp_datagram': a=[{'type':'gre_udp_reply','data':e['data'],'encoding':e['encoding']}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(base, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network"
    }
}

impl Server for GreProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let kind = action["type"].as_str().unwrap_or_default();
        // Validate first, so the registry's instance (no request) checks what it can.
        match kind {
            "gre_arp_reply" => {
                mac_param(&action, [2, 0, 0, 0, 0, 1])?;
            }
            "gre_icmp_echo_reply" => {}
            "gre_udp_reply" => {
                frame::data_bytes(&action)?;
            }
            other => bail!("Unknown GRE action {other:?}"),
        }
        let Some(ctx) = &self.request else {
            return Ok(ActionResult::NoAction);
        };
        match (kind, &ctx.frame.payload) {
            ("gre_arp_reply", Payload::Arp(arp)) if arp.request => {
                let mac = mac_param(&action, ctx.default_mac)?;
                ctx.remember(arp.target_ip, mac);
                Ok(ctx.wrap(frame::arp_frame(
                    false,
                    mac,
                    arp.target_ip,
                    arp.sender_mac,
                    arp.sender_ip,
                )))
            }
            (
                "gre_icmp_echo_reply",
                Payload::Echo {
                    request: true,
                    identifier,
                    sequence,
                    data,
                },
            ) => ctx.ip_reply(1, &frame::icmp_echo(false, *identifier, *sequence, data)),
            (
                "gre_udp_reply",
                Payload::Udp {
                    src_port, dst_port, ..
                },
            ) => {
                let data = frame::data_bytes(&action)?;
                let (src, dst) = (
                    ctx.frame.dst_ip.context("not an IPv4 request")?,
                    ctx.frame.src_ip.context("not an IPv4 request")?,
                );
                ctx.ip_reply(17, &frame::udp(src, dst, *dst_port, *src_port, &data))
            }
            (kind, _) => bail!("{kind} does not answer this packet"),
        }
    }
}

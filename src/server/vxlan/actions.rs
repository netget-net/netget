//! What the model answers as hosts on a VXLAN, Geneve or GRE (gretap) overlay: who has an IP (ARP), echo
//! replies, and UDP replies. The frames are built here from the request they answer, so the
//! model supplies only what a host would decide — its MAC, and what its service says.
use super::frame::{self, Encap, Frame, Mac, Payload};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, LazyLock, Mutex};

pub const DEFAULT_ENCAPSULATION: &str = "vxlan";

/// The frame an answer answers, and what the server knows about its overlay hosts.
#[derive(Clone)]
pub struct FrameContext {
    pub encap: Encap,
    /// The request's encapsulation header, which the reply mirrors: the same VNI or GRE key,
    /// and for GRE a checksum and a sequence number when the request had them.
    pub header: frame::Header,
    pub frame: Frame,
    pub default_mac: Mac,
    /// The MAC each IP was given in an ARP reply, used as the source of that IP's frames.
    pub macs: Arc<Mutex<HashMap<Ipv4Addr, Mac>>>,
}

#[derive(Default, Clone)]
pub struct VxlanProtocol {
    request: Option<FrameContext>,
}

impl VxlanProtocol {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn for_frame(ctx: FrameContext) -> Self {
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
    let info = match name {
        "vxlan_arp_reply" => "-> overlay ARP reply {mac}".to_string(),
        "vxlan_icmp_echo_reply" => "-> overlay echo reply".to_string(),
        "vxlan_udp_reply" => "-> overlay UDP reply".to_string(),
        other => format!("-> overlay {}", other.trim_start_matches("vxlan_")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(info)),
    }
}

pub fn arp_reply_action() -> ActionDefinition {
    action(
        "vxlan_arp_reply",
        "Answer the ARP request: the target IP is one of your overlay hosts, at this MAC. To say no host has it, answer nothing.",
        vec![p("mac", "string", "The host's MAC, e.g. 02:4e:47:00:00:02 (default: the server's overlay_mac)", false)],
        json!({"type":"vxlan_arp_reply","mac":"02:4e:47:00:00:02"}),
    )
}

pub fn echo_reply_action() -> ActionDefinition {
    action(
        "vxlan_icmp_echo_reply",
        "Answer the ping: an echo reply with the request's identifier, sequence and data.",
        vec![],
        json!({"type":"vxlan_icmp_echo_reply"}),
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
        "vxlan_udp_reply",
        "Answer the UDP datagram from the port it was sent to, back to its sender.",
        data_params(),
        json!({"type":"vxlan_udp_reply","data":"pong","encoding":"utf8"}),
    )
}

fn common_params() -> Vec<Parameter> {
    vec![
        p(
            "vni",
            "number",
            "The overlay network: the VXLAN/Geneve Network Identifier, or the GRE key (null for GRE without a key)",
            false,
        ),
        p(
            "vtep",
            "string",
            "The tunnel endpoint the frame came from, ip:port",
            true,
        ),
        p("src_mac", "string", "The sending host's MAC", true),
    ]
}

pub static ARP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = common_params();
    params.push(p("sender_ip", "string", "The asking host's IP", true));
    params.push(p("target_ip", "string", "The IP it is looking for", true));
    EventType::new(
        "vxlan_arp_request",
        "A host on the overlay asks who has target_ip. Answer vxlan_arp_reply if one of your hosts does, or nothing.",
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
        "vxlan_icmp_echo_request",
        "A host on the overlay pings dst_ip. Answer vxlan_icmp_echo_reply if that host is up, or nothing.",
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
        "vxlan_udp_datagram",
        "A host on the overlay sent a UDP datagram to dst_ip:dst_port. Answer vxlan_udp_reply, or nothing.",
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

impl FrameContext {
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
    /// Encapsulated as the request was. A GRE sequence number is a placeholder here; the
    /// server writes the real one as the reply leaves.
    fn wrap(&self, inner: Vec<u8>) -> ActionResult {
        let header = frame::Header {
            sequence: self.header.sequence.map(|_| 0),
            ..self.header
        };
        ActionResult::Output(frame::encap(self.encap, &header, &inner))
    }
    /// An IPv4 reply to the request's sender, from the address it was sent to.
    fn ip_reply(&self, protocol: u8, payload: &[u8]) -> Result<ActionResult> {
        let (src, dst) = (
            self.frame.dst_ip.context("not an IPv4 request")?,
            self.frame.src_ip.context("not an IPv4 request")?,
        );
        let packet = frame::ipv4(src, dst, protocol, rand::random(), payload);
        Ok(self.wrap(frame::ethernet(
            self.frame.src_mac,
            self.our_mac(Some(src)),
            frame::ETHERTYPE_IPV4,
            &packet,
        )))
    }
}

impl Protocol for VxlanProtocol {
    fn protocol_name(&self) -> &'static str {
        "VXLAN"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>VXLAN"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "vxlan",
            "geneve",
            "gre-in-udp",
            "overlay",
            "vtep",
            "4789",
            "6081",
            "4754",
            "tunnel endpoint",
        ]
    }
    fn description(&self) -> &'static str {
        "VXLAN/Geneve/GRE (gretap in UDP) tunnel endpoint whose overlay hosts the model plays: answers ARP, ping and UDP arriving through the tunnel from Linux, Open vSwitch or a switch"
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
        Some(crate::protocol::BindingDefaults::port_based("127.0.0.1", 0))
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "encapsulation".into(),
                type_hint: "string".into(),
                description: "vxlan (RFC 7348, port 4789), geneve (RFC 8926, port 6081) or gretap (Ethernet over GRE, RFC 2784/2890, in UDP per RFC 8086 on port 4754: a Linux gretap link with encap fou). Pass the port for geneve and gretap; with none the server takes VXLAN's 4789".into(),
                required: false,
                example: json!("geneve"),
                default: Some(json!(DEFAULT_ENCAPSULATION)),
            },
            ParameterDefinition {
                name: "vni".into(),
                type_hint: "number".into(),
                description: "Serve only this VNI; for gretap, only frames carrying this GRE key, so keyless frames are dropped (default: every VNI or key that arrives, and frames without a key)".into(),
                required: false,
                example: json!(42),
                default: None,
            },
            ParameterDefinition {
                name: "overlay_mac".into(),
                type_hint: "string".into(),
                description: "The MAC of the overlay hosts when an ARP reply names none".into(),
                required: false,
                example: json!("02:4e:47:00:00:02"),
                default: Some(json!(frame::DEFAULT_MAC)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(4789)
            .connectionless()
            .deliberately_silent()
            .implementation("Hand-rolled VXLAN (RFC 7348), Geneve (RFC 8926, options skipped) and Ethernet-over-GRE (RFC 2784/2890 key, checksum and sequence number; carried in UDP per RFC 8086) decapsulation, with Ethernet, ARP, IPv4 (header checksum checked, fragments not reassembled), ICMP echo and UDP (checksums checked and written) for the overlay hosts; replies go back through the tunnel to the sending endpoint, mirroring the request's VNI or GRE key, checksum and sequence flags")
            .llm_control("Which overlay IPs exist and at which MAC (ARP), which hosts answer ping, and what each UDP service replies")
            .e2e_testing("tests/server/vxlan: the Linux kernel's vxlan driver, and its gretap driver over a fou port (GRE key, checksum and sequence numbers on), each in a network namespace (ping and a UDP exchange through the tunnel, the neighbour entry the model's ARP reply created); the pcap oracle (tshark's vxlan, geneve and gre dissectors) over NetGet's frames; GRE refusals (version, protocol type, checksum, key, truncation) before the model")
            .notes("DELIBERATELY SILENT: an overlay IP with no host is silence, never a reply, because every ARP, echo or UDP reply asserts that a host exists (logged decision=model_silent / fail_closed_*). No TCP, no IPv6 (frames are logged and dropped), no IP fragmentation, no MAC learning or flooding to other VTEPs. GRE here is GRE-in-UDP only; GRE directly on IP protocol 47 needs a raw socket and is the separate gre protocol, so this one stays unprivileged. Geneve interop with a kernel peer is unverified here; its framing is checked by tshark.")
            .max_inbound_bytes(frame::MAX_DATAGRAM)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Be a VXLAN endpoint on VNI 42 where 10.99.0.2 answers ping and echoes UDP"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_server","base_stack":"vxlan","port":0,"startup_params":{"vni":42},
            "instruction":"You are host 10.99.0.2 (MAC 02:4e:47:00:00:02) on VNI 42. Answer ARP for 10.99.0.2, answer pings to it, and echo UDP back."});
        let mut static_example = base.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"vxlan_arp_request","handler":{"type":"static","actions":[arp_reply_action().example]}},
            {"event_pattern":"vxlan_icmp_echo_request","handler":{"type":"static","actions":[echo_reply_action().example]}}
        ]);
        let mut scripted = base.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='vxlan_arp_request' and e['target_ip']=='10.99.0.2': a=[{'type':'vxlan_arp_reply','mac':'02:4e:47:00:00:02'}]\nelif t=='vxlan_icmp_echo_request' and e['dst_ip']=='10.99.0.2': a=[{'type':'vxlan_icmp_echo_reply'}]\nelif t=='vxlan_udp_datagram': a=[{'type':'vxlan_udp_reply','data':e['data'],'encoding':e['encoding']}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(base, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network"
    }
}

impl Server for VxlanProtocol {
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
            "vxlan_arp_reply" => {
                mac_param(&action, [2, 0, 0, 0, 0, 1])?;
            }
            "vxlan_icmp_echo_reply" => {}
            "vxlan_udp_reply" => {
                frame::data_bytes(&action)?;
            }
            other => bail!("Unknown VXLAN action {other:?}"),
        }
        let Some(ctx) = &self.request else {
            return Ok(ActionResult::NoAction);
        };
        match (kind, &ctx.frame.payload) {
            ("vxlan_arp_reply", Payload::Arp(arp)) if arp.request => {
                let mac = mac_param(&action, ctx.default_mac)?;
                ctx.macs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(arp.target_ip, mac);
                Ok(ctx.wrap(frame::arp_frame(
                    false,
                    mac,
                    arp.target_ip,
                    arp.sender_mac,
                    arp.sender_ip,
                )))
            }
            (
                "vxlan_icmp_echo_reply",
                Payload::Echo {
                    request: true,
                    identifier,
                    sequence,
                    data,
                },
            ) => ctx.ip_reply(1, &frame::icmp_echo(false, *identifier, *sequence, data)),
            (
                "vxlan_udp_reply",
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
            (kind, _) => bail!("{kind} does not answer this frame"),
        }
    }
}

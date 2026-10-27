//! What the model can do as a host behind a GRE tunnel (IP protocol 47) to one remote tunnel
//! endpoint: ping, send UDP, and on a gretap tunnel resolve an IP and send whole Ethernet
//! frames; on a gre tunnel, send a Cisco-style keepalive.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::gre::actions::{action, data_params, p, Tunnel};
use crate::server::vxlan::frame::{self, Mac};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::sync::LazyLock;

pub const DEFAULT_TUNNEL: &str = "gre";
/// Packets carry no GRE checksum unless asked.
pub const DEFAULT_GRE_CHECKSUM: bool = false;
/// Packets carry no GRE sequence number unless asked.
pub const DEFAULT_GRE_SEQUENCE: bool = false;

#[derive(Default)]
pub struct GreClientProtocol;
impl GreClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn resolve_action() -> ActionDefinition {
    action(
        "gre_resolve",
        "gretap only: ARP for an IP behind the tunnel; the answer arrives as gre_arp_resolved (or gre_unreachable).",
        vec![p("ip", "string", "The IPv4 address to resolve", true)],
        json!({"type":"gre_resolve","ip":"10.99.0.1"}),
    )
}

fn ping_action() -> ActionDefinition {
    action(
        "gre_ping",
        "Send one ICMP echo request through the tunnel (on gretap, ARPing first if needed); the reply arrives as gre_icmp_echo_reply.",
        vec![
            p("ip", "string", "The IPv4 address to ping", true),
            p("data", "string", "Echo payload text (default: netget)", false),
        ],
        json!({"type":"gre_ping","ip":"10.99.0.1","data":"netget"}),
    )
}

fn send_udp_action() -> ActionDefinition {
    let mut params = vec![
        p("ip", "string", "The IPv4 address to send to", true),
        p("port", "number", "The destination UDP port", true),
        p(
            "source_port",
            "number",
            "The source port (default 40000)",
            false,
        ),
    ];
    params.extend(data_params());
    action(
        "gre_send_udp",
        "Send a UDP datagram through the tunnel (on gretap, ARPing first if needed). Replies arrive as gre_udp_datagram; a closed port as gre_icmp_error.",
        params,
        json!({"type":"gre_send_udp","ip":"10.99.0.1","port":9999,"data":"hello","encoding":"utf8"}),
    )
}

fn send_ethernet_action() -> ActionDefinition {
    let mut params = vec![
        p(
            "dst_mac",
            "string",
            "The destination MAC, e.g. ff:ff:ff:ff:ff:ff to broadcast",
            true,
        ),
        p(
            "ethertype",
            "number",
            "The EtherType (1536-65535), e.g. 34997 (0x88b5, for local experiments)",
            true,
        ),
    ];
    params.extend(data_params());
    action(
        "gre_send_ethernet",
        "gretap only: send one Ethernet frame through the tunnel, from this host's MAC, carrying data.",
        params,
        json!({"type":"gre_send_ethernet","dst_mac":"ff:ff:ff:ff:ff:ff","ethertype":34997,"data":"hello","encoding":"utf8"}),
    )
}

fn keepalive_action() -> ActionDefinition {
    action(
        "gre_send_keepalive",
        "gre only: send a Cisco-style GRE keepalive, which the remote endpoint reflects back if the tunnel works; the answer arrives as gre_keepalive_reply.",
        vec![],
        json!({"type":"gre_send_keepalive"}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the tunnel endpoint.",
        vec![],
        json!({"type":"disconnect"}),
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        resolve_action(),
        ping_action(),
        send_udp_action(),
        send_ethernet_action(),
        keepalive_action(),
        disconnect_action(),
    ]
}

fn ev(id: &str, description: &str, params: Vec<crate::llm::actions::Parameter>) -> EventType {
    EventType::new(id, description, ping_action().example.clone())
        .with_parameters(params)
        .with_actions(actions())
}

pub static READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "gre_ready",
        "The tunnel endpoint is up and this host is behind it.",
        vec![
            p(
                "overlay_ip",
                "string",
                "This host's IP inside the tunnel",
                true,
            ),
            p(
                "overlay_mac",
                "string",
                "This host's MAC (gretap; null for gre)",
                false,
            ),
            p(
                "remote",
                "string",
                "The remote tunnel endpoint packets go to",
                true,
            ),
            p(
                "local",
                "string",
                "The local address packets are sent from",
                true,
            ),
            p(
                "key",
                "number",
                "The GRE key (null when packets carry none)",
                false,
            ),
            p("tunnel", "string", "gre (IPv4) or gretap (Ethernet)", true),
        ],
    )
});

pub static RESOLVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "gre_arp_resolved",
        "An ARP request you asked for was answered (gretap).",
        vec![
            p("ip", "string", "The IPv4 address", true),
            p("mac", "string", "The MAC that answered for it", true),
        ],
    )
});

pub static UNREACHABLE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "gre_unreachable",
        "Nobody answered ARP for an IP (gretap), so what was meant for it was not sent.",
        vec![
            p("ip", "string", "The IP nobody answered for", true),
            p(
                "action",
                "string",
                "The action that was waiting on it",
                true,
            ),
        ],
    )
});

pub static ECHO_REPLY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "gre_icmp_echo_reply",
        "A ping was answered.",
        vec![
            p("src_ip", "string", "The IP that answered", true),
            p("identifier", "number", "The echo identifier", true),
            p("sequence", "number", "The echo sequence number", true),
            p("data", "string", "The echoed payload", true),
            p(
                "encoding",
                "string",
                "utf8 or hex, as data is written",
                true,
            ),
            p(
                "rtt_ms",
                "number",
                "Round-trip time in milliseconds, when the request was ours",
                false,
            ),
        ],
    )
});

pub static UDP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "gre_udp_datagram",
        "A UDP datagram arrived for this host through the tunnel.",
        vec![
            p("src_ip", "string", "The sender's IP", true),
            p("src_port", "number", "The sender's port", true),
            p("dst_port", "number", "The port it was sent to", true),
            p("data", "string", "The datagram's payload", true),
            p(
                "encoding",
                "string",
                "utf8 or hex, as data is written",
                true,
            ),
        ],
    )
});

pub static ICMP_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "gre_icmp_error",
        "A host or router reported a delivery failure, e.g. port unreachable for a UDP datagram.",
        vec![
            p("from", "string", "Who reported it", true),
            p(
                "meaning",
                "string",
                "port_unreachable, host_unreachable, ttl_exceeded, ...",
                true,
            ),
            p("type", "number", "The ICMP type number", true),
            p("code", "number", "The ICMP code number", true),
            p(
                "original_dst",
                "string",
                "Where the failed packet was going",
                true,
            ),
            p(
                "original_dst_port",
                "number",
                "Its UDP destination port, if it was UDP",
                false,
            ),
        ],
    )
});

pub static KEEPALIVE_REPLY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "gre_keepalive_reply",
        "The remote endpoint reflected a keepalive: the tunnel carries packets both ways.",
        vec![p(
            "rtt_ms",
            "number",
            "Round-trip time in milliseconds since the oldest unanswered keepalive",
            false,
        )],
    )
});

pub fn ip_of(v: &Value) -> Result<Ipv4Addr> {
    v["ip"]
        .as_str()
        .context("ip is required")?
        .parse()
        .context("ip is an IPv4 address")
}

fn port_of(v: &Value, key: &str) -> Result<Option<u16>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(x) => {
            let n = x.as_u64().filter(|n| (1..=65535).contains(n));
            Ok(Some(n.with_context(|| format!("{key} is 1-65535"))? as u16))
        }
    }
}

/// A MAC address, broadcast and multicast included (an Ethernet frame may go to either).
pub fn any_mac(s: &str) -> Result<Mac> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    ensure!(
        parts.len() == 6,
        "{s:?} is not a MAC like ff:ff:ff:ff:ff:ff"
    );
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] =
            u8::from_str_radix(part, 16).with_context(|| format!("{s:?} is not a MAC address"))?;
    }
    Ok(mac)
}

/// What a client action asks for, checked.
pub enum Request {
    Resolve(Ipv4Addr),
    Ping {
        ip: Ipv4Addr,
        data: Vec<u8>,
    },
    Udp {
        ip: Ipv4Addr,
        port: u16,
        source_port: Option<u16>,
        data: Vec<u8>,
    },
    Ethernet {
        dst_mac: Mac,
        ethertype: u16,
        data: Vec<u8>,
    },
    Keepalive,
}

impl Request {
    /// The IP whose MAC a gretap tunnel needs before this can be sent.
    pub fn ip(&self) -> Option<Ipv4Addr> {
        match self {
            Request::Resolve(ip) | Request::Ping { ip, .. } | Request::Udp { ip, .. } => Some(*ip),
            Request::Ethernet { .. } | Request::Keepalive => None,
        }
    }
}

/// Validate a client action; with `tunnel`, also that it applies to that tunnel.
pub fn check(v: &Value, tunnel: Option<Tunnel>) -> Result<Request> {
    let kind = v["type"].as_str().unwrap_or_default();
    let only = |t: Tunnel| -> Result<()> {
        if let Some(have) = tunnel {
            ensure!(
                have == t,
                "{kind} applies to a {} tunnel, and this one is {}",
                t.name(),
                have.name()
            );
        }
        Ok(())
    };
    match kind {
        "gre_resolve" => {
            only(Tunnel::Gretap)?;
            Ok(Request::Resolve(ip_of(v)?))
        }
        "gre_ping" => {
            let data = v
                .get("data")
                .and_then(Value::as_str)
                .unwrap_or("netget")
                .as_bytes()
                .to_vec();
            ensure!(
                data.len() <= frame::MAX_UDP_PAYLOAD,
                "ping data is too long"
            );
            Ok(Request::Ping {
                ip: ip_of(v)?,
                data,
            })
        }
        "gre_send_udp" => Ok(Request::Udp {
            ip: ip_of(v)?,
            data: frame::data_bytes(v)?,
            port: port_of(v, "port")?.context("port is required")?,
            source_port: port_of(v, "source_port")?,
        }),
        "gre_send_ethernet" => {
            only(Tunnel::Gretap)?;
            let ethertype = v["ethertype"]
                .as_u64()
                .filter(|t| (0x0600..=0xffff).contains(t))
                .context("ethertype is a number from 1536 (0x0600) to 65535")?;
            Ok(Request::Ethernet {
                dst_mac: any_mac(v["dst_mac"].as_str().context("dst_mac is required")?)?,
                ethertype: ethertype as u16,
                data: frame::data_bytes(v)?,
            })
        }
        "gre_send_keepalive" => {
            only(Tunnel::Gre)?;
            Ok(Request::Keepalive)
        }
        other => bail!("Unknown GRE client action {other:?}"),
    }
}

impl Protocol for GreClientProtocol {
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
            "gre client",
            "generic routing encapsulation",
            "ip protocol 47",
        ]
    }
    fn description(&self) -> &'static str {
        "GRE tunnel endpoint on IP protocol 47 as a host behind the tunnel: pings, sends UDP and (gretap) Ethernet frames through a gre or gretap tunnel to a remote endpoint (Linux, a router, a firewall), sends keepalives, and answers ARP and ping for itself"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            READY_EVENT.clone(),
            RESOLVED_EVENT.clone(),
            UNREACHABLE_EVENT.clone(),
            ECHO_REPLY_EVENT.clone(),
            UDP_EVENT.clone(),
            ICMP_ERROR_EVENT.clone(),
            KEEPALIVE_REPLY_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "overlay_ip".into(),
                type_hint: "string".into(),
                description: "This host's IPv4 address inside the tunnel".into(),
                required: true,
                example: json!("10.99.0.2"),
                default: None,
            },
            ParameterDefinition {
                name: "tunnel".into(),
                type_hint: "string".into(),
                description: "gre (IPv4 in GRE, a Linux gre link or a router's GRE IP tunnel) or gretap (Ethernet in GRE, a Linux gretap link)".into(),
                required: false,
                example: json!("gretap"),
                default: Some(json!(DEFAULT_TUNNEL)),
            },
            ParameterDefinition {
                name: "overlay_mac".into(),
                type_hint: "string".into(),
                description: "gretap: this host's MAC".into(),
                required: false,
                example: json!("02:4e:47:00:00:02"),
                default: Some(json!(frame::DEFAULT_MAC)),
            },
            ParameterDefinition {
                name: "key".into(),
                type_hint: "number".into(),
                description: "The GRE key every packet carries (0-4294967295), and the only one accepted back; leaving it out sends and accepts packets with no key".into(),
                required: false,
                example: json!(42),
                default: None,
            },
            ParameterDefinition {
                name: "gre_checksum".into(),
                type_hint: "boolean".into(),
                description: "Put a GRE checksum on every packet (what a Linux tunnel with csum/icsum expects)".into(),
                required: false,
                example: json!(true),
                default: Some(json!(DEFAULT_GRE_CHECKSUM)),
            },
            ParameterDefinition {
                name: "gre_sequence".into(),
                type_hint: "boolean".into(),
                description: "Number every packet with a GRE sequence number (what a Linux tunnel with seq/iseq expects)".into(),
                required: false,
                example: json!(true),
                default: Some(json!(DEFAULT_GRE_SEQUENCE)),
            },
            ParameterDefinition {
                name: "local_address".into(),
                type_hint: "string".into(),
                description: "The IPv4 address to send from and receive on: the remote endpoint's configured peer (default: the source of the route to it)".into(),
                required: false,
                example: json!("198.18.0.1"),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::RawSockets)
            .implementation("A raw IPv4 socket for IP protocol 47 (src/server/gre/raw.rs), the shared GRE codec (src/utils/gre.rs: key, checksum and sequence number each optional) and the Ethernet/ARP/IPv4/ICMP/UDP framing of src/server/vxlan/frame.rs. One host behind a gre (IPv4) or gretap (Ethernet) tunnel to one remote endpoint: ARP (gretap) and echo requests for its own IP are answered in Rust; on gretap sends wait on ARP (2 s) and report gre_unreachable when nobody answers; Cisco-style keepalives are built in Rust and their reflection reported")
            .llm_control("Which IPs to ping and send UDP to, which Ethernet frames to send (gretap), when to send keepalives (gre), and what to do with what comes back")
            .e2e_testing("tests/client/gre: the Linux kernel's ip_gre driver in a network namespace, as a gre link and a gretap link, each with key, checksums and sequence numbers on, which it demands on input. It answers ping (and ARP on gretap) itself, a UDP service behind it answers, a closed port sends the ICMP error, a gretap frame is captured on the kernel's link, and with forwarding on it reflects NetGet's keepalives. Linux only, as root")
            .notes("Experimental: the peer is Linux-run and the pair job had not run in CI when this landed. Unix only (a raw socket); the macOS path compiles but has not been run as root here. No TCP, no IPv6, no IP fragmentation; one remote endpoint. Linux delivers every protocol-47 packet for the local address to its own GRE module as well, so a kernel gre/gretap link on the same local address would see the same packets.")
            .max_inbound_bytes(crate::server::gre::raw::MAX_IP_PACKET)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Through the GRE tunnel to the router at 198.18.0.2, as 10.99.0.2 with key 42, ping 10.99.0.1"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"gre","remote_addr":"198.18.0.2",
            "startup_params":{"overlay_ip":"10.99.0.2","key":42},
            "instruction":"Ping 10.99.0.1 through the tunnel and report the round-trip time"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"gre_ready","handler":{"type":"static","actions":[ping_action().example]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1] = json!({"event_pattern":"gre_icmp_echo_reply","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'gre_send_udp','ip':e['src_ip'],'port':9999,'data':'rtt %s ms' % e.get('rtt_ms')}]}))"}});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network"
    }
}

impl Client for GreClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v, None)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}

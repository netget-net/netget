//! What the model can do as a host on a VXLAN, Geneve or GRE (gretap) overlay, reached
//! through a tunnel to one remote endpoint: resolve an IP, ping it, send it UDP.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::vxlan::actions::{action, data_params, p};
use crate::server::vxlan::frame;
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::sync::LazyLock;

pub const DEFAULT_VNI: u32 = 1;
/// gretap: frames carry no GRE checksum unless asked.
pub const DEFAULT_GRE_CHECKSUM: bool = false;
/// gretap: frames carry no GRE sequence number unless asked.
pub const DEFAULT_GRE_SEQUENCE: bool = false;

#[derive(Default)]
pub struct VxlanClientProtocol;
impl VxlanClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn resolve_action() -> ActionDefinition {
    action(
        "vxlan_resolve",
        "ARP for an overlay IP; the answer arrives as vxlan_arp_resolved (or vxlan_unreachable).",
        vec![p(
            "ip",
            "string",
            "The overlay IPv4 address to resolve",
            true,
        )],
        json!({"type":"vxlan_resolve","ip":"10.99.0.1"}),
    )
}

fn ping_action() -> ActionDefinition {
    action(
        "vxlan_ping",
        "Send one ICMP echo request through the tunnel (ARPing first if needed); the reply arrives as vxlan_icmp_echo_reply.",
        vec![
            p("ip", "string", "The overlay IPv4 address to ping", true),
            p("data", "string", "Echo payload text (default: netget)", false),
        ],
        json!({"type":"vxlan_ping","ip":"10.99.0.1","data":"netget"}),
    )
}

fn send_udp_action() -> ActionDefinition {
    let mut params = vec![
        p("ip", "string", "The overlay IPv4 address to send to", true),
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
        "vxlan_send_udp",
        "Send a UDP datagram through the tunnel (ARPing first if needed). Replies arrive as vxlan_udp_datagram; a closed port as vxlan_icmp_error.",
        params,
        json!({"type":"vxlan_send_udp","ip":"10.99.0.1","port":9999,"data":"hello","encoding":"utf8"}),
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
        "vxlan_ready",
        "The tunnel endpoint is up and this host is on the overlay.",
        vec![
            p("overlay_ip", "string", "This host's overlay IP", true),
            p("overlay_mac", "string", "This host's overlay MAC", true),
            p(
                "remote_vtep",
                "string",
                "The tunnel endpoint frames go to",
                true,
            ),
            p(
                "vni",
                "number",
                "The overlay network identifier, or the GRE key (null for gretap without a key)",
                false,
            ),
            p("encapsulation", "string", "vxlan, geneve or gretap", true),
        ],
    )
});

pub static RESOLVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "vxlan_arp_resolved",
        "An ARP request you asked for was answered.",
        vec![
            p("ip", "string", "The overlay IPv4 address", true),
            p("mac", "string", "The MAC that answered for it", true),
        ],
    )
});

pub static UNREACHABLE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "vxlan_unreachable",
        "Nobody answered ARP for an IP, so what was meant for it was not sent.",
        vec![
            p("ip", "string", "The overlay IP nobody answered for", true),
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
        "vxlan_icmp_echo_reply",
        "A ping was answered.",
        vec![
            p("src_ip", "string", "The overlay IP that answered", true),
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
        "vxlan_udp_datagram",
        "A UDP datagram arrived for this host through the tunnel.",
        vec![
            p("src_ip", "string", "The sender's overlay IP", true),
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

pub static ICMP_ERROR_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        ev(
        "vxlan_icmp_error",
        "A host or router reported a delivery failure, e.g. port unreachable for a UDP datagram.",
        vec![
            p("from", "string", "Who reported it", true),
            p("meaning", "string", "port_unreachable, host_unreachable, ttl_exceeded, ...", true),
            p("type", "number", "The ICMP type number", true),
            p("code", "number", "The ICMP code number", true),
            p("original_dst", "string", "Where the failed packet was going", true),
            p("original_dst_port", "number", "Its UDP destination port, if it was UDP", false),
        ],
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

/// Validate a client action. Returns (destination, dst port, src port) where they apply.
pub fn check(v: &Value) -> Result<(Ipv4Addr, Option<u16>, Option<u16>)> {
    let ip = ip_of(v)?;
    match v["type"].as_str().unwrap_or_default() {
        "vxlan_resolve" => Ok((ip, None, None)),
        "vxlan_ping" => {
            if let Some(d) = v.get("data").and_then(Value::as_str) {
                ensure!(d.len() <= frame::MAX_UDP_PAYLOAD, "ping data is too long");
            }
            Ok((ip, None, None))
        }
        "vxlan_send_udp" => {
            frame::data_bytes(v)?;
            let port = port_of(v, "port")?.context("port is required")?;
            Ok((ip, Some(port), port_of(v, "source_port")?))
        }
        other => bail!("Unknown VXLAN client action {other:?}"),
    }
}

impl Protocol for VxlanClientProtocol {
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
            "gre",
            "gretap",
            "overlay",
            "vtep",
            "tunnel",
            "vxlan client",
        ]
    }
    fn description(&self) -> &'static str {
        "VXLAN/Geneve/GRE (gretap in UDP) tunnel endpoint as a host on the overlay: ARPs, pings and sends UDP through the tunnel to a remote endpoint (Linux, Open vSwitch, a switch), and answers ARP and ping for itself"
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
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "overlay_ip".into(),
                type_hint: "string".into(),
                description: "This host's IPv4 address on the overlay".into(),
                required: true,
                example: json!("10.99.0.2"),
                default: None,
            },
            ParameterDefinition {
                name: "overlay_mac".into(),
                type_hint: "string".into(),
                description: "This host's MAC on the overlay".into(),
                required: false,
                example: json!("02:4e:47:00:00:02"),
                default: Some(json!(frame::DEFAULT_MAC)),
            },
            ParameterDefinition {
                name: "vni".into(),
                type_hint: "number".into(),
                description: "The overlay network identifier (0-16777215). For gretap it is the GRE key (0-4294967295), and leaving it out sends and accepts frames with no key".into(),
                required: false,
                example: json!(42),
                default: Some(json!(DEFAULT_VNI)),
            },
            ParameterDefinition {
                name: "encapsulation".into(),
                type_hint: "string".into(),
                description: "vxlan (port 4789), geneve (port 6081) or gretap (Ethernet over GRE in UDP, port 4754: a Linux gretap link with encap fou)".into(),
                required: false,
                example: json!("vxlan"),
                default: Some(json!(crate::server::vxlan::actions::DEFAULT_ENCAPSULATION)),
            },
            ParameterDefinition {
                name: "gre_checksum".into(),
                type_hint: "boolean".into(),
                description: "gretap only: put a GRE checksum on every frame (what a Linux gretap with csum/ocsum expects)".into(),
                required: false,
                example: json!(true),
                default: Some(json!(DEFAULT_GRE_CHECKSUM)),
            },
            ParameterDefinition {
                name: "gre_sequence".into(),
                type_hint: "boolean".into(),
                description: "gretap only: number every frame with a GRE sequence number (what a Linux gretap with seq/iseq expects)".into(),
                required: false,
                example: json!(true),
                default: Some(json!(DEFAULT_GRE_SEQUENCE)),
            },
            ParameterDefinition {
                name: "local_address".into(),
                type_hint: "string".into(),
                description: "The underlay IP to send from and listen on: the remote VTEP's configured peer (default: the source of the route to it)".into(),
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
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's VXLAN/Geneve/GRE-in-UDP and Ethernet/ARP/IPv4/ICMP/UDP framing (src/server/vxlan/frame.rs); one overlay host with an ARP cache, answering ARP and echo requests for its own IP in Rust; sends wait on ARP (2 s) and report vxlan_unreachable when nobody answers; for gretap, the GRE key, checksum and sequence number are each optional")
            .llm_control("Which overlay IPs to resolve, ping and send UDP to, and what to do with what comes back")
            .e2e_testing("tests/client/vxlan: the Linux kernel's vxlan driver, and its gretap driver over a fou port (GRE key, checksum and sequence numbers on), each in a network namespace, which answers ARP and ping itself, with a UDP service behind it and a closed port for the ICMP error")
            .notes("No TCP, no IPv6, no IP fragmentation; the tunnel goes to one remote endpoint (no flooding or learning of others). GRE is GRE-in-UDP only: GRE directly on IP protocol 47 needs a raw socket and is not implemented.")
            .max_inbound_bytes(frame::MAX_DATAGRAM)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Join VNI 42 through the VTEP at 198.18.0.2 as 10.99.0.2 and ping 10.99.0.1"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"vxlan","remote_addr":"127.0.0.1:4789",
            "startup_params":{"overlay_ip":"10.99.0.2","vni":42},
            "instruction":"Ping 10.99.0.1 through the tunnel and report the round-trip time"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"vxlan_ready","handler":{"type":"static","actions":[ping_action().example]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1] = json!({"event_pattern":"vxlan_icmp_echo_reply","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'vxlan_send_udp','ip':e['src_ip'],'port':9999,'data':'rtt %s ms' % e.get('rtt_ms')}]}))"}});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network"
    }
}

impl Client for VxlanClientProtocol {
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
        check(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}

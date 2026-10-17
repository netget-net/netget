//! What the model can do as the near end of a GTP path: an SGSN towards a GGSN (GTPv1 Gn),
//! an SGW towards a PGW (GTPv2 S5/S8), or an MME towards an SGW (GTPv2 S11) — echo the path,
//! create a session, modify its bearer, delete it, and carry user packets through its tunnel.
//!
//! Every action is fields. Sequence numbers, TEIDs, F-TEIDs, the IE encoding and the inner
//! packet's checksums are Rust's; which procedures run and with what subscriber, APN, PDN
//! type and bearer QoS is the model's.
use super::msg::{self, CreateParams, Role};
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::server::gtp::codec::{self, GtpVersion};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct GtpClientProtocol;
impl GtpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub const ECHO: &str = "gtp_echo";
pub const CREATE: &str = "gtp_create_session";
pub const MODIFY: &str = "gtp_modify_bearer";
pub const DELETE: &str = "gtp_delete_session";
pub const GPDU: &str = "gtp_send_gpdu";
pub const END_MARKER: &str = "gtp_send_end_marker";
pub const ERROR_INDICATION: &str = "gtp_send_error_indication";
pub const RESPOND: &str = "gtp_respond";

fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
    }
}

fn action(
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
            LogTemplate::new().with_info(format!("-> GTP {}", name.trim_start_matches("gtp_"))),
        ),
    }
}

fn session_param() -> Parameter {
    p(
        "session",
        "number",
        "The session, by the number this client gave it (gtp_response's session)",
        true,
    )
}

fn echo() -> ActionDefinition {
    action(
        ECHO,
        "Send an Echo Request on the control or user plane; the answer arrives as gtp_response (request echo_request) with the peer's Recovery counter.",
        vec![p("plane", "string", "Which path to probe (default control)", false)
            .with_choices(["control", "user"])],
        json!({"type": ECHO, "plane": "control"}),
    )
}

fn create() -> ActionDefinition {
    action(
        CREATE,
        "Ask the peer for a session: Create Session Request on GTPv2 (S5/S8 or S11), Create PDP Context Request on GTPv1 (Gn). Rust allocates this side's TEIDs and adds the F-TEIDs / GSN addresses, Recovery and the sequence number. The answer arrives as gtp_response with the cause, the UE address and the peer's TEIDs, and a session number to use afterwards.",
        vec![
            p("imsi", "string", "Subscriber IMSI, 5 to 15 digits. An identifier you invent; nothing looks it up", true),
            p("apn", "string", "Access point name, dotted (e.g. \"internet\")", true),
            p("msisdn", "string", "Subscriber number, up to 15 digits", false),
            p("mei", "string", "IMEI or IMEISV, 14 to 16 digits", false),
            p("pdn_type", "string", "Address family asked for (default ipv4)", false)
                .with_choices(["ipv4", "ipv6", "ipv4v6"]),
            p("ebi", "number", "EPS bearer id / NSAPI, 5..15 (default 5)", false),
            p("rat_type", "string", "Radio access: EUTRAN (default on GTPv2), UTRAN (default on GTPv1), GERAN, NR, LTE-M …", false),
            p("mcc", "string", "Serving network MCC, 3 digits (default 001)", false),
            p("mnc", "string", "Serving network MNC, 2 or 3 digits (default 01)", false),
            p("selection_mode", "number", "APN selection mode 0..3 (default 0: subscribed APN verified)", false),
            p("qos", "object", "Default bearer QoS: {qci 1..254 (default 9), arp_priority_level 1..15 (default 8), pre_emption_capability bool, pre_emption_vulnerability bool, mbr_uplink_kbps, mbr_downlink_kbps, gbr_uplink_kbps, gbr_downlink_kbps}. GTPv1 carries only the ARP (clamped to 1..3) in a best-effort profile", false),
            p("ambr_uplink_kbps", "number", "APN-AMBR uplink in kbit/s (GTPv2; default 100000)", false),
            p("ambr_downlink_kbps", "number", "APN-AMBR downlink in kbit/s (GTPv2; default 100000)", false),
            p("request_dns", "boolean", "Ask for DNS servers in the PCO (default true)", false),
            p("pgw_address", "string", "S11 only, required there: the PGW the SGW should create the session on", false),
        ],
        json!({"type": CREATE, "imsi": "001010123456789", "apn": "internet", "msisdn": "15551234567",
               "pdn_type": "ipv4", "qos": {"qci": 9, "arp_priority_level": 8}}),
    )
}

fn modify() -> ActionDefinition {
    action(
        MODIFY,
        "Tell the peer where this side's user plane is: Modify Bearer Request on GTPv2 (on S11 this client's GTP-U endpoint is the eNodeB's S1-U F-TEID), Update PDP Context Request on GTPv1. Addressed to the peer's control TEID learned at creation.",
        vec![session_param()],
        json!({"type": MODIFY, "session": 1}),
    )
}

fn delete() -> ActionDefinition {
    action(
        DELETE,
        "End a session: Delete Session Request on GTPv2, Delete PDP Context Request (teardown) on GTPv1, addressed to the peer's control TEID.",
        vec![session_param()],
        json!({"type": DELETE, "session": 1}),
    )
}

fn gpdu() -> ActionDefinition {
    action(
        GPDU,
        "Send one user packet through a session's tunnel as a G-PDU to the peer's data TEID. Describe the inner IPv4 packet; Rust builds the IP header and the ICMP or UDP header with their checksums. Packets the peer sends back arrive as gtp_tunnel_packet.",
        vec![
            session_param(),
            p("destination", "string", "Inner destination IPv4 address", true),
            p("source", "string", "Inner source IPv4 address (default: the session's UE address)", false),
            p("protocol", "string", "Inner packet kind (default icmp_echo)", false)
                .with_choices(["icmp_echo", "udp"]),
            p("identifier", "number", "ICMP echo identifier (default 1)", false),
            p("sequence", "number", "ICMP echo sequence number (default 1)", false),
            p("source_port", "number", "UDP source port (required for udp)", false),
            p("destination_port", "number", "UDP destination port (required for udp)", false),
            p("ttl", "number", "Inner TTL (default 64)", false),
            p("payload", "string", "Transport payload: text, or hex when encoding is hex", false),
            p("encoding", "string", "How payload is written (default utf8)", false)
                .with_choices(["utf8", "hex"]),
        ],
        json!({"type": GPDU, "session": 1, "destination": "10.45.0.1", "protocol": "icmp_echo",
               "identifier": 7, "sequence": 1, "payload": "ping"}),
    )
}

fn end_marker() -> ActionDefinition {
    action(
        END_MARKER,
        "Send an End Marker on a session's tunnel: no more packets follow on this path.",
        vec![session_param()],
        json!({"type": END_MARKER, "session": 1}),
    )
}

fn error_indication() -> ActionDefinition {
    action(
        ERROR_INDICATION,
        "Tell a peer that a TEID it sent a G-PDU to is not a tunnel here (Error Indication). Goes to the address that G-PDU came from; only a TEID seen in a gtp_tunnel_packet with known_tunnel false can be named.",
        vec![p("teid", "number", "The unknown TEID, from gtp_tunnel_packet", true)],
        json!({"type": ERROR_INDICATION, "teid": 4096}),
    )
}

fn respond() -> ActionDefinition {
    action(
        RESPOND,
        "Answer a request the peer sent (gtp_peer_request), with a cause only. Without an answer the peer retransmits and gives up; nothing is sent on your behalf.",
        vec![
            p("sequence", "number", "The request's sequence number, from gtp_peer_request", true),
            p("cause", "string", "request_accepted, context_not_found, system_failure, … or a number", true),
        ],
        json!({"type": RESPOND, "sequence": 1, "cause": "request_accepted"}),
    )
}

fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Stop the client. Sessions are not deleted first; delete them if the peer should know.",
        vec![],
        json!({"type": "disconnect"}),
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        echo(),
        create(),
        modify(),
        delete(),
        gpdu(),
        end_marker(),
        error_indication(),
        respond(),
        disconnect(),
    ]
}

fn ev(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, create().example.clone())
        .with_parameters(params)
        .with_actions(actions())
}

pub static READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "gtp_client_ready",
        "The client is bound and knows its peer; nothing has been sent yet.",
        vec![
            p("peer", "string", "The peer's control-plane address", true),
            p(
                "interface",
                "string",
                "gn (GTPv1, SGSN to GGSN), s5 (GTPv2, SGW to PGW) or s11 (GTPv2, MME to SGW)",
                true,
            ),
            p(
                "version",
                "number",
                "GTP version on the control plane",
                true,
            ),
            p(
                "local_control",
                "string",
                "This client's control-plane address",
                true,
            ),
            p(
                "local_user_plane",
                "string",
                "This client's GTP-U address",
                true,
            ),
        ],
    )
});

pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "gtp_response",
        "The peer answered a request this client sent.",
        vec![
            p(
                "request",
                "string",
                "What it answers: echo_request, create_session, modify_bearer, delete_session",
                true,
            ),
            p("message", "string", "The response's message name", true),
            p("sequence", "number", "The request's sequence number", true),
            p(
                "session",
                "number",
                "The session, for session procedures",
                false,
            ),
            p(
                "cause",
                "string",
                "The cause, by name (e.g. request_accepted) or cause_<n>",
                false,
            ),
            p(
                "accepted",
                "boolean",
                "Whether the cause grants the request",
                false,
            ),
            p(
                "ue_address",
                "string",
                "The address the peer gave the UE",
                false,
            ),
            p(
                "peer_control_teid",
                "number",
                "The peer's control TEID",
                false,
            ),
            p(
                "peer_data_teid",
                "number",
                "The peer's user-plane TEID",
                false,
            ),
            p("dns_servers", "array", "DNS servers from the PCO", false),
            p("recovery", "number", "The peer's restart counter", false),
        ],
    )
});

pub static TIMEOUT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "gtp_timeout",
        "A request went unanswered through all its retransmissions (T3-RESPONSE x N3-REQUESTS).",
        vec![
            p("request", "string", "The request that went unanswered: echo_request, create_session, modify_bearer or delete_session", true),
            p("sequence", "number", "Its sequence number", true),
            p("session", "number", "The session, if any", false),
            p("attempts", "number", "How many times it was sent", true),
        ],
    )
});

pub static TUNNEL_PACKET_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "gtp_tunnel_packet",
        "A G-PDU arrived on the user plane. The inner packet is decoded: addresses, protocol, ports or ICMP type, checksum verdicts, payload.",
        vec![
            p("teid", "number", "The TEID it was sent to", true),
            p("session", "number", "The session that TEID belongs to", false),
            p("known_tunnel", "boolean", "Whether the TEID is one of this client's", true),
            p("source_address", "string", "Where it came from", true),
            p("inner", "object", "The decoded inner packet", true),
        ],
    )
});

pub static TUNNEL_NOTIFICATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "gtp_tunnel_notification",
        "The peer sent an Error Indication (a TEID this client used is not a tunnel there) or an End Marker on the user plane.",
        vec![
            p("message", "string", "error_indication or end_marker", true),
            p("teid", "number", "The TEID concerned", true),
            p("session", "number", "The session it concerns, if known", false),
            p("peer_address", "string", "The GTP-U peer address the Error Indication names", false),
        ],
    )
});

pub static PEER_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "gtp_peer_request",
        "The peer sent a session request (e.g. Delete Bearer Request, Delete PDP Context Request). Echo Requests are answered automatically. Answer with gtp_respond.",
        vec![
            p("message", "string", "The request's name", true),
            p("sequence", "number", "Its sequence number, for gtp_respond", true),
            p("session", "number", "The session its TEID names, if any", false),
            p("cause", "string", "A cause it carried, if any", false),
        ],
    )
});

/// Bounds and shapes that do not depend on the client's role; the role-specific half
/// (S11's pgw_address, GTPv1's RAT numbering) is checked again when the action runs.
pub fn check(v: &Value) -> Result<()> {
    let kind = v["type"].as_str().unwrap_or_default();
    match kind {
        ECHO => {
            if let Some(plane) = v.get("plane") {
                ensure!(
                    matches!(plane.as_str(), Some("control" | "user")),
                    "plane is control or user"
                );
            }
        }
        CREATE => {
            CreateParams::from_action(Role::S5, v)?;
        }
        MODIFY | DELETE | END_MARKER => {
            session(v)?;
        }
        GPDU => {
            session(v)?;
            gpdu_parts(v)?;
        }
        ERROR_INDICATION => {
            v["teid"]
                .as_u64()
                .filter(|t| *t <= u32::MAX as u64)
                .context("teid is a 32-bit number")?;
        }
        RESPOND => {
            v["sequence"]
                .as_u64()
                .filter(|s| *s <= codec::V2_MAX_SEQUENCE as u64)
                .context("sequence is the request's sequence number")?;
            msg::cause_value(GtpVersion::V2, v.get("cause").context("cause is required")?)?;
        }
        other => bail!("Unknown GTP client action {other:?}"),
    }
    Ok(())
}

pub fn session(v: &Value) -> Result<u32> {
    v["session"]
        .as_u64()
        .filter(|s| *s <= u32::MAX as u64)
        .map(|s| s as u32)
        .context("session is required: the number gtp_response gave")
}

/// The validated pieces of a gtp_send_gpdu.
pub struct GpduParts {
    pub destination: std::net::Ipv4Addr,
    pub source: Option<std::net::Ipv4Addr>,
    pub inner: msg::Inner,
    pub ttl: u8,
    pub payload: Vec<u8>,
}

fn v4(v: &Value, key: &str) -> Result<Option<std::net::Ipv4Addr>> {
    match v.get(key).and_then(Value::as_str) {
        None => Ok(None),
        Some(s) => s.parse::<std::net::Ipv4Addr>().map(Some).with_context(|| {
            format!("{key} {s:?} is not an IPv4 address (the inner packet is IPv4)")
        }),
    }
}

fn port(v: &Value, key: &str) -> Result<u16> {
    v.get(key)
        .and_then(Value::as_u64)
        .filter(|p| *p <= 65535)
        .map(|p| p as u16)
        .with_context(|| format!("{key} is a port number, required for udp"))
}

pub fn gpdu_parts(v: &Value) -> Result<GpduParts> {
    let destination = v4(v, "destination")?.context("destination is required")?;
    let source = v4(v, "source")?;
    let u16_or = |k: &str, d: u16| -> Result<u16> {
        match v.get(k) {
            None => Ok(d),
            Some(x) => x
                .as_u64()
                .filter(|n| *n <= 65535)
                .map(|n| n as u16)
                .with_context(|| format!("{k} is 0..=65535")),
        }
    };
    let inner = match v
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("icmp_echo")
    {
        "icmp_echo" => msg::Inner::IcmpEcho {
            identifier: u16_or("identifier", 1)?,
            sequence: u16_or("sequence", 1)?,
        },
        "udp" => msg::Inner::Udp {
            source_port: port(v, "source_port")?,
            destination_port: port(v, "destination_port")?,
        },
        other => bail!("protocol {other:?} is icmp_echo or udp"),
    };
    let ttl = match v.get("ttl") {
        None => 64,
        Some(x) => x
            .as_u64()
            .filter(|n| (1..=255).contains(n))
            .context("ttl is 1..=255")? as u8,
    };
    let text = v.get("payload").and_then(Value::as_str).unwrap_or("");
    let payload = match v.get("encoding").and_then(Value::as_str).unwrap_or("utf8") {
        "utf8" => text.as_bytes().to_vec(),
        "hex" => hex::decode(text.trim()).context("payload is not valid hex")?,
        other => bail!("encoding {other:?} is utf8 or hex"),
    };
    ensure!(
        payload.len() <= msg::MAX_INNER_PAYLOAD,
        "payload of {} octets is past {}",
        payload.len(),
        msg::MAX_INNER_PAYLOAD
    );
    Ok(GpduParts {
        destination,
        source,
        inner,
        ttl,
        payload,
    })
}

impl Protocol for GtpClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "GTP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>GTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "gtp client",
            "gtp-c client",
            "sgsn",
            "mme",
            "sgw-c",
            "create session request",
            "create pdp context",
        ]
    }
    fn description(&self) -> &'static str {
        "GTP client: the near end of a mobile-core path (an SGSN on Gn, an SGW on S5/S8 or an MME on S11) that creates, modifies and deletes sessions and carries user packets through the tunnel"
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
            RESPONSE_EVENT.clone(),
            TIMEOUT_EVENT.clone(),
            TUNNEL_PACKET_EVENT.clone(),
            TUNNEL_NOTIFICATION_EVENT.clone(),
            PEER_REQUEST_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "interface".into(),
                type_hint: "string".into(),
                description: "Which node this client is: s5 (GTPv2, an SGW towards a PGW), s11 (GTPv2, an MME towards an SGW) or gn (GTPv1, an SGSN towards a GGSN)".into(),
                required: false,
                example: json!("s5"),
                default: Some(json!(super::DEFAULT_INTERFACE)),
            },
            ParameterDefinition {
                name: "local_port".into(),
                type_hint: "number".into(),
                description: "UDP port the control plane sends from (default ephemeral; 2123 to receive requests a peer starts)".into(),
                required: false,
                example: json!(2123),
                default: None,
            },
            ParameterDefinition {
                name: "user_plane_port".into(),
                type_hint: "number".into(),
                description: "UDP port of this client's GTP-U endpoint. Peers send G-PDUs to 2152 whatever the F-TEID says, so that is the default; when 2152 is taken the client says so and uses an ephemeral port. 0 asks for an ephemeral port".into(),
                required: false,
                example: json!(2152),
                default: Some(json!(codec::GTPU_PORT)),
            },
            ParameterDefinition {
                name: "peer_user_plane_port".into(),
                type_hint: "number".into(),
                description: "UDP port G-PDUs and user-plane echoes are sent to on the peer".into(),
                required: false,
                example: json!(2152),
                default: Some(json!(codec::GTPU_PORT)),
            },
            ParameterDefinition {
                name: "t3_response_ms".into(),
                type_hint: "number".into(),
                description: "T3-RESPONSE: milliseconds to wait for an answer before retransmitting (100..=60000)".into(),
                required: false,
                example: json!(3000),
                default: Some(json!(super::T3_RESPONSE.as_millis() as u64)),
            },
            ParameterDefinition {
                name: "n3_requests".into(),
                type_hint: "number".into(),
                description: "N3-REQUESTS: retransmissions after the first send before gtp_timeout (0..=10)".into(),
                required: false,
                example: json!(3),
                default: Some(json!(super::N3_REQUESTS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's GTP codec (src/server/gtp/codec.rs) in the requesting role: Create Session / Create PDP Context, Modify Bearer / Update PDP Context, Delete Session / Delete PDP Context and Echo, with sequence numbers, TEID allocation, F-TEIDs and GSN addresses in Rust; responses matched by sequence and message type; T3-RESPONSE/N3-REQUESTS retransmission; a GTP-U endpoint that sends G-PDUs whose inner IPv4/ICMP/UDP packet Rust builds with its checksums, answers echoes, and decodes what arrives")
            .llm_control("Which procedures to run and when, the subscriber (IMSI, MSISDN, MEI), APN, PDN type, bearer QoS and AMBR, what to send through the tunnel, and how to answer requests the peer starts")
            .e2e_testing("tests/client/gtp: wmnsk/go-gtp v0.8.12 as a PGW (GTPv2 S5/S8, GTP-U) decoding every request NetGet sends, and Osmocom osmo-ggsn as a GGSN (GTPv1 Gn) whose kernel tun device answers an ICMP echo NetGet tunnels to it; tshark's gtp/gtpv2 dissectors read both directions")
            .notes("Experimental: the client Beta bar's peers exist and the tests fail rather than skip without them, but osmo-ggsn runs only on Linux with a tun device, so its half of the evidence runs in the gtp-client job of protocol-pairs.yml (dispatched by hand) and not on every change. One peer per client. The inner packet is IPv4 only. No secondary PDP contexts or dedicated bearers, no handover, no GTP' or GTPv0.")
            .max_inbound_bytes(msg::MAX_DATAGRAM)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Act as an SGW towards the PGW at 192.0.2.10: create a session for IMSI 001010123456789 on APN internet, then ping 8.8.8.8 through the tunnel"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"gtp","remote_addr":"127.0.0.1:2123",
            "startup_params": {"interface": "s5"},
            "instruction":"Create a session for IMSI 001010123456789 on APN internet, then send one ICMP echo through the tunnel to 10.45.0.1"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"gtp_client_ready","handler":{"type":"static","actions":[create().example]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1] = json!({"event_pattern":"gtp_response","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\na=[]\nif e.get('request')=='create_session' and e.get('accepted'):\n  a=[{'type':'gtp_send_gpdu','session':e['session'],'destination':'10.45.0.1','payload':'ping'}]\nprint(json.dumps({'actions':a}))"}});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Mobile"
    }
}

impl Client for GtpClientProtocol {
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

//! HSRP (Hot Standby Router Protocol) actions, events and metadata.
//!
//! Everything the model sees is structured and named: states are words, not the numbers that
//! differ between the two versions; addresses are dotted quads; the authentication field is a
//! string. Nothing here accepts or emits raw bytes or base64 — see the action-design rules in
//! the root `CLAUDE.md`, and `codec.rs` for why the state numbering in particular must never
//! cross the boundary as an integer.
//!
//! **Read `src/server/hsrp/CLAUDE.md` before changing any of this.** The model picks the
//! priority and may send a Coup; winning makes NetGet the segment's default gateway.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::hsrp::codec::{
    self, HsrpMessage, HsrpState, HsrpVersion, Opcode, DEFAULT_AUTH_DATA,
};
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::LazyLock;

/// The port HSRPv1 and HSRPv2-over-IPv4 use (RFC 2281 §5.1).
///
/// **It is above 1023**, which is why this protocol declares `PrivilegeRequirement::None` and
/// is the one member of its tier that can actually be exercised in an unprivileged test.
pub const HSRP_PORT: u16 = 1985;

/// The port HSRPv2 uses for IPv6.
pub const HSRP_V6_PORT: u16 = 2029;

/// All-routers multicast group, used by HSRPv1 (RFC 2281 §5.1).
pub const HSRP_V1_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);

/// HSRPv2's own IPv4 group. **Not the same as v1's** — v2 moved off the all-routers group so
/// that v1 speakers do not see its TLVs.
pub const HSRP_V2_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 102);

/// HSRPv2's IPv6 group.
pub const HSRP_V6_GROUP: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x0066);

/// Cisco's default Hello interval, in seconds.
const DEFAULT_HELLOTIME_SECS: u64 = 3;
/// Cisco's default hold time, in seconds. Conventionally ~3x the hello interval.
const DEFAULT_HOLDTIME_SECS: u64 = 10;

pub struct HsrpProtocol;

impl Default for HsrpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl HsrpProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for HsrpProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "version".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Which HSRP version this instance is configured for: 1 (RFC 2281, a flat \
                     20-byte packet on 224.0.0.2) or 2 (Cisco's TLV format on 224.0.0.102, or \
                     FF02::66 for IPv6). Defaults to 1. THE TWO WIRE FORMATS ARE NOT \
                     INTEROPERABLE. This selects the multicast group joined, and is reported to \
                     the model as 'configured_version' on every event; incoming datagrams of \
                     either version are still parsed and reported."
                        .to_string(),
                required: false,
                example: json!(1),
                default: None,
            },
            ParameterDefinition {
                name: "join_multicast".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "Join the HSRP multicast group so advertisements from the segment are \
                     received. Defaults to true. A failed join is logged and never fatal - \
                     loopback carries no multicast route, so this fails routinely in local \
                     testing while datagrams sent straight to this port are still handled."
                        .to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
            ParameterDefinition {
                name: "multicast_interface".to_string(),
                type_hint: "string".to_string(),
                description: "Local IPv4 address of the interface to join the group on (e.g. \
                     '192.168.1.10'). Omit to let the host choose. Ignored when join_multicast \
                     is false or the socket is IPv6, which selects by interface index instead."
                    .to_string(),
                required: false,
                example: json!("192.168.1.10"),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Deliberately empty, and this is the safety property of the whole protocol.
        //
        // An async action is one the model can fire without a network event - i.e. a way to
        // start advertising on its own initiative and keep going. That is exactly the
        // autonomous Active router this protocol must not become: an election NetGet wins and
        // then cannot serve black-holes the segment. Every advertisement here is a reply to
        // something that actually arrived.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_hsrp_hello_action(),
            send_hsrp_coup_action(),
            send_hsrp_resign_action(),
            no_advertisement_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "HSRP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_hsrp_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>HSRP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "hsrp",
            "hot standby router protocol",
            "first hop redundancy",
            "fhrp",
            "rfc2281",
            "gateway redundancy",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // Every datagram becomes a connection entry that nothing ever closes; the 10-second
            // idle sweep reaps them only for protocols that declare this.
            .connectionless()
            // Deliberately silent: HSRP has no error message. A hello asserts a router's state and
            // priority for the virtual gateway, and a fabricated one can win the election and pull
            // the segment's default route onto this host.
            .deliberately_silent()
            .state(DevelopmentState::Experimental)
            // Port 1985 is above 1023 and joining a multicast group needs no elevation, so
            // unlike the rest of the L2/routing tier this protocol really does run - and really
            // is exercised - in an unprivileged test.
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(1985)
            .implementation(
                "Hand-written codec for both wire formats (src/server/hsrp/codec.rs), no \
                 third-party HSRP crate exists. HSRPv1 is the flat 20-byte RFC 2281 packet; \
                 HSRPv2 is Cisco's TLV format (Group State type 1 length 40, plus Text Auth \
                 type 3). The two are parsed apart by their first byte - v1's Version byte is \
                 0, a v2 TLV type never is. NO autonomous election state machine: the server \
                 never advertises on its own initiative.",
            )
            .llm_control(
                "Every received Hello, Coup and Resign. The model chooses the priority, the \
                 state it claims and whether to send a Coup - i.e. it decides whether NetGet \
                 tries to become the segment's active gateway.",
            )
            .e2e_testing(
                "tests/server/hsrp/e2e_test.rs drives the real UDP socket and pins both packet \
                 layouts against literal bytes written from RFC 2281 and Cisco's HSRPv2 \
                 documentation, including the NUL-padded 'cisco' auth field. The transport IS \
                 exercised. The peer is a hand-written in-test encoder, which the root \
                 CLAUDE.md classes as an independent READING of the spec, not an independent \
                 implementation.",
            )
            .notes(
                "Experimental. The transport genuinely executes in the test suite - port 1985 \
                 is unprivileged, so unlike the rest of this tier nothing is mocked away - but \
                 NO independent HSRP implementation has ever accepted a packet from this \
                 server. There is no HSRP crate on crates.io and no runnable HSRP speaker on \
                 this machine (keepalived and vrrpd speak VRRP, not HSRP; a real peer means a \
                 Cisco device). The HSRPv2 layout in particular is derived from Cisco \
                 documentation and dissectors and has never been checked against real hardware. \
                 SAFETY: an LLM failure produces SILENCE, never a fabricated Hello - a Hello \
                 asserts gateway ownership, and winning an election NetGet cannot serve \
                 black-holes the segment. The plaintext auth field (default 'cisco') is NOT \
                 security; HSRPv2 MD5 digests are reported structurally but neither verified \
                 nor generated.",
            )
            .max_inbound_bytes(crate::server::hsrp::MAX_DATAGRAM_LEN)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Hot Standby Router Protocol gateway-redundancy speaker (HSRPv1 RFC 2281 and HSRPv2)"
    }

    fn example_prompt(&self) -> &'static str {
        "HSRP on port 1985: observe group 1 and stay in Listen, never claim Active"
    }

    fn group_name(&self) -> &'static str {
        "Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // A deterministic observer: report what the segment is doing, claim nothing. This is
        // the shape most uses of this protocol should have, which is why it is the script
        // example rather than a priority contest.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] in ("hsrp_hello_received", "hsrp_coup_received",
                             "hsrp_resign_received"):
    # Answer a neighbour's Hello with our own, one priority BELOW theirs, so this
    # speaker is visible on the segment but never wins the election. Claiming
    # Active would make NetGet the default gateway for every host on the link.
    theirs = event.get("priority", 100)
    actions = [{"type": "send_hsrp_hello",
                "version": event["version"],
                "state": "listen",
                "priority": max(theirs - 1, 0),
                "group": event["group"],
                "virtual_ip": event["virtual_ip"],
                "auth_data": event.get("auth_data") or "cisco"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: deciding whether to contest an election is a judgement call, and the
            // instruction is where the operator constrains it.
            json!({
                "type": "open_server",
                "port": HSRP_PORT,
                "base_stack": "hsrp",
                "startup_params": {"version": 1},
                "instruction": "Act as an HSRPv1 speaker in group 1 for virtual IP 192.168.1.1. Answer every Hello with a Hello of your own in the 'listen' state at priority 50. NEVER send a Coup and NEVER claim the 'active' state - this router cannot actually forward traffic, so winning the election would black-hole the segment."
            }),
            // Script mode: no model call, fully deterministic, and it echoes the group and
            // virtual IP out of the event rather than hardcoding them.
            json!({
                "type": "open_server",
                "port": HSRP_PORT,
                "base_stack": "hsrp",
                "startup_params": {"version": 1},
                "event_handlers": [{
                    "event_pattern": "hsrp_*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode expresses one thing well here: deliberate silence. A static handler
            // cannot see the event, so it cannot echo the group or the virtual IP, and a Hello
            // carrying the wrong group is ignored by every receiver - silence with extra steps.
            json!({
                "type": "open_server",
                "port": HSRP_PORT,
                "base_stack": "hsrp",
                "event_handlers": [{
                    "event_pattern": "hsrp_*",
                    "handler": {
                        "type": "static",
                        "actions": [{"type": "no_advertisement"}]
                    }
                }]
            }),
        )
    }
}

impl Server for HsrpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move { crate::server::hsrp::HsrpServer::spawn_with_llm_actions(ctx).await })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_hsrp_hello" => build_advertisement(&action, Opcode::Hello),
            "send_hsrp_coup" => build_advertisement(&action, Opcode::Coup),
            "send_hsrp_resign" => build_advertisement(&action, Opcode::Resign),
            // Explicit silence, and a real answer rather than a missing one: the caller
            // distinguishes it from "the model produced nothing" and logs `decision=model_silent`.
            "no_advertisement" => Ok(ActionResult::NoAction),
            _ => Err(anyhow!("Unknown HSRP action: {action_type}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

fn required_str<'a>(action: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    action
        .get(key)
        .and_then(|v| v.as_str())
        .with_context(|| format!("Missing '{key}' parameter"))
}

fn required_u64(action: &serde_json::Value, key: &str) -> Result<u64> {
    action
        .get(key)
        .and_then(|v| v.as_u64())
        .with_context(|| format!("Missing or non-numeric '{key}' parameter"))
}

/// Parse `aa:bb:cc:dd:ee:ff` (or `-` separated) into the HSRPv2 six-byte identifier.
fn parse_identifier(value: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = value.split([':', '-']).collect();
    if parts.len() != 6 {
        return Err(anyhow!(
            "'identifier' must be a 6-octet MAC-style address like '00:11:22:33:44:55', got \
             '{value}'"
        ));
    }
    let mut out = [0u8; 6];
    for (slot, part) in out.iter_mut().zip(parts) {
        *slot = u8::from_str_radix(part, 16)
            .with_context(|| format!("Invalid hex octet '{part}' in identifier '{value}'"))?;
    }
    Ok(out)
}

/// Build one advertisement from the model's action.
///
/// Every failure here is a hard error rather than a substituted default. That is the
/// fail-closed direction: an unusable action becomes `decision=fail_closed_action_error` and
/// **nothing goes on the wire**, which is right for a protocol whose every message is a
/// positive claim about who owns the segment's gateway address.
fn build_advertisement(action: &serde_json::Value, opcode: Opcode) -> Result<ActionResult> {
    // Required rather than defaulted. Defaulting the version would let a model that forgot the
    // field put a v1 packet on a v2 segment, where it is silently ignored - which looks
    // exactly like this server having said nothing.
    let version = HsrpVersion::from_number(required_u64(action, "version")?)?;
    let state = HsrpState::from_str_name(required_str(action, "state")?)?;

    let priority = required_u64(action, "priority")?;
    let priority = u32::try_from(priority).map_err(|_| {
        anyhow!("'priority' must fit in 32 bits (HSRPv2) or 8 bits (HSRPv1), got {priority}")
    })?;

    let group = required_u64(action, "group")?;
    let group = u16::try_from(group)
        .map_err(|_| anyhow!("'group' must be 0-255 (HSRPv1) or 0-4095 (HSRPv2), got {group}"))?;

    let virtual_ip_str = required_str(action, "virtual_ip")?;
    let virtual_ip = IpAddr::from_str(virtual_ip_str).with_context(|| {
        format!("'virtual_ip' must be an IP address like '192.168.1.1', got '{virtual_ip_str}'")
    })?;

    let hellotime_secs = action
        .get("hellotime")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_HELLOTIME_SECS);
    let holdtime_secs = action
        .get("holdtime")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_HOLDTIME_SECS);
    let hellotime_secs = u32::try_from(hellotime_secs)
        .map_err(|_| anyhow!("'hellotime' is out of range: {hellotime_secs}"))?;
    let holdtime_secs = u32::try_from(holdtime_secs)
        .map_err(|_| anyhow!("'holdtime' is out of range: {holdtime_secs}"))?;

    // The field exists in every v1 packet, so a v1 message with no auth_data gets the Cisco
    // default rather than eight zero bytes, which no real peer sends.
    let auth_data = match action.get("auth_data").and_then(|v| v.as_str()) {
        Some(value) => Some(value.to_string()),
        None => match version {
            HsrpVersion::V1 => Some(DEFAULT_AUTH_DATA.to_string()),
            // In v2 the string is its own TLV, so "absent" is expressible and is what
            // omitting the field should mean.
            HsrpVersion::V2 => None,
        },
    };

    let identifier = match action.get("identifier").and_then(|v| v.as_str()) {
        Some(value) => parse_identifier(value)?,
        None => [0u8; 6],
    };

    // The digest is 16 raw bytes derived from a shared key. NetGet holds no key material and
    // implements no storage, so it cannot produce a valid one - and an invalid digest is worse
    // than no TLV, because a peer configured for MD5 logs it as an attack rather than as a
    // misconfiguration. Refusing with the reason named is the honest failure.
    if action.get("md5_key").is_some() || action.get("md5_key_id").is_some() {
        return Err(anyhow!(
            "HSRPv2 MD5 authentication cannot be generated: it needs a shared key, and NetGet \
             stores no key material and implements no storage. Incoming MD5 TLVs are reported \
             structurally (algorithm, flags, sender_address, key_id) but are neither verified \
             nor produced. Use 'auth_data' for the plaintext Text Authentication TLV."
        ));
    }

    let message = HsrpMessage {
        version,
        opcode,
        state,
        hellotime_secs,
        holdtime_secs,
        priority,
        group,
        auth_data,
        virtual_ip,
        identifier,
        md5_auth: None,
    };

    Ok(ActionResult::Output(codec::encode(&message)?))
}

// ---------------------------------------------------------------------------
// Action definitions
// ---------------------------------------------------------------------------

/// The parameters every advertisement shares. All three opcodes carry the identical packet;
/// only the opcode byte differs, so sharing the list keeps them from drifting.
fn advertisement_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "version".to_string(),
            type_hint: "number".to_string(),
            description:
                "1 or 2. REQUIRED - HSRPv1 and HSRPv2 are different, non-interoperable wire \
                 formats, and a v1 packet on a v2 segment is silently ignored. Echo the \
                 'version' from the event to answer a neighbour in the format it spoke."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "state".to_string(),
            type_hint: "string".to_string(),
            description:
                "One of 'initial', 'learn', 'listen', 'speak', 'standby', 'active'. NAMES, not \
                 numbers, because v1 and v2 encode them differently. 'active' CLAIMS THE \
                 VIRTUAL IP: it tells every host on the segment that this router is their \
                 default gateway. Only claim it if NetGet is genuinely meant to answer for that \
                 address."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "priority".to_string(),
            type_hint: "number".to_string(),
            description:
                "Election priority: highest wins. 0-255 for HSRPv1, 0-4294967295 for HSRPv2; \
                 Cisco's default is 100. A priority above the current Active router's will take \
                 the gateway role over (when preemption is enabled on the peer)."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "group".to_string(),
            type_hint: "number".to_string(),
            description: "HSRP group number: 0-255 for HSRPv1, 0-4095 for HSRPv2. Must match the \
                 neighbour's group or the advertisement is ignored - echo it from the event."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "virtual_ip".to_string(),
            type_hint: "string".to_string(),
            description: "The virtual gateway address this group shares, as a dotted quad (e.g. \
                 '192.168.1.1'), or an IPv6 address for HSRPv2. Echo it from the event."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "hellotime".to_string(),
            type_hint: "number".to_string(),
            description: "Seconds between Hellos, as advertised to peers. Defaults to 3 (Cisco's \
                 default). HSRPv1 allows 1-255; HSRPv2 carries milliseconds on the wire and \
                 this value is multiplied by 1000."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "holdtime".to_string(),
            type_hint: "number".to_string(),
            description:
                "Seconds a peer should wait before declaring this speaker dead. Defaults to 10 \
                 (Cisco's default); conventionally about three times the hellotime."
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "auth_data".to_string(),
            type_hint: "string".to_string(),
            description:
                "Plaintext authentication string, at most 8 characters, NUL-padded on the wire. \
                 Defaults to 'cisco' for HSRPv1 (the field is mandatory there and 'cisco' is the \
                 universal default); omitted entirely for HSRPv2, where it is an optional TLV. \
                 THIS IS NOT SECURITY - it travels in clear text in every packet and anyone on \
                 the segment can read it."
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "identifier".to_string(),
            type_hint: "string".to_string(),
            description:
                "HSRPv2 only: the sender's 6-octet identifier, MAC-style ('00:11:22:33:44:55'). \
                 Defaults to all zeros. Ignored for HSRPv1, which has no such field."
                    .to_string(),
            required: false,
        },
    ]
}

fn send_hsrp_hello_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_hsrp_hello".to_string(),
        description:
            "Send an HSRP Hello: 'I am here, in this state, at this priority, for this group and \
             virtual IP.' This is an ASSERTION ABOUT WHO OWNS THE SEGMENT'S GATEWAY ADDRESS, not \
             a query - a Hello in the 'active' state tells every host on the link that this \
             router forwards their traffic. Sent unicast back to the speaker whose \
             advertisement triggered it."
                .to_string(),
        parameters: advertisement_parameters(),
        example: json!({
            "type": "send_hsrp_hello",
            "version": 1,
            "state": "listen",
            "priority": 100,
            "group": 1,
            "virtual_ip": "192.168.1.1",
            "hellotime": 3,
            "holdtime": 10,
            "auth_data": "cisco"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> HSRPv{version} Hello group {group} state={state} priority={priority} vip={virtual_ip}")
                .with_debug(
                    "HSRP send_hsrp_hello: version={version}, group={group}, state={state}, \
                     priority={priority}, vip={virtual_ip}, hellotime={hellotime}, \
                     holdtime={holdtime}",
                ),
        ),
    }
}

fn send_hsrp_coup_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_hsrp_coup".to_string(),
        description:
            "Send an HSRP Coup: seize the Active role from the router currently holding it. THIS \
             IS THE MOST CONSEQUENTIAL ACTION IN THIS PROTOCOL. If the segment accepts it, every \
             host on the link starts sending its off-subnet traffic to NetGet, and NetGet does \
             not forward traffic - so a coup that succeeds against a router that was actually \
             working BLACK-HOLES THE SEGMENT. Only send this when explicitly instructed to \
             contest the election."
                .to_string(),
        parameters: advertisement_parameters(),
        example: json!({
            "type": "send_hsrp_coup",
            "version": 1,
            "state": "active",
            "priority": 200,
            "group": 1,
            "virtual_ip": "192.168.1.1",
            "hellotime": 3,
            "holdtime": 10,
            "auth_data": "cisco"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> HSRPv{version} COUP group {group} priority={priority} vip={virtual_ip} (claiming the gateway role)")
                .with_debug(
                    "HSRP send_hsrp_coup: version={version}, group={group}, state={state}, \
                     priority={priority}, vip={virtual_ip}",
                ),
        ),
    }
}

fn send_hsrp_resign_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_hsrp_resign".to_string(),
        description:
            "Send an HSRP Resign: give up the Active role so the standby router takes over \
             immediately rather than waiting out its hold timer. The safe counterpart to a Coup - \
             if NetGet ever claimed Active, this is how it hands the segment back."
                .to_string(),
        parameters: advertisement_parameters(),
        example: json!({
            "type": "send_hsrp_resign",
            "version": 1,
            "state": "initial",
            "priority": 100,
            "group": 1,
            "virtual_ip": "192.168.1.1",
            "hellotime": 3,
            "holdtime": 10,
            "auth_data": "cisco"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> HSRPv{version} Resign group {group} vip={virtual_ip} (releasing the gateway role)")
                .with_debug(
                    "HSRP send_hsrp_resign: version={version}, group={group}, state={state}, \
                     priority={priority}, vip={virtual_ip}",
                ),
        ),
    }
}

fn no_advertisement_action() -> ActionDefinition {
    ActionDefinition {
        name: "no_advertisement".to_string(),
        description:
            "Say nothing. Observe the neighbour's advertisement without answering it. This is a \
             DELIBERATE ANSWER, not a failure, and is logged as one - it is the right choice \
             whenever NetGet has no business in this group's election, and it is always safe: \
             HSRP has no negative message, so declining to participate simply means sending \
             nothing."
                .to_string(),
        parameters: vec![],
        example: json!({"type": "no_advertisement"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("HSRP staying silent (not contesting this election)")
                .with_debug("HSRP no_advertisement: nothing will be written to the wire"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Action & event constants
// ---------------------------------------------------------------------------

pub static SEND_HSRP_HELLO_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_hsrp_hello_action);
pub static SEND_HSRP_COUP_ACTION: LazyLock<ActionDefinition> = LazyLock::new(send_hsrp_coup_action);
pub static SEND_HSRP_RESIGN_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_hsrp_resign_action);
pub static NO_ADVERTISEMENT_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(no_advertisement_action);

/// The vocabulary offered on every HSRP event.
///
/// All three events get the same set: any of the three opcodes is a legal reply to any of
/// them, and silence is always legal. Attaching these is not optional - `call_llm` builds the
/// model's tool list from `event.event_type.actions`, so an event without them leaves the
/// model unable to answer at all.
fn hsrp_event_actions() -> Vec<ActionDefinition> {
    vec![
        SEND_HSRP_HELLO_ACTION.clone(),
        SEND_HSRP_COUP_ACTION.clone(),
        SEND_HSRP_RESIGN_ACTION.clone(),
        NO_ADVERTISEMENT_ACTION.clone(),
    ]
}

/// The fields every HSRP event carries. Identical across the three because the packet is
/// identical across the three opcodes.
fn hsrp_event_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "version".to_string(),
            type_hint: "number".to_string(),
            description: "1 or 2 - which wire format the sender used. Echo it back to answer in \
                          the same format."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "opcode".to_string(),
            type_hint: "string".to_string(),
            description: "'hello', 'coup' or 'resign'.".to_string(),
            required: true,
        },
        Parameter {
            name: "state".to_string(),
            type_hint: "string".to_string(),
            description: "The sender's state: 'initial', 'learn', 'listen', 'speak', 'standby' or \
                 'active'. A sender in 'active' currently owns the virtual IP."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "priority".to_string(),
            type_hint: "number".to_string(),
            description: "The sender's election priority. Highest wins.".to_string(),
            required: true,
        },
        Parameter {
            name: "group".to_string(),
            type_hint: "number".to_string(),
            description: "HSRP group number. Echo it in any reply or the reply is ignored."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "hellotime".to_string(),
            type_hint: "number".to_string(),
            description: "The sender's advertised Hello interval, in seconds.".to_string(),
            required: true,
        },
        Parameter {
            name: "holdtime".to_string(),
            type_hint: "number".to_string(),
            description: "Seconds before the sender should be declared dead, as it advertises it."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "virtual_ip".to_string(),
            type_hint: "string".to_string(),
            description: "The virtual gateway address this group shares, as a dotted quad (or an \
                          IPv6 address for HSRPv2)."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "auth_data".to_string(),
            type_hint: "string".to_string(),
            description:
                "The plaintext authentication string the sender used, trailing NULs stripped; \
                 null if the field was empty or absent. Usually 'cisco'. It is clear text and \
                 proves nothing about the sender."
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "identifier".to_string(),
            type_hint: "string".to_string(),
            description: "HSRPv2 only: the sender's 6-octet identifier, MAC-style. All zeros for \
                          HSRPv1, which has no such field."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "md5_auth".to_string(),
            type_hint: "object".to_string(),
            description:
                "HSRPv2 only, null when absent: {algorithm, flags, sender_address, key_id} from \
                 an MD5 Authentication TLV. The digest itself is deliberately not reported and \
                 is NOT verified - that would need the shared key, which NetGet does not hold."
                    .to_string(),
            required: false,
        },
        Parameter {
            name: "source_address".to_string(),
            type_hint: "string".to_string(),
            description: "Address and port the datagram came from. Any reply goes here, unicast."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "configured_version".to_string(),
            type_hint: "number".to_string(),
            description: "The HSRP version this NetGet instance was started for (its 'version' \
                          startup parameter). Datagrams of the other version are still reported."
                .to_string(),
            required: true,
        },
    ]
}

fn hsrp_event(id: &'static str, description: &'static str) -> EventType {
    EventType::new(
        id,
        description,
        json!({
            "type": "send_hsrp_hello",
            "version": 1,
            "state": "listen",
            "priority": 100,
            "group": 1,
            "virtual_ip": "192.168.1.1",
            "hellotime": 3,
            "holdtime": 10,
            "auth_data": "cisco"
        }),
    )
    .with_parameters(hsrp_event_parameters())
    .with_actions(hsrp_event_actions())
    .with_alternative_example(json!({"type": "no_advertisement"}))
    .with_log_template(
        LogTemplate::new()
            .with_info(
                "HSRPv{version} {opcode} group {group} from {source_address} state={state} \
                 priority={priority} vip={virtual_ip}",
            )
            .with_debug(
                "HSRP {opcode}: version={version}, group={group}, state={state}, \
                 priority={priority}, vip={virtual_ip}, hellotime={hellotime}, \
                 holdtime={holdtime}, auth={auth_data}, from={source_address}",
            )
            .with_trace("HSRP event: {json_pretty(.)}"),
    )
}

/// A neighbour advertised its presence and its place in the election.
pub static HSRP_HELLO_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    hsrp_event(
        "hsrp_hello_received",
        "An HSRP speaker on the segment announced itself: its group, its state, its priority and \
         the virtual gateway IP the group shares. Answering with a Hello of your own puts NetGet \
         into that election; answering with 'active' or a Coup claims the gateway role for every \
         host on the link. Prefer 'no_advertisement' unless instructed otherwise.",
    )
});

/// A neighbour is seizing the Active role.
pub static HSRP_COUP_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    hsrp_event(
        "hsrp_coup_received",
        "An HSRP speaker sent a Coup: it is taking the Active role, and therefore the virtual \
         gateway address, from whoever holds it now. If NetGet is not the active router this is \
         purely informational and 'no_advertisement' is the right answer.",
    )
});

/// A neighbour is giving up the Active role.
pub static HSRP_RESIGN_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    hsrp_event(
        "hsrp_resign_received",
        "An HSRP speaker sent a Resign: it is giving up the Active role, so the gateway address \
         is about to move. The standby router takes over on its own; NetGet has no obligation to \
         answer, and should not claim the role unless it can actually forward traffic.",
    )
});

/// Event types this protocol raises. All three have real emit sites in `mod.rs`, selected by
/// the received opcode.
pub fn get_hsrp_event_types() -> Vec<EventType> {
    vec![
        HSRP_HELLO_RECEIVED_EVENT.clone(),
        HSRP_COUP_RECEIVED_EVENT.clone(),
        HSRP_RESIGN_RECEIVED_EVENT.clone(),
    ]
}

/// Map an opcode to the event it raises. Keeping this next to the definitions is what stops a
/// fourth opcode being added with no event, or an event being declared and never emitted.
pub fn event_for_opcode(opcode: Opcode) -> &'static LazyLock<EventType> {
    match opcode {
        Opcode::Hello => &HSRP_HELLO_RECEIVED_EVENT,
        Opcode::Coup => &HSRP_COUP_RECEIVED_EVENT,
        Opcode::Resign => &HSRP_RESIGN_RECEIVED_EVENT,
    }
}

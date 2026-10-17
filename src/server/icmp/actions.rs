//! ICMP protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Name of the loopback interface on this platform.
///
/// Linux and Windows call it `lo`; macOS and the BSDs call it `lo0`. Hardcoding `lo` made the
/// default binding unresolvable on macOS ("Device 'lo' not found").
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const DEFAULT_LOOPBACK_INTERFACE: &str = "lo0";
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
const DEFAULT_LOOPBACK_INTERFACE: &str = "lo";

/// ICMP protocol action handler
pub struct IcmpProtocol;

impl IcmpProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for IcmpProtocol {
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        // ICMP uses interface-based binding (loopback by default)
        Some(crate::protocol::BindingDefaults::interface_based(
            DEFAULT_LOOPBACK_INTERFACE,
        ))
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_echo_reply_action(),
            send_destination_unreachable_action(),
            send_time_exceeded_action(),
            // send_timestamp_reply_action(), // TODO: Removed - timestamp support requires pnet timestamp packet types
            ignore_icmp_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "ICMP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_icmp_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "IP>ICMP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["icmp", "ping", "echo", "traceroute"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::RawSockets)
            .connectionless()
            // Deliberately silent: RFC 792 defines no failure reply to an echo request, and a
            // synthesised Destination Unreachable would be a false statement about reachability.
            // Silence is exactly what a filtered host does, so every peer already handles it.
            .deliberately_silent()
            .implementation("Raw IP sockets + pnet for ICMP packet handling")
            .llm_control("Full control - can respond to all ICMP message types")
            .e2e_testing(
                "tests/server/icmp/packet_codec_test.rs is the only ICMP server test that runs \
                 unprivileged: it asserts every emitted packet field-by-field against RFC 791 \
                 and RFC 792, that hostile action JSON is refused rather than panicking, and \
                 that each advertised example is accepted by its own executor. \
                 tests/capture_startup_reports_failure_test.rs asserts spawn() returns Err \
                 without raw-socket privilege. tests/server/icmp/e2e_test.rs crafts real echo \
                 requests and reads the replies off a raw socket, but is #[ignore]d for \
                 privilege and has never been run in CI.",
            )
            .notes(
                "Requires root/CAP_NET_RAW for raw socket access. Startup failure is reported: \
                 spawn_with_llm awaits the SOCK_RAW sockets, so a privilege failure lands in \
                 ServerStatus::Error rather than Running. UNVERIFIED, and this is the whole \
                 gap: no packet this server builds has ever been observed leaving a real \
                 socket. Until this pass none could have been correct - the send socket did not \
                 set IP_HDRINCL, so the kernel prepended its own header and every reply went out \
                 with our IPv4 header sitting where the ICMP message belongs. That is fixed and \
                 unit-tested up to the syscall, no further. The 'interface' argument is accepted \
                 and ignored - the socket receives ICMP from every interface. Note the kernel \
                 answers echo requests itself, so a userspace reply is a second reply on the \
                 wire.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "ICMP (Internet Control Message Protocol) server"
    }

    fn example_prompt(&self) -> &'static str {
        "Listen for ICMP echo requests on eth0"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: reply to every echo request, swapping source/dest and
        // echoing the id/sequence/payload, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "icmp_echo_request":
    actions = [{"type": "send_echo_reply",
                "source_ip": event.get("destination_ip", ""),
                "destination_ip": event.get("source_ip", ""),
                "identifier": event.get("identifier", 0),
                "sequence": event.get("sequence", 0),
                "payload_hex": event.get("payload_hex", "")}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "interface": "eth0",
                "base_stack": "icmp",
                "instruction": "ICMP server that responds to ping requests"
            }),
            json!({
                "type": "open_server",
                "interface": "eth0",
                "base_stack": "icmp",
                "event_handlers": [{
                    "event_pattern": "icmp_echo_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "interface": "eth0",
                "base_stack": "icmp",
                "event_handlers": [{
                    "event_pattern": "icmp_echo_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "ignore_icmp"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for IcmpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::icmp::IcmpServer;

            // ICMP uses interface-based binding
            // Extract interface from context (defaults already applied)
            let interface = ctx
                .interface()
                .context("ICMP requires network interface")?
                .to_string();

            // Get listen address before moving ctx fields
            let listen_addr = ctx.legacy_listen_addr();

            // Spawn the ICMP server
            let _interface_name = IcmpServer::spawn_with_llm(
                interface,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await?;

            // ICMP doesn't bind to a socket, so return a dummy address
            // The listen_addr from context is just a placeholder
            Ok(listen_addr)
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_echo_reply" => self.execute_send_echo_reply(action),
            "send_destination_unreachable" => self.execute_send_destination_unreachable(action),
            "send_time_exceeded" => self.execute_send_time_exceeded(action),
            // "send_timestamp_reply" => self.execute_send_timestamp_reply(action), // TODO: Removed - timestamp support requires pnet timestamp packet types
            "ignore_icmp" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown ICMP action: {}", action_type)),
        }
    }
}

/// Largest payload that still fits an ICMP message inside one unfragmented IPv4 datagram:
/// 65535 total, less the 20-byte IPv4 header and the 8-byte ICMP header.
const MAX_ICMP_PAYLOAD: usize = 65535 - 20 - 8;

/// Read a required 16-bit action parameter.
///
/// `as u16` on a `u64` truncates in silence: an identifier of 70000 becomes 4464 and the reply
/// no longer matches any request the peer sent. Refusing is the honest answer, and the model is
/// told the range.
fn u16_field(action: &serde_json::Value, name: &str) -> Result<u16> {
    let raw = action
        .get(name)
        .and_then(|v| v.as_u64())
        .with_context(|| format!("Missing '{name}' parameter"))?;
    u16::try_from(raw)
        .with_context(|| format!("'{name}' must be a 16-bit ICMP field (0-65535), got {raw}"))
}

/// Read an 8-bit action parameter, with `default` used when it is absent.
///
/// Same reasoning as [`u16_field`]: an ICMP code of 300 silently became 44, which is not a code
/// at all.
fn u8_field(action: &serde_json::Value, name: &str, default: Option<u8>) -> Result<u8> {
    let raw = match action.get(name).and_then(|v| v.as_u64()) {
        Some(raw) => raw,
        None => return default.with_context(|| format!("Missing '{name}' parameter")),
    };
    u8::try_from(raw).with_context(|| format!("'{name}' must be an ICMP code (0-255), got {raw}"))
}

/// Read an optional 16-bit field, falling back to `default` when it is absent.
fn u16_field_or(spec: &serde_json::Value, name: &str, default: u16) -> Result<u16> {
    let Some(raw) = spec.get(name).and_then(|v| v.as_u64()) else {
        return Ok(default);
    };
    u16::try_from(raw).with_context(|| format!("'{name}' must be 0-65535, got {raw}"))
}

/// The ones' complement sum RFC 1071 defines, over `bytes` plus a pre-seeded `carry`.
fn ones_complement(bytes: &[u8], carry: u32) -> u16 {
    let mut sum = carry;
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [odd] = chunks.remainder() {
        sum += u32::from(*odd) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build the 28 bytes RFC 792 asks an ICMP error to quote — the offending IPv4 header plus the
/// first 64 bits of its transport header — from fields a model can actually read.
///
/// This exists because `original_packet_hex` asked the model to *invent* an IPv4 header
/// whenever it had not literally been handed one: twenty bytes of bit-packed fields ending in
/// a ones' complement checksum. That is the case `CLAUDE.md`'s "never put raw bytes in action
/// parameters" rule is about, and a wrong checksum here is silent — the quoted datagram is not
/// what the peer matches its outstanding probe against, so the error is simply ignored.
///
/// The hex escape hatch stays for the one case that genuinely needs it: a relay quoting bytes
/// it really captured, which it should copy rather than re-derive.
fn build_quoted_datagram(spec: &serde_json::Value) -> Result<Vec<u8>> {
    if !spec.is_object() {
        anyhow::bail!(
            "'original_packet' must be an object describing the datagram that provoked this \
             error, e.g. {{\"source_ip\": \"192.168.1.50\", \"destination_ip\": \
             \"203.0.113.5\", \"protocol\": \"udp\", \"source_port\": 41234, \
             \"destination_port\": 53}}"
        );
    }

    let source: std::net::Ipv4Addr = spec
        .get("source_ip")
        .and_then(|v| v.as_str())
        .context("Missing 'original_packet.source_ip'")?
        .parse()
        .context("'original_packet.source_ip' is not an IPv4 address")?;
    let destination: std::net::Ipv4Addr = spec
        .get("destination_ip")
        .and_then(|v| v.as_str())
        .context("Missing 'original_packet.destination_ip'")?
        .parse()
        .context("'original_packet.destination_ip' is not an IPv4 address")?;

    // Accepted as a name or as an IANA number, because both spellings turn up in a model's
    // vocabulary and neither is ambiguous.
    let protocol = match spec.get("protocol") {
        None | Some(serde_json::Value::Null) => 17u8,
        Some(serde_json::Value::String(name)) => match name.to_ascii_lowercase().as_str() {
            "udp" => 17,
            "tcp" => 6,
            "icmp" => 1,
            other => anyhow::bail!(
                "'original_packet.protocol' is {other:?}; use \"udp\", \"tcp\", \"icmp\", or \
                 supply the whole quotation through 'original_packet_hex'"
            ),
        },
        Some(serde_json::Value::Number(n)) => {
            let raw = n
                .as_u64()
                .context("'original_packet.protocol' must be 0-255")?;
            u8::try_from(raw).context("'original_packet.protocol' must be 0-255")?
        }
        Some(other) => {
            anyhow::bail!("'original_packet.protocol' must be a string or a number, got {other}")
        }
    };

    let ttl = u8_field(spec, "ttl", Some(64))?;
    let identification = u16_field_or(spec, "identification", 0)?;

    // 20-byte header + the 8 transport bytes the quotation carries. Everything the model can
    // set is a named field; the two checksums are computed here and never asked for.
    const TOTAL_LEN: u16 = 28;
    let mut packet = vec![0u8; TOTAL_LEN as usize];
    packet[0] = 0x45; // IPv4, 5 * 4 = 20-byte header, no options
    packet[2..4].copy_from_slice(&TOTAL_LEN.to_be_bytes());
    packet[4..6].copy_from_slice(&identification.to_be_bytes());
    packet[8] = ttl;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let header_checksum = ones_complement(&packet[..20], 0);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    match protocol {
        17 => {
            let source_port = u16_field_or(spec, "source_port", 0)?;
            let destination_port = u16_field_or(spec, "destination_port", 0)?;
            packet[20..22].copy_from_slice(&source_port.to_be_bytes());
            packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
            packet[24..26].copy_from_slice(&8u16.to_be_bytes()); // header only, no payload
                                                                 // Pseudo-header: source, destination, zero, protocol, UDP length.
            let carry = u32::from(u16::from_be_bytes([packet[12], packet[13]]))
                + u32::from(u16::from_be_bytes([packet[14], packet[15]]))
                + u32::from(u16::from_be_bytes([packet[16], packet[17]]))
                + u32::from(u16::from_be_bytes([packet[18], packet[19]]))
                + u32::from(protocol)
                + 8;
            let checksum = ones_complement(&packet[20..28], carry);
            // RFC 768: a computed zero is transmitted as all ones, because zero means
            // "no checksum".
            let checksum = if checksum == 0 { 0xffff } else { checksum };
            packet[26..28].copy_from_slice(&checksum.to_be_bytes());
        }
        6 => {
            let source_port = u16_field_or(spec, "source_port", 0)?;
            let destination_port = u16_field_or(spec, "destination_port", 0)?;
            // The quotation reaches only as far as the sequence number, which is exactly what
            // the peer matches an outstanding connection attempt against.
            let sequence =
                u32::try_from(spec.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0))
                    .context("'original_packet.sequence' must fit in 32 bits")?;
            packet[20..22].copy_from_slice(&source_port.to_be_bytes());
            packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
            packet[24..28].copy_from_slice(&sequence.to_be_bytes());
        }
        1 => {
            let icmp_type = u8_field(spec, "icmp_type", Some(8))?;
            let icmp_code = u8_field(spec, "icmp_code", Some(0))?;
            let identifier = u16_field_or(spec, "identifier", 0)?;
            let sequence = u16_field_or(spec, "sequence", 0)?;
            packet[20] = icmp_type;
            packet[21] = icmp_code;
            packet[24..26].copy_from_slice(&identifier.to_be_bytes());
            packet[26..28].copy_from_slice(&sequence.to_be_bytes());
            let checksum = ones_complement(&packet[20..28], 0);
            packet[22..24].copy_from_slice(&checksum.to_be_bytes());
        }
        other => anyhow::bail!(
            "'original_packet.protocol' {other} has no structured form here — only udp (17), \
             tcp (6) and icmp (1) do. Supply the whole quotation through 'original_packet_hex'."
        ),
    }

    Ok(packet)
}

/// Resolve the quoted datagram from whichever of the two spellings the action used.
///
/// Exactly one, never both, and never sniffed: the structured form and the hex form say the
/// same thing in incompatible ways, and only the sender knows which it meant.
fn quoted_datagram(action: &serde_json::Value) -> Result<Vec<u8>> {
    let structured = action.get("original_packet").filter(|v| !v.is_null());
    let raw = action
        .get("original_packet_hex")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    match (structured, raw) {
        (Some(spec), None) => build_quoted_datagram(spec),
        (None, Some(encoded)) => hex::decode(encoded).context("Invalid hex in original_packet_hex"),
        (Some(_), Some(_)) => anyhow::bail!(
            "Give 'original_packet' or 'original_packet_hex', not both — they describe the same \
             quoted datagram and nothing can tell which one you meant"
        ),
        (None, None) => anyhow::bail!(
            "Missing the quoted datagram. Describe the packet that provoked this error with \
             'original_packet' ({{\"source_ip\": …, \"destination_ip\": …, \"protocol\": \
             \"udp\", \"source_port\": …, \"destination_port\": …}}), or pass the bytes you \
             captured as 'original_packet_hex'"
        ),
    }
}

impl IcmpProtocol {
    /// Execute send_echo_reply action
    fn execute_send_echo_reply(&self, action: serde_json::Value) -> Result<ActionResult> {
        let source_ip = action
            .get("source_ip")
            .and_then(|v| v.as_str())
            .context("Missing 'source_ip' parameter")?;

        let destination_ip = action
            .get("destination_ip")
            .and_then(|v| v.as_str())
            .context("Missing 'destination_ip' parameter")?;

        let identifier = u16_field(&action, "identifier")?;
        let sequence = u16_field(&action, "sequence")?;

        let payload_hex = action
            .get("payload_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let payload = if payload_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(payload_hex).context("Invalid hex in payload_hex")?
        };

        // `set_total_length(ip_size as u16)` would wrap silently past this, producing a header
        // whose length field disagrees with the buffer it describes.
        anyhow::ensure!(
            payload.len() <= MAX_ICMP_PAYLOAD,
            "payload_hex decodes to {} bytes; an ICMP echo reply carries at most {}",
            payload.len(),
            MAX_ICMP_PAYLOAD
        );

        // Parse IP addresses
        let source_ip_parsed: std::net::Ipv4Addr =
            source_ip.parse().context("Invalid source_ip format")?;
        let destination_ip_parsed: std::net::Ipv4Addr = destination_ip
            .parse()
            .context("Invalid destination_ip format")?;

        // Build ICMP echo reply packet
        use crate::server::icmp::IcmpServer;
        let packet = IcmpServer::build_echo_reply(
            source_ip_parsed,
            destination_ip_parsed,
            identifier,
            sequence,
            &payload,
        );

        Ok(ActionResult::Output(packet))
    }

    /// Execute send_destination_unreachable action
    fn execute_send_destination_unreachable(
        &self,
        action: serde_json::Value,
    ) -> Result<ActionResult> {
        let source_ip = action
            .get("source_ip")
            .and_then(|v| v.as_str())
            .context("Missing 'source_ip' parameter")?;

        let destination_ip = action
            .get("destination_ip")
            .and_then(|v| v.as_str())
            .context("Missing 'destination_ip' parameter")?;

        let code = u8_field(&action, "code", None)?;

        let original_packet = quoted_datagram(&action)?;

        // Parse IP addresses
        let source_ip_parsed: std::net::Ipv4Addr =
            source_ip.parse().context("Invalid source_ip format")?;
        let destination_ip_parsed: std::net::Ipv4Addr = destination_ip
            .parse()
            .context("Invalid destination_ip format")?;

        // Build ICMP destination unreachable packet
        use crate::server::icmp::IcmpServer;
        let packet = IcmpServer::build_destination_unreachable(
            source_ip_parsed,
            destination_ip_parsed,
            code,
            &original_packet,
        );

        Ok(ActionResult::Output(packet))
    }

    /// Execute send_time_exceeded action
    fn execute_send_time_exceeded(&self, action: serde_json::Value) -> Result<ActionResult> {
        let source_ip = action
            .get("source_ip")
            .and_then(|v| v.as_str())
            .context("Missing 'source_ip' parameter")?;

        let destination_ip = action
            .get("destination_ip")
            .and_then(|v| v.as_str())
            .context("Missing 'destination_ip' parameter")?;

        // Default 0 = TTL exceeded in transit.
        let code = u8_field(&action, "code", Some(0))?;

        let original_packet = quoted_datagram(&action)?;

        // Parse IP addresses
        let source_ip_parsed: std::net::Ipv4Addr =
            source_ip.parse().context("Invalid source_ip format")?;
        let destination_ip_parsed: std::net::Ipv4Addr = destination_ip
            .parse()
            .context("Invalid destination_ip format")?;

        // Build ICMP time exceeded packet
        use crate::server::icmp::IcmpServer;
        let packet = IcmpServer::build_time_exceeded(
            source_ip_parsed,
            destination_ip_parsed,
            code,
            &original_packet,
        );

        Ok(ActionResult::Output(packet))
    }

    /* TODO: Timestamp support requires pnet to add timestamp packet types
    /// Execute send_timestamp_reply action
    fn execute_send_timestamp_reply(&self, action: serde_json::Value) -> Result<ActionResult> {
        let source_ip = action
            .get("source_ip")
            .and_then(|v| v.as_str())
            .context("Missing 'source_ip' parameter")?;

        let destination_ip = action
            .get("destination_ip")
            .and_then(|v| v.as_str())
            .context("Missing 'destination_ip' parameter")?;

        let identifier = action
            .get("identifier")
            .and_then(|v| v.as_u64())
            .context("Missing 'identifier' parameter")? as u16;

        let sequence = action
            .get("sequence")
            .and_then(|v| v.as_u64())
            .context("Missing 'sequence' parameter")? as u16;

        let originate_timestamp = action
            .get("originate_timestamp")
            .and_then(|v| v.as_u64())
            .context("Missing 'originate_timestamp' parameter")? as u32;

        // Parse IP addresses
        let source_ip_parsed: std::net::Ipv4Addr =
            source_ip.parse().context("Invalid source_ip format")?;
        let destination_ip_parsed: std::net::Ipv4Addr =
            destination_ip.parse().context("Invalid destination_ip format")?;

        // Build ICMP timestamp reply packet
        use crate::server::icmp::IcmpServer;
        let packet = IcmpServer::build_timestamp_reply(
            source_ip_parsed,
            destination_ip_parsed,
            identifier,
            sequence,
            originate_timestamp,
        );

        Ok(ActionResult::Output(packet))
    }
    */
}

/// Action definition for send_echo_reply
fn send_echo_reply_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_echo_reply".to_string(),
        description: "Send an ICMP Echo Reply packet in response to an Echo Request (ping)"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "source_ip".to_string(),
                type_hint: "string".to_string(),
                description: "Source IP address (format: X.X.X.X)".to_string(),
                required: true,
            },
            Parameter {
                name: "destination_ip".to_string(),
                type_hint: "string".to_string(),
                description: "Destination IP address (format: X.X.X.X)".to_string(),
                required: true,
            },
            Parameter {
                name: "identifier".to_string(),
                type_hint: "number".to_string(),
                description: "ICMP identifier (must match request)".to_string(),
                required: true,
            },
            Parameter {
                name: "sequence".to_string(),
                type_hint: "number".to_string(),
                description: "ICMP sequence number (must match request)".to_string(),
                required: true,
            },
            Parameter {
                name: "payload_hex".to_string(),
                type_hint: "string".to_string(),
                description: "Payload data as hex string (must match request)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_echo_reply",
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.50",
            "identifier": 1234,
            "sequence": 1,
            "payload_hex": "48656c6c6f"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> ICMP echo reply to {destination_ip}")
                .with_debug(
                    "ICMP send_echo_reply: dst={destination_ip} id={identifier} seq={sequence}",
                ),
        ),
    }
}

/// The structured spelling of RFC 792's quoted datagram, shared by both error actions.
fn quoted_datagram_parameter() -> Parameter {
    Parameter {
        name: "original_packet".to_string(),
        type_hint: "object".to_string(),
        description: "The datagram that provoked this error, described as fields: \
                      'source_ip' and 'destination_ip' (required), 'protocol' (\"udp\" \
                      default, \"tcp\", \"icmp\", or an IANA number), 'source_port' and \
                      'destination_port' for udp/tcp, 'ttl' (default 64) and \
                      'identification' (default 0). The server builds the 20-byte IPv4 \
                      header and the 8 transport bytes RFC 792 quotes, and computes both \
                      checksums. Prefer this over 'original_packet_hex' — give exactly one."
            .to_string(),
        required: false,
    }
}

/// The byte-for-byte spelling, for a relay quoting a datagram it actually saw.
fn quoted_datagram_hex_parameter() -> Parameter {
    Parameter {
        name: "original_packet_hex".to_string(),
        type_hint: "string".to_string(),
        description: "Escape hatch: the quoted datagram byte for byte as hex (original IP \
                      header + first 8 bytes of its payload), for bytes you captured rather \
                      than invented. Nothing is computed for you, and a wrong header \
                      checksum makes the peer ignore the error silently. Give this or \
                      'original_packet', not both."
            .to_string(),
        required: false,
    }
}

/// Action definition for send_destination_unreachable
fn send_destination_unreachable_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_destination_unreachable".to_string(),
        description: "Send an ICMP Destination Unreachable message".to_string(),
        parameters: vec![
            Parameter {
                name: "source_ip".to_string(),
                type_hint: "string".to_string(),
                description: "Source IP address (format: X.X.X.X)".to_string(),
                required: true,
            },
            Parameter {
                name: "destination_ip".to_string(),
                type_hint: "string".to_string(),
                description: "Destination IP address (format: X.X.X.X)".to_string(),
                required: true,
            },
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "Unreachable code: 0=net, 1=host, 2=protocol, 3=port, 4=fragmentation needed, 5=source route failed".to_string(),
                required: true,
            },
            quoted_datagram_parameter(),
            quoted_datagram_hex_parameter(),
        ],
        // RFC 792 wants the original IP header plus the next 64 bits. Described as fields
        // rather than as 28 bytes of hex: both checksums in that quotation are ones'
        // complement sums over the header, which a model cannot compute and cannot proofread,
        // and a wrong one is silent — the peer simply does not match the error to its probe.
        example: json!({
            "type": "send_destination_unreachable",
            "source_ip": "192.168.1.1",
            "destination_ip": "192.168.1.50",
            "code": 3,
            "original_packet": {
                "source_ip": "192.168.1.50",
                "destination_ip": "203.0.113.5",
                "protocol": "udp",
                "source_port": 41234,
                "destination_port": 53
            }
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> ICMP unreachable code={code} to {destination_ip}")
                .with_debug("ICMP send_destination_unreachable: dst={destination_ip} code={code}"),
        ),
    }
}

/// Action definition for send_time_exceeded
fn send_time_exceeded_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_time_exceeded".to_string(),
        description: "Send an ICMP Time Exceeded message (used in traceroute)".to_string(),
        parameters: vec![
            Parameter {
                name: "source_ip".to_string(),
                type_hint: "string".to_string(),
                description: "Source IP address (format: X.X.X.X)".to_string(),
                required: true,
            },
            Parameter {
                name: "destination_ip".to_string(),
                type_hint: "string".to_string(),
                description: "Destination IP address (format: X.X.X.X)".to_string(),
                required: true,
            },
            Parameter {
                name: "code".to_string(),
                type_hint: "number".to_string(),
                description: "Time exceeded code: 0=TTL exceeded in transit, 1=fragment reassembly time exceeded".to_string(),
                required: false,
            },
            quoted_datagram_parameter(),
            quoted_datagram_hex_parameter(),
        ],
        // The original IP header plus the next 64 bits (RFC 792), as fields: a classic UDP
        // traceroute probe from 192.168.1.50 to 203.0.113.5 with TTL 1. Written out this way
        // the `ttl: 1` that makes it a traceroute probe is legible, which it is not when the
        // same fact is bit 8 of a hex blob.
        example: json!({
            "type": "send_time_exceeded",
            "source_ip": "10.0.0.1",
            "destination_ip": "192.168.1.50",
            "code": 0,
            "original_packet": {
                "source_ip": "192.168.1.50",
                "destination_ip": "203.0.113.5",
                "protocol": "udp",
                "source_port": 41234,
                "destination_port": 33434,
                "ttl": 1
            }
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> ICMP TTL exceeded to {destination_ip}")
                .with_debug("ICMP send_time_exceeded: dst={destination_ip} code={code}"),
        ),
    }
}

/* TODO: Timestamp support requires pnet to add timestamp packet types
/// Action definition for send_timestamp_reply
fn send_timestamp_reply_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_timestamp_reply".to_string(),
        description: "Send an ICMP Timestamp Reply message".to_string(),
        parameters: vec![
            Parameter {
                name: "source_ip".to_string(),
                type_hint: "string".to_string(),
                description: "Source IP address (format: X.X.X.X)".to_string(),
                required: true,
            },
            Parameter {
                name: "destination_ip".to_string(),
                type_hint: "string".to_string(),
                description: "Destination IP address (format: X.X.X.X)".to_string(),
                required: true,
            },
            Parameter {
                name: "identifier".to_string(),
                type_hint: "number".to_string(),
                description: "ICMP identifier (must match request)".to_string(),
                required: true,
            },
            Parameter {
                name: "sequence".to_string(),
                type_hint: "number".to_string(),
                description: "ICMP sequence number (must match request)".to_string(),
                required: true,
            },
            Parameter {
                name: "originate_timestamp".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Originate timestamp from request (milliseconds since midnight UT)".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_timestamp_reply",
            "source_ip": "192.168.1.1",
            "destination_ip": "192.168.1.50",
            "identifier": 1234,
            "sequence": 1,
            "originate_timestamp": 12345678
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> ICMP timestamp reply to {destination_ip}")
                .with_debug("ICMP send_timestamp_reply: dst={destination_ip} id={identifier} seq={sequence}"),
        ),
    }
}
*/

/// Action definition for ignore_icmp
fn ignore_icmp_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_icmp".to_string(),
        description: "Ignore this ICMP packet (no action taken)".to_string(),
        parameters: vec![],
        example: json!({
            "type": "ignore_icmp"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> ICMP ignore")
                .with_debug("ICMP ignore_icmp"),
        ),
    }
}

// ============================================================================
// ICMP Event Type Constants
// ============================================================================

pub static ICMP_ECHO_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "icmp_echo_request",
        "ICMP Echo Request (ping) received from network",
        json!({
            "type": "send_echo_reply",
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.50",
            "identifier": 1234,
            "sequence": 1,
            "payload_hex": "48656c6c6f"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "source_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Source IP address of the ping request".to_string(),
            required: true,
        },
        Parameter {
            name: "destination_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Destination IP address (our server)".to_string(),
            required: true,
        },
        Parameter {
            name: "identifier".to_string(),
            type_hint: "number".to_string(),
            description: "ICMP identifier".to_string(),
            required: true,
        },
        Parameter {
            name: "sequence".to_string(),
            type_hint: "number".to_string(),
            description: "ICMP sequence number".to_string(),
            required: true,
        },
        Parameter {
            name: "payload_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Hexadecimal representation of the payload data".to_string(),
            required: false,
        },
        Parameter {
            name: "ttl".to_string(),
            type_hint: "number".to_string(),
            description: "Time to live from IP header".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![send_echo_reply_action(), ignore_icmp_action()])
});

/* TODO: Timestamp support requires pnet to add timestamp packet types
pub static ICMP_TIMESTAMP_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "icmp_timestamp_request",
        "ICMP Timestamp Request received from network",
        json!({
            "type": "send_timestamp_reply",
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.50",
            "identifier": 1234,
            "sequence": 1,
            "originate_timestamp": 12345678
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "source_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Source IP address".to_string(),
            required: true,
        },
        Parameter {
            name: "destination_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Destination IP address".to_string(),
            required: true,
        },
        Parameter {
            name: "identifier".to_string(),
            type_hint: "number".to_string(),
            description: "ICMP identifier".to_string(),
            required: true,
        },
        Parameter {
            name: "sequence".to_string(),
            type_hint: "number".to_string(),
            description: "ICMP sequence number".to_string(),
            required: true,
        },
        Parameter {
            name: "originate_timestamp".to_string(),
            type_hint: "number".to_string(),
            description: "Originate timestamp (milliseconds since midnight UT)".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![send_timestamp_reply_action(), ignore_icmp_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("ICMP timestamp request from {source_ip}")
            .with_debug("ICMP timestamp_request: src={source_ip} id={identifier} seq={sequence}"),
    )
});
*/

pub static ICMP_OTHER_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "icmp_other_message",
        "Other ICMP message type received (not echo or timestamp)",
        json!({
            "type": "send_destination_unreachable",
            "source_ip": "192.168.1.1",
            "destination_ip": "192.168.1.50",
            "code": 3,
            "original_packet": {
                "source_ip": "192.168.1.50",
                "destination_ip": "203.0.113.5",
                "protocol": "udp",
                "source_port": 41234,
                "destination_port": 53
            }
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "source_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Source IP address".to_string(),
            required: true,
        },
        Parameter {
            name: "destination_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Destination IP address".to_string(),
            required: true,
        },
        Parameter {
            name: "icmp_type".to_string(),
            type_hint: "number".to_string(),
            description: "ICMP message type".to_string(),
            required: true,
        },
        Parameter {
            name: "icmp_code".to_string(),
            type_hint: "number".to_string(),
            description: "ICMP message code".to_string(),
            required: true,
        },
        Parameter {
            name: "packet_hex".to_string(),
            type_hint: "string".to_string(),
            description: "Full ICMP packet as hex".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        send_destination_unreachable_action(),
        send_time_exceeded_action(),
        ignore_icmp_action(),
    ])
});

pub fn get_icmp_event_types() -> Vec<EventType> {
    vec![
        ICMP_ECHO_REQUEST_EVENT.clone(),
        // ICMP_TIMESTAMP_REQUEST_EVENT.clone(), // TODO: Removed - timestamp support requires pnet timestamp packet types
        ICMP_OTHER_MESSAGE_EVENT.clone(),
    ]
}

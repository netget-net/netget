//! DataLink client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

pub use crate::client::datalink::packet::LinkType;
use crate::client::datalink::packet::{
    build_ipv4_tcp, link_header, tcp_flag_list, BuildDefaults, TcpFlow, MP_CAPABLE_FLAG_NAMES,
    TCP_OPTION_KINDS,
};

/// The shortest thing that can be an Ethernet frame: 6 + 6 + 2.
///
/// Anything shorter has no EtherType and libpcap would either refuse it or put a runt on the
/// wire, so it is rejected here where the model can be told why.
pub const MIN_ETHERNET_FRAME_BYTES: usize = 14;

/// Upper bound on an injected frame, matching the capture snaplen. Well above any jumbo MTU;
/// the point is to refuse an accidental megabyte of hex before it reaches libpcap.
pub const MAX_ETHERNET_FRAME_BYTES: usize = 65535;

/// EtherType names the model may write instead of a number.
///
/// A name is the whole reason the structured form is worth having: `"ethertype": "arp"` is a
/// thing a model can get right and a reader can check, and `0806` is not. The table is
/// deliberately short — the four a model reaches for — and anything outside it is written as
/// a number or a `0x` string.
pub const ETHERTYPE_NAMES: &[(&str, u16)] = &[
    ("ipv4", 0x0800),
    ("arp", 0x0806),
    ("vlan", 0x8100),
    ("ipv6", 0x86dd),
];

/// A MAC address in the spelling the events use and `inject_frame` accepts back.
pub fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Six bytes from `aa:bb:cc:dd:ee:ff`, `aa-bb-…`, `aa bb …` or `aabbccddeeff`.
fn parse_mac(value: &str, field: &str) -> Result<[u8; 6]> {
    let cleaned: String = value
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.' | ' ' | '\t'))
        .collect();
    let bytes = hex::decode(&cleaned).map_err(|e| {
        anyhow::anyhow!(
            "'{field}' is not a MAC address ({value:?}): {e}. Write six bytes, e.g. \
             \"00:11:22:33:44:55\"."
        )
    })?;
    if bytes.len() != 6 {
        anyhow::bail!(
            "'{field}' decodes to {} bytes; a MAC address is 6, e.g. \"00:11:22:33:44:55\" \
             (or \"ff:ff:ff:ff:ff:ff\" to broadcast)",
            bytes.len()
        );
    }
    let mut out = [0u8; 6];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// The EtherType, as a name, a number, or a `0x`-prefixed string — never a bare `"0806"`.
///
/// A bare four-digit string is refused on purpose: `"0806"` is 2054 read as hex and 806 read
/// as decimal, and there is no way to tell which the caller meant. That is the same ambiguity
/// the `encoding` field exists for, so it gets the same treatment — say which, do not guess.
fn parse_ethertype(value: &serde_json::Value) -> Result<u16> {
    if let Some(n) = value.as_u64() {
        return u16::try_from(n).map_err(|_| {
            anyhow::anyhow!("'ethertype' {n} does not fit in the 2-byte EtherType field")
        });
    }
    let Some(text) = value.as_str() else {
        anyhow::bail!(
            "'ethertype' must be a name ({}), a number (2054), or a hex string with a 0x \
             prefix (\"0x0806\"); got {value}",
            ETHERTYPE_NAMES
                .iter()
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
                .join(", ")
        );
    };
    let lowered = text.trim().to_ascii_lowercase();
    if let Some((_, v)) = ETHERTYPE_NAMES.iter().find(|(n, _)| *n == lowered) {
        return Ok(*v);
    }
    if let Some(digits) = lowered.strip_prefix("0x") {
        return u16::from_str_radix(digits, 16)
            .map_err(|e| anyhow::anyhow!("'ethertype' {text:?} is not a 2-byte hex value: {e}"));
    }
    anyhow::bail!(
        "'ethertype' {text:?} is neither a known name ({}) nor a 0x-prefixed hex value. A bare \
         \"0806\" is refused because it is 2054 as hex and 806 as decimal and only you know \
         which; write \"0x0806\", 2054, or \"arp\".",
        ETHERTYPE_NAMES
            .iter()
            .map(|(n, _)| *n)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// The payload bytes, read according to the action's required `payload_encoding`.
///
/// `payload_encoding` has no default, unlike `send_tcp_data`'s `encoding`. An Ethernet
/// payload is binary far more often than it is text — ARP, IPv4, IPv6 are the three a model
/// will build — so a `utf8` default would put the ASCII characters of an ARP body on the wire
/// for exactly the frames most likely to be written. That is the `send_tcp_data` bug again,
/// so the field is required and nothing is sniffed.
fn parse_payload(action: &serde_json::Value) -> Result<Vec<u8>> {
    let Some(payload) = action.get("payload").and_then(|v| v.as_str()) else {
        return Ok(Vec::new());
    };
    let Some(encoding) = action.get("payload_encoding").and_then(|v| v.as_str()) else {
        anyhow::bail!(
            "'payload' was given without 'payload_encoding'. Say which it is: \"hex\" for \
             binary (ARP, IP, anything with a header), \"utf8\" to put the characters of \
             'payload' on the wire as they are. There is no default and nothing is guessed - \
             \"deadbeef\" is four bytes as hex and eight characters as text."
        );
    };
    match encoding {
        "utf8" => Ok(payload.as_bytes().to_vec()),
        "hex" => {
            let cleaned: String = payload
                .chars()
                .filter(|c| !matches!(c, ' ' | ':' | '-' | '.' | '\n' | '\r' | '\t'))
                .collect();
            if cleaned.len() % 2 != 0 {
                anyhow::bail!(
                    "Invalid hex in 'payload': expected an even number of hex digits, got {}. \
                     Each byte is two hex digits.",
                    cleaned.len()
                );
            }
            hex::decode(&cleaned)
                .map_err(|e| anyhow::anyhow!("Invalid hex in 'payload' ({payload:?}): {e}"))
        }
        other => anyhow::bail!(
            "Invalid 'payload_encoding' value {other:?}. Valid values are \"hex\" (decode \
             'payload' as hex-encoded bytes) and \"utf8\" (send its characters as they are)."
        ),
    }
}

/// Assemble the bytes `inject_frame` will hand to libpcap on an **Ethernet** link.
///
/// Kept for callers that know they are on Ethernet; [`build_frame_for_link`] is what the
/// client executes, with the link type of its open handle.
pub fn build_frame(action: &serde_json::Value) -> Result<Vec<u8>> {
    build_frame_for_link(action, LinkType::Ethernet)
}

/// Assemble the bytes `inject_frame` will hand to libpcap, from whichever spelling was used,
/// for the interface's link type.
///
/// Two spellings, and exactly one of them per action:
///
/// - **Structured** — on Ethernet `dst_mac`, `src_mac`, `ethertype`; on a loopback link
///   (`NULL` / `LOOP`) `ethertype` alone (ipv4 / ipv6, which becomes the 4-byte family
///   header); on `RAW` nothing (the payload is the IP packet). Plus an optional `payload`
///   with its required `payload_encoding`. This is the one the model is shown, because
///   every part of it is a thing a model can write correctly and a person can check.
/// - **`frame_hex`** — the whole frame as hex, link header included. The escape hatch, kept
///   because `datalink_frame_captured` hands the model exactly this and replaying or
///   amending a captured frame is a real thing to want.
///
/// Supplying both is **refused** rather than resolved by precedence: they are two statements
/// about the same wire bytes and guessing which one was meant is how a frame nobody intended
/// goes out. A structured spelling missing a required field is refused by name rather than
/// silently falling back to zeros, and a field the link cannot carry (a MAC on loopback) is
/// refused rather than dropped.
pub fn build_frame_for_link(action: &serde_json::Value, link: LinkType) -> Result<Vec<u8>> {
    let frame_hex = action.get("frame_hex").and_then(|v| v.as_str());
    let structured = ["dst_mac", "src_mac", "ethertype"]
        .iter()
        .any(|k| action.get(k).is_some())
        || (!link.has_macs() && action.get("payload").is_some());

    let frame = match (frame_hex, structured) {
        (Some(_), true) => anyhow::bail!(
            "Both 'frame_hex' and the structured fields (dst_mac / src_mac / ethertype / \
             payload) were supplied. Send exactly one: the structured form for a frame you are \
             building, or 'frame_hex' for a frame you already have in full. They are not \
             combined and neither takes precedence."
        ),
        (None, false) => anyhow::bail!(
            "Missing frame. Give {} (plus an optional 'payload' with its 'payload_encoding'), \
             or the whole frame as 'frame_hex'.",
            structured_fields_for(link)
        ),
        (Some(h), false) => decode_frame_hex(h)?,
        (None, true) if link != LinkType::Ethernet => {
            let payload = parse_payload(action)?;
            let ethertype = match action.get("ethertype") {
                Some(v) => parse_ethertype(v)?,
                // A raw-IP link carries no type of its own; the IP version nibble says it.
                None if matches!(link, LinkType::Raw | LinkType::Ipv4 | LinkType::Ipv6) => {
                    match payload.first().map(|b| b >> 4) {
                        Some(6) => 0x86dd,
                        _ => 0x0800,
                    }
                }
                None => anyhow::bail!(
                    "Missing 'ethertype'. This interface's link type is {}: give 'ethertype' \
                     (\"ipv4\" or \"ipv6\") and the 4-byte family header is built from it.",
                    link.name()
                ),
            };
            let macs_given = action.get("dst_mac").is_some() || action.get("src_mac").is_some();
            let mut frame = link_header(link, ethertype, macs_given.then_some(([0; 6], [0; 6])))?;
            frame.extend_from_slice(&payload);
            frame
        }
        (None, true) => {
            let get = |k: &str| -> Result<&serde_json::Value> {
                action.get(k).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Missing '{k}'. A structured frame needs all of 'dst_mac', 'src_mac' \
                         and 'ethertype'; 'payload' and its 'payload_encoding' are optional."
                    )
                })
            };
            let dst = parse_mac(get("dst_mac")?.as_str().unwrap_or_default(), "dst_mac")?;
            let src = parse_mac(get("src_mac")?.as_str().unwrap_or_default(), "src_mac")?;
            let ethertype = parse_ethertype(get("ethertype")?)?;

            let payload = parse_payload(action)?;
            let mut frame = Vec::with_capacity(MIN_ETHERNET_FRAME_BYTES + payload.len());
            frame.extend_from_slice(&dst);
            frame.extend_from_slice(&src);
            frame.extend_from_slice(&ethertype.to_be_bytes());
            frame.extend_from_slice(&payload);
            frame
        }
    };

    check_frame_bounds(&frame, link)?;
    Ok(frame)
}

/// The structured fields a link type's `inject_frame` is built from, for messages.
pub fn structured_fields_for(link: LinkType) -> &'static str {
    match link {
        LinkType::Ethernet => "'dst_mac', 'src_mac' and 'ethertype'",
        LinkType::Null | LinkType::Loop => {
            "'ethertype' (\"ipv4\" or \"ipv6\"; this link has no MAC addresses)"
        }
        LinkType::Raw | LinkType::Ipv4 | LinkType::Ipv6 => {
            "'payload' (the IP packet itself; this link has no header)"
        }
        LinkType::LinuxSll | LinkType::Other(_) => {
            "'frame_hex' (this link type has no structured form)"
        }
    }
}

/// Bounds before libpcap sees a frame: a runt has no link header, and a frame the size of a
/// prompt is a mistake worth naming rather than an ENOBUFS from a syscall. The model is told
/// the actual length so it can fix the frame.
fn check_frame_bounds(frame: &[u8], link: LinkType) -> Result<()> {
    if link == LinkType::Ethernet && frame.len() < MIN_ETHERNET_FRAME_BYTES {
        anyhow::bail!(
            "the frame is {} bytes; an Ethernet frame needs at least {} (6-byte destination \
             MAC, 6-byte source MAC, 2-byte EtherType)",
            frame.len(),
            MIN_ETHERNET_FRAME_BYTES
        );
    }
    let min = link.header_len().unwrap_or(0).max(1);
    if frame.len() < min {
        anyhow::bail!(
            "the frame is {} bytes; on link type {} it needs at least {min}",
            frame.len(),
            link.name()
        );
    }
    if frame.len() > MAX_ETHERNET_FRAME_BYTES {
        anyhow::bail!(
            "the frame is {} bytes; the maximum injectable frame is {}",
            frame.len(),
            MAX_ETHERNET_FRAME_BYTES
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// IPv4 / TCP crafting
// ---------------------------------------------------------------------------

/// What one open DataLink client knows about its interface. The registry's instance has
/// none ([`LinkSession::default`]): it validates actions, it never sends.
#[derive(Debug, Clone, Default)]
pub struct LinkSession {
    /// The open handle's link type; `None` on an instance with no handle behind it.
    pub link_type: Option<LinkType>,
    /// Whether the interface is a loopback (checksum offload notes).
    pub loopback: bool,
    /// Destination defaults from `remote_addr`.
    pub defaults: BuildDefaults,
}

/// Longest a `probe_tcp` waits for replies.
pub const MAX_PROBE_TIMEOUT_MS: u64 = 10_000;
/// Default `probe_tcp` wait.
pub const DEFAULT_PROBE_TIMEOUT_MS: u64 = 1_000;
/// Most replies one `probe_tcp` collects.
pub const MAX_PROBE_REPLIES: u64 = 16;

/// What `probe_tcp` hands the client loop: the frame, the flow its replies come back on, and
/// how long and for how many to wait. Internal — the model never writes or sees this shape.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProbeRequest {
    /// The whole frame, link header included.
    pub frame: Vec<u8>,
    /// The flow the probe opens, from the sender's side.
    pub flow: TcpFlow,
    /// How long to wait for replies after sending.
    pub timeout_ms: u64,
    /// Stop after this many replies.
    pub max_replies: usize,
}

/// An IPv4/TCP frame for this client's link: the packet from [`build_ipv4_tcp`], behind the
/// link header the open handle needs (Ethernet needs `dst_mac` / `src_mac`; loopback gets the
/// AF_INET family header; RAW gets none).
pub fn build_tcp_frame(
    action: &serde_json::Value,
    session: &LinkSession,
) -> Result<(Vec<u8>, TcpFlow)> {
    let built = build_ipv4_tcp(action, &session.defaults)?;
    let macs = match (action.get("dst_mac"), action.get("src_mac")) {
        (None, None) => None,
        (Some(d), Some(s)) => Some((
            parse_mac(d.as_str().unwrap_or_default(), "dst_mac")?,
            parse_mac(s.as_str().unwrap_or_default(), "src_mac")?,
        )),
        _ => anyhow::bail!("give both 'dst_mac' and 'src_mac', or neither"),
    };
    let header = match session.link_type {
        Some(link) => link_header(link, 0x0800, macs)?,
        // No handle: validation only. Frame it as the MACs say.
        None => match macs {
            Some(m) => link_header(LinkType::Ethernet, 0x0800, Some(m))?,
            None => Vec::new(),
        },
    };
    let mut frame = header;
    frame.extend_from_slice(&built.packet);
    Ok((frame, built.flow))
}

/// `probe_tcp`'s request: [`build_tcp_frame`] plus `timeout_ms` and `max_replies`.
pub fn build_probe(action: &serde_json::Value, session: &LinkSession) -> Result<ProbeRequest> {
    let (frame, flow) = build_tcp_frame(action, session)?;
    let num = |k: &str| -> Result<Option<u64>> {
        match action.get(k) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(v) => v
                .as_u64()
                .map(Some)
                .with_context(|| format!("'{k}' must be a positive number; got {v}")),
        }
    };
    let timeout_ms = num("timeout_ms")?.unwrap_or(DEFAULT_PROBE_TIMEOUT_MS);
    if timeout_ms == 0 || timeout_ms > MAX_PROBE_TIMEOUT_MS {
        anyhow::bail!("'timeout_ms' must be 1 to {MAX_PROBE_TIMEOUT_MS}; got {timeout_ms}");
    }
    let max_replies = num("max_replies")?.unwrap_or(1);
    if max_replies == 0 || max_replies > MAX_PROBE_REPLIES {
        anyhow::bail!("'max_replies' must be 1 to {MAX_PROBE_REPLIES}; got {max_replies}");
    }
    Ok(ProbeRequest {
        frame,
        flow,
        timeout_ms,
        max_replies: max_replies as usize,
    })
}

/// `frame_hex`, with the separators a model reading a packet dump naturally writes
/// ("ff:ff:ff:ff:ff:ff 00 11 …") stripped: they carry no information and rejecting them
/// teaches the model nothing it can act on.
fn decode_frame_hex(frame_hex: &str) -> Result<Vec<u8>> {
    let cleaned: String = frame_hex
        .chars()
        .filter(|c| !matches!(c, ' ' | ':' | '-' | '.' | '\n' | '\r' | '\t'))
        .collect();
    hex::decode(&cleaned).context("Invalid hex frame data")
}

/// The frame fields every frame-carrying event exposes. Shared so the two events cannot drift
/// from each other or from what `mod.rs` actually puts in them.
fn frame_parameters(what: &str) -> Vec<Parameter> {
    vec![
        Parameter {
            name: "dst_mac".to_string(),
            type_hint: "string".to_string(),
            description: format!(
                "Destination MAC of {what}, as \"aa:bb:cc:dd:ee:ff\". Pass it straight back \
                 to inject_frame. Null when the link has no MAC addresses (link_type NULL, \
                 LOOP, RAW - macOS lo0 is NULL) or the bytes are shorter than the link header."
            ),
            required: true,
        },
        Parameter {
            name: "src_mac".to_string(),
            type_hint: "string".to_string(),
            description: format!("Source MAC of {what}, in the same spelling as dst_mac"),
            required: true,
        },
        Parameter {
            name: "ethertype".to_string(),
            type_hint: "string".to_string(),
            description: format!(
                "EtherType of {what} as a 0x-prefixed hex string, e.g. \"0x0806\" (ARP) or \
                 \"0x0800\" (IPv4); on a loopback link, the one its address family means. \
                 inject_frame accepts this spelling unchanged."
            ),
            required: true,
        },
        Parameter {
            name: "payload".to_string(),
            type_hint: "string".to_string(),
            description: format!(
                "Everything in {what} after the link header (14 bytes on Ethernet, 4 on a \
                 NULL/LOOP loopback, none on RAW), read according to 'payload_encoding'. A \
                 prefix when `truncated` is true."
            ),
            required: true,
        },
        Parameter {
            name: "payload_encoding".to_string(),
            type_hint: "string".to_string(),
            description: "How to read 'payload': \"utf8\" means it is the payload bytes as \
                          literal text, \"hex\" means it is those bytes hex-encoded. Pass \
                          'payload' and 'payload_encoding' unchanged to inject_frame to put \
                          the same bytes back on the wire."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "frame_hex".to_string(),
            type_hint: "string".to_string(),
            description: format!(
                "The whole of the first {} bytes of {} as hex (link header and payload), for \
                 replaying it verbatim through inject_frame's 'frame_hex' \
                 escape hatch. Longer frames are cut there - see `truncated`.",
                crate::client::datalink::MAX_HEX_BYTES_TO_MODEL,
                what
            ),
            required: true,
        },
        Parameter {
            name: "frame_length".to_string(),
            type_hint: "number".to_string(),
            description: "Full length of the frame in bytes, before any truncation".to_string(),
            required: true,
        },
        Parameter {
            name: "captured_length".to_string(),
            type_hint: "number".to_string(),
            description: "Number of bytes actually encoded in frame_hex".to_string(),
            required: true,
        },
        Parameter {
            name: "truncated".to_string(),
            type_hint: "boolean".to_string(),
            description: "True when frame_hex is a prefix of the frame rather than all of it"
                .to_string(),
            required: true,
        },
    ]
    .into_iter()
    .chain(decoded_frame_parameters())
    .collect()
}

/// The decoded fields both DataLink protocols add to a frame event (see
/// [`crate::client::datalink::packet::decode_frame`]). `link_type` is always present; the
/// rest only when the frame carries them.
pub fn decoded_frame_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "link_type".to_string(),
            type_hint: "string".to_string(),
            description: "The interface's link-layer format: \"EN10MB\" (Ethernet), \"NULL\" \
                          (BSD loopback such as macOS lo0: a 4-byte address family, no MACs), \
                          \"LOOP\", \"RAW\" (no link header), \"LINUX_SLL\""
                .to_string(),
            required: true,
        },
        Parameter {
            name: "family".to_string(),
            type_hint: "string".to_string(),
            description: "NULL/LOOP links only: the address family in the 4-byte header, \
                          \"AF_INET\" or \"AF_INET6\" (a number when unknown)"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "ip".to_string(),
            type_hint: "object".to_string(),
            description: "The IPv4 header, decoded: src, dst, protocol, ttl, id, \
                          dont_fragment, total_length, checksum and checksum_ok. Absent when \
                          the frame is not IPv4."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "tcp".to_string(),
            type_hint: "object".to_string(),
            description: "The TCP header, decoded: src_port, dst_port, seq, ack, flags (names), \
                          window, options (a list in the spelling send_ipv4_tcp accepts - mss, \
                          wscale, sack_perm, timestamps, mp_capable with version and flags, \
                          other MPTCP subtypes by name), checksum / checksum_ok / \
                          checksum_note (0x0000 on loopback is checksum offload, not an \
                          error), payload_length. Absent unless the frame is IPv4 TCP."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "udp".to_string(),
            type_hint: "object".to_string(),
            description: "The UDP header, decoded: src_port, dst_port, length, checksum. \
                          Absent unless the frame is IPv4 UDP."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "icmp".to_string(),
            type_hint: "object".to_string(),
            description: "ICMP type, type_name and code; for an error, 'about' names the \
                          packet it reports on. Absent unless the frame is ICMP."
                .to_string(),
            required: false,
        },
    ]
}

/// DataLink client frame captured event (for promiscuous mode listening)
pub static DATALINK_CLIENT_FRAME_CAPTURED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "datalink_frame_captured",
        "Raw Ethernet frame captured on interface",
        json!({
            "type": "inject_frame",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_mac": "00:11:22:33:44:55",
            "ethertype": "0x88b5",
            "payload": "netget",
            "payload_encoding": "utf8"
        }),
    )
    .with_parameters(frame_parameters("the captured frame"))
    .with_actions(vec![inject_frame_action(true), wait_for_more_action()])
});

/// Raised once the capture handle is open, so the model can act on its instruction.
///
/// Without this the client opened the interface and asked the model nothing, so a client
/// created with "inject an ARP request for 10.0.0.2" sat there having done nothing.
pub static DATALINK_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "datalink_connected",
        "Capture handle open on the interface; ready to inject and capture",
        json!({
            "type": "inject_frame",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_mac": "00:11:22:33:44:55",
            "ethertype": "0x88b5",
            "payload": "netget",
            "payload_encoding": "utf8"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "interface".to_string(),
            type_hint: "string".to_string(),
            description: "The interface the capture was opened on".to_string(),
            required: true,
        },
        Parameter {
            name: "promiscuous".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether the interface was opened in promiscuous mode".to_string(),
            required: true,
        },
        Parameter {
            name: "link_type".to_string(),
            type_hint: "string".to_string(),
            description: "The interface's link-layer format, which decides how frames are \
                          built: \"EN10MB\" (Ethernet - inject_frame needs dst_mac, src_mac, \
                          ethertype), \"NULL\" / \"LOOP\" (loopback, e.g. macOS lo0 - no \
                          MACs; give only ethertype ipv4/ipv6), \"RAW\" (no link header at all)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "capture".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether captured frames are delivered as datalink_frame_captured"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "filter".to_string(),
            type_hint: "string".to_string(),
            description: "The BPF filter frames are captured through, or null for none".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        inject_frame_action(false),
        send_ipv4_tcp_action(),
        probe_tcp_action(),
        wait_for_more_action(),
    ])
});

/// Raised when a `probe_tcp` the model asked for has finished waiting for replies.
pub static DATALINK_CLIENT_PROBE_COMPLETED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "datalink_probe_completed",
        "A probe_tcp segment was sent and the replies on its flow collected",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "flow".to_string(),
            type_hint: "object".to_string(),
            description: "The probe's flow from our side: src_ip, dst_ip, src_port, dst_port"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "sent".to_string(),
            type_hint: "object".to_string(),
            description: "The probe as sent, decoded (ip, tcp with its options)".to_string(),
            required: true,
        },
        Parameter {
            name: "replies".to_string(),
            type_hint: "array".to_string(),
            description: "Each reply on the flow, decoded like a captured frame (ip, tcp or \
                          icmp, options), plus options_echoed / options_not_echoed against \
                          the probe's own options"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "reply_count".to_string(),
            type_hint: "number".to_string(),
            description: "How many replies were collected".to_string(),
            required: true,
        },
        Parameter {
            name: "waited_ms".to_string(),
            type_hint: "number".to_string(),
            description: "How long the probe listened".to_string(),
            required: true,
        },
        Parameter {
            name: "summary".to_string(),
            type_hint: "array".to_string(),
            description: "One line per reply, or one saying none came".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        send_ipv4_tcp_action(),
        probe_tcp_action(),
        inject_frame_action(false),
        wait_for_more_action(),
    ])
});

/// Raised after a frame really went out on the wire.
pub static DATALINK_CLIENT_FRAME_INJECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "datalink_frame_injected",
        "A raw frame was written to the interface",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(frame_parameters("the frame that was written"))
    .with_actions(vec![inject_frame_action(false), wait_for_more_action()])
});

/// `inject_frame`, in the two wordings the model sees it in.
///
/// One definition rather than the two hand-written near-copies that were here: the sync copy
/// documented `frame_hex` differently from the async one, and the async one told the model to
/// include the **FCS**. That is wrong for `pcap::sendpacket` — the driver appends the frame
/// check sequence, so four bytes of the model's arithmetic would go on the wire as payload.
fn inject_frame_action(in_response: bool) -> ActionDefinition {
    ActionDefinition {
        name: "inject_frame".to_string(),
        description: format!(
            "{} Build it from fields, which depend on the interface's link_type (reported \
             in datalink_connected). On Ethernet (EN10MB): 'dst_mac' and 'src_mac' as \
             \"aa:bb:cc:dd:ee:ff\" and 'ethertype'. On a loopback link (NULL/LOOP - macOS \
             lo0): no MACs, only 'ethertype' \"ipv4\" or \"ipv6\", which becomes the 4-byte \
             address-family header. On RAW: no header at all, just 'payload'. \
             'ethertype' is a name ({}), a number (2054) or a 0x string (\"0x0806\"), and an \
             optional 'payload' whose 'payload_encoding' says whether it is \"hex\" (binary - \
             ARP, IP, anything with a header) or \"utf8\" (its characters, as they are). \
             'payload_encoding' has no default and nothing is sniffed: \"deadbeef\" is four \
             bytes as hex and eight characters as text. For an ARP request set 'ethertype' to \
             \"arp\" and put the 28-byte RFC 826 body in 'payload' as hex. The link \
             header for this interface is assembled for you, so do not repeat it in 'payload'. \
             For IPv4 TCP use send_ipv4_tcp instead: it builds and checksums the headers. Do NOT \
             append the FCS - the interface computes it. The whole frame must be at least \
             {MIN_ETHERNET_FRAME_BYTES} and at most {MAX_ETHERNET_FRAME_BYTES} bytes. \
             Alternatively, for a frame you already have in full - one a \
             datalink_frame_captured event handed you, say - pass it as 'frame_hex' instead; \
             supplying both spellings is refused rather than guessed.",
            if in_response {
                "Inject a raw Ethernet frame in response to a captured frame."
            } else {
                "Inject a raw Ethernet frame onto the network."
            },
            ETHERTYPE_NAMES
                .iter()
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        parameters: vec![
            Parameter {
                name: "dst_mac".to_string(),
                type_hint: "string".to_string(),
                description: "Destination MAC address, e.g. \"00:11:22:33:44:55\", or \
                              \"ff:ff:ff:ff:ff:ff\" to broadcast. Ethernet (link_type EN10MB) only, \
                              where it is required unless 'frame_hex' is used; refused on a \
                              loopback or RAW link, which has no MACs."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "src_mac".to_string(),
                type_hint: "string".to_string(),
                description: "Source MAC address, same spelling as 'dst_mac'. Ethernet only, \
                              like 'dst_mac'."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "ethertype".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "What the payload is: a name ({}), a number (2054), or a 0x-prefixed hex \
                     string (\"0x0806\"). A bare \"0806\" is refused - it is 2054 as hex \
                     and 806 as decimal. Required unless 'frame_hex' is used (or the link \
                     is RAW). On a loopback link only ipv4 and ipv6 exist.",
                    ETHERTYPE_NAMES
                        .iter()
                        .map(|(n, _)| *n)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                required: false,
            },
            Parameter {
                name: "payload".to_string(),
                type_hint: "string".to_string(),
                description: "Everything after the link header (14 bytes on Ethernet, 4 on \
                              NULL/LOOP, none on RAW), read according to 'payload_encoding'. \
                              Omit it for a header-only frame."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "payload_encoding".to_string(),
                type_hint: "string".to_string(),
                description: "How to turn 'payload' into bytes. \"hex\" decodes it as \
                              hex-encoded bytes, two hex digits per byte - use it for ARP, IP \
                              and anything else binary. \"utf8\" puts its characters on the \
                              wire unchanged. There is NO default and no auto-detection: \
                              required whenever 'payload' is present."
                    .to_string(),
                required: false,
            }
            .with_choices(["hex", "utf8"]),
            Parameter {
                name: "frame_hex".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "Escape hatch: a complete frame as hex, link header included, for \
                     replaying one a datalink_frame_captured event gave you. Prefer the \
                     structured fields for a frame you are composing - a model cannot \
                     proofread hex. At least {MIN_ETHERNET_FRAME_BYTES} and at most \
                     {MAX_ETHERNET_FRAME_BYTES} bytes, i.e. {} to {} hex characters. Cannot \
                     be combined with 'dst_mac' / 'src_mac' / 'ethertype'.",
                    MIN_ETHERNET_FRAME_BYTES * 2,
                    MAX_ETHERNET_FRAME_BYTES * 2
                ),
                required: false,
            },
        ],
        example: json!({
            "type": "inject_frame",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_mac": "00:11:22:33:44:55",
            "ethertype": "0x88b5",
            "payload": "netget",
            "payload_encoding": "utf8"
        }),
        log_template: None,
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Wait for more frames before responding".to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: None,
    }
}

/// The parameters `send_ipv4_tcp` and `probe_tcp` share.
fn tcp_segment_parameters() -> Vec<Parameter> {
    let p = |name: &str, type_hint: &str, description: String| Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description,
        required: false,
    };
    vec![
        p(
            "dst_ip",
            "string",
            "Destination IPv4 address. Defaults to the host in the client's remote_addr.".into(),
        ),
        p(
            "dst_port",
            "number",
            "Destination TCP port. Defaults to the port in the client's remote_addr.".into(),
        ),
        p(
            "src_ip",
            "string",
            "Source IPv4 address. Defaults to dst_ip when that is loopback; required otherwise."
                .into(),
        ),
        p(
            "src_port",
            "number",
            "Source TCP port. Default: a random ephemeral port (49152-65535).".into(),
        ),
        p(
            "flags",
            "array",
            format!(
                "TCP flags by name, e.g. [\"syn\"] or [\"syn\", \"ack\"] (default \
                 [\"syn\"]). Names: {}",
                tcp_flag_list()
            ),
        ),
        p("seq", "number", "Sequence number. Default: random.".into()),
        p("ack", "number", "Acknowledgement number. Default 0.".into()),
        p(
            "window",
            "number",
            "Advertised window. Default 65535.".into(),
        ),
        p(
            "options",
            "array",
            format!(
                "TCP options in order, each an object with a 'kind': {{\"kind\":\"mss\", \
                 \"value\":1460}}, {{\"kind\":\"wscale\",\"shift\":7}}, \
                 {{\"kind\":\"sack_perm\"}}, {{\"kind\":\"timestamps\",\"tsval\":1, \
                 \"tsecr\":0}}, {{\"kind\":\"nop\"}}, and MPTCP {{\"kind\":\"mp_capable\", \
                 \"version\":1,\"flags\":1}} (flags a number or names: {}; optional \
                 sender_key / receiver_key as 64-bit numbers). Escape hatch for anything \
                 else: {{\"kind\": <number>, \"data_hex\": \"...\"}}. Known kinds: {}. \
                 Padded to 4 bytes for you; 40 bytes at most.",
                MP_CAPABLE_FLAG_NAMES
                    .iter()
                    .map(|(_, n)| *n)
                    .collect::<Vec<_>>()
                    .join(", "),
                TCP_OPTION_KINDS.join(", ")
            ),
        ),
        p("ttl", "number", "IPv4 TTL. Default 64.".into()),
        p(
            "ip_id",
            "number",
            "IPv4 identification. Default: random.".into(),
        ),
        p(
            "dont_fragment",
            "boolean",
            "IPv4 DF bit. Default true.".into(),
        ),
        p(
            "payload",
            "string",
            "TCP data, read according to 'payload_encoding'. Omit for a bare segment.".into(),
        ),
        Parameter {
            name: "payload_encoding".to_string(),
            type_hint: "string".to_string(),
            description: "\"utf8\" or \"hex\"; required with 'payload', no default.".into(),
            required: false,
        }
        .with_choices(["hex", "utf8"]),
        p(
            "dst_mac",
            "string",
            "Ethernet (EN10MB) links only, with src_mac: the next hop's MAC. Refused on a \
             loopback or RAW link."
                .into(),
        ),
        p(
            "src_mac",
            "string",
            "Ethernet links only: this interface's MAC.".into(),
        ),
    ]
}

/// `send_ipv4_tcp`: one IPv4 TCP segment from fields, checksums and link header built.
fn send_ipv4_tcp_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ipv4_tcp".to_string(),
        description: "Send one hand-crafted IPv4 TCP segment from fields: addresses, ports, \
         flags by name, sequence numbers and TCP options as a structured list \
         (including MPTCP mp_capable). The IPv4 and TCP headers and both \
         checksums are computed for you, and the link header is built for this \
         interface's link_type - no MACs on loopback. dst_ip/dst_port default to \
         the client's remote_addr. Use probe_tcp instead to get the replies back."
            .to_string(),
        parameters: tcp_segment_parameters(),
        example: json!({
            "type": "send_ipv4_tcp",
            "dst_ip": "127.0.0.1",
            "dst_port": 3333,
            "src_port": 40000,
            "flags": ["syn"],
            "options": [
                {"kind": "mss", "value": 16344},
                {"kind": "mp_capable", "version": 1, "flags": 1}
            ]
        }),
        log_template: None,
    }
}

/// `probe_tcp`: send like `send_ipv4_tcp`, then collect the replies on that flow.
fn probe_tcp_action() -> ActionDefinition {
    let mut parameters = tcp_segment_parameters();
    parameters.push(Parameter {
        name: "timeout_ms".to_string(),
        type_hint: "number".to_string(),
        description: format!(
            "How long to listen for replies after sending (default {DEFAULT_PROBE_TIMEOUT_MS}, \
             max {MAX_PROBE_TIMEOUT_MS})"
        ),
        required: false,
    });
    parameters.push(Parameter {
        name: "max_replies".to_string(),
        type_hint: "number".to_string(),
        description: format!(
            "Stop listening after this many replies (default 1, max {MAX_PROBE_REPLIES})"
        ),
        required: false,
    });
    ActionDefinition {
        name: "probe_tcp".to_string(),
        description: "Send one IPv4 TCP segment exactly as send_ipv4_tcp does, then listen on \
         its flow and report the replies decoded: flags, sequence numbers, every \
         TCP option (MPTCP subtypes by name) and which of the probe's options \
         came back. A SYN to an open port returns its SYN-ACK; to a closed one, \
         a RST. Works whether or not 'capture' is on: the probe opens its own \
         capture filtered to the reply flow. From send_to_client the replies are \
         the result; from the model they arrive as datalink_probe_completed."
            .to_string(),
        parameters,
        example: json!({
            "type": "probe_tcp",
            "dst_ip": "127.0.0.1",
            "dst_port": 3333,
            "flags": ["syn"],
            "options": [
                {"kind": "mss", "value": 16344},
                {"kind": "mp_capable", "version": 1, "flags": 1}
            ],
            "timeout_ms": 1000
        }),
        log_template: None,
    }
}

/// DataLink client protocol action handler.
///
/// The registry's instance ([`DataLinkClientProtocol::new`]) has no open handle behind it and
/// only validates. A connected client executes with [`DataLinkClientProtocol::with_session`],
/// which knows the link type, so frames are built for the interface they go out on.
#[derive(Default)]
pub struct DataLinkClientProtocol {
    session: LinkSession,
}

impl DataLinkClientProtocol {
    pub fn new() -> Self {
        Self::default()
    }

    /// An executor for one open client: its link type, loopback flag and remote_addr defaults.
    pub fn with_session(session: LinkSession) -> Self {
        Self { session }
    }

    /// What this executor knows about its interface.
    pub fn session(&self) -> &LinkSession {
        &self.session
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for DataLinkClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "interface".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Network interface name for frame injection (e.g., 'eth0', 'en0', 'wlan0')"
                        .to_string(),
                required: true,
                example: json!("eth0"),
                default: None,
            },
            ParameterDefinition {
                name: "promiscuous".to_string(),
                type_hint: "boolean".to_string(),
                description: "Open the interface in promiscuous mode, so frames addressed to \
                              other hosts are seen too (default false). Irrelevant on loopback. \
                              On its own it also turns 'capture' on, as it always has."
                    .to_string(),
                required: false,
                example: json!(false),
                default: None,
            },
            ParameterDefinition {
                name: "capture".to_string(),
                type_hint: "boolean".to_string(),
                description: "Deliver captured frames to the model as datalink_frame_captured \
                              (each one is a model call or a handler run). Independent of \
                              promiscuous mode; defaults to the value of 'promiscuous', so a \
                              client that sets neither only injects. probe_tcp needs neither."
                    .to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
            ParameterDefinition {
                name: "filter".to_string(),
                type_hint: "string".to_string(),
                description: "BPF filter for captured frames, e.g. \"tcp port 3333\" or \
                              \"arp\". Without one, a remote_addr that is an address \
                              (\"127.0.0.1:3333\") captures through \"host 127.0.0.1 and port \
                              3333\"; a remote_addr that is not an address captures everything. \
                              \"\" means no filter at all."
                    .to_string(),
                required: false,
                example: json!("tcp port 3333"),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            inject_frame_action(false),
            send_ipv4_tcp_action(),
            probe_tcp_action(),
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Close the DataLink client and release the interface".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            inject_frame_action(true),
            send_ipv4_tcp_action(),
            wait_for_more_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "DataLink"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        // Clones of the statics this client actually raises, so a declaration cannot
        // drift from what is emitted. These were hand-written duplicates, and
        // `datalink_frame_injected` named an event nothing raised at all.
        vec![
            DATALINK_CLIENT_CONNECTED_EVENT.clone(),
            DATALINK_CLIENT_FRAME_INJECTED_EVENT.clone(),
            DATALINK_CLIENT_FRAME_CAPTURED_EVENT.clone(),
            DATALINK_CLIENT_PROBE_COMPLETED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "datalink",
            "data link",
            "layer 2",
            "layer2",
            "l2",
            "ethernet",
            "frame",
            "inject",
            "pcap",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // Not RawSockets. This opens a libpcap handle, exactly like the DataLink *server*
            // (which declares PacketCapture) - never a SOCK_RAW socket. The two are separate
            // capabilities in `SystemCapabilities`, and a macOS user in the ChmodBPF group has
            // capture without raw sockets, so the wrong variant refuses a host that works.
            .privilege_requirement(PrivilegeRequirement::PacketCapture)
            .implementation(
                "libpcap (pcap crate) for frame injection and capture, framed for the handle's \
                 link type (Ethernet, BSD loopback NULL/LOOP, RAW); IPv4/TCP crafting and \
                 decoding with TCP and MPTCP options in client/datalink/packet.rs",
            )
            .llm_control("Full control over Ethernet frames (inject/capture)")
            .e2e_testing(
                "tests/client/datalink: `action_test.rs` pins the action/event surface with no \
                 privilege at all (every declared example is accepted by execute_action, and a \
                 runt, an over-long frame and bad hex are refused by name). \
                 `command_channel_test.rs` covers the dashboard's [ send ] path, including a \
                 real acknowledged `sendpacket` in its privileged half. The subprocess e2e \
                 tests open a real capture on loopback and inject real frames; they fail with \
                 an explicit message on a host without capture access rather than skipping.",
            )
            .notes(
                "Needs layer-2 capture access (/dev/bpf* on macOS/BSD, root or CAP_NET_RAW on \
                 Linux) for both injection and promiscuous mode. connect() awaits the pcap \
                 handle and returns Err when it cannot be opened, so a host without that \
                 access lands in ClientStatus::Error rather than reporting Connected having \
                 opened nothing. Frame injection has been observed end to end on macOS \
                 (2026-09-08) but only through tests that need that access. On an LLM failure \
                 nothing is injected - the outcome is in the log as decision=model_inject / \
                 model_silent / model_reject / fail_closed_llm_error. The inject -> \
                 datalink_frame_injected -> inject chain is capped at 4 hops; captured frames \
                 arriving while a model turn is running are dropped and counted, not queued. \
                 The link type is read from the open handle and reported as link_type: on \
                 macOS lo0 (NULL) frames carry a 4-byte address family, not MACs. Capture is \
                 its own startup parameter (default: the value of promiscuous), with an \
                 optional BPF filter that defaults from an address remote_addr. probe_tcp \
                 sends a crafted segment and returns the decoded replies on its flow.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            // The only client that puts arbitrary bytes on the wire, IP packets included.
            .search_terms(&["raw", "packet", "packets", "ip", "injection"])
            .build()
    }
    fn description(&self) -> &'static str {
        "DataLink client for raw Ethernet frame injection"
    }
    fn example_prompt(&self) -> &'static str {
        "Inject ARP request on eth0"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles DataLink client
            json!({
                "type": "open_client",
                "remote_addr": "eth0",
                "base_stack": "datalink",
                "instruction": "Inject an ARP request and capture responses",
                "startup_params": {
                    "interface": "eth0",
                    "promiscuous": true
                }
            }),
            // Script mode: Code-based frame handling
            json!({
                "type": "open_client",
                "remote_addr": "eth0",
                "base_stack": "datalink",
                "startup_params": {
                    "interface": "eth0",
                    "promiscuous": true
                },
                "event_handlers": [{
                    "event_pattern": "datalink_frame_captured",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<datalink_handler>"
                    }
                }]
            }),
            // Static mode: Fixed frame injection
            json!({
                "type": "open_client",
                "remote_addr": "eth0",
                "base_stack": "datalink",
                "startup_params": {
                    "interface": "eth0",
                    "promiscuous": false
                },
                "event_handlers": [{
                    "event_pattern": "datalink_frame_injected",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "wait_for_more"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for DataLinkClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::datalink::DataLinkClient;
            DataLinkClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                ctx.startup_params,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "inject_frame" => Ok(ClientActionResult::SendData(build_frame_for_link(
                &action,
                self.session.link_type.unwrap_or_default(),
            )?)),
            "send_ipv4_tcp" => Ok(ClientActionResult::SendData(
                build_tcp_frame(&action, &self.session)?.0,
            )),
            "probe_tcp" => Ok(ClientActionResult::Custom {
                name: "probe_tcp".to_string(),
                data: serde_json::to_value(build_probe(&action, &self.session)?)?,
            }),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown DataLink client action: {}",
                action_type
            )),
        }
    }
}

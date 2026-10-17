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

/// Assemble the bytes `inject_frame` will hand to libpcap, from whichever spelling was used.
///
/// Two spellings, and exactly one of them per action:
///
/// - **Structured** — `dst_mac`, `src_mac`, `ethertype`, and an optional `payload` with its
///   required `payload_encoding`. This is the one the model is shown, because every part of
///   it is a thing a model can write correctly and a person can check.
/// - **`frame_hex`** — the whole frame as hex. The escape hatch, kept because
///   `datalink_frame_captured` hands the model exactly this and replaying or amending a
///   captured frame is a real thing to want.
///
/// Supplying both is **refused** rather than resolved by precedence: they are two statements
/// about the same wire bytes and guessing which one was meant is how a frame nobody intended
/// goes out. A structured spelling missing one of its three required fields is refused by
/// name rather than silently falling back to zeros.
pub fn build_frame(action: &serde_json::Value) -> Result<Vec<u8>> {
    let frame_hex = action.get("frame_hex").and_then(|v| v.as_str());
    let structured = ["dst_mac", "src_mac", "ethertype"]
        .iter()
        .any(|k| action.get(k).is_some());

    let frame = match (frame_hex, structured) {
        (Some(_), true) => anyhow::bail!(
            "Both 'frame_hex' and the structured fields (dst_mac / src_mac / ethertype) were \
             supplied. Send exactly one: the structured form for a frame you are building, or \
             'frame_hex' for a frame you already have in full. They are not combined and \
             neither takes precedence."
        ),
        (None, false) => anyhow::bail!(
            "Missing frame. Give 'dst_mac', 'src_mac' and 'ethertype' (plus an optional \
             'payload' with its 'payload_encoding'), or the whole frame as 'frame_hex'."
        ),
        (Some(h), false) => decode_frame_hex(h)?,
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

    // Bounds before libpcap sees it: a runt has no EtherType, and a frame the size of a
    // prompt is a mistake worth naming rather than an ENOBUFS from a syscall. The model is
    // told the actual length so it can fix the frame.
    if frame.len() < MIN_ETHERNET_FRAME_BYTES {
        anyhow::bail!(
            "the frame is {} bytes; an Ethernet frame needs at least {} (6-byte destination \
             MAC, 6-byte source MAC, 2-byte EtherType)",
            frame.len(),
            MIN_ETHERNET_FRAME_BYTES
        );
    }
    if frame.len() > MAX_ETHERNET_FRAME_BYTES {
        anyhow::bail!(
            "the frame is {} bytes; the maximum injectable frame is {}",
            frame.len(),
            MAX_ETHERNET_FRAME_BYTES
        );
    }

    Ok(frame)
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
                 to inject_frame. Null only when the captured bytes are shorter than an \
                 Ethernet header."
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
                 \"0x0800\" (IPv4). inject_frame accepts this spelling unchanged."
            ),
            required: true,
        },
        Parameter {
            name: "payload".to_string(),
            type_hint: "string".to_string(),
            description: format!(
                "Everything in {what} after the 14-byte Ethernet header, read according to \
                 'payload_encoding'. A prefix when `truncated` is true."
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
                "The whole of the first {} bytes of {} as hex (dst MAC, src MAC, EtherType, \
                 payload), for replaying it verbatim through inject_frame's 'frame_hex' \
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
    ])
    .with_actions(vec![inject_frame_action(false), wait_for_more_action()])
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
            "{} Build it from fields: 'dst_mac' and 'src_mac' as \"aa:bb:cc:dd:ee:ff\", \
             'ethertype' as a name ({}), a number (2054) or a 0x string (\"0x0806\"), and an \
             optional 'payload' whose 'payload_encoding' says whether it is \"hex\" (binary - \
             ARP, IP, anything with a header) or \"utf8\" (its characters, as they are). \
             'payload_encoding' has no default and nothing is sniffed: \"deadbeef\" is four \
             bytes as hex and eight characters as text. For an ARP request set 'ethertype' to \
             \"arp\" and put the 28-byte RFC 826 body in 'payload' as hex. The 14-byte \
             Ethernet header is assembled for you, so do not repeat it in 'payload'. Do NOT \
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
                              \"ff:ff:ff:ff:ff:ff\" to broadcast. Required unless \
                              'frame_hex' is used."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "src_mac".to_string(),
                type_hint: "string".to_string(),
                description: "Source MAC address, same spelling as 'dst_mac'. Required unless \
                              'frame_hex' is used."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "ethertype".to_string(),
                type_hint: "string".to_string(),
                description: format!(
                    "What the payload is: a name ({}), a number (2054), or a 0x-prefixed hex \
                     string (\"0x0806\"). A bare \"0806\" is refused - it is 2054 as hex \
                     and 806 as decimal. Required unless 'frame_hex' is used.",
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
                description: "Everything after the 14-byte Ethernet header, read according to \
                              'payload_encoding'. Omit it for a header-only frame."
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
                    "Escape hatch: a complete Ethernet frame as hex, header included, for \
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

/// DataLink client protocol action handler
pub struct DataLinkClientProtocol;

impl DataLinkClientProtocol {
    pub fn new() -> Self {
        Self
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
                description:
                    "Enable promiscuous mode to capture frames (requires root/CAP_NET_RAW)"
                        .to_string(),
                required: false,
                example: json!(false),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            inject_frame_action(false),
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
        vec![inject_frame_action(true), wait_for_more_action()]
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
            .implementation("libpcap (pcap crate) for Layer 2 frame injection and capture")
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
                 arriving while a model turn is running are dropped and counted, not queued.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
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
            "inject_frame" => Ok(ClientActionResult::SendData(build_frame(&action)?)),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown DataLink client action: {}",
                action_type
            )),
        }
    }
}

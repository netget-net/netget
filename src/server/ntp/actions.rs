//! NTP protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use crate::utils::clock::{SystemTime, UNIX_EPOCH};
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// NTP protocol handler.
///
/// The server builds one instance per received datagram (see
/// [`crate::server::ntp::NtpServer::spawn_with_llm_actions`]) so the request's own
/// transmit timestamp and version travel with the actions generated for it. The
/// registry's instance is created with [`NtpProtocol::new`] and carries no request.
pub struct NtpProtocol {
    /// The client's transmit timestamp, as the raw 64-bit NTP value taken from bytes
    /// 40-47 of the request. RFC 5905 requires the server to copy it into the reply's
    /// origin timestamp; a client that does not find its own value there discards the
    /// reply, which looks exactly like a timeout.
    request_origin_timestamp: Option<u64>,
    /// NTP version the client used, echoed back in the reply's first byte.
    request_version: u8,
}

impl NtpProtocol {
    pub fn new() -> Self {
        Self {
            request_origin_timestamp: None,
            request_version: 4,
        }
    }

    /// Build a handler bound to one request: `origin_timestamp` is the client's raw
    /// 64-bit transmit timestamp and `version` the NTP version it used (1-4).
    pub fn for_request(origin_timestamp: Option<u64>, version: u8) -> Self {
        Self {
            request_origin_timestamp: origin_timestamp,
            request_version: if (1..=4).contains(&version) {
                version
            } else {
                4
            },
        }
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for NtpProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_ntp_time_response_action(),
            send_ntp_response_action(),
            ignore_request_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "NTP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_ntp_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>NTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["ntp", "time"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            // Answers on failure: a Kiss-o'-Death (RATE when overloaded, INIT otherwise), never
            // the mechanical time response.
            .answers_on_failure()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(123))
            .well_known_udp_port(123)
            .implementation("Manual 48-byte NTP packet construction")
            .llm_control("Optional: normal time responses are static by default (mechanical), LLM only on opt-in")
            .e2e_testing(
                "rsntp, a third-party SNTP client, in tests/server/ntp/test.rs -- not \
                 #[ignore]d and not skip-gated (rsntp is a compiled-in dependency). It must \
                 SUCCEED: it validates the origin-timestamp echo, the mode and the leap \
                 indicator, which are the three things a real client rejects a reply over. The \
                 raw 48-byte path alongside it decodes every field by hand against RFC 5905, \
                 and llm_failure_test.rs / decision_tag_test.rs assert the Kiss-o'-Death on the \
                 fail-closed paths, stratum included, so the wire and the log cannot drift \
                 apart. \
                 ONE CLIENT, and a second is blocked by the protocol rather than by effort. \
                 The reference clients are sntp and ntpdate (ntp 4.2.8), both installed on this \
                 machine, and NEITHER accepts a port: sntp takes a bare hostname-or-IP with no \
                 -p, ntpdate's usage line has none either, and both reject `127.0.0.1:12345` as \
                 an unresolvable name. A test binds an ephemeral port, so neither can be aimed \
                 at it without running the server on 123 as root. This is the same shape as \
                 dhcp, whose own metadata records that dhclient and ipconfig bind UDP/68, need \
                 root and cannot target an ephemeral loopback port. \
                 UNPROVEN: NTPv5, extension fields, authentication (none is implemented), \
                 broadcast and symmetric modes, and the NTP control protocol.",
            )
            .notes("Client/server mode only (mode 3 -> mode 4). A normal time response is mechanical (stratum 2, LOCL, current-time timestamps, origin+version echoed from the request), so it is answered STATICALLY with no LLM round-trip by default. The LLM is consulted only when the operator opts in with a server instruction or per-event handler — the way to make the server skew or lie about the time. On LLM failure in opt-in mode the server falls back to the correct static time response. Sub-ms with scripting")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Network Time Protocol server for time synchronization"
    }
    fn example_prompt(&self) -> &'static str {
        "pretend to be a ntp server on port 123"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            // LLM-driven example
            json!({
                "type": "open_server",
                "port": 123,
                "base_stack": "ntp",
                "instruction": "NTP server responding with current system time as stratum 2"
            }),
            // Script-based example
            json!({
                "type": "open_server",
                "port": 123,
                "base_stack": "ntp",
                "event_handlers": [{
                    "event_pattern": "ntp_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "# Return NTP time response\nrespond([{'type': 'send_ntp_time_response', 'stratum': 2, 'reference_id': 'LOCL'}])"
                    }
                }]
            }),
            // Static handler example
            json!({
                "type": "open_server",
                "port": 123,
                "base_stack": "ntp",
                "event_handlers": [{
                    "event_pattern": "ntp_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_ntp_time_response",
                            "stratum": 2,
                            "reference_id": "LOCL"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for NtpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::ntp::NtpServer;
            NtpServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
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
            "send_ntp_time_response" => self.execute_send_ntp_time_response(action),
            "send_ntp_response" => self.execute_send_ntp_response(action),
            "ignore_request" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown NTP action: {}", action_type)),
        }
    }
}

impl NtpProtocol {
    fn execute_send_ntp_time_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Extract all NTP fields from the action
        let stratum = action.get("stratum").and_then(|v| v.as_u64()).unwrap_or(2) as u8;

        let reference_id = action
            .get("reference_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let leap_indicator = action
            .get("leap_indicator")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;

        let poll = action.get("poll").and_then(|v| v.as_u64()).unwrap_or(6) as u8;

        let precision = action
            .get("precision")
            .and_then(|v| v.as_i64())
            .unwrap_or(-20) as i8;

        let root_delay = action
            .get("root_delay")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let root_dispersion = action
            .get("root_dispersion")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        // Timestamps - support "current_time", unix timestamp (seconds), or null
        let reference_timestamp = Self::parse_timestamp(action.get("reference_timestamp"));
        let receive_timestamp = Self::parse_timestamp(action.get("receive_timestamp"));
        let transmit_timestamp = Self::parse_timestamp(action.get("transmit_timestamp"));

        // Origin timestamp: whatever the action asked for, else the client's own transmit
        // timestamp captured from this request. Falling back to "now" would produce a
        // reply the client rejects, so an unknown origin stays zero.
        let origin_timestamp = match action.get("origin_timestamp") {
            Some(serde_json::Value::Null) | None => self.request_origin_timestamp,
            Some(v) => Self::parse_timestamp(Some(v)).or(self.request_origin_timestamp),
        };

        // Build NTP response packet
        let packet = Self::build_ntp_packet(
            self.request_version,
            leap_indicator,
            stratum,
            poll,
            precision,
            root_delay,
            root_dispersion,
            reference_id,
            reference_timestamp,
            origin_timestamp,
            receive_timestamp,
            transmit_timestamp,
        );
        Ok(ActionResult::Output(packet))
    }

    fn parse_timestamp(value: Option<&serde_json::Value>) -> Option<u64> {
        match value {
            Some(serde_json::Value::String(s)) if s == "current_time" => {
                Some(Self::get_current_ntp_time())
            }
            Some(serde_json::Value::Number(n)) => {
                n.as_u64().map(|timestamp| {
                    // If value is > 2^32 (4,294,967,296), it's a full 64-bit NTP timestamp (seconds + fraction)
                    // Otherwise, it's a Unix timestamp (seconds only) that needs conversion
                    if timestamp > 0xFFFFFFFF {
                        // Raw NTP timestamp (64-bit: 32-bit seconds + 32-bit fraction)
                        timestamp
                    } else {
                        // Unix timestamp (seconds since 1970) - convert to NTP timestamp (seconds part only)
                        // Note: This loses fractional precision, but LLM typically provides whole seconds
                        let ntp_seconds = timestamp + 2_208_988_800;
                        ntp_seconds << 32 // Shift to upper 32 bits, fraction = 0
                    }
                })
            }
            Some(serde_json::Value::Null) | None => None,
            _ => None,
        }
    }

    fn get_current_ntp_time() -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ntp_seconds = now + 2_208_988_800; // Unix epoch to NTP epoch offset
        ntp_seconds << 32 // Return 64-bit timestamp: seconds in upper 32 bits, fraction=0 in lower 32 bits
    }

    /// Decode the raw-packet escape hatch.
    ///
    /// `data` is documented as hex, so it is decoded strictly as hex. Falling back to the
    /// string's own bytes (the previous behaviour) silently put ASCII on the wire whenever
    /// the model produced slightly malformed hex, and an NTP client cannot read that.
    fn execute_send_ntp_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let data = action
            .get("data")
            .and_then(|v| v.as_str())
            .context("Missing 'data' parameter")?;

        // Models routinely emit "0x" prefixes and byte separators; strip them first.
        let cleaned: String = data
            .chars()
            .filter(|c| !c.is_ascii_whitespace() && *c != ':')
            .collect();
        let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);

        if cleaned.len() % 2 != 0 {
            return Err(anyhow::anyhow!(
                "Invalid hex in 'data': {} hex digits is an odd number, and every byte is two \
                 digits. Value was {data:?}",
                cleaned.len()
            ));
        }

        let bytes = hex::decode(cleaned).map_err(|e| {
            anyhow::anyhow!(
                "Invalid hex in 'data' ({data:?}): {e}. Use only 0-9 and a-f, two digits per byte. \
                 This field is a raw packet - there is no text mode."
            )
        })?;

        if bytes.len() < 48 {
            return Err(anyhow::anyhow!(
                "'data' decodes to {} bytes; an NTP packet is at least 48 (96 hex characters). \
                 Prefer send_ntp_time_response, which builds a correct packet for you.",
                bytes.len()
            ));
        }

        Ok(ActionResult::Output(bytes))
    }

    /// Build a valid NTP response packet
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_ntp_packet(
        version: u8,
        leap_indicator: u8,
        stratum: u8,
        poll: u8,
        precision: i8,
        root_delay: f64,
        root_dispersion: f64,
        reference_id: &str,
        reference_timestamp: Option<u64>,
        origin_timestamp: Option<u64>,
        receive_timestamp: Option<u64>,
        transmit_timestamp: Option<u64>,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 48];

        // Byte 0: LI (2 bits), Version (3 bits), Mode=4 (3 bits, server).
        // RFC 5905 says a server answers in the version the client used, so this echoes
        // the request's version rather than hardcoding 4.
        let li = (leap_indicator & 0x03) << 6; // LI in bits 7-6
        let vn = (version & 0x07) << 3; // Version in bits 5-3
        let mode = 0x04; // Mode 4 (server) in bits 2-0
        packet[0] = li | vn | mode;

        // Byte 1: Stratum
        packet[1] = stratum;

        // Byte 2: Poll interval (log2 seconds)
        packet[2] = poll;

        // Byte 3: Precision (log2 seconds, signed 8-bit)
        packet[3] = precision as u8;

        // Bytes 4-7: Root delay (32-bit fixed point: 16 bits integer, 16 bits fraction)
        let root_delay_fixed = (root_delay * 65536.0) as u32;
        packet[4..8].copy_from_slice(&root_delay_fixed.to_be_bytes());

        // Bytes 8-11: Root dispersion (32-bit fixed point: 16 bits integer, 16 bits fraction)
        let root_dispersion_fixed = (root_dispersion * 65536.0) as u32;
        packet[8..12].copy_from_slice(&root_dispersion_fixed.to_be_bytes());

        // Bytes 12-15: Reference ID (4-byte ASCII identifier)
        let ref_id_bytes = if reference_id.is_empty() {
            [0u8; 4] // Zeros if not specified
        } else {
            let mut bytes = [0u8; 4];
            for (i, b) in reference_id.bytes().take(4).enumerate() {
                bytes[i] = b;
            }
            bytes
        };
        packet[12..16].copy_from_slice(&ref_id_bytes);

        // Helper to write timestamp (64-bit: upper 32 bits = seconds, lower 32 bits = fraction)
        let write_timestamp = |packet: &mut [u8], offset: usize, timestamp: Option<u64>| {
            if let Some(ntp_time) = timestamp {
                let seconds = ((ntp_time >> 32) & 0xFFFFFFFF) as u32; // Upper 32 bits
                let fraction = (ntp_time & 0xFFFFFFFF) as u32; // Lower 32 bits
                packet[offset..offset + 4].copy_from_slice(&seconds.to_be_bytes());
                packet[offset + 4..offset + 8].copy_from_slice(&fraction.to_be_bytes());
            }
            // else: leave as zeros
        };

        // Reference timestamp (bytes 16-23) - when the clock was last set
        write_timestamp(
            &mut packet,
            16,
            reference_timestamp.or_else(|| Some(Self::get_current_ntp_time())),
        );

        // Origin timestamp (bytes 24-31) - a verbatim copy of the client's transmit
        // timestamp. Left as zeros when this request had none (a short or malformed
        // packet): zeros at least make the mismatch obvious, whereas writing the current
        // time would claim the client sent something it did not.
        write_timestamp(&mut packet, 24, origin_timestamp);

        // Receive timestamp (bytes 32-39) - when we received the request
        write_timestamp(
            &mut packet,
            32,
            receive_timestamp.or_else(|| Some(Self::get_current_ntp_time())),
        );

        // Transmit timestamp (bytes 40-47) - when we send the response
        write_timestamp(
            &mut packet,
            40,
            transmit_timestamp.or_else(|| Some(Self::get_current_ntp_time())),
        );

        packet
    }
}

/// Build a Kiss-o'-Death packet (RFC 5905 §7.4) for a request we cannot answer.
///
/// NTP has no error message, but it does have a defined way for a server to say
/// "do not use me": stratum 0, leap indicator 3 (unsynchronized), and a
/// four-character kiss code in the reference identifier. `chrony`, `ntpd` and
/// `ntpdate` all recognise it, refuse to take time from the packet, and stop
/// polling — which is exactly right when the backend that would have decided the
/// answer is unavailable. Writing nothing instead leaves the client retrying
/// against a server it believes is merely slow.
///
/// It also fails closed: a KoD can never be mistaken for a time sample, so an
/// outage cannot silently hand a client a fabricated clock reading.
///
/// The client's transmit timestamp is echoed as the origin timestamp for the
/// same reason a normal reply echoes it — a reply that fails that check is
/// discarded, which would put us back at silence.
///
/// `kiss_code` should be one of the registered codes; this server uses `RATE`
/// (reduce your polling rate) when the failure is capacity exhaustion and `INIT`
/// (association not yet synchronized) for every other failure.
pub fn build_kod_packet(version: u8, origin_timestamp: Option<u64>, kiss_code: &str) -> Vec<u8> {
    NtpProtocol::build_ntp_packet(
        version,
        3,         // LI = 3, unsynchronized
        0,         // stratum 0 — this is what marks the packet as a KoD
        0,         // poll
        0,         // precision
        0.0,       // root delay
        0.0,       // root dispersion
        kiss_code, // reference identifier carries the kiss code
        None,      // reference timestamp: now
        origin_timestamp,
        None, // receive timestamp: now
        None, // transmit timestamp: now
    )
}

fn send_ntp_time_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ntp_time_response".to_string(),
        description: "Send NTP time synchronization response. Most fields have sensible defaults, override only if instructed.".to_string(),
        parameters: vec![
            Parameter {
                name: "leap_indicator".to_string(),
                type_hint: "number".to_string(),
                description: "Leap second warning: 0=no warning, 1=last minute has 61s, 2=last minute has 59s, 3=alarm/unsync. Default: 0".to_string(),
                required: false,
            },
            Parameter {
                name: "stratum".to_string(),
                type_hint: "number".to_string(),
                description: "Stratum level: 0=unspec, 1=primary (GPS/atomic), 2-15=secondary. Can be inferred from server instructions. Default: 2".to_string(),
                required: false,
            },
            Parameter {
                name: "poll".to_string(),
                type_hint: "number".to_string(),
                description: "Poll interval (log2 seconds): 4=16s, 6=64s, 10=1024s. Default: 6".to_string(),
                required: false,
            },
            Parameter {
                name: "precision".to_string(),
                type_hint: "number".to_string(),
                description: "Clock precision (log2 seconds): -6=~15ms, -20=~1us. Negative values. Default: -20".to_string(),
                required: false,
            },
            Parameter {
                name: "root_delay".to_string(),
                type_hint: "number".to_string(),
                description: "Total round-trip delay to primary reference (seconds, float). Default: 0.0".to_string(),
                required: false,
            },
            Parameter {
                name: "root_dispersion".to_string(),
                type_hint: "number".to_string(),
                description: "Max error relative to primary reference (seconds, float). Default: 0.0".to_string(),
                required: false,
            },
            Parameter {
                name: "reference_id".to_string(),
                type_hint: "string".to_string(),
                description: "4-char clock identifier: 'LOCL'=local, 'GPS.'=GPS, 'PPS.'=PPS, 'ATOM'=atomic, or IP address. Default: empty".to_string(),
                required: false,
            },
            Parameter {
                name: "reference_timestamp".to_string(),
                type_hint: "string | number".to_string(),
                description: "When clock was last set: 'current_time', Unix timestamp (seconds), or null. Default: current_time".to_string(),
                required: false,
            },
            Parameter {
                name: "origin_timestamp".to_string(),
                type_hint: "number".to_string(),
                description: "Leave this out. The server copies the client's own transmit timestamp from the request it is answering, which is what the client checks to accept the reply. Setting it to anything else (including the current time) makes the client discard the response and report a timeout. Only override it - with the exact 'client_transmit_timestamp' value from the event - when you are deliberately testing a mismatch".to_string(),
                required: false,
            },
            Parameter {
                name: "receive_timestamp".to_string(),
                type_hint: "string | number".to_string(),
                description: "When server received request: 'current_time', Unix timestamp, or null. Default: current_time".to_string(),
                required: false,
            },
            Parameter {
                name: "transmit_timestamp".to_string(),
                type_hint: "string | number".to_string(),
                description: "When server sends response: 'current_time', Unix timestamp, or null. Default: current_time".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_ntp_time_response",
            "stratum": 2
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NTP stratum {stratum}")
                .with_debug("NTP send_ntp_time_response: stratum={stratum}"),
        ),
    }
}

fn send_ntp_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_ntp_response".to_string(),
        description: "Escape hatch: send an NTP packet you assembled yourself, byte for byte. Prefer send_ntp_time_response, which fills in the header and echoes the client's origin timestamp; use this only for packets that action cannot express (Kiss-o'-Death, deliberately malformed replies). Nothing is echoed for you here - bytes 24-31 must contain the client's own transmit timestamp or the client will discard the packet.".to_string(),
        parameters: vec![Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The whole packet as hex, two digits per byte (spaces and ':' are allowed and ignored), at least 48 bytes = 96 hex characters. Decoded strictly as hex - it is never sent as text"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_ntp_response",
            "data": "240201e900000000000000000000000000000000000000000000000000000000eca56dd14ae94680eca56dd14ae94680eca56dd14ae94680"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> NTP raw response ({data_len}B)")
                .with_debug("NTP send_ntp_response: {data_len} bytes"),
        ),
    }
}

fn ignore_request_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_request".to_string(),
        description: "Ignore this NTP request".to_string(),
        parameters: vec![],
        example: json!({
            "type": "ignore_request"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("NTP request ignored")
                .with_debug("NTP ignore_request"),
        ),
    }
}

// ============================================================================
// NTP Event Type Constants
// ============================================================================

/// NTP request event - triggered when NTP client sends a time request
pub static NTP_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("ntp_request", "NTP client sent a time synchronization request", json!({"type": "placeholder", "event_id": "ntp_request"}))
    .with_parameters(vec![
        Parameter {
            name: "current_time".to_string(),
            type_hint: "number".to_string(),
            description: "The server's current time as a Unix timestamp (seconds since 1970), for reference when deciding what time to report".to_string(),
            required: true,
        },
        Parameter {
            name: "client_transmit_timestamp".to_string(),
            type_hint: "number".to_string(),
            description: "The client's transmit timestamp as the raw 64-bit NTP value (upper 32 bits seconds since 1900, lower 32 bits fraction). send_ntp_time_response copies it into the reply for you, so you do not need to pass it back - it is here only so a handler can inspect or deliberately alter it. Absent if the request was shorter than 48 bytes".to_string(),
            required: false,
        },
        Parameter {
            name: "client_transmit_unix".to_string(),
            type_hint: "number".to_string(),
            description: "The same client timestamp converted to whole Unix seconds, for readability. Lossy - never echo this one back as origin_timestamp".to_string(),
            required: false,
        },
        Parameter {
            name: "client_version".to_string(),
            type_hint: "number".to_string(),
            description: "NTP version the client used, 1-4. The reply is sent in the same version automatically".to_string(),
            required: false,
        },
        Parameter {
            name: "client_mode".to_string(),
            type_hint: "number".to_string(),
            description: "Mode field of the request: 3 is a normal client query. Other values (1, 2, 5, 6) are symmetric/broadcast/control packets that this server still answers as if they were client queries".to_string(),
            required: false,
        },
        Parameter {
            name: "bytes_received".to_string(),
            type_hint: "number".to_string(),
            description: "Size of the received datagram in bytes. A standard request is 48; larger means extension fields or an authentication MAC, which this server ignores".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        send_ntp_time_response_action(),
        send_ntp_response_action(),
        ignore_request_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("NTP request from {client_ip}")
            .with_debug("NTP time sync request: {bytes_received}B from {client_ip}")
            .with_trace("NTP request: {json_pretty(.)}"),
    )
});

/// Get NTP event types
pub fn get_ntp_event_types() -> Vec<EventType> {
    vec![NTP_REQUEST_EVENT.clone()]
}

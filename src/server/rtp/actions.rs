//! RTP protocol actions.
//!
//! The model never emits samples or bytes. It answers a received-packet event with a *structured
//! description* of what to stream — a tone frequency, DTMF digits, silence — and the server
//! (`mod.rs` + `media.rs`) synthesizes G.711 and frames it into RTP. This mirrors VNC, where the
//! model describes a screen and Rust owns the pixels.

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

pub struct RtpProtocol;

impl RtpProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RtpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for RtpProtocol {
    /// One parameter, read by [`crate::server::rtp::RtpConfig::from_params`].
    ///
    /// RTP is the one protocol here where the model genuinely cannot be on the per-packet path,
    /// so the ceiling is configuration rather than a constant.
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![ParameterDefinition {
            name: "llm_max_per_minute".to_string(),
            type_hint: "number".to_string(),
            description: format!(
                "Ceiling on model consultations per rolling minute (default {}). A single G.711 \
                 stream is 50 packets per second, so without a ceiling one stream is 50 LLM \
                 calls a second. Datagrams over the ceiling are dropped and nothing is sent, \
                 logged as decision=fail_closed_rate_limited. A script or static event handler \
                 is never charged against this, so 0 - forbidding model consultation entirely - \
                 is the right value for a server driven wholly by handlers.",
                crate::server::rtp::DEFAULT_LLM_MAX_PER_MINUTE
            ),
            required: false,
            example: json!(30),
            default: None,
        }]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![send_rtp_audio_action(), send_rtcp_sender_report_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![send_rtp_audio_action(), send_rtcp_sender_report_action()]
    }
    fn protocol_name(&self) -> &'static str {
        "RTP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![RTP_RECEIVED_EVENT.clone(), RTCP_RECEIVED_EVENT.clone()]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>RTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "rtp",
            "real-time transport",
            "rtp media stream",
            "voip audio",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder()
            .connectionless()
            .state(DevelopmentState::Experimental)
            .well_known_udp_port(5004)
            // Deliberately silent: An RTP packet asserts media content at a timestamp; there
            // is no error packet, and a fabricated one is played.
            .deliberately_silent()
            .implementation(
                "Manual RFC 3550 packetizer with a G.711 (PCMU/PCMA) synthesis engine; the model \
                 describes content, Rust owns the samples and framing",
            )
            .llm_control(
                "What each stream carries (tone frequency, DTMF digits, silence, or hex-encoded \
                 codec bytes) and the response to inbound RTP/RTCP",
            )
            .e2e_testing(
                "Byte-literal RTP header assertions (mock LLM); interop with ffmpeg/ffprobe via \
                 the rtsp front door",
            )
            .notes(
                "PCMU (PT 0) and PCMA (PT 8) audio genuinely synthesize and decode in ffmpeg. \
                 There is no video codec: video PTs are out of scope. Speech is NOT synthesized — \
                 there is no TTS; ask for a tone/DTMF/silence, or supply raw codec bytes hex-encoded. \
                 RTCP is a minimal SR with no report blocks.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "RTP media server that synthesizes G.711 audio streams under LLM direction"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an RTP server on port 40000. When a packet arrives, stream a 440 Hz PCMU tone back."
    }
    fn group_name(&self) -> &'static str {
        "Proxy & Network"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: play a 440 Hz tone in response to every received RTP
        // packet, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "rtp_packet_received":
    actions = [{"type": "send_rtp_audio", "tone_hz": 440, "duration_ms": 200}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 40000,
                "base_stack": "rtp",
                "instruction": "RTP media endpoint. When an RTP packet arrives, answer with send_rtp_audio streaming a 440 Hz PCMU tone for 2 seconds, echoing the caller's SSRC."
            }),
            json!({
                "type": "open_server",
                "port": 40000,
                "base_stack": "rtp",
                "event_handlers": [{
                    "event_pattern": "rtp_packet_received",
                    "handler": {"type": "script", "language": "python", "code": script}
                }]
            }),
            json!({
                "type": "open_server",
                "port": 40000,
                "base_stack": "rtp",
                "event_handlers": [{
                    "event_pattern": "rtp_packet_received",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_rtp_audio",
                            "payload_type": "pcmu",
                            "content": "tone",
                            "tone_hz": 440,
                            "duration_ms": 1000
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for RtpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::rtp::{RtpConfig, RtpServer};
            let cfg = RtpConfig::from_params(&ctx.startup_params)?;
            RtpServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                cfg,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Wire I/O (synthesis + send) is performed in mod.rs from the raw action JSON, exactly as
        // SIP builds its response there. Here we only validate that the action is well-formed so a
        // malformed one is reported rather than silently sent.
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;
        match action_type {
            "send_rtp_audio" => {
                // Validate content/codec now for a clean error; discard the synthesized bytes.
                let codec = action
                    .get("payload_type")
                    .and_then(|v| v.as_str())
                    .map(crate::server::rtp::media::AudioCodec::parse)
                    .unwrap_or(Ok(crate::server::rtp::media::AudioCodec::Pcmu))?;
                let content = crate::server::rtp::media::parse_audio_content(&action)?;
                let duration = action
                    .get("duration_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1000);
                crate::server::rtp::media::synthesize(codec, &content, duration)?;
                Ok(ActionResult::NoAction)
            }
            "send_rtcp_sender_report" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown RTP action: {}", action_type)),
        }
    }
}

pub static RTP_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rtp_packet_received",
        "An RTP packet arrived. Answer with send_rtp_audio to stream media back to the caller \
         (describe the content — a tone, DTMF, or silence — never raw samples). Echo the caller's \
         ssrc if you want the reply attributed to the same source, or omit it for a fresh one.",
        json!({
            "type": "send_rtp_audio",
            "payload_type": "pcmu",
            "content": "tone",
            "tone_hz": 440,
            "duration_ms": 1000
        }),
    )
    .with_actions(vec![
        send_rtp_audio_action(),
        send_rtcp_sender_report_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("RTP pkt pt={payload_type} seq={sequence}")
            .with_debug("RTP in pt={payload_type} seq={sequence} ssrc={ssrc} len={payload_len}")
            .with_trace("RTP: {json_pretty(.)}"),
    )
});

pub static RTCP_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rtcp_packet_received",
        "An RTCP control packet arrived (sender/receiver report, BYE, …). Optionally answer with \
         send_rtcp_sender_report to report this endpoint's own sending statistics.",
        json!({
            "type": "send_rtcp_sender_report",
            "packet_count": 50,
            "octet_count": 8000
        }),
    )
    .with_actions(vec![send_rtcp_sender_report_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("RTCP pkt type={packet_type}")
            .with_debug("RTCP in type={packet_type} len={length}")
            .with_trace("RTCP: {json_pretty(.)}"),
    )
});

pub fn send_rtp_audio_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_rtp_audio".to_string(),
        description: "Stream synthesized G.711 audio to the caller as RTP packets. Describe the \
                      content structurally; the server owns the samples and the packet framing."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "payload_type".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Codec: \"pcmu\" (PT 0, µ-law) or \"pcma\" (PT 8, A-law). Default pcmu."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "content".to_string(),
                type_hint: "string".to_string(),
                description: "\"tone\", \"dtmf\", \"silence\", or \"raw\". Default tone."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "tone_hz".to_string(),
                type_hint: "number".to_string(),
                description: "Tone frequency in Hz (20-3800) when content=tone. Default 440."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "digits".to_string(),
                type_hint: "string".to_string(),
                description: "DTMF digits (0-9,*,#,A-D) when content=dtmf.".to_string(),
                required: false,
            },
            Parameter {
                name: "duration_ms".to_string(),
                type_hint: "number".to_string(),
                description: "Stream length in milliseconds (1-30000). Default 1000. Ignored \
                              for content=dtmf, whose length is 200 ms per digit, and for \
                              content=raw, whose length is the decoded payload; both are held \
                              to the same 30 s ceiling."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "encoding".to_string(),
                type_hint: "string".to_string(),
                description: "For content=raw only: must be \"hex\". The server hex-decodes \
                              `samples` into codec bytes for real (never base64, never sniffed)."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "samples".to_string(),
                type_hint: "string".to_string(),
                description:
                    "For content=raw only: hex-encoded, already codec-encoded payload bytes."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "ssrc".to_string(),
                type_hint: "number".to_string(),
                description: "Synchronization source id (32-bit). Omit for a random one."
                    .to_string(),
                required: false,
            },
            // Both are read by the executor and handed to RtpPacketizer, but were declared
            // nowhere - so a model continuing an existing stream could not keep its numbering
            // continuous, and every call restarted the sequence and timestamp.
            Parameter {
                name: "start_sequence".to_string(),
                type_hint: "number".to_string(),
                description: "RTP sequence number for the first packet (16-bit). Omit to                     continue from a random start; set it to resume an existing stream without                     a gap."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "start_timestamp".to_string(),
                type_hint: "number".to_string(),
                description: "RTP timestamp for the first packet (32-bit, 8kHz for G.711).                     Omit for a random start; set it to keep a resumed stream's clock                     continuous."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_rtp_audio",
            "payload_type": "pcmu",
            "content": "tone",
            "tone_hz": 440,
            "duration_ms": 2000,
            "ssrc": 305419896
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("→ RTP {content} {payload_type} {duration_ms}ms")
                .with_debug("RTP send_rtp_audio content={content} pt={payload_type}"),
        ),
    }
}

pub fn send_rtcp_sender_report_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_rtcp_sender_report".to_string(),
        description: "Send a minimal RTCP Sender Report (RFC 3550 §6.4.1) to the caller."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "ssrc".to_string(),
                type_hint: "number".to_string(),
                description: "Sender SSRC. Omit for a random one.".to_string(),
                required: false,
            },
            Parameter {
                name: "rtp_timestamp".to_string(),
                type_hint: "number".to_string(),
                description: "RTP timestamp reported in the SR. Default 0.".to_string(),
                required: false,
            },
            Parameter {
                name: "packet_count".to_string(),
                type_hint: "number".to_string(),
                description: "Sender's cumulative packet count. Default 0.".to_string(),
                required: false,
            },
            Parameter {
                name: "octet_count".to_string(),
                type_hint: "number".to_string(),
                description: "Sender's cumulative payload octet count. Default 0.".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_rtcp_sender_report",
            "packet_count": 50,
            "octet_count": 8000
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("→ RTCP SR")
                .with_debug("RTP send_rtcp_sender_report packets={packet_count}"),
        ),
    }
}

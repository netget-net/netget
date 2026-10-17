//! RTSP protocol actions.
//!
//! RTSP framing (CSeq, Transport, Session, RTP-Info, port allocation) is owned by `mod.rs`. The
//! model shapes the DESCRIBE SDP, gates status codes, and — on PLAY — decides what the RTP stream
//! carries, described structurally and synthesized by the shared RTP media engine.

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

pub struct RtspProtocol;

impl RtspProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RtspProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for RtspProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Seconds a connected peer may send no request at all before the server \
                     closes it. Default 30: RTSP is client-speaks-first (RFC 2326 §10) and \
                     ffprobe, ffplay and VLC all send OPTIONS or DESCRIBE inside their open \
                     path, and there is no NetGet RTSP client that could sit connected and \
                     silent waiting for a person."
                        .to_string(),
                required: false,
                example: json!(30),
                default: Some(serde_json::json!(super::FIRST_BYTE_READ_TIMEOUT.as_secs())),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Seconds an established session may go without a further request before \
                     the server closes it, which also stops any PLAY stream on that session. \
                     Default 300 — five times the 60-second session timeout RFC 2326 §12.37 \
                     assumes when no `timeout=` is given, so a client keeping its own session \
                     alive is never caught by it."
                        .to_string(),
                required: false,
                example: json!(300),
                default: Some(serde_json::json!(
                    super::IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs()
                )),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            rtsp_options_response_action(),
            rtsp_describe_response_action(),
            rtsp_setup_response_action(),
            rtsp_play_response_action(),
            rtsp_teardown_response_action(),
            rtsp_generic_response_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "RTSP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            RTSP_OPTIONS_EVENT.clone(),
            RTSP_DESCRIBE_EVENT.clone(),
            RTSP_SETUP_EVENT.clone(),
            RTSP_PLAY_EVENT.clone(),
            RTSP_TEARDOWN_EVENT.clone(),
            RTSP_OTHER_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>RTSP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "rtsp",
            "real-time streaming",
            "rtsp control",
            "streaming setup",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder()
            .connectionless()
            // Answers on failure: 503 with Retry-After when overloaded, 500 otherwise.
            .answers_on_failure()
            .state(DevelopmentState::Beta)
            .well_known_port(554)
            .implementation(
                "Manual RFC 2326 control server over TCP; SETUP allocates a real RTP UDP socket and \
                 PLAY streams G.711 via the shared rtp media engine",
            )
            .llm_control(
                "DESCRIBE SDP, per-method status codes, and the content of the RTP stream started \
                 by PLAY (tone/DTMF/silence)",
            )
            .e2e_testing(
                "ffprobe (ffmpeg's libavformat, which shares no code with this repository) \
                 completes a real OPTIONS→DESCRIBE→SETUP→PLAY, reads RTP off the negotiated \
                 UDP port and reports pcm_mulaw/8000 Hz, in \
                 tests/server/rtsp/ffprobe_test.rs::ffprobe_reads_rtsp_stream. That test is \
                 NOT #[ignore]d and fails rather than skips when ffprobe is absent; until \
                 September 2026 it was #[ignore]d for \"run manually\", so it ran nowhere \
                 while this field cited it. Alongside it, byte-literal RTSP status and SDP \
                 assertions against a mock model, and a parser test for a complete request \
                 followed by non-UTF-8 bytes. Untested: TCP interleaved transport (not \
                 implemented), video, and any player other than ffmpeg.",
            )
            .notes(
                "TCP interleaved transport (RTP over the RTSP TCP channel) is NOT implemented — \
                 only UDP RTP via client_port/server_port. Only PCMU/PCMA audio streams; no video. \
                 Default port 8554 (unprivileged); pass port 554 explicitly if you have privilege.",
            )
            .max_inbound_bytes(crate::server::rtsp::MAX_REQUEST_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "RTSP control server that sets up and plays real RTP media streams"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an RTSP server on port 8554 that offers a PCMU audio stream and plays a 440 Hz tone on PLAY."
    }
    fn group_name(&self) -> &'static str {
        "Proxy & Network"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: answer DESCRIBE with a fixed audio SDP, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "rtsp_describe":
    actions = [{"type": "rtsp_describe_response",
                "sdp": "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=NetGet Stream\r\nt=0 0\r\nm=audio 0 RTP/AVP 0\r\n"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 8554,
                "base_stack": "rtsp",
                "instruction": "RTSP media server. On DESCRIBE return SDP for one PCMU audio stream. On PLAY, stream a 440 Hz tone for 5 seconds."
            }),
            json!({
                "type": "open_server",
                "port": 8554,
                "base_stack": "rtsp",
                "event_handlers": [{
                    "event_pattern": "rtsp_describe",
                    "handler": {"type": "script", "language": "python", "code": script}
                }]
            }),
            json!({
                "type": "open_server",
                "port": 8554,
                "base_stack": "rtsp",
                "event_handlers": [{
                    "event_pattern": "rtsp_play",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "rtsp_play_response",
                            "status_code": 200,
                            "payload_type": "pcmu",
                            "content": "tone",
                            "tone_hz": 440,
                            "duration_ms": 5000
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for RtspProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::rtsp::RtspServer;

            // Both read deadlines are the operator's to choose: who is on the other end is
            // the only thing that decides them, and only the operator knows that.
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let first_byte_timeout_secs = secs("first_byte_timeout_secs")?;
            let idle_timeout_secs = secs("idle_timeout_secs")?;

            RtspServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                first_byte_timeout_secs,
                idle_timeout_secs,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        // RTSP framing and RTP streaming happen in mod.rs from the raw action; here we only
        // validate the action is recognized so a typo is reported.
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;
        match action_type {
            "rtsp_options_response"
            | "rtsp_describe_response"
            | "rtsp_setup_response"
            | "rtsp_teardown_response"
            | "rtsp_generic_response" => Ok(ActionResult::NoAction),
            "rtsp_play_response" => {
                // Validate media description early for a clean error.
                if action.get("content").is_some() || action.get("tone_hz").is_some() {
                    crate::server::rtp::media::parse_audio_content(&action)?;
                }
                Ok(ActionResult::NoAction)
            }
            // The dashboard's "disconnect this peer" injects this; the generic peer task
            // half-closes the write side on CloseConnection and the reader sees EOF.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown RTSP action: {}", action_type)),
        }
    }
}

pub static RTSP_OPTIONS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rtsp_options",
        "A client sent OPTIONS to discover supported methods. Answer with rtsp_options_response; \
         omit public_methods to advertise the default set.",
        json!({"type": "rtsp_options_response", "public_methods": ["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"]}),
    )
    .with_actions(vec![rtsp_options_response_action()])
    .with_log_template(LogTemplate::new().with_info("RTSP OPTIONS").with_trace("RTSP: {json_pretty(.)}"))
});

pub static RTSP_DESCRIBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rtsp_describe",
        "A client sent DESCRIBE to learn the stream layout. Answer with rtsp_describe_response \
         carrying the SDP that describes the media (an audio m-line with a PCMU/PCMA rtpmap).",
        json!({
            "type": "rtsp_describe_response",
            "sdp": "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=NetGet Stream\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=control:streamid=0\r\n"
        }),
    )
    .with_actions(vec![rtsp_describe_response_action()])
    .with_log_template(LogTemplate::new().with_info("RTSP DESCRIBE").with_trace("RTSP: {json_pretty(.)}"))
});

pub static RTSP_SETUP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rtsp_setup",
        "A client sent SETUP to establish transport. The server allocates the RTP socket and \
         echoes Transport/Session itself; answer with rtsp_setup_response only to override the \
         status code (default 200).",
        json!({"type": "rtsp_setup_response", "status_code": 200}),
    )
    .with_actions(vec![rtsp_setup_response_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("RTSP SETUP")
            .with_trace("RTSP: {json_pretty(.)}"),
    )
});

pub static RTSP_PLAY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rtsp_play",
        "A client sent PLAY. Answer with rtsp_play_response describing what the RTP stream should \
         carry (tone/DTMF/silence); the server synthesizes G.711 and sends it to the negotiated \
         client RTP port.",
        json!({
            "type": "rtsp_play_response",
            "payload_type": "pcmu",
            "content": "tone",
            "tone_hz": 440,
            "duration_ms": 5000
        }),
    )
    .with_actions(vec![rtsp_play_response_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("RTSP PLAY")
            .with_trace("RTSP: {json_pretty(.)}"),
    )
});

pub static RTSP_TEARDOWN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rtsp_teardown",
        "A client sent TEARDOWN to end the session. Answer with rtsp_teardown_response; the server \
         stops any running stream.",
        json!({"type": "rtsp_teardown_response", "status_code": 200}),
    )
    .with_actions(vec![rtsp_teardown_response_action()])
    .with_log_template(LogTemplate::new().with_info("RTSP TEARDOWN").with_trace("RTSP: {json_pretty(.)}"))
});

pub static RTSP_OTHER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rtsp_other",
        "A client sent an RTSP method this server does not specially handle (PAUSE, ANNOUNCE, \
         GET_PARAMETER, …). Answer with rtsp_generic_response and a status code.",
        json!({"type": "rtsp_generic_response", "status_code": 501}),
    )
    .with_actions(vec![rtsp_generic_response_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("RTSP {method}")
            .with_trace("RTSP: {json_pretty(.)}"),
    )
});

fn status_param(default: &'static str) -> Parameter {
    Parameter {
        name: "status_code".to_string(),
        type_hint: "number".to_string(),
        description: format!("RTSP status code (default {})", default),
        required: false,
    }
}

fn rtsp_options_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "rtsp_options_response".to_string(),
        description: "Respond to RTSP OPTIONS.".to_string(),
        parameters: vec![
            status_param("200"),
            Parameter {
                name: "public_methods".to_string(),
                type_hint: "array".to_string(),
                description: "Methods to advertise in the Public header.".to_string(),
                required: false,
            },
        ],
        example: json!({"type": "rtsp_options_response", "public_methods": ["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"]}),
        log_template: Some(LogTemplate::new().with_info("→ RTSP {status_code} OPTIONS")),
    }
}

fn rtsp_describe_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "rtsp_describe_response".to_string(),
        description: "Respond to RTSP DESCRIBE with an SDP session description.".to_string(),
        parameters: vec![
            status_param("200"),
            Parameter {
                name: "sdp".to_string(),
                type_hint: "string".to_string(),
                description: "SDP body describing the media (audio m-line + PCMU/PCMA rtpmap). \
                              Structured text, never bytes."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "rtsp_describe_response",
            "sdp": "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=NetGet Stream\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=control:streamid=0\r\n"
        }),
        log_template: Some(LogTemplate::new().with_info("→ RTSP {status_code} DESCRIBE")),
    }
}

fn rtsp_setup_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "rtsp_setup_response".to_string(),
        description: "Gate the status code of an RTSP SETUP. Transport/Session are framed by the \
                      server."
            .to_string(),
        parameters: vec![status_param("200")],
        example: json!({"type": "rtsp_setup_response", "status_code": 200}),
        log_template: Some(LogTemplate::new().with_info("→ RTSP {status_code} SETUP")),
    }
}

fn rtsp_play_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "rtsp_play_response".to_string(),
        description:
            "Respond to RTSP PLAY and describe the RTP stream to start (tone/DTMF/silence)."
                .to_string(),
        parameters: vec![
            status_param("200"),
            Parameter {
                name: "payload_type".to_string(),
                type_hint: "string".to_string(),
                description: "\"pcmu\" (default) or \"pcma\".".to_string(),
                required: false,
            },
            Parameter {
                name: "content".to_string(),
                type_hint: "string".to_string(),
                description: "\"tone\" (default), \"dtmf\", or \"silence\".".to_string(),
                required: false,
            },
            Parameter {
                name: "tone_hz".to_string(),
                type_hint: "number".to_string(),
                description: "Tone frequency in Hz when content=tone. Default 440.".to_string(),
                required: false,
            },
            Parameter {
                name: "digits".to_string(),
                type_hint: "string".to_string(),
                description: "DTMF digits when content=dtmf.".to_string(),
                required: false,
            },
            Parameter {
                name: "duration_ms".to_string(),
                type_hint: "number".to_string(),
                description: "Stream length in milliseconds (1-30000). Default 5000.".to_string(),
                required: false,
            },
            Parameter {
                name: "ssrc".to_string(),
                type_hint: "number".to_string(),
                description: "RTP SSRC. Omit for a random one.".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "rtsp_play_response",
            "status_code": 200,
            "payload_type": "pcmu",
            "content": "tone",
            "tone_hz": 440,
            "duration_ms": 5000
        }),
        log_template: Some(LogTemplate::new().with_info("→ RTSP {status_code} PLAY {content}")),
    }
}

fn rtsp_teardown_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "rtsp_teardown_response".to_string(),
        description: "Respond to RTSP TEARDOWN.".to_string(),
        parameters: vec![status_param("200")],
        example: json!({"type": "rtsp_teardown_response", "status_code": 200}),
        log_template: Some(LogTemplate::new().with_info("→ RTSP {status_code} TEARDOWN")),
    }
}

fn rtsp_generic_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "rtsp_generic_response".to_string(),
        description: "Respond to any other RTSP method with a status code.".to_string(),
        parameters: vec![status_param("501")],
        example: json!({"type": "rtsp_generic_response", "status_code": 501}),
        log_template: Some(LogTemplate::new().with_info("→ RTSP {status_code}")),
    }
}

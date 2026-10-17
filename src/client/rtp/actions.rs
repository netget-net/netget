//! What the model does as an RTP endpoint: stream synthesized G.711 audio to the remote
//! (described, never sampled), report as a sender over RTCP, and hear about the streams that
//! arrive — one event when a stream starts and one when it ends, never one per packet.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::rtp::actions::{send_rtcp_sender_report_action, send_rtp_audio_action};
use crate::server::rtp::media;
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const SEND_AUDIO: &str = "send_rtp_audio";
pub const SEND_SR: &str = "send_rtcp_sender_report";
/// Where the endpoint receives when nowhere is named.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:0";

#[derive(Default)]
pub struct RtpClientProtocol;
impl RtpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn p(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    let mut audio = send_rtp_audio_action();
    audio.description = "Stream synthesized G.711 audio to the remote as paced 20 ms RTP packets (one stream at a time; a new one replaces it). Describe the content; Rust owns the samples and the framing.".into();
    let mut sr = send_rtcp_sender_report_action();
    sr.description = "Send the remote a minimal RTCP Sender Report (RFC 3550 §6.4.1).".into();
    vec![
        audio,
        sr,
        ActionDefinition {
            name: "disconnect".into(),
            description: "Stop: any stream being sent stops and the socket closes.".into(),
            parameters: vec![],
            example: json!({"type": "disconnect"}),
            log_template: Some(
                crate::protocol::log_template::LogTemplate::new().with_info("-> RTP disconnect"),
            ),
        },
    ]
}

fn event(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, json!({"type": SEND_AUDIO, "payload_type": "pcmu", "content": "tone", "tone_hz": 440, "duration_ms": 1000}))
        .with_parameters(params)
        .with_actions(actions())
}

pub static READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "rtp_ready",
        "The endpoint is bound; nothing is sent until an action asks.",
        vec![
            p(
                "local_addr",
                "string",
                "Where this endpoint receives RTP",
                true,
            ),
            p("remote_addr", "string", "Where it sends RTP", true),
        ],
    )
});

pub static STREAM_STARTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "rtp_stream_started",
        "A new RTP stream (a new SSRC) began arriving.",
        vec![
            p(
                "ssrc",
                "number",
                "The stream's synchronisation source",
                true,
            ),
            p("payload_type", "number", "Its RTP payload type", true),
            p(
                "codec",
                "string",
                "pcmu or pcma when it is G.711, otherwise unknown",
                true,
            ),
            p("from", "string", "The sender's address and port", true),
        ],
    )
});

pub static STREAM_ENDED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("rtp_stream_ended", "A stream stopped (nothing for a second): what arrived, and for G.711 what it sounded like.", vec![
        p("ssrc", "number", "The stream's synchronisation source", true),
        p("packets", "number", "Packets received", true),
        p("lost", "number", "Packets missing from the sequence numbers", true),
        p("octets", "number", "Payload bytes received", true),
        p("duration_ms", "number", "Media length by RTP timestamps at 8 kHz", true),
        p("tone_hz", "number", "For G.711: the dominant frequency of the decoded audio, estimated from zero crossings", false),
        p("level_dbfs", "number", "For G.711: the decoded audio's RMS level in dBFS", false),
    ])
});

pub static SENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "rtp_sent",
        "A stream this endpoint was sending finished (or was replaced).",
        vec![
            p("ssrc", "number", "The SSRC it was sent with", true),
            p(
                "packets",
                "number",
                "How many RTP packets went out, one per 20 ms frame",
                true,
            ),
            p(
                "duration_ms",
                "number",
                "How much audio went out, in milliseconds",
                true,
            ),
            p(
                "complete",
                "boolean",
                "False when a newer stream or a disconnect cut it short",
                true,
            ),
        ],
    )
});

pub static RTCP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "rtcp_received",
        "An RTCP packet arrived (sender or receiver report, BYE, …).",
        vec![
            p(
                "packet_type",
                "number",
                "200 SR, 201 RR, 202 SDES, 203 BYE, 204 APP",
                true,
            ),
            p("ssrc", "number", "The reporting source", true),
            p("from", "string", "The sender's address and port", true),
        ],
    )
});

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        SEND_AUDIO => {
            let codec = v
                .get("payload_type")
                .and_then(Value::as_str)
                .map(media::AudioCodec::parse)
                .unwrap_or(Ok(media::AudioCodec::Pcmu))?;
            let content = media::parse_audio_content(v)?;
            media::synthesize(codec, &content, v["duration_ms"].as_u64().unwrap_or(1000))?;
            Ok(())
        }
        SEND_SR => Ok(()),
        other => bail!("Unknown RTP client action {other:?}"),
    }
}

impl Protocol for RtpClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "RTP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>RTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "rtp client",
            "rtp sender",
            "rtp",
            "voip audio",
            "real-time transport",
        ]
    }
    fn description(&self) -> &'static str {
        "RTP endpoint that streams synthesized G.711 to a remote and reports the streams it receives"
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
            STREAM_STARTED_EVENT.clone(),
            STREAM_ENDED_EVENT.clone(),
            SENT_EVENT.clone(),
            RTCP_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "listen".into(),
            type_hint: "string".into(),
            description: "Address this endpoint receives RTP on (the remote sends media here)"
                .into(),
            required: false,
            example: json!("0.0.0.0:40002"),
            default: Some(json!(DEFAULT_LISTEN)),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Tokio UDP with the RTP server's synthesis and packetizer (G.711 PCMU/PCMA, 20 ms frames paced in real time); inbound RTP tracked per SSRC (loss from sequence numbers, length from timestamps) and G.711 decoded to estimate tone and level; RTCP Sender Reports")
            .llm_control("What audio to send and when, and what to do about the streams that arrive")
            .e2e_testing("tests/client/rtp: ffmpeg receives NetGet's stream through an SDP and decodes it (its tone measured in the WAV it writes), and ffmpeg's own RTP muxer streams a sine to NetGet, whose decoded tone and packet accounting are asserted")
            .notes("Audio only, G.711 only; no SRTP, no jitter buffer, no receiver reports. Inbound streams are summarised, never reported per packet.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Send a 440 Hz tone for two seconds to the RTP endpoint at 127.0.0.1:40000"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"rtp","remote_addr":"127.0.0.1:40000",
            "instruction":"Send a 440 Hz PCMU tone for two seconds, then report what comes back"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"rtp_ready","handler":{"type":"static","actions":[{"type":SEND_AUDIO,"content":"tone","tone_hz":440,"duration_ms":2000}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']\na=[{'type':'send_rtp_audio','content':'dtmf','digits':'123#'}] if t=='rtp_ready' else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Proxy & Network"
    }
}

impl Client for RtpClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        if name == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}

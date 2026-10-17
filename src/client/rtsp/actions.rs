//! What the model does as an RTSP client: ask a media server what it has (OPTIONS, DESCRIBE),
//! set a track up over UDP, play, pause and tear down — and hear about the media that arrives,
//! summarised per stream. Rust owns CSeq, sessions, transports and the RTP ports.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const OPTIONS: &str = "rtsp_options";
pub const DESCRIBE: &str = "rtsp_describe";
pub const SETUP: &str = "rtsp_setup";
pub const PLAY: &str = "rtsp_play";
pub const PAUSE: &str = "rtsp_pause";
pub const TEARDOWN: &str = "rtsp_teardown";

#[derive(Default)]
pub struct RtspClientProtocol;
impl RtspClientProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("-> RTSP {name}"))),
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(OPTIONS, "Ask the server which methods it supports (OPTIONS).", vec![], json!({"type": OPTIONS})),
        action(DESCRIBE, "Ask for the stream's description (DESCRIBE); the SDP comes back parsed.", vec![], json!({"type": DESCRIBE})),
        action(SETUP, "Set a track up over UDP (SETUP). Rust binds the RTP/RTCP ports and keeps the session.",
            vec![p("track", "string", "The track's control URL from the DESCRIBE answer (absolute or relative); default the first audio or video track", false)],
            json!({"type": SETUP})),
        action(PLAY, "Start the media of the session (PLAY); what arrives is summarised per stream.",
            vec![p("range", "string", "An RTSP Range, e.g. npt=0- (default none)", false)], json!({"type": PLAY})),
        action(PAUSE, "Pause the session's media (PAUSE).", vec![], json!({"type": PAUSE})),
        action(TEARDOWN, "End the session (TEARDOWN); its RTP ports close.", vec![], json!({"type": TEARDOWN})),
        action("disconnect", "Close the RTSP connection.", vec![], json!({"type": "disconnect"})),
    ]
}

fn event(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, json!({"type": DESCRIBE}))
        .with_parameters(params)
        .with_actions(actions())
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "rtsp_connected",
        "Connected to the RTSP server.",
        vec![p(
            "url",
            "string",
            "The stream URL requests are made for",
            true,
        )],
    )
});

pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("rtsp_response", "The server answered a request.", vec![
        p("method", "string", "The request answered, e.g. DESCRIBE", true),
        p("status", "number", "RTSP status code, e.g. 200 or 404", true),
        p("reason", "string", "The status line's reason phrase", true),
        p("headers", "object", "Public, Content-Base, Session, Transport, RTP-Info and Range when present", true),
        p("sdp", "object", "For DESCRIBE: {media: [{type, port, protocol, formats, rtpmap, control}], control}", false),
        p("error", "string", "Why the request failed before an answer", false),
    ])
});

pub static STREAM_STARTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "rtsp_stream_started",
        "RTP began arriving on a set-up track.",
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
            p("from", "string", "The server's RTP address", true),
        ],
    )
});

pub static STREAM_ENDED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("rtsp_stream_ended", "A stream stopped (nothing for a second): what arrived, and for G.711 what it sounded like.", vec![
        p("ssrc", "number", "The stream's synchronisation source", true),
        p("packets", "number", "RTP packets received", true),
        p("lost", "number", "Packets missing from the sequence numbers", true),
        p("octets", "number", "Payload bytes received", true),
        p("duration_ms", "number", "Media length by RTP timestamps at 8 kHz", true),
        p("tone_hz", "number", "For G.711: the dominant frequency of the decoded audio", false),
        p("level_dbfs", "number", "For G.711: the decoded audio's RMS level in dBFS", false),
    ])
});

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        OPTIONS | DESCRIBE | PAUSE | TEARDOWN => {}
        SETUP => {
            if let Some(t) = v.get("track").filter(|x| !x.is_null()) {
                let t = t.as_str().unwrap_or_default();
                ensure!(
                    !t.is_empty() && t.len() <= 1024 && !t.contains(['\r', '\n', ' ']),
                    "track is a control URL"
                );
            }
        }
        PLAY => {
            if let Some(r) = v.get("range").filter(|x| !x.is_null()) {
                let r = r.as_str().unwrap_or_default();
                ensure!(
                    r.len() <= 128 && !r.contains(['\r', '\n']),
                    "range is an RTSP Range value"
                );
            }
        }
        other => bail!("Unknown RTSP client action {other:?}"),
    }
    Ok(())
}

impl Protocol for RtspClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "RTSP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>RTSP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "rtsp client",
            "rtsp",
            "rtsp player",
            "ip camera",
            "streaming client",
        ]
    }
    fn description(&self) -> &'static str {
        "RTSP client: describes, sets up and plays streams from a media server and reports the media that arrives"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            RESPONSE_EVENT.clone(),
            STREAM_STARTED_EVENT.clone(),
            STREAM_ENDED_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("RTSP/1.0 over Tokio TCP (CSeq, Session, Content-Base and Transport handled in Rust), SDP parsed for the model, UDP RTP/RTCP port pairs bound per SETUP, and the RTP client's per-stream tracker (loss, length, decoded G.711 tone and level)")
            .llm_control("Which requests to make in which order, which track to set up, and what to do with the media that arrives")
            .e2e_testing("tests/client/rtsp: mediamtx 1.9.3 serving a G.711 stream that ffmpeg publishes into it; NetGet describes, sets up, plays and tears down, and the tone it decodes is asserted")
            .notes("UDP transport only (no TCP interleaving), no authentication, no RTSP 2.0, no requests from the server. A handler chain stops after 8 follow-ups.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Open rtsp://127.0.0.1:8554/cam, describe it, play its audio for a few seconds and tell me what it sounds like"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"rtsp","remote_addr":"rtsp://127.0.0.1:8554/cam",
            "instruction":"Describe the stream, set up its first track and play it"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"rtsp_connected","handler":{"type":"static","actions":[{"type":DESCRIBE}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\nnext={'DESCRIBE':'rtsp_setup','SETUP':'rtsp_play'}\na=[{'type':'rtsp_describe'}] if t=='rtsp_connected' else ([{'type':next[e['method']]}] if t=='rtsp_response' and e['status']==200 and e['method'] in next else [])\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Proxy & Network"
    }
}

impl Client for RtspClientProtocol {
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

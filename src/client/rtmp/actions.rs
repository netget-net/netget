use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::rtmp::actions::{action, parameter};
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct RtmpClientProtocol;
impl RtmpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn play() -> ActionDefinition {
    action(
        "rtmp_play",
        "Play a stream for a while and report what arrived: status codes, metadata, codecs, message and keyframe counts, timestamps and data messages",
        vec![
            parameter("stream", "string", "Stream name in the connected app, e.g. cam1", true),
            parameter("seconds", "number", "How long to watch, 1 to 60 (default 5)", false),
        ],
        json!({"type": "rtmp_play", "stream": "cam1", "seconds": 5}),
    )
}
fn publish() -> ActionDefinition {
    action(
        "rtmp_publish",
        "Publish an FLV file the operator supplied as a live stream, its tags paced by their timestamps, then unpublish and report",
        vec![
            parameter("stream", "string", "Stream name (often a stream key) to publish as", true),
            parameter("flv_file", "string", "Path of an FLV file under the client's media_root directory (64 MiB at most); a relative path is resolved against that directory, and nothing outside it is read", true),
            parameter("realtime", "boolean", "Pace tags by their timestamps (default true); false sends as fast as possible", false),
        ],
        json!({"type": "rtmp_publish", "stream": "abc123", "flv_file": "clip.flv"}),
    )
}
fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Close the connection",
        vec![],
        json!({"type": "disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![play(), publish(), disconnect()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rtmp_connected",
        "The server accepted connect for the application",
        play().example.clone(),
    )
    .with_parameters(vec![
        parameter("app", "string", "The application connected to", true),
        parameter(
            "server",
            "object",
            "The server's properties from _result (fmsVer, capabilities)",
            true,
        ),
    ])
    .with_actions(actions())
});
pub static REPORT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rtmp_report",
        "What a play or publish did",
        disconnect().example.clone(),
    )
    .with_parameters(vec![
        parameter("operation", "string", "play or publish", true),
        parameter(
            "stream",
            "string",
            "The stream name that was played or published",
            true,
        ),
        parameter(
            "status_codes",
            "array",
            "onStatus codes the server sent, e.g. NetStream.Play.Start",
            true,
        ),
        parameter(
            "video_messages",
            "number",
            "Video messages received (play) or sent (publish)",
            true,
        ),
        parameter(
            "audio_messages",
            "number",
            "Audio messages received or sent",
            true,
        ),
        parameter("keyframes", "number", "Video keyframes", true),
        parameter(
            "video_codec",
            "string",
            "avc, hevc, av1, vp9 or the FLV codec ID",
            false,
        ),
        parameter(
            "audio_codec",
            "string",
            "aac, mp3 or the FLV sound format",
            false,
        ),
        parameter(
            "metadata",
            "object",
            "onMetaData received or published",
            false,
        ),
        parameter(
            "first_timestamp",
            "number",
            "First media timestamp, ms",
            false,
        ),
        parameter(
            "last_timestamp",
            "number",
            "Last media timestamp, ms",
            false,
        ),
        parameter(
            "data_messages",
            "array",
            "Other data messages received: [{handler, data}]",
            false,
        ),
    ])
    .with_actions(actions())
});

impl Protocol for RtmpClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "RTMP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>RTMP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["rtmp", "live streaming", "play", "publish", "ingest"]
    }
    fn description(&self) -> &'static str {
        "RTMP client: connects to an application, plays streams and reports what arrives, publishes FLV files live"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), REPORT_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "app".into(),
                type_hint: "string".into(),
                description: "Application to connect to, e.g. live".into(),
                required: false,
                example: json!("live"),
                default: Some(json!(super::DEFAULT_APP)),
            },
            ParameterDefinition {
                name: crate::client::media_root::MEDIA_ROOT_PARAM.into(),
                type_hint: "string".into(),
                description: "Directory rtmp_publish may read FLV files from; nothing outside it is sent. Defaults to NetGet's own media directory under the platform's local-data dir.".into(),
                required: false,
                example: json!("/var/lib/netget/media"),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's handshake, chunk and AMF0 code as a client; FLV demuxing for publish")
            .llm_control("Which streams to play or publish and when")
            .e2e_testing("tests/client/rtmp: MediaMTX (independent Go RTMP) serves a stream FFmpeg publishes, which the client plays; the client publishes an FLV that MediaMTX reports with its tracks")
            .notes("AMF0 only, no RTMPS, simple handshake; publishes FLV files only.")
            .max_inbound_bytes(crate::server::rtmp::chunk::MAX_MESSAGE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to rtmp://127.0.0.1:1935/live and watch stream cam1 for five seconds"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"rtmp","remote_addr":"127.0.0.1:1935","instruction":"Watch cam1 for five seconds","startup_params":{"app":"live"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"rtmp_connected","handler":{"type":"static","actions":[play().example]}},
            {"event_pattern":"rtmp_report","handler":{"type":"static","actions":[{"type":"disconnect"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'disconnect'}] if e['video_messages']>0 else [{'type':'rtmp_play','stream':e['stream'],'seconds':5}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Real-time"
    }
}

fn name_ok(s: Option<&str>) -> bool {
    s.is_some_and(|s| !s.is_empty() && s.len() <= 256 && !crate::utils::sanitize::has_controls(&s))
}

impl Client for RtmpClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("rtmp_play") => {
                ensure!(name_ok(v["stream"].as_str()), "stream is a name");
                if let Some(s) = v.get("seconds").filter(|s| !s.is_null()) {
                    ensure!(
                        s.as_f64().is_some_and(|s| (1.0..=60.0).contains(&s)),
                        "seconds is 1 to 60"
                    );
                }
            }
            Some("rtmp_publish") => {
                ensure!(name_ok(v["stream"].as_str()), "stream is a name");
                ensure!(name_ok(v["flv_file"].as_str()), "flv_file is a path");
            }
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown RTMP client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

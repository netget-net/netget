use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct RtmpProtocol;
impl RtmpProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn parameter(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}

pub fn action(
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
        log_template: Some(LogTemplate::new().with_info(format!("-> RTMP {name}"))),
    }
}

fn accept() -> ActionDefinition {
    action("rtmp_accept", "Allow it: Rust answers with the NetConnection / NetStream success status and starts relaying", vec![], json!({"type": "rtmp_accept"}))
}
fn reject() -> ActionDefinition {
    action(
        "rtmp_reject",
        "Refuse it: Rust answers NetConnection.Connect.Rejected, NetStream.Publish.Denied or NetStream.Play.StreamNotFound with this description",
        vec![parameter("description", "string", "Why, as the status description the client shows, up to 256 characters", true)],
        json!({"type": "rtmp_reject", "description": "stream key not recognised"}),
    )
}
fn ignore() -> ActionDefinition {
    action(
        "rtmp_ignore",
        "Acknowledge the report; nothing is sent to anyone",
        vec![],
        json!({"type": "rtmp_ignore"}),
    )
}
pub fn send_data() -> ActionDefinition {
    action(
        "rtmp_send_data",
        "Send an AMF0 data message into the stream: from a publisher's connection to every player of its stream, from a player's connection to that player (e.g. onTextData for captions, onCuePoint for markers)",
        vec![
            parameter("handler", "string", "The data handler name, e.g. onTextData or onCuePoint", true),
            parameter("data", "object", "The handler's argument as a JSON object, e.g. {\"text\": \"Hello\"}", true),
        ],
        json!({"type": "rtmp_send_data", "handler": "onTextData", "data": {"text": "Live in five"}}),
    )
}

pub static CONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rtmp_connect",
        "A client completed the handshake and sends connect for an application",
        accept().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "app",
            "string",
            "Application name from the connect command (e.g. live)",
            true,
        ),
        parameter(
            "tc_url",
            "string",
            "tcUrl the client used, e.g. rtmp://host/live",
            false,
        ),
        parameter(
            "flash_ver",
            "string",
            "flashVer the client announced (e.g. FMLE/3.0 or LNX 9,0,124,2)",
            false,
        ),
    ])
    .with_actions(vec![accept(), reject()])
});
pub static PUBLISH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rtmp_publish",
        "A client wants to publish a live stream (the stream name is often a stream key)",
        accept().example.clone(),
    )
    .with_parameters(vec![
        parameter("app", "string", "The connection's application", true),
        parameter(
            "stream",
            "string",
            "Stream name to publish, without query string handling",
            true,
        ),
        parameter(
            "type",
            "string",
            "Publishing type from the command: live, record or append",
            true,
        ),
    ])
    .with_actions(vec![accept(), reject()])
});
pub static PLAY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("rtmp_play", "A client wants to play a stream; if nobody publishes it yet, the player waits for the publisher", accept().example.clone())
        .with_parameters(vec![
            parameter("app", "string", "The connection's application", true),
            parameter("stream", "string", "Stream name to play", true),
            parameter("live", "boolean", "Whether someone is publishing it right now", true),
        ])
        .with_actions(vec![accept(), reject()])
});
pub static PUBLISH_ENDED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rtmp_publish_ended",
        "A publisher stopped; what it sent",
        ignore().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "app",
            "string",
            "The application the stream was published in, e.g. live",
            true,
        ),
        parameter(
            "stream",
            "string",
            "The stream name (often a stream key) that was published",
            true,
        ),
        parameter("duration_ms", "number", "How long it published", true),
        parameter("video_messages", "number", "Video messages received", true),
        parameter("audio_messages", "number", "Audio messages received", true),
        parameter("keyframes", "number", "Video keyframes received", true),
        parameter(
            "media_bytes",
            "number",
            "Audio and video payload bytes",
            true,
        ),
        parameter("players", "number", "Players attached when it ended", true),
    ])
    .with_actions(vec![ignore()])
});

pub fn check_answer(v: &Value) -> Result<()> {
    ensure!(
        crate::utils::json_budget::within_budget(v, 256 * 1024, 10_000, 16),
        "answer exceeds the RTMP bounds"
    );
    match v["type"].as_str() {
        Some("rtmp_accept" | "rtmp_ignore") => {}
        Some("rtmp_reject") => ensure!(
            v["description"].as_str().is_some_and(|d| !d.is_empty()
                && d.len() <= 256
                && !crate::utils::sanitize::has_controls(&d)),
            "description is 1 to 256 printable characters"
        ),
        Some("rtmp_send_data") => {
            ensure!(
                v["handler"].as_str().is_some_and(|h| !h.is_empty()
                    && h.len() <= 64
                    && h.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'|' || b == b'@')),
                "handler is a name like onTextData"
            );
            ensure!(v["data"].is_object(), "data is a JSON object");
        }
        _ => bail!("Unknown RTMP server action"),
    }
    Ok(())
}

fn startup(
    name: &str,
    kind: &str,
    description: &str,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required: false,
        example,
        default,
    }
}

impl Protocol for RtmpProtocol {
    fn protocol_name(&self) -> &'static str {
        "RTMP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>RTMP"
    }
    fn description(&self) -> &'static str {
        "RTMP live server: publishers push streams, players pull them; the handler admits each and can inject data messages"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "rtmp",
            "flash",
            "live streaming",
            "obs",
            "ffmpeg",
            "publish",
            "ingest",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![send_data()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![accept(), reject(), ignore()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECT_EVENT.clone(),
            PUBLISH_EVENT.clone(),
            PLAY_EVENT.clone(),
            PUBLISH_ENDED_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![startup("idle_timeout_secs", "integer", "Seconds a connection may send nothing before it is closed (players receiving media are kept)", json!(30), Some(json!(super::IDLE_TIMEOUT.as_secs())))]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(1935)
            .implementation("Hand-written RTMP: simple handshake, chunk streams (all header formats, extended timestamps, chunk size, acknowledgements), AMF0 commands, NetConnection/NetStream flow, live relay with cached metadata and sequence headers, keyframe join and per-player timestamp rebasing")
            .llm_control("Which applications, publishers (stream keys) and players are admitted, and data messages pushed into streams")
            .e2e_testing("tests/server/rtmp: FFmpeg (independent) publishes H.264/AAC and plays it back decoding frames; MediaMTX (independent Go RTMP) pulls the stream and reports its tracks; refused apps and stream keys")
            .notes("Live only (no recording or VOD), AMF0 only, no RTMPS/RTMPT, no complex (digest) handshake, no enhanced-RTMP multitrack. Media is relayed, never stored.")
            .answers_on_failure()
            .max_inbound_bytes(super::chunk::MAX_MESSAGE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "RTMP ingest on port 1935 that accepts the stream key abc123 on app live and lets anyone watch"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"rtmp","port":1935,"instruction":"Accept app live; only stream key abc123 may publish; anyone may play"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"static","actions":[{"type":"rtmp_accept"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([
            {"event_pattern":"rtmp_publish","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'rtmp_accept'} if e['stream']=='abc123' else {'type':'rtmp_reject','description':'bad stream key'}]}))"}},
            {"event_pattern":"*","handler":{"type":"static","actions":[{"type":"rtmp_accept"}]}}
        ]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Real-time"
    }
}

impl Server for RtmpProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        check_answer(&v)?;
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

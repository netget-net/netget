use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::srt::actions::{action, parameter};
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct SrtClientProtocol;
impl SrtClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn receive() -> ActionDefinition {
    action(
        "srt_receive",
        "Read what the listener sends for a while and report it: messages, bytes, MPEG-TS packets with their PIDs and stream types, text messages, and SRT loss and retransmission statistics",
        vec![parameter("seconds", "number", "How long to read, 1 to 60 (default 5)", false)],
        json!({"type": "srt_receive", "seconds": 5}),
    )
}
fn send_file() -> ActionDefinition {
    action(
        "srt_send_file",
        "Send an MPEG-TS file the operator supplied, 7 TS packets (1316 bytes) per SRT message, paced at a bitrate",
        vec![
            parameter("path", "string", "Path of a .ts file under the client's media_root directory (64 MiB at most); a relative path is resolved against that directory, and nothing outside it is read", true),
            parameter("bitrate_kbps", "number", "Pacing bitrate in kbit/s, 100 to 50000 (default 2000)", false),
        ],
        json!({"type": "srt_send_file", "path": "clip.ts", "bitrate_kbps": 2000}),
    )
}
fn send_text() -> ActionDefinition {
    action(
        "srt_send_text",
        "Send a UTF-8 text message as one SRT message",
        vec![parameter(
            "text",
            "string",
            "The message, up to 1316 bytes",
            true,
        )],
        json!({"type": "srt_send_text", "text": "hello"}),
    )
}
fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Close the SRT connection",
        vec![],
        json!({"type": "disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![receive(), send_file(), send_text(), disconnect()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "srt_connected",
        "The listener accepted the connection",
        receive().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "stream_id",
            "string",
            "The stream ID this client sent",
            true,
        ),
        parameter(
            "latency_ms",
            "number",
            "The negotiated receive latency",
            true,
        ),
    ])
    .with_actions(actions())
});
pub static REPORT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "srt_report",
        "What a receive or send did",
        disconnect().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "operation",
            "string",
            "receive, send_file or send_text",
            true,
        ),
        parameter("messages", "number", "SRT messages received or sent", true),
        parameter("bytes", "number", "Payload bytes received or sent", true),
        parameter(
            "ts_packets",
            "number",
            "MPEG-TS packets (188 bytes, sync byte 0x47) among them",
            false,
        ),
        parameter("pids", "array", "MPEG-TS PIDs seen", false),
        parameter(
            "stream_types",
            "array",
            "Elementary stream types from the PMT: h264, hevc, aac, mp3 or the hex code",
            false,
        ),
        parameter("texts", "array", "Text messages received (up to 20)", false),
        parameter(
            "statistics",
            "object",
            "SRT statistics: packets, bytes, lost, retransmitted, dropped, RTT",
            true,
        ),
    ])
    .with_actions(actions())
});

impl Protocol for SrtClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "SRT"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>SRT"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["srt", "secure reliable transport", "caller", "mpeg-ts"]
    }
    fn description(&self) -> &'static str {
        "SRT caller: connects with a stream ID, reads and reports a stream, or sends an MPEG-TS file or text"
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
        let p =
            |name: &str, kind: &str, description: &str, example: Value, default: Option<Value>| {
                ParameterDefinition {
                    name: name.into(),
                    type_hint: kind.into(),
                    description: description.into(),
                    required: false,
                    example,
                    default,
                }
            };
        vec![
            p(
                "stream_id",
                "string",
                "Stream ID to send, e.g. #!::r=live/cam,m=request or publish:live/cam",
                json!("#!::r=live/cam,m=publish"),
                None,
            ),
            p(
                "latency_ms",
                "integer",
                "SRT latency in milliseconds, 20 to 8000",
                json!(200),
                Some(json!(crate::server::srt::DEFAULT_LATENCY.as_millis() as u64)),
            ),
            p(
                "passphrase",
                "string",
                "AES-128 passphrase (10 to 79 characters) when the listener encrypts",
                json!("correct horse battery"),
                None,
            ),
            p(
                crate::client::media_root::MEDIA_ROOT_PARAM,
                "string",
                "Directory srt_send_file may read files from; nothing outside it is sent. Defaults to NetGet's own media directory under the platform's local-data dir.",
                json!("/var/lib/netget/media"),
                None,
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("srt-tokio 0.4.4 caller; MPEG-TS PAT/PMT inspection for reports")
            .llm_control("What to read or send and when")
            .e2e_testing("tests/client/srt: libsrt 1.5 (srt-live-transmit, independent) as listener sends a paced H.264/AAC MPEG-TS stream the client reads and reports, and writes the file the client publishes, which ffprobe decodes")
            .notes("Live mode, caller only; no rendezvous. Files are paced by bitrate, not PCR.")
            .max_inbound_bytes(1500)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Read live/cam from the SRT listener at 127.0.0.1:9000 for five seconds"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"srt","remote_addr":"127.0.0.1:9000","instruction":"Read the stream for five seconds","startup_params":{"stream_id":"#!::r=live/cam,m=request"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"srt_connected","handler":{"type":"static","actions":[receive().example]}},
            {"event_pattern":"srt_report","handler":{"type":"static","actions":[{"type":"disconnect"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'disconnect'}] if e['bytes']>0 else [{'type':'srt_receive','seconds':5}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Real-time"
    }
}

impl Client for SrtClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("srt_receive") => {
                if let Some(s) = v.get("seconds").filter(|s| !s.is_null()) {
                    ensure!(
                        s.as_f64().is_some_and(|s| (1.0..=60.0).contains(&s)),
                        "seconds is 1 to 60"
                    );
                }
            }
            Some("srt_send_file") => {
                ensure!(
                    v["path"].as_str().is_some_and(|p| !p.is_empty()
                        && p.len() <= 1024
                        && !crate::utils::sanitize::has_controls(&p)),
                    "path is a file path"
                );
                if let Some(b) = v.get("bitrate_kbps").filter(|b| !b.is_null()) {
                    ensure!(
                        b.as_f64().is_some_and(|b| (100.0..=50_000.0).contains(&b)),
                        "bitrate_kbps is 100 to 50000"
                    );
                }
            }
            Some("srt_send_text") => ensure!(
                v["text"]
                    .as_str()
                    .is_some_and(|t| !t.is_empty() && t.len() <= 1316),
                "text is 1 to 1316 bytes"
            ),
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown SRT client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

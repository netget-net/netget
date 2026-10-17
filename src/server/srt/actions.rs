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
pub struct SrtProtocol;
impl SrtProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("-> SRT {name}"))),
    }
}

fn accept() -> ActionDefinition {
    action("srt_accept", "Admit the caller: Rust completes the SRT handshake; a publisher's stream is relayed to every reader of the same resource", vec![], json!({"type": "srt_accept"}))
}
fn reject() -> ActionDefinition {
    action(
        "srt_reject",
        "Refuse the caller with an SRT server reject code in the handshake",
        vec![parameter("reason", "string", "unauthorized (2401), forbidden (2403), not_found (2404), bad_request (2400), conflict (2409) or overload (2402)", true)],
        json!({"type": "srt_reject", "reason": "unauthorized"}),
    )
}
fn ignore() -> ActionDefinition {
    action(
        "srt_ignore",
        "Acknowledge the report; nothing is sent to anyone",
        vec![],
        json!({"type": "srt_ignore"}),
    )
}
pub fn send_text() -> ActionDefinition {
    action(
        "srt_send_text",
        "Send a UTF-8 text message to this reader as one SRT message (alongside any relayed stream)",
        vec![parameter("text", "string", "The message, up to 1316 bytes so it fits one SRT packet", true)],
        json!({"type": "srt_send_text", "text": "stream starts in one minute"}),
    )
}

pub static CONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "srt_connect",
        "A caller completed the SRT induction and asks to connect with this stream ID",
        accept().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "stream_id",
            "string",
            "The stream ID as sent, e.g. #!::r=live/cam,m=publish or publish:live/cam",
            true,
        ),
        parameter(
            "resource",
            "string",
            "The resource it names, e.g. live/cam",
            true,
        ),
        parameter(
            "mode",
            "string",
            "publish (sends a stream) or request (reads one)",
            true,
        ),
        parameter("user", "string", "The user (u=) it names, when any", false),
        parameter("remote", "string", "The caller's UDP address", true),
    ])
    .with_actions(vec![accept(), reject()])
});
pub static CLOSED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "srt_closed",
        "An admitted connection ended, with the SRT statistics of its last report",
        ignore().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "resource",
            "string",
            "The resource it published or read",
            true,
        ),
        parameter("mode", "string", "publish or request", true),
        parameter("duration_ms", "number", "How long it was connected", true),
        parameter("reason", "string", "Why it ended: the caller closed, the publisher went idle, a slow reader was dropped, or the operator disconnected it", true),
        parameter(
            "statistics",
            "object",
            "rx/tx packets and bytes, lost, retransmitted and dropped packets, RTT",
            false,
        ),
    ])
    .with_actions(vec![ignore()])
});

pub fn check_answer(v: &Value) -> Result<()> {
    match v["type"].as_str() {
        Some("srt_accept" | "srt_ignore") => {}
        Some("srt_reject") => {
            let r = v["reason"].as_str().unwrap_or_default();
            ensure!(
                super::REJECT_CODES.iter().any(|(n, _)| *n == r),
                "unknown reject reason {r:?}"
            );
        }
        Some("srt_send_text") => ensure!(
            v["text"]
                .as_str()
                .is_some_and(|t| !t.is_empty() && t.len() <= 1316),
            "text is 1 to 1316 bytes"
        ),
        _ => bail!("Unknown SRT server action"),
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

impl Protocol for SrtProtocol {
    fn protocol_name(&self) -> &'static str {
        "SRT"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>SRT"
    }
    fn description(&self) -> &'static str {
        "SRT listener: callers publish or read streams by stream ID; Rust relays each publisher to its readers over SRT's retransmission and latency buffer"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "srt",
            "secure reliable transport",
            "haivision",
            "contribution",
            "live streaming",
            "mpeg-ts",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![send_text()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![accept(), reject(), ignore()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECT_EVENT.clone(), CLOSED_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup("latency_ms", "integer", "SRT latency (TSBPD delay) in milliseconds, 20 to 8000", json!(200), Some(json!(super::DEFAULT_LATENCY.as_millis() as u64))),
            startup("idle_timeout_secs", "integer", "Seconds a publisher may send nothing before it is closed", json!(5), Some(json!(super::IDLE_TIMEOUT.as_secs()))),
            startup("passphrase", "string", "Encrypt with AES-128 using this passphrase (10 to 79 characters); unencrypted without it", json!("correct horse battery"), None),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .port_transport(PortTransport::Udp)
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("srt-tokio 0.4.4 (pure-Rust SRT: handshake, ARQ, TSBPD, too-late drop, AES); stream-ID access-control parsing and the publish-to-readers relay are NetGet's")
            .llm_control("Which callers may publish or read which resources, and text messages to readers")
            .e2e_testing("tests/server/srt: libsrt 1.5 (srt-live-transmit, independent) publishes a paced H.264/AAC MPEG-TS stream and a second libsrt caller reads it back, which ffprobe decodes; a forbidden resource is refused in the handshake. MediaMTX (gosrt) refuses srt-tokio's SRT 1.3 handshake in both directions, so it is not a peer")
            .notes("Live mode only, single publisher per resource, no rendezvous, no bidirectional mode, no FEC or bonding. The relay forwards payloads; it does not parse MPEG-TS. srt-tokio announces SRT 1.3 and puts its payload size in the handshake MSS field; the payload size is raised to 1456 so libsrt peers can send 1316-byte messages.")
            .answers_on_failure()
            .max_inbound_bytes(1500)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "SRT ingest on UDP port 9000 that admits publishers to live/* and anyone reading"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"srt","port":9000,"instruction":"Admit publishers to resources under live/ and every reader"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"static","actions":[{"type":"srt_accept"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([
            {"event_pattern":"srt_connect","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nok=e['mode']=='request' or e['resource'].startswith('live/')\nprint(json.dumps({'actions':[{'type':'srt_accept'} if ok else {'type':'srt_reject','reason':'forbidden'}]}))"}},
            {"event_pattern":"*","handler":{"type":"static","actions":[{"type":"srt_ignore"}]}}
        ]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Real-time"
    }
}

impl Server for SrtProtocol {
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

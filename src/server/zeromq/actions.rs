use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct ZeromqProtocol;
impl ZeromqProtocol {
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
    let log_template = match name {
        "zmq_reply" | "zmq_send" => {
            LogTemplate::new().with_info(format!("-> ZeroMQ {name} {{preview(frames,120)}}"))
        }
        _ => LogTemplate::new().with_info(format!("-> ZeroMQ {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

pub fn frames_param(what: &str) -> Parameter {
    parameter("frames", "array", what, true)
}

pub fn encoding_param() -> Parameter {
    parameter(
        "encoding",
        "string",
        "utf8 (default) or hex, for every frame",
        false,
    )
}

fn reply_action() -> ActionDefinition {
    action(
        "zmq_reply",
        "Answer the message on the same connection. For a REP socket, or a REQ peer of a ROUTER, Rust adds the envelope back.",
        vec![frames_param("Reply frames, each a string (at most 64)"), encoding_param()],
        json!({"type":"zmq_reply","frames":["World"]}),
    )
}

fn ignore_action() -> ActionDefinition {
    action(
        "zmq_ignore",
        "Send nothing back: the only answer on a PULL socket, and on a ROUTER it leaves the peer waiting.",
        vec![],
        json!({"type":"zmq_ignore"}),
    )
}

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zmq_message",
        "A peer sent a multipart message to this socket.",
        reply_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "socket_type",
            "string",
            "This socket's type: REP, ROUTER or PULL",
            true,
        ),
        parameter(
            "peer_socket_type",
            "string",
            "The peer's Socket-Type from its READY",
            true,
        ),
        parameter(
            "peer_identity",
            "string",
            "The peer's Identity property, if it set one",
            false,
        ),
        frames_param("Message frames after any request envelope, each a string"),
        parameter(
            "encoding",
            "string",
            "utf8, or hex when any frame is not UTF-8",
            true,
        ),
        parameter("remote_addr", "string", "Peer address and port", true),
    ])
    .with_actions(vec![reply_action(), ignore_action()])
});

impl Protocol for ZeromqProtocol {
    fn protocol_name(&self) -> &'static str {
        "ZeroMQ"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ZMTP"
    }
    fn description(&self) -> &'static str {
        "ZeroMQ (ZMTP 3.1) REP, ROUTER or PULL socket whose replies the handler writes"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["zeromq", "zmq", "zmtp", "0mq", "rep", "router", "pull"]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![reply_action(), ignore_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![MESSAGE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "socket_type".into(),
                type_hint: "string".into(),
                description: "rep (answer each request in turn), router (answer any message) or pull (receive only)".into(),
                required: false,
                example: json!("router"),
                default: Some(json!(super::DEFAULT_SOCKET_TYPE)),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".into(),
                type_hint: "number".into(),
                description: "Seconds a connection may stay silent between messages (1..=86400)".into(),
                required: false,
                example: json!(600),
                default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("ZMTP 3.1 over Tokio TCP, hand-written: greeting, NULL mechanism, READY with Socket-Type and Identity, the socket-type compatibility check, multipart frames, PING/PONG; REP strips and restores the request envelope")
            .llm_control("The reply to each message, as frames")
            .e2e_testing("tests/server/zeromq: raw ZMTP and bounds; pyzmq (libzmq 4.3.5) and go-zeromq/zmq4 (pure Go) as independent peers")
            .notes("NULL security only (no PLAIN or CURVE). One message is handled at a time per connection; REP answers strictly in turn, and a REP request the handler does not answer closes the connection rather than leaving the peer to wait forever. Frames and messages are capped at 1 MiB, 64 frames per message; each connection may be silent idle_timeout_secs. Binding is the server's role: NetGet never connects out from here.")
            .request_only("A ZeroMQ server socket only ever answers a message it received")
            .max_inbound_bytes(super::wire::MAX_MESSAGE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "ZeroMQ REP socket on port 5555 that answers each request with a JSON status"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"zeromq","port":5555,"instruction":"Answer each request with {\"status\":\"ok\"}"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"zmq_message","handler":{"type":"script","language":"python","code":"import json,sys\nf=json.load(sys.stdin)['event']['frames']\nprint(json.dumps({'actions':[{'type':'zmq_reply','frames':[x.upper() for x in f]}]}))"}}]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"zmq_message","handler":{"type":"static","actions":[{"type":"zmq_reply","frames":["World"]}]}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for ZeromqProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("zmq_reply") => {
                let frames = v["frames"]
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("frames must be an array of strings"))?;
                super::wire::frames_from_text(frames, v["encoding"].as_str())?;
                Ok(ActionResult::Custom {
                    name: "zmq_reply".into(),
                    data: v,
                })
            }
            Some("zmq_ignore") => Ok(ActionResult::Custom {
                name: "zmq_ignore".into(),
                data: v,
            }),
            _ => bail!("Unknown ZeroMQ server action"),
        }
    }
}

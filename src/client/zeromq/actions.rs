use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::zeromq::{
    actions::{action, encoding_param, frames_param, parameter},
    wire,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct ZeromqClientProtocol;
impl ZeromqClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn send_action() -> ActionDefinition {
    action(
        "zmq_send",
        "Send a multipart message. A REQ socket adds the envelope and must get its reply before sending again; SUB sockets cannot send.",
        vec![frames_param("Message frames, each a string (at most 64)"), encoding_param()],
        json!({"type":"zmq_send","frames":["Hello"]}),
    )
}

fn subscribe_action() -> ActionDefinition {
    action(
        "zmq_subscribe",
        "SUB only: receive messages whose first frame starts with this prefix (empty for all).",
        vec![parameter(
            "topic",
            "string",
            "Prefix of the first frame to subscribe to",
            true,
        )],
        json!({"type":"zmq_subscribe","topic":"weather"}),
    )
}

fn unsubscribe_action() -> ActionDefinition {
    action(
        "zmq_unsubscribe",
        "SUB only: stop receiving a prefix subscribed to earlier.",
        vec![parameter("topic", "string", "The prefix to drop", true)],
        json!({"type":"zmq_unsubscribe","topic":"weather"}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the ZeroMQ connection",
        vec![],
        json!({"type":"disconnect"}),
    )
}

fn actions() -> Vec<ActionDefinition> {
    vec![
        send_action(),
        subscribe_action(),
        unsubscribe_action(),
        disconnect_action(),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zmq_connected",
        "The ZMTP handshake completed; the socket is ready.",
        send_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "socket_type",
            "string",
            "This socket's type: REQ, DEALER, PUSH or SUB",
            true,
        ),
        parameter(
            "peer_socket_type",
            "string",
            "The server's Socket-Type from its READY",
            true,
        ),
    ])
    .with_actions(actions())
});

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "zmq_message",
        "A message arrived: a REQ socket's reply, or what a DEALER or SUB socket received.",
        send_action().example.clone(),
    )
    .with_parameters(vec![
        frames_param("Message frames after any reply envelope, each a string"),
        parameter(
            "encoding",
            "string",
            "utf8, or hex when any frame is not UTF-8",
            true,
        ),
    ])
    .with_actions(actions())
});

pub fn socket_type(name: &str) -> Result<&'static str> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "req" => "REQ",
        "dealer" => "DEALER",
        "push" => "PUSH",
        "sub" => "SUB",
        other => bail!("socket_type must be req, dealer, push or sub, not {other}"),
    })
}

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str() {
        Some("zmq_send") => {
            let frames = v["frames"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("frames must be an array of strings"))?;
            ensure!(!frames.is_empty(), "a message has at least one frame");
            wire::frames_from_text(frames, v["encoding"].as_str())?;
        }
        Some("zmq_subscribe" | "zmq_unsubscribe") => {
            let topic = v["topic"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("topic must be a string"))?;
            ensure!(topic.len() <= 255, "topic is at most 255 bytes");
        }
        _ => bail!("Unknown ZeroMQ client action"),
    }
    Ok(())
}

impl Protocol for ZeromqClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "ZeroMQ"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ZMTP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "zeromq", "zmq", "zmtp", "0mq", "req", "dealer", "push", "sub",
        ]
    }
    fn description(&self) -> &'static str {
        "ZeroMQ (ZMTP 3.1) REQ, DEALER, PUSH or SUB socket connecting to a server"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), MESSAGE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "socket_type".into(),
                type_hint: "string".into(),
                description: "req (request then reply), dealer, push (send only) or sub (subscribe and receive)".into(),
                required: false,
                example: json!("sub"),
                default: Some(json!(super::DEFAULT_SOCKET_TYPE)),
            },
            ParameterDefinition {
                name: "identity".into(),
                type_hint: "string".into(),
                description: "Identity property sent in READY, which a ROUTER peer sees".into(),
                required: false,
                example: json!("worker-1"),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("ZMTP 3.1 over Tokio TCP, hand-written: greeting, NULL mechanism, READY, compatibility check, multipart frames, PING/PONG, subscriptions as ZMTP 3.0 subscription messages (which 3.1 peers also accept)")
            .llm_control("What to send, which topics to subscribe to, and what to do with each message received")
            .e2e_testing("tests/client/zeromq: NetGet's own server for REQ and DEALER; pyzmq (libzmq 4.3.5) REP, ROUTER, PULL and PUB as the independent peers")
            .notes("NULL security only. One connection, no reconnection: if the server goes away the client ends. A REQ socket refuses a second send before its reply arrives. Frames and messages are capped at 1 MiB, 64 frames per message.")
            .max_inbound_bytes(wire::MAX_MESSAGE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect a ZeroMQ REQ socket to 127.0.0.1:5555 and send Hello"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"zeromq","remote_addr":"127.0.0.1:5555","instruction":"Send Hello and report the reply"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"zmq_connected","handler":{"type":"static","actions":[{"type":"zmq_send","frames":["Hello"]}]}},
            {"event_pattern":"zmq_message","handler":{"type":"static","actions":[{"type":"disconnect"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\nf=json.load(sys.stdin)['event']['frames']\nprint(json.dumps({'actions':[{'type':'zmq_send','frames':['again']}] if f==['World'] else [{'type':'disconnect'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for ZeromqClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}

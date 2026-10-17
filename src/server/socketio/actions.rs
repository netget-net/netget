use super::packet;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct SocketIoProtocol;
impl SocketIoProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("-> Socket.IO {name}"))),
    }
}

pub fn emit_action() -> ActionDefinition {
    action(
        "socketio_emit",
        "Emit an event. Rust encodes the Socket.IO packet and delivers it to the chosen sockets over their Engine.IO transport (polling or WebSocket).",
        vec![
            parameter("event", "string", "Event name, e.g. chat message (not a reserved name like connect or disconnect)", true),
            parameter("args", "array", "Event arguments as JSON values, e.g. [\"hello\", {\"from\": \"bot\"}]", false),
            parameter("to", "string", "Recipients: sender (default, the socket that triggered this), namespace (every socket in it), room:<name>, or socket:<id>", false),
            parameter("namespace", "string", "Namespace to emit in; defaults to the one the event came from, else /", false),
            parameter("include_sender", "boolean", "For namespace and room broadcasts: also deliver to the triggering socket (default true)", false),
            parameter("ack", "boolean", "Ask the single recipient to acknowledge; its answer arrives as socketio_ack_received", false),
        ],
        json!({"type":"socketio_emit","event":"chat message","args":["welcome!"]}),
    )
}
fn ack_action() -> ActionDefinition {
    action(
        "socketio_ack",
        "Acknowledge the event the client sent with an acknowledgement id (its callback receives these arguments)",
        vec![parameter("args", "array", "Arguments passed to the client's callback, e.g. [{\"ok\": true}]", false)],
        json!({"type":"socketio_ack","args":[{"ok":true}]}),
    )
}
fn join_action() -> ActionDefinition {
    action(
        "socketio_join",
        "Add the triggering socket to a room in its namespace",
        vec![parameter(
            "room",
            "string",
            "Room name, 1 to 128 characters",
            true,
        )],
        json!({"type":"socketio_join","room":"lobby"}),
    )
}
fn leave_action() -> ActionDefinition {
    action(
        "socketio_leave",
        "Remove the triggering socket from a room",
        vec![parameter("room", "string", "Room name to leave", true)],
        json!({"type":"socketio_leave","room":"lobby"}),
    )
}
pub fn disconnect_socket_action() -> ActionDefinition {
    action("socketio_disconnect_socket", "Disconnect the socket from its namespace (Socket.IO DISCONNECT); the Engine.IO session stays open", vec![], json!({"type":"socketio_disconnect_socket"}))
}
fn accept_action() -> ActionDefinition {
    action(
        "socketio_accept",
        "Accept the namespace connection; Rust assigns the socket id and answers CONNECT",
        vec![],
        json!({"type":"socketio_accept"}),
    )
}
fn reject_action() -> ActionDefinition {
    action(
        "socketio_reject",
        "Refuse the namespace connection with CONNECT_ERROR",
        vec![
            parameter(
                "message",
                "string",
                "Reason the client's connect_error handler receives, e.g. not authorized",
                true,
            ),
            parameter(
                "data",
                "object",
                "Optional extra details sent with the error",
                false,
            ),
        ],
        json!({"type":"socketio_reject","message":"not authorized"}),
    )
}
fn close_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the whole Engine.IO session (every namespace on it)",
        vec![],
        json!({"type":"disconnect"}),
    )
}

fn reacting() -> Vec<ActionDefinition> {
    vec![
        emit_action(),
        ack_action(),
        join_action(),
        leave_action(),
        disconnect_socket_action(),
    ]
}

pub static CONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("socketio_connect", "A client asks to connect to a namespace (Socket.IO CONNECT). Accept or reject; emits after an accept go to the new socket.", accept_action().example.clone())
        .with_parameters(vec![
            parameter("namespace", "string", "Namespace requested, e.g. / or /admin", true),
            parameter("auth", "object", "The client's auth payload, when it sent one", false),
            parameter("session_id", "string", "Engine.IO session id", true),
            parameter("transport", "string", "polling or websocket", true),
        ])
        .with_actions(vec![accept_action(), reject_action(), emit_action(), join_action()])
});
pub static EVENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socketio_event",
        "A client emitted an event",
        emit_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("socket_id", "string", "The emitting socket", true),
        parameter(
            "namespace",
            "string",
            "Namespace of the socket, e.g. / or /admin",
            true,
        ),
        parameter(
            "event",
            "string",
            "Name of the event the peer emitted, e.g. chat message",
            true,
        ),
        parameter("args", "array", "Event arguments", true),
        parameter(
            "ack_requested",
            "boolean",
            "True when the client waits for socketio_ack",
            true,
        ),
        parameter("rooms", "array", "Rooms the socket has joined", true),
    ])
    .with_actions(reacting())
});
pub static ACK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socketio_ack_received",
        "A client acknowledged an event emitted with ack: true",
        emit_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("socket_id", "string", "The acknowledging socket", true),
        parameter(
            "namespace",
            "string",
            "Namespace of the socket, e.g. / or /admin",
            true,
        ),
        parameter(
            "event",
            "string",
            "The emitted event being acknowledged",
            true,
        ),
        parameter(
            "args",
            "array",
            "The arguments the client's callback was given",
            true,
        ),
    ])
    .with_actions(reacting())
});
pub static DISCONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("socketio_disconnect", "A socket left its namespace (client disconnect, transport close or ping timeout); emit to others if they should know", emit_action().example.clone())
        .with_parameters(vec![
            parameter("socket_id", "string", "The socket that left", true),
            parameter("namespace", "string", "Namespace of the socket, e.g. / or /admin", true),
            parameter("reason", "string", "client namespace disconnect, client disconnect, transport close, ping timeout or server namespace disconnect", true),
        ])
        .with_actions(vec![emit_action()])
});

fn startup(
    name: &str,
    kind: &str,
    description: &str,
    example: Value,
    default: Value,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required: false,
        example,
        default: Some(default),
    }
}

impl Protocol for SocketIoProtocol {
    fn protocol_name(&self) -> &'static str {
        "Socket.IO"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Engine.IO>Socket.IO"
    }
    fn description(&self) -> &'static str {
        "Socket.IO v5 server over Engine.IO v4 (long-polling and WebSocket): namespaces, events, acknowledgements, rooms"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "socket.io",
            "socketio",
            "engine.io",
            "realtime",
            "websocket events",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![emit_action(), disconnect_socket_action(), close_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept_action(),
            reject_action(),
            emit_action(),
            ack_action(),
            join_action(),
            leave_action(),
            disconnect_socket_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECT_EVENT.clone(),
            EVENT_EVENT.clone(),
            ACK_EVENT.clone(),
            DISCONNECT_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup("path", "string", "HTTP path Engine.IO is served on", json!("/realtime/"), json!(super::DEFAULT_PATH)),
            startup("namespaces", "array", "Namespaces clients may connect to; others get CONNECT_ERROR Invalid namespace", json!(["/", "/admin"]), json!(super::DEFAULT_NAMESPACES)),
            startup("ping_interval_ms", "integer", "Engine.IO pingInterval: how often the server pings each session (1000 to 120000)", json!(10000), json!(super::DEFAULT_PING_INTERVAL.as_millis() as u64)),
            startup("ping_timeout_ms", "integer", "Engine.IO pingTimeout: how long a pong may take before the session is closed (1000 to 120000)", json!(5000), json!(super::DEFAULT_PING_TIMEOUT.as_millis() as u64)),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("hyper HTTP/1.1 Engine.IO v4: long-polling with record-separated payloads, WebSocket (direct or by probe/upgrade, tokio-tungstenite), server heartbeats; Socket.IO v5 packets, namespaces, acknowledgements both ways, rooms and broadcasts in Rust")
            .llm_control("Which namespace connections to accept and what to emit, acknowledge, join, leave or disconnect for each event")
            .e2e_testing("tests/server/socketio: python-socketio 5.17.0 (polling with upgrade, and WebSocket only) and the reference socket.io-client 4.8.4 (JavaScript) connect, emit with acks, receive broadcasts and server acks, use a second namespace and are refused a forbidden one")
            .notes("Text packets only: binary events and attachments are refused. No CORS headers, no Engine.IO v3 / Socket.IO v4 protocol revisions, no adapter for several processes. 256 sessions, 1 MB payloads, 256 queued packets per session.")
            .answers_on_failure()
            .max_inbound_bytes(packet::MAX_PAYLOAD)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Socket.IO chat server that echoes every chat message to the whole room"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"socketio","port":3000,"instruction":"A chat server: accept everyone and broadcast every chat message"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"socketio_connect","handler":{"type":"static","actions":[{"type":"socketio_accept"}]}},
            {"event_pattern":"socketio_event","handler":{"type":"static","actions":[{"type":"socketio_emit","event":"chat message","args":["ok"],"to":"namespace"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'socketio_emit','event':e['event'],'args':e['args'],'to':'namespace'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Real-time"
    }
}

impl Server for SocketIoProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        check_action(&v)?;
        if v["type"] == "disconnect" {
            return Ok(ActionResult::CloseConnection);
        }
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

pub fn check_action(v: &Value) -> Result<()> {
    ensure!(
        crate::utils::json_budget::within_budget(v, packet::MAX_PAYLOAD, 20_000, 32),
        "action exceeds the Socket.IO bounds"
    );
    let room = |k: &str| -> Result<()> {
        let r = v[k].as_str().with_context(|| format!("{k} is required"))?;
        ensure!(
            !r.is_empty() && r.len() <= 128,
            "{k} must be 1..128 characters"
        );
        Ok(())
    };
    match v["type"].as_str() {
        Some("socketio_emit") => {
            let e = v["event"].as_str().context("event is required")?;
            ensure!(
                !e.is_empty() && e.len() <= packet::MAX_EVENT_NAME && !packet::reserved(e),
                "event must be 1..128 characters and not reserved"
            );
            if let Some(a) = v.get("args").filter(|a| !a.is_null()) {
                ensure!(
                    a.as_array().is_some_and(|a| a.len() <= packet::MAX_ARGS),
                    "args must be an array of at most 16 values"
                );
            }
            if let Some(t) = v.get("to").filter(|t| !t.is_null()) {
                let t = t.as_str().context("to must be a string")?;
                ensure!(
                    t == "sender"
                        || t == "namespace"
                        || t.strip_prefix("room:")
                            .is_some_and(|r| !r.is_empty() && r.len() <= 128)
                        || t.strip_prefix("socket:")
                            .is_some_and(|r| !r.is_empty() && r.len() <= 64),
                    "to is sender, namespace, room:<name> or socket:<id>"
                );
            }
            if let Some(n) = v.get("namespace").filter(|n| !n.is_null()) {
                ensure!(
                    n.as_str().is_some_and(packet::namespace_ok),
                    "namespace must look like /name"
                );
            }
        }
        Some("socketio_ack") => {
            if let Some(a) = v.get("args").filter(|a| !a.is_null()) {
                ensure!(
                    a.as_array().is_some_and(|a| a.len() <= packet::MAX_ARGS),
                    "args must be an array of at most 16 values"
                );
            }
        }
        Some("socketio_join" | "socketio_leave") => room("room")?,
        Some("socketio_reject") => {
            ensure!(
                v["message"]
                    .as_str()
                    .is_some_and(|m| !m.is_empty() && m.len() <= 1024),
                "message must be 1..1024 bytes"
            );
        }
        Some("socketio_accept" | "socketio_disconnect_socket" | "disconnect") => {}
        _ => bail!("Unknown Socket.IO server action"),
    }
    Ok(())
}

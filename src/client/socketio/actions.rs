use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::socketio::actions::{action, parameter};
use crate::server::socketio::packet;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct SocketIoClientProtocol;
impl SocketIoClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn emit_action() -> ActionDefinition {
    action(
        "socketio_emit",
        "Emit an event on a connected namespace; with ack the server's acknowledgement arrives as socketio_ack_received",
        vec![
            parameter("event", "string", "Event name, e.g. chat message (not a reserved name like connect)", true),
            parameter("args", "array", "Event arguments as JSON values, e.g. [\"hello\"]", false),
            parameter("namespace", "string", "Namespace to emit on (default /)", false),
            parameter("ack", "boolean", "Ask the server to acknowledge this event", false),
        ],
        json!({"type":"socketio_emit","event":"chat message","args":["hello"],"ack":true}),
    )
}
fn ack_action() -> ActionDefinition {
    action(
        "socketio_ack",
        "Acknowledge an event the server sent with an acknowledgement id",
        vec![
            parameter("ack_id", "number", "The ack_id from socketio_event", true),
            parameter(
                "namespace",
                "string",
                "The event's namespace (default /)",
                false,
            ),
            parameter(
                "args",
                "array",
                "Arguments for the server's callback",
                false,
            ),
        ],
        json!({"type":"socketio_ack","ack_id":1,"args":["got it"]}),
    )
}
fn join_action() -> ActionDefinition {
    action(
        "socketio_connect_namespace",
        "Connect to another namespace on the same session",
        vec![
            parameter("namespace", "string", "Namespace, e.g. /admin", true),
            parameter(
                "auth",
                "object",
                "Optional auth payload for the server",
                false,
            ),
        ],
        json!({"type":"socketio_connect_namespace","namespace":"/admin"}),
    )
}
fn leave_action() -> ActionDefinition {
    action(
        "socketio_disconnect_namespace",
        "Leave a namespace (Socket.IO DISCONNECT); the session stays open",
        vec![parameter("namespace", "string", "Namespace to leave", true)],
        json!({"type":"socketio_disconnect_namespace","namespace":"/admin"}),
    )
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the Engine.IO session and stop this client",
        vec![],
        json!({"type":"disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![
        emit_action(),
        ack_action(),
        join_action(),
        leave_action(),
        disconnect_action(),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socketio_connected",
        "A namespace accepted the connection",
        emit_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("namespace", "string", "The connected namespace", true),
        parameter("socket_id", "string", "Socket id the server assigned", true),
        parameter("transport", "string", "websocket or polling", true),
    ])
    .with_actions(actions())
});
pub static CONNECT_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socketio_connect_error",
        "A namespace refused the connection (CONNECT_ERROR)",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("namespace", "string", "The refused namespace", true),
        parameter("message", "string", "The server's reason", true),
        parameter("data", "object", "Extra details, when sent", false),
    ])
    .with_actions(actions())
});
pub static EVENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socketio_event",
        "The server emitted an event",
        ack_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("namespace", "string", "Namespace it arrived on", true),
        parameter(
            "event",
            "string",
            "Name of the event the peer emitted, e.g. chat message",
            true,
        ),
        parameter("args", "array", "Event arguments", true),
        parameter(
            "ack_id",
            "number",
            "Present when the server waits for socketio_ack",
            false,
        ),
    ])
    .with_actions(actions())
});
pub static ACK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socketio_ack_received",
        "The server acknowledged an event emitted with ack",
        emit_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("namespace", "string", "Namespace of the event", true),
        parameter("event", "string", "The acknowledged event", true),
        parameter(
            "args",
            "array",
            "The server's acknowledgement arguments",
            true,
        ),
    ])
    .with_actions(actions())
});
pub static DISCONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socketio_disconnected",
        "The server disconnected a namespace (or the whole session)",
        join_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "namespace",
            "string",
            "The namespace, or * for the whole session",
            true,
        ),
        parameter(
            "reason",
            "string",
            "io server disconnect, transport close or ping timeout",
            true,
        ),
    ])
    .with_actions(actions())
});

impl Protocol for SocketIoClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Socket.IO"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Engine.IO>Socket.IO"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["socket.io", "socketio", "engine.io", "socket.io client"]
    }
    fn description(&self) -> &'static str {
        "Socket.IO v5 client over Engine.IO v4 (WebSocket or long-polling): namespaces, events and acknowledgements"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            CONNECT_ERROR_EVENT.clone(),
            EVENT_EVENT.clone(),
            ACK_EVENT.clone(),
            DISCONNECTED_EVENT.clone(),
        ]
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
                "path",
                "string",
                "HTTP path the server serves Engine.IO on",
                json!("/realtime/"),
                Some(json!(crate::server::socketio::DEFAULT_PATH)),
            ),
            p(
                "transport",
                "string",
                "websocket (direct) or polling (HTTP long-polling only)",
                json!("polling"),
                Some(json!(super::DEFAULT_TRANSPORT)),
            ),
            p(
                "namespaces",
                "array",
                "Namespaces to connect to on startup",
                json!(["/", "/chat"]),
                Some(json!(crate::server::socketio::DEFAULT_NAMESPACES)),
            ),
            p(
                "auth",
                "object",
                "Auth payload sent with every namespace CONNECT",
                json!({"token": "abc"}),
                None,
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Engine.IO v4 over a direct WebSocket (tokio-tungstenite) or HTTP long-polling (reqwest); answers server pings; Socket.IO v5 packets, namespaces and acknowledgement ids in Rust")
            .llm_control("What to emit, which events to acknowledge and how, and which namespaces to join or leave")
            .e2e_testing("tests/client/socketio: python-socketio 5.17.0's server (independent) over WebSocket and polling: connects, emits with acks, receives broadcasts and server acks, joins a second namespace and is refused a forbidden one")
            .notes("No transport upgrade from polling to WebSocket, no binary attachments, no automatic reconnection. 1 MB payloads.")
            .max_inbound_bytes(packet::MAX_PAYLOAD)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Join the Socket.IO chat at 127.0.0.1:3000 and say hello"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"socketio","remote_addr":"127.0.0.1:3000","instruction":"Say hello in the chat"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"socketio_connected","handler":{"type":"static","actions":[emit_action().example]}},
            {"event_pattern":"socketio_event","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Real-time"
    }
}

impl Client for SocketIoClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        ensure!(
            crate::utils::json_budget::within_budget(&v, packet::MAX_PAYLOAD, 20_000, 32),
            "action exceeds the Socket.IO bounds"
        );
        let nsp_ok = |k: &str| -> Result<()> {
            if let Some(n) = v.get(k).filter(|n| !n.is_null()) {
                ensure!(
                    n.as_str().is_some_and(packet::namespace_ok),
                    "{k} must look like /name"
                );
            }
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
                nsp_ok("namespace")?;
            }
            Some("socketio_ack") => {
                ensure!(v["ack_id"].as_u64().is_some(), "ack_id is required");
                nsp_ok("namespace")?;
            }
            Some("socketio_connect_namespace" | "socketio_disconnect_namespace") => {
                ensure!(
                    v["namespace"].as_str().is_some_and(packet::namespace_ok),
                    "namespace must look like /name"
                );
                if let Some(a) = v.get("auth").filter(|a| !a.is_null()) {
                    ensure!(a.is_object(), "auth must be an object");
                }
            }
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown Socket.IO client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

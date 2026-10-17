use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::msgpack_rpc::actions::{
    action, check_notify, check_value, notify_action, parameter, VALUE_NOTE,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct MsgpackRpcClientProtocol;
impl MsgpackRpcClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn call_action() -> ActionDefinition {
    action(
        "msgpack_call",
        "Call a method on the server; the result or error arrives as msgpack_response.",
        vec![
            parameter("method", "string", "Method name, e.g. nvim_eval", true),
            parameter("params", "array", VALUE_NOTE, true),
        ],
        json!({"type":"msgpack_call","method":"nvim_eval","params":["1 + 2"]}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the MessagePack-RPC connection",
        vec![],
        json!({"type":"disconnect"}),
    )
}

fn actions() -> Vec<ActionDefinition> {
    vec![call_action(), notify_action(), disconnect_action()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "msgpack_connected",
        "Connected to the MessagePack-RPC server.",
        call_action().example.clone(),
    )
    .with_parameters(vec![parameter(
        "remote_addr",
        "string",
        "Server address and port",
        true,
    )])
    .with_actions(actions())
});

pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "msgpack_response",
        "The server answered a call.",
        call_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("method", "string", "The method that was called", true),
        parameter("msgid", "number", "The call's message id", true),
        parameter("result", "any", "The result, null on error", true),
        parameter("error", "any", "The error value, null on success", true),
    ])
    .with_actions(actions())
});

pub static NOTIFICATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "msgpack_notification",
        "The server sent a notification.",
        call_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("method", "string", "Notification method name", true),
        parameter("params", "array", "The parameters, as an array", true),
    ])
    .with_actions(actions())
});

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str() {
        Some("msgpack_call") => {
            ensure!(
                v["method"].as_str().is_some_and(|m| !m.is_empty()),
                "method must be a non-empty string"
            );
            ensure!(v["params"].is_array(), "params must be an array");
            check_value(&v["params"])
        }
        Some("msgpack_notify") => check_notify(v),
        _ => bail!("Unknown MessagePack-RPC client action"),
    }
}

impl Protocol for MsgpackRpcClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "MessagePack-RPC"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>MessagePack-RPC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["msgpack-rpc", "messagepack-rpc", "msgpack", "neovim rpc"]
    }
    fn description(&self) -> &'static str {
        "MessagePack-RPC client: calls, notifications, and the server's notifications as events"
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
            NOTIFICATION_EVENT.clone(),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("MessagePack-RPC over Tokio TCP with the server's hand-written codec: pipelined calls matched by msgid, notifications both ways")
            .llm_control("Which methods to call or notify, and what to do with each response and notification")
            .e2e_testing("tests/client/msgpack_rpc: NetGet's own server; Neovim (--listen) and ugorji/go's MsgpackSpecRpc server as independent peers")
            .notes("A request from the server is answered with an error: this client serves no methods. At most 64 calls may await their responses. Messages are capped at 1 MiB, nesting at 32 levels.")
            .max_inbound_bytes(crate::server::msgpack_rpc::wire::MAX_MESSAGE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to Neovim's RPC socket at 127.0.0.1:6666 and evaluate 1 + 2"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"msgpack-rpc","remote_addr":"127.0.0.1:6666","instruction":"Ask Neovim for its version"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"msgpack_connected","handler":{"type":"static","actions":[{"type":"msgpack_call","method":"nvim_eval","params":["v:version"]}]}},
            {"event_pattern":"msgpack_response","handler":{"type":"static","actions":[{"type":"disconnect"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'msgpack_notify','method':'log','params':[e['result']]},{'type':'disconnect'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for MsgpackRpcClientProtocol {
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

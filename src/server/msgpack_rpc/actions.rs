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
pub struct MsgpackRpcProtocol;
impl MsgpackRpcProtocol {
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
    let log_template =
        match name {
            "msgpack_result" => {
                LogTemplate::new().with_info("-> MessagePack-RPC result {preview(result,100)}")
            }
            "msgpack_error" => {
                LogTemplate::new().with_info("-> MessagePack-RPC error {preview(error,100)}")
            }
            "msgpack_notify" => LogTemplate::new()
                .with_info("-> MessagePack-RPC notify {method} {preview(params,80)}"),
            "msgpack_call" => LogTemplate::new()
                .with_info("-> MessagePack-RPC call {method} {preview(params,80)}"),
            _ => LogTemplate::new().with_info(format!("-> MessagePack-RPC {name}")),
        };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

pub const VALUE_NOTE: &str =
    "Any JSON; {\"$bin\": hex} is binary and {\"$ext\": type, \"hex\": hex} an extension";

fn result_action() -> ActionDefinition {
    action(
        "msgpack_result",
        "Answer the request successfully with a result value.",
        vec![parameter("result", "any", VALUE_NOTE, true)],
        json!({"type":"msgpack_result","result":3}),
    )
}

fn error_action() -> ActionDefinition {
    action(
        "msgpack_error",
        "Answer the request with an error value (a string, or e.g. [code, message]); the result is nil.",
        vec![parameter("error", "any", "The error value; must not be null", true)],
        json!({"type":"msgpack_error","error":"no such method"}),
    )
}

pub fn notify_action() -> ActionDefinition {
    action(
        "msgpack_notify",
        "Send the peer a notification [2, method, params]. May accompany an answer.",
        vec![
            parameter("method", "string", "Notification method name", true),
            parameter("params", "array", "Notification parameters", true),
        ],
        json!({"type":"msgpack_notify","method":"progress","params":[50]}),
    )
}

fn ignore_action() -> ActionDefinition {
    action(
        "msgpack_ignore",
        "Take no action on a notification (notifications have no reply).",
        vec![],
        json!({"type":"msgpack_ignore"}),
    )
}

pub static REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "msgpack_request",
        "A peer called a method; answer with a result or an error (and optionally notify it).",
        result_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("method", "string", "The method the peer called", true),
        parameter("params", "array", "The parameters, as an array", true),
        parameter(
            "msgid",
            "number",
            "Request id Rust echoes in the response",
            true,
        ),
        parameter("remote_addr", "string", "Peer address and port", true),
    ])
    .with_actions(vec![result_action(), error_action(), notify_action()])
});

pub static NOTIFICATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "msgpack_notification",
        "A peer sent a notification, which expects no reply.",
        ignore_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("method", "string", "Notification method name", true),
        parameter("params", "array", "The parameters, as an array", true),
        parameter("remote_addr", "string", "Peer address and port", true),
    ])
    .with_actions(vec![ignore_action(), notify_action()])
});

pub fn check_value(v: &Value) -> Result<()> {
    super::wire::encode_message(v)?;
    Ok(())
}

pub fn check_notify(v: &Value) -> Result<()> {
    ensure!(
        v["method"].as_str().is_some_and(|m| !m.is_empty()),
        "method must be a non-empty string"
    );
    ensure!(v["params"].is_array(), "params must be an array");
    check_value(&v["params"])
}

impl Protocol for MsgpackRpcProtocol {
    fn protocol_name(&self) -> &'static str {
        "MessagePack-RPC"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>MessagePack-RPC"
    }
    fn description(&self) -> &'static str {
        "MessagePack-RPC server (the protocol Neovim speaks) whose method results the handler decides"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "msgpack-rpc",
            "messagepack-rpc",
            "msgpack",
            "rpc",
            "neovim rpc",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            result_action(),
            error_action(),
            notify_action(),
            ignore_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![REQUEST_EVENT.clone(), NOTIFICATION_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "idle_timeout_secs".into(),
            type_hint: "number".into(),
            description: "Seconds a connection may stay silent between messages (1..=86400)".into(),
            required: false,
            example: json!(600),
            default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("MessagePack-RPC over Tokio TCP with a hand-written MessagePack codec: requests, responses, notifications; values mapped to JSON with $bin and $ext objects for binary and extensions")
            .llm_control("The result or error of every request, and any notification sent back")
            .e2e_testing("tests/server/msgpack_rpc: raw messages and bounds; Neovim (rpcrequest/rpcnotify over sockconnect) and ugorji/go's MsgpackSpecRpc net/rpc codec as independent clients")
            .notes("Requests on one connection are answered in order. Messages are capped at 1 MiB and decoded only once complete, nesting at 32 levels; a connection may be silent idle_timeout_secs. A handler failure on a request answers an error value naming a generic failure, never a fabricated result.")
            .request_only("Every response answers a request; notifications go back only as part of an answer")
            .answers_on_failure()
            .max_inbound_bytes(super::wire::MAX_MESSAGE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "MessagePack-RPC server on port 6666 with add and echo methods"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"msgpack-rpc","port":6666,"instruction":"Implement add(a, b) and echo(x); anything else is an error"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"msgpack_request","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\na={'type':'msgpack_result','result':sum(e['params'])} if e['method']=='add' else {'type':'msgpack_error','error':'no such method'}\nprint(json.dumps({'actions':[a]}))"}}]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"msgpack_request","handler":{"type":"static","actions":[{"type":"msgpack_result","result":"ok"}]}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for MsgpackRpcProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        match name.as_str() {
            "msgpack_result" => check_value(&v["result"])?,
            "msgpack_error" => {
                ensure!(!v["error"].is_null(), "error must not be null");
                check_value(&v["error"])?;
            }
            "msgpack_notify" => check_notify(&v)?,
            "msgpack_ignore" => {}
            _ => bail!("Unknown MessagePack-RPC server action"),
        }
        Ok(ActionResult::Custom { name, data: v })
    }
}

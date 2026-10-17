use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::capnp_rpc::actions::{action, parameter, schema_parameters, VALUE_NOTE};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct CapnpRpcClientProtocol;
impl CapnpRpcClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn call_action() -> ActionDefinition {
    action(
        "capnp_call",
        "Call a method of the server's bootstrap capability; the answer arrives as capnp_result.",
        vec![
            parameter(
                "method",
                "string",
                "Method name, one of capnp_connected's methods",
                true,
            ),
            parameter("params", "object", VALUE_NOTE, true),
        ],
        json!({"type":"capnp_call","method":"add","params":{"a":2,"b":3}}),
        "-> Cap'n Proto call {method} {preview(params,80)}",
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the Cap'n Proto RPC connection",
        vec![],
        json!({"type":"disconnect"}),
        "-> Cap'n Proto disconnect",
    )
}

fn actions() -> Vec<ActionDefinition> {
    vec![call_action(), disconnect_action()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "capnp_connected",
        "Connected and bootstrapped: the server's capability is ready to call.",
        call_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("remote_addr", "string", "Server address and port", true),
        parameter("interface", "string", "The bootstrap interface", true),
        parameter(
            "methods",
            "array",
            "Each method's name with its params and results fields",
            true,
        ),
    ])
    .with_actions(actions())
});

pub static RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "capnp_result",
        "The server answered a call with results or an exception.",
        call_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("method", "string", "The method that was called", true),
        parameter(
            "results",
            "object|null",
            "The results struct as JSON, null on an exception",
            true,
        ),
        parameter(
            "exception",
            "object|null",
            "{reason, kind} when the call failed, otherwise null",
            true,
        ),
    ])
    .with_actions(actions())
});

impl Protocol for CapnpRpcClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Cap'n Proto RPC"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>CapnProtoRPC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["capnp", "cap'n proto", "capnproto", "capnp-rpc"]
    }
    fn description(&self) -> &'static str {
        "Cap'n Proto RPC client: bootstraps the server's capability and calls its methods, typed by a schema"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESULT_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        schema_parameters()
    }
    fn get_dependencies(&self) -> Vec<crate::protocol::dependencies::ProtocolDependency> {
        let mut deps =
            crate::llm::actions::protocol_trait::default_dependencies_from_privilege(self);
        deps.push(crate::protocol::dependencies::ProtocolDependency::ToolInPath("capnp"));
        deps
    }
    fn startup_dependencies(
        &self,
        startup_params: Option<&Value>,
    ) -> Vec<crate::protocol::dependencies::ProtocolDependency> {
        let mut deps = self.get_dependencies();
        if !crate::server::capnp_rpc::needs_compiler(startup_params) {
            deps.retain(|d| {
                *d != crate::protocol::dependencies::ProtocolDependency::ToolInPath("capnp")
            });
        }
        deps
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's hand-written Cap'n Proto encoding and RPC messages: Bootstrap, pipelined Calls on the bootstrap capability matched by question id, Return, Finish")
            .llm_control("Which methods to call with which parameters, and what to do with each result")
            .e2e_testing("tests/client/capnp_rpc: NetGet's own server; pycapnp (the C++ Cap'n Proto runtime) and capnproto.org/go/capnp v3 as independent servers")
            .notes("Only the bootstrap capability is called; capabilities in results are not followed. The client exports nothing, so a call from the server is answered with an exception. At most 64 calls may await answers; a handler chain stops after 8 follow-ups. Same message bounds as the server.")
            .max_inbound_bytes(crate::server::capnp_rpc::layout::MAX_MESSAGE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the Cap'n Proto RPC server at 127.0.0.1:5923 (a Directory interface) and look up readme"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"capnp-rpc","remote_addr":"127.0.0.1:5923","startup_params":{"schema":crate::server::capnp_rpc::actions::EXAMPLE_SCHEMA,"interface":"Directory"},"instruction":"Look up the entry named readme"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"capnp_connected","handler":{"type":"static","actions":[{"type":"capnp_call","method":"lookup","params":{"name":"readme"}}]}},
            {"event_pattern":"capnp_result","handler":{"type":"static","actions":[{"type":"disconnect"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'disconnect'}] if e['exception'] else []}))"});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for CapnpRpcClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        match name.as_str() {
            "disconnect" => return Ok(ClientActionResult::Disconnect),
            "capnp_call" => {
                ensure!(
                    v["method"].as_str().is_some_and(|m| !m.is_empty()),
                    "method must be a non-empty string"
                );
                ensure!(
                    v["params"].is_object() || v["params"].is_null(),
                    "params must be an object"
                );
            }
            _ => bail!("Unknown Cap'n Proto RPC client action"),
        }
        Ok(ClientActionResult::Custom { name, data: v })
    }
}

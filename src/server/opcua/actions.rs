use crate::llm::actions::protocol_trait::{ActionResult, Server};
use crate::llm::actions::{protocol_trait::Protocol, ActionDefinition};
use crate::protocol::{EventType, SpawnContext};
use crate::server::ics_support::{action, parameter};
use crate::state::AppState;
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::LazyLock};
#[derive(Default)]
pub struct OpcuaProtocol;
impl OpcuaProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn replies() -> Vec<ActionDefinition> {
    vec![action(
        "opcua_reply",
        "Read value, write approval, method outputs or status",
        vec![
            parameter(
                "value_type",
                "string",
                "Scalar data type matching the value field",
                false,
            ),
            parameter(
                "value",
                "any",
                "Typed value returned by the read handler",
                false,
            ),
            parameter("accepted", "boolean", "Explicit write approval", false),
            parameter("outputs", "array", "Typed method outputs", false),
            parameter(
                "status",
                "string",
                "denied,type_mismatch,unknown,unsupported",
                false,
            ),
        ],
        json!({"type":"opcua_reply","value_type":"double","value":12.5}),
    )]
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![EventType::new(
        "opcua_request",
        "OPC UA device address space and browse/read/write/method/subscription client",
        replies()[0].example.clone(),
    )
    .with_parameters(vec![
        parameter("operation", "string", "read,write,call", true),
        parameter(
            "node_id",
            "string",
            "Numeric or string node identifier",
            true,
        ),
        parameter(
            "value_type",
            "string",
            "Type of the decoded write request value",
            false,
        ),
        parameter(
            "value",
            "any",
            "Decoded typed value of the write request",
            false,
        ),
        parameter("arguments", "array", "Method arguments", false),
    ])
    .with_actions(replies())]
});
impl Protocol for OpcuaProtocol {
    fn protocol_name(&self) -> &'static str {
        "OPC UA"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>OPCUA"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["opcua"]
    }
    fn description(&self) -> &'static str {
        "OPC UA device address space and browse/read/write/method/subscription client"
    }
    fn example_prompt(&self) -> &'static str {
        "Simulate a OPC UA device on localhost"
    }
    fn group_name(&self) -> &'static str {
        "Industrial"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![action(
            "disconnect",
            "Close this peer",
            vec![],
            json!({"type":"disconnect"}),
        )]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        replies()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        EVENTS.clone()
    }

    fn metadata(&self) -> crate::protocol::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).implementation("async-opcua 0.19.0 with bounded lifecycle patch; anonymous None endpoint and handler-backed address space").llm_control("Handler supplies device values, operation approvals and refusals; client handler selects structured operations").e2e_testing("Independent peer integration plus negative and lifecycle tests in tests/server/opcua").notes("Only SecurityPolicy None / MessageSecurityMode None / Anonymous. Not secure for untrusted networks. Namespace urn:netget:device exposes Device, writable Double Value, Method(Double)->Double. Handler values are never stored; subscriptions notify initially and on approved writes. Client supports scalar double/boolean/int32/uint32/string and bounded forward browse. No history, events, node management or secure policies. 256 TCP connections; 20 sessions; 256KiB messages. Client local socket address unavailable from library.").max_inbound_bytes(crate::server::opcua::codec::MAX_FRAME).well_known_port(4840).answers_on_failure().history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_server","base_stack":"opcua","port":4840,"instruction":"Supply device decisions with structured actions"});
        let a = replies()[0].example.clone();
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"opcua_request","handler":{"type":"static","actions":[a.clone()]}}]);
        let code = format!("print({})", json!(json!({"actions":[a]}).to_string()));
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"opcua_request","handler":{"type":"script","language":"python","code":code}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
    }
}
impl Server for OpcuaProtocol {
    fn spawn(&self, ctx: SpawnContext) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ActionResult::CloseConnection);
        }
        ensure!(
            replies().iter().any(|a| v["type"] == a.name),
            "unknown device reply action"
        );
        ensure!(
            crate::utils::json_budget::within_budget(&v, 4096, 1024, 16),
            "reply exceeds JSON budget"
        );
        Ok(ActionResult::Custom {
            name: v["type"].as_str().expect("validated").into(),
            data: v,
        })
    }
}

use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::{protocol_trait::Protocol, ActionDefinition};
use crate::protocol::{ConnectContext, EventType};
use crate::server::ics_support::{action, parameter};
use crate::state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::LazyLock};
#[derive(Default)]
pub struct OpcuaClientProtocol;
impl OpcuaClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn requests() -> Vec<ActionDefinition> {
    let f = || {
        vec![parameter(
            "node_id",
            "string",
            "Numeric or string OPC UA NodeId",
            true,
        )]
    };
    let mut w = f();
    w.extend([
        parameter(
            "value_type",
            "string",
            "double,boolean,int32,uint32,string",
            true,
        ),
        parameter(
            "value",
            "any",
            "Typed scalar value matching value_type",
            true,
        ),
    ]);
    vec![
        action(
            "opcua_browse",
            "Browse forward references",
            f(),
            json!({"type":"opcua_browse","node_id":"i=85"}),
        ),
        action(
            "opcua_read",
            "Read Value attribute",
            f(),
            json!({"type":"opcua_read","node_id":"ns=2;s=Value"}),
        ),
        action(
            "opcua_write",
            "Write scalar Value",
            w,
            json!({"type":"opcua_write","node_id":"ns=2;s=Value","value_type":"double","value":23.5}),
        ),
        action(
            "opcua_call",
            "Invoke a method with typed scalar arguments",
            vec![
                parameter(
                    "object_id",
                    "string",
                    "NodeId of the owning method object",
                    true,
                ),
                parameter(
                    "method_id",
                    "string",
                    "NodeId of the method to invoke",
                    true,
                ),
                parameter("arguments", "array", "Typed scalar arguments", true),
            ],
            json!({"type":"opcua_call","object_id":"ns=2;s=Device","method_id":"ns=2;s=Method","arguments":[{"value_type":"double","value":3.0}]}),
        ),
        action(
            "opcua_subscribe",
            "Create data-change monitored item",
            f(),
            json!({"type":"opcua_subscribe","node_id":"ns=2;s=Value"}),
        ),
        action(
            "disconnect",
            "Close UA session",
            vec![],
            json!({"type":"disconnect"}),
        ),
    ]
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![
        EventType::new(
            "opcua_connected",
            "Transport ready for device operations",
            requests()[0].example.clone(),
        )
        .with_parameters(vec![parameter(
            "remote_addr",
            "string",
            "Address of the connected remote device",
            true,
        )])
        .with_actions(requests()),
        EventType::new(
            "opcua_response",
            "Device operation result or protocol status",
            requests()[0].example.clone(),
        )
        .with_parameters(vec![
            parameter(
                "success",
                "boolean",
                "Whether the device accepted the operation",
                false,
            ),
            parameter("status", "number", "Protocol error status, if any", false),
            parameter("value", "object", "Decoded response fields", false),
        ])
        .with_actions(requests()),
    ]
});
impl Protocol for OpcuaClientProtocol {
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
        "Connect to a OPC UA device on localhost"
    }
    fn group_name(&self) -> &'static str {
        "Industrial"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        requests()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        EVENTS.clone()
    }

    fn metadata(&self) -> crate::protocol::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).implementation("async-opcua 0.19.0 with bounded lifecycle patch; anonymous None endpoint and handler-backed address space").llm_control("Handler supplies device values, operation approvals and refusals; client handler selects structured operations").e2e_testing("Independent peer integration plus negative and lifecycle tests in tests/client/opcua").notes("Only SecurityPolicy None / MessageSecurityMode None / Anonymous. Not secure for untrusted networks. Namespace urn:netget:device exposes Device, writable Double Value, Method(Double)->Double. Handler values are never stored; subscriptions notify initially and on approved writes. Client supports scalar double/boolean/int32/uint32/string and bounded forward browse. No history, events, node management or secure policies. 256 TCP connections; 20 sessions; 256KiB messages. Client local socket address unavailable from library.").max_inbound_bytes(crate::server::opcua::codec::MAX_FRAME).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_client","protocol":"opcua","remote_addr":"127.0.0.1:4840","instruction":"Supply device decisions with structured actions"});
        let a = requests()[0].example.clone();
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"opcua_connected","handler":{"type":"static","actions":[a.clone()]}}]);
        let code = format!("print({})", json!(json!({"actions":[a]}).to_string()));
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"opcua_connected","handler":{"type":"script","language":"python","code":code}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
    }
}
impl Client for OpcuaClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        crate::server::opcua::codec::validate(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("action type"))?
                .into(),
            data: v,
        })
    }
}

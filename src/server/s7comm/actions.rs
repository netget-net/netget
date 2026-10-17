use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition,
};
use crate::protocol::{EventType, SpawnContext};
use crate::server::ics_support::{action, parameter};
use crate::state::AppState;
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};
#[derive(Default)]
pub struct S7commProtocol;
impl S7commProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn reply() -> ActionDefinition {
    action("s7comm_reply", "Answer each requested item with values for a read, accepted=true for a write, or error=address|denied|unsupported", vec![parameter("items","array","One {values:[0..255]} or {accepted:true} or {error:\"address\"} per request item",true)], json!({"type":"s7comm_reply","items":[{"values":[42]}]}))
}
impl Protocol for S7commProtocol {
    fn protocol_name(&self) -> &'static str {
        "S7comm"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TPKT>COTP>S7comm"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["s7comm"]
    }
    fn description(&self) -> &'static str {
        "Selected legacy S7comm PLC simulator"
    }
    fn example_prompt(&self) -> &'static str {
        "Simulate a PLC on S7comm port 102, supply DB1 reads from a handler"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_server","base_stack":"s7comm","port":102,"instruction":"Supply data-area decisions with structured actions"});
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"s7comm_request","handler":{"type":"static","actions":[reply().example]}}]);
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"s7comm_request","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\na=[{'error':'denied'} for _ in e['items']]\nprint(json.dumps({'actions':[{'type':'s7comm_reply','items':a}]}))"}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
    }
    fn group_name(&self) -> &'static str {
        "Industrial"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![action(
            "disconnect",
            "Close this PLC peer",
            vec![],
            json!({"type":"disconnect"}),
        )]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![reply()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        EVENTS.clone()
    }
    fn metadata(&self) -> crate::protocol::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::PrivilegedPort(102)).implementation("Hand-written TPKT/COTP/S7comm, setup negotiation and selected S7ANY byte items").llm_control("Selected data-area read values, write acceptance and address/access errors; client read/write operations").e2e_testing("Independent python-snap7 peer, malformed framing, error replies and stop/rebind lifecycle").notes("Legacy byte reads/writes only: DB, inputs, outputs, markers. No S7plus, block upload/download, PLC control or persistence. 480-byte PDU, 16 items per request, 200 bytes per item. 30 s first frame, 600 s idle, 256 connections, 10 s client exchange.").max_inbound_bytes(crate::server::s7comm::codec::MAX_FRAME).well_known_port(102).answers_on_failure().history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
}
impl Server for S7commProtocol {
    fn spawn(&self, ctx: SpawnContext) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(crate::server::ics_support::spawn(
            ctx,
            Arc::new(Self),
            super::codec::Device::default,
            &EVENTS,
        ))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ActionResult::CloseConnection);
        }
        ensure!(v["type"] == "s7comm_reply", "unknown S7comm action");
        let items = v["items"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("items required"))?;
        ensure!(
            !items.is_empty() && items.len() <= super::codec::MAX_ITEMS,
            "invalid reply count"
        );
        Ok(ActionResult::Custom {
            name: "s7comm_reply".into(),
            data: v,
        })
    }
}
pub static EVENTS: std::sync::LazyLock<Vec<EventType>> =
    std::sync::LazyLock::new(|| {
        vec![EventType::new(
        "s7comm_request",
        "Legacy data-area read or write: ordered items carry area/db/start/count and write values",
        reply().example.clone(),
    )
    .with_parameters(vec![
        parameter("operation", "string", "Device data read or write operation", true),
        parameter("reference", "number", "S7 PDU reference", true),
        parameter("items", "array", "Requested data area items", true),
    ])
    .with_actions(vec![reply()])]
    });

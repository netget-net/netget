use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::ics_support::{action, parameter};
use crate::state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};
#[derive(Default)]
pub struct S7commClientProtocol;
impl S7commClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn requests() -> Vec<ActionDefinition> {
    let fields = || {
        vec![
            parameter("area", "string", "db, inputs, outputs or markers", true),
            parameter("db", "number", "DB number (0 for non-DB areas)", true),
            parameter("start", "number", "Byte offset (0..2097151)", true),
        ]
    };
    let mut r = fields();
    r.push(parameter("count", "number", "Byte count 1..200", true));
    let mut w = fields();
    w.push(parameter(
        "values",
        "array",
        "Byte elements 0..255, 1..200 elements",
        true,
    ));
    vec![
        action(
            "s7comm_read",
            "Read a legacy data area",
            r,
            json!({"type":"s7comm_read","area":"db","db":1,"start":0,"count":1}),
        ),
        action(
            "s7comm_write",
            "Write a legacy data area",
            w,
            json!({"type":"s7comm_write","area":"db","db":1,"start":0,"values":[42]}),
        ),
        action(
            "disconnect",
            "Close the PLC connection",
            vec![],
            json!({"type":"disconnect"}),
        ),
    ]
}
impl Protocol for S7commClientProtocol {
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
        "Selected legacy S7comm byte-area scanner"
    }
    fn example_prompt(&self) -> &'static str {
        "Read byte 0 of DB1 from the S7comm PLC at 127.0.0.1:102"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_client","protocol":"s7comm","remote_addr":"127.0.0.1:102","instruction":"Supply data-area decisions with structured actions"});
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"s7comm_connected","handler":{"type":"static","actions":[requests()[0].example]}}]);
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"s7comm_connected","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'s7comm_read','area':'db','db':1,'start':0,'count':1}]}))"}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
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
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).implementation("Hand-written TPKT/COTP/S7comm, setup negotiation and selected S7ANY byte items").llm_control("Selected data-area read values, write acceptance and address/access errors; client read/write operations").e2e_testing("Independent python-snap7 peer, malformed framing, error replies and stop/rebind lifecycle").notes("Legacy byte reads/writes only: DB, inputs, outputs, markers. No S7plus, block upload/download, PLC control or persistence. 480-byte PDU, 16 items per request, 200 bytes per item. 30 s first frame, 600 s idle, 256 connections, 10 s client exchange.").max_inbound_bytes(crate::server::s7comm::codec::MAX_FRAME).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
}
impl Client for S7commClientProtocol {
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
        crate::server::s7comm::codec::validate(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().expect("validated").into(),
            data: v,
        })
    }
}
pub static EVENTS: std::sync::LazyLock<Vec<EventType>> = std::sync::LazyLock::new(|| {
    vec![
        EventType::new(
            "s7comm_connected",
            "COTP and S7 setup complete",
            requests()[0].example.clone(),
        )
        .with_actions(requests()),
        EventType::new(
            "s7comm_response",
            "PLC response, including error status",
            requests()[0].example.clone(),
        )
        .with_actions(requests()),
    ]
});

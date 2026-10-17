use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition,
};
use crate::protocol::{EventType, SpawnContext};
use crate::server::p2p_support::{action, parameter};
use crate::state::AppState;
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, LazyLock},
};

#[derive(Default)]
pub struct AdcProtocol;
impl AdcProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn reply() -> ActionDefinition {
    action(
        "adc_reply",
        "Handler-approved identities, public/private chat, search and peer-connect routing",
        vec![parameter(
            "accepted",
            "boolean",
            "Approve identification or forwarding",
            true,
        )],
        json!({"type":"adc_reply","accepted":false}),
    )
}
impl Protocol for AdcProtocol {
    fn protocol_name(&self) -> &'static str {
        "ADC"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ADC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["adc", "adc"]
    }
    fn description(&self) -> &'static str {
        "Selected ADC hub and peer operations listening role"
    }
    fn example_prompt(&self) -> &'static str {
        "Listen on ADC port 1511; supply protocol decisions with handlers"
    }
    fn group_name(&self) -> &'static str {
        "Peer-to-peer"
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        crate::server::p2p_support::tls_parameters(true)
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_server","base_stack":"adc","port":1511,"instruction":"Serve selected ADC operations"});
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"adc_request","handler":{"type":"static","actions":[reply().example]}}]);
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"adc_request","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'adc_reply','error':'denied'}]}))"}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
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
        vec![reply()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        EVENTS.clone()
    }
    fn metadata(&self) -> crate::protocol::ProtocolMetadataV2 {
        crate::protocol::ProtocolMetadataV2::builder().state(crate::protocol::metadata::DevelopmentState::Experimental).implementation("Native bounded ADC selected codec; TCP and optional implicit TLS").llm_control("Handler-approved identities, public/private chat, search and peer-connect routing").e2e_testing("Independent peer exchanges, malformed input, owner shutdown and standalone feature builds").notes("ADC 1.0 BASE/TIGR, anonymous identities with CID/PID validation and per-connection IDs. ADCS uses verified implicit TLS. Selected BINF/BMSG/DMSG/BSCH/DRES/DCTM/DRCM routing. No GPA/PAS password login, UDP search, NAT traversal or persistent hub account database. 256 connections, 30 s first frame, 600 s idle, 10 s handshake/exchange. No persistent protocol data; handlers supply content and decisions.").max_inbound_bytes(super::codec::MAX_COMMAND).well_known_port(1511).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
}
impl Server for AdcProtocol {
    fn spawn(&self, ctx: SpawnContext) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        {
            let hub = Arc::new(super::codec::Hub::default());
            Box::pin(crate::server::p2p_support::spawn(
                ctx,
                Arc::new(Self),
                move || super::codec::Device::new(hub.clone()),
                &EVENTS,
            ))
        }
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ActionResult::CloseConnection);
        }
        ensure!(v["type"] == "adc_reply", "unknown action");
        Ok(ActionResult::Custom {
            name: "adc_reply".into(),
            data: v,
        })
    }
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![EventType::new(
        "adc_request",
        "Handler-approved identities, public/private chat, search and peer-connect routing",
        reply().example,
    )
    .with_actions(vec![reply()])
    .with_parameters(vec![
        parameter("operation", "string", "Selected protocol operation", true),
        parameter(
            "identifier",
            "string",
            "Requested object, message or file identifier",
            false,
        ),
    ])]
});

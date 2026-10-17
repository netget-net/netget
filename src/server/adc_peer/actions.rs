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
pub struct AdcPeerProtocol;
impl AdcPeerProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn reply() -> ActionDefinition {
    action(
        "adc_peer_reply",
        "Handler-supplied file and file-list downloads, ranges and refusals",
        vec![
            parameter(
                "data_base64",
                "string",
                "Complete source bytes; NetGet selects the requested range",
                false,
            ),
            parameter(
                "file_list_xml",
                "string",
                "XML file list, optionally BZip2-compressed",
                false,
            ),
            parameter("error", "string", "Refuse this request", false),
        ],
        json!({"type":"adc_peer_reply","error":"denied"}),
    )
}
impl Protocol for AdcPeerProtocol {
    fn protocol_name(&self) -> &'static str {
        "ADC Peer"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ADC Peer"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["adc_peer", "adc peer"]
    }
    fn description(&self) -> &'static str {
        "Selected ADC Peer file transfers listening role"
    }
    fn example_prompt(&self) -> &'static str {
        "Listen on ADC Peer port 1512; supply protocol decisions with handlers"
    }
    fn group_name(&self) -> &'static str {
        "Peer-to-peer"
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        {
            let mut p = crate::server::p2p_support::tls_parameters(true);
            p.push(crate::llm::actions::ParameterDefinition{name:"cid".into(),description:"Own CID matching the identity announced on the hub; random when omitted".into(),type_hint:"string".into(),required:false,example:json!(""),default:None});
            p
        }
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_server","base_stack":"adc_peer","port":1512,"instruction":"Serve selected ADC Peer operations"});
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"adc_peer_request","handler":{"type":"static","actions":[reply().example]}}]);
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"adc_peer_request","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'adc_peer_reply','error':'denied'}]}))"}}]);
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
        crate::protocol::ProtocolMetadataV2::builder().state(crate::protocol::metadata::DevelopmentState::Experimental).implementation("Native bounded ADC Peer selected codec; TCP and optional implicit TLS").llm_control("Handler-supplied file and file-list downloads, ranges and refusals").e2e_testing("Independent peer exchanges, malformed input, owner shutdown and standalone feature builds").notes("ADC BASE/TIGR CINF negotiation and selected CGET/CSND file ranges; ADCS uses verified implicit TLS. XML/BZip2 file lists and optional full-payload Tiger tree hash verification. 1 MiB per transfer. Direct connections only; no hub token binding, multi-source scheduler, NAT traversal or filesystem access. 256 connections, 30 s first frame, 600 s idle, 10 s handshake/exchange. No persistent protocol data; handlers supply content and decisions.").max_inbound_bytes(super::codec::MAX_COMMAND).well_known_port(1512).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
}
impl Server for AdcPeerProtocol {
    fn spawn(&self, ctx: SpawnContext) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        {
            let configured = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("cid"))
                .transpose();
            let cid = match configured {
                Ok(id) => id.flatten().unwrap_or_else(super::codec::identity),
                Err(e) => return Box::pin(async move { Err(e.into()) }),
            };
            if let Err(e) = crate::server::adc::codec::cid(&cid) {
                return Box::pin(async move { Err(e.into()) });
            }
            Box::pin(crate::server::p2p_support::spawn(
                ctx,
                Arc::new(Self),
                move || super::codec::Device::with_cid(cid.clone()),
                &EVENTS,
            ))
        }
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ActionResult::CloseConnection);
        }
        ensure!(v["type"] == "adc_peer_reply", "unknown action");
        Ok(ActionResult::Custom {
            name: "adc_peer_reply".into(),
            data: v,
        })
    }
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![EventType::new(
        "adc_peer_request",
        "Handler-supplied file and file-list downloads, ranges and refusals",
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

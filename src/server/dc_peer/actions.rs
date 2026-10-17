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
pub struct DcPeerProtocol;
impl DcPeerProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn reply() -> ActionDefinition {
    action(
        "dc_peer_reply",
        "Handler-supplied file and file-list downloads, ranges and refusals",
        vec![
            parameter(
                "data_base64",
                "string",
                "Complete source bytes (1 MiB max); requested range is selected by NetGet",
                false,
            ),
            parameter(
                "file_list_xml",
                "string",
                "XML file list to transmit, optionally BZip2-compressed",
                false,
            ),
            parameter("error", "string", "Refuse this request", false),
        ],
        json!({"type":"dc_peer_reply","data_base64":"SGVsbG8="}),
    )
}
impl Protocol for DcPeerProtocol {
    fn protocol_name(&self) -> &'static str {
        "NMDC Peer"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>NMDC Peer"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["dc_peer", "nmdc peer"]
    }
    fn description(&self) -> &'static str {
        "Selected NMDC Peer file transfers listening role"
    }
    fn example_prompt(&self) -> &'static str {
        "Listen on NMDC Peer port 412; supply protocol decisions with handlers"
    }
    fn group_name(&self) -> &'static str {
        "Peer-to-peer"
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        let mut fields = crate::server::p2p_support::tls_parameters(true);
        fields.push(crate::server::dc_peer::codec::nickname_parameter(
            crate::server::dc_peer::codec::DEFAULT_LISTENER_NICKNAME,
        ));
        fields
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_server","base_stack":"dc_peer","port":412,"instruction":"Serve selected NMDC Peer operations"});
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"dc_peer_request","handler":{"type":"static","actions":[reply().example]}}]);
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"dc_peer_request","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'dc_peer_reply','error':'denied'}]}))"}}]);
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
        crate::protocol::ProtocolMetadataV2::builder().state(crate::protocol::metadata::DevelopmentState::Experimental).implementation("Native bounded NMDC Peer selected codec; TCP and optional implicit TLS").llm_control("Handler-supplied file and file-list downloads, ranges and refusals").e2e_testing("Independent peer exchanges, malformed input, owner shutdown and standalone feature builds").notes("NMDC uploader/listener and downloader/connector. ADCGET/ADCSND file requests, XML/BZip2 file lists and optional full-payload Tiger tree hash verification. Configurable local nickname must match hub rendezvous identity. 1 MiB per transfer; no filesystem access, multi-source scheduler, peer discovery or push uploads. 256 connections, 30 s first frame, 600 s idle, 10 s handshake/exchange. No persistent protocol data; handlers supply content and decisions.").max_inbound_bytes(super::codec::MAX_COMMAND).well_known_port(412).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
}
impl Server for DcPeerProtocol {
    fn spawn(&self, ctx: SpawnContext) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(async move {
            let name = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("nickname"))
                .transpose()?
                .flatten()
                .unwrap_or_else(|| super::codec::DEFAULT_LISTENER_NICKNAME.into());
            super::codec::nickname(&name)?;
            crate::server::p2p_support::spawn(
                ctx,
                Arc::new(Self),
                move || super::codec::Device::with_nickname(name.clone()),
                &EVENTS,
            )
            .await
        })
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ActionResult::CloseConnection);
        }
        ensure!(v["type"] == "dc_peer_reply", "unknown action");
        Ok(ActionResult::Custom {
            name: "dc_peer_reply".into(),
            data: v,
        })
    }
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![EventType::new(
        "dc_peer_request",
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

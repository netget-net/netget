use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::p2p_support::{action, parameter};
use crate::state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::LazyLock};

#[derive(Default)]
pub struct DcPeerClientProtocol;
impl DcPeerClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn requests() -> Vec<ActionDefinition> {
    vec![
        action(
            "dc_peer_get",
            "Download a file or file list",
            vec![
                parameter(
                    "identifier",
                    "string",
                    "TTH/hash, files.xml.bz2 or relative file identifier",
                    true,
                ),
                parameter(
                    "offset",
                    "number",
                    "Starting byte offset within the requested file (zero based)",
                    true,
                ),
                parameter(
                    "length",
                    "number",
                    "Bytes to transfer (0..1048576) or -1 for remainder",
                    true,
                ),
                parameter(
                    "expected_tth",
                    "string",
                    "Optional whole-payload Tiger tree hash",
                    false,
                ),
            ],
            json!({"type":"dc_peer_get","identifier":"files.xml.bz2","offset":0,"length":-1}),
        ),
        action(
            "disconnect",
            "Close this peer",
            vec![],
            json!({"type":"disconnect"}),
        ),
    ]
}
impl Protocol for DcPeerClientProtocol {
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
        "Selected NMDC Peer file transfers connecting role"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to NMDC Peer on 127.0.0.1:412"
    }
    fn group_name(&self) -> &'static str {
        "Peer-to-peer"
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        let mut fields = crate::server::p2p_support::tls_parameters(false);
        fields.push(crate::server::dc_peer::codec::nickname_parameter(
            crate::server::dc_peer::codec::DEFAULT_CONNECTOR_NICKNAME,
        ));
        fields
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_client","protocol":"dc_peer","remote_addr":"127.0.0.1:412","instruction":"Use selected NMDC Peer operations"});
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"dc_peer_connected","handler":{"type":"static","actions":[requests()[0].example]}}]);
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"dc_peer_connected","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'disconnect'}]}))"}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
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
        crate::protocol::ProtocolMetadataV2::builder().state(crate::protocol::metadata::DevelopmentState::Experimental).implementation("Native bounded NMDC Peer selected codec; TCP and optional implicit TLS").llm_control("Handler-supplied file and file-list downloads, ranges and refusals").e2e_testing("Independent peer exchanges, malformed input, owner shutdown and standalone feature builds").notes("NMDC uploader/listener and downloader/connector. ADCGET/ADCSND file requests, XML/BZip2 file lists and optional full-payload Tiger tree hash verification. Configurable local nickname must match hub rendezvous identity. 1 MiB per transfer; no filesystem access, multi-source scheduler, peer discovery or push uploads. 256 connections, 30 s first frame, 600 s idle, 10 s handshake/exchange. No persistent protocol data; handlers supply content and decisions.").max_inbound_bytes(crate::server::dc_peer::codec::MAX_COMMAND).well_known_port(412).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
}
impl Client for DcPeerClientProtocol {
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
        crate::server::dc_peer::codec::validate(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().expect("validated type").into(),
            data: v,
        })
    }
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![
        EventType::new(
            "dc_peer_connected",
            "Peer negotiation completed",
            json!({"type":"disconnect"}),
        )
        .with_actions(requests()),
        EventType::new(
            "dc_peer_response",
            "Protocol response or incoming message",
            json!({"type":"disconnect"}),
        )
        .with_actions(requests()),
    ]
});

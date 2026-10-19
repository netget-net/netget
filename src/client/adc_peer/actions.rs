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
pub struct AdcPeerClientProtocol;
impl AdcPeerClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn requests() -> Vec<ActionDefinition> {
    vec![
        action(
            "adc_peer_get",
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
            json!({"type":"adc_peer_get","identifier":"files.xml.bz2","offset":0,"length":-1}),
        ),
        action(
            "disconnect",
            "Close this peer",
            vec![],
            json!({"type":"disconnect"}),
        ),
    ]
}
impl Protocol for AdcPeerClientProtocol {
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
        "Selected ADC Peer file transfers connecting role"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to ADC Peer on 127.0.0.1:1512"
    }
    fn group_name(&self) -> &'static str {
        "Peer-to-peer"
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        {
            let mut p = crate::server::p2p_support::tls_parameters(false);
            for (name, description) in [
                (
                    "cid",
                    "Own ADC CID matching the identity announced on the hub",
                ),
                ("token", "Rendezvous token from DCTM/DRCM"),
            ] {
                p.push(crate::llm::actions::ParameterDefinition {
                    name: name.into(),
                    description: description.into(),
                    type_hint: "string".into(),
                    required: false,
                    example: json!(""),
                    default: None,
                });
            }
            p
        }
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_client","protocol":"adc_peer","remote_addr":"127.0.0.1:1512","instruction":"Use selected ADC Peer operations"});
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"adc_peer_connected","handler":{"type":"static","actions":[requests()[0].example]}}]);
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"adc_peer_connected","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'disconnect'}]}))"}}]);
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
        crate::protocol::ProtocolMetadataV2::builder().state(crate::protocol::metadata::DevelopmentState::Experimental).implementation("Native bounded ADC Peer selected codec; TCP and optional implicit TLS").llm_control("Handler-supplied file and file-list downloads, ranges and refusals").e2e_testing("Independent peer exchanges, malformed input, owner shutdown and standalone feature builds").notes("ADC BASE/TIGR CINF negotiation and selected CGET/CSND file ranges; ADCS uses verified implicit TLS. XML/BZip2 file lists and optional full-payload Tiger tree hash verification. 1 MiB per transfer. Direct connections only; no hub token binding, multi-source scheduler, NAT traversal or filesystem access. 256 connections, 30 s first frame, 600 s idle, 10 s handshake/exchange. No persistent protocol data; handlers supply content and decisions.").max_inbound_bytes(crate::server::adc_peer::codec::MAX_COMMAND).well_known_port(1512).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        // Replies queue on the shared p2p_support::connect runner; what arrives while the
        // model answers is answered together (call_llm_for_client_batch).
        .batching(crate::protocol::metadata::BatchingMode::On)
        .build()
    }
}
impl Client for AdcPeerClientProtocol {
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
        crate::server::adc_peer::codec::validate(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().expect("validated type").into(),
            data: v,
        })
    }
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![
        EventType::new(
            "adc_peer_connected",
            "Peer negotiation completed",
            json!({"type":"disconnect"}),
        )
        .with_actions(requests()),
        EventType::new(
            "adc_peer_response",
            "Protocol response or incoming message",
            json!({"type":"disconnect"}),
        )
        .with_actions(requests()),
    ]
});

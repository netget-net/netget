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
pub struct AdcClientProtocol;
impl AdcClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn requests() -> Vec<ActionDefinition> {
    vec![
        action(
            "adc_chat",
            "Send public or private chat",
            vec![
                parameter(
                    "message",
                    "string",
                    "UTF-8 chat message to send to the hub or selected peer",
                    true,
                ),
                parameter("destination", "string", "Optional destination SID", false),
            ],
            json!({"type":"adc_chat","message":"Hello"}),
        ),
        action(
            "adc_search",
            "Broadcast a filename search through the connected ADC hub",
            vec![parameter("query", "string", "Filename search term", true)],
            json!({"type":"adc_search","query":"test"}),
        ),
        action(
            "adc_connect",
            "Request a direct peer transfer connection",
            vec![
                parameter(
                    "destination",
                    "string",
                    "Four-character session ID of the destination ADC hub peer",
                    true,
                ),
                parameter("port", "number", "Listening peer transfer port", true),
                parameter("token", "string", "Connection token", true),
                parameter(
                    "secure",
                    "boolean",
                    "Request an implicit TLS peer connection using ADCS/1.0",
                    false,
                ),
            ],
            json!({"type":"adc_connect","destination":"AAAB","port":1512,"token":"netget"}),
        ),
        action(
            "adc_reverse_connect",
            "Ask a peer to initiate rendezvous",
            vec![
                parameter("destination", "string", "Destination SID", true),
                parameter("token", "string", "Rendezvous token", true),
                parameter(
                    "secure",
                    "boolean",
                    "Request an implicit TLS peer connection rather than cleartext ADC",
                    false,
                ),
            ],
            json!({"type":"adc_reverse_connect","destination":"AAAA","token":"1"}),
        ),
        action(
            "adc_search_result",
            "Send a search result to a peer",
            vec![
                parameter("destination", "string", "Destination SID", true),
                parameter(
                    "identifier",
                    "string",
                    "Shared relative file name returned in the search result",
                    true,
                ),
                parameter("size", "number", "Unsigned byte count", true),
                parameter("tth", "string", "Tiger tree hash", true),
                parameter(
                    "token",
                    "string",
                    "Correlation token from the original ADC search request",
                    true,
                ),
            ],
            json!({"type":"adc_search_result","destination":"AAAA","identifier":"hello.txt","size":5,"tth":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","token":"1"}),
        ),
        action(
            "disconnect",
            "Close this peer",
            vec![],
            json!({"type":"disconnect"}),
        ),
    ]
}
impl Protocol for AdcClientProtocol {
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
        "Selected ADC hub and peer operations connecting role"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to ADC on 127.0.0.1:1511"
    }
    fn group_name(&self) -> &'static str {
        "Peer-to-peer"
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        crate::server::p2p_support::tls_parameters(false)
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_client","protocol":"adc","remote_addr":"127.0.0.1:1511","instruction":"Use selected ADC operations"});
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"adc_connected","handler":{"type":"static","actions":[requests()[0].example]}}]);
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"adc_connected","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'disconnect'}]}))"}}]);
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
        crate::protocol::ProtocolMetadataV2::builder().state(crate::protocol::metadata::DevelopmentState::Experimental).implementation("Native bounded ADC selected codec; TCP and optional implicit TLS").llm_control("Handler-approved identities, public/private chat, search and peer-connect routing").e2e_testing("Independent peer exchanges, malformed input, owner shutdown and standalone feature builds").notes("ADC 1.0 BASE/TIGR, anonymous identities with CID/PID validation and per-connection IDs. ADCS uses verified implicit TLS. Selected BINF/BMSG/DMSG/BSCH/DRES/DCTM/DRCM routing. No GPA/PAS password login, UDP search, NAT traversal or persistent hub account database. 256 connections, 30 s first frame, 600 s idle, 10 s handshake/exchange. No persistent protocol data; handlers supply content and decisions.").max_inbound_bytes(crate::server::adc::codec::MAX_COMMAND).well_known_port(1511).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        // Replies queue on the shared p2p_support::connect runner; what arrives while the
        // model answers is answered together (call_llm_for_client_batch).
        .batching(crate::protocol::metadata::BatchingMode::On)
        .build()
    }
}
impl Client for AdcClientProtocol {
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
        crate::server::adc::codec::validate(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().expect("validated type").into(),
            data: v,
        })
    }
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![
        EventType::new(
            "adc_connected",
            "Peer negotiation completed",
            json!({"type":"disconnect"}),
        )
        .with_actions(requests()),
        EventType::new(
            "adc_response",
            "Protocol response or incoming message",
            json!({"type":"disconnect"}),
        )
        .with_actions(requests()),
    ]
});

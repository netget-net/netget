//! What the model can do as a devp2p dialler: choose this node's Status, ask the peer for
//! headers, bodies and pooled transactions, answer the peer's requests, and disconnect.
//!
//! The actions and the session events are the server's (`crate::server::devp2p::actions`):
//! after the handshake both ends of a devp2p session speak the same protocol. What differs is
//! the Status event — a dialler may have to speak first — and the two events only a client has,
//! `devp2p_error` and `devp2p_disconnected`.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::server::devp2p::actions as shared;
use crate::server::devp2p::actions::p;
use crate::server::devp2p::session;
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct Devp2pClientProtocol;

impl Devp2pClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub static STATUS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "eth_status",
        "The RLPx handshake and Hello are done and this node must send its eth Status. \
         peer_status is the peer's own Status, or null when the peer is waiting for ours. Send \
         eth_send_status (requests in the same answer go out once both Statuses are \
         exchanged) or devp2p_disconnect",
        json!({"type": session::SEND_STATUS, "mirror_peer": true}),
    )
    .with_parameters(vec![
        p("remote", "string", "The peer's address", true),
        p("client_id", "string", "The client id from its Hello", true),
        p(
            "node_id",
            "string",
            "Its node id (128 hex characters)",
            true,
        ),
        p("capabilities", "array", "Capabilities from its Hello", true),
        p(
            "eth_version",
            "number",
            "The eth version both sides speak",
            true,
        ),
        p(
            "peer_status",
            "object",
            "Its Status, or null if it has not sent one yet",
            true,
        ),
        p(
            "configured",
            "object",
            "The Status values configured at startup",
            true,
        ),
    ])
    .with_actions(shared::all_actions())
    .with_alternative_example(json!({"type": session::DISCONNECT, "reason": "useless_peer"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("devp2p connected to {client_id} at {remote}, eth/{eth_version}")
            .with_trace("devp2p status: {json_pretty(.)}"),
    )
});

pub static HEADERS_REQUESTED_EVENT: LazyLock<EventType> =
    LazyLock::new(|| shared::HEADERS_REQUESTED_EVENT.clone());
pub static BODIES_REQUESTED_EVENT: LazyLock<EventType> =
    LazyLock::new(|| shared::BODIES_REQUESTED_EVENT.clone());
pub static POOLED_REQUESTED_EVENT: LazyLock<EventType> =
    LazyLock::new(|| shared::POOLED_REQUESTED_EVENT.clone());
pub static ANNOUNCED_EVENT: LazyLock<EventType> = LazyLock::new(|| shared::ANNOUNCED_EVENT.clone());
pub static HEADERS_RECEIVED_EVENT: LazyLock<EventType> =
    LazyLock::new(|| shared::HEADERS_RECEIVED_EVENT.clone());
pub static BODIES_RECEIVED_EVENT: LazyLock<EventType> =
    LazyLock::new(|| shared::BODIES_RECEIVED_EVENT.clone());
pub static POOLED_RECEIVED_EVENT: LazyLock<EventType> =
    LazyLock::new(|| shared::POOLED_RECEIVED_EVENT.clone());
pub static REQUEST_TIMEOUT_EVENT: LazyLock<EventType> =
    LazyLock::new(|| shared::REQUEST_TIMEOUT_EVENT.clone());

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "devp2p_error",
        "An action could not be carried out; nothing was sent for it",
        json!({"type": session::REQUEST_HEADERS, "origin": 0}),
    )
    .with_parameters(vec![
        p("action", "string", "The action's type", true),
        p("message", "string", "Why it was refused", true),
    ])
    .with_actions(shared::all_actions())
    .with_log_template(LogTemplate::new().with_info("devp2p {action} refused: {message}"))
});

pub static DISCONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "devp2p_disconnected",
        "The session ended. Nothing more can be sent on it",
        json!({"type": "show_message", "message": "devp2p session ended"}),
    )
    .with_parameters(vec![p(
        "reason",
        "string",
        "Why the session ended, and which side ended it",
        true,
    )])
    .with_no_actions()
    .with_log_template(LogTemplate::new().with_info("devp2p session ended: {reason}"))
});

impl Protocol for Devp2pClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "devp2p"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>RLPx>devp2p"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "devp2p",
            "ethereum",
            "eth/68",
            "eth/69",
            "rlpx",
            "enode",
            "geth",
            "ethereum client",
        ]
    }
    fn description(&self) -> &'static str {
        "Ethereum devp2p dialler: connects to a node by enode URL over RLPx, exchanges Hello and an eth Status the LLM chooses, and fetches block headers, bodies and pooled transactions with hashes computed locally"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        shared::all_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            STATUS_EVENT.clone(),
            HEADERS_REQUESTED_EVENT.clone(),
            BODIES_REQUESTED_EVENT.clone(),
            POOLED_REQUESTED_EVENT.clone(),
            ANNOUNCED_EVENT.clone(),
            HEADERS_RECEIVED_EVENT.clone(),
            BODIES_RECEIVED_EVENT.clone(),
            POOLED_RECEIVED_EVENT.clone(),
            REQUEST_TIMEOUT_EVENT.clone(),
            ERROR_EVENT.clone(),
            DISCONNECTED_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        shared::common_startup_parameters()
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's hand-written RLPx (EIP-8 handshake as the initiator, AES-256-CTR frames, keccak MACs, Snappy), RLP codec, Hello and eth/68 and eth/69, dialled to an enode URL. Every header received is decoded and hashed here; a response is checked against the request it answers")
            .llm_control("This node's Status (eth_status, with the peer's Status when it has sent one), the header, body and pooled-transaction requests to send, answers to the peer's requests, and when to disconnect")
            .e2e_testing("tests/client/devp2p: go-ethereum 1.17 and reth 2.7, each on a private dev chain with blocks, accept NetGet's handshake and eth/69 Status and serve headers whose computed hashes match their own eth_getBlockByNumber")
            .notes("Experimental: two independent servers (go-ethereum and reth) drive it in tests that fail rather than skip, but nobody has reviewed it and its pair job had not run in CI when it landed. No discovery: the peer is named by its enode URL. No snap protocol. Received bodies are decoded (transaction hashes, uncles, withdrawals) but not checked against the header's transactionsRoot.")
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to enode://<node id>@127.0.0.1:30303, mirror its Status, and fetch the first four block headers"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let enode = format!("enode://{}@127.0.0.1:30303", "8a".repeat(64));
        let llm = json!({"type": "open_client", "protocol": "devp2p", "remote_addr": enode,
            "instruction": "Mirror the peer's Status, then fetch headers 0 to 3 and report their hashes"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "eth_status", "handler": {"type": "static", "actions": [
                {"type": session::SEND_STATUS, "mirror_peer": true},
                {"type": session::REQUEST_HEADERS, "origin": 0, "amount": 4}
            ]}},
            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0] = json!({"event_pattern": "eth_status", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ne=json.load(sys.stdin)['event']\nlatest=(e.get('peer_status') or {}).get('latest_block',0)\nprint(json.dumps({'actions':[{'type':'eth_send_status','mirror_peer':e.get('peer_status') is not None},{'type':'eth_request_block_headers','origin':latest,'amount':1}]}))"}});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Blockchain"
    }
}

impl Client for Devp2pClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }

    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        session::parse_command(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}

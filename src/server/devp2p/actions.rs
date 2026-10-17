//! What the model decides on a devp2p node: whether to admit a peer and with what Status, how
//! to answer its `eth` requests, and what to ask it for.
//!
//! Rust owns everything under that — the RLPx handshake and frame encryption, Snappy, RLP, the
//! Hello exchange, Ping/Pong, block hashes. The model writes headers as the JSON fields
//! `eth_getBlockByNumber` returns and never a byte of RLP; Rust encodes them, hashes them, and
//! refuses an answer whose headers are not the ones the peer asked for (wrong numbers, a first
//! hash that is not the requested one, a header whose parentHash is not the previous header's
//! hash, or a `hash` field the fields do not produce).
//!
//! The action definitions here are shared with the client (`src/client/devp2p/actions.rs`):
//! once the handshake is done both sides of a devp2p session speak the same protocol.
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::devp2p::session::{self, StatusDefaults};
use crate::server::devp2p::{crypto::NodeKey, eth};
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// The client id NetGet sends in Hello unless configured otherwise.
pub fn default_client_id() -> String {
    format!("NetGet/v{}", env!("CARGO_PKG_VERSION"))
}

#[derive(Clone, Default)]
pub struct Devp2pProtocol;

impl Devp2pProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
    }
}

/// A complete, valid header for examples: block 1 of an empty post-Cancun chain.
pub fn example_header() -> Value {
    let z32 = format!("0x{}", "00".repeat(32));
    json!({
        "parentHash": format!("0x{}", "11".repeat(32)),
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "miner": format!("0x{}", "00".repeat(20)),
        "stateRoot": format!("0x{}", "22".repeat(32)),
        "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "difficulty": "0x0",
        "number": "0x1",
        "gasLimit": "0x1c9c380",
        "gasUsed": "0x0",
        "timestamp": "0x6553f100",
        "extraData": "0x",
        "mixHash": z32,
        "nonce": "0x0000000000000000",
        "baseFeePerGas": "0x3b9aca00"
    })
}

fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(
            LogTemplate::new()
                .with_info(format!("devp2p {name}"))
                .with_debug(format!("devp2p {name}: {{json(.)}}")),
        ),
    }
}

pub fn send_status_action() -> ActionDefinition {
    action(
        session::SEND_STATUS,
        "Send this node's eth Status, which admits the peer: the eth handshake completes when \
         both Statuses are exchanged. Fields left out come from the peer's Status when \
         mirror_peer is true, else from the startup configuration. The fork hash, when no one \
         gives it, is computed from genesis_hash and forks (EIP-2124). A peer on another \
         network or genesis will drop the session itself.",
        vec![
            p("mirror_peer", "boolean", "Copy every field not given here from the peer's own Status (claim its chain and head)", false),
            p("network_id", "number", "Network id (1 is mainnet)", false),
            p("genesis_hash", "string", "0x-prefixed 32-byte genesis block hash", false),
            p("fork_hash", "string", "0x-prefixed 4-byte EIP-2124 fork hash", false),
            p("fork_next", "number", "Next fork block or timestamp, 0 for none", false),
            p("forks", "array", "Fork block numbers or timestamps this chain has passed, to compute fork_hash from", false),
            p("earliest_block", "number", "eth/69: oldest block served", false),
            p("latest_block", "number", "eth/69: newest block number", false),
            p("latest_block_hash", "string", "eth/69: newest block hash", false),
            p("total_difficulty", "number", "eth/68: total difficulty", false),
            p("head_hash", "string", "eth/68: head block hash", false),
        ],
        json!({"type": session::SEND_STATUS, "mirror_peer": true}),
    )
}

pub fn send_headers_action() -> ActionDefinition {
    action(
        session::SEND_HEADERS,
        "Answer a GetBlockHeaders with block headers, each an object of the fields \
         eth_getBlockByNumber returns (parentHash, sha3Uncles, miner, stateRoot, \
         transactionsRoot, receiptsRoot, logsBloom, difficulty, number, gasLimit, gasUsed, \
         timestamp, extraData, mixHash, nonce, then baseFeePerGas, withdrawalsRoot, \
         blobGasUsed, excessBlobGas, parentBeaconBlockRoot, requestsHash when the chain has \
         them). NetGet encodes and hashes them; the first must be the requested block, the \
         numbers must follow the request's skip and direction, each must name the previous as \
         its parent, and a 'hash' field must equal the computed hash. An empty list says \
         'I do not have them'.",
        vec![
            p(
                "headers",
                "array",
                "Header objects, at most the amount requested",
                true,
            ),
            p(
                "request_id",
                "number",
                "The request answered; defaults to the one in the event",
                false,
            ),
        ],
        json!({"type": session::SEND_HEADERS, "headers": [example_header()]}),
    )
}

pub fn send_bodies_action() -> ActionDefinition {
    action(
        session::SEND_BODIES,
        "Answer a GetBlockBodies: one body per requested hash, in order (fewer is allowed). A \
         body is {transactions: [signed transactions as 0x-hex, as eth_getRawTransactionByHash \
         returns them], uncles: [header objects], withdrawals: [{index, validatorIndex, \
         address, amount}] for post-Shanghai blocks}. An empty list says 'I do not have them'.",
        vec![
            p(
                "bodies",
                "array",
                "One block body per requested hash, in the order requested",
                true,
            ),
            p(
                "request_id",
                "number",
                "The request answered; defaults to the one in the event",
                false,
            ),
        ],
        json!({"type": session::SEND_BODIES, "bodies": [{"transactions": [], "uncles": [], "withdrawals": []}]}),
    )
}

pub fn send_pooled_action() -> ActionDefinition {
    action(
        session::SEND_POOLED,
        "Answer a GetPooledTransactions with signed transactions (0x-hex canonical encodings). \
         NetGet hashes each one and refuses any the peer did not ask for. An empty list says \
         'I do not have them'.",
        vec![
            p("transactions", "array", "Signed transactions, 0x-hex", true),
            p(
                "request_id",
                "number",
                "The request answered; defaults to the one in the event",
                false,
            ),
        ],
        json!({"type": session::SEND_POOLED, "transactions": []}),
    )
}

pub fn request_headers_action() -> ActionDefinition {
    action(
        session::REQUEST_HEADERS,
        "Ask the peer for block headers (GetBlockHeaders). The answer arrives as \
         eth_block_headers_received with every header decoded and its hash computed.",
        vec![
            p(
                "origin",
                "number",
                "First block: a number, or a 0x-prefixed 32-byte block hash",
                true,
            ),
            p(
                "amount",
                "number",
                "How many headers, 1 to 64 (default 1)",
                false,
            ),
            p(
                "skip",
                "number",
                "Blocks skipped between consecutive headers (default 0)",
                false,
            ),
            p(
                "reverse",
                "boolean",
                "Walk towards genesis instead of the head (default false)",
                false,
            ),
        ],
        json!({"type": session::REQUEST_HEADERS, "origin": 0, "amount": 4}),
    )
}

pub fn request_bodies_action() -> ActionDefinition {
    action(
        session::REQUEST_BODIES,
        "Ask the peer for block bodies by block hash (GetBlockBodies). The answer arrives as \
         eth_block_bodies_received.",
        vec![p("hashes", "array", "Block hashes, 0x-hex, 1 to 256", true)],
        json!({"type": session::REQUEST_BODIES, "hashes": [format!("0x{}", "ab".repeat(32))]}),
    )
}

pub fn request_pooled_action() -> ActionDefinition {
    action(
        session::REQUEST_POOLED,
        "Ask the peer for transactions from its pool by hash (GetPooledTransactions), \
         typically ones it announced. The answer arrives as eth_pooled_transactions_received.",
        vec![p(
            "hashes",
            "array",
            "Transaction hashes, 0x-hex, 1 to 256",
            true,
        )],
        json!({"type": session::REQUEST_POOLED, "hashes": [format!("0x{}", "cd".repeat(32))]}),
    )
}

pub fn disconnect_action() -> ActionDefinition {
    action(
        session::DISCONNECT,
        "Send Disconnect with a reason and close the session. Reasons: requested, \
         useless_peer, too_many_peers, already_connected, incompatible_version, \
         breach_of_protocol, subprotocol_error, client_quitting.",
        vec![p(
            "reason",
            "string",
            "The reason (default requested)",
            false,
        )],
        json!({"type": session::DISCONNECT, "reason": "useless_peer"}),
    )
}

/// Every action, in the order the model sees them.
pub fn all_actions() -> Vec<ActionDefinition> {
    vec![
        send_status_action(),
        send_headers_action(),
        send_bodies_action(),
        send_pooled_action(),
        request_headers_action(),
        request_bodies_action(),
        request_pooled_action(),
        disconnect_action(),
    ]
}

fn requests() -> Vec<ActionDefinition> {
    vec![
        request_headers_action(),
        request_bodies_action(),
        request_pooled_action(),
        disconnect_action(),
    ]
}

fn with(first: Vec<ActionDefinition>) -> Vec<ActionDefinition> {
    let mut v = first;
    v.extend(requests());
    v
}

pub static STATUS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "eth_status",
        "A peer completed the RLPx handshake and Hello and sent its eth Status. Admit it with \
         eth_send_status (follow-up requests may come in the same answer) or refuse it with \
         devp2p_disconnect",
        json!({"type": session::SEND_STATUS, "mirror_peer": true}),
    )
    .with_parameters(vec![
        p("remote", "string", "The peer's address", true),
        p("client_id", "string", "The client id from its Hello", true),
        p("node_id", "string", "Its node id (128 hex characters)", true),
        p("capabilities", "array", "Capabilities from its Hello, as name/version", true),
        p("eth_version", "number", "The eth version both sides speak", true),
        p("peer_status", "object", "Its Status: network_id, genesis_hash, fork_hash, fork_next, and the eth/69 block range or eth/68 total difficulty and head", true),
        p("configured", "object", "The Status values configured at startup", true),
    ])
    .with_actions(with(vec![send_status_action()]))
    .with_alternative_example(json!({"type": session::DISCONNECT, "reason": "useless_peer"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("devp2p peer {client_id} at {remote} sent its Status")
            .with_trace("devp2p status: {json_pretty(.)}"),
    )
});

pub static HEADERS_REQUESTED_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        EventType::new(
        "eth_block_headers_requested",
        "The peer asked for block headers. Answer with eth_send_block_headers (an empty list if \
         you do not have them); a request left unanswered closes the session",
        json!({"type": session::SEND_HEADERS, "headers": []}),
    )
    .with_parameters(vec![
        p("request_id", "number", "The request's id", true),
        p("origin", "number", "First block: a number, or a 0x block hash", true),
        p("amount", "number", "How many headers at most", true),
        p("skip", "number", "Blocks between consecutive headers", true),
        p("reverse", "boolean", "Towards genesis instead of the head", true),
    ])
    .with_actions(with(vec![send_headers_action()]))
    .with_log_template(
        LogTemplate::new()
            .with_info("devp2p peer asks for {amount} headers from {origin}")
            .with_debug("devp2p GetBlockHeaders: {json(.)}"),
    )
    });

pub static BODIES_REQUESTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "eth_block_bodies_requested",
        "The peer asked for block bodies by hash. Answer with eth_send_block_bodies (an empty \
         list if you do not have them)",
        json!({"type": session::SEND_BODIES, "bodies": []}),
    )
    .with_parameters(vec![
        p("request_id", "number", "The request's id", true),
        p(
            "hashes",
            "array",
            "The hashes of the blocks whose bodies are wanted",
            true,
        ),
    ])
    .with_actions(with(vec![send_bodies_action()]))
    .with_log_template(LogTemplate::new().with_info("devp2p peer asks for block bodies"))
});

pub static POOLED_REQUESTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "eth_pooled_transactions_requested",
        "The peer asked for transactions from this node's pool. Answer with \
         eth_send_pooled_transactions (an empty list if you do not have them)",
        json!({"type": session::SEND_POOLED, "transactions": []}),
    )
    .with_parameters(vec![
        p("request_id", "number", "The request's id", true),
        p("hashes", "array", "Transaction hashes", true),
    ])
    .with_actions(with(vec![send_pooled_action()]))
    .with_log_template(LogTemplate::new().with_info("devp2p peer asks for pooled transactions"))
});

pub static ANNOUNCED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "eth_transactions_announced",
        "The peer announced transactions in its pool (NewPooledTransactionHashes). Request \
         them with eth_request_pooled_transactions, or do nothing",
        json!({"type": session::REQUEST_POOLED, "hashes": [format!("0x{}", "cd".repeat(32))]}),
    )
    .with_parameters(vec![p(
        "transactions",
        "array",
        "Announced transactions: hash, type and size",
        true,
    )])
    .with_actions(requests())
    .with_log_template(LogTemplate::new().with_info("devp2p peer announced transactions"))
});

pub static HEADERS_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "eth_block_headers_received",
        "The peer answered a header request. Every header is decoded with its computed hash; \
         matches_request says whether they are the blocks asked for, linked whether each \
         names the previous as its parent",
        json!({"type": session::REQUEST_HEADERS, "origin": 4, "amount": 4}),
    )
    .with_parameters(vec![
        p("request_id", "number", "The request answered", true),
        p(
            "request",
            "object",
            "The request this answers: its kind and its query or hashes",
            true,
        ),
        p("count", "number", "How many headers came back", true),
        p(
            "headers",
            "array",
            "Header fields and hash, by eth_getBlockByNumber names",
            true,
        ),
        p(
            "matches_request",
            "boolean",
            "The numbers (or first hash) are the ones asked for",
            true,
        ),
        p(
            "linked",
            "boolean",
            "Each header's parentHash is the previous header's hash",
            true,
        ),
    ])
    .with_actions(requests())
    .with_log_template(
        LogTemplate::new()
            .with_info("devp2p received {count} headers")
            .with_trace("devp2p headers: {json_pretty(.)}"),
    )
});

pub static BODIES_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "eth_block_bodies_received",
        "The peer answered a body request: per block, its transactions (hash, type, size), \
         uncles and withdrawals",
        json!({"type": session::REQUEST_HEADERS, "origin": 0}),
    )
    .with_parameters(vec![
        p("request_id", "number", "The request answered", true),
        p(
            "request",
            "object",
            "The request this answers: its kind and its query or hashes",
            true,
        ),
        p("count", "number", "How many bodies came back", true),
        p(
            "bodies",
            "array",
            "Per block: its hash, transactions (hash, type, size), uncles and withdrawals",
            true,
        ),
    ])
    .with_actions(requests())
    .with_log_template(LogTemplate::new().with_info("devp2p received {count} block bodies"))
});

pub static POOLED_RECEIVED_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        EventType::new(
        "eth_pooled_transactions_received",
        "The peer answered a pooled-transaction request: each transaction's hash, type and size",
        json!({"type": session::REQUEST_POOLED, "hashes": [format!("0x{}", "cd".repeat(32))]}),
    )
    .with_parameters(vec![
        p("request_id", "number", "The request answered", true),
        p("request", "object", "The request this answers: its kind and its query or hashes", true),
        p("count", "number", "How many came back", true),
        p("transactions", "array", "hash, type and size of each", true),
        p("unrequested", "number", "How many were not asked for", true),
    ])
    .with_actions(requests())
    .with_log_template(LogTemplate::new().with_info("devp2p received {count} pooled transactions"))
    });

pub static REQUEST_TIMEOUT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "eth_request_timed_out",
        "A request this node sent got no answer in time; it is forgotten",
        json!({"type": session::REQUEST_HEADERS, "origin": 0}),
    )
    .with_parameters(vec![
        p(
            "request_id",
            "number",
            "The id of the request that went unanswered",
            true,
        ),
        p(
            "request",
            "object",
            "The request this answers: its kind and its query or hashes",
            true,
        ),
        p("timeout_secs", "number", "How long NetGet waited", true),
    ])
    .with_actions(requests())
    .with_log_template(LogTemplate::new().with_info("devp2p request {request_id} timed out"))
});

pub fn event_types() -> Vec<EventType> {
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
    ]
}

/// The startup parameters both roles share: identity and the Status defaults.
pub fn common_startup_parameters() -> Vec<ParameterDefinition> {
    let param =
        |name: &str, type_hint: &str, description: &str, example: Value| ParameterDefinition {
            name: name.into(),
            type_hint: type_hint.into(),
            description: description.into(),
            required: false,
            example,
            default: None,
        };
    vec![
        param(
            "node_private_key",
            "string",
            "The node's secp256k1 private key, 64 hex characters; its public key is the node id \
             in the enode URL. Without it a fresh key is made at start",
            json!("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"),
        ),
        ParameterDefinition {
            name: "client_id".into(),
            type_hint: "string".into(),
            description: "The client id sent in Hello (peers show it as the node's name)".into(),
            required: false,
            example: json!("NetGet/v1.0/linux"),
            default: Some(json!(default_client_id())),
        },
        param(
            "network_id",
            "number",
            "Status default: network id (1 is mainnet)",
            json!(1337),
        ),
        param(
            "genesis_hash",
            "string",
            "Status default: 0x-prefixed genesis block hash",
            json!(format!("0x{}", "00".repeat(32))),
        ),
        param(
            "forks",
            "array",
            "Status default: fork block numbers or timestamps the chain has passed, for the \
             EIP-2124 fork hash (forks at genesis are left out)",
            json!([1150000, 1920000]),
        ),
        param(
            "fork_next",
            "number",
            "Status default: the next fork, 0 for none",
            json!(0),
        ),
        param(
            "latest_block",
            "number",
            "Status default: newest block number",
            json!(0),
        ),
        param(
            "latest_block_hash",
            "string",
            "Status default: newest block hash (the genesis hash when not given)",
            json!(format!("0x{}", "00".repeat(32))),
        ),
    ]
}

/// Parsed startup configuration shared by both roles.
pub struct CommonConfig {
    pub key: NodeKey,
    pub client_id: String,
    pub defaults: StatusDefaults,
}

pub fn common_config(params: Option<&crate::protocol::StartupParams>) -> Result<CommonConfig> {
    let s = |k: &str| -> Result<Option<String>> {
        Ok(params
            .map(|p| p.get_optional_string(k))
            .transpose()?
            .flatten())
    };
    let u = |k: &str| -> Result<Option<u64>> {
        Ok(params.map(|p| p.get_optional_u64(k)).transpose()?.flatten())
    };
    let key = match s("node_private_key")? {
        Some(k) => NodeKey::from_hex(&k).context("node_private_key")?,
        None => NodeKey::random(),
    };
    let client_id = s("client_id")?.unwrap_or_else(default_client_id);
    anyhow::ensure!(
        !client_id.is_empty()
            && client_id.len() <= eth::MAX_CLIENT_ID_CHARS
            && !crate::utils::sanitize::has_controls(&client_id),
        "client_id is 1 to {} printable characters",
        eth::MAX_CLIENT_ID_CHARS
    );
    let hash = |k: &str| -> Result<Option<[u8; 32]>> {
        s(k)?
            .map(|h| eth::parse_fixed::<32>(&json!(h), k))
            .transpose()
    };
    let forks = match params
        .map(|p| p.get_optional_array("forks"))
        .transpose()?
        .flatten()
    {
        Some(a) => {
            anyhow::ensure!(a.len() <= 64, "at most 64 forks");
            a.iter()
                .map(|f| eth::parse_u64(f, "forks entry"))
                .collect::<Result<Vec<_>>>()?
        }
        None => Vec::new(),
    };
    Ok(CommonConfig {
        key,
        client_id,
        defaults: StatusDefaults {
            network_id: u("network_id")?,
            genesis: hash("genesis_hash")?,
            forks,
            fork_next: u("fork_next")?,
            latest_block: u("latest_block")?,
            latest_block_hash: hash("latest_block_hash")?,
        },
    })
}

impl Protocol for Devp2pProtocol {
    fn protocol_name(&self) -> &'static str {
        "devp2p"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>RLPx>devp2p"
    }
    fn description(&self) -> &'static str {
        "Ethereum devp2p node (RLPx, eth/68 and eth/69) whose admission, Status and block-header answers the LLM decides"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an Ethereum devp2p node on port 30303; admit every peer by mirroring its Status and answer header requests from these blocks"
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
            "ethereum node",
            "execution client",
        ]
    }
    fn group_name(&self) -> &'static str {
        "Blockchain"
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(30303)
            .answers_on_failure()
            .max_inbound_bytes(session::MAX_MESSAGE_BYTES)
            .implementation(
                "Hand-written RLPx (no Ethereum crate): the EIP-8 auth/ack handshake (secp256k1 \
                 ECDH and recoverable signatures from the secp256k1 crate, ECIES with \
                 AES-128-CTR and HMAC-SHA256 over a SHA-256 concat KDF), AES-256-CTR frames \
                 with go-ethereum's keccak MAC construction, Snappy after Hello v5, a bounded \
                 canonical RLP codec, the base protocol (Hello, Disconnect, Ping/Pong) and \
                 eth/68 and eth/69 (Status, GetBlockHeaders/BlockHeaders, \
                 GetBlockBodies/BlockBodies, NewPooledTransactionHashes, \
                 GetPooledTransactions/PooledTransactions, BlockRangeUpdate; GetReceipts is \
                 answered empty). Block hashes are keccak-256 of the RLP header, computed here",
            )
            .llm_control(
                "Admission and this node's Status (eth_status), every answer to the peer's \
                 header, body and pooled-transaction requests, and the requests sent to it; \
                 headers are JSON fields, never bytes",
            )
            .e2e_testing(
                "tests/server/devp2p: go-ethereum 1.17 dials NetGet after admin_addPeer, \
                 completes the eth/69 handshake, lists NetGet in admin_peers with the block \
                 range NetGet sent, and verifies with --eth.requiredblocks that the header \
                 NetGet served hashes to its own block; go-ethereum's devp2p tool reads \
                 NetGet's Hello; reth 2.7 dials NetGet and lists it in admin_peers. \
                 tshark has no RLPx dissector (every frame is encrypted), so no pcap oracle",
            )
            .notes(
                "Experimental: two independent implementations (go-ethereum, with its devp2p \
                 tool, and reth) complete sessions with it in tests that fail rather than skip, \
                 but no fuzz target exists, nobody has reviewed it against the devp2p specs \
                 line by line, and its pair job had not run in CI when it landed. No discovery \
                 (discv4/discv5): peers are added statically (admin_addPeer, --bootnodes, \
                 static nodes). No snap protocol. Bodies and pooled transactions are checked \
                 for shape and, for pooled transactions, against the hashes asked for; a body \
                 is not checked against its header's transactionsRoot (that needs a Merkle \
                 Patricia trie). Nothing is stored: every header the node serves is one the \
                 model wrote.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        common_startup_parameters()
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        all_actions()
    }

    fn get_event_types(&self) -> Vec<EventType> {
        event_types()
    }

    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 30303,
                "base_stack": "devp2p",
                "startup_params": {"network_id": 1337},
                "instruction": "Admit every peer on network 1337 by mirroring its Status. Answer \
                                header requests with an empty list."
            }),
            json!({
                "type": "open_server",
                "port": 30303,
                "base_stack": "devp2p",
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']\na=[]\nif t=='eth_status': a=[{'type':'eth_send_status','mirror_peer':True}]\nelif t=='eth_block_headers_requested': a=[{'type':'eth_send_block_headers','headers':[]}]\nprint(json.dumps({'actions':a}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 30303,
                "base_stack": "devp2p",
                "event_handlers": [
                    {"event_pattern": "eth_status", "handler": {"type": "static", "actions": [
                        {"type": session::SEND_STATUS, "mirror_peer": true}
                    ]}},
                    {"event_pattern": "eth_block_headers_requested", "handler": {"type": "static", "actions": [
                        {"type": session::SEND_HEADERS, "headers": []}
                    ]}},
                    {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
                ]
            }),
        )
    }
}

impl Server for Devp2pProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let config = common_config(ctx.startup_params.as_ref())?;
            crate::server::devp2p::Devp2pServer::spawn(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                config,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let kind = action
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'type' field in action"))?
            .to_string();
        session::parse_command(&action)?;
        Ok(ActionResult::Custom {
            name: kind,
            data: action,
        })
    }
}

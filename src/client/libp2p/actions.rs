//! What the model does as a libp2p dialler: open streams on the remote's protocols, send and
//! close them, ping and re-identify the remote, disconnect. Messages the remote sends (on
//! streams either side opened) come back as events.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::libp2p::{
    actions::{action, p},
    host, wire,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct Libp2pClientProtocol;
impl Libp2pClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn data(required: bool) -> Vec<crate::llm::actions::Parameter> {
    vec![
        p(
            "data",
            "string",
            "The message: text, or hex with encoding hex",
            required,
        ),
        p("encoding", "string", "utf8 (default) or hex", false),
    ]
}

pub fn actions() -> Vec<ActionDefinition> {
    let mut open = vec![p(
        "protocol",
        "string",
        "The protocol id to open, e.g. /netget/chat/1.0.0",
        true,
    )];
    open.extend(data(false));
    let mut send = vec![p(
        "stream_id",
        "number",
        "The stream to write on (from libp2p_response or libp2p_message)",
        true,
    )];
    send.extend(data(true));
    vec![
        action(
            "libp2p_open_stream",
            "Open a stream on a protocol the remote supports, optionally with a first message.",
            open,
            json!({"type": "libp2p_open_stream", "protocol": "/netget/chat/1.0.0", "data": "hello"}),
        ),
        action(
            "libp2p_send",
            "Send one length-prefixed message on an open stream.",
            send,
            json!({"type": "libp2p_send", "stream_id": 1, "data": "hello again"}),
        ),
        action(
            "libp2p_close_stream",
            "Close our half of a stream; the remote reads end-of-stream.",
            vec![p(
                "stream_id",
                "number",
                "The stream to close, by its id",
                true,
            )],
            json!({"type": "libp2p_close_stream", "stream_id": 1}),
        ),
        action(
            "libp2p_ping",
            "Ping the remote (/ipfs/ping/1.0.0) and learn the round-trip time.",
            vec![],
            json!({"type": "libp2p_ping"}),
        ),
        action(
            "libp2p_identify",
            "Ask the remote's identify again: agent, protocols and addresses.",
            vec![],
            json!({"type": "libp2p_identify"}),
        ),
        action(
            "ipfs_bitswap_want",
            "Ask the remote for blocks over Bitswap (needs the ipfs startup parameter). Each block that comes back is hashed and checked against the CID you asked for before it reaches you as ipfs_block_received; anything else is refused. DONT_HAVE and HAVE arrive as ipfs_bitswap_presence.",
            vec![
                p("cids", "array", "CIDs to fetch (Qm… or b…), raw or dag-pb", true),
                p("want", "string", "block (default: send the block) or have (only say whether you have it)", false),
            ],
            json!({"type": "ipfs_bitswap_want", "cids": ["bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"]}),
        ),
        action(
            "ipfs_fetch",
            "Fetch a whole file or directory by its root CID over Bitswap (needs the ipfs startup parameter). NetGet walks the DAG itself, verifying every block's hash, and answers with ipfs_fetched: a file's content (cut at max_bytes, with its whole size and SHA-256), a directory's listing (name, cid, kind, size of each entry), or a symlink's target.",
            vec![
                p("cid", "string", "The root CID (Qm… or b…), raw or dag-pb", true),
                p("max_bytes", "number", "File bytes to show, at most 1048576 (default 65536); the whole file is read and checked either way", false),
                p("timeout_secs", "number", "How long to wait for the whole DAG, 1 to 600 (default 120)", false),
            ],
            json!({"type": "ipfs_fetch", "cid": "QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn"}),
        ),
        action(
            "ipfs_bitswap_cancel",
            "Withdraw wants sent with ipfs_bitswap_want.",
            vec![p("cids", "array", "CIDs no longer wanted", true)],
            json!({"type": "ipfs_bitswap_cancel", "cids": ["bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"]}),
        ),
        action(
            "ipfs_kad_find_node",
            "Ask the remote's Kademlia DHT for the peers closest to a peer id (FIND_NODE). The answer arrives as libp2p_response with closer_peers.",
            vec![
                p("peer_id", "string", "The peer id to look up", true),
                p("protocol", "string", "/ipfs/kad/1.0.0 (default) or the LAN DHT's /ipfs/lan/kad/1.0.0", false),
            ],
            json!({"type": "ipfs_kad_find_node", "peer_id": "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA"}),
        ),
        action(
            "ipfs_kad_get_providers",
            "Ask the remote's Kademlia DHT who provides a CID (GET_PROVIDERS). The answer arrives as libp2p_response with provider_peers and closer_peers.",
            vec![
                p("cid", "string", "The CID whose providers to find", true),
                p("protocol", "string", "/ipfs/kad/1.0.0 (default) or the LAN DHT's /ipfs/lan/kad/1.0.0", false),
            ],
            json!({"type": "ipfs_kad_get_providers", "cid": "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"}),
        ),
        action(
            "ipfs_kad_get_value",
            "Ask the remote's Kademlia DHT for an IPNS record (GET_VALUE /ipns/<name>). The answer arrives as libp2p_response with the record verified (signature, name, expiry) and shown as {name, value, sequence, validity, valid}, and closer_peers.",
            vec![
                p("name", "string", "The IPNS name: a peer id (12D3KooW…)", true),
                p("protocol", "string", "/ipfs/kad/1.0.0 (default) or the LAN DHT's /ipfs/lan/kad/1.0.0", false),
            ],
            json!({"type": "ipfs_kad_get_value", "name": "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA"}),
        ),
        action(
            "disconnect",
            "Close the connection.",
            vec![],
            json!({"type": "disconnect"}),
        ),
    ]
}

fn event(id: &str, description: &str, params: Vec<crate::llm::actions::Parameter>) -> EventType {
    EventType::new(
        id,
        description,
        json!({"type": "libp2p_open_stream", "protocol": "/netget/chat/1.0.0", "data": "hello"}),
    )
    .with_parameters(params)
    .with_actions(actions())
}

pub static CONNECTED_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        event(
        "libp2p_connected",
        "Connected: the remote proved its peer id in the Noise handshake and answered identify.",
        vec![
            p("peer_id", "string", "The remote's peer id", true),
            p("agent_version", "string", "What the remote says it is, e.g. go-libp2p", true),
            p("protocols", "array", "The protocols the remote supports", true),
            p("listen_addrs", "array", "Where the remote says it listens", true),
            p("observed_addr", "string", "This client's address as the remote sees it", false),
        ],
    )
    });

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "libp2p_message",
        "The remote sent a message, on a stream either side opened.",
        vec![
            p(
                "stream_id",
                "number",
                "The stream it arrived on (use it with libp2p_send)",
                true,
            ),
            p("protocol", "string", "The stream's protocol id", true),
            p(
                "data",
                "string",
                "The message (text, or hex when encoding is hex)",
                true,
            ),
            p(
                "encoding",
                "string",
                "How data is written: utf8 text, or hex for binary",
                true,
            ),
        ],
    )
});

pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "libp2p_response",
        "The outcome of an action that asks something of the remote (open_stream, ping, identify).",
        vec![
            p("operation", "string", "The action that was performed", true),
            p("ok", "boolean", "Whether it succeeded", true),
            p(
                "stream_id",
                "number",
                "The new stream, for open_stream",
                false,
            ),
            p("rtt_ms", "number", "The round trip, for ping", false),
            p(
                "result",
                "object",
                "The remote's identify, for identify",
                false,
            ),
            p(
                "closer_peers",
                "array",
                "For a DHT request: [{peer_id, addrs}] the remote says are closer",
                false,
            ),
            p(
                "provider_peers",
                "array",
                "For ipfs_kad_get_providers: [{peer_id, addrs}] that have the content",
                false,
            ),
            p(
                "record",
                "object",
                "For ipfs_kad_get_value: the IPNS record, verified ({name, value, sequence, validity, ttl_secs, valid}; valid false with error when it does not verify)",
                false,
            ),
            p(
                "error",
                "string",
                "Why it failed, e.g. the remote refused the protocol",
                false,
            ),
        ],
    )
});

pub static BLOCK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "ipfs_block_received",
        "A block you wanted arrived over Bitswap, and its bytes hash to the CID you asked for. A dag-pb block's links are listed; want them to fetch the rest of a file or directory.",
        vec![
            p("cid", "string", "The CID you asked for", true),
            p("codec", "string", "The block's codec: raw (the bytes are the content) or dag-pb (a UnixFS node)", true),
            p("size", "number", "The block's size in bytes", true),
            p("data", "string", "The content: the block for raw, the UnixFS data for dag-pb (text, or hex when encoding is hex)", true),
            p("encoding", "string", "How data is written: utf8 text, or hex for binary", true),
            p("truncated", "boolean", "Whether data was cut short for display (the block was verified whole)", true),
            p("unixfs_type", "string", "For dag-pb: file, directory, raw, symlink, …", false),
            p("file_size", "number", "For a UnixFS file: the whole file's size", false),
            p("links", "array", "For dag-pb: [{cid, name, size}] of the children", true),
        ],
    )
});

pub static FETCHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "ipfs_fetched",
        "An ipfs_fetch finished: every block of the DAG arrived and hashed to its CID, or the fetch failed (ok false, with why).",
        vec![
            p("cid", "string", "The root CID fetched", true),
            p("ok", "boolean", "Whether the whole DAG was fetched and verified", true),
            p("kind", "string", "file, directory or symlink", false),
            p("size", "number", "A file's size in bytes", false),
            p("data", "string", "A file's content up to max_bytes (text, or hex when encoding is hex)", false),
            p("encoding", "string", "How data is written: utf8 text, or hex for binary", false),
            p("truncated", "boolean", "Whether data is shorter than the file", false),
            p("sha256", "string", "SHA-256 of the whole file, hex", false),
            p("entries", "array", "A directory's entries: [{name, cid, tsize, kind, size}]", false),
            p("target", "string", "A symlink's target", false),
            p("blocks", "number", "Blocks fetched and verified", true),
            p("depth", "number", "The DAG's depth (a single block is 0)", false),
            p("error", "string", "Why the fetch failed", false),
        ],
    )
});

pub static PRESENCE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "ipfs_bitswap_presence",
        "The remote said whether it has a block you wanted: HAVE (have true) or DONT_HAVE.",
        vec![
            p("cid", "string", "The CID you asked about", true),
            p(
                "have",
                "boolean",
                "true for HAVE, false for DONT_HAVE",
                true,
            ),
        ],
    )
});

pub fn check(v: &Value) -> Result<()> {
    let stream = || {
        v["stream_id"]
            .as_u64()
            .context("stream_id must be a number")
    };
    match v["type"].as_str().unwrap_or_default() {
        "libp2p_open_stream" => {
            let proto = v["protocol"].as_str().context("protocol is required")?;
            ensure!(
                proto.starts_with('/') && proto.len() <= 256 && !proto.contains('\n'),
                "protocol must be a protocol id such as /netget/chat/1.0.0"
            );
            if !v["data"].is_null() {
                wire::data_bytes(v)?;
            }
        }
        "libp2p_send" => {
            stream()?;
            ensure!(
                wire::data_bytes(v)?.len() <= host::MAX_MESSAGE,
                "message too long"
            );
        }
        "libp2p_close_stream" => {
            stream()?;
        }
        "libp2p_ping" | "libp2p_identify" | "disconnect" => {}
        "ipfs_bitswap_want" => {
            super::ipfs::cids(v)?;
            super::ipfs::want_type(v)?;
        }
        "ipfs_bitswap_cancel" => {
            super::ipfs::cids(v)?;
        }
        "ipfs_fetch" => {
            super::ipfs::fetch_params(v)?;
        }
        "ipfs_kad_find_node" | "ipfs_kad_get_providers" | "ipfs_kad_get_value" => {
            super::ipfs::kad_request(v)?;
            super::ipfs::kad_protocol(v)?;
        }
        t => bail!("Unknown libp2p client action {t:?}"),
    }
    Ok(())
}

impl Protocol for Libp2pClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "libp2p"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>libp2p"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "libp2p",
            "ipfs",
            "p2p",
            "dial peer",
            "multiaddr",
            "bitswap",
            "cid",
            "kademlia",
            "kubo",
        ]
    }
    fn description(&self) -> &'static str {
        "libp2p dialler over TCP (Noise, yamux): identifies and pings the remote, talks length-prefixed messages on its protocols' streams, and with ipfs on fetches blocks and whole files and directories by CID over Bitswap (each block verified) and asks the remote's Kademlia DHT, IPNS records included"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            MESSAGE_EVENT.clone(),
            RESPONSE_EVENT.clone(),
            BLOCK_EVENT.clone(),
            PRESENCE_EVENT.clone(),
            FETCHED_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "peer_id".into(),
                type_hint: "string".into(),
                description: "The remote's expected peer id (12D3KooW…); the handshake fails if it proves another. Also accepted inside a /p2p/ multiaddr.".into(),
                required: false,
                example: json!("12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA"),
                default: None,
            },
            ParameterDefinition {
                name: "protocols".into(),
                type_hint: "array".into(),
                description: "Application protocol ids the remote may open streams to this client on".into(),
                required: false,
                example: json!(["/netget/chat/1.0.0"]),
                default: Some(json!(host::DEFAULT_PROTOCOLS)),
            },
            ParameterDefinition {
                name: "private_key_seed".into(),
                type_hint: "string".into(),
                description: "Any text; its SHA-256 is the Ed25519 identity key, so the same text gives the same peer id (default: a new key)".into(),
                required: false,
                example: json!("my-stable-node"),
                default: None,
            },
            ParameterDefinition {
                name: "ipfs".into(),
                type_hint: "boolean".into(),
                description: "Also speak IPFS: accept Bitswap so blocks wanted with ipfs_bitswap_want can arrive (each verified against its CID)".into(),
                required: false,
                example: json!(true),
                default: Some(json!(crate::server::libp2p::actions::IPFS_DEFAULT)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's hand-rolled stack in the dialler role: multistream-select, Noise XX as initiator (checking the remote's peer id when one is named), yamux, identify and ping; the remote's own identify and ping are answered. With ipfs: Bitswap wants on a stream of its own and blocks accepted on the remote's streams, each hashed against the outstanding wants; ipfs_fetch walks a whole UnixFS DAG (files of many blocks, directories, symlinks) iteratively and bounded, verifying every block; DHT FIND_NODE, GET_PROVIDERS and GET_VALUE (IPNS records verified), one question per stream")
            .llm_control("Which protocols to open streams on, what to send, when to ping, identify, close and disconnect, and how to answer the remote's messages. With ipfs: which DAG to fetch whole, which CIDs to want or cancel block by block, and what to ask the remote's DHT")
            .e2e_testing("tests/client/libp2p: go-libp2p listening (TCP, Noise, yamux), which identifies NetGet, answers its chat stream and opens one of its own to NetGet; Kubo 0.43.1 (loopback only) serves files it added — a CIDv0 UnixFS file, a CIDv1 raw block, a chunked file whose leaves NetGet wants from the root's links, and, through ipfs_fetch, CIDv0 and CIDv1 directory trees, a 2.2 MB file and a depth-4 file checked by size and SHA-256 — and answers FIND_NODE, GET_PROVIDERS and GET_VALUE for its own IPNS name; Helia 7.1.16 serves a tree NetGet fetches whole; a go-libp2p peer answering wants with tampered bytes is refused before the model hears of it, and never completes a fetch")
            .notes("TCP only; Ed25519 identities only; no gossipsub, relay or hole punching. remote_addr is host:port or /ip4|ip6|dns/…/tcp/…[/p2p/<id>]. A handler chain stops after 8 follow-ups. IPFS limits: sha2-256 and the raw and dag-pb codecs only (other CIDs are refused before anything is sent); at most 1024 outstanding wants; block content shown to the model is cut at 64 KiB (the block is verified whole); a fetch is at most 8192 blocks, 32 levels and 1 GiB, shows at most 1 MiB, and runs one at a time per connection; HAMT-sharded directories are not walked; the client serves no blocks and answers no DHT requests; Kubo keeps its own provider records in its LAN DHT while its WAN DHT is inactive, so ask /ipfs/lan/kad/1.0.0 on a private network.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Dial the libp2p peer /ip4/127.0.0.1/tcp/4001/p2p/12D3KooW... and say hello on /netget/chat/1.0.0"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"libp2p","remote_addr":"127.0.0.1:4001",
            "instruction":"Say hello on /netget/chat/1.0.0 and answer whatever comes back"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"libp2p_connected","handler":{"type":"static","actions":[{"type":"libp2p_open_stream","protocol":"/netget/chat/1.0.0","data":"hello"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python","code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='libp2p_connected': a=[{'type':'libp2p_open_stream','protocol':'/netget/chat/1.0.0','data':'hello'}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Peer-to-peer"
    }
}

impl Client for Libp2pClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        if name == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}

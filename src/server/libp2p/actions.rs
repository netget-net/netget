//! What the model does as a libp2p host: answer messages on the application protocols'
//! streams, open streams of its own to a connected peer, close them, and drop peers. Rust
//! owns the transport (Noise, yamux, multistream-select) and answers identify and ping.
use super::bitswap::{self, Format, Supplied};
use super::host::{self, Config};
use super::ipfs::{self, Cid};
use super::kad;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const SEND: &str = "libp2p_send";
pub const OPEN: &str = "libp2p_open_stream";
pub const CLOSE: &str = "libp2p_close_stream";
pub const DISCONNECT: &str = "libp2p_disconnect";
pub const BLOCKS: &str = "ipfs_bitswap_blocks";
pub const KAD_REPLY: &str = "ipfs_kad_reply";
pub const ADD: &str = "ipfs_add";
pub const KAD_QUERY: &str = "ipfs_kad_query";
/// IPFS (Bitswap and the DHT) is off unless asked for.
pub const IPFS_DEFAULT: bool = false;

#[derive(Default, Clone)]
pub struct Libp2pProtocol;

impl Libp2pProtocol {
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

pub fn action(
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
                .with_info(format!("-> libp2p {}", name.trim_start_matches("libp2p_"))),
        ),
    }
}

fn data_params() -> Vec<Parameter> {
    vec![
        p(
            "data",
            "string",
            "The message: text, or hex with encoding hex",
            true,
        ),
        p("encoding", "string", "utf8 (default) or hex", false),
    ]
}

pub fn send_action() -> ActionDefinition {
    let mut params = data_params();
    params.push(p(
        "stream_id",
        "number",
        "The stream to write on (default: the stream of the message being answered)",
        false,
    ));
    action(
        SEND,
        "Send one message on a stream (framed with its length, the libp2p convention).",
        params,
        json!({"type": SEND, "data": "hello from NetGet"}),
    )
}

pub fn open_action() -> ActionDefinition {
    let mut params = vec![p(
        "protocol",
        "string",
        "The protocol id to open, e.g. /netget/chat/1.0.0",
        true,
    )];
    params.extend(data_params().into_iter().map(|mut x| {
        x.required = false;
        x
    }));
    action(
        OPEN,
        "Open a stream to the peer on a protocol it supports, optionally sending a first message. Its replies arrive as libp2p_message events.",
        params,
        json!({"type": OPEN, "protocol": "/netget/chat/1.0.0", "data": "hi"}),
    )
}

pub fn close_action() -> ActionDefinition {
    action(
        CLOSE,
        "Close our half of a stream: the peer reads end-of-stream after what was sent.",
        vec![p(
            "stream_id",
            "number",
            "The stream to close (default: the stream of the message being answered)",
            false,
        )],
        json!({"type": CLOSE}),
    )
}

pub fn disconnect_action() -> ActionDefinition {
    action(
        DISCONNECT,
        "Close the whole connection to this peer.",
        vec![],
        json!({"type": DISCONNECT}),
    )
}

pub fn all_actions() -> Vec<ActionDefinition> {
    vec![
        send_action(),
        open_action(),
        close_action(),
        disconnect_action(),
    ]
}

pub fn blocks_action() -> ActionDefinition {
    action(
        BLOCKS,
        "Answer a Bitswap wantlist with the blocks you have. Give each block's content and format; NetGet computes its CID from the bytes and sends it only for a want it really matches (a block claimed under a CID it does not hash to is never sent). Wants you do not answer get DONT_HAVE. Answer with no blocks to say you have none.",
        vec![p(
            "blocks",
            "array",
            "Blocks: {content, encoding (utf8 default, or hex), format (raw, or unixfs for a single-block UnixFS file; default: from cid's codec, else raw), cid (optional: the wanted CID this answers)}",
            true,
        )],
        json!({"type": BLOCKS, "blocks": [{"content": "hello from NetGet\n", "format": "unixfs"}]}),
    )
}

pub fn kad_reply_action() -> ActionDefinition {
    action(
        KAD_REPLY,
        "Answer a DHT GET_PROVIDERS request. provider_peers: peers that have the content; closer_peers: peers closer to the key (default: the connected peers closest to it). Each is {peer_id, addrs}; peer_id \"self\" is this host, and addrs may be omitted for this host and for connected peers.",
        vec![
            p(
                "closer_peers",
                "array",
                "[{peer_id, addrs: [multiaddr]}], at most 20",
                false,
            ),
            p(
                "provider_peers",
                "array",
                "[{peer_id, addrs: [multiaddr]}], at most 20",
                false,
            ),
        ],
        json!({"type": KAD_REPLY, "provider_peers": [{"peer_id": "self"}], "closer_peers": []}),
    )
}

/// The fields of a file or directory description, shared by the `ipfs_add` action and the
/// `ipfs_content` startup parameter.
pub const DESCRIPTION_FIELDS: &str = "A file is {text} or {hex}, or {size, extents: [{offset, text|hex|fill, length}]} (zeroes where no extent covers); a directory is {entries: [{name, kind: file|dir|symlink, ...the same fields}]}; a symlink is {kind: symlink, target}. Layout options are Kubo's ipfs add flags: cid_version 0 (default, Qm… roots, UnixFS leaves) or 1 (raw leaves unless raw_leaves is false), chunk_size (default 262144), max_links (default 174)";

pub fn add_action() -> ActionDefinition {
    action(
        ADD,
        "Serve a file or a whole directory tree over Bitswap. Describe the content; NetGet chunks it and builds the UnixFS DAG exactly as Kubo's ipfs add does (same root CID), then answers every block of it, now and for later wants, without asking you again. The root CID is logged and returned.",
        vec![
            p("name", "string", "A label for the log (a directory's own name is not part of its CID)", false),
            p("kind", "string", "file (default), dir (default when entries is given) or symlink", false),
            p("text", "string", "A file's content as text", false),
            p("hex", "string", "A file's content as hex", false),
            p("size", "number", "A file's size in bytes, with extents", false),
            p("extents", "array", "[{offset, text|hex|fill, length (for fill)}]: a file's content in pieces; zeroes elsewhere", false),
            p("entries", "array", "A directory's entries: [{name, kind, text|hex|size+extents|entries|target}]", false),
            p("target", "string", "A symlink's target", false),
            p("cid_version", "number", "0 (default) or 1, as ipfs add --cid-version", false),
            p("raw_leaves", "boolean", "Raw leaf blocks (default: true under CIDv1), as ipfs add --raw-leaves", false),
            p("chunk_size", "number", "Bytes per leaf, 256 to 1048576 (default 262144), as ipfs add --chunker=size-N", false),
            p("max_links", "number", "Links per file node, 2 to 1024 (default 174), as ipfs add --max-file-links", false),
        ],
        json!({"type": ADD, "name": "site", "entries": [
            {"name": "index.html", "text": "<h1>served by NetGet</h1>\n"},
            {"name": "big.bin", "size": 1000000, "extents": [{"offset": 0, "length": 1000000, "fill": 0}]}
        ]}),
    )
}

pub fn kad_query_action() -> ActionDefinition {
    action(
        KAD_QUERY,
        "Ask this peer's Kademlia DHT one question: FIND_NODE (peer_id), GET_PROVIDERS (cid) or GET_VALUE (name, an IPNS name). The answer arrives as ipfs_kad_answer; an IPNS record in it is verified (signature, name, expiry) before you see it. At most 8 questions a minute per peer.",
        vec![
            p("request", "string", "FIND_NODE, GET_PROVIDERS or GET_VALUE", true),
            p("peer_id", "string", "For FIND_NODE: the peer id to look up", false),
            p("cid", "string", "For GET_PROVIDERS: the content's CID", false),
            p("name", "string", "For GET_VALUE: the IPNS name, a peer id (12D3KooW…)", false),
            p("protocol", "string", "/ipfs/kad/1.0.0 (default) or the LAN DHT's /ipfs/lan/kad/1.0.0", false),
        ],
        json!({"type": KAD_QUERY, "request": "GET_PROVIDERS", "cid": "QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn"}),
    )
}

pub fn ipfs_actions() -> Vec<ActionDefinition> {
    vec![
        blocks_action(),
        kad_reply_action(),
        add_action(),
        kad_query_action(),
    ]
}

/// The blocks an `ipfs_bitswap_blocks` action supplies, each checked and encoded, its CID
/// not yet compared with any want.
pub fn supplied_blocks(v: &Value) -> Result<Vec<Supplied>> {
    let list = v["blocks"].as_array().context("blocks must be an array")?;
    ensure!(
        list.len() <= bitswap::MAX_SUPPLIED_BLOCKS,
        "at most {} blocks per answer",
        bitswap::MAX_SUPPLIED_BLOCKS
    );
    list.iter()
        .map(|b| {
            ensure!(b.is_object(), "each block is an object with content");
            let content = super::wire::data_bytes(&json!({
                "data": b["content"].as_str().context("each block needs content")?,
                "encoding": b["encoding"].clone(),
            }))?;
            let claimed = match b["cid"].as_str() {
                Some(c) => Some(Cid::parse(c)?),
                None => None,
            };
            if let Some(c) = &claimed {
                c.supported()?;
            }
            let format = match (b["format"].as_str(), &claimed) {
                (Some(f), _) => Format::parse(f)?,
                (None, Some(c)) if c.codec == ipfs::DAG_PB => Format::UnixFsFile,
                _ => Format::Raw,
            };
            Supplied::new(&content, format, claimed)
        })
        .collect()
}

/// The peers an `ipfs_kad_reply` names, (closer, providers): ids checked, addresses parsed,
/// and "self" and omitted addresses filled in from what the host knows.
pub fn kad_peers(v: &Value, cfg: &Config) -> Result<(Vec<kad::Peer>, Vec<kad::Peer>)> {
    let list = |field: &str| -> Result<Vec<kad::Peer>> {
        let Some(items) = v[field].as_array() else {
            ensure!(v[field].is_null(), "{field} must be an array");
            return Ok(Vec::new());
        };
        ensure!(
            items.len() <= kad::MAX_PEERS,
            "{field} may name at most {} peers",
            kad::MAX_PEERS
        );
        items
            .iter()
            .map(|p| {
                let id = p["peer_id"].as_str().context("each peer needs peer_id")?;
                let addrs: Vec<String> = match p["addrs"].as_array() {
                    Some(a) => a
                        .iter()
                        .map(|x| x.as_str().map(str::to_string).context("addrs are strings"))
                        .collect::<Result<_>>()?,
                    None => Vec::new(),
                };
                let id = if id == "self" {
                    super::wire::base58(&cfg.identity.peer_id)
                } else {
                    id.to_string()
                };
                let mut peer = kad::Peer::from_text(&id, &addrs)?;
                if peer.addrs.is_empty() {
                    peer.addrs = super::serve_ipfs::known_addrs(cfg, &peer.id);
                }
                Ok(peer)
            })
            .collect()
    };
    Ok((list("closer_peers")?, list("provider_peers")?))
}

pub static WANT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ipfs_bitswap_want",
        "A peer asked this host for blocks over Bitswap. Supply the ones you have with ipfs_bitswap_blocks (content and format; NetGet computes and checks each CID); the rest are answered DONT_HAVE.",
        json!({"type": BLOCKS, "blocks": [{"content": "hello from NetGet\n", "format": "raw"}]}),
    )
    .with_parameters(vec![
        p("peer_id", "string", "The peer id of the peer asking, proven by its Noise handshake", true),
        p(
            "wants",
            "array",
            "[{cid, codec (raw or dag-pb), want (block or have)}]",
            true,
        ),
        p(
            "full",
            "boolean",
            "Whether this is the peer's whole wantlist rather than an update",
            true,
        ),
    ])
    .with_actions(vec![blocks_action(), add_action(), disconnect_action()])
});

pub static KAD_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ipfs_kad_request",
        "A peer asked this host's Kademlia DHT who provides some content (GET_PROVIDERS: answer with ipfs_kad_reply), or announced that it provides some (ADD_PROVIDER: no answer is sent; remember it if you want to name it later). FIND_NODE is answered by NetGet itself from the connected peers.",
        json!({"type": KAD_REPLY, "provider_peers": [{"peer_id": "self"}]}),
    )
    .with_parameters(vec![
        p("peer_id", "string", "The peer id of the peer asking, proven by its Noise handshake", true),
        p("stream_id", "number", "The stream it arrived on", true),
        p(
            "protocol",
            "string",
            "/ipfs/kad/1.0.0, or the LAN DHT's /ipfs/lan/kad/1.0.0",
            true,
        ),
        p(
            "request",
            "string",
            "GET_PROVIDERS or ADD_PROVIDER",
            true,
        ),
        p(
            "key",
            "string",
            "The content key: a base58 sha2-256 multihash (the CIDv0 spelling)",
            true,
        ),
        p(
            "cids",
            "array",
            "The CIDs (v0, v1 dag-pb, v1 raw) the key stands for",
            true,
        ),
        p(
            "providers",
            "array",
            "For ADD_PROVIDER: the peer announcing itself, with its addrs",
            true,
        ),
        p("self", "object", "This host: {peer_id, addrs}", true),
        p(
            "connected_peers",
            "array",
            "Peers connected to this host, closest to the key first",
            true,
        ),
    ])
    .with_actions(vec![kad_reply_action(), disconnect_action()])
});

pub static KAD_ANSWER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ipfs_kad_answer",
        "This peer's DHT answered an ipfs_kad_query (or the question failed: ok false, with why). An IPNS record in it was verified before you see it.",
        json!({"type": KAD_QUERY, "request": "FIND_NODE", "peer_id": "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA"}),
    )
    .with_parameters(vec![
        p("peer_id", "string", "The peer that was asked", true),
        p("ok", "boolean", "Whether the peer answered", true),
        p("request", "string", "FIND_NODE, GET_PROVIDERS or GET_VALUE", true),
        p("protocol", "string", "The DHT protocol asked", false),
        p("key", "string", "What was asked about", false),
        p("closer_peers", "array", "[{peer_id, addrs}] the peer says are closer", false),
        p("provider_peers", "array", "For GET_PROVIDERS: [{peer_id, addrs}] that have the content", false),
        p("record", "object", "For GET_VALUE: {name, value, sequence, validity, ttl_secs, valid} (valid false with error when it does not verify)", false),
        p("error", "string", "Why the question failed", false),
    ])
    .with_actions(vec![kad_query_action(), add_action(), disconnect_action()])
});

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "libp2p_peer_connected",
        "A peer connected (Noise-authenticated, yamux-multiplexed) and answered identify. Open a stream to speak first, or do nothing and wait for its streams.",
        json!({"type": OPEN, "protocol": "/netget/chat/1.0.0", "data": "welcome"}),
    )
    .with_parameters(vec![
        p("peer_id", "string", "The peer's id, proven by its Noise handshake", true),
        p("remote_addr", "string", "The peer's address as a multiaddr", true),
        p("agent_version", "string", "What the peer's identify says it is, e.g. go-libp2p", true),
        p("protocols", "array", "The protocols the peer says it supports", true),
        p("listen_addrs", "array", "Where the peer says it listens", true),
    ])
    .with_actions(vec![
        open_action(),
        add_action(),
        kad_query_action(),
        disconnect_action(),
    ])
});

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "libp2p_message",
        "A peer sent a message on a stream of one of this host's application protocols.",
        json!({"type": SEND, "data": "hello back"}),
    )
    .with_parameters(vec![
        p("peer_id", "string", "The peer id of who sent it", true),
        p("stream_id", "number", "The stream it arrived on", true),
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
    ])
    .with_actions({
        let mut a = all_actions();
        a.push(add_action());
        a.push(kad_query_action());
        a
    })
});

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        SEND => {
            super::wire::data_bytes(v)?;
            if !v["stream_id"].is_null() {
                v["stream_id"]
                    .as_u64()
                    .context("stream_id must be a number")?;
            }
        }
        OPEN => {
            let proto = v["protocol"].as_str().context("protocol is required")?;
            ensure!(
                proto.starts_with('/') && proto.len() <= 256 && !proto.contains('\n'),
                "protocol must be a protocol id such as /netget/chat/1.0.0"
            );
            if !v["data"].is_null() {
                super::wire::data_bytes(v)?;
            }
        }
        CLOSE => {
            if !v["stream_id"].is_null() {
                v["stream_id"]
                    .as_u64()
                    .context("stream_id must be a number")?;
            }
        }
        DISCONNECT => {}
        BLOCKS => {
            supplied_blocks(v)?;
        }
        ADD => {
            // The shape and every bound; hashing waits for the add itself.
            super::unixfs::parse(v)?;
        }
        KAD_QUERY => {
            kad::request_of(v["request"].as_str().unwrap_or_default(), v)?;
            kad::protocol_of(v)?;
        }
        KAD_REPLY => {
            // Checked against a stand-in host: the real one fills in "self" when it answers.
            let stand_in = Config {
                identity: super::noise::Identity::from_seed([0; 32]),
                protocols: Vec::new(),
                listen_addrs: Vec::new(),
                bitswap: false,
                kad: false,
                directory: Default::default(),
                dag: Default::default(),
                dht: Default::default(),
            };
            kad_peers(v, &stand_in)?;
        }
        other => bail!("Unknown libp2p action {other:?}"),
    }
    Ok(())
}

impl Protocol for Libp2pProtocol {
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
            "noise",
            "yamux",
            "multistream",
            "peer id",
            "4001",
            "bitswap",
            "kademlia",
            "cid",
            "kubo",
            "unixfs",
            "ipns",
        ]
    }
    fn description(&self) -> &'static str {
        "libp2p host over TCP (multistream-select, Noise, yamux): answers identify and ping, talks length-prefixed messages on its application protocols' streams, and with ipfs on serves over Bitswap the files and directories the model describes (built as Kubo builds them) and the blocks it supplies, and keeps IPNS and provider records in its Kademlia DHT"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut a = all_actions();
        a.extend(ipfs_actions());
        a
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            MESSAGE_EVENT.clone(),
            WANT_EVENT.clone(),
            KAD_EVENT.clone(),
            KAD_ANSWER_EVENT.clone(),
        ]
    }
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        Some(crate::protocol::BindingDefaults::port_based("127.0.0.1", 0))
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "protocols".into(),
                type_hint: "array".into(),
                description: "Application protocol ids this host accepts streams for (identify and ping are always answered)".into(),
                required: false,
                example: json!(["/netget/chat/1.0.0", "/chat/1.0.0"]),
                default: Some(json!(host::DEFAULT_PROTOCOLS)),
            },
            ParameterDefinition {
                name: "private_key_seed".into(),
                type_hint: "string".into(),
                description: "Any text; its SHA-256 is the Ed25519 identity key, so the same text gives the same peer id (default: a new key each start)".into(),
                required: false,
                example: json!("my-stable-node"),
                default: None,
            },
            ParameterDefinition {
                name: "ipfs".into(),
                type_hint: "boolean".into(),
                description: "Also be an IPFS peer: answer Bitswap wantlists (ipfs_bitswap_want) with blocks the model supplies, and Kademlia DHT requests (ipfs_kad_request), so Kubo can fetch from and route through this host".into(),
                required: false,
                example: json!(true),
                default: Some(json!(IPFS_DEFAULT)),
            },
            ParameterDefinition {
                name: "ipfs_content".into(),
                type_hint: "array".into(),
                description: format!("With ipfs: files and directories to serve from the start, each described as ipfs_add describes one. {DESCRIPTION_FIELDS}"),
                required: false,
                example: json!([{"name": "hello.txt", "text": "hello from NetGet\n"}]),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(4001)
            .implementation("Hand-rolled (src/server/libp2p): multistream-select 1.0; Noise XX (25519, ChaChaPoly, SHA256) with the libp2p handshake payload, on ring, x25519-dalek and ed25519-dalek; yamux with per-stream windows; identify (/ipfs/id/1.0.0, push accepted) and ping answered in Rust; Ed25519 peer ids. With ipfs: Bitswap 1.2.0/1.1.0/1.0.0 (answers on a stream of its own) with a per-peer ledger of remembered wants, CIDv0/CIDv1 (base58btc, base32) over sha2-256, raw and dag-pb, UnixFS files and directories built from descriptions exactly as Kubo's ipfs add builds them (fixed-size chunker, balanced layout, CIDv0 UnixFS or CIDv1 raw leaves) and served from the description, and the Kademlia DHT message on /ipfs/kad/1.0.0 and /ipfs/lan/kad/1.0.0 with IPNS records (signatureV2, DAG-CBOR data, sequence) and provider records kept in Rust")
            .llm_control("Every message on the application protocols' streams: reply, open streams to the peer, close them, drop the peer. With ipfs: which files and directories to serve (ipfs_add or ipfs_content: a description Rust turns into a DAG whose blocks it then serves at no model cost), which wanted blocks it has otherwise (their content and format; Rust computes each CID and sends only blocks that hash to a want), who provides a key Rust does not know (GET_PROVIDERS), and what to ask a peer's DHT (ipfs_kad_query); it is told of ADD_PROVIDER. FIND_NODE, GET_VALUE, PUT_VALUE and known providers are answered in Rust")
            .e2e_testing("tests/server/libp2p: go-libp2p (TCP, Noise, yamux) dials NetGet, verifies its peer id, runs identify and ping, and talks on /netget/chat/1.0.0; Kubo 0.43.1 (loopback only) fetches model-served content with ipfs cat and ipfs block get, and reads described trees and multi-block files with ipfs ls, cat, get, dag get and refs -r, every root CID first checked against Kubo's ipfs add --only-hash (seven layout profiles, files 0 B to 2.2 MB, trees with empty files, empty directories, symlinks and UTF-8 names) and against Helia's ipfs-unixfs-importer 17.1.1; Helia 7.1.16 (js-libp2p 3.5.1) reads the same trees; Kubo's cat waits on a remembered want until the model adds the content; Kubo publishes an IPNS name into NetGet's DHT and a second Kubo resolves it there; over go-libp2p, go-cid recomputes the CID of every block sent, remembered wants are answered when content arrives and forgotten on CANCEL, a block that does not hash is never sent, a failed model answers DONT_HAVE, stale and tampered IPNS records are refused, and oversized, malformed and unknown-codec messages are refused before the model")
            .notes("TCP only: no QUIC, WebTransport, WebRTC, TLS security or mplex. Ed25519 identities only (RSA/secp256k1/ECDSA peers are refused). No gossipsub, no relay, no hole punching, no signed peer records. Messages are uvarint-length-prefixed, at most 1 MiB (Bitswap 4 MiB, DHT 64 KiB). A model failure resets the stream it was answering; a failed Bitswap answer is DONT_HAVE, never a block. IPFS limits: sha2-256 only; raw and dag-pb only (dag-cbor and others answered DONT_HAVE); fixed-size chunker and balanced layout only (no rabin, buzhash, trickle or inline); no HAMT-sharded directories (a directory Kubo would shard is refused); an add is at most 256 MiB and 65536 blocks, DAGs at most 32 deep; at most 1024 remembered wants per peer; IPNS records only under Ed25519 names, at most 1024 names; the host's DHT answers from what it holds and asks one connected peer at a time (no iterative lookups, no republishing).")
            .max_inbound_bytes(host::MAX_MESSAGE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "libp2p peer on port 4001 that answers /netget/chat/1.0.0 messages"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let base = json!({"type":"open_server","base_stack":"libp2p","port":0,
            "instruction":"Answer every chat message with a short friendly reply"});
        let mut scripted = base.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"libp2p_message","handler":{"type":"script","language":"python",
            "code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'libp2p_send','data':'echo: '+e['data']}]}))"}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}]);
        let mut static_example = base.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"libp2p_message","handler":{"type":"static","actions":[{"type":SEND,"data":"hello"}]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[]}}]);
        StartupExamples::new(base, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Peer-to-peer"
    }
}

impl Server for Libp2pProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        check(&action)?;
        let name = action["type"].as_str().unwrap_or_default().to_string();
        Ok(ActionResult::Custom { name, data: action })
    }
}

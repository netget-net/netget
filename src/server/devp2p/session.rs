//! One devp2p session after the TCP connection, shared by the server and the client.
//!
//! [`establish`] runs the RLPx handshake and the Hello exchange (bounded by
//! [`HANDSHAKE_TIMEOUT`]); [`read_loop`] is the reader task, which answers Ping itself so a
//! model call in progress never makes the peer time the session out; [`Session`] holds what the
//! two sides have said — both Statuses, the requests each side still owes an answer — decodes
//! every `eth` message into a [`PeerEvent`] for the model, and carries out the model's
//! [`Command`]s, refusing any that would put something on the wire the session cannot vouch for:
//! headers that do not answer the request they claim to, transactions nobody asked for, a reply
//! to a request that is already answered.
use super::crypto::{self, NodeKey};
use super::eth::{self, code, Announcement, HeaderRequest, Hello, Origin, Status};
use super::rlp::Rlp;
use super::rlpx::{self, FrameError, FrameReader, FrameWriter};
use crate::utils::clock::Instant;
use anyhow::{bail, ensure, Context, Result};
use secp256k1::PublicKey;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

/// The largest message accepted after decompression, and the server's `max_inbound_bytes`.
/// go-ethereum's own cap is 10 MiB; nothing a model answers or asks for comes near either.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// The RLPx handshake and the Hello exchange together.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a session may go without a frame. Peers ping every 15 seconds.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// How often this side pings.
pub const PING_INTERVAL: Duration = Duration::from_secs(15);
/// How long a request NetGet sent may stay unanswered.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// How long one frame may take to write.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(20);
/// Requests NetGet may have outstanding at once.
pub const MAX_OUTSTANDING: usize = 16;
/// Peer requests NetGet may owe an answer to at once; past this, the session is closed.
pub const MAX_OWED: usize = 64;
/// The most headers NetGet asks for in one request.
pub const MAX_REQUEST_HEADERS: u64 = 64;
/// The most hashes NetGet asks about in one request.
pub const MAX_REQUEST_HASHES: usize = 256;
/// The most headers, bodies or transactions one answer may carry (go-ethereum serves at most
/// 1024 headers).
pub const MAX_ANSWER_ITEMS: usize = 1024;
/// The most hashes a peer may ask about or announce in one message.
pub const MAX_PEER_HASHES: usize = 4096;

pub type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
pub type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// The write side: the frame codec and the socket half, behind one lock so frames never
/// interleave.
pub struct Writer {
    codec: FrameWriter,
    half: BoxWrite,
}

pub type SharedWriter = Arc<Mutex<Writer>>;

/// Send one message; returns the bytes written.
pub async fn send(w: &SharedWriter, msg_code: u64, payload: &[u8]) -> Result<usize> {
    ensure!(
        payload.len() <= MAX_MESSAGE_BYTES,
        "a {}-byte message is above the {MAX_MESSAGE_BYTES}-byte bound",
        payload.len()
    );
    let mut g = w.lock().await;
    let frame = g.codec.encode(msg_code, payload)?;
    let half = &mut g.half;
    tokio::time::timeout(WRITE_TIMEOUT, async {
        half.write_all(&frame).await?;
        half.flush().await
    })
    .await
    .context("writing a frame timed out")??;
    Ok(frame.len())
}

/// Send Disconnect and close our side. Best effort: the peer may already be gone.
pub async fn disconnect(w: &SharedWriter, reason: u64) {
    let _ = send(w, code::DISCONNECT, &eth::encode_disconnect(reason)).await;
    close(w).await;
}

pub async fn close(w: &SharedWriter) {
    let mut g = w.lock().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), g.half.shutdown()).await;
}

/// Who dials.
pub enum Role {
    Dial(PublicKey),
    Listen,
}

/// A session past Hello.
pub struct Established {
    pub reader: FrameReader,
    pub read_half: BoxRead,
    pub writer: SharedWriter,
    pub hello: Hello,
    pub eth_version: u64,
    pub remote_id: [u8; 64],
}

/// Why a session never got past Hello.
#[derive(Debug)]
pub enum EstablishError {
    /// The handshake failed, timed out, or the peer is not speaking RLPx.
    Transport(String),
    /// The peer sent Disconnect instead of Hello.
    PeerDisconnected(u64),
    /// NetGet refused the peer at the protocol level and told it why.
    Refused { reason: u64, detail: String },
}

impl std::fmt::Display for EstablishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EstablishError::Transport(m) => write!(f, "{m}"),
            EstablishError::PeerDisconnected(r) => {
                write!(f, "the peer disconnected: {}", eth::reason_name(*r))
            }
            EstablishError::Refused { reason, detail } => {
                write!(f, "refused ({}): {detail}", eth::reason_name(*reason))
            }
        }
    }
}

/// The RLPx handshake, then Hello both ways. Our Hello goes out first and unconditionally — it
/// is NetGet's identity, not a decision — and the peer's must name the key it authenticated
/// with and share an `eth` version.
pub async fn establish(
    mut read_half: BoxRead,
    mut write_half: BoxWrite,
    key: &NodeKey,
    role: Role,
    client_id: &str,
    listen_port: u16,
) -> std::result::Result<Established, EstablishError> {
    let transport = |e: anyhow::Error| EstablishError::Transport(format!("{e:#}"));
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
        let secrets = match role {
            Role::Dial(remote) => {
                rlpx::initiate(&mut read_half, &mut write_half, key, &remote).await
            }
            Role::Listen => rlpx::respond(&mut read_half, &mut write_half, key).await,
        }
        .map_err(transport)?;
        let remote_id = crypto::node_id(&secrets.remote);
        let (mut reader, codec) = rlpx::codec(secrets, MAX_MESSAGE_BYTES);
        let writer: SharedWriter = Arc::new(Mutex::new(Writer {
            codec,
            half: write_half,
        }));
        let ours = Hello::ours(client_id, listen_port, key.id());
        send(&writer, code::HELLO, &ours.encode())
            .await
            .map_err(transport)?;
        let (msg, payload) = reader.read(&mut read_half).await.map_err(|e| match e {
            FrameError::Io(e) => EstablishError::Transport(format!("reading Hello: {e}")),
            other => EstablishError::Transport(format!("reading Hello: {other}")),
        })?;
        if msg == code::DISCONNECT {
            return Err(EstablishError::PeerDisconnected(eth::decode_disconnect(
                &payload,
            )));
        }
        if msg != code::HELLO {
            disconnect(&writer, 0x02).await;
            return Err(EstablishError::Refused {
                reason: 0x02,
                detail: format!("the first message is {msg:#04x}, not Hello"),
            });
        }
        let hello = match Hello::decode(&payload) {
            Ok(h) => h,
            Err(e) => {
                disconnect(&writer, 0x02).await;
                return Err(EstablishError::Refused {
                    reason: 0x02,
                    detail: format!("Hello: {e:#}"),
                });
            }
        };
        // From here on, both directions are Snappy when the peer speaks version 5.
        let snappy = hello.version >= eth::BASE_VERSION;
        reader.set_snappy(snappy);
        writer.lock().await.codec.set_snappy(snappy);
        if hello.id != remote_id {
            disconnect(&writer, 0x09).await;
            return Err(EstablishError::Refused {
                reason: 0x09,
                detail: "the Hello names a different node than the handshake authenticated".into(),
            });
        }
        if hello.id == key.id() {
            disconnect(&writer, 0x0a).await;
            return Err(EstablishError::Refused {
                reason: 0x0a,
                detail: "the peer is this node".into(),
            });
        }
        let Some(eth_version) = hello.shared_eth() else {
            disconnect(&writer, 0x03).await;
            return Err(EstablishError::Refused {
                reason: 0x03,
                detail: format!(
                    "no shared eth version: the peer offers {:?}, NetGet speaks eth/68 and eth/69",
                    hello.caps_strings()
                ),
            });
        };
        Ok(Established {
            reader,
            read_half,
            writer,
            hello,
            eth_version,
            remote_id,
        })
    })
    .await
    .unwrap_or_else(|_| {
        Err(EstablishError::Transport(format!(
            "the handshake did not finish within {}s",
            HANDSHAKE_TIMEOUT.as_secs()
        )))
    })
}

/// What the reader task hands over.
#[derive(Debug)]
pub enum Inbound {
    Message { code: u64, payload: Vec<u8> },
    Ended(End),
}

/// Why a session ended, and how to tag it.
#[derive(Debug, Clone)]
pub struct End {
    pub reason: String,
    /// The `decision=` tag for the log, or None for an ordinary end.
    pub decision: Option<&'static str>,
}

impl End {
    pub fn plain(reason: impl Into<String>) -> End {
        End {
            reason: reason.into(),
            decision: None,
        }
    }
}

/// The reader task: read frames until the session ends, answering Ping with Pong itself.
pub async fn read_loop(
    mut reader: FrameReader,
    mut half: BoxRead,
    writer: SharedWriter,
    tx: mpsc::Sender<Inbound>,
) {
    let end = loop {
        match reader.read(&mut half).await {
            Ok((code::PING, _)) => {
                if send(&writer, code::PONG, &eth::empty_payload())
                    .await
                    .is_err()
                {
                    break End::plain("the connection could not be written");
                }
            }
            Ok((code::PONG, _)) => {}
            Ok((code, payload)) => {
                if tx.send(Inbound::Message { code, payload }).await.is_err() {
                    return;
                }
            }
            Err(FrameError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break End::plain("the peer closed the connection");
            }
            Err(FrameError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                break End {
                    reason: format!("no frame for {}s", IDLE_TIMEOUT.as_secs()),
                    decision: Some("fail_closed_idle_timeout"),
                };
            }
            Err(FrameError::Io(e)) => break End::plain(format!("read failed: {e}")),
            Err(e @ FrameError::TooLarge { .. }) => {
                disconnect(&writer, 0x02).await;
                break End {
                    reason: format!("message too large: {e}"),
                    decision: Some("fail_closed_message_too_large"),
                };
            }
            Err(FrameError::Protocol(m)) => {
                disconnect(&writer, 0x02).await;
                break End {
                    reason: m,
                    decision: Some("protocol_error"),
                };
            }
        }
    };
    let _ = tx.send(Inbound::Ended(end)).await;
}

// ---------------------------------------------------------------------------------------
// What the model may tell a session to do
// ---------------------------------------------------------------------------------------

/// A Status as the model specifies it: explicit fields, optionally mirroring the peer's.
#[derive(Debug, Clone, Default)]
pub struct StatusSpec {
    pub fields: Map<String, Value>,
    pub mirror_peer: bool,
}

/// One validated action.
#[derive(Debug, Clone)]
pub enum Command {
    SendStatus(StatusSpec),
    SendHeaders {
        request_id: Option<u64>,
        headers: Vec<Rlp>,
    },
    SendBodies {
        request_id: Option<u64>,
        bodies: Vec<Rlp>,
    },
    SendPooled {
        request_id: Option<u64>,
        transactions: Vec<(Rlp, [u8; 32])>,
    },
    RequestHeaders(HeaderRequest),
    RequestBodies(Vec<[u8; 32]>),
    RequestPooled(Vec<[u8; 32]>),
    Disconnect(u64),
}

pub const SEND_STATUS: &str = "eth_send_status";
pub const SEND_HEADERS: &str = "eth_send_block_headers";
pub const SEND_BODIES: &str = "eth_send_block_bodies";
pub const SEND_POOLED: &str = "eth_send_pooled_transactions";
pub const REQUEST_HEADERS: &str = "eth_request_block_headers";
pub const REQUEST_BODIES: &str = "eth_request_block_bodies";
pub const REQUEST_POOLED: &str = "eth_request_pooled_transactions";
pub const DISCONNECT: &str = "devp2p_disconnect";

const STATUS_FIELDS: &[&str] = &[
    "network_id",
    "genesis_hash",
    "fork_hash",
    "fork_next",
    "forks",
    "earliest_block",
    "latest_block",
    "latest_block_hash",
    "total_difficulty",
    "head_hash",
];

fn request_id(v: &Value) -> Result<Option<u64>> {
    match v.get("request_id") {
        None | Some(Value::Null) => Ok(None),
        Some(r) => Ok(Some(eth::parse_u64(r, "request_id")?)),
    }
}

fn array<'a>(v: &'a Value, key: &str, max: usize) -> Result<&'a Vec<Value>> {
    let a = v[key]
        .as_array()
        .with_context(|| format!("{key} is an array"))?;
    ensure!(
        a.len() <= max,
        "{key} holds {} entries, above {max}",
        a.len()
    );
    Ok(a)
}

fn hashes(v: &Value, key: &str, max: usize) -> Result<Vec<[u8; 32]>> {
    let a = array(v, key, max)?;
    ensure!(!a.is_empty(), "{key} names at least one hash");
    a.iter().map(|h| eth::parse_fixed::<32>(h, key)).collect()
}

/// Validate one action. Everything a peer would see is checked here, so an action the
/// executor accepts is one the session can carry out.
pub fn parse_command(v: &Value) -> Result<Command> {
    let kind = v["type"].as_str().context("an action has a type")?;
    Ok(match kind {
        SEND_STATUS => {
            let obj = v.as_object().context("action")?;
            let mut fields = Map::new();
            for (k, val) in obj {
                if k == "type" || k == "mirror_peer" || val.is_null() {
                    continue;
                }
                ensure!(
                    STATUS_FIELDS.contains(&k.as_str()),
                    "{k:?} is not a Status field; the fields are {}",
                    STATUS_FIELDS.join(", ")
                );
                fields.insert(k.clone(), val.clone());
            }
            let spec = StatusSpec {
                fields,
                mirror_peer: v["mirror_peer"].as_bool().unwrap_or(false),
            };
            // Check the formats now; which fields are missing depends on the peer.
            check_status_fields(&spec)?;
            Command::SendStatus(spec)
        }
        SEND_HEADERS => {
            let headers = array(v, "headers", MAX_ANSWER_ITEMS)?
                .iter()
                .enumerate()
                .map(|(i, h)| eth::header_from_json(h).with_context(|| format!("headers[{i}]")))
                .collect::<Result<Vec<_>>>()?;
            Command::SendHeaders {
                request_id: request_id(v)?,
                headers,
            }
        }
        SEND_BODIES => {
            let bodies = array(v, "bodies", MAX_ANSWER_ITEMS)?
                .iter()
                .enumerate()
                .map(|(i, b)| eth::body_from_json(b).with_context(|| format!("bodies[{i}]")))
                .collect::<Result<Vec<_>>>()?;
            Command::SendBodies {
                request_id: request_id(v)?,
                bodies,
            }
        }
        SEND_POOLED => {
            let transactions = array(v, "transactions", MAX_ANSWER_ITEMS)?
                .iter()
                .enumerate()
                .map(|(i, t)| {
                    eth::transaction_from_hex(t).with_context(|| format!("transactions[{i}]"))
                })
                .collect::<Result<Vec<_>>>()?;
            Command::SendPooled {
                request_id: request_id(v)?,
                transactions,
            }
        }
        REQUEST_HEADERS => {
            let origin = Origin::from_json(&v["origin"])?;
            let num = |k: &str, d: u64| -> Result<u64> {
                match v.get(k) {
                    None | Some(Value::Null) => Ok(d),
                    Some(x) => eth::parse_u64(x, k),
                }
            };
            let amount = num("amount", 1)?;
            ensure!(
                (1..=MAX_REQUEST_HEADERS).contains(&amount),
                "amount is 1 to {MAX_REQUEST_HEADERS}"
            );
            let skip = num("skip", 0)?;
            ensure!(skip <= 1_000_000, "skip is at most 1000000");
            Command::RequestHeaders(HeaderRequest {
                origin,
                amount,
                skip,
                reverse: v["reverse"].as_bool().unwrap_or(false),
            })
        }
        REQUEST_BODIES => Command::RequestBodies(hashes(v, "hashes", MAX_REQUEST_HASHES)?),
        REQUEST_POOLED => Command::RequestPooled(hashes(v, "hashes", MAX_REQUEST_HASHES)?),
        DISCONNECT | "close_connection" => Command::Disconnect(eth::reason_code(
            v["reason"].as_str().unwrap_or("requested"),
        )?),
        other => bail!("unknown devp2p action {other:?}"),
    })
}

fn check_status_fields(spec: &StatusSpec) -> Result<()> {
    for (k, v) in &spec.fields {
        match k.as_str() {
            "network_id" | "fork_next" | "earliest_block" | "latest_block" => {
                eth::parse_u64(v, k)?;
            }
            "genesis_hash" | "latest_block_hash" | "head_hash" => {
                eth::parse_fixed::<32>(v, k)?;
            }
            "fork_hash" => {
                eth::parse_fixed::<4>(v, k)?;
            }
            "total_difficulty" => {
                eth::parse_big(v, k)?;
            }
            "forks" => {
                let a = v
                    .as_array()
                    .context("forks is an array of block numbers or timestamps")?;
                ensure!(a.len() <= 64, "at most 64 forks");
                for f in a {
                    eth::parse_u64(f, "forks entry")?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Status values configured at startup, used for whatever the model leaves out.
#[derive(Debug, Clone, Default)]
pub struct StatusDefaults {
    pub network_id: Option<u64>,
    pub genesis: Option<[u8; 32]>,
    pub forks: Vec<u64>,
    pub fork_next: Option<u64>,
    pub latest_block: Option<u64>,
    pub latest_block_hash: Option<[u8; 32]>,
}

impl StatusDefaults {
    pub fn to_json(&self) -> Value {
        json!({
            "network_id": self.network_id,
            "genesis_hash": self.genesis.map(|g| eth::hex0x(&g)),
            "forks": self.forks,
            "fork_next": self.fork_next,
            "latest_block": self.latest_block,
            "latest_block_hash": self.latest_block_hash.map(|h| eth::hex0x(&h)),
        })
    }
}

/// Resolve a Status: each field from the action, else the peer's (with `mirror_peer`), else
/// the startup configuration, else a refusal naming the field. The fork hash, when nobody gave
/// one, is computed from the genesis hash and the passed forks.
pub fn build_status(
    spec: &StatusSpec,
    version: u64,
    peer: Option<&Status>,
    defaults: &StatusDefaults,
) -> Result<Status> {
    let mirror = if spec.mirror_peer {
        Some(peer.context(
            "mirror_peer: the peer has not sent its Status yet, so there is nothing to mirror",
        )?)
    } else {
        None
    };
    let f = |k: &str| spec.fields.get(k);
    let missing = |k: &str| {
        anyhow::anyhow!(
            "Status needs {k}: give it in eth_send_status, set mirror_peer, or configure it at startup"
        )
    };
    let network_id = match f("network_id") {
        Some(v) => eth::parse_u64(v, "network_id")?,
        None => mirror
            .map(|p| p.network_id)
            .or(defaults.network_id)
            .ok_or_else(|| missing("network_id"))?,
    };
    let genesis = match f("genesis_hash") {
        Some(v) => eth::parse_fixed(v, "genesis_hash")?,
        None => mirror
            .map(|p| p.genesis)
            .or(defaults.genesis)
            .ok_or_else(|| missing("genesis_hash"))?,
    };
    let forks = match f("forks") {
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| eth::parse_u64(x, "forks entry"))
            .collect::<Result<Vec<_>>>()?,
        _ => defaults.forks.clone(),
    };
    let fork_next_given = match f("fork_next") {
        Some(v) => Some(eth::parse_u64(v, "fork_next")?),
        None => None,
    };
    let (fork_hash, fork_next) = match f("fork_hash") {
        Some(v) => (
            eth::parse_fixed(v, "fork_hash")?,
            fork_next_given.unwrap_or(0),
        ),
        None => match mirror {
            Some(p) if f("forks").is_none() => {
                (p.fork_hash, fork_next_given.unwrap_or(p.fork_next))
            }
            _ => (
                eth::fork_hash(&genesis, &forks),
                fork_next_given.or(defaults.fork_next).unwrap_or(0),
            ),
        },
    };
    let u = |k: &str, from_peer: Option<u64>, default: Option<u64>| -> Result<u64> {
        Ok(match f(k) {
            Some(v) => eth::parse_u64(v, k)?,
            None => from_peer.or(default).unwrap_or(0),
        })
    };
    let h = |k: &str, from_peer: Option<[u8; 32]>, default: Option<[u8; 32]>| -> Result<[u8; 32]> {
        Ok(match f(k) {
            Some(v) => eth::parse_fixed(v, k)?,
            None => from_peer.or(default).unwrap_or(genesis),
        })
    };
    let mut s = Status {
        version,
        network_id,
        genesis,
        fork_hash,
        fork_next,
        total_difficulty: Vec::new(),
        head: [0; 32],
        earliest_block: 0,
        latest_block: 0,
        latest_block_hash: [0; 32],
    };
    if version >= 69 {
        s.earliest_block = u("earliest_block", mirror.map(|p| p.earliest_block), Some(0))?;
        s.latest_block = u(
            "latest_block",
            mirror.map(|p| p.latest_block),
            defaults.latest_block,
        )?;
        s.latest_block_hash = h(
            "latest_block_hash",
            mirror.map(|p| p.latest_block_hash),
            defaults.latest_block_hash,
        )?;
        ensure!(
            s.earliest_block <= s.latest_block,
            "earliest_block {} is after latest_block {}",
            s.earliest_block,
            s.latest_block
        );
        ensure!(s.latest_block_hash != [0; 32], "latest_block_hash is zero");
    } else {
        s.total_difficulty = match f("total_difficulty") {
            Some(v) => eth::parse_big(v, "total_difficulty")?,
            None => mirror
                .map(|p| p.total_difficulty.clone())
                .unwrap_or_default(),
        };
        s.head = h(
            "head_hash",
            mirror.map(|p| p.head),
            defaults.latest_block_hash,
        )?;
    }
    Ok(s)
}

/// Whether two Statuses describe the same chain, and if not, why not.
pub fn compatible(ours: &Status, theirs: &Status) -> std::result::Result<(), String> {
    if ours.network_id != theirs.network_id {
        return Err(format!(
            "network id {} is not the peer's {}",
            ours.network_id, theirs.network_id
        ));
    }
    if ours.genesis != theirs.genesis {
        return Err(format!(
            "genesis {} is not the peer's {}",
            eth::hex0x(&ours.genesis),
            eth::hex0x(&theirs.genesis)
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The running session
// ---------------------------------------------------------------------------------------

/// What NetGet asked for.
#[derive(Debug, Clone)]
enum Asked {
    Headers(HeaderRequest),
    Bodies(Vec<[u8; 32]>),
    Pooled(Vec<[u8; 32]>),
}

struct Outstanding {
    asked: Asked,
    deadline: Instant,
    depth: u32,
}

/// What the peer asked for and is owed.
#[derive(Debug, Clone)]
enum Owed {
    Headers(HeaderRequest),
    Bodies(usize),
    Pooled(Vec<[u8; 32]>),
}

/// Something the model should hear about.
#[derive(Debug, Clone)]
pub struct PeerEvent {
    pub kind: PeerEventKind,
    pub data: Value,
    /// For a request from the peer: its id, which an answer defaults to.
    pub request_id: Option<u64>,
    /// How many model turns led here.
    pub depth: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerEventKind {
    HeadersRequested,
    BodiesRequested,
    PooledRequested,
    Announced,
    HeadersReceived,
    BodiesReceived,
    PooledReceived,
    RequestTimedOut,
}

/// The session state both roles share.
pub struct Session {
    pub writer: SharedWriter,
    pub eth_version: u64,
    pub peer_status: Option<Status>,
    pub our_status: Option<Status>,
    next_request_id: u64,
    outstanding: HashMap<u64, Outstanding>,
    owed: HashMap<u64, Owed>,
    /// Bytes written, for the connection's statistics.
    pub bytes_sent: u64,
}

/// The outcome of one command.
#[derive(Debug)]
pub enum Applied {
    Sent(String),
    StatusSent(Status),
    Disconnected(u64),
}

fn eth_code(c: u64) -> u64 {
    eth::ETH_OFFSET + c
}

impl Session {
    pub fn new(writer: SharedWriter, eth_version: u64) -> Session {
        Session {
            writer,
            eth_version,
            peer_status: None,
            our_status: None,
            next_request_id: rand::random::<u32>() as u64,
            outstanding: HashMap::new(),
            owed: HashMap::new(),
            bytes_sent: 0,
        }
    }

    /// Both Statuses exchanged.
    pub fn ready(&self) -> bool {
        self.peer_status.is_some() && self.our_status.is_some()
    }

    /// Whether a request from the peer is still unanswered.
    pub fn owes(&self, request_id: u64) -> bool {
        self.owed.contains_key(&request_id)
    }

    async fn send_eth(&mut self, c: u64, payload: &[u8]) -> Result<()> {
        let n = send(&self.writer, eth_code(c), payload).await?;
        self.bytes_sent += n as u64;
        Ok(())
    }

    /// Read the peer's Status from a message: Ok(None) for anything that is not one.
    pub fn take_status(&mut self, msg_code: u64, payload: &[u8]) -> Result<Option<Status>> {
        if msg_code != eth_code(code::STATUS) {
            return Ok(None);
        }
        ensure!(self.peer_status.is_none(), "a second Status");
        let s = Status::decode(payload, self.eth_version)?;
        self.peer_status = Some(s.clone());
        Ok(Some(s))
    }

    /// Requests NetGet sent that have gone unanswered too long.
    pub fn expire(&mut self) -> Vec<PeerEvent> {
        let now = Instant::now();
        let expired: Vec<u64> = self
            .outstanding
            .iter()
            .filter(|(_, o)| o.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        expired
            .into_iter()
            .filter_map(|id| self.outstanding.remove(&id).map(|o| (id, o)))
            .map(|(id, o)| PeerEvent {
                kind: PeerEventKind::RequestTimedOut,
                data: json!({"request_id": id, "request": asked_json(&o.asked), "timeout_secs": REQUEST_TIMEOUT.as_secs()}),
                request_id: None,
                depth: o.depth,
            })
            .collect()
    }

    /// Decode one message from the running session. `Ok(None)` is a message handled here
    /// (logged, or answered without the model); `Err` ends the session with that reason
    /// after a Disconnect `breach_of_protocol`.
    pub async fn on_message(&mut self, msg_code: u64, payload: &[u8]) -> Result<Option<PeerEvent>> {
        if msg_code < eth::ETH_OFFSET {
            bail!("base protocol message {msg_code:#04x} after Hello");
        }
        let c = msg_code - eth::ETH_OFFSET;
        ensure!(
            c < eth::eth_length(self.eth_version),
            "message {msg_code:#04x} is outside eth/{}",
            self.eth_version
        );
        ensure!(
            self.peer_status.is_some(),
            "message {msg_code:#04x} before the peer's Status"
        );
        let event = |kind, data, request_id, depth| {
            Ok(Some(PeerEvent {
                kind,
                data,
                request_id,
                depth,
            }))
        };
        match c {
            code::STATUS => bail!("a second Status"),
            code::GET_BLOCK_HEADERS => {
                let (id, req) = HeaderRequest::decode(payload)?;
                self.owe(id, Owed::Headers(req.clone()))?;
                event(
                    PeerEventKind::HeadersRequested,
                    json!({"request_id": id, "origin": req.origin.to_json(), "amount": req.amount, "skip": req.skip, "reverse": req.reverse}),
                    Some(id),
                    0,
                )
            }
            code::GET_BLOCK_BODIES => {
                let (id, hashes) =
                    eth::decode_hash_request(payload, MAX_PEER_HASHES, "GetBlockBodies")?;
                self.owe(id, Owed::Bodies(hashes.len()))?;
                event(
                    PeerEventKind::BodiesRequested,
                    json!({"request_id": id, "hashes": hashes.iter().map(|h| eth::hex0x(h)).collect::<Vec<_>>()}),
                    Some(id),
                    0,
                )
            }
            code::GET_POOLED_TRANSACTIONS => {
                let (id, hashes) =
                    eth::decode_hash_request(payload, MAX_PEER_HASHES, "GetPooledTransactions")?;
                self.owe(id, Owed::Pooled(hashes.clone()))?;
                event(
                    PeerEventKind::PooledRequested,
                    json!({"request_id": id, "hashes": hashes.iter().map(|h| eth::hex0x(h)).collect::<Vec<_>>()}),
                    Some(id),
                    0,
                )
            }
            code::GET_RECEIPTS => {
                // NetGet keeps no receipts and the model cannot produce them: say so, the way
                // the protocol says it — an empty list.
                let (id, _) = eth::decode_hash_request(payload, MAX_PEER_HASHES, "GetReceipts")?;
                self.send_eth(code::RECEIPTS, &eth::encode_response(id, Vec::new()))
                    .await?;
                Ok(None)
            }
            code::NEW_POOLED_TRANSACTION_HASHES => {
                let a = Announcement::decode(payload, MAX_PEER_HASHES)?;
                event(
                    PeerEventKind::Announced,
                    json!({
                        "transactions": a.hashes.iter().zip(&a.types).zip(&a.sizes)
                            .map(|((h, t), s)| json!({"hash": eth::hex0x(h), "type": t, "size": s}))
                            .collect::<Vec<_>>()
                    }),
                    None,
                    0,
                )
            }
            code::BLOCK_HEADERS => self.answer_for(payload, "BlockHeaders"),
            code::BLOCK_BODIES => self.answer_for(payload, "BlockBodies"),
            code::POOLED_TRANSACTIONS => self.answer_for(payload, "PooledTransactions"),
            code::BLOCK_RANGE_UPDATE => {
                let (earliest, latest, hash) = eth::decode_block_range(payload)?;
                if let Some(p) = self.peer_status.as_mut() {
                    p.earliest_block = earliest;
                    p.latest_block = latest;
                    p.latest_block_hash = hash;
                }
                Ok(None)
            }
            code::TRANSACTIONS | code::NEW_BLOCK_HASHES | code::NEW_BLOCK | code::RECEIPTS => {
                // Broadcasts and an unasked-for answer: noted, not modelled.
                Ok(None)
            }
            other => bail!("eth message {other:#04x} is not handled"),
        }
    }

    fn owe(&mut self, id: u64, owed: Owed) -> Result<()> {
        ensure!(
            self.owed.len() < MAX_OWED,
            "the peer has {MAX_OWED} requests unanswered"
        );
        ensure!(
            !self.owed.contains_key(&id),
            "the peer reused request id {id} while it is still unanswered"
        );
        self.owed.insert(id, owed);
        Ok(())
    }

    /// An answer to something NetGet asked: decoded, checked against the question, reported.
    fn answer_for(&mut self, payload: &[u8], what: &str) -> Result<Option<PeerEvent>> {
        let (id, items) = eth::decode_response(payload, MAX_ANSWER_ITEMS, what)?;
        let Some(o) = self.outstanding.remove(&id) else {
            tracing::debug!(
                "devp2p {what} for request {id}, which NetGet did not send or gave up on"
            );
            return Ok(None);
        };
        let depth = o.depth + 1;
        let request = asked_json(&o.asked);
        match o.asked {
            Asked::Headers(req) => {
                ensure!(
                    items.len() as u64 <= req.amount,
                    "{} headers for a request of {}",
                    items.len(),
                    req.amount
                );
                let headers = items
                    .iter()
                    .map(eth::header_to_json)
                    .collect::<Result<Vec<_>>>()?;
                let (matches, linked) = check_headers(&req, &items);
                Ok(Some(PeerEvent {
                    kind: PeerEventKind::HeadersReceived,
                    data: json!({"request_id": id, "request": request, "count": headers.len(),
                                 "headers": headers, "matches_request": matches, "linked": linked}),
                    request_id: None,
                    depth,
                }))
            }
            Asked::Bodies(hashes) => {
                ensure!(
                    items.len() <= hashes.len(),
                    "{} bodies for {} hashes",
                    items.len(),
                    hashes.len()
                );
                let bodies = items
                    .iter()
                    .zip(&hashes)
                    .map(|(b, h)| {
                        let mut j = eth::body_json(b)?;
                        j["block_hash"] = json!(eth::hex0x(h));
                        Ok(j)
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(Some(PeerEvent {
                    kind: PeerEventKind::BodiesReceived,
                    data: json!({"request_id": id, "request": request, "count": bodies.len(), "bodies": bodies}),
                    request_id: None,
                    depth,
                }))
            }
            Asked::Pooled(hashes) => {
                let txs = items
                    .iter()
                    .map(eth::transaction_json)
                    .collect::<Result<Vec<_>>>()?;
                let asked: Vec<String> = hashes.iter().map(|h| eth::hex0x(h)).collect();
                let unasked = txs
                    .iter()
                    .filter(|t| !asked.iter().any(|a| Some(a.as_str()) == t["hash"].as_str()))
                    .count();
                Ok(Some(PeerEvent {
                    kind: PeerEventKind::PooledReceived,
                    data: json!({"request_id": id, "request": request, "count": txs.len(),
                                 "transactions": txs, "unrequested": unasked}),
                    request_id: None,
                    depth,
                }))
            }
        }
    }

    /// Carry out one command. `answering` is the peer request the current event is about,
    /// which a reply without its own `request_id` answers; `depth` is the turn this command
    /// came from, carried onto the answer to any request it sends.
    pub async fn apply(
        &mut self,
        command: Command,
        answering: Option<u64>,
        depth: u32,
        defaults: &StatusDefaults,
    ) -> Result<Applied> {
        let reply_id = |given: Option<u64>| {
            given
                .or(answering)
                .context("request_id is required: this is not an answer to a request event")
        };
        match command {
            Command::Disconnect(reason) => {
                disconnect(&self.writer, reason).await;
                Ok(Applied::Disconnected(reason))
            }
            Command::SendStatus(spec) => {
                ensure!(self.our_status.is_none(), "Status was already sent");
                let status =
                    build_status(&spec, self.eth_version, self.peer_status.as_ref(), defaults)?;
                self.send_eth(code::STATUS, &status.encode()).await?;
                self.our_status = Some(status.clone());
                Ok(Applied::StatusSent(status))
            }
            _ if !self.ready() => {
                bail!("the eth handshake has not finished: both Statuses must be exchanged first")
            }
            Command::SendHeaders {
                request_id,
                headers,
            } => {
                let id = reply_id(request_id)?;
                let Some(Owed::Headers(req)) = self.owed.get(&id).cloned() else {
                    bail!("there is no unanswered GetBlockHeaders {id}");
                };
                validate_answer(&req, &headers)?;
                let hashes: Vec<String> = headers
                    .iter()
                    .map(|h| eth::hex0x(&eth::header_hash(h)))
                    .collect();
                self.send_eth(code::BLOCK_HEADERS, &eth::encode_response(id, headers))
                    .await?;
                self.owed.remove(&id);
                Ok(Applied::Sent(format!(
                    "sent {} headers for request {id}: {}",
                    hashes.len(),
                    hashes.join(", ")
                )))
            }
            Command::SendBodies { request_id, bodies } => {
                let id = reply_id(request_id)?;
                let Some(Owed::Bodies(n)) = self.owed.get(&id).cloned() else {
                    bail!("there is no unanswered GetBlockBodies {id}");
                };
                ensure!(
                    bodies.len() <= n,
                    "{} bodies for a request naming {n} blocks",
                    bodies.len()
                );
                let count = bodies.len();
                self.send_eth(code::BLOCK_BODIES, &eth::encode_response(id, bodies))
                    .await?;
                self.owed.remove(&id);
                Ok(Applied::Sent(format!(
                    "sent {count} bodies for request {id}"
                )))
            }
            Command::SendPooled {
                request_id,
                transactions,
            } => {
                let id = reply_id(request_id)?;
                let Some(Owed::Pooled(asked)) = self.owed.get(&id).cloned() else {
                    bail!("there is no unanswered GetPooledTransactions {id}");
                };
                for (_, h) in &transactions {
                    ensure!(
                        asked.contains(h),
                        "transaction {} was not asked for",
                        eth::hex0x(h)
                    );
                }
                let count = transactions.len();
                let items = transactions.into_iter().map(|(t, _)| t).collect();
                self.send_eth(code::POOLED_TRANSACTIONS, &eth::encode_response(id, items))
                    .await?;
                self.owed.remove(&id);
                Ok(Applied::Sent(format!(
                    "sent {count} transactions for request {id}"
                )))
            }
            Command::RequestHeaders(req) => {
                let id = self.next_id()?;
                self.send_eth(code::GET_BLOCK_HEADERS, &req.encode(id))
                    .await?;
                let what = format!(
                    "asked for {} headers from {:?} (request {id})",
                    req.amount, req.origin
                );
                self.track(id, Asked::Headers(req), depth);
                Ok(Applied::Sent(what))
            }
            Command::RequestBodies(hashes) => {
                let id = self.next_id()?;
                self.send_eth(
                    code::GET_BLOCK_BODIES,
                    &eth::encode_hash_request(id, &hashes),
                )
                .await?;
                let what = format!("asked for {} bodies (request {id})", hashes.len());
                self.track(id, Asked::Bodies(hashes), depth);
                Ok(Applied::Sent(what))
            }
            Command::RequestPooled(hashes) => {
                let id = self.next_id()?;
                self.send_eth(
                    code::GET_POOLED_TRANSACTIONS,
                    &eth::encode_hash_request(id, &hashes),
                )
                .await?;
                let what = format!("asked for {} transactions (request {id})", hashes.len());
                self.track(id, Asked::Pooled(hashes), depth);
                Ok(Applied::Sent(what))
            }
        }
    }

    fn next_id(&mut self) -> Result<u64> {
        ensure!(
            self.outstanding.len() < MAX_OUTSTANDING,
            "{MAX_OUTSTANDING} requests are already waiting for answers"
        );
        self.next_request_id = self.next_request_id.wrapping_add(1);
        Ok(self.next_request_id)
    }

    fn track(&mut self, id: u64, asked: Asked, depth: u32) {
        self.outstanding.insert(
            id,
            Outstanding {
                asked,
                deadline: Instant::now() + REQUEST_TIMEOUT,
                depth,
            },
        );
    }
}

fn asked_json(a: &Asked) -> Value {
    match a {
        Asked::Headers(r) => json!({"kind": "headers", "query": r.to_json()}),
        Asked::Bodies(h) => {
            json!({"kind": "bodies", "hashes": h.iter().map(|x| eth::hex0x(x)).collect::<Vec<_>>()})
        }
        Asked::Pooled(h) => {
            json!({"kind": "transactions", "hashes": h.iter().map(|x| eth::hex0x(x)).collect::<Vec<_>>()})
        }
    }
}

/// Whether received headers are the ones asked for (numbers, or the first hash) and, for a
/// contiguous request, whether each names the previous one as its parent.
fn check_headers(req: &HeaderRequest, headers: &[Rlp]) -> (bool, bool) {
    let numbers: Vec<Option<u64>> = headers.iter().map(|h| eth::header_number(h).ok()).collect();
    let first = match req.origin {
        Origin::Number(n) => Some(n),
        Origin::Hash(h) => headers
            .first()
            .filter(|f| eth::header_hash(f) == h)
            .and_then(|f| eth::header_number(f).ok()),
    };
    let matches = headers.is_empty()
        || first.is_some_and(|first| {
            numbers
                .iter()
                .enumerate()
                .all(|(i, n)| *n == req.number_at(first, i as u64))
        });
    (matches, linked(req, headers))
}

fn linked(req: &HeaderRequest, headers: &[Rlp]) -> bool {
    if req.skip != 0 {
        return true;
    }
    headers.windows(2).all(|w| {
        let (older, newer) = if req.reverse {
            (&w[1], &w[0])
        } else {
            (&w[0], &w[1])
        };
        eth::header_parent(newer).ok() == Some(eth::header_hash(older))
    })
}

/// Refuse headers that do not answer `req`: more than asked for, the wrong numbers, a first
/// header whose hash is not the one asked for, or (for a contiguous request) a header that
/// does not name the previous one as its parent.
pub fn validate_answer(req: &HeaderRequest, headers: &[Rlp]) -> Result<()> {
    ensure!(
        headers.len() as u64 <= req.amount,
        "{} headers for a request of {}",
        headers.len(),
        req.amount
    );
    let Some(first) = headers.first() else {
        return Ok(());
    };
    let first_number = eth::header_number(first)?;
    match req.origin {
        Origin::Number(n) => ensure!(
            first_number == n,
            "the first header is block {first_number}, the request starts at {n}"
        ),
        Origin::Hash(h) => ensure!(
            eth::header_hash(first) == h,
            "the first header's hash is {}, the request starts at {}",
            eth::hex0x(&eth::header_hash(first)),
            eth::hex0x(&h)
        ),
    }
    for (i, h) in headers.iter().enumerate() {
        let n = eth::header_number(h)?;
        let want = req.number_at(first_number, i as u64);
        ensure!(
            Some(n) == want,
            "headers[{i}] is block {n}, the request asks for {want:?} there"
        );
    }
    ensure!(
        linked(req, headers),
        "the headers do not form a chain: a header's parentHash is not the previous header's hash"
    );
    Ok(())
}

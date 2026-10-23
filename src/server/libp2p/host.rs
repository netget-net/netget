//! One libp2p connection, either role: upgrading TCP to Noise and yamux, answering the
//! peer's identify, identify-push and ping streams in Rust, and turning the application
//! protocols' streams into messages (uvarint-length-prefixed, the libp2p convention).
use super::noise::{self, Identity, NoiseConn};
use super::wire::{self, Io};
use super::yamux::{Opener, Stream, StreamWriter};
use super::{bitswap, kad};
use anyhow::{ensure, Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The application protocol a host speaks when none is configured.
pub const DEFAULT_PROTOCOLS: &[&str] = &["/netget/chat/1.0.0"];
/// One application message is at most this long (go-msgio's own default is 8 MiB; NetGet
/// hands each to a model).
pub const MAX_MESSAGE: usize = 1024 * 1024;
/// Negotiating security, the multiplexer, or a stream's protocol.
pub const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);
pub const AGENT: &str = concat!("netget/", env!("CARGO_PKG_VERSION"));
pub const PROTOCOL_VERSION: &str = "ipfs/0.1.0";
/// Streams whose writers a connection keeps for actions.
pub const MAX_REMEMBERED_STREAMS: usize = 1024;
/// A ping is 32 random bytes echoed back.
pub const PING_SIZE: usize = 32;

pub struct Config {
    pub identity: Identity,
    pub protocols: Vec<String>,
    pub listen_addrs: Vec<Vec<u8>>,
    /// Accept Bitswap streams (`/ipfs/bitswap/1.2.0` and older) and advertise them.
    pub bitswap: bool,
    /// Accept Kademlia DHT streams (`/ipfs/kad/1.0.0`, `/ipfs/lan/kad/1.0.0`) and advertise
    /// them, which makes this host a DHT server in its peers' eyes.
    pub kad: bool,
    /// The peers connected to this host and the addresses their identify gave, for DHT
    /// answers. One entry per live connection, so it is bounded by the connection limit.
    pub directory: Directory,
    /// The UnixFS content this host serves over Bitswap, built from descriptions.
    pub dag: Arc<super::unixfs::Shared>,
}

/// Connected peers (base58 id) and their listen addresses (binary multiaddrs).
pub type Directory = Arc<Mutex<BTreeMap<String, Vec<Vec<u8>>>>>;

impl Config {
    /// Every protocol this host answers, in the order identify lists them.
    pub fn served_protocols(&self) -> Vec<String> {
        let mut out: Vec<String> = [wire::IDENTIFY, wire::IDENTIFY_PUSH, wire::PING]
            .iter()
            .map(|s| s.to_string())
            .collect();
        if self.bitswap {
            out.extend(bitswap::PROTOCOLS.iter().map(|s| s.to_string()));
        }
        if self.kad {
            out.extend(kad::PROTOCOLS.iter().map(|s| s.to_string()));
        }
        out.extend(self.protocols.iter().cloned());
        out
    }
    /// The longest message a stream of `protocol` may carry.
    pub fn max_message(&self, protocol: &str) -> usize {
        if bitswap::is_bitswap(protocol) {
            bitswap::MAX_MESSAGE
        } else if kad::is_kad(protocol) {
            kad::MAX_MESSAGE
        } else {
            MAX_MESSAGE
        }
    }
}

/// What a connection's streams report to whoever answers for it.
pub enum Note {
    Message {
        stream_id: u32,
        protocol: String,
        data: Vec<u8>,
    },
    /// The peer closed its half of a stream (or it failed); `error` says why when it failed.
    Closed {
        stream_id: u32,
        protocol: String,
        error: Option<String>,
    },
    /// The connection ended.
    Ended(Option<String>),
}

pub type Task = Pin<Box<dyn Future<Output = ()> + Send>>;
/// Spawns a task owned by the server or client this connection belongs to.
pub type Spawn = Arc<dyn Fn(Task) -> Task + Send + Sync>;

/// A live connection: what actions need to open, write and close streams.
pub struct Peer {
    pub opener: Opener,
    pub remote_peer: String,
    pub remote_addr: SocketAddr,
    pub streams: Mutex<HashMap<u32, (String, StreamWriter)>>,
    pub notes: mpsc::Sender<Note>,
}

impl Peer {
    pub fn writer(&self, stream_id: u32) -> Option<(String, StreamWriter)> {
        self.streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&stream_id)
            .cloned()
    }
    /// Keep a stream's writer for later actions; the oldest are dropped past a bound, so a
    /// peer opening and closing streams forever cannot grow the table.
    pub fn remember(&self, stream_id: u32, protocol: String, writer: StreamWriter) {
        let mut t = self.streams.lock().unwrap_or_else(|e| e.into_inner());
        while t.len() >= MAX_REMEMBERED_STREAMS {
            let oldest = *t.keys().min().expect("non-empty");
            t.remove(&oldest);
        }
        t.insert(stream_id, (protocol, writer));
    }
    pub fn forget(&self, stream_id: u32) {
        self.streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&stream_id);
    }
}

/// Listener side: select `/noise`, handshake as responder, select `/yamux/1.0.0`.
pub async fn upgrade_inbound(mut tcp: TcpStream, cfg: &Config) -> Result<NoiseConn> {
    tokio::time::timeout(NEGOTIATION_TIMEOUT, async {
        wire::ms_listen(&mut tcp, |p| p == wire::NOISE).await?;
        let mut conn = noise::handshake(tcp, &cfg.identity, false, None).await?;
        wire::ms_listen(&mut conn, |p| p == wire::YAMUX).await?;
        Ok(conn)
    })
    .await
    .context("libp2p upgrade timed out")?
}

/// Dialler side; `expected` is the peer id the address named, if any.
pub async fn upgrade_outbound(
    mut tcp: TcpStream,
    cfg: &Config,
    expected: Option<&[u8]>,
) -> Result<NoiseConn> {
    tokio::time::timeout(NEGOTIATION_TIMEOUT, async {
        ensure!(
            wire::ms_dial(&mut tcp, wire::NOISE).await?,
            "the peer does not speak /noise"
        );
        let mut conn = noise::handshake(tcp, &cfg.identity, true, expected).await?;
        ensure!(
            wire::ms_dial(&mut conn, wire::YAMUX).await?,
            "the peer does not speak /yamux/1.0.0"
        );
        Ok(conn)
    })
    .await
    .context("libp2p upgrade timed out")?
}

/// Serve every stream the peer opens until the connection ends.
pub async fn accept_streams(
    mut incoming: mpsc::Receiver<Stream>,
    cfg: Arc<Config>,
    peer: Arc<Peer>,
    spawn: Spawn,
) {
    while let Some(stream) = incoming.recv().await {
        spawn(Box::pin(inbound(stream, cfg.clone(), peer.clone()))).await;
    }
}

async fn inbound(mut stream: Stream, cfg: Arc<Config>, peer: Arc<Peer>) {
    let served = cfg.served_protocols();
    let supported = |p: &str| served.iter().any(|x| x == p);
    let writer = stream.writer();
    let protocol =
        match tokio::time::timeout(NEGOTIATION_TIMEOUT, wire::ms_listen(&mut stream, supported))
            .await
        {
            Ok(Ok(p)) => p,
            _ => {
                writer.reset();
                return;
            }
        };
    match protocol.as_str() {
        wire::IDENTIFY => {
            let msg = wire::encode_identify(&wire::Identify {
                protocol_version: PROTOCOL_VERSION.into(),
                agent_version: AGENT.into(),
                public_key: cfg.identity.public_key_proto.clone(),
                listen_addrs: cfg.listen_addrs.clone(),
                observed_addr: Some(wire::multiaddr_bytes(&peer.remote_addr)),
                protocols: cfg.served_protocols(),
            });
            let _ = writer.send(wire::length_prefixed(&msg));
            writer.close();
        }
        wire::IDENTIFY_PUSH => {
            // Read (bounded) and let it go: NetGet keeps what the first identify said.
            let _ = wire::read_length_prefixed(&mut stream, wire::MAX_IDENTIFY_BYTES).await;
            writer.close();
        }
        wire::PING => {
            let mut b = [0u8; PING_SIZE];
            while stream.read_exact(&mut b).await.is_ok() {
                if writer.send(b.to_vec()).is_err() {
                    break;
                }
            }
            writer.close();
        }
        _ => {
            peer.remember(stream.id, protocol.clone(), writer);
            let max = cfg.max_message(&protocol);
            read_messages(stream, protocol, peer.notes.clone(), max).await;
        }
    }
}

/// Turn a stream's messages (each at most `max` bytes) into notes until the peer closes it.
pub async fn read_messages(
    mut stream: Stream,
    protocol: String,
    notes: mpsc::Sender<Note>,
    max: usize,
) {
    let error = loop {
        match wire::read_length_prefixed(&mut stream, max).await {
            Ok(data) => {
                let note = Note::Message {
                    stream_id: stream.id,
                    protocol: protocol.clone(),
                    data,
                };
                if notes.send(note).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                let text = e.to_string();
                break (!text.contains("closed by the peer")).then_some(text);
            }
        }
    };
    if error.is_some() {
        stream.writer().reset();
    }
    let _ = notes
        .send(Note::Closed {
            stream_id: stream.id,
            protocol,
            error,
        })
        .await;
}

/// What the remote said about itself.
pub struct Remote {
    pub agent_version: String,
    pub protocol_version: String,
    pub protocols: Vec<String>,
    pub listen_addrs: Vec<String>,
    pub observed_addr: Option<String>,
}

/// Ask the remote's identify.
pub async fn identify(peer: &Peer) -> Result<Remote> {
    tokio::time::timeout(NEGOTIATION_TIMEOUT, async {
        let mut s = peer.opener.open()?;
        ensure!(
            wire::ms_dial(&mut s, wire::IDENTIFY).await?,
            "the peer does not answer identify"
        );
        let msg = wire::read_length_prefixed(&mut s, wire::MAX_IDENTIFY_BYTES).await?;
        s.writer().close();
        let id = wire::decode_identify(&msg)?;
        Ok(Remote {
            agent_version: id.agent_version,
            protocol_version: id.protocol_version,
            protocols: id.protocols,
            listen_addrs: id
                .listen_addrs
                .iter()
                .filter_map(|a| wire::multiaddr_text(a).ok())
                .collect(),
            observed_addr: id.observed_addr.and_then(|a| wire::multiaddr_text(&a).ok()),
        })
    })
    .await
    .context("identify timed out")?
}

/// Ping the remote once: the round trip.
pub async fn ping(peer: &Peer) -> Result<Duration> {
    tokio::time::timeout(NEGOTIATION_TIMEOUT, async {
        let mut s = peer.opener.open()?;
        ensure!(
            wire::ms_dial(&mut s, wire::PING).await?,
            "the peer does not answer ping"
        );
        let payload: [u8; PING_SIZE] = rand::random();
        let started = crate::utils::clock::Instant::now();
        s.write_all(&payload).await?;
        let mut back = [0u8; PING_SIZE];
        s.read_exact(&mut back).await?;
        let rtt = started.elapsed();
        s.writer().close();
        ensure!(back == payload, "the ping came back different");
        Ok(rtt)
    })
    .await
    .context("ping timed out")?
}

/// Open a stream for an application protocol; None when the peer refuses the protocol.
/// Its messages arrive as notes, read by the task this returns.
pub async fn open_app_stream(peer: &Arc<Peer>, protocol: &str) -> Result<Option<(u32, Task)>> {
    let mut s = peer.opener.open()?;
    let accepted = tokio::time::timeout(NEGOTIATION_TIMEOUT, wire::ms_dial(&mut s, protocol))
        .await
        .context("protocol negotiation timed out")??;
    if !accepted {
        s.writer().close();
        return Ok(None);
    }
    let id = s.id;
    peer.remember(id, protocol.to_string(), s.writer());
    let reader: Task = Box::pin(read_messages(
        s,
        protocol.to_string(),
        peer.notes.clone(),
        MAX_MESSAGE,
    ));
    Ok(Some((id, reader)))
}

/// Open a stream proposing each of `protocols` in turn: the stream and the protocol the peer
/// accepted, or None when it accepts none of them. The caller owns the stream.
pub async fn open_negotiated(peer: &Peer, protocols: &[&str]) -> Result<Option<(Stream, String)>> {
    let mut s = peer.opener.open()?;
    let accepted = tokio::time::timeout(NEGOTIATION_TIMEOUT, wire::ms_dial_any(&mut s, protocols))
        .await
        .context("protocol negotiation timed out")??;
    match accepted {
        Some(p) => Ok(Some((s, p))),
        None => {
            s.writer().close();
            Ok(None)
        }
    }
}

/// Write one message to a stream this connection has open.
pub fn send(peer: &Peer, stream_id: u32, data: &[u8]) -> Result<()> {
    ensure!(
        data.len() <= MAX_MESSAGE,
        "message longer than {MAX_MESSAGE} bytes"
    );
    let (_, w) = peer
        .writer(stream_id)
        .with_context(|| format!("no open stream {stream_id}"))?;
    w.send(wire::length_prefixed(data))
}

//! yamux (the hashicorp spec, `/yamux/1.0.0`) over a Noise channel. One task reads frames
//! and routes them to streams; one task owns the writer and every stream's send window, so
//! data the peer has no window for waits there rather than being sent past its limit.
use super::noise::{NoiseConn, NoiseReader, NoiseWriter};
use super::wire::Io;
use anyhow::{bail, ensure, Result};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Each side's starting receive window per stream (the spec's 256 KiB).
pub const INITIAL_WINDOW: u32 = 256 * 1024;
/// Streams the peer may have open on one connection; past it, new ones are reset.
pub const MAX_STREAMS: usize = 256;
/// One data frame carries at most this much.
pub const MAX_FRAME_DATA: usize = 64 * 1024;

const T_DATA: u8 = 0;
const T_WINDOW: u8 = 1;
const T_PING: u8 = 2;
const T_GO_AWAY: u8 = 3;
const F_SYN: u16 = 1;
const F_ACK: u16 = 2;
const F_FIN: u16 = 4;
const F_RST: u16 = 8;

fn header(kind: u8, flags: u16, id: u32, len: u32) -> [u8; 12] {
    let mut h = [0u8; 12];
    h[1] = kind;
    h[2..4].copy_from_slice(&flags.to_be_bytes());
    h[4..8].copy_from_slice(&id.to_be_bytes());
    h[8..12].copy_from_slice(&len.to_be_bytes());
    h
}

enum Cmd {
    Open(u32),
    Ack(u32),
    Data(u32, Vec<u8>),
    Fin(u32),
    Rst(u32),
    Grant(u32, u32),
    PeerWindow(u32, u32),
    Pong(u32),
    GoAway(u32),
}

impl Cmd {
    /// Bytes this command puts on the wire, for the session's outbound bound: a 12-byte yamux
    /// header plus any payload.
    fn weight(&self) -> usize {
        match self {
            Cmd::Data(_, payload) => 12 + payload.len(),
            _ => 12,
        }
    }
}

struct Inbound {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Bytes the peer may still send before it must wait for a window update.
    window: Arc<AtomicI64>,
}

type Table = Arc<Mutex<HashMap<u32, Inbound>>>;

/// One multiplexed stream. Reading pulls the peer's data. Our half stays open until
/// [`StreamWriter::close`], so a reply can follow the peer's own half-close.
pub struct Stream {
    pub id: u32,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
    consumed: u32,
    window: Arc<AtomicI64>,
    writer: StreamWriter,
}

/// The write side of a stream, which can be held apart from its reader.
#[derive(Clone)]
pub struct StreamWriter {
    pub id: u32,
    cmd: crate::utils::outbox::OutboxSender<Cmd>,
}

impl StreamWriter {
    pub fn send(&self, data: Vec<u8>) -> Result<()> {
        for chunk in data.chunks(MAX_FRAME_DATA) {
            self.cmd
                .send(Cmd::Data(self.id, chunk.to_vec()))
                .map_err(|_| anyhow::anyhow!("connection closed"))?;
        }
        Ok(())
    }
    /// Half-close: the peer reads EOF after everything sent so far.
    pub fn close(&self) {
        let _ = self.cmd.send(Cmd::Fin(self.id));
    }
    pub fn reset(&self) {
        let _ = self.cmd.send(Cmd::Rst(self.id));
    }
}

impl Stream {
    pub fn writer(&self) -> StreamWriter {
        self.writer.clone()
    }
    /// The next chunk of data, or None once the peer has closed its half.
    pub async fn next_chunk(&mut self) -> Option<Vec<u8>> {
        if self.pos < self.buf.len() {
            let rest = self.buf[self.pos..].to_vec();
            self.pos = self.buf.len();
            return Some(rest);
        }
        let chunk = self.rx.recv().await?;
        self.consumed(chunk.len());
        Some(chunk)
    }
    fn consumed(&mut self, n: usize) {
        self.consumed += n as u32;
        if self.consumed >= INITIAL_WINDOW / 2 {
            let delta = self.consumed;
            self.consumed = 0;
            self.window.fetch_add(i64::from(delta), Ordering::SeqCst);
            let _ = self.writer.cmd.send(Cmd::Grant(self.id, delta));
        }
    }
}

impl Io for Stream {
    async fn read_exact(&mut self, out: &mut [u8]) -> Result<()> {
        let mut done = 0;
        while done < out.len() {
            if self.pos == self.buf.len() {
                match self.rx.recv().await {
                    Some(chunk) => {
                        self.consumed(chunk.len());
                        self.buf = chunk;
                        self.pos = 0;
                    }
                    None => bail!("stream closed by the peer"),
                }
                continue;
            }
            let n = (out.len() - done).min(self.buf.len() - self.pos);
            out[done..done + n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            done += n;
        }
        Ok(())
    }
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> impl Future<Output = Result<()>> + Send + 'a {
        let r = self.writer.send(buf.to_vec());
        async move { r }
    }
}

/// Opens outbound streams; cheap to clone.
#[derive(Clone)]
pub struct Opener {
    cmd: crate::utils::outbox::OutboxSender<Cmd>,
    next_id: Arc<AtomicU32>,
    table: Table,
}

impl Opener {
    pub fn open(&self) -> Result<Stream> {
        let id = self.next_id.fetch_add(2, Ordering::SeqCst);
        let (tx, rx) = mpsc::unbounded_channel();
        let window = Arc::new(AtomicI64::new(i64::from(INITIAL_WINDOW)));
        {
            let mut t = self.table.lock().unwrap_or_else(|e| e.into_inner());
            ensure!(t.len() < MAX_STREAMS, "too many open streams");
            t.insert(
                id,
                Inbound {
                    tx,
                    window: window.clone(),
                },
            );
        }
        self.cmd
            .send(Cmd::Open(id))
            .map_err(|_| anyhow::anyhow!("connection closed"))?;
        Ok(Stream {
            id,
            rx,
            buf: Vec::new(),
            pos: 0,
            consumed: 0,
            window,
            writer: StreamWriter {
                id,
                cmd: self.cmd.clone(),
            },
        })
    }
    /// Tell the peer we are leaving, then close the connection.
    pub fn go_away(&self) {
        let _ = self.cmd.send(Cmd::GoAway(0));
    }
}

/// A yamux session: the opener, the peer's new streams, and the two futures that run it
/// (which the caller spawns and registers).
pub struct Session {
    pub opener: Opener,
    pub incoming: mpsc::Receiver<Stream>,
    pub reader: std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send>>,
    pub writer: std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send>>,
}

/// Start yamux on a secured connection; `client` is the side that dialled it (odd stream ids).
pub fn session(conn: NoiseConn, client: bool) -> Session {
    // Bounded: the read loop answers every PING and SYN at once, so a peer that sends without
    // reading is cut off rather than queued for (`utils::outbox`).
    let (cmd, cmd_rx) = crate::utils::outbox::channel(
        "libp2p yamux session",
        crate::utils::outbox::OutboxLimits::DEFAULT,
        Cmd::weight,
    );
    let table: Table = Arc::new(Mutex::new(HashMap::new()));
    let (incoming_tx, incoming) = mpsc::channel(MAX_STREAMS);
    let opener = Opener {
        cmd: cmd.clone(),
        next_id: Arc::new(AtomicU32::new(if client { 1 } else { 2 })),
        table: table.clone(),
    };
    Session {
        opener,
        incoming,
        reader: Box::pin(read_loop(conn.reader, cmd, table, incoming_tx, client)),
        writer: Box::pin(write_loop(conn.writer, cmd_rx)),
    }
}

async fn read_loop(
    mut r: NoiseReader,
    cmd: crate::utils::outbox::OutboxSender<Cmd>,
    table: Table,
    incoming: mpsc::Sender<Stream>,
    client: bool,
) -> Result<()> {
    let result = async {
        loop {
            let mut h = [0u8; 12];
            r.read_exact(&mut h).await?;
            ensure!(h[0] == 0, "unsupported yamux version {}", h[0]);
            let kind = h[1];
            let flags = u16::from_be_bytes([h[2], h[3]]);
            let id = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
            let len = u32::from_be_bytes([h[8], h[9], h[10], h[11]]);
            match kind {
                T_PING => {
                    if flags & F_SYN != 0 {
                        let _ = cmd.send(Cmd::Pong(len));
                    }
                    continue;
                }
                T_GO_AWAY => return Ok(()),
                T_DATA | T_WINDOW => {}
                k => bail!("unknown yamux frame type {k}"),
            }
            if flags & F_SYN != 0 {
                // A stream the peer opens has the peer's parity: odd from a dialler.
                let theirs = (id % 2 == 1) != client;
                let mut t = table.lock().unwrap_or_else(|e| e.into_inner());
                if !theirs || id == 0 || t.contains_key(&id) {
                    drop(t);
                    bail!("invalid stream id {id} in SYN");
                }
                if t.len() >= MAX_STREAMS {
                    drop(t);
                    let _ = cmd.send(Cmd::Rst(id));
                } else {
                    let (tx, rx) = mpsc::unbounded_channel();
                    let window = Arc::new(AtomicI64::new(i64::from(INITIAL_WINDOW)));
                    t.insert(
                        id,
                        Inbound {
                            tx,
                            window: window.clone(),
                        },
                    );
                    drop(t);
                    let _ = cmd.send(Cmd::Ack(id));
                    let stream = Stream {
                        id,
                        rx,
                        buf: Vec::new(),
                        pos: 0,
                        consumed: 0,
                        window,
                        writer: StreamWriter {
                            id,
                            cmd: cmd.clone(),
                        },
                    };
                    if incoming.try_send(stream).is_err() {
                        table.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                    }
                }
            }
            if kind == T_WINDOW {
                if len > 0 {
                    let _ = cmd.send(Cmd::PeerWindow(id, len));
                }
            } else if len > 0 {
                let mut data = vec![0u8; len as usize];
                // The peer may not send more than the window it was given.
                let window = table
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&id)
                    .map(|s| s.window.clone());
                if let Some(w) = &window {
                    ensure!(
                        w.fetch_sub(i64::from(len), Ordering::SeqCst) >= i64::from(len),
                        "peer sent {len} bytes past stream {id}'s receive window"
                    );
                } else {
                    ensure!(
                        len as usize <= INITIAL_WINDOW as usize,
                        "data frame larger than any window"
                    );
                }
                r.read_exact(&mut data).await?;
                if let Some(s) = table.lock().unwrap_or_else(|e| e.into_inner()).get(&id) {
                    let _ = s.tx.send(data);
                }
            }
            if flags & (F_FIN | F_RST) != 0 {
                // Dropping the sender is the reader's EOF.
                table.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
            }
        }
    }
    .await;
    table.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let _ = cmd.send(Cmd::GoAway(0));
    result
}

#[derive(Default)]
struct Outbound {
    window: u32,
    pending: VecDeque<Vec<u8>>,
    fin: bool,
}

async fn write_loop(
    mut w: NoiseWriter,
    mut cmds: crate::utils::outbox::OutboxReceiver<Cmd>,
) -> Result<()> {
    let mut streams: HashMap<u32, Outbound> = HashMap::new();
    let fresh = || Outbound {
        window: INITIAL_WINDOW,
        ..Default::default()
    };
    while let Some(c) = cmds.recv().await {
        let flush_id = match c {
            Cmd::Open(id) => {
                streams.insert(id, fresh());
                w.write_all(&header(T_WINDOW, F_SYN, id, 0)).await?;
                None
            }
            Cmd::Ack(id) => {
                streams.insert(id, fresh());
                w.write_all(&header(T_WINDOW, F_ACK, id, 0)).await?;
                None
            }
            Cmd::Data(id, data) => {
                if let Some(s) = streams.get_mut(&id) {
                    if !s.fin {
                        s.pending.push_back(data);
                    }
                }
                Some(id)
            }
            Cmd::Fin(id) => {
                if let Some(s) = streams.get_mut(&id) {
                    s.fin = true;
                }
                Some(id)
            }
            Cmd::Rst(id) => {
                streams.remove(&id);
                w.write_all(&header(T_WINDOW, F_RST, id, 0)).await?;
                None
            }
            Cmd::Grant(id, delta) => {
                w.write_all(&header(T_WINDOW, 0, id, delta)).await?;
                None
            }
            Cmd::PeerWindow(id, delta) => {
                if let Some(s) = streams.get_mut(&id) {
                    s.window = s.window.saturating_add(delta);
                }
                Some(id)
            }
            Cmd::Pong(v) => {
                w.write_all(&header(T_PING, F_ACK, 0, v)).await?;
                None
            }
            Cmd::GoAway(code) => {
                let _ = w.write_all(&header(T_GO_AWAY, 0, 0, code)).await;
                w.shutdown().await;
                return Ok(());
            }
        };
        let Some(id) = flush_id else { continue };
        let Some(s) = streams.get_mut(&id) else {
            continue;
        };
        let mut out = Vec::new();
        while s.window > 0 {
            let Some(front) = s.pending.front_mut() else {
                break;
            };
            let n = front.len().min(s.window as usize);
            out.extend_from_slice(&header(T_DATA, 0, id, n as u32));
            out.extend(front.drain(..n));
            s.window -= n as u32;
            if front.is_empty() {
                s.pending.pop_front();
            }
        }
        if s.fin && s.pending.is_empty() {
            out.extend_from_slice(&header(T_WINDOW, F_FIN, id, 0));
            streams.remove(&id);
        }
        if !out.is_empty() {
            w.write_all(&out).await?;
        }
    }
    w.shutdown().await;
    Ok(())
}

//! OpenFlow 1.3 controller — a switch connects over TCP (6653) and NetGet is its controller.
//!
//! Rust runs the session: both sides send HELLO and negotiate 1.3 from the version bitmap; the
//! controller then asks for FEATURES, sets the switch to send whole packets (SET_CONFIG with
//! `OFPCML_NO_BUFFER`), asks for the switch's description and ports (DESC and PORT_DESC
//! multipart), and raises `openflow_switch_connected`. From then on it answers ECHO, sends its
//! own ECHO to a quiet switch and disconnects one that stops answering, matches every reply to
//! the request it answers by xid, reassembles multipart replies, and refuses what a switch
//! should not send (with an OpenFlow ERROR naming the offending message).
//!
//! The model decides the network: the flows on connect, what happens to each PACKET_IN, which
//! statistics to read, and how to react to FLOW_REMOVED, PORT_STATUS and ERROR.
//!
//! ## Two tasks per connection, and why
//!
//! The connection loop never waits on the model. A switch expects ECHO_REPLY within seconds
//! (Open vSwitch's inactivity probe is five) and a model may take thirty, so events go to a
//! worker task through a bounded queue of [`MAX_QUEUED_EVENTS`]; one model call runs at a time
//! per switch, in arrival order. A full queue drops the event — for a PACKET_IN, the packet is
//! not forwarded — and says so (`decision=fail_closed_queue_full`).
//!
//! ## Failing closed
//!
//! With no usable answer for a PACKET_IN nothing is sent: no PACKET_OUT and no flow, so the
//! packet goes nowhere, exactly as the switch's own table miss would leave it. There is no
//! default flood. Each event the model is asked about logs exactly one `decision=` line:
//! `model_answer`, `model_reject` (an explicit drop or disconnect), `model_silent`,
//! `fail_closed_bad_action`, `fail_closed_llm_error` / `fail_closed_llm_overloaded`, or
//! `fail_closed_queue_full` / `followup_depth` when it was never asked.
pub mod actions;
pub mod fields;
pub mod packet;
pub mod wire;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::{ActionResult, Server};
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::{Event, EventType};
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::state::{AccessLogOwner, ServerId};
use actions::OpenFlowProtocol;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex};
use wire::{err, msg, Message, VERSION_1_3};

/// How long a new connection has to send its HELLO.
const FIRST_MESSAGE_TIMEOUT: Duration = Duration::from_secs(30);
/// A backstop on a silent socket. Liveness is the echo keepalive (`echo_interval_secs`); this
/// only bounds a connection whose keepalive somehow never fires.
const IDLE_BETWEEN_MESSAGES_TIMEOUT: Duration = Duration::from_secs(1800);
/// How long the switch has to answer FEATURES_REQUEST once the HELLOs are exchanged, and to
/// answer the DESC and PORT_DESC queries before the switch is announced without them.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a statistics request may wait for its (last) reply.
const REPLY_TIMEOUT: Duration = Duration::from_secs(60);
/// Concurrent switch connections.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;
/// Requests waiting for a reply on one connection.
pub const MAX_OUTSTANDING_XIDS: usize = 256;
/// Of those, multipart requests being reassembled.
pub const MAX_OUTSTANDING_MULTIPART: usize = 16;
/// The largest multipart reply reassembled, all parts together.
pub const MAX_MULTIPART_BYTES: usize = 1 << 20;
/// The most parts one multipart reply may arrive in.
pub const MAX_MULTIPART_PARTS: usize = 512;
/// Received packets kept so a later PACKET_OUT or FLOW_MOD can name them by packet_in_id.
pub const MAX_STORED_PACKETS: usize = 128;
/// Events waiting for the model on one connection.
pub const MAX_QUEUED_EVENTS: usize = 64;
/// How many model turns may follow from one another (an ERROR answering a FLOW_MOD the model
/// sent in answer to an ERROR …) before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// Entries of a statistics reply shown to the model.
pub const MAX_REPORTED_ENTRIES: usize = 256;
/// Messages remembered after sending, so an ERROR can be traced to what it refused.
const RECENT_SENT: usize = 64;

/// What a switch over [`MAX_CONNECTIONS`] reads: an OpenFlow 1.3 ERROR, HELLO_FAILED / EPERM,
/// carrying the reason as text, as the spec allows for HELLO_FAILED.
pub const CONNECTION_CAP_REFUSAL: &[u8] =
    b"\x04\x01\x00\x24\x00\x00\x00\x00\x00\x00\x00\x01connection limit reached";

/// What a switch offering no version we speak reads.
pub const INCOMPATIBLE_TEXT: &str = "this controller speaks OpenFlow 1.3 (wire version 4) only";

pub struct OpenFlowServer;

struct Shared {
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: ServerId,
    echo_interval: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    Features,
    /// A multipart query the handshake sent (DESC or PORT_DESC).
    Handshake(u16),
    /// A multipart query the model sent.
    Stats(u16),
}

struct Outstanding {
    expect: Expect,
    depth: u32,
    sent: crate::utils::clock::Instant,
    parts: Vec<u8>,
    n_parts: usize,
}

struct Sent {
    xid: u32,
    msg_type: u8,
    what: String,
    depth: u32,
}

#[derive(Clone)]
struct StoredPacket {
    buffer_id: u32,
    in_port: u32,
    data: Vec<u8>,
}

#[derive(Default)]
struct Book {
    replies: HashMap<u32, Outstanding>,
    recent: VecDeque<Sent>,
    packets: HashMap<String, StoredPacket>,
    packet_order: VecDeque<String>,
    next_packet: u64,
}

/// One switch connection, shared by its loop and its model worker.
struct Conn {
    shared: Arc<Shared>,
    connection_id: ConnectionId,
    writer: Mutex<WriteHalf<TcpStream>>,
    next_xid: AtomicU32,
    book: std::sync::Mutex<Book>,
    datapath_id: std::sync::Mutex<String>,
    close: watch::Sender<bool>,
}

impl Conn {
    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.shared.status_tx))
    }

    fn dpid(&self) -> String {
        self.datapath_id
            .lock()
            .map(|d| d.clone())
            .unwrap_or_default()
    }

    async fn write(&self, bytes: &[u8]) -> Result<()> {
        {
            let mut w = self.writer.lock().await;
            w.write_all(bytes).await?;
            w.flush().await?;
        }
        self.shared
            .app_state
            .update_connection_stats(
                self.shared.server_id,
                self.connection_id,
                None,
                Some(bytes.len() as u64),
                None,
                Some(1),
            )
            .await;
        Ok(())
    }

    /// Send a message with a fresh xid. `track` registers it as waiting for a reply.
    async fn send(
        &self,
        msg_type: u8,
        body: &[u8],
        track: Option<Expect>,
        depth: u32,
        what: &str,
    ) -> Result<u32> {
        let mut xid = self.next_xid.fetch_add(1, Ordering::SeqCst);
        if xid == 0 {
            xid = self.next_xid.fetch_add(1, Ordering::SeqCst);
        }
        let bytes = wire::encode(VERSION_1_3, msg_type, xid, body)?;
        {
            let mut book = self
                .book
                .lock()
                .map_err(|_| anyhow::anyhow!("connection state poisoned"))?;
            if let Some(expect) = track {
                if book.replies.len() >= MAX_OUTSTANDING_XIDS {
                    bail!("{MAX_OUTSTANDING_XIDS} requests are already waiting for the switch");
                }
                let multipart = book
                    .replies
                    .values()
                    .filter(|o| matches!(o.expect, Expect::Stats(_) | Expect::Handshake(_)))
                    .count();
                if matches!(expect, Expect::Stats(_)) && multipart >= MAX_OUTSTANDING_MULTIPART {
                    bail!(
                        "{MAX_OUTSTANDING_MULTIPART} statistics requests are already waiting \
                         for the switch"
                    );
                }
                book.replies.insert(
                    xid,
                    Outstanding {
                        expect,
                        depth,
                        sent: crate::utils::clock::Instant::now(),
                        parts: Vec::new(),
                        n_parts: 0,
                    },
                );
            }
            book.recent.push_back(Sent {
                xid,
                msg_type,
                what: what.to_string(),
                depth,
            });
            while book.recent.len() > RECENT_SENT {
                book.recent.pop_front();
            }
        }
        if let Err(e) = self.write(&bytes).await {
            if let Ok(mut book) = self.book.lock() {
                book.replies.remove(&xid);
            }
            return Err(e);
        }
        Ok(xid)
    }

    async fn reply(&self, msg_type: u8, xid: u32, body: &[u8]) -> Result<()> {
        self.write(&wire::encode(VERSION_1_3, msg_type, xid, body)?)
            .await
    }

    /// Refuse a message the switch sent with an ERROR echoing it.
    async fn refuse(&self, m: &Message, etype: u16, code: u16, why: &str) {
        self.log().warn(format!(
            "OpenFlow {} from switch {} refused with {}/{} decision=protocol_error: {why}",
            wire::msg_name(m.header.msg_type),
            self.dpid(),
            wire::error_type_name(etype),
            wire::error_code_name(etype, code)
        ));
        let _ = self
            .reply(
                msg::ERROR,
                m.header.xid,
                &wire::protocol_error(etype, code, m),
            )
            .await;
    }

    fn store_packet(&self, p: StoredPacket) -> String {
        let Ok(mut book) = self.book.lock() else {
            return String::new();
        };
        book.next_packet += 1;
        let id = format!("pi-{}", book.next_packet);
        book.packets.insert(id.clone(), p);
        book.packet_order.push_back(id.clone());
        while book.packet_order.len() > MAX_STORED_PACKETS {
            if let Some(old) = book.packet_order.pop_front() {
                book.packets.remove(&old);
            }
        }
        id
    }

    fn packet(&self, id: &str) -> Option<StoredPacket> {
        self.book.lock().ok()?.packets.get(id).cloned()
    }
}

/// One event for the model.
struct Job {
    event: Event,
    depth: u32,
    packet_in_id: Option<String>,
}

impl OpenFlowServer {
    pub async fn spawn(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        echo_interval: Duration,
    ) -> Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        // The E2E harness parses the port out of everything after the last "on ".
        Log::new(Some(&status_tx)).info(format!("OpenFlow controller listening on {local_addr}"));
        let shared = Arc::new(Shared {
            app_state: app_state.clone(),
            llm_client,
            status_tx: status_tx.clone(),
            server_id,
            echo_interval,
        });
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let registrar = app_state.clone();
        let accept = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "OpenFlow",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote, permit)) => {
                        let shared = shared.clone();
                        let local = stream.local_addr().unwrap_or(local_addr);
                        let owner = app_state.clone();
                        owner
                            .spawn_server_task(server_id, async move {
                                let _permit = permit;
                                if let Err(e) =
                                    handle_connection(shared.clone(), stream, remote, local).await
                                {
                                    Log::new(Some(&shared.status_tx)).debug(format!(
                                        "OpenFlow connection from {remote} ended: {e:#}"
                                    ));
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("OpenFlow accept failed, stopping loop: {e}"));
                        break;
                    }
                }
            }
        });
        registrar.register_server_task(server_id, accept).await;
        Ok(local_addr)
    }
}

async fn handle_connection(
    shared: Arc<Shared>,
    stream: TcpStream,
    remote: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    let app_state = shared.app_state.clone();
    let server_id = shared.server_id;
    let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);
    let _ = stream.set_nodelay(true);
    let (read_half, write_half) = tokio::io::split(stream);
    let now = crate::utils::clock::Instant::now();
    app_state
        .add_connection_to_server(
            server_id,
            ConnectionState {
                id: connection_id,
                remote_addr: remote,
                local_addr: local,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                last_activity: now,
                status: ConnectionStatus::Active,
                status_changed_at: now,
                protocol_info: ProtocolConnectionInfo::empty(),
            },
        )
        .await;
    let _ = shared.status_tx.send("__UPDATE_UI__".to_string());
    let peer_rx = crate::server::peer_support::register_peer_channel(
        &app_state,
        server_id,
        connection_id.as_u32(),
    )
    .await;
    let (close_tx, close_rx) = watch::channel(false);
    let conn = Arc::new(Conn {
        shared: shared.clone(),
        connection_id,
        writer: Mutex::new(write_half),
        next_xid: AtomicU32::new(1),
        book: std::sync::Mutex::new(Book::default()),
        datapath_id: std::sync::Mutex::new(String::from("unknown")),
        close: close_tx,
    });

    // The reader: whole messages, bounded by the 16-bit length, into the loop's channel.
    let (msg_tx, msg_rx) = mpsc::channel::<std::result::Result<Message, String>>(16);
    let mut reader = crate::server::accept_bounded::IdleTimeoutReader::with_first(
        read_half,
        FIRST_MESSAGE_TIMEOUT,
        IDLE_BETWEEN_MESSAGES_TIMEOUT,
    );
    let reader_task = app_state
        .spawn_server_task(server_id, async move {
            loop {
                match wire::read_message(&mut reader).await {
                    Ok(m) => {
                        if msg_tx.send(Ok(m)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = msg_tx.send(Err(e.to_string())).await;
                        break;
                    }
                }
            }
        })
        .await;
    let (job_tx, job_rx) = mpsc::channel::<Job>(MAX_QUEUED_EVENTS);
    let worker_conn = conn.clone();
    let worker_task = app_state
        .spawn_server_task(server_id, async move { worker(worker_conn, job_rx).await })
        .await;

    let result = run(&conn, msg_rx, peer_rx, close_rx, &job_tx, remote).await;

    reader_task.abort();
    drop(job_tx);
    worker_task.abort();
    {
        let mut w = conn.writer.lock().await;
        let _ = w.shutdown().await;
    }
    app_state
        .remove_peer_handle(server_id, connection_id.as_u32())
        .await;
    app_state
        .remove_connection_from_server(server_id, connection_id)
        .await;
    let _ = shared.status_tx.send("__UPDATE_UI__".to_string());
    result
}

/// What the handshake has learned about the switch.
#[derive(Default)]
struct Handshake {
    features: Option<wire::Features>,
    desc: Option<Value>,
    desc_done: bool,
    ports: Vec<Value>,
    ports_done: bool,
    announced: bool,
}

/// The connection loop: HELLO, the handshake, then every message the switch sends.
async fn run(
    conn: &Arc<Conn>,
    mut msgs: mpsc::Receiver<std::result::Result<Message, String>>,
    mut peer_rx: mpsc::Receiver<ClientCommand>,
    mut close_rx: watch::Receiver<bool>,
    jobs: &mpsc::Sender<Job>,
    remote: SocketAddr,
) -> Result<()> {
    let log = conn.log();
    conn.reply(msg::HELLO, 0, &wire::hello_body(&[VERSION_1_3]))
        .await?;
    // The first message must be the switch's HELLO.
    let first = match tokio::time::timeout(FIRST_MESSAGE_TIMEOUT, msgs.recv()).await {
        Ok(Some(Ok(m))) => m,
        Ok(Some(Err(e))) => bail!("before its HELLO: {e}"),
        Ok(None) => return Ok(()),
        Err(_) => {
            log.warn(format!(
                "OpenFlow peer {remote} sent no HELLO in {FIRST_MESSAGE_TIMEOUT:?} \
                 decision=protocol_timeout"
            ));
            return Ok(());
        }
    };
    count_in(conn, &first).await;
    if first.header.msg_type != msg::HELLO {
        conn.refuse(
            &first,
            err::HELLO_FAILED,
            err::HELLO_INCOMPATIBLE,
            "the first message was not HELLO",
        )
        .await;
        return Ok(());
    }
    let bitmap = match wire::parse_hello_bitmap(&first.body) {
        Ok(b) => b,
        Err(e) => {
            conn.refuse(
                &first,
                err::HELLO_FAILED,
                err::HELLO_INCOMPATIBLE,
                &e.to_string(),
            )
            .await;
            return Ok(());
        }
    };
    if wire::negotiate(first.header.version, bitmap.as_deref()).is_none() {
        let offered = match &bitmap {
            Some(b) => wire::bitmap_versions(b)
                .into_iter()
                .map(wire::version_name)
                .collect::<Vec<_>>()
                .join(", "),
            None => wire::version_name(first.header.version),
        };
        log.warn(format!(
            "OpenFlow peer {remote} offers {offered}, not 1.3 decision=protocol_reject_version"
        ));
        let _ = conn
            .reply(
                msg::ERROR,
                first.header.xid,
                &wire::error_body(
                    err::HELLO_FAILED,
                    err::HELLO_INCOMPATIBLE,
                    INCOMPATIBLE_TEXT.as_bytes(),
                ),
            )
            .await;
        return Ok(());
    }
    log.info(format!("OpenFlow switch {remote} negotiated version 1.3"));
    conn.send(
        msg::FEATURES_REQUEST,
        &[],
        Some(Expect::Features),
        0,
        "features request",
    )
    .await?;
    conn.send(
        msg::SET_CONFIG,
        &wire::config_body(0, wire::CML_NO_BUFFER),
        None,
        0,
        "set config (whole packets)",
    )
    .await?;
    conn.send(
        msg::MULTIPART_REQUEST,
        &wire::multipart_body(wire::mp::DESC, 0, &[]),
        Some(Expect::Handshake(wire::mp::DESC)),
        0,
        "description query",
    )
    .await?;
    conn.send(
        msg::MULTIPART_REQUEST,
        &wire::multipart_body(wire::mp::PORT_DESC, 0, &[]),
        Some(Expect::Handshake(wire::mp::PORT_DESC)),
        0,
        "port description query",
    )
    .await?;

    let started = crate::utils::clock::Instant::now();
    let mut hs = Handshake::default();
    let mut last_rx = crate::utils::clock::Instant::now();
    let mut echo: Option<(u32, crate::utils::clock::Instant)> = None;
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    let mut peer_open = true;
    let echo_interval = conn.shared.echo_interval;
    loop {
        tokio::select! {
            m = msgs.recv() => match m {
                Some(Ok(m)) => {
                    last_rx = crate::utils::clock::Instant::now();
                    count_in(conn, &m).await;
                    if m.header.msg_type == msg::ECHO_REPLY {
                        if echo.is_some_and(|(x, _)| x == m.header.xid) {
                            echo = None;
                        }
                        continue;
                    }
                    if !handle(conn, &m, &mut hs, jobs).await {
                        return Ok(());
                    }
                }
                Some(Err(e)) => {
                    log.info(format!("OpenFlow switch {} connection ended: {e}", conn.dpid()));
                    return Ok(());
                }
                None => return Ok(()),
            },
            c = peer_rx.recv(), if peer_open => match c {
                Some(c) => {
                    if command(conn, c).await {
                        return Ok(());
                    }
                }
                None => peer_open = false,
            },
            _ = close_rx.changed() => {
                log.info(format!("OpenFlow switch {} disconnected by decision", conn.dpid()));
                return Ok(());
            }
            _ = tick.tick() => {
                let now = crate::utils::clock::Instant::now();
                if let Some((_, at)) = echo {
                    if now.duration_since(at) >= echo_interval {
                        log.warn(format!(
                            "OpenFlow switch {} did not answer ECHO in {echo_interval:?}; \
                             disconnecting decision=protocol_timeout",
                            conn.dpid()
                        ));
                        return Ok(());
                    }
                } else if now.duration_since(last_rx) >= echo_interval {
                    let xid = conn.send(msg::ECHO_REQUEST, &[], None, 0, "echo request").await?;
                    echo = Some((xid, now));
                }
                if !hs.announced && now.duration_since(started) >= HANDSHAKE_TIMEOUT {
                    if hs.features.is_none() {
                        log.warn(format!(
                            "OpenFlow peer {remote} sent no FEATURES_REPLY in \
                             {HANDSHAKE_TIMEOUT:?} decision=protocol_timeout"
                        ));
                        return Ok(());
                    }
                    hs.desc_done = true;
                    hs.ports_done = true;
                    announce(conn, &mut hs, remote, jobs);
                }
                expire(conn, jobs);
            }
        }
        if !hs.announced && hs.features.is_some() && hs.desc_done && hs.ports_done {
            announce(conn, &mut hs, remote, jobs);
        }
    }
}

async fn count_in(conn: &Conn, m: &Message) {
    conn.shared
        .app_state
        .update_connection_stats(
            conn.shared.server_id,
            conn.connection_id,
            Some((wire::HEADER_LEN + m.body.len()) as u64),
            None,
            Some(1),
            None,
        )
        .await;
}

fn enqueue(conn: &Conn, jobs: &mpsc::Sender<Job>, job: Job) {
    let id = job.event.event_type.id.clone();
    if jobs.try_send(job).is_err() {
        conn.log().warn(format!(
            "OpenFlow {id} from switch {} not sent to the model: {MAX_QUEUED_EVENTS} events are \
             already waiting decision=fail_closed_queue_full",
            conn.dpid()
        ));
    }
}

fn announce(conn: &Conn, hs: &mut Handshake, remote: SocketAddr, jobs: &mpsc::Sender<Job>) {
    hs.announced = true;
    let Some(f) = hs.features else { return };
    let data = json!({
        "switch": remote.to_string(),
        "datapath_id": wire::datapath_id_str(f.datapath_id),
        "version": "1.3",
        "n_tables": f.n_tables,
        "n_buffers": f.n_buffers,
        "capabilities": wire::capability_names(f.capabilities),
        "ports": hs.ports,
        "description": hs.desc,
    });
    enqueue(
        conn,
        jobs,
        Job {
            event: Event::new(&actions::SWITCH_CONNECTED_EVENT, data),
            depth: 0,
            packet_in_id: None,
        },
    );
}

/// Take the outstanding request this reply answers, if it answers one of ours.
fn take(conn: &Conn, m: &Message, want: impl Fn(Expect) -> bool) -> Option<Outstanding> {
    let mut book = conn.book.lock().ok()?;
    match book.replies.get(&m.header.xid) {
        Some(o) if want(o.expect) => book.replies.remove(&m.header.xid),
        _ => {
            drop(book);
            conn.log().debug(format!(
                "OpenFlow {} with xid {:#x} answers nothing NetGet asked; ignored \
                 decision=protocol_unsolicited_reply",
                wire::msg_name(m.header.msg_type),
                m.header.xid
            ));
            None
        }
    }
}

/// Handle one message from the switch. Returns false when the connection should close.
async fn handle(
    conn: &Arc<Conn>,
    m: &Message,
    hs: &mut Handshake,
    jobs: &mpsc::Sender<Job>,
) -> bool {
    if m.header.version != VERSION_1_3 && m.header.msg_type != msg::HELLO {
        conn.refuse(
            m,
            err::BAD_REQUEST,
            err::BAD_REQUEST_BAD_VERSION,
            "not the negotiated version",
        )
        .await;
        return true;
    }
    match m.header.msg_type {
        msg::HELLO => {}
        msg::ECHO_REQUEST => {
            let _ = conn.reply(msg::ECHO_REPLY, m.header.xid, &m.body).await;
        }
        msg::FEATURES_REPLY => {
            if take(conn, m, |e| e == Expect::Features).is_some() {
                match wire::Features::parse(&m.body) {
                    Ok(f) => {
                        if let Ok(mut d) = conn.datapath_id.lock() {
                            *d = wire::datapath_id_str(f.datapath_id);
                        }
                        hs.features = Some(f);
                    }
                    Err(e) => {
                        conn.refuse(
                            m,
                            err::BAD_REQUEST,
                            err::BAD_REQUEST_BAD_LEN,
                            &e.to_string(),
                        )
                        .await;
                        return false;
                    }
                }
            }
        }
        msg::MULTIPART_REPLY => multipart(conn, m, hs, jobs).await,
        msg::BARRIER_REPLY
        | msg::GET_CONFIG_REPLY
        | msg::ROLE_REPLY
        | msg::GET_ASYNC_REPLY
        | msg::QUEUE_GET_CONFIG_REPLY => {
            let _ = take(conn, m, |_| false);
        }
        msg::PACKET_IN => match wire::PacketIn::parse(&m.body) {
            Ok(pi) => {
                let in_port = pi.in_port().unwrap_or(wire::port::CONTROLLER);
                let id = conn.store_packet(StoredPacket {
                    buffer_id: pi.buffer_id,
                    in_port,
                    data: pi.data.clone(),
                });
                let data = json!({
                    "packet_in_id": id,
                    "datapath_id": conn.dpid(),
                    "in_port": fields::port_to_json(in_port),
                    "reason": wire::packet_in_reason::name(pi.reason),
                    "table_id": pi.table_id,
                    "cookie": format!("{:#x}", pi.cookie),
                    "buffered": pi.buffer_id != wire::NO_BUFFER,
                    "total_len": pi.total_len,
                    "match": fields::match_to_json(&pi.matched),
                    "packet": packet::describe(&pi.data),
                });
                enqueue(
                    conn,
                    jobs,
                    Job {
                        event: Event::new(&actions::PACKET_IN_EVENT, data),
                        depth: 0,
                        packet_in_id: Some(id),
                    },
                );
            }
            Err(e) => {
                conn.refuse(
                    m,
                    err::BAD_REQUEST,
                    err::BAD_REQUEST_BAD_LEN,
                    &e.to_string(),
                )
                .await
            }
        },
        msg::FLOW_REMOVED => match wire::FlowRemoved::parse(&m.body) {
            Ok(fr) => {
                let data = json!({
                    "datapath_id": conn.dpid(),
                    "reason": wire::removed_reason::name(fr.reason),
                    "table_id": fr.table_id,
                    "priority": fr.priority,
                    "cookie": format!("{:#x}", fr.cookie),
                    "match": fields::match_to_json(&fr.matched),
                    "packet_count": fr.packet_count,
                    "byte_count": fr.byte_count,
                    "duration_sec": fr.duration_sec,
                    "idle_timeout": fr.idle_timeout,
                    "hard_timeout": fr.hard_timeout,
                });
                enqueue(
                    conn,
                    jobs,
                    Job {
                        event: Event::new(&actions::FLOW_REMOVED_EVENT, data),
                        depth: 0,
                        packet_in_id: None,
                    },
                );
            }
            Err(e) => {
                conn.refuse(
                    m,
                    err::BAD_REQUEST,
                    err::BAD_REQUEST_BAD_LEN,
                    &e.to_string(),
                )
                .await
            }
        },
        msg::PORT_STATUS => match wire::parse_port_status(&m.body) {
            Ok((reason, port)) => {
                let data = json!({
                    "datapath_id": conn.dpid(),
                    "reason": match reason { 0 => "add", 1 => "delete", 2 => "modify", _ => "unknown" },
                    "port": actions::port_json(&port),
                });
                enqueue(
                    conn,
                    jobs,
                    Job {
                        event: Event::new(&actions::PORT_STATUS_EVENT, data),
                        depth: 0,
                        packet_in_id: None,
                    },
                );
            }
            Err(e) => {
                conn.refuse(
                    m,
                    err::BAD_REQUEST,
                    err::BAD_REQUEST_BAD_LEN,
                    &e.to_string(),
                )
                .await
            }
        },
        msg::ERROR => return error(conn, m, hs, jobs),
        msg::EXPERIMENTER => {
            conn.refuse(
                m,
                err::BAD_REQUEST,
                err::BAD_REQUEST_BAD_EXPERIMENTER,
                "no experimenter extensions are supported",
            )
            .await
        }
        _ => {
            conn.refuse(
                m,
                err::BAD_REQUEST,
                err::BAD_REQUEST_BAD_TYPE,
                "a switch does not send this to a controller",
            )
            .await
        }
    }
    true
}

/// Attribute a switch's ERROR to what it refused, and tell the model.
fn error(conn: &Conn, m: &Message, hs: &mut Handshake, jobs: &mpsc::Sender<Job>) -> bool {
    let Ok(e) = wire::ErrorMsg::parse(&m.body) else {
        conn.log()
            .warn("OpenFlow ERROR too short to read decision=protocol_error".to_string());
        return true;
    };
    let type_name = wire::error_type_name(e.etype);
    let code_name = wire::error_code_name(e.etype, e.code);
    if e.etype == err::HELLO_FAILED {
        conn.log().warn(format!(
            "OpenFlow switch {} refused the HELLO ({code_name}); closing",
            conn.dpid()
        ));
        return false;
    }
    let xid = e.offending().map(|(_, x)| x).unwrap_or(m.header.xid);
    let (request, depth) = {
        let Ok(mut book) = conn.book.lock() else {
            return true;
        };
        let tracked = book.replies.remove(&xid);
        if let Some(o) = &tracked {
            if let Expect::Handshake(t) = o.expect {
                if t == wire::mp::DESC {
                    hs.desc_done = true;
                } else {
                    hs.ports_done = true;
                }
            }
        }
        match book.recent.iter().find(|s| s.xid == xid) {
            Some(s) => (
                json!({"type": wire::msg_name(s.msg_type), "xid": xid, "what": s.what}),
                s.depth,
            ),
            None => (
                json!({"type": e.offending().map(|(t, _)| wire::msg_name(t)), "xid": xid}),
                tracked.map(|o| o.depth).unwrap_or(0),
            ),
        }
    };
    conn.log().warn(format!(
        "OpenFlow switch {} refused {} with {type_name}/{code_name}",
        conn.dpid(),
        request["what"].as_str().unwrap_or("a message")
    ));
    if !hs.announced {
        return true;
    }
    let data = json!({
        "datapath_id": conn.dpid(),
        "error_type": type_name,
        "error_code": code_name,
        "request": request,
    });
    enqueue(
        conn,
        jobs,
        Job {
            event: Event::new(&actions::ERROR_EVENT, data),
            depth: depth + 1,
            packet_in_id: None,
        },
    );
    true
}

async fn multipart(conn: &Conn, m: &Message, hs: &mut Handshake, jobs: &mpsc::Sender<Job>) {
    let Ok((mtype, flags, body)) = wire::parse_multipart(&m.body) else {
        conn.refuse(
            m,
            err::BAD_REQUEST,
            err::BAD_REQUEST_BAD_LEN,
            "a short multipart reply",
        )
        .await;
        return;
    };
    // Accumulate under the lock; decide what to do with it outside.
    let finished: Option<(Expect, u32, Vec<u8>)>;
    let mut overflow: Option<(Expect, u32)> = None;
    {
        let Ok(mut book) = conn.book.lock() else {
            return;
        };
        let matches = book.replies.get(&m.header.xid).is_some_and(
            |o| matches!(o.expect, Expect::Handshake(t) | Expect::Stats(t) if t == mtype),
        );
        if !matches {
            drop(book);
            conn.log().debug(format!(
                "OpenFlow {} multipart reply with xid {:#x} answers nothing NetGet asked; \
                 ignored decision=protocol_unsolicited_reply",
                wire::mp::name(mtype),
                m.header.xid
            ));
            return;
        }
        let Some(o) = book.replies.get_mut(&m.header.xid) else {
            return;
        };
        o.n_parts += 1;
        if o.parts.len() + body.len() > MAX_MULTIPART_BYTES || o.n_parts > MAX_MULTIPART_PARTS {
            overflow = Some((o.expect, o.depth));
            book.replies.remove(&m.header.xid);
            finished = None;
        } else {
            o.parts.extend_from_slice(body);
            if flags & wire::mp::MORE != 0 {
                finished = None;
            } else {
                finished = book
                    .replies
                    .remove(&m.header.xid)
                    .map(|o| (o.expect, o.depth, o.parts));
            }
        }
    }
    if let Some((expect, depth)) = overflow {
        conn.log().warn(format!(
            "OpenFlow {} reply from switch {} exceeded {MAX_MULTIPART_BYTES} bytes or \
             {MAX_MULTIPART_PARTS} parts; discarded decision=fail_closed_multipart_too_large",
            wire::mp::name(mtype),
            conn.dpid()
        ));
        match expect {
            Expect::Handshake(wire::mp::DESC) => hs.desc_done = true,
            Expect::Handshake(_) => hs.ports_done = true,
            _ => stats_event(
                conn,
                jobs,
                mtype,
                json!({"error": format!("the reply exceeded {MAX_MULTIPART_BYTES} bytes and was discarded")}),
                depth,
            ),
        }
        return;
    }
    let Some((expect, depth, bytes)) = finished else {
        return;
    };
    let decoded = decode_stats(mtype, &bytes);
    match expect {
        Expect::Handshake(wire::mp::DESC) => {
            hs.desc_done = true;
            hs.desc = decoded.ok().and_then(|v| v.get("summary").cloned());
        }
        Expect::Handshake(_) => {
            hs.ports_done = true;
            if let Ok(v) = decoded {
                hs.ports = v["entries"].as_array().cloned().unwrap_or_default();
            }
        }
        _ => {
            let v = decoded.unwrap_or_else(|e| json!({"error": format!("undecodable reply: {e}")}));
            stats_event(conn, jobs, mtype, v, depth);
        }
    }
}

fn stats_event(conn: &Conn, jobs: &mpsc::Sender<Job>, mtype: u16, body: Value, depth: u32) {
    let mut data = json!({"datapath_id": conn.dpid(), "kind": wire::mp::name(mtype)});
    if let (Some(d), Value::Object(b)) = (data.as_object_mut(), body) {
        d.extend(b);
    }
    enqueue(
        conn,
        jobs,
        Job {
            event: Event::new(&actions::STATS_REPLY_EVENT, data),
            depth: depth + 1,
            packet_in_id: None,
        },
    );
}

fn bounded(entries: Vec<Value>) -> Value {
    let truncated = entries.len() > MAX_REPORTED_ENTRIES;
    let shown: Vec<Value> = entries.into_iter().take(MAX_REPORTED_ENTRIES).collect();
    let mut v = json!({"entries": shown});
    if truncated {
        v["truncated"] = json!(true);
    }
    v
}

/// A reassembled multipart reply as the model reads it.
pub fn decode_stats(mtype: u16, body: &[u8]) -> Result<Value> {
    use wire::mp;
    Ok(match mtype {
        mp::DESC => {
            let mut summary = serde_json::Map::new();
            for (k, v) in wire::parse_desc(body)? {
                summary.insert(k.to_string(), json!(v));
            }
            json!({"summary": summary})
        }
        mp::PORT_DESC => bounded(
            wire::parse_ports(body)?
                .iter()
                .map(actions::port_json)
                .collect(),
        ),
        mp::FLOW => bounded(
            wire::FlowStats::parse_all(body)?
                .iter()
                .map(|f| {
                    json!({
                        "table_id": f.table_id,
                        "priority": f.priority,
                        "match": fields::match_to_json(&f.matched),
                        "instructions": fields::instructions_to_json(&f.instructions),
                        "cookie": format!("{:#x}", f.cookie),
                        "idle_timeout": f.idle_timeout,
                        "hard_timeout": f.hard_timeout,
                        "flags": wire::flow_flag_names(f.flags),
                        "packet_count": f.packet_count,
                        "byte_count": f.byte_count,
                        "duration_sec": f.duration_sec,
                    })
                })
                .collect(),
        ),
        mp::AGGREGATE => {
            let (packets, bytes, flows) = wire::parse_aggregate(body)?;
            json!({"summary": {"packet_count": packets, "byte_count": bytes, "flow_count": flows}})
        }
        mp::TABLE => {
            let all = wire::TableStats::parse_all(body)?;
            let total = all.len();
            let mut v = bounded(
                all.iter()
                    .filter(|t| t.active_count > 0 || t.lookup_count > 0)
                    .map(|t| {
                        json!({
                            "table_id": t.table_id,
                            "active_count": t.active_count,
                            "lookup_count": t.lookup_count,
                            "matched_count": t.matched_count,
                        })
                    })
                    .collect(),
            );
            v["tables_total"] = json!(total);
            v
        }
        mp::PORT_STATS => bounded(
            wire::PortStats::parse_all(body)?
                .iter()
                .map(|p| {
                    let mut o = serde_json::Map::new();
                    o.insert("port_no".into(), fields::port_to_json(p.port_no));
                    for (name, value) in wire::PORT_STATS_COUNTERS.iter().zip(p.counters) {
                        o.insert((*name).into(), json!(value));
                    }
                    o.insert("duration_sec".into(), json!(p.duration_sec));
                    Value::Object(o)
                })
                .collect(),
        ),
        other => bail!("no decoder for {} replies", wire::mp::name(other)),
    })
}

/// Requests that have waited too long for an answer.
fn expire(conn: &Conn, jobs: &mpsc::Sender<Job>) {
    let now = crate::utils::clock::Instant::now();
    let stale: Vec<(u32, Outstanding)> = {
        let Ok(mut book) = conn.book.lock() else {
            return;
        };
        let ids: Vec<u32> = book
            .replies
            .iter()
            .filter(|(_, o)| {
                matches!(o.expect, Expect::Stats(_)) && now.duration_since(o.sent) >= REPLY_TIMEOUT
            })
            .map(|(x, _)| *x)
            .collect();
        ids.into_iter()
            .filter_map(|x| book.replies.remove(&x).map(|o| (x, o)))
            .collect()
    };
    for (xid, o) in stale {
        if let Expect::Stats(t) = o.expect {
            conn.log().warn(format!(
                "OpenFlow {} request {xid:#x} to switch {} got no reply in {REPLY_TIMEOUT:?} \
                 decision=protocol_timeout",
                wire::mp::name(t),
                conn.dpid()
            ));
            stats_event(
                conn,
                jobs,
                t,
                json!({"error": "the switch did not answer"}),
                o.depth,
            );
        }
    }
}

/// One action the model (or an operator) asked for.
struct Item {
    name: String,
    data: Value,
}

/// What carrying out a decision did.
#[derive(Default)]
struct Outcome {
    sent: Vec<String>,
    dropped: bool,
    closed: bool,
    errors: Vec<String>,
}

/// Carry out one action against the connection. `answering` is the PACKET_IN the action
/// answers, if any.
async fn apply(conn: &Conn, item: &Item, answering: Option<&str>, depth: u32, out: &mut Outcome) {
    let result: Result<Option<String>> = async {
        match item.name.as_str() {
            actions::RESULT_FLOW_MOD => {
                let mut fm = actions::flow_mod_from_json(&item.data)?;
                if let Some(id) = item.data.get("packet_in_id").and_then(Value::as_str) {
                    let p = conn
                        .packet(id)
                        .with_context(|| format!("no stored packet {id:?}"))?;
                    fm.buffer_id = p.buffer_id;
                }
                let what = format!(
                    "flow_mod {} priority {} table {}",
                    wire::flow_cmd::NAMES[fm.command as usize],
                    fm.priority,
                    fm.table_id
                );
                conn.send(msg::FLOW_MOD, &fm.encode(), None, depth, &what)
                    .await?;
                Ok(Some(what))
            }
            actions::RESULT_PACKET_OUT => {
                let spec = actions::packet_out_from_json(&item.data)?;
                let (buffer_id, mut in_port, data, what) = match spec.source {
                    actions::PacketSource::Built(frame) => (
                        wire::NO_BUFFER,
                        wire::port::CONTROLLER,
                        frame,
                        "packet_out of a new packet".to_string(),
                    ),
                    actions::PacketSource::Received(id) => {
                        let id = id.or_else(|| answering.map(str::to_string)).context(
                            "no packet to send: name a packet_in_id or describe a packet",
                        )?;
                        let p = conn.packet(&id).with_context(|| {
                            format!(
                                "no stored packet {id:?} (the last {MAX_STORED_PACKETS} are kept)"
                            )
                        })?;
                        let data = if p.buffer_id == wire::NO_BUFFER {
                            p.data
                        } else {
                            Vec::new()
                        };
                        (p.buffer_id, p.in_port, data, format!("packet_out of {id}"))
                    }
                };
                if let Some(p) = spec.in_port {
                    in_port = p;
                }
                let po = wire::PacketOut {
                    buffer_id,
                    in_port,
                    actions: spec.actions,
                    data,
                };
                conn.send(msg::PACKET_OUT, &po.encode(), None, depth, &what)
                    .await?;
                Ok(Some(what))
            }
            actions::RESULT_STATS => {
                let (mtype, body) = actions::stats_request_from_json(&item.data)?;
                let what = format!("{} statistics request", wire::mp::name(mtype));
                conn.send(
                    msg::MULTIPART_REQUEST,
                    &wire::multipart_body(mtype, 0, &body),
                    Some(Expect::Stats(mtype)),
                    depth,
                    &what,
                )
                .await?;
                Ok(Some(what))
            }
            actions::RESULT_DROP => {
                out.dropped = true;
                Ok(None)
            }
            other => bail!("not an OpenFlow controller result: {other}"),
        }
    }
    .await;
    match result {
        Ok(Some(what)) => out.sent.push(what),
        Ok(None) => {}
        Err(e) => out.errors.push(format!("{}: {e:#}", item.name)),
    }
}

fn flatten(results: Vec<ActionResult>, out: &mut Vec<ActionResult>) {
    for r in results {
        match r {
            ActionResult::Multiple(inner) => flatten(inner, out),
            other => out.push(other),
        }
    }
}

/// The model worker: one event at a time, in order.
async fn worker(conn: Arc<Conn>, mut jobs: mpsc::Receiver<Job>) {
    while let Some(job) = jobs.recv().await {
        let id = job.event.event_type.id.clone();
        let label = match &job.packet_in_id {
            Some(p) => format!("{id} {p}"),
            None => id.clone(),
        };
        let log = conn.log();
        if job.depth >= MAX_FOLLOWUP_DEPTH {
            log.warn(format!(
                "OpenFlow {label} from switch {} not sent to the model: {} turns deep \
                 decision=followup_depth",
                conn.dpid(),
                job.depth
            ));
            continue;
        }
        let execution = match call_llm(
            &conn.shared.llm_client,
            &conn.shared.app_state,
            conn.shared.server_id,
            Some(conn.connection_id),
            &job.event,
            &OpenFlowProtocol::new(),
        )
        .await
        {
            Ok(x) => x,
            Err(e) => {
                let tag = match crate::utils::wire_failure::WireFailure::classify(&e) {
                    crate::utils::wire_failure::WireFailure::Overloaded => {
                        "fail_closed_llm_overloaded"
                    }
                    crate::utils::wire_failure::WireFailure::Unavailable => "fail_closed_llm_error",
                };
                log.error(format!(
                    "OpenFlow {label} on {} not answered; nothing sent decision={tag}: {e}",
                    conn.connection_id
                ));
                continue;
            }
        };
        for m in execution.messages {
            let _ = conn.shared.status_tx.send(m);
        }
        let mut results = Vec::new();
        flatten(execution.protocol_results, &mut results);
        let mut items = Vec::new();
        let mut close = false;
        for r in results {
            match r {
                ActionResult::Custom { name, data } => items.push(Item { name, data }),
                ActionResult::CloseConnection => close = true,
                _ => {}
            }
        }
        let mut outcome = Outcome::default();
        for item in &items {
            apply(
                &conn,
                item,
                job.packet_in_id.as_deref(),
                job.depth,
                &mut outcome,
            )
            .await;
        }
        let refused = execution
            .failures
            .iter()
            .map(|f| format!("{}: {}", f.action, f.error))
            .chain(outcome.errors.iter().cloned())
            .collect::<Vec<_>>()
            .join("; ");
        if close {
            outcome.closed = true;
        }
        if !outcome.sent.is_empty() {
            log.info(format!(
                "OpenFlow {label} on {} decision=model_answer: sent {}{}",
                conn.connection_id,
                outcome.sent.join(", "),
                if refused.is_empty() {
                    String::new()
                } else {
                    format!(" (refused: {refused})")
                }
            ));
        } else if outcome.dropped || outcome.closed {
            log.info(format!(
                "OpenFlow {label} on {} decision=model_reject{}",
                conn.connection_id,
                if outcome.closed {
                    ": disconnecting the switch"
                } else {
                    ": dropped"
                }
            ));
        } else if !refused.is_empty() {
            log.error(format!(
                "OpenFlow {label} on {} produced no usable action; nothing sent \
                 decision=fail_closed_bad_action ({refused})",
                conn.connection_id
            ));
        } else {
            log.warn(format!(
                "OpenFlow {label} on {} produced no action; nothing sent decision=model_silent",
                conn.connection_id
            ));
        }
        if outcome.closed {
            let _ = conn.close.send(true);
            return;
        }
    }
}

/// An action an operator injected into this connection (`send_to_peer`). Returns true when the
/// connection should close.
async fn command(conn: &Conn, c: ClientCommand) -> bool {
    let action = c.action.clone();
    let outcome: Result<ClientSendOutcome> =
        match OpenFlowProtocol::new().execute_action(action.clone()) {
            Ok(ActionResult::CloseConnection) => Ok(ClientSendOutcome::Disconnected),
            Ok(ActionResult::Custom { name, data }) => {
                let mut out = Outcome::default();
                apply(conn, &Item { name, data }, None, 0, &mut out).await;
                if let Some(e) = out.errors.first() {
                    Ok(ClientSendOutcome::Rejected { error: e.clone() })
                } else {
                    Ok(ClientSendOutcome::Executed {
                        detail: json!({"sent": out.sent, "dropped": out.dropped}).to_string(),
                    })
                }
            }
            Ok(_) => Ok(ClientSendOutcome::Executed {
                detail: "nothing to send".into(),
            }),
            Err(e) => Ok(ClientSendOutcome::Rejected {
                error: e.to_string(),
            }),
        };
    let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
    let outcome_json = match &outcome {
        Ok(o) => serde_json::to_value(o).unwrap_or(Value::Null),
        Err(e) => json!({"error": e.to_string()}),
    };
    conn.shared
        .app_state
        .record_access_log(
            AccessLogOwner::Server(conn.shared.server_id.as_u32()),
            "OpenFlow",
            Some(conn.connection_id.as_u32()),
            "injected_action",
            action,
            vec![outcome_json],
        )
        .await;
    let _ = c.reply_tx.send(outcome);
    disconnect
}

/// The event types this server raises, for registries and tests.
pub fn raised_events() -> Vec<&'static EventType> {
    vec![
        &actions::SWITCH_CONNECTED_EVENT,
        &actions::PACKET_IN_EVENT,
        &actions::FLOW_REMOVED_EVENT,
        &actions::PORT_STATUS_EVENT,
        &actions::STATS_REPLY_EVENT,
        &actions::ERROR_EVENT,
    ]
}

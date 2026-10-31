//! Neo4j's Bolt protocol — the model is the graph database.
//!
//! A client opens with the 4-byte magic `60 60 B0 17` and four version proposals; the server
//! answers with the version it picked (Bolt 5.0–5.8, see [`messages::negotiate`]). From then on
//! both sides exchange chunked PackStream messages. The model is asked exactly two things — may
//! this login in ([`actions::BOLT_AUTHENTICATE_EVENT`]), and what does this Cypher query return
//! ([`actions::BOLT_QUERY_EVENT`]) — and everything else is NetGet's:
//!
//! * **The state machine.** CONNECTED → (HELLO) → AUTHENTICATION → (LOGON) → READY; RUN →
//!   STREAMING; PULL/DISCARD drain it back to READY; BEGIN → TX_READY, RUN → TX_STREAMING,
//!   COMMIT/ROLLBACK → READY; a FAILURE → FAILED, where every message but RESET and GOODBYE is
//!   answered IGNORED; RESET → READY from anywhere. A message that arrives ahead of a RESET the
//!   client already sent is IGNORED (the INTERRUPTED state), and a message the current state does
//!   not allow is a `Neo.ClientError.Request.Invalid` FAILURE and a close. Bolt 5.0 carries the
//!   credentials in HELLO and goes straight to READY.
//! * **Result streaming.** The model answers RUN with every row at once; NetGet sends the column
//!   list in RUN's SUCCESS, then as many RECORDs as each PULL's `n` asks for with `has_more`, and
//!   the summary (`type`, `db`, `stats`, a bookmark for writes) at the end. Inside a transaction
//!   several results may be open at once and PULL/DISCARD address them by `qid`.
//! * **What costs no model call.** HELLO, ROUTE (a single-server routing table naming the address
//!   the client dialled), BEGIN/COMMIT/ROLLBACK, RESET, LOGOFF, TELEMETRY, and the admin queries
//!   `cypher-shell` runs on every connect (`CALL db.ping()`, `CALL
//!   dbms.licenseAgreementDetails()`, `CALL dbms.components()`), so connecting costs nothing.
//! * **The password.** With a `password` startup parameter NetGet compares the credential itself,
//!   in constant time, and a mismatch never reaches the model. The credential never appears in an
//!   event either way.
//!
//! Three bounds, each refused before anything is allocated for it: the handshake must arrive
//! within `first_byte_timeout_secs`, a message is capped at [`packstream::MAX_MESSAGE_BYTES`]
//! summed over its chunks, and PackStream nesting at [`packstream::MAX_PACKSTREAM_DEPTH`]. The
//! read deadlines wrap the read, never the answer, so a query parked for a human under a
//! `manual` rule is not closed by `idle_timeout_secs`.
//!
//! On a backend failure, an unusable answer or no answer, the client gets FAILURE
//! `Neo.TransientError.General.DatabaseUnavailable` with a fixed message (never the error text)
//! and the connection stays usable after RESET — Bolt's own recovery path. A refused login closes
//! the connection, as Neo4j does.
pub mod actions;
pub mod messages;
pub mod packstream;
pub mod values;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use anyhow::Result;
use messages::Request;
use packstream::{Dechunker, Value};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};

pub use packstream::{MAX_MESSAGE_BYTES, MAX_PACKSTREAM_DEPTH};

/// Neo4j version the server claims unless `neo4j_version` says otherwise.
pub const DEFAULT_NEO4J_VERSION: &str = "5.26.0";

/// How long a new connection may take to send its 20-byte handshake. Bolt is client-first and
/// every driver sends it with the connect, so 30 seconds only ever matters for a peer that is not
/// speaking Bolt at all.
pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the server waits for the next message after the handshake. Drivers pool connections
/// and leave them idle between queries; five minutes keeps a pooled connection useful without
/// letting abandoned ones accumulate.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Concurrent connections admitted before new ones are refused — the house default. Each holds a
/// task, a message buffer of up to [`MAX_MESSAGE_BYTES`] and the rows of its open results.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// Bolt has nothing to say before the handshake, so a peer over the cap is simply closed, as a
/// Neo4j server at its own `server.bolt.thread_pool_max_size` does.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

const REQUEST_INVALID: &str = "Neo.ClientError.Request.Invalid";
const DATABASE_UNAVAILABLE: &str = "Neo.TransientError.General.DatabaseUnavailable";
/// Fixed FAILURE messages for the two `WireFailure` categories. Nothing derived from the error
/// reaches the client.
const UNAVAILABLE_MESSAGE: &str = "The database is unavailable: the query could not be answered.";
const OVERLOADED_MESSAGE: &str = "The database is at capacity; retry the query later.";
const UNAUTHORIZED_MESSAGE: &str = "The client is unauthorized due to authentication failure.";

/// Startup configuration shared by every connection.
#[derive(Debug, Clone)]
pub struct BoltConfig {
    pub password: Option<String>,
    pub neo4j_version: String,
    pub first_byte_timeout: Duration,
    pub idle_timeout: Duration,
}

pub struct BoltServer;

impl BoltServer {
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        config: BoltConfig,
    ) -> Result<SocketAddr> {
        let listener = TcpListener::bind(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        Log::new(Some(&status_tx)).info(format!(
            "Bolt server listening on {} (Neo4j/{})",
            local_addr, config.neo4j_version
        ));

        let config = Arc::new(config);
        let protocol = Arc::new(actions::BoltProtocol::new());
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Bolt",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((socket, peer_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();
                        app_state
                            .add_connection_to_server(
                                server_id,
                                ServerConnectionState {
                                    id: connection_id,
                                    remote_addr: peer_addr,
                                    local_addr,
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
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        Log::new(Some(&status_tx))
                            .info(format!("Bolt client connected from {}", peer_addr));

                        let session = Session {
                            peer_addr,
                            local_addr,
                            llm_client: llm_client.clone(),
                            app_state: app_state.clone(),
                            status_tx: status_tx.clone(),
                            server_id,
                            protocol: protocol.clone(),
                            connection_id,
                            config: config.clone(),
                        };
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Released when the connection ends, so MAX_CONNECTIONS caps
                                // live connections.
                                let _permit = permit;
                                session.run(socket).await
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx)).error(format!("Bolt accept error: {}", e));
                        break;
                    }
                }
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;
        Ok(local_addr)
    }
}

/// Where the connection is in Bolt's server state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Handshake done, waiting for HELLO.
    Connected,
    /// HELLO answered, waiting for LOGON (Bolt 5.1+).
    Authentication,
    Ready,
    /// An auto-commit result is open.
    Streaming,
    TxReady,
    /// At least one result inside the transaction is open.
    TxStreaming,
    Failed,
}

impl Phase {
    fn wire_name(self) -> &'static str {
        match self {
            Phase::Connected => "CONNECTED",
            Phase::Authentication => "AUTHENTICATION",
            Phase::Ready => "READY",
            Phase::Streaming => "STREAMING",
            Phase::TxReady => "TX_READY",
            Phase::TxStreaming => "TX_STREAMING",
            Phase::Failed => "FAILED",
        }
    }
}

/// One RUN's answer, held until PULL or DISCARD has consumed it.
struct OpenResult {
    qid: i64,
    records: VecDeque<Vec<Value>>,
    query_type: &'static str,
    stats: Option<Value>,
    db: String,
}

struct Transaction {
    db: Option<String>,
    read: bool,
}

/// Per-connection protocol state.
struct Conn {
    minor: u8,
    phase: Phase,
    authenticated: bool,
    user_agent: String,
    /// The `address` from HELLO's routing context: what the client dialled, and so what a
    /// routing table must name for the client to come back here.
    routing_address: Option<String>,
    tx: Option<Transaction>,
    results: Vec<OpenResult>,
    next_qid: i64,
}

impl Conn {
    fn new(minor: u8) -> Self {
        Self {
            minor,
            phase: Phase::Connected,
            authenticated: false,
            user_agent: String::new(),
            routing_address: None,
            tx: None,
            results: Vec::new(),
            next_qid: 0,
        }
    }
}

/// What handling one message decided about the connection.
enum Flow {
    Continue,
    Close,
}

/// Outcome of asking whoever answers queries.
enum QueryOutcome {
    Answer(values::QueryAnswer),
    /// A FAILURE has been queued and the connection is in FAILED.
    Failed,
    Close,
}

/// Outcome of asking whoever answers logins.
enum Login {
    Accepted,
    /// A FAILURE has been queued; close.
    Refused,
    Closed,
}

struct Session {
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: crate::state::ServerId,
    protocol: Arc<actions::BoltProtocol>,
    connection_id: ConnectionId,
    config: Arc<BoltConfig>,
}

/// Bytes queued for one write, so a PULL's records and summary leave in one `write_all`.
#[derive(Default)]
struct Out {
    bytes: Vec<u8>,
    messages: u64,
}

impl Out {
    fn push(&mut self, message: &Value) {
        self.bytes.extend(packstream::message_bytes(message));
        self.messages += 1;
    }
}

fn is_reset(raw: &[u8]) -> bool {
    raw.len() >= 2 && raw[0] == 0xB0 && raw[1] == messages::RESET
}

impl Session {
    async fn run(self, socket: tokio::net::TcpStream) {
        let (mut reader, write_half) = tokio::io::split(socket);
        let write_half = Arc::new(Mutex::new(write_half));

        // The dashboard's [ disconnect ] goes through this handle. Bolt defines no message a
        // server may send unprompted, so an injected answer action is validated and reported but
        // writes nothing; `close_connection` half-closes the socket.
        let peer_rx = crate::server::peer_support::register_peer_channel(
            &self.app_state,
            self.server_id,
            self.connection_id.as_u32(),
        )
        .await;
        crate::server::peer_support::spawn_peer_command_task(
            peer_rx,
            self.protocol.clone(),
            self.app_state.clone(),
            self.server_id,
            self.connection_id.as_u32(),
            write_half.clone(),
            self.status_tx.clone(),
        );

        self.session(&mut reader, &write_half).await;

        self.app_state
            .remove_peer_handle(self.server_id, self.connection_id.as_u32())
            .await;
        let _ = write_half.lock().await.shutdown().await;
        linger(&mut reader).await;
        self.app_state
            .update_connection_status(
                self.server_id,
                self.connection_id,
                crate::state::server::ConnectionStatus::Closed,
            )
            .await;
        let _ = self.status_tx.send("__UPDATE_UI__".to_string());
    }

    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.status_tx))
    }

    async fn write<W>(&self, write_half: &Arc<Mutex<W>>, data: &[u8], messages: u64) -> bool
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        if data.is_empty() {
            return true;
        }
        let ok = {
            let mut writer = write_half.lock().await;
            writer.write_all(data).await.is_ok() && writer.flush().await.is_ok()
        };
        self.app_state
            .update_connection_stats(
                self.server_id,
                self.connection_id,
                None,
                Some(data.len() as u64),
                None,
                Some(messages.max(1)),
            )
            .await;
        ok
    }

    async fn received(&self, bytes: usize) {
        self.app_state
            .update_connection_stats(
                self.server_id,
                self.connection_id,
                Some(bytes as u64),
                None,
                Some(1),
                None,
            )
            .await;
    }

    async fn session<R, W>(&self, reader: &mut R, write_half: &Arc<Mutex<W>>)
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let Some(minor) = self.handshake(reader, write_half).await else {
            return;
        };
        let mut conn = Conn::new(minor);
        let mut dechunker = Dechunker::new(MAX_MESSAGE_BYTES);
        let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
        let mut buf = vec![0u8; 16 * 1024];

        loop {
            loop {
                match dechunker.next_message() {
                    Ok(Some(message)) => queue.push_back(message),
                    Ok(None) => break,
                    Err(packstream::FrameError::TooLarge { limit }) => {
                        self.log().warn(format!(
                            "Bolt message from {} exceeds {} bytes \
                             decision=fail_closed_message_too_large",
                            self.peer_addr, limit
                        ));
                        let mut out = Out::default();
                        out.push(&messages::failure(
                            conn.minor,
                            REQUEST_INVALID,
                            &format!("Message exceeds the {limit}-byte limit of this server."),
                        ));
                        self.write(write_half, &out.bytes, out.messages).await;
                        return;
                    }
                }
            }

            let Some(raw) = queue.pop_front() else {
                let read =
                    tokio::time::timeout(self.config.idle_timeout, reader.read(&mut buf)).await;
                match read {
                    Err(_) => {
                        self.log().info(format!(
                            "Bolt client {} sent nothing for {}s; closing",
                            self.peer_addr,
                            self.config.idle_timeout.as_secs()
                        ));
                        return;
                    }
                    Ok(Ok(0)) => {
                        self.log()
                            .info(format!("Bolt client {} disconnected", self.peer_addr));
                        return;
                    }
                    Ok(Ok(n)) => {
                        self.received(n).await;
                        dechunker.push(&buf[..n]);
                    }
                    Ok(Err(e)) => {
                        self.log()
                            .error(format!("Bolt read error from {}: {}", self.peer_addr, e));
                        return;
                    }
                }
                continue;
            };

            let interrupted = queue.iter().any(|m| is_reset(m));
            let mut out = Out::default();
            let flow = self.handle(&raw, interrupted, &mut conn, &mut out).await;
            if !self.write(write_half, &out.bytes, out.messages).await {
                return;
            }
            if matches!(flow, Flow::Close) {
                return;
            }
        }
    }

    /// Read the 20-byte handshake and answer it. `None` means the connection is over.
    async fn handshake<R, W>(&self, reader: &mut R, write_half: &Arc<Mutex<W>>) -> Option<u8>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut hs = [0u8; 20];
        match tokio::time::timeout(self.config.first_byte_timeout, reader.read_exact(&mut hs)).await
        {
            Err(_) => {
                self.log().info(format!(
                    "Bolt client {} sent no handshake within {}s; closing",
                    self.peer_addr,
                    self.config.first_byte_timeout.as_secs()
                ));
                return None;
            }
            Ok(Err(_)) => {
                self.log().info(format!(
                    "Bolt client {} closed before completing the handshake",
                    self.peer_addr
                ));
                return None;
            }
            Ok(Ok(_)) => {}
        }
        self.received(hs.len()).await;
        if hs[..4] != messages::MAGIC {
            self.log().warn(format!(
                "Bolt client {} did not open with the Bolt magic (got {:02X?}) \
                 decision=fail_closed_bad_magic",
                self.peer_addr,
                &hs[..4]
            ));
            return None;
        }
        let mut proposals = [0u8; 16];
        proposals.copy_from_slice(&hs[4..]);
        match messages::negotiate(&proposals) {
            Some((major, minor)) => {
                self.log().debug(format!(
                    "Bolt client {} proposed {:02X?}; speaking {}.{}",
                    self.peer_addr, proposals, major, minor
                ));
                if !self.write(write_half, &[0, 0, minor, major], 1).await {
                    return None;
                }
                Some(minor)
            }
            None => {
                self.log().warn(format!(
                    "Bolt client {} proposed no version in 5.{}..=5.{} ({:02X?}) \
                     decision=fail_closed_no_common_version",
                    self.peer_addr,
                    messages::MIN_MINOR,
                    messages::MAX_MINOR,
                    proposals
                ));
                self.write(write_half, &[0, 0, 0, 0], 1).await;
                None
            }
        }
    }

    /// A message the protocol does not allow here: FAILURE `Request.Invalid`, then close.
    fn protocol_violation(&self, conn: &Conn, out: &mut Out, what: String) -> Flow {
        self.log().warn(format!(
            "Bolt client {}: {} decision=fail_closed_protocol_violation",
            self.peer_addr, what
        ));
        out.push(&messages::failure(conn.minor, REQUEST_INVALID, &what));
        Flow::Close
    }

    async fn handle(&self, raw: &[u8], interrupted: bool, conn: &mut Conn, out: &mut Out) -> Flow {
        let value = match packstream::decode(raw) {
            Ok(v) => v,
            Err(e) => {
                let decision = if e == packstream::DecodeError::TooDeep {
                    "fail_closed_too_deep"
                } else {
                    "fail_closed_malformed_message"
                };
                self.log().warn(format!(
                    "Bolt message from {} is not PackStream: {} decision={}",
                    self.peer_addr, e, decision
                ));
                out.push(&messages::failure(
                    conn.minor,
                    REQUEST_INVALID,
                    &format!("Invalid message: {e}"),
                ));
                return Flow::Close;
            }
        };
        let request = match messages::parse_request(value) {
            Ok(r) => r,
            Err(e) => return self.protocol_violation(conn, out, format!("Invalid message: {e}")),
        };
        self.log().trace(format!(
            "Bolt {} from {} in {}",
            request.name(),
            self.peer_addr,
            conn.phase.wire_name()
        ));

        match (&request, conn.phase) {
            (Request::Goodbye, _) => {
                self.log()
                    .debug(format!("Bolt client {} said GOODBYE", self.peer_addr));
                return Flow::Close;
            }
            (Request::Reset, Phase::Connected) => {}
            (Request::Reset, _) => {
                conn.tx = None;
                conn.results.clear();
                conn.phase = if conn.authenticated {
                    Phase::Ready
                } else {
                    Phase::Authentication
                };
                out.push(&messages::success(Vec::new()));
                return Flow::Continue;
            }
            // INTERRUPTED: the client has already sent a RESET behind this message.
            (_, _) if interrupted => {
                out.push(&messages::ignored());
                return Flow::Continue;
            }
            (_, Phase::Failed) => {
                out.push(&messages::ignored());
                return Flow::Continue;
            }
            _ => {}
        }

        match (request, conn.phase) {
            (Request::Hello { extra }, Phase::Connected) => self.hello(extra, conn, out).await,
            (Request::Logon { auth }, Phase::Authentication) if conn.minor >= 1 => {
                match self.authenticate(&auth, conn, out).await {
                    Login::Accepted => {
                        conn.authenticated = true;
                        conn.phase = Phase::Ready;
                        out.push(&messages::success(Vec::new()));
                        Flow::Continue
                    }
                    Login::Refused | Login::Closed => Flow::Close,
                }
            }
            (Request::Logoff, Phase::Ready) if conn.minor >= 1 => {
                conn.authenticated = false;
                conn.phase = Phase::Authentication;
                out.push(&messages::success(Vec::new()));
                Flow::Continue
            }
            (
                Request::Run {
                    query,
                    params,
                    extra,
                },
                Phase::Ready,
            ) => self.run_query(&query, &params, &extra, conn, out).await,
            (
                Request::Run {
                    query,
                    params,
                    extra,
                },
                Phase::TxReady | Phase::TxStreaming,
            ) => self.run_query(&query, &params, &extra, conn, out).await,
            (Request::Pull { n, qid }, Phase::Streaming | Phase::TxStreaming) => {
                self.stream(n, qid, false, conn, out)
            }
            (Request::Discard { n, qid }, Phase::Streaming | Phase::TxStreaming) => {
                self.stream(n, qid, true, conn, out)
            }
            (Request::Begin { extra }, Phase::Ready) => {
                conn.tx = Some(Transaction {
                    db: extra.get("db").and_then(Value::as_str).map(str::to_string),
                    read: extra.get("mode").and_then(Value::as_str) == Some("r"),
                });
                conn.phase = Phase::TxReady;
                out.push(&messages::success(Vec::new()));
                Flow::Continue
            }
            (Request::Commit, Phase::TxReady) => {
                conn.tx = None;
                conn.phase = Phase::Ready;
                out.push(&messages::success(vec![(
                    "bookmark",
                    Value::String(self.bookmark()),
                )]));
                Flow::Continue
            }
            (Request::Rollback, Phase::TxReady) => {
                conn.tx = None;
                conn.phase = Phase::Ready;
                out.push(&messages::success(Vec::new()));
                Flow::Continue
            }
            (Request::Route { routing, extra }, Phase::Ready) => {
                out.push(&self.routing_table(&routing, &extra, conn));
                Flow::Continue
            }
            (Request::Telemetry, Phase::Ready) if conn.minor >= 4 => {
                out.push(&messages::success(Vec::new()));
                Flow::Continue
            }
            (request, phase) => self.protocol_violation(
                conn,
                out,
                format!(
                    "Message '{}' cannot be handled by a session in the {} state.",
                    request.name(),
                    phase.wire_name()
                ),
            ),
        }
    }

    fn server_agent(&self) -> String {
        format!("Neo4j/{}", self.config.neo4j_version)
    }

    fn bookmark(&self) -> String {
        format!(
            "FB:netget:{}:{}",
            self.server_id.as_u32(),
            crate::utils::clock::SystemTime::now()
                .duration_since(crate::utils::clock::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        )
    }

    async fn hello(&self, extra: Value, conn: &mut Conn, out: &mut Out) -> Flow {
        conn.user_agent = extra
            .get("user_agent")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        conn.routing_address = extra
            .get("routing")
            .and_then(|r| r.get("address"))
            .and_then(Value::as_str)
            .map(str::to_string);
        self.log().info(format!(
            "Bolt 5.{} HELLO from {} ({})",
            conn.minor, self.peer_addr, conn.user_agent
        ));
        let success = messages::success(vec![
            ("server", Value::String(self.server_agent())),
            (
                "connection_id",
                Value::String(format!("bolt-{}", self.connection_id.as_u32())),
            ),
            ("hints", Value::Map(Vec::new())),
        ]);
        if conn.minor == 0 {
            // Bolt 5.0: the credentials ride in HELLO itself.
            match self.authenticate(&extra, conn, out).await {
                Login::Accepted => {
                    conn.authenticated = true;
                    conn.phase = Phase::Ready;
                    out.push(&success);
                    Flow::Continue
                }
                Login::Refused | Login::Closed => Flow::Close,
            }
        } else {
            conn.phase = Phase::Authentication;
            out.push(&success);
            Flow::Continue
        }
    }

    /// Decide a login. NetGet refuses a configured-password mismatch itself; everything else is
    /// the `bolt_authenticate` event's to answer.
    async fn authenticate(&self, auth: &Value, conn: &Conn, out: &mut Out) -> Login {
        let scheme = auth
            .get("scheme")
            .and_then(Value::as_str)
            .unwrap_or("none")
            .to_string();
        let principal = auth
            .get("principal")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let credentials = auth.get("credentials").and_then(Value::as_str);

        if let Some(expected) = &self.config.password {
            let matches = scheme == "basic"
                && credentials.is_some_and(|c| constant_time_eq(c.as_bytes(), expected.as_bytes()));
            if !matches {
                self.log().warn(format!(
                    "Bolt login {:?} ({}) from {} does not match the configured password \
                     decision=reject_bad_credentials",
                    principal, scheme, self.peer_addr
                ));
                out.push(&messages::failure(
                    conn.minor,
                    actions::UNAUTHORIZED,
                    UNAUTHORIZED_MESSAGE,
                ));
                return Login::Refused;
            }
        }

        let event = Event::new(
            &actions::BOLT_AUTHENTICATE_EVENT,
            serde_json::json!({
                "user_agent": conn.user_agent,
                "scheme": scheme,
                "principal": principal,
                "credentials_present": credentials.is_some_and(|c| !c.is_empty()),
                "password_configured": self.config.password.is_some(),
                "answer_with": actions::login_answer_with(
                    &principal,
                    &scheme,
                    credentials.is_some_and(|c| !c.is_empty()),
                ),
            }),
        );
        let (results, refused) = match self.ask(&event, "login").await {
            Ok(answer) => answer,
            Err(message) => {
                out.push(&messages::failure(
                    conn.minor,
                    DATABASE_UNAVAILABLE,
                    message,
                ));
                return Login::Refused;
            }
        };
        for result in results {
            match result {
                ActionResult::CloseConnection => {
                    self.log().info(format!(
                        "Bolt login from {} decision=model_close",
                        self.peer_addr
                    ));
                    return Login::Closed;
                }
                ActionResult::Custom { name, data } if name == actions::LOGIN_RESULT => {
                    if data["accept"].as_bool() == Some(true) {
                        self.log().info(format!(
                            "Bolt login {:?} from {} decision=model_answer accepted",
                            principal, self.peer_addr
                        ));
                        return Login::Accepted;
                    }
                    let code = data["code"].as_str().unwrap_or(actions::UNAUTHORIZED);
                    let message = data["message"].as_str().unwrap_or(UNAUTHORIZED_MESSAGE);
                    self.log().info(format!(
                        "Bolt login {:?} from {} decision=model_reject code={}",
                        principal, self.peer_addr, code
                    ));
                    out.push(&messages::failure(conn.minor, code, message));
                    return Login::Refused;
                }
                ActionResult::Custom { name, .. } => {
                    self.log().warn(format!(
                        "Bolt login from {}: answered with {} decision=fail_closed_mismatched_reply",
                        self.peer_addr, name
                    ));
                    out.push(&messages::failure(
                        conn.minor,
                        DATABASE_UNAVAILABLE,
                        UNAVAILABLE_MESSAGE,
                    ));
                    return Login::Refused;
                }
                _ => {}
            }
        }
        self.log().warn(format!(
            "Bolt login from {}: no usable answer decision={}",
            self.peer_addr,
            nothing_usable(refused)
        ));
        out.push(&messages::failure(
            conn.minor,
            DATABASE_UNAVAILABLE,
            UNAVAILABLE_MESSAGE,
        ));
        Login::Refused
    }

    /// Raise an event and flatten what the model decided, with how many of its actions the
    /// executor refused. `Err` carries the fixed FAILURE message for the backend-failure
    /// category; the error itself only reaches the log.
    async fn ask(
        &self,
        event: &Event,
        what: &str,
    ) -> Result<(Vec<ActionResult>, usize), &'static str> {
        match call_llm(
            &self.llm_client,
            &self.app_state,
            self.server_id,
            Some(self.connection_id),
            event,
            self.protocol.as_ref(),
        )
        .await
        {
            Ok(result) => {
                for message in &result.messages {
                    self.log().info(message);
                }
                for failure in &result.failures {
                    self.log()
                        .warn(format!("Bolt {} answer refused: {:?}", what, failure));
                }
                let mut flat = Vec::new();
                let mut stack = result.protocol_results;
                stack.reverse();
                while let Some(item) = stack.pop() {
                    match item {
                        ActionResult::Multiple(items) => stack.extend(items.into_iter().rev()),
                        other => flat.push(other),
                    }
                }
                Ok((flat, result.failures.len()))
            }
            Err(e) => {
                let (category, message) = match crate::utils::WireFailure::classify(&e) {
                    crate::utils::WireFailure::Overloaded => ("overloaded", OVERLOADED_MESSAGE),
                    crate::utils::WireFailure::Unavailable => ("unavailable", UNAVAILABLE_MESSAGE),
                };
                self.log().warn(format!(
                    "Bolt {} from {} decision=fail_closed_llm_error category={}",
                    what, self.peer_addr, category
                ));
                self.log().debug(format!("Bolt LLM call failed: {}", e));
                Err(message)
            }
        }
    }

    async fn run_query(
        &self,
        query: &str,
        params: &Value,
        extra: &Value,
        conn: &mut Conn,
        out: &mut Out,
    ) -> Flow {
        let in_tx = conn.tx.is_some();
        let db = extra
            .get("db")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| conn.tx.as_ref().and_then(|t| t.db.clone()));
        let read = match &conn.tx {
            Some(tx) => tx.read,
            None => extra.get("mode").and_then(Value::as_str) == Some("r"),
        };

        let answer = if let Some(answer) = self.admin_answer(query) {
            self.log().debug(format!(
                "Bolt {:?} from {} answered by NetGet (admin query, no model call)",
                query, self.peer_addr
            ));
            answer
        } else {
            let mut data = serde_json::json!({
                "query": query,
                "parameters": values::value_to_json(params),
                "mode": if read { "read" } else { "write" },
                "in_transaction": in_tx,
                "answer_with": actions::query_answer_with(query),
            });
            if let Some(db) = &db {
                data["database"] = serde_json::json!(db);
            }
            let event = Event::new(&actions::BOLT_QUERY_EVENT, data);
            let (results, refused) = match self.ask(&event, "query").await {
                Ok(answer) => answer,
                Err(message) => {
                    conn.phase = Phase::Failed;
                    out.push(&messages::failure(
                        conn.minor,
                        DATABASE_UNAVAILABLE,
                        message,
                    ));
                    return Flow::Continue;
                }
            };
            match self.query_outcome(query, results, refused, conn, out) {
                QueryOutcome::Answer(answer) => answer,
                QueryOutcome::Failed => return Flow::Continue,
                QueryOutcome::Close => return Flow::Close,
            }
        };

        let qid = conn.next_qid;
        conn.next_qid += 1;
        let mut metadata = vec![
            (
                "fields",
                Value::List(answer.fields.iter().cloned().map(Value::String).collect()),
            ),
            ("t_first", Value::Int(0)),
        ];
        if in_tx {
            metadata.push(("qid", Value::Int(qid)));
        }
        out.push(&messages::success(metadata));
        conn.results.push(OpenResult {
            qid,
            records: answer.records.into(),
            query_type: answer.query_type,
            stats: answer.stats,
            db: db.unwrap_or_else(|| "neo4j".to_string()),
        });
        conn.phase = if in_tx {
            Phase::TxStreaming
        } else {
            Phase::Streaming
        };
        Flow::Continue
    }

    /// Turn the model's answer to a query into a result, or queue the FAILURE it chose — or the
    /// one NetGet chooses when it chose nothing usable.
    fn query_outcome(
        &self,
        query: &str,
        results: Vec<ActionResult>,
        refused: usize,
        conn: &mut Conn,
        out: &mut Out,
    ) -> QueryOutcome {
        let mut decision = nothing_usable(refused);
        for result in results {
            match result {
                ActionResult::CloseConnection => {
                    self.log().info(format!(
                        "Bolt query {:?} from {} decision=model_close",
                        query, self.peer_addr
                    ));
                    return QueryOutcome::Close;
                }
                ActionResult::Custom { name, data } if name == actions::RECORDS_RESULT => {
                    match values::query_answer(&data) {
                        Ok(answer) => {
                            self.log().info(format!(
                                "Bolt query {:?} from {} decision=model_answer rows={}",
                                query,
                                self.peer_addr,
                                answer.records.len()
                            ));
                            return QueryOutcome::Answer(answer);
                        }
                        Err(e) => {
                            self.log().warn(format!(
                                "Bolt query from {}: unusable result ({})",
                                self.peer_addr, e
                            ));
                            decision = "fail_closed_invalid_answer";
                            break;
                        }
                    }
                }
                ActionResult::Custom { name, data } if name == actions::FAILURE_RESULT => {
                    let code = data["code"].as_str().unwrap_or(DATABASE_UNAVAILABLE);
                    let message = data["message"].as_str().unwrap_or(UNAVAILABLE_MESSAGE);
                    self.log().info(format!(
                        "Bolt query {:?} from {} decision=model_reject code={}",
                        query, self.peer_addr, code
                    ));
                    conn.phase = Phase::Failed;
                    out.push(&messages::failure(conn.minor, code, message));
                    return QueryOutcome::Failed;
                }
                ActionResult::Custom { name, .. } => {
                    self.log().warn(format!(
                        "Bolt query from {}: answered with {}",
                        self.peer_addr, name
                    ));
                    decision = "fail_closed_mismatched_reply";
                    break;
                }
                _ => {}
            }
        }
        self.log().warn(format!(
            "Bolt query {:?} from {}: no usable answer decision={}",
            query, self.peer_addr, decision
        ));
        conn.phase = Phase::Failed;
        out.push(&messages::failure(
            conn.minor,
            DATABASE_UNAVAILABLE,
            UNAVAILABLE_MESSAGE,
        ));
        QueryOutcome::Failed
    }

    /// PULL (or DISCARD) up to `n` records of the result `qid` addresses (`-1`: the last opened).
    fn stream(&self, n: i64, qid: i64, discard: bool, conn: &mut Conn, out: &mut Out) -> Flow {
        let index = if qid == -1 {
            conn.results.len().checked_sub(1)
        } else {
            conn.results.iter().position(|r| r.qid == qid)
        };
        let Some(index) = index else {
            return self.protocol_violation(conn, out, format!("No open result with qid {qid}."));
        };
        let result = &mut conn.results[index];
        let take = if n == -1 {
            result.records.len()
        } else {
            (n as usize).min(result.records.len())
        };
        for row in result.records.drain(..take) {
            if !discard {
                out.push(&messages::record(row));
            }
        }
        if !result.records.is_empty() {
            out.push(&messages::success(vec![("has_more", Value::Bool(true))]));
            return Flow::Continue;
        }

        let result = conn.results.remove(index);
        let mut summary = vec![
            ("type", Value::string(result.query_type)),
            ("t_last", Value::Int(0)),
            ("db", Value::String(result.db)),
        ];
        if let Some(stats) = result.stats {
            summary.push(("stats", stats));
        }
        let autocommit = conn.tx.is_none();
        if autocommit && result.query_type != "r" {
            summary.push(("bookmark", Value::String(self.bookmark())));
        }
        out.push(&messages::success(summary));
        conn.phase = match (autocommit, conn.results.is_empty()) {
            (true, _) => Phase::Ready,
            (false, true) => Phase::TxReady,
            (false, false) => Phase::TxStreaming,
        };
        Flow::Continue
    }

    /// ROUTE: one server in every role — this one, at the address the client used.
    fn routing_table(&self, routing: &Value, extra: &Value, conn: &Conn) -> Value {
        let address = routing
            .get("address")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| conn.routing_address.clone())
            .unwrap_or_else(|| self.local_addr.to_string());
        let db = extra
            .get("db")
            .and_then(Value::as_str)
            .unwrap_or("neo4j")
            .to_string();
        let server = |role: &str| {
            Value::map([
                (
                    "addresses",
                    Value::List(vec![Value::String(address.clone())]),
                ),
                ("role", Value::string(role)),
            ])
        };
        messages::success(vec![(
            "rt",
            Value::map([
                ("ttl", Value::Int(300)),
                ("db", Value::String(db)),
                (
                    "servers",
                    Value::List(vec![server("WRITE"), server("READ"), server("ROUTE")]),
                ),
            ]),
        )])
    }

    /// The admin queries `cypher-shell` runs on connect, answered here so connecting costs no
    /// model call. Matched on the whole query, whitespace- and case-insensitively.
    fn admin_answer(&self, query: &str) -> Option<values::QueryAnswer> {
        let normalized = query
            .trim()
            .trim_end_matches(';')
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        let version = Value::List(vec![Value::String(self.config.neo4j_version.clone())]);
        let (fields, row): (&[&str], Vec<Value>) = match normalized.as_str() {
            "call db.ping()" => (&["success"], vec![Value::Bool(true)]),
            "call dbms.licenseagreementdetails()" => (
                &["status", "daysLeftOnTrial", "totalTrialDays"],
                vec![Value::string("yes"), Value::Int(0), Value::Int(0)],
            ),
            "call dbms.components()" => (
                &["name", "versions", "edition"],
                vec![
                    Value::string("Neo4j Kernel"),
                    version,
                    Value::string("community"),
                ],
            ),
            "call dbms.components() yield versions" => (&["versions"], vec![version]),
            _ => return None,
        };
        Some(values::QueryAnswer {
            fields: fields.iter().map(|f| f.to_string()).collect(),
            records: vec![row],
            stats: None,
            query_type: "r",
        })
    }
}

/// The decision token for an answer with nothing usable in it: the executor refused what the
/// model sent (a malformed record, an invalid code), or the model sent nothing at all.
fn nothing_usable(refused: usize) -> &'static str {
    if refused > 0 {
        "fail_closed_invalid_answer"
    } else {
        "model_silent"
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Length is not secret-bearing enough to hide here; the contents are compared in full.
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// How long, and how much, the server keeps reading after it has sent its last message and
/// half-closed, so a peer with pipelined messages in flight reads the FAILURE and then FIN rather
/// than an RST that can destroy it. Bounded both ways.
const LINGER_TIME: Duration = Duration::from_secs(2);
const LINGER_BYTES: usize = 64 * 1024;

async fn linger<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) {
    let deadline = tokio::time::Instant::now() + LINGER_TIME;
    let mut sink = [0u8; 4096];
    let mut drained = 0usize;
    while drained < LINGER_BYTES {
        match tokio::time::timeout_at(deadline, reader.read(&mut sink)).await {
            Ok(Ok(n)) if n > 0 => drained += n,
            _ => break,
        }
    }
}

//! Cassandra/CQL server implementation using cassandra-protocol
//!
//! Phase 1 (Minimal Viable):
//! - STARTUP → READY (no auth)
//! - OPTIONS → SUPPORTED
//! - QUERY → RESULT (LLM-generated rows)
//! - Single-stream operation (sequential processing)
//! - Protocol v4 only
//! - Basic types: int, varchar, boolean

pub mod actions;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::utils::clock::Instant;
use actions::*;
use anyhow::{Context, Result};
use bytes::{Buf, BytesMut};
use cassandra_protocol::compression::Compression;
use cassandra_protocol::frame::{Direction, Envelope, Flags, Opcode, Version};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, trace, warn};

/// Largest frame body accepted, matching the native protocol's own 256 MiB maximum.
pub const MAX_FRAME_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Header bit marking a frame as travelling server → client (native protocol v4 §2.1).
const DIRECTION_RESPONSE: u8 = 0x80;
/// Header flag: "the response contains warnings" (native protocol v4 §2.2, flag 0x08).
const FLAG_WARNING: u8 = 0x08;

/// Decode one complete request frame, refusing the two header bits that make no sense on a
/// request before the decoder sees them.
///
/// `Envelope::from_buffer` (cassandra-protocol 5.0) parses the header fields a *client*
/// decoding a *response* needs: with the **tracing** flag on a frame whose direction bit says
/// response it reads a 16-byte tracing id, and with the **warning** flag it reads a
/// `[string list]` off the front of the body. It returns `Err` for every malformed shape of
/// those fields — a missing tracing id, a negative list count, a string longer than the body,
/// all of which `tests/server/cassandra/decoder_panic_test.rs` sends. It does not refuse the
/// bits themselves, though:
///
/// - A **response-direction** frame decodes as an ordinary frame when its body is well formed,
///   so without this check the server would act on a frame no client sends. Apache Cassandra
///   refuses it ("Wrong message direction"), and so does this.
/// - The **warning** flag on a request makes the decoder strip a string list out of the body
///   and hand on the rest, so a request carrying it is decoded from the wrong offset.
///   Warnings are something a coordinator attaches to its answers.
///
/// So a frame carrying either is refused here, through the caller's PROTOCOL_ERROR path on the
/// frame's own stream id, whether or not the decoder would have found the body well formed.
/// The tracing flag on a *request* is ordinary (the client asking for a trace) and
/// `from_buffer` ignores it there, so it is left alone.
///
/// A declared body length that is negative or above [`MAX_FRAME_BODY_BYTES`] never reaches this
/// function: the read loop refuses it before buffering a frame (the decoder now refuses the same
/// lengths too, `MAX_ENVELOPE_BODY_SIZE` being the same 256 MiB).
pub fn parse_request_frame(frame_bytes: &[u8]) -> Result<Envelope> {
    let (Some(&version), Some(&flags)) = (frame_bytes.first(), frame_bytes.get(1)) else {
        anyhow::bail!("CQL frame shorter than its header");
    };
    if version & DIRECTION_RESPONSE != 0 {
        anyhow::bail!("refused before decoding: a response frame (version byte {version:#04x}) sent to the server");
    }
    if flags & FLAG_WARNING != 0 {
        anyhow::bail!(
            "refused before decoding: the warning flag on a request (flags {flags:#04x})"
        );
    }
    let parsed = Envelope::from_buffer(frame_bytes, Compression::None)
        .context("Failed to parse Cassandra frame")?;
    Ok(parsed.envelope)
}

/// A v4 response frame on `stream_id`, with no flags, tracing id or warnings.
fn response_envelope(stream_id: i16, opcode: Opcode, body: Vec<u8>) -> Envelope {
    Envelope::new(
        Version::V4,
        Direction::Response,
        Flags::empty(),
        opcode,
        stream_id,
        body,
        None,
        vec![],
    )
}

/// How long to wait for a peer's first frame after it has connected.
///
/// CQL is client-speaks-first: the driver sends OPTIONS and then STARTUP inside its connect
/// path, and the server says nothing before them. A peer that has connected and sent nothing
/// has not begun a handshake, so it gets the short bound — and this is the one an
/// unauthenticated flood lives under, because it never reaches the idle bound below.
const FIRST_FRAME_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to wait for a *further* frame once the connection is ready.
///
/// Fifteen minutes, and long on purpose. A Cassandra driver holds a *pool* of persistent
/// connections and legitimately sends nothing on most of them for long stretches — that is how
/// the protocol is meant to be used, not a symptom. What keeps the bound meaningful is that the
/// drivers answer the same question themselves: both the DataStax and ScyllaDB drivers send a
/// heartbeat OPTIONS on an idle connection, at a default interval of 30 seconds, precisely so
/// an idle-but-live connection keeps proving it is live. Fifteen minutes is thirty of those
/// intervals; a connection that produces neither a query nor a single heartbeat in that time is
/// indistinguishable from a peer that has gone away. (Cassandra's own
/// `native_transport_idle_timeout_in_ms` ships disabled, so unlike Kafka there is no upstream
/// default to copy.)
const IDLE_BETWEEN_FRAMES_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

/// Concurrent connections this server admits.
///
/// Each connection may buffer a frame of up to [`MAX_FRAME_BODY_BYTES`], so the cap is what
/// turns that per-connection bound into a total one.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// A peer over [`MAX_CONNECTIONS`] gets a plain close, and the reason is specific to CQL.
///
/// There *is* a natural vocabulary — an ERROR frame carrying
/// [`CASSANDRA_ERROR_OVERLOADED`] — but every CQL frame is stamped with the protocol version,
/// and the version is chosen by the client's first frame, which this peer has not sent. Any
/// ERROR written here would have to guess it, and guessing wrong replaces a clear "server is
/// full" with a protocol-version error: strictly less informative than silence. Real Cassandra
/// exceeding `native_transport_max_concurrent_connections` closes the channel without a frame
/// for the same reason. The refusal is logged with `decision=fail_closed_connection_cap`.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// Cap on prepared statements retained per connection.
///
/// This is protocol session state, not storage: it holds the query text a client asked the
/// server to remember so a later EXECUTE can be resolved back to it. It still needs a bound,
/// because a client can PREPARE unlimited distinct queries on one connection and every one of
/// them was retained for the life of that connection.
const MAX_PREPARED_STATEMENTS: usize = 1024;

/// Native-protocol ERROR code 0x0000, "Server error: something unexpected happened".
const CASSANDRA_ERROR_SERVER_ERROR: u32 = 0x0000;

/// Native-protocol ERROR code 0x1001, "Overloaded: the request cannot be processed because the
/// coordinator node is overloaded". Drivers treat it as retryable.
const CASSANDRA_ERROR_OVERLOADED: u32 = 0x1001;

/// Native-protocol ERROR code 0x000A, "Protocol error: some client message triggered a
/// protocol violation". What a real coordinator answers to a frame it cannot parse.
const CASSANDRA_ERROR_PROTOCOL: u32 = 0x000A;

/// Native-protocol ERROR code 0x2500, "Unprepared".
///
/// The only error whose body carries a payload beyond the message: `[short bytes]` naming the
/// statement id the coordinator does not know. Drivers exist to handle it — scylla re-PREPAREs
/// and retries — so answering it turns an unknown id from a dead session into a hiccup.
const CASSANDRA_ERROR_UNPREPARED: u32 = 0x2500;

/// Name the `[short]` consistency level a client asked for (native protocol v4, §3).
///
/// Reported verbatim to the handler. Anything outside the defined set is `UNKNOWN` rather
/// than a plausible-looking guess — the handler can refuse what it does not recognise, but
/// only if it is told the truth.
fn consistency_name(code: u16) -> &'static str {
    match code {
        0x0000 => "ANY",
        0x0001 => "ONE",
        0x0002 => "TWO",
        0x0003 => "THREE",
        0x0004 => "QUORUM",
        0x0005 => "ALL",
        0x0006 => "LOCAL_QUORUM",
        0x0007 => "EACH_QUORUM",
        0x0008 => "SERIAL",
        0x0009 => "LOCAL_SERIAL",
        0x000A => "LOCAL_ONE",
        _ => "UNKNOWN",
    }
}

/// Cassandra server implementation
pub struct CassandraServer {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    _status_tx: mpsc::UnboundedSender<String>,
    server_id: Option<crate::state::ServerId>,
}

/// Connection state for a Cassandra client
struct CassandraConnectionState {
    ready: bool,
    protocol_version: u8,
    /// Prepared statements: statement_id -> (query_string, param_count)
    prepared_statements: HashMap<Vec<u8>, (String, usize)>,
    /// Authentication state
    authenticated: bool,
    /// Authenticated username (if any)
    username: Option<String>,
}

/// The write half of one live connection, plus what counting a write needs.
///
/// Every reply goes through this rather than through the socket: the write half is shared with
/// the dashboard's peer-command task (`server::peer_support`), so it lives behind a `Mutex`,
/// and an injected send and the server's own reply cannot interleave bytes into the middle of
/// each other's frame. `bytes_sent`/`packets_sent` are updated here — they were updated
/// nowhere before, so the rail's arrow counters sat at zero for the life of a CQL session.
struct ConnWrite {
    write_half: Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
    app_state: Arc<AppState>,
    server_id: Option<crate::state::ServerId>,
    connection_id: ConnectionId,
}

impl ConnWrite {
    /// Write one whole CQL frame and count it. The guard is dropped before the stats update,
    /// so nothing awaits on `AppState`'s lock while holding the write half.
    async fn write(&self, data: &[u8]) -> Result<()> {
        {
            let mut writer = self.write_half.lock().await;
            writer.write_all(data).await?;
            writer.flush().await?;
        }
        if let Some(server_id) = self.server_id {
            self.app_state
                .update_connection_stats(
                    server_id,
                    self.connection_id,
                    None,
                    Some(data.len() as u64),
                    None,
                    Some(1),
                )
                .await;
        }
        Ok(())
    }
}

impl CassandraServer {
    /// Create a new Cassandra server
    pub fn new(
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: Option<crate::state::ServerId>,
    ) -> Self {
        Self {
            llm_client,
            app_state,
            _status_tx: status_tx,
            server_id,
        }
    }

    /// Spawn Cassandra server with LLM integration
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        let listener = TcpListener::bind(listen_addr).await?;
        let actual_addr = listener.local_addr()?;

        Log::new(Some(&status_tx))
            .info(format!("Cassandra/CQL server listening on {}", actual_addr));

        let server = Arc::new(CassandraServer::new(
            llm_client,
            app_state.clone(),
            status_tx.clone(),
            Some(server_id),
        ));

        // Spawn the accept loop
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let loop_state = app_state.clone();
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Cassandra",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, addr, permit)) => {
                        Log::new(Some(&status_tx))
                            .debug(format!("Cassandra connection from {}", addr));

                        let server_clone = server.clone();
                        let status_tx_clone = status_tx.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = loop_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection, so the cap counts live
                                // clients rather than accepts.
                                let _permit = permit;
                                if let Err(e) = server_clone
                                    .handle_connection(stream, addr, status_tx_clone)
                                    .await
                                {
                                    error!("Cassandra connection error: {}", e);
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        // A persistent accept error (EMFILE, listener torn down) recurs
                        // immediately, so continuing spins a hot loop that floods the
                        // unbounded status channel. Stop the listener instead.
                        Log::new(Some(&status_tx))
                            .error(format!("Cassandra accept failed, listener stopped: {}", e));
                        break;
                    }
                }
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        app_state
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(actual_addr)
    }

    /// Set one Cassandra connection up, run it, and tear it down on every exit path.
    async fn handle_connection(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let connection_id = ConnectionId::new(self.app_state.get_next_unified_id().await);
        let local_addr = stream.local_addr().unwrap_or(addr);

        // Track the connection
        if let Some(server_id) = self.server_id {
            let now = Instant::now();
            let conn_state = ConnectionState {
                id: connection_id,
                remote_addr: addr,
                local_addr,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                last_activity: now,
                status: ConnectionStatus::Active,
                status_changed_at: now,
                protocol_info: ProtocolConnectionInfo::empty(),
            };

            self.app_state
                .add_connection_to_server(server_id, conn_state)
                .await;
        }

        // Split (never clone) so the write half can be shared with the peer-command task.
        let (reader, write_half) = tokio::io::split(stream);
        let write_half = Arc::new(Mutex::new(write_half));
        let out = ConnWrite {
            write_half: write_half.clone(),
            app_state: self.app_state.clone(),
            server_id: self.server_id,
            connection_id,
        };

        // Peer messaging, registered BEFORE the first read. CQL is client-speaks-first and the
        // server says nothing until the driver sends OPTIONS/STARTUP, so a `*` manual rule
        // parks the very first event this connection produces - and the operator being asked to
        // decide about it must be able to reach, or hang up, the connection while it waits.
        if let Some(server_id) = self.server_id {
            let peer_rx = crate::server::peer_support::register_peer_channel(
                &self.app_state,
                server_id,
                connection_id.as_u32(),
            )
            .await;
            let protocol = Arc::new(CassandraProtocol::new(
                connection_id,
                self.app_state.clone(),
                status_tx.clone(),
            ));
            crate::server::peer_support::spawn_peer_command_task(
                peer_rx,
                protocol,
                self.app_state.clone(),
                server_id,
                connection_id.as_u32(),
                write_half.clone(),
                status_tx.clone(),
            );
        }

        let result = self
            .run_session(reader, &out, addr, connection_id, &status_tx)
            .await;

        // Every exit path lands here - EOF, a read error, an oversized frame, a handler's
        // close, an injected disconnect. Dropping the handle also ends the peer command task,
        // which releases its clone of the write half; the explicit shutdown makes the FIN
        // immediate rather than waiting on it.
        if let Some(server_id) = self.server_id {
            self.app_state
                .remove_peer_handle(server_id, connection_id.as_u32())
                .await;
        }
        let _ = write_half.lock().await.shutdown().await;

        // Close connection
        if let Some(server_id) = self.server_id {
            self.app_state
                .close_connection_on_server(server_id, connection_id)
                .await;
        }

        result
    }

    /// The read/parse/dispatch loop. Replies go out through `out`, never through the socket.
    async fn run_session(
        &self,
        mut reader: tokio::io::ReadHalf<TcpStream>,
        out: &ConnWrite,
        addr: SocketAddr,
        connection_id: ConnectionId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let mut conn_state = CassandraConnectionState {
            ready: false,
            protocol_version: 4,
            prepared_statements: HashMap::new(),
            authenticated: false,
            username: None,
        };

        let mut buffer = BytesMut::with_capacity(4096);
        // Set once a handler asks to close, so the outer read loop stops too. Breaking only
        // out of the inner frame loop left the connection open and re-entered read_buf, which
        // made `close_this_connection` a no-op on every path.
        let mut closing = false;

        loop {
            // The deadline wraps this `read_buf` and nothing else in the loop. The LLM
            // round-trip that answers a query, and a `manual` rule parking it for a human
            // (`src/state/intercepts.rs`, 300s by default), happen in the frame loop below,
            // after bytes have already arrived — so neither is inside a read deadline and
            // neither can be cut short by one. Only a peer that holds the connection while
            // sending nothing is bounded.
            let read_timeout = if conn_state.ready {
                IDLE_BETWEEN_FRAMES_TIMEOUT
            } else {
                FIRST_FRAME_READ_TIMEOUT
            };

            // Read data from the read half
            let read = match tokio::time::timeout(read_timeout, reader.read_buf(&mut buffer)).await
            {
                Ok(read) => read,
                Err(_) => {
                    Log::new(Some(status_tx)).debug(format!(
                        "Cassandra client {} sent nothing for {}s; closing idle connection",
                        addr,
                        read_timeout.as_secs()
                    ));
                    break;
                }
            };
            let n = match read {
                Ok(0) => {
                    Log::new(Some(status_tx))
                        .debug(format!("Cassandra client {} disconnected", addr));
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    error!("Read error from {}: {}", addr, e);
                    break;
                }
            };

            // Counted on every read, as `ConnWrite::write` counts every write. Nothing
            // updated these before, so a CQL connection's arrow counters never moved.
            if let Some(server_id) = self.server_id {
                self.app_state
                    .update_connection_stats(
                        server_id,
                        connection_id,
                        Some(n as u64),
                        None,
                        Some(1),
                        None,
                    )
                    .await;
            }

            trace!("Read {} bytes from Cassandra client {}", n, addr);

            // Try to parse and handle frames
            while buffer.remaining() >= 9 {
                // Check if we have a complete frame header (9 bytes)
                let frame_start = buffer.as_ref();
                if frame_start.len() < 9 {
                    break;
                }

                // Read frame length from header (bytes 5-8)
                let length = u32::from_be_bytes([
                    frame_start[5],
                    frame_start[6],
                    frame_start[7],
                    frame_start[8],
                ]) as usize;

                // The length is attacker-chosen and up to 4 GiB. Without this check the loop
                // simply waits for the declared bytes while read_buf keeps growing BytesMut,
                // so a client that declares a huge frame and then dribbles data grows the
                // process without limit. 256 MiB is the protocol's own maximum frame size.
                if length > MAX_FRAME_BODY_BYTES {
                    Log::new(Some(status_tx)).error(format!(
                        "Cassandra frame too large ({} bytes, limit {}), closing {}",
                        length, MAX_FRAME_BODY_BYTES, addr
                    ));
                    closing = true;
                    break;
                }

                // Check if we have the complete frame
                if buffer.remaining() < 9 + length {
                    trace!(
                        "Waiting for complete frame: have {}, need {}",
                        buffer.remaining(),
                        9 + length
                    );
                    break;
                }

                // We have a complete frame, parse it
                let frame_bytes = buffer.split_to(9 + length);

                match self
                    .handle_frame(&frame_bytes, &mut conn_state, out, connection_id, status_tx)
                    .await
                {
                    Ok(should_continue) => {
                        if !should_continue {
                            debug!("Closing Cassandra connection to {}", addr);
                            closing = true;
                            break;
                        }
                    }
                    Err(e) => {
                        // The comment here said "send error frame and close connection" and
                        // then closed without sending anything. A driver blocked on the reply
                        // to that stream id saw the socket vanish and reported a *transport*
                        // fault, so a truncated EXECUTE or a frame `Envelope::from_buffer`
                        // rejected killed the whole session with no diagnosis on either end.
                        //
                        // The stream id is at bytes 2..4 of the header and does not depend on
                        // the body parsing, so the reply reaches the right request even when
                        // nothing else about the frame could be understood. The peer gets the
                        // category only — a fixed string, never `e`, which carries anyhow
                        // context and library messages.
                        Log::new(Some(status_tx)).error(format!(
                            "Cassandra connection {} decision=fail_closed_protocol_error: {}",
                            connection_id, e
                        ));
                        let stream_id = i16::from_be_bytes([frame_bytes[2], frame_bytes[3]]);
                        if let Err(send_err) = self
                            .send_error(
                                stream_id,
                                CASSANDRA_ERROR_PROTOCOL,
                                "netget: malformed CQL frame",
                                out,
                                status_tx,
                            )
                            .await
                        {
                            debug!(
                                "Cassandra could not report the protocol error to {}: {}",
                                addr, send_err
                            );
                        }
                        closing = true;
                        break;
                    }
                }
            }

            if closing {
                break;
            }
        }

        Ok(())
    }

    /// Handle a single Cassandra frame
    async fn handle_frame(
        &self,
        frame_bytes: &[u8],
        conn_state: &mut CassandraConnectionState,
        out: &ConnWrite,
        connection_id: ConnectionId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<bool> {
        let frame = parse_request_frame(frame_bytes)?;

        Log::new(Some(status_tx)).trace(format!(
            "Cassandra ← {:?} stream={}",
            frame.opcode, frame.stream_id
        ));

        match frame.opcode {
            Opcode::Startup => {
                self.handle_startup(frame, conn_state, out, connection_id, status_tx)
                    .await
            }
            Opcode::Options => {
                self.handle_options(frame, out, connection_id, status_tx)
                    .await
            }
            Opcode::Query => {
                self.handle_query(frame, out, connection_id, status_tx)
                    .await
            }
            Opcode::Prepare => {
                self.handle_prepare(frame, conn_state, out, connection_id, status_tx)
                    .await
            }
            Opcode::Execute => {
                self.handle_execute(frame, conn_state, out, connection_id, status_tx)
                    .await
            }
            Opcode::AuthResponse => {
                self.handle_auth_response(frame, conn_state, out, connection_id, status_tx)
                    .await
            }
            Opcode::Register => {
                // Client wants to register for server events
                // We don't support server events, but respond with READY to acknowledge
                Log::new(Some(status_tx))
                    .debug("Cassandra: Client registered for events (not supported, no-op)");
                self.send_ready(frame.stream_id, out, status_tx).await?;
                Ok(true)
            }
            _ => {
                Log::new(Some(status_tx))
                    .warn(format!("Unsupported Cassandra opcode: {:?}", frame.opcode));
                // Send error response
                self.send_error(
                    frame.stream_id,
                    0x000A,
                    "Unsupported operation",
                    out,
                    status_tx,
                )
                .await?;
                Ok(true)
            }
        }
    }

    /// Handle STARTUP frame
    async fn handle_startup(
        &self,
        frame: Envelope,
        conn_state: &mut CassandraConnectionState,
        out: &ConnWrite,
        connection_id: ConnectionId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<bool> {
        debug!("Handling STARTUP from connection {}", connection_id);

        // Parse startup options (CQL_VERSION, etc.)
        // For Phase 1, we just accept any version and send READY

        // Call LLM to decide response
        let protocol =
            CassandraProtocol::new(connection_id, self.app_state.clone(), status_tx.clone());

        let event = Event {
            event_type: &CASSANDRA_STARTUP_EVENT,
            data: json!({
                "protocol_version": conn_state.protocol_version,
                "options": {"CQL_VERSION": "3.0.0"}
            }),
        };

        let server_id = self.server_id.context("Server ID not set")?;

        let execution_result = match call_llm(
            &self.llm_client,
            &self.app_state,
            server_id,
            Some(connection_id),
            &event,
            &protocol,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                self.send_llm_failure_error(
                    frame.stream_id,
                    "STARTUP",
                    &e,
                    out,
                    connection_id,
                    status_tx,
                )
                .await?;
                return Ok(true);
            }
        };

        // Show messages
        for message in &execution_result.messages {
            Log::new(Some(status_tx)).info(format!("{}", message));
        }

        // Execute the protocol actions
        for action_result in execution_result.protocol_results {
            match action_result {
                ActionResult::Custom { name, data } => match name.as_str() {
                    "cassandra_ready" => {
                        conn_state.ready = true;
                        self.send_ready(frame.stream_id, out, status_tx).await?;
                        return Ok(true);
                    }
                    // Answering STARTUP with AUTHENTICATE is the only way a driver is ever
                    // prompted for credentials. Without it the client goes straight to
                    // queries, so cassandra_auth never fired and cassandra_auth_success was
                    // unreachable - the whole "Phase 3" auth path was dead.
                    "cassandra_authenticate" => {
                        let authenticator = data
                            .get("authenticator")
                            .and_then(|v| v.as_str())
                            .unwrap_or("org.apache.cassandra.auth.PasswordAuthenticator");
                        self.send_authenticate(frame.stream_id, authenticator, out, status_tx)
                            .await?;
                        return Ok(true);
                    }
                    "cassandra_error" => {
                        let error_code = data
                            .get("error_code")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0x0000) as u32;
                        let message = data
                            .get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        self.send_model_error(
                            frame.stream_id,
                            "STARTUP",
                            error_code,
                            message,
                            out,
                            connection_id,
                            status_tx,
                        )
                        .await?;
                        return Ok(true);
                    }
                    _ => {}
                },
                ActionResult::CloseConnection => {
                    return Ok(false);
                }
                _ => {
                    warn!("Unexpected action result for STARTUP");
                }
            }
        }

        // Fail closed: a CQL session is granted by an explicit `cassandra_ready` or
        // `cassandra_authenticate` and by nothing else. Falling through to READY here handed
        // out an unauthenticated session on silence, so the model had no way to make a refusal
        // distinguishable from a backend outage.
        self.send_no_answer_error(frame.stream_id, "STARTUP", out, connection_id, status_tx)
            .await?;
        Ok(false)
    }

    /// Handle OPTIONS frame
    async fn handle_options(
        &self,
        frame: Envelope,
        out: &ConnWrite,
        connection_id: ConnectionId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<bool> {
        debug!("Handling OPTIONS from connection {}", connection_id);

        let protocol =
            CassandraProtocol::new(connection_id, self.app_state.clone(), status_tx.clone());

        let event = Event {
            event_type: &CASSANDRA_OPTIONS_EVENT,
            data: json!({}),
        };

        let server_id = self.server_id.context("Server ID not set")?;

        let execution_result = match call_llm(
            &self.llm_client,
            &self.app_state,
            server_id,
            Some(connection_id),
            &event,
            &protocol,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                self.send_llm_failure_error(
                    frame.stream_id,
                    "OPTIONS",
                    &e,
                    out,
                    connection_id,
                    status_tx,
                )
                .await?;
                return Ok(true);
            }
        };

        // Show messages
        for message in &execution_result.messages {
            Log::new(Some(status_tx)).info(format!("{}", message));
        }

        // Execute the protocol actions
        for action_result in execution_result.protocol_results {
            match action_result {
                ActionResult::Custom { name, data } => match name.as_str() {
                    "cassandra_supported" => {
                        let options = data
                            .get("options")
                            .and_then(|v| v.as_object())
                            .cloned()
                            .unwrap_or_default();
                        self.send_supported(frame.stream_id, options, out, status_tx)
                            .await?;
                        return Ok(true);
                    }
                    "cassandra_error" => {
                        let error_code = data
                            .get("error_code")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0x0000) as u32;
                        let message = data
                            .get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        self.send_model_error(
                            frame.stream_id,
                            "OPTIONS",
                            error_code,
                            message,
                            out,
                            connection_id,
                            status_tx,
                        )
                        .await?;
                        return Ok(true);
                    }
                    _ => {}
                },
                ActionResult::CloseConnection => {
                    return Ok(false);
                }
                _ => {
                    warn!("Unexpected action result for OPTIONS");
                }
            }
        }

        // If no action was executed, send default SUPPORTED
        self.send_supported(frame.stream_id, serde_json::Map::new(), out, status_tx)
            .await?;
        Ok(true)
    }

    /// Handle QUERY frame
    async fn handle_query(
        &self,
        frame: Envelope,
        out: &ConnWrite,
        connection_id: ConnectionId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<bool> {
        // Parse query from frame body
        let (query_str, consistency) = self.parse_query(&frame)?;

        Log::new(Some(status_tx)).debug(format!(
            "Cassandra ← Query from connection {}: {}",
            connection_id, query_str
        ));

        let protocol =
            CassandraProtocol::new(connection_id, self.app_state.clone(), status_tx.clone());

        let event = Event {
            event_type: &CASSANDRA_QUERY_EVENT,
            data: json!({
                "query": query_str,
                "consistency": consistency
            }),
        };

        let server_id = self.server_id.context("Server ID not set")?;

        let execution_result = match call_llm(
            &self.llm_client,
            &self.app_state,
            server_id,
            Some(connection_id),
            &event,
            &protocol,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                self.send_llm_failure_error(
                    frame.stream_id,
                    "QUERY",
                    &e,
                    out,
                    connection_id,
                    status_tx,
                )
                .await?;
                return Ok(true);
            }
        };

        // Show messages
        for message in &execution_result.messages {
            Log::new(Some(status_tx)).info(format!("{}", message));
        }

        // Execute the protocol actions
        for action_result in execution_result.protocol_results {
            match action_result {
                ActionResult::Custom { name, data } => match name.as_str() {
                    "cassandra_result_rows" => {
                        let columns = data
                            .get("columns")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        let rows = data
                            .get("rows")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        self.send_result_rows(frame.stream_id, columns, rows, out, status_tx)
                            .await?;
                        return Ok(true);
                    }
                    "cassandra_error" => {
                        let error_code = data
                            .get("error_code")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0x0000) as u32;
                        let message = data
                            .get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        self.send_model_error(
                            frame.stream_id,
                            "QUERY",
                            error_code,
                            message,
                            out,
                            connection_id,
                            status_tx,
                        )
                        .await?;
                        return Ok(true);
                    }
                    _ => {}
                },
                ActionResult::CloseConnection => {
                    return Ok(false);
                }
                _ => {
                    warn!("Unexpected action result for QUERY");
                }
            }
        }

        // Fail closed: an empty RESULT/Rows frame means "no rows matched", which is an
        // answer about the data. A missing handler answer is not that.
        self.send_no_answer_error(frame.stream_id, "QUERY", out, connection_id, status_tx)
            .await?;
        Ok(true)
    }

    /// Parse the query string and requested consistency level from a QUERY frame.
    ///
    /// Body layout (native protocol v4): `[long string] query`, then `<query_parameters>`,
    /// which begins `[short] consistency [byte] flags …`.
    ///
    /// The consistency level used to be reported to the handler as the literal `"ONE"` for
    /// every query, whatever the client asked for — a fabricated event field, and the one
    /// piece of a CQL request a handler might reasonably branch on ("refuse writes at ALL",
    /// "answer LOCAL_QUORUM from this replica set"). Two bytes off the wire say what the
    /// client actually requested.
    fn parse_query(&self, frame: &Envelope) -> Result<(String, &'static str)> {
        let body = &frame.body;
        if body.len() < 4 {
            return Err(anyhow::anyhow!("Query frame too short"));
        }

        // Read long string length (4 bytes, big-endian)
        let query_len = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;

        // `4 + query_len` on a 32-bit target could wrap; compare the addends instead.
        if body.len().saturating_sub(4) < query_len {
            return Err(anyhow::anyhow!("Query frame truncated"));
        }

        let query_bytes = &body[4..4 + query_len];
        let query_str = String::from_utf8_lossy(query_bytes).to_string();

        // A QUERY frame always carries query_parameters, but a truncated one must not panic.
        // An absent or unrecognised level is reported as null rather than guessed at: the
        // handler is better served by "the client did not say" than by an invented ONE.
        let consistency = body
            .get(4 + query_len..6 + query_len)
            .map(|b| consistency_name(u16::from_be_bytes([b[0], b[1]])))
            .unwrap_or("UNKNOWN");

        Ok((query_str, consistency))
    }

    /// Send READY response
    async fn send_ready(
        &self,
        stream_id: i16,
        out: &ConnWrite,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let response = response_envelope(stream_id, Opcode::Ready, vec![]);

        let bytes = response.encode_with(Compression::None)?;
        out.write(&bytes).await?;

        Log::new(Some(status_tx)).trace(format!("Cassandra → READY ({} bytes)", bytes.len()));

        Ok(())
    }

    /// Send SUPPORTED response
    async fn send_supported(
        &self,
        stream_id: i16,
        options: serde_json::Map<String, serde_json::Value>,
        out: &ConnWrite,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        // Build SUPPORTED body: string multimap
        // For Phase 1, send minimal options
        let mut body = Vec::new();

        // Number of options (2 bytes)
        body.extend_from_slice(&(options.len() as u16).to_be_bytes());

        for (key, value) in options.iter() {
            // Key (string)
            let key_bytes = key.as_bytes();
            body.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
            body.extend_from_slice(key_bytes);

            // Value list (string list)
            if let Some(arr) = value.as_array() {
                body.extend_from_slice(&(arr.len() as u16).to_be_bytes());
                for item in arr {
                    if let Some(s) = item.as_str() {
                        let s_bytes = s.as_bytes();
                        body.extend_from_slice(&(s_bytes.len() as u16).to_be_bytes());
                        body.extend_from_slice(s_bytes);
                    }
                }
            } else {
                // Empty list
                body.extend_from_slice(&0u16.to_be_bytes());
            }
        }

        let response = response_envelope(stream_id, Opcode::Supported, body);

        let bytes = response.encode_with(Compression::None)?;
        out.write(&bytes).await?;

        Log::new(Some(status_tx)).trace(format!("Cassandra → SUPPORTED ({} bytes)", bytes.len()));

        Ok(())
    }

    /// Send RESULT with rows
    async fn send_result_rows(
        &self,
        stream_id: i16,
        columns: Vec<serde_json::Value>,
        rows: Vec<serde_json::Value>,
        out: &ConnWrite,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        // Build RESULT body (kind=ROWS)
        // This is complex in Cassandra protocol - for Phase 1, we send a simplified response
        let mut body = Vec::new();

        // Result kind (4 bytes): 0x0002 = Rows
        body.extend_from_slice(&0x00000002u32.to_be_bytes());

        // Metadata
        // Flags (4 bytes): 0x0001 = GlobalTablesSpec
        body.extend_from_slice(&0x00000001u32.to_be_bytes());

        // Column count (4 bytes)
        body.extend_from_slice(&(columns.len() as u32).to_be_bytes());

        // Global keyspace and table (for simplicity)
        let keyspace = b"system";
        let table = b"local";
        body.extend_from_slice(&(keyspace.len() as u16).to_be_bytes());
        body.extend_from_slice(keyspace);
        body.extend_from_slice(&(table.len() as u16).to_be_bytes());
        body.extend_from_slice(table);

        // Column specs
        for col in &columns {
            let name = col.get("name").and_then(|v| v.as_str()).unwrap_or("col");
            let col_type = col
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("varchar");

            // Column name
            body.extend_from_slice(&(name.len() as u16).to_be_bytes());
            body.extend_from_slice(name.as_bytes());

            // Column type (simplified: 0x000D = varchar, 0x0009 = int)
            let type_code: u16 = match col_type {
                "int" => 0x0009,
                "boolean" => 0x0004,
                _ => 0x000D, // varchar
            };
            body.extend_from_slice(&type_code.to_be_bytes());
        }

        // Rows count (4 bytes)
        body.extend_from_slice(&(rows.len() as u32).to_be_bytes());

        // Row data.
        //
        // A driver reads exactly columns.len() cells per row and takes whatever follows as
        // the next row. A handler that returns a row with the wrong number of cells therefore
        // does not just mangle that row - it desynchronizes the rest of the result set. Rows
        // are padded with NULL and truncated to the declared column count so a wrong-arity
        // answer stays parseable.
        for row in &rows {
            let empty = Vec::new();
            let row_arr = row.as_array().unwrap_or(&empty);
            if row_arr.len() != columns.len() {
                warn!(
                    "Cassandra row has {} cell(s) but {} column(s) were declared; padding/truncating",
                    row_arr.len(),
                    columns.len()
                );
            }
            for i in 0..columns.len() {
                let col_type = columns[i].get("type").and_then(|v| v.as_str());
                let cell_bytes = row_arr
                    .get(i)
                    .and_then(|cell| self.serialize_cell_value(cell, col_type));

                if let Some(bytes) = cell_bytes {
                    body.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                    body.extend_from_slice(&bytes);
                } else {
                    // NULL value (-1)
                    body.extend_from_slice(&(-1i32).to_be_bytes());
                }
            }
        }

        let response = response_envelope(stream_id, Opcode::Result, body);

        let bytes = response.encode_with(Compression::None)?;
        out.write(&bytes).await?;

        Log::new(Some(status_tx)).trace(format!(
            "Cassandra → RESULT ({} rows, {} bytes)",
            rows.len(),
            bytes.len()
        ));

        Ok(())
    }

    /// Serialize a cell for the column type that was declared for it.
    ///
    /// The column type must drive the encoding, not the JSON type. The column spec on the wire
    /// tells the driver how to read the bytes, so a column declared `int` whose value arrives
    /// as the JSON string `"5"` has to go out as a 4-byte big-endian 5 - emitting the ASCII
    /// "5" made the driver read a 1-byte int and fail. This function previously ignored the
    /// column type entirely (the parameter was `_col_type`) and switched on the JSON type
    /// alone, so any handler that quoted a number, or answered a varchar column with a number,
    /// produced a result set the driver rejected.
    ///
    /// Returns `None` for a NULL cell.
    fn serialize_cell_value(
        &self,
        value: &serde_json::Value,
        col_type: Option<&str>,
    ) -> Option<Vec<u8>> {
        if value.is_null() {
            return None;
        }

        match col_type.unwrap_or("varchar") {
            "int" => {
                let n = match value {
                    serde_json::Value::Number(n) => n.as_i64(),
                    serde_json::Value::String(s) => s.trim().parse::<i64>().ok(),
                    serde_json::Value::Bool(b) => Some(if *b { 1 } else { 0 }),
                    _ => None,
                };
                match n {
                    // Out-of-range values are NULL rather than silently wrapped: a truncated
                    // integer is a wrong answer the client cannot detect.
                    Some(n) if n >= i32::MIN as i64 && n <= i32::MAX as i64 => {
                        Some((n as i32).to_be_bytes().to_vec())
                    }
                    _ => {
                        warn!("Cassandra int column got {:?}, sending NULL", value);
                        None
                    }
                }
            }
            "boolean" => {
                let b = match value {
                    serde_json::Value::Bool(b) => Some(*b),
                    serde_json::Value::Number(n) => n.as_i64().map(|n| n != 0),
                    serde_json::Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
                        "true" | "1" | "yes" => Some(true),
                        "false" | "0" | "no" => Some(false),
                        _ => None,
                    },
                    _ => None,
                };
                match b {
                    Some(b) => Some(vec![u8::from(b)]),
                    None => {
                        warn!("Cassandra boolean column got {:?}, sending NULL", value);
                        None
                    }
                }
            }
            // varchar/text and every unrecognized type are sent as UTF-8, matching the
            // 0x000D type code send_result_rows writes for them. Strings go out verbatim;
            // anything else is rendered rather than dropped.
            _ => match value {
                serde_json::Value::String(s) => Some(s.as_bytes().to_vec()),
                other => Some(other.to_string().into_bytes()),
            },
        }
    }

    /// Handle PREPARE frame
    async fn handle_prepare(
        &self,
        frame: Envelope,
        conn_state: &mut CassandraConnectionState,
        out: &ConnWrite,
        connection_id: ConnectionId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<bool> {
        debug!("Handling PREPARE from connection {}", connection_id);

        // Parse query from frame. A PREPARE body is a bare `[long string]` with no
        // query_parameters, so the consistency `parse_query` also returns is always UNKNOWN
        // here and is discarded: the level is chosen at EXECUTE, not at PREPARE.
        let (query, _consistency) = self.parse_query(&frame)?;
        trace!("PREPARE query: {}", query);

        // Generate statement ID from query hash
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        query.hash(&mut hasher);
        let hash = hasher.finish();
        let statement_id = hash.to_be_bytes().to_vec();

        // Count parameters in query (simple heuristic: count '?' occurrences)
        let param_count = query.matches('?').count();

        // Store prepared statement
        if conn_state.prepared_statements.len() >= MAX_PREPARED_STATEMENTS
            && !conn_state.prepared_statements.contains_key(&statement_id)
        {
            warn!(
                "Cassandra connection {} reached {} prepared statements; rejecting PREPARE",
                connection_id, MAX_PREPARED_STATEMENTS
            );
            self.send_error(
                frame.stream_id,
                0x2200,
                "Too many prepared statements on this connection",
                out,
                status_tx,
            )
            .await?;
            return Ok(true);
        }
        conn_state
            .prepared_statements
            .insert(statement_id.clone(), (query.clone(), param_count));

        debug!(
            "Prepared statement ID {:?} with {} params",
            statement_id, param_count
        );

        // Call LLM to decide response
        let protocol =
            CassandraProtocol::new(connection_id, self.app_state.clone(), status_tx.clone());

        let event = Event {
            event_type: &CASSANDRA_PREPARE_EVENT,
            data: json!({
                "query": query,
                "statement_id": hex::encode(&statement_id),
                "param_count": param_count,
            }),
        };

        let server_id = self.server_id.context("Server ID not set")?;

        let execution_result = match call_llm(
            &self.llm_client,
            &self.app_state,
            server_id,
            Some(connection_id),
            &event,
            &protocol,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                self.send_llm_failure_error(
                    frame.stream_id,
                    "PREPARE",
                    &e,
                    out,
                    connection_id,
                    status_tx,
                )
                .await?;
                return Ok(true);
            }
        };

        // Show messages
        for message in &execution_result.messages {
            Log::new(Some(status_tx)).info(format!("{}", message));
        }

        // Execute the protocol actions
        for action_result in execution_result.protocol_results {
            match action_result {
                ActionResult::Custom { name, data } => match name.as_str() {
                    "cassandra_prepared" => {
                        let columns = data
                            .get("columns")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        let params = data.get("params").and_then(|v| v.as_array()).cloned();
                        self.send_prepared(
                            frame.stream_id,
                            statement_id,
                            columns,
                            params,
                            param_count,
                            out,
                            status_tx,
                        )
                        .await?;
                        return Ok(true);
                    }
                    "cassandra_error" => {
                        let error_code = data
                            .get("error_code")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0x0000) as u32;
                        let message = data
                            .get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        self.send_model_error(
                            frame.stream_id,
                            "PREPARE",
                            error_code,
                            message,
                            out,
                            connection_id,
                            status_tx,
                        )
                        .await?;
                        return Ok(true);
                    }
                    _ => {}
                },
                ActionResult::CloseConnection => {
                    return Ok(false);
                }
                _ => {
                    warn!("Unexpected action result for PREPARE");
                }
            }
        }

        // Fail closed: handing back a valid statement id would let a later EXECUTE run off a
        // preparation nobody approved.
        self.send_no_answer_error(frame.stream_id, "PREPARE", out, connection_id, status_tx)
            .await?;
        Ok(true)
    }

    /// Handle EXECUTE frame
    async fn handle_execute(
        &self,
        frame: Envelope,
        conn_state: &mut CassandraConnectionState,
        out: &ConnWrite,
        connection_id: ConnectionId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<bool> {
        debug!("Handling EXECUTE from connection {}", connection_id);

        // Parse statement ID and parameters from frame
        let (statement_id, params, consistency) = self.parse_execute(&frame)?;

        // Look up prepared statement.
        //
        // This used to be `?`, so an id we do not hold propagated out of `handle_frame` and
        // the connection was dropped with nothing written. It is reachable in ordinary use:
        // ids are a hash of the query text and are held *per connection*, so a driver
        // executing on a pooled connection that never saw the PREPARE lands here, as does one
        // reconnecting after a restart. CQL has an error for exactly this — UNPREPARED (0x2500)
        // carrying the unknown id — and drivers act on it: scylla re-PREPAREs and retries, so
        // the statement then succeeds instead of the session dying.
        let Some((query, expected_param_count)) = conn_state
            .prepared_statements
            .get(&statement_id)
            .map(|(q, n)| (q.clone(), *n))
        else {
            Log::new(Some(status_tx)).warn(format!(
                "Cassandra connection {} decision=unprepared stage=EXECUTE: statement id {} is \
                 not prepared on this connection; answering ERROR 0x{:04X} so the driver \
                 re-prepares",
                connection_id,
                hex::encode(&statement_id),
                CASSANDRA_ERROR_UNPREPARED
            ));
            self.send_unprepared_error(frame.stream_id, &statement_id, out, status_tx)
                .await?;
            return Ok(true);
        };

        trace!("EXECUTE statement: {} with {} params", query, params.len());

        // Validate parameter count
        if params.len() != expected_param_count {
            let err_msg = format!(
                "Expected {} parameters, got {}",
                expected_param_count,
                params.len()
            );
            self.send_error(frame.stream_id, 0x2200, &err_msg, out, status_tx)
                .await?;
            return Ok(true);
        }

        // Call LLM with query and bound parameters
        let protocol =
            CassandraProtocol::new(connection_id, self.app_state.clone(), status_tx.clone());

        let event = Event {
            event_type: &CASSANDRA_EXECUTE_EVENT,
            data: json!({
                "query": query,
                "statement_id": hex::encode(&statement_id),
                "parameters": params,
                "consistency": consistency,
            }),
        };

        let server_id = self.server_id.context("Server ID not set")?;

        let execution_result = match call_llm(
            &self.llm_client,
            &self.app_state,
            server_id,
            Some(connection_id),
            &event,
            &protocol,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                self.send_llm_failure_error(
                    frame.stream_id,
                    "EXECUTE",
                    &e,
                    out,
                    connection_id,
                    status_tx,
                )
                .await?;
                return Ok(true);
            }
        };

        // Show messages
        for message in &execution_result.messages {
            Log::new(Some(status_tx)).info(format!("{}", message));
        }

        // Execute the protocol actions
        for action_result in execution_result.protocol_results {
            match action_result {
                ActionResult::Custom { name, data } => match name.as_str() {
                    "cassandra_result_rows" => {
                        let columns = data
                            .get("columns")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        let rows = data
                            .get("rows")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        self.send_result_rows(frame.stream_id, columns, rows, out, status_tx)
                            .await?;
                        return Ok(true);
                    }
                    "cassandra_error" => {
                        let error_code = data
                            .get("error_code")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0x0000) as u32;
                        let message = data
                            .get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        self.send_model_error(
                            frame.stream_id,
                            "EXECUTE",
                            error_code,
                            message,
                            out,
                            connection_id,
                            status_tx,
                        )
                        .await?;
                        return Ok(true);
                    }
                    _ => {}
                },
                ActionResult::CloseConnection => {
                    return Ok(false);
                }
                _ => {
                    warn!("Unexpected action result for EXECUTE");
                }
            }
        }

        // Fail closed: an empty RESULT/Rows frame means "no rows matched", which is an
        // answer about the data. A missing handler answer is not that.
        self.send_no_answer_error(frame.stream_id, "EXECUTE", out, connection_id, status_tx)
            .await?;
        Ok(true)
    }

    /// Parse statement ID and parameters from EXECUTE frame
    fn parse_execute(
        &self,
        frame: &Envelope,
    ) -> Result<(Vec<u8>, Vec<serde_json::Value>, &'static str)> {
        let body = &frame.body;
        if body.len() < 2 {
            return Err(anyhow::anyhow!("EXECUTE frame too short"));
        }

        // Read statement ID (short bytes)
        let id_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        if body.len() < 2 + id_len {
            return Err(anyhow::anyhow!("EXECUTE frame truncated (statement ID)"));
        }

        let statement_id = body[2..2 + id_len].to_vec();
        let mut offset = 2 + id_len;

        // Consistency level (2 bytes). These bytes were read and thrown away under a comment
        // saying "skip", so the handler was told nothing about what durability the client
        // asked for — the same gap `parse_query` had, where the answer was hardcoded to ONE.
        if body.len() < offset + 2 {
            return Err(anyhow::anyhow!("EXECUTE frame truncated (consistency)"));
        }
        let consistency = consistency_name(u16::from_be_bytes([body[offset], body[offset + 1]]));
        offset += 2;

        // Skip flags (1 byte)
        if body.len() < offset + 1 {
            return Err(anyhow::anyhow!("EXECUTE frame truncated (flags)"));
        }
        let flags = body[offset];
        offset += 1;

        let mut params = Vec::new();

        // If VALUES flag is set, parse parameter values
        if flags & 0x01 != 0 {
            // Read parameter count (2 bytes)
            if body.len() < offset + 2 {
                return Err(anyhow::anyhow!("EXECUTE frame truncated (param count)"));
            }
            let param_count = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
            offset += 2;

            // Parse each parameter (bytes or null)
            for _ in 0..param_count {
                if body.len() < offset + 4 {
                    return Err(anyhow::anyhow!("EXECUTE frame truncated (param length)"));
                }

                let param_len = i32::from_be_bytes([
                    body[offset],
                    body[offset + 1],
                    body[offset + 2],
                    body[offset + 3],
                ]);
                offset += 4;

                if param_len < 0 {
                    // Null value
                    params.push(serde_json::Value::Null);
                } else {
                    let param_len = param_len as usize;
                    if body.len() < offset + param_len {
                        return Err(anyhow::anyhow!("EXECUTE frame truncated (param data)"));
                    }

                    let param_bytes = &body[offset..offset + param_len];
                    // For Phase 2, treat all params as strings
                    let param_str = String::from_utf8_lossy(param_bytes).to_string();
                    params.push(json!(param_str));
                    offset += param_len;
                }
            }
        }

        Ok((statement_id, params, consistency))
    }

    /// Send RESULT (Prepared) response
    async fn send_prepared(
        &self,
        stream_id: i16,
        statement_id: Vec<u8>,
        columns: Vec<serde_json::Value>,
        params: Option<Vec<serde_json::Value>>,
        param_count: usize,
        out: &ConnWrite,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let mut body = Vec::new();

        // Result kind: Prepared (0x0004)
        body.extend_from_slice(&0x00000004u32.to_be_bytes());

        // Statement ID (short bytes)
        body.extend_from_slice(&(statement_id.len() as u16).to_be_bytes());
        body.extend_from_slice(&statement_id);

        // FIRST: Metadata for bound variables (parameters) - describes bind markers for EXECUTE
        let keyspace = b"netget";
        let table = b"data";

        // Flags: 0x0001 (GLOBAL_TABLES_SPEC)
        body.extend_from_slice(&0x00000001u32.to_be_bytes());

        // Parameter count
        body.extend_from_slice(&(param_count as u32).to_be_bytes());

        // Partition key count (protocol v4+)
        body.extend_from_slice(&0u32.to_be_bytes()); // No PK indexes (token routing not supported)
                                                     // Note: pk_indexes would follow here if pk_count > 0

        // Global keyspace and table for parameters
        body.extend_from_slice(&(keyspace.len() as u16).to_be_bytes());
        body.extend_from_slice(keyspace);
        body.extend_from_slice(&(table.len() as u16).to_be_bytes());
        body.extend_from_slice(table);

        // Parameter specifications
        for i in 0..param_count {
            let param_name = format!("param{}", i);
            let param_bytes = param_name.as_bytes();
            body.extend_from_slice(&(param_bytes.len() as u16).to_be_bytes());
            body.extend_from_slice(param_bytes);

            // Get type from params array if available, otherwise default to varchar
            let param_type = params
                .as_ref()
                .and_then(|p| p.get(i))
                .and_then(|param| param.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("varchar");

            // Type code
            let type_code: u16 = match param_type {
                "int" => 0x0009,
                "varchar" | "text" => 0x000D,
                "boolean" => 0x0004,
                _ => 0x000D, // Default to varchar
            };
            body.extend_from_slice(&type_code.to_be_bytes());
        }

        // SECOND: Result metadata - describes columns returned when this statement is executed
        // Uses ROWS metadata format (Section 4.2.5.2) - does NOT include pk_count
        // Flags: 0x0001 (GLOBAL_TABLES_SPEC)
        body.extend_from_slice(&0x00000001u32.to_be_bytes());

        // Column count
        body.extend_from_slice(&(columns.len() as u32).to_be_bytes());

        // NOTE: No pk_count field in result metadata (only in parameters metadata)

        // Global keyspace and table
        body.extend_from_slice(&(keyspace.len() as u16).to_be_bytes());
        body.extend_from_slice(keyspace);
        body.extend_from_slice(&(table.len() as u16).to_be_bytes());
        body.extend_from_slice(table);

        // Column specifications
        for col in columns {
            let name = col.get("name").and_then(|v| v.as_str()).unwrap_or("col");
            let col_type = col
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("varchar");

            // Column name
            let name_bytes = name.as_bytes();
            body.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
            body.extend_from_slice(name_bytes);

            // Column type (simple types only for Phase 2)
            let type_code: u16 = match col_type {
                "int" => 0x0009,
                "varchar" | "text" => 0x000D,
                "boolean" => 0x0004,
                _ => 0x000D, // Default to varchar
            };
            body.extend_from_slice(&type_code.to_be_bytes());
        }

        trace!(
            "PREPARED response body hex (first 200 bytes): {}",
            hex::encode(&body[..std::cmp::min(200, body.len())])
        );

        let response = response_envelope(stream_id, Opcode::Result, body);

        let bytes = response.encode_with(Compression::None)?;
        out.write(&bytes).await?;

        Log::new(Some(status_tx)).trace(format!(
            "Cassandra → RESULT (Prepared: {} params, {} bytes)",
            param_count,
            bytes.len()
        ));

        Ok(())
    }

    /// Send the ERROR frame that answers a failed LLM call.
    ///
    /// The native protocol has an ERROR opcode with a numeric code, and a driver surfaces it as
    /// an exception on the exact request that produced it - so unlike silence it cannot be
    /// mistaken for a slow query, and unlike a RESULT frame it cannot be mistaken for an empty
    /// result set, which in CQL means "no rows matched".
    ///
    /// 0x1001 `Overloaded` is the protocol's own "the coordinator cannot take this right now",
    /// and every driver treats it as retryable - so capacity exhaustion gets a signal the
    /// client already knows how to act on. Everything else is 0x0000 `Server error`.
    ///
    /// Note what is *not* used for the AUTH_RESPONSE stage: 0x0100 `Bad credentials`. The
    /// credentials were never examined, and saying they were bad both misattributes the
    /// failure and would make a driver stop retrying with correct ones. An ERROR frame of any
    /// code is a refusal - AUTH_SUCCESS is the only thing that authenticates - so this stays
    /// fail-closed either way.
    async fn send_llm_failure_error(
        &self,
        stream_id: i16,
        stage: &str,
        err: &anyhow::Error,
        out: &ConnWrite,
        connection_id: ConnectionId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let overloaded = crate::llm::is_overload_error(err);
        let (code, label) = if overloaded {
            (CASSANDRA_ERROR_OVERLOADED, "Overloaded")
        } else {
            (CASSANDRA_ERROR_SERVER_ERROR, "Server error")
        };
        let message = crate::utils::WireFailure::classify(err).prefixed_text();
        Log::new(Some(status_tx)).warn(format!(
            "Cassandra connection {} answering {} with ERROR 0x{:04X} ({}): {}",
            connection_id, stage, code, label, message
        ));
        self.send_error(stream_id, code, &message, out, status_tx)
            .await
    }

    /// Answer a stage the handler left unanswered.
    ///
    /// A no-answer is not permission. Silence used to fall through to the success frame for
    /// the stage - READY for STARTUP, an empty RESULT/Rows for QUERY and EXECUTE, a valid
    /// statement id for PREPARE - so an LLM outage, a handler that returned nothing, and a
    /// model that deliberately refused were indistinguishable on the wire, and two of the
    /// three granted the client exactly what it asked for.
    ///
    /// Every success frame here has to be produced by an explicit action; nothing synthesises
    /// one. An empty Rows result in particular is a statement about the data ("no rows
    /// matched") and must never be manufactured by a failure.
    ///
    /// The log carries `decision=fail_closed_no_answer`, distinct from
    /// `decision=fail_closed_llm_error` (backend failed) and `decision=model_reject` (the
    /// handler asked for an ERROR), because the CQL wire cannot tell the three apart.
    async fn send_no_answer_error(
        &self,
        stream_id: i16,
        stage: &str,
        out: &ConnWrite,
        connection_id: ConnectionId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        Log::new(Some(status_tx)).warn(format!(
            "Cassandra connection {} decision=fail_closed_no_answer stage={}: handler produced \
             no recognised action, answering ERROR 0x{:04X} (Server error)",
            connection_id, stage, CASSANDRA_ERROR_SERVER_ERROR
        ));
        self.send_error(
            stream_id,
            CASSANDRA_ERROR_SERVER_ERROR,
            "netget: no handler answer for this request",
            out,
            status_tx,
        )
        .await
    }

    /// Send the ERROR frame a handler explicitly asked for.
    ///
    /// Logged as `decision=model_reject` so a deliberate refusal is separable from the two
    /// failure paths above, which reach the same opcode.
    async fn send_model_error(
        &self,
        stream_id: i16,
        stage: &str,
        error_code: u32,
        message: &str,
        out: &ConnWrite,
        connection_id: ConnectionId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        Log::new(Some(status_tx)).info(format!(
            "Cassandra connection {} decision=model_reject stage={}: ERROR 0x{:04X}",
            connection_id, stage, error_code
        ));
        self.send_error(stream_id, error_code, message, out, status_tx)
            .await
    }

    /// Send ERROR 0x2500 UNPREPARED, whose body carries the id the driver must re-prepare.
    ///
    /// UNPREPARED is the one native-protocol error with a payload after the message:
    /// `[int code][string message][short bytes id]`. Omitting the id is not a smaller version
    /// of the same answer — a driver reads the trailing bytes unconditionally and treats a
    /// missing id as a framing fault, so it must be written.
    async fn send_unprepared_error(
        &self,
        stream_id: i16,
        statement_id: &[u8],
        out: &ConnWrite,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let message = "netget: statement not prepared on this connection";
        let mut body = Vec::new();
        body.extend_from_slice(&CASSANDRA_ERROR_UNPREPARED.to_be_bytes());
        body.extend_from_slice(&(message.len() as u16).to_be_bytes());
        body.extend_from_slice(message.as_bytes());
        // [short bytes]: a 2-byte length then the id. Ids come from `send_prepared`, which
        // writes a 16-byte hash, so the cast cannot truncate in practice; clamp anyway rather
        // than emit a length that disagrees with what follows it.
        let id_len = u16::try_from(statement_id.len()).unwrap_or(u16::MAX) as usize;
        body.extend_from_slice(&(id_len as u16).to_be_bytes());
        body.extend_from_slice(&statement_id[..id_len]);

        let response = response_envelope(stream_id, Opcode::Error, body);

        let bytes = response.encode_with(Compression::None)?;
        out.write(&bytes).await?;

        Log::new(Some(status_tx)).trace(format!(
            "Cassandra → ERROR 0x{:04X} UNPREPARED id={}",
            CASSANDRA_ERROR_UNPREPARED,
            hex::encode(statement_id)
        ));

        Ok(())
    }

    /// Send ERROR response
    async fn send_error(
        &self,
        stream_id: i16,
        error_code: u32,
        message: &str,
        out: &ConnWrite,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let mut body = Vec::new();

        // Error code (4 bytes)
        body.extend_from_slice(&error_code.to_be_bytes());

        // Error message (string)
        let msg_bytes = message.as_bytes();
        body.extend_from_slice(&(msg_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(msg_bytes);

        let response = response_envelope(stream_id, Opcode::Error, body);

        let bytes = response.encode_with(Compression::None)?;
        out.write(&bytes).await?;

        Log::new(Some(status_tx)).trace(format!(
            "Cassandra → ERROR 0x{:04X} - {}",
            error_code, message
        ));

        Ok(())
    }

    /// Handle AUTH_RESPONSE frame (Phase 3)
    async fn handle_auth_response(
        &self,
        frame: Envelope,
        conn_state: &mut CassandraConnectionState,
        out: &ConnWrite,
        connection_id: ConnectionId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<bool> {
        debug!("Handling AUTH_RESPONSE from connection {}", connection_id);

        // Parse credentials from frame body (SASL PLAIN format: \0username\0password)
        let body = &frame.body;

        // Extract username and password from SASL PLAIN format
        let (username, password) = self.parse_sasl_plain(body)?;

        trace!("AUTH_RESPONSE: username={}", username);

        // Call LLM to decide whether to accept authentication
        let protocol =
            CassandraProtocol::new(connection_id, self.app_state.clone(), status_tx.clone());

        let event = Event {
            event_type: &CASSANDRA_AUTH_EVENT,
            data: json!({
                "username": username,
                "password": password,
            }),
        };

        let server_id = self.server_id.context("Server ID not set")?;

        let execution_result = match call_llm(
            &self.llm_client,
            &self.app_state,
            server_id,
            Some(connection_id),
            &event,
            &protocol,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                self.send_llm_failure_error(
                    frame.stream_id,
                    "AUTH_RESPONSE",
                    &e,
                    out,
                    connection_id,
                    status_tx,
                )
                .await?;
                return Ok(true);
            }
        };

        // Show messages
        for message in &execution_result.messages {
            Log::new(Some(status_tx)).info(format!("{}", message));
        }

        // Execute the protocol actions
        for action_result in execution_result.protocol_results {
            match action_result {
                ActionResult::Custom { name, data } => {
                    match name.as_str() {
                        "cassandra_auth_success" => {
                            conn_state.authenticated = true;
                            conn_state.username = Some(username);
                            self.send_auth_success(frame.stream_id, out, status_tx)
                                .await?;
                            return Ok(true);
                        }
                        "cassandra_error" => {
                            let error_code =
                                data.get("error_code")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0x0000) as u32;
                            let message = data
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Unknown error");
                            self.send_model_error(
                                frame.stream_id,
                                "AUTH_RESPONSE",
                                error_code,
                                message,
                                out,
                                connection_id,
                                status_tx,
                            )
                            .await?;
                            return Ok(false); // Close connection on auth failure
                        }
                        _ => {}
                    }
                }
                ActionResult::CloseConnection => {
                    return Ok(false);
                }
                _ => {
                    warn!("Unexpected action result for AUTH_RESPONSE");
                }
            }
        }

        // Default: deny authentication
        self.send_error(
            frame.stream_id,
            0x0100,
            "Authentication failed",
            out,
            status_tx,
        )
        .await?;
        Ok(false)
    }

    /// Parse SASL PLAIN credentials (format: \0username\0password)
    fn parse_sasl_plain(&self, body: &[u8]) -> Result<(String, String)> {
        if body.is_empty() {
            return Err(anyhow::anyhow!("Empty AUTH_RESPONSE body"));
        }

        // Skip optional authorization identity (first \0-terminated string)
        let mut idx = 0;
        while idx < body.len() && body[idx] != 0 {
            idx += 1;
        }
        idx += 1; // Skip the \0

        if idx >= body.len() {
            return Err(anyhow::anyhow!("Invalid SASL PLAIN format"));
        }

        // Extract username
        let username_start = idx;
        while idx < body.len() && body[idx] != 0 {
            idx += 1;
        }
        let username = String::from_utf8_lossy(&body[username_start..idx]).to_string();
        idx += 1; // Skip the \0

        if idx >= body.len() {
            return Err(anyhow::anyhow!(
                "Invalid SASL PLAIN format - missing password"
            ));
        }

        // Extract password
        let password = String::from_utf8_lossy(&body[idx..]).to_string();

        Ok((username, password))
    }

    /// Send AUTHENTICATE response (request authentication)
    async fn send_authenticate(
        &self,
        stream_id: i16,
        authenticator: &str,
        out: &ConnWrite,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let mut body = Vec::new();

        // Authenticator name (string)
        let auth_bytes = authenticator.as_bytes();
        body.extend_from_slice(&(auth_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(auth_bytes);

        let response = response_envelope(stream_id, Opcode::Authenticate, body);

        let bytes = response.encode_with(Compression::None)?;
        out.write(&bytes).await?;

        Log::new(Some(status_tx)).trace(format!("Cassandra → AUTHENTICATE ({})", authenticator));

        Ok(())
    }

    /// Send AUTH_SUCCESS response
    async fn send_auth_success(
        &self,
        stream_id: i16,
        out: &ConnWrite,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        // AUTH_SUCCESS body can contain optional token (we send empty for SASL PLAIN)
        let body = vec![];

        let response = response_envelope(stream_id, Opcode::AuthSuccess, body);

        let bytes = response.encode_with(Compression::None)?;
        out.write(&bytes).await?;

        Log::new(Some(status_tx)).trace("Cassandra → AUTH_SUCCESS");

        Ok(())
    }
}

//! MongoDB server implementation with manual OP_MSG parsing
pub mod actions;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::{console_debug, console_error};
use actions::{MongodbProtocol, MONGODB_COMMAND_EVENT, MONGODB_DISCONNECTED_EVENT};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

use crate::utils::bson_depth::{
    scan_bson_document, scan_bson_document_with_limit, BsonScan, MAX_BSON_DEPTH,
};
use bson::{doc, Bson, Document};

/// Largest MongoDB wire message we will accept.
///
/// Matches the server-advertised `maxMessageSizeBytes` (48 MB). The header's `messageLength`
/// is attacker-controlled, so it has to be range-checked before it is used as an allocation
/// size - see `read_message_body`.
pub const MAX_MESSAGE_SIZE: i32 = 48 * 1024 * 1024;

/// MongoDB wire protocol opcode for OP_MSG (MongoDB 3.6+).
const OP_MSG: i32 = 2013;

/// How long the rest of a message may take to arrive once its 16-byte header has.
///
/// [`MAX_MESSAGE_SIZE`] bounds one buffer; this bounds how long a peer may hold it. Without
/// it, sixteen bytes claiming a 48 MB body pin 48 MB per connection indefinitely.
const BODY_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to wait for a peer's first message header after it has connected.
///
/// MongoDB is client-speaks-first: the server says nothing until an OP_MSG arrives, and every
/// real driver opens with `hello`/`isMaster` inside its own connect path. A peer that has
/// connected and sent no header at all has started nothing, so it gets the short bound.
const FIRST_HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to wait for a *further* message header once one has been answered.
///
/// Ten minutes, matching the driver-side idle window the official drivers ship
/// (`maxIdleTimeMS` is unset by default, but connection pools reap at this order and a
/// `heartbeatFrequencyMS` of 10 s keeps a monitoring connection far inside it). A pooled
/// connection between operations is legitimately silent for minutes; forever is not a
/// legitimate configuration.
///
/// **This bound is what makes `[ disconnect this peer ]` take effect.** The dashboard's
/// disconnect half-closes the socket and marks the row closed, which a peer that is not
/// reading never notices — so without a deadline on the *header* read this task stayed parked
/// in `read_exact` until the peer itself closed, holding the connection's tasks and state row
/// behind an operator action that reported success. [`BODY_READ_TIMEOUT`] did not cover it:
/// that one arms only once sixteen bytes have already arrived.
///
/// Like every read deadline in this tree it is armed lazily, per read: the future is created
/// at the top of the loop, *after* the previous message's LLM round-trip (or a `manual` rule
/// parked for a human, 300 s by default) has finished, so no clock runs during that work and a
/// long park cannot evict a live session. That is the TFTP eviction defect stated in reverse.
const IDLE_BETWEEN_MESSAGES_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Concurrent connections this server admits before it starts refusing.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`].
/// [`FIRST_HEADER_READ_TIMEOUT`] and [`IDLE_BETWEEN_MESSAGES_TIMEOUT`] bound how long *one*
/// peer holds a slot; only a cap bounds how many of them there can be at once, and the idle
/// bound is ten minutes, so without a cap a peer connecting once a second pins six hundred
/// sockets before the first is even eligible to close.
///
/// A MongoDB connection is a pooled *session*, not a request — a driver opens
/// `maxPoolSize` (100 by default) per client and keeps them — so this server's live-connection
/// count is its client population times that pool, and the house default sits deliberately
/// above two such clients. The per-connection memory is bounded separately by
/// [`MAX_MESSAGE_SIZE`], which is the half of the product that actually describes the cost;
/// a deployment that wants a tighter total should tighten that rather than this.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// A peer over [`MAX_CONNECTIONS`] gets a **plain close**, with nothing written.
///
/// MongoDB's wire protocol has a perfectly good way to say "unavailable" — this server already
/// sends [`MONGODB_TEMPORARILY_UNAVAILABLE`] when the model backend is saturated — and it is
/// unusable here for the reason `ipp` and `ident` are silent: **every reply is addressed to a
/// request that a refused peer has not sent.** A wire message's header carries `responseTo`,
/// which the driver matches against its outstanding `requestID`; nothing has arrived at the
/// accept, so the only value available is zero.
///
/// That is worse than silence rather than merely useless. A driver that receives a reply it
/// did not ask for does not surface it as an error — it has no request to fail — so an
/// invented OP_MSG is discarded while the driver goes on waiting for the `hello` it did send,
/// and the peer we meant to turn away instead blocks until its own `connectTimeoutMS`. An EOF
/// during the handshake is a case every driver already has: the connection is marked failed
/// immediately, the pool retries elsewhere, and SDAM records a transient network error rather
/// than a protocol one.
///
/// The refusal is logged with `decision=fail_closed_connection_cap`, and that log line is the
/// diagnosis.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// The write half of one connection, shared between the session loop and the dashboard's
/// peer-command task (`server::peer_support`).
///
/// Both may write, so the mutex is what keeps an injected write from landing inside an
/// OP_MSG the session is emitting. The guard is never held across an LLM call — see
/// `write_response`.
type SharedWrite = Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>;

/// MongoDB server implementation
pub struct MongodbServer {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    _status_tx: mpsc::UnboundedSender<String>,
    server_id: Option<crate::state::ServerId>,
}

impl MongodbServer {
    /// Create a new MongoDB server
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

    /// Spawn MongoDB server with LLM integration
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        let listener = TcpListener::bind(listen_addr).await?;
        let actual_addr = listener.local_addr()?;

        info!("MongoDB server starting on {}", actual_addr);
        let _ = status_tx.send(format!(
            "[INFO] MongoDB server listening on {}",
            actual_addr
        ));

        let server = Arc::new(MongodbServer::new(
            llm_client,
            app_state.clone(),
            status_tx.clone(),
            Some(server_id),
        ));

        let status_tx_clone = status_tx.clone();
        let task_registrar = app_state.clone();

        // Spawn the accept loop
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "MONGODB",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, addr, permit)) => {
                        console_debug!(status_tx, "MongoDB connection from {}", addr);

                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(actual_addr);

                        // Track the connection
                        if let Some(server_id) = server.server_id {
                            use crate::state::server::{
                                ConnectionState as ServerConnectionState, ConnectionStatus,
                                ProtocolConnectionInfo,
                            };
                            let now = crate::utils::clock::Instant::now();
                            let conn_state = ServerConnectionState {
                                id: connection_id,
                                remote_addr: addr,
                                local_addr: local_addr_conn,
                                bytes_sent: 0,
                                bytes_received: 0,
                                packets_sent: 0,
                                packets_received: 0,
                                last_activity: now,
                                status: ConnectionStatus::Active,
                                status_changed_at: now,
                                protocol_info: ProtocolConnectionInfo::empty(),
                            };
                            server
                                .app_state
                                .add_connection_to_server(server_id, conn_state)
                                .await;
                        }

                        let handler = MongodbHandler::new(
                            connection_id,
                            server.llm_client.clone(),
                            server.app_state.clone(),
                            status_tx.clone(),
                            server.server_id,
                            addr,
                        );

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Released when this task ends, and this task is the whole of
                                // the connection — `handle_connection` spawns nothing that
                                // outlives it; the dashboard's peer-command task writes
                                // through a shared write half rather than owning one — so
                                // `MAX_CONNECTIONS` caps live connections rather than accepts.
                                let _permit = permit;
                                if let Err(e) = handler.handle_connection(stream).await {
                                    error!("MongoDB connection error: {:?}", e);
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        console_error!(status_tx, "MongoDB accept error: {}", e);
                    }
                }
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
        Ok(actual_addr)
    }
}

/// MongoDB connection handler
pub struct MongodbHandler {
    connection_id: ConnectionId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    #[allow(dead_code)]
    status_tx: mpsc::UnboundedSender<String>,
    #[allow(dead_code)]
    server_id: Option<crate::state::ServerId>,
    #[allow(dead_code)]
    remote_addr: SocketAddr,
    /// MongoDB protocol handler for action execution
    protocol: Arc<MongodbProtocol>,
}

impl MongodbHandler {
    pub fn new(
        connection_id: ConnectionId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: Option<crate::state::ServerId>,
        remote_addr: SocketAddr,
    ) -> Self {
        let protocol = Arc::new(MongodbProtocol::new(
            connection_id,
            app_state.clone(),
            status_tx.clone(),
        ));

        Self {
            connection_id,
            llm_client,
            app_state,
            status_tx,
            server_id,
            remote_addr,
            protocol,
        }
    }

    /// Run the connection, then always mark it closed in `AppState`.
    ///
    /// The socket is split here rather than inside the read loop, because the write half has
    /// two owners: the loop's own replies and the dashboard's peer-command task. Registration
    /// happens **before the first read** — MongoDB is client-speaks-first, and a `manual` rule
    /// can park the very first command for minutes, so the operator has to be able to reach
    /// (or hang up) a connection that has not said anything yet.
    async fn handle_connection(self, stream: TcpStream) -> Result<()> {
        let server_id = self.server_id;
        let connection_id = self.connection_id;
        let app_state = self.app_state.clone();

        // Owning split, never a clone: the write half outlives this function's stack frame
        // inside the peer-command task.
        let (reader, write_half) = tokio::io::split(stream);
        let write_half: SharedWrite = Arc::new(Mutex::new(write_half));

        if let Some(server_id) = server_id {
            let peer_rx = crate::server::peer_support::register_peer_channel(
                &app_state,
                server_id,
                connection_id.as_u32(),
            )
            .await;
            crate::server::peer_support::spawn_peer_command_task(
                peer_rx,
                self.protocol.clone(),
                app_state.clone(),
                server_id,
                connection_id.as_u32(),
                write_half.clone(),
                self.status_tx.clone(),
            );
        }

        let outcome = self.run_session(reader, &write_half).await;

        // Every exit path — EOF, a read error, a refused message length, an injected
        // disconnect — lands here. The handle goes first so the rail stops offering a dead
        // connection *before* the disconnected event's round-trip, which a `manual` rule can
        // park for minutes; the shutdown then makes the FIN immediate rather than waiting for
        // the peer task to drop its clone of the write half.
        if let Some(server_id) = server_id {
            app_state
                .remove_peer_handle(server_id, connection_id.as_u32())
                .await;
        }
        let _ = write_half.lock().await.shutdown().await;
        if let Some(server_id) = server_id {
            app_state
                .close_connection_on_server(server_id, connection_id)
                .await;
        }

        // The socket is finished with before the disconnected event goes to the LLM, rather
        // than being held open for the round-trip. A session that ended in a read error never
        // raised this event and still does not: the reason strings describe how a *session*
        // ended, and there is none to report.
        match outcome {
            Ok(disconnect_reason) => {
                let event = Event::new(
                    &MONGODB_DISCONNECTED_EVENT,
                    serde_json::json!({"reason": disconnect_reason}),
                );
                let server_id = server_id.unwrap_or_else(|| crate::state::ServerId::new(0));
                let _ = call_llm(
                    &self.llm_client,
                    &self.app_state,
                    server_id,
                    Some(self.connection_id),
                    &event,
                    self.protocol.as_ref(),
                )
                .await;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Write a reply and count it.
    ///
    /// Every response goes through here so the rail's `↑` counter and `last_activity` cannot
    /// drift from what actually left the socket — MongoDB is connection-oriented, so nothing
    /// else refreshes them. The guard is dropped before the stats update, so nothing awaits
    /// `AppState` while holding the write half.
    async fn write_response(&self, write_half: &SharedWrite, bytes: &[u8]) -> Result<()> {
        {
            let mut writer = write_half.lock().await;
            writer.write_all(bytes).await?;
            writer.flush().await?;
        }
        self.record_sent(bytes.len() as u64).await;
        Ok(())
    }

    async fn record_received(&self, bytes: u64) {
        if let Some(server_id) = self.server_id {
            self.app_state
                .update_connection_stats(
                    server_id,
                    self.connection_id,
                    Some(bytes),
                    None,
                    Some(1),
                    None,
                )
                .await;
        }
    }

    async fn record_sent(&self, bytes: u64) {
        if let Some(server_id) = self.server_id {
            self.app_state
                .update_connection_stats(
                    server_id,
                    self.connection_id,
                    None,
                    Some(bytes),
                    None,
                    Some(1),
                )
                .await;
        }
    }

    /// The read/dispatch/reply loop. Returns the reason the session ended, which the caller
    /// reports as `mongodb_disconnected` once the socket has been shut down.
    async fn run_session(
        &self,
        mut reader: tokio::io::ReadHalf<TcpStream>,
        write_half: &SharedWrite,
    ) -> Result<&'static str> {
        debug!(
            "MongoDB handler starting for connection {}",
            self.connection_id
        );

        // MongoDB doesn't require handshake - client sends first
        // The disconnect reason reported to the LLM once the socket is done.
        let mut disconnect_reason = "client_disconnect";
        // Whether this session has already answered a message, which decides which of the two
        // header deadlines applies.
        let mut answered_one = false;

        loop {
            // Read MongoDB wire protocol message header (16 bytes)
            // Format: messageLength (4) + requestID (4) + responseTo (4) + opCode (4)
            //
            // Bounded: `BODY_READ_TIMEOUT` used to be the only deadline in this loop, and it
            // arms only after a header has arrived, so a peer that connected and said nothing
            // — or one the operator disconnected from the dashboard, which half-closes without
            // the peer noticing — parked this task in `read_exact` indefinitely.
            let header_timeout = if answered_one {
                IDLE_BETWEEN_MESSAGES_TIMEOUT
            } else {
                FIRST_HEADER_READ_TIMEOUT
            };
            let mut header = [0u8; 16];
            let header_read =
                match tokio::time::timeout(header_timeout, reader.read_exact(&mut header)).await {
                    Ok(read) => read,
                    Err(_) => {
                        debug!(
                            "MongoDB: {} sent no message header for {:?}; closing idle connection",
                            self.remote_addr, header_timeout
                        );
                        let _ = self.status_tx.send(format!(
                            "[INFO] MongoDB: {} sent nothing for {:?}, closing idle connection",
                            self.remote_addr, header_timeout
                        ));
                        disconnect_reason = "idle_timeout";
                        break;
                    }
                };
            match header_read {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("MongoDB client disconnected");
                    break;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }

            let message_length = i32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            let request_id = i32::from_le_bytes([header[4], header[5], header[6], header[7]]);
            let _response_to = i32::from_le_bytes([header[8], header[9], header[10], header[11]]);
            let op_code = i32::from_le_bytes([header[12], header[13], header[14], header[15]]);

            trace!(
                "MongoDB message: length={}, requestID={}, opCode={}",
                message_length,
                request_id,
                op_code
            );

            // `messageLength` comes off the wire. A value below 16 used to underflow the
            // `message_length - 16` subtraction into a ~18 exabyte `vec![0u8; n]`, aborting
            // the process; a value near i32::MAX allocated gigabytes per connection. Both are
            // reachable with 16 bytes from an unauthenticated peer.
            if !(16..=MAX_MESSAGE_SIZE).contains(&message_length) {
                error!(
                    "MongoDB: rejecting message with out-of-range length {} from {}",
                    message_length, self.remote_addr
                );
                let _ = self.status_tx.send(format!(
                    "[ERROR] MongoDB: invalid message length {} from {}, closing connection",
                    message_length, self.remote_addr
                ));
                disconnect_reason = "invalid_message_length";
                break;
            }

            // Read the rest of the message body.
            //
            // The length check above bounds one message at 48 MB, but nothing bounded how
            // long the peer could take to deliver it. A client that sends a 48 MB header
            // and then stops holds that whole buffer for the life of the process, and a
            // hundred such connections is 4.8 GB with sixteen bytes sent each. The rest of
            // a message whose header has already arrived is in flight by definition, so a
            // deadline here refuses a stalled peer without truncating a legitimate one.
            let body_length = (message_length - 16) as usize;
            let mut body = vec![0u8; body_length];
            match tokio::time::timeout(BODY_READ_TIMEOUT, reader.read_exact(&mut body)).await {
                Ok(r) => {
                    r?;
                }
                Err(_) => {
                    error!(
                        "MongoDB: {} did not finish a {}-byte message within {:?}, closing",
                        self.remote_addr, message_length, BODY_READ_TIMEOUT
                    );
                    let _ = self.status_tx.send(format!(
                        "[ERROR] MongoDB: incomplete message body from {} after {:?}, \
                         closing connection",
                        self.remote_addr, BODY_READ_TIMEOUT
                    ));
                    disconnect_reason = "incomplete_message_body";
                    break;
                }
            }
            self.record_received(message_length as u64).await;
            // A whole message has arrived, so this connection is in use rather than merely
            // open: subsequent header reads get the long, pooled-connection bound.
            answered_one = true;

            // Parse command based on opCode. Only OP_MSG is implemented; anything else would
            // leave the client waiting forever for a reply it can parse, so close instead.
            if op_code != OP_MSG {
                error!(
                    "MongoDB: unsupported opCode {} from {}, closing connection",
                    op_code, self.remote_addr
                );
                let _ = self.status_tx.send(format!(
                    "[ERROR] MongoDB: unsupported opCode {} (only OP_MSG {} is implemented)",
                    op_code, OP_MSG
                ));
                disconnect_reason = "unsupported_opcode";
                break;
            }

            let command_doc = match self.parse_op_msg(&body) {
                Ok(ParsedOpMsg::Command(doc)) => doc,
                Ok(ParsedOpMsg::TooDeep { limit }) => {
                    // The whole message has been read, so the connection is still in step:
                    // answer this request with MongoDB's own depth error and carry on, as a
                    // real server does. Nothing from the document reaches the model.
                    warn!(
                        "MongoDB connection {} decision=fail_closed_bson_too_deep: command \
                         document nests deeper than {} levels; refused without decoding",
                        self.connection_id, limit
                    );
                    let _ = self.status_tx.send(format!(
                        "[WARN] MongoDB connection {} decision=fail_closed_bson_too_deep",
                        self.connection_id
                    ));
                    let doc = mongodb_error_doc(MONGODB_OVERFLOW, BSON_TOO_DEEP_ERRMSG);
                    let response_bytes = self.encode_op_msg_response(request_id, doc)?;
                    self.write_response(write_half, &response_bytes).await?;
                    continue;
                }
                Err(e) => {
                    error!("MongoDB: malformed OP_MSG from {}: {}", self.remote_addr, e);
                    let _ = self
                        .status_tx
                        .send(format!("[ERROR] MongoDB: malformed OP_MSG: {}", e));
                    disconnect_reason = "malformed_op_msg";
                    break;
                }
            };

            trace!("MongoDB command document: {:?}", command_doc);

            // In the MongoDB command format the *first* key is the command name and its value
            // is the collection, e.g. `{find: "users", filter: {...}, $db: "testdb"}`. The old
            // code looked for a literal "collection" field, which no command ever sends, so
            // the documented `collection` event parameter was always null.
            let command_name = command_doc
                .keys()
                .next()
                .map(|k| k.as_str())
                .unwrap_or("unknown")
                .to_string();
            let collection = command_doc
                .get(&command_name)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let database = command_doc.get_str("$db").unwrap_or("admin").to_string();

            // The driver handshake is protocol business, not a question for the model: it must
            // carry the wire-version range and size limits, and a driver that does not get them
            // aborts before it ever sends a real command. This mirrors how the sibling database
            // protocols handle their handshakes (opensrv-mysql, pgwire's startup handler, and
            // MSSQL's hand-written PRELOGIN/LOGIN).
            if command_name.eq_ignore_ascii_case("hello")
                || command_name.eq_ignore_ascii_case("ismaster")
            {
                debug!(
                    "MongoDB handshake ({}) from {}",
                    command_name, self.remote_addr
                );
                let response_bytes = self.encode_op_msg_response(
                    request_id,
                    hello_response(self.connection_id.as_u32()),
                )?;
                self.write_response(write_half, &response_bytes).await?;
                continue;
            }

            // Call LLM with command event
            let event_data = serde_json::json!({
                "command": command_name,
                "database": database,
                "collection": collection,
                "filter": self.bson_to_json(command_doc.get("filter")),
                "document": self.bson_to_json(command_doc.get("documents").or_else(|| command_doc.get("document"))),
                // `update` and `delete` carry their statements here — inline, or as the kind-1
                // document sequences drivers send them as, merged by `parse_op_msg_sections`.
                "updates": self.bson_to_json(command_doc.get("updates")),
                "deletes": self.bson_to_json(command_doc.get("deletes")),
            });

            let event = Event::new(&MONGODB_COMMAND_EVENT, event_data);

            let server_id = self
                .server_id
                .unwrap_or_else(|| crate::state::ServerId::new(0));
            let execution_result = match call_llm(
                &self.llm_client,
                &self.app_state,
                server_id,
                Some(self.connection_id),
                &event,
                self.protocol.as_ref(),
            )
            .await
            {
                Ok(result) => result,
                Err(e) => {
                    // `?` here dropped the connection with nothing written, and a
                    // MongoDB driver blocks on the reply to every command it sends, so
                    // the operation hung until the driver's own timeout and was then
                    // reported as a network fault rather than a server error.
                    //
                    // `{ok: 0}` is the only shape a driver reads as a command failure;
                    // anything with `ok: 1` is a result, and an empty result for `find`
                    // means "no documents matched" - a statement about the data.
                    //
                    // The two categories get distinct codes so a client can back off
                    // rather than record a permanent fault. The choice is constrained:
                    // MongoDB's *driver-retryable* codes all describe replica-set
                    // failover (ShutdownInProgress, PrimarySteppedDown,
                    // NotWritablePrimary), and claiming one would send the driver
                    // hunting for a new primary that does not exist. `TemporarilyUnavailable`
                    // (365) says exactly "saturated, try again" without implying a
                    // topology change, so it carries the overload case; everything else
                    // is InternalError (1).
                    let failure = crate::utils::WireFailure::classify(&e);
                    let code = match failure {
                        crate::utils::WireFailure::Overloaded => MONGODB_TEMPORARILY_UNAVAILABLE,
                        crate::utils::WireFailure::Unavailable => MONGODB_INTERNAL_ERROR,
                    };
                    error!(
                        "MongoDB command '{}' on connection {}: decision=fail_closed_llm_error \
                         category={:?} code={} error={}",
                        command_name, self.connection_id, failure, code, e
                    );
                    let message = failure.prefixed_text();
                    let _ = self.status_tx.send(format!(
                        "[ERROR] MongoDB connection {} decision=fail_closed_llm_error code={}: {}",
                        self.connection_id, code, message
                    ));
                    let doc = mongodb_error_doc(code, message);
                    let response_bytes = self.encode_op_msg_response(request_id, doc)?;
                    self.write_response(write_half, &response_bytes).await?;
                    continue;
                }
            };

            // Execute actions from LLM
            let namespace = format!("{}.{}", database, collection.as_deref().unwrap_or("$cmd"));
            let mut responded = false;
            let mut close_requested = false;

            for protocol_result in execution_result.protocol_results {
                match protocol_result {
                    ActionResult::Custom { name, data } => {
                        if name == "mongodb_response" {
                            // A model answer the encoder cannot use is a *third* case,
                            // distinct from the backend erroring and from the model
                            // saying nothing. It used to propagate with `?`, which drops
                            // the connection mid-command: the driver blocks on a reply
                            // that never comes and reports a network fault. Answer
                            // `{ok: 0}` and keep the connection, exactly as the LLM-error
                            // branch does.
                            let response_doc = match self.json_to_bson_doc(&data, &namespace) {
                                Ok(d) => {
                                    if data.get("type").and_then(|v| v.as_str())
                                        == Some("error_response")
                                    {
                                        debug!(
                                            "MongoDB command '{}' on connection {}: \
                                             decision=model_reject",
                                            command_name, self.connection_id
                                        );
                                    }
                                    d
                                }
                                Err(e) => {
                                    error!(
                                        "MongoDB command '{}' on connection {}: \
                                         decision=fail_closed_unusable_answer error={}",
                                        command_name, self.connection_id, e
                                    );
                                    let _ = self.status_tx.send(format!(
                                        "[ERROR] MongoDB connection {} \
                                         decision=fail_closed_unusable_answer for command '{}'",
                                        self.connection_id, command_name
                                    ));
                                    mongodb_error_doc(
                                        MONGODB_INTERNAL_ERROR,
                                        crate::utils::WireFailure::Unavailable.prefixed_text(),
                                    )
                                }
                            };
                            let response_bytes =
                                self.encode_op_msg_response(request_id, response_doc)?;
                            self.write_response(write_half, &response_bytes).await?;
                            responded = true;
                        } else {
                            warn!(
                                "MongoDB: no wire encoding for action result '{}', ignoring",
                                name
                            );
                        }
                    }
                    ActionResult::CloseConnection => {
                        debug!("Closing MongoDB connection");
                        close_requested = true;
                    }
                    ActionResult::NoAction => {}
                    _ => {
                        debug!("Unhandled action result");
                    }
                }
            }

            if !responded && !close_requested {
                // MongoDB is strictly request/response: a command with no reply hangs the
                // driver until its own timeout. Answer with an error instead.
                warn!(
                    "MongoDB command '{}' on connection {}: decision=fail_closed_no_answer",
                    command_name, self.connection_id
                );
                let _ = self.status_tx.send(format!(
                    "[WARN] MongoDB connection {} decision=fail_closed_no_answer for command '{}'",
                    self.connection_id, command_name
                ));
                let doc = mongodb_error_doc(
                    59,
                    &format!(
                        "netget: no response produced for command '{}'",
                        command_name
                    ),
                );
                let response_bytes = self.encode_op_msg_response(request_id, doc)?;
                self.write_response(write_half, &response_bytes).await?;
            }

            if close_requested {
                disconnect_reason = "close_this_connection";
                break;
            }
        }

        Ok(disconnect_reason)
    }

    /// Parse OP_MSG body (MongoDB 3.6+ wire protocol)
    fn parse_op_msg(&self, body: &[u8]) -> Result<ParsedOpMsg> {
        parse_op_msg_sections(body)
    }


    /// Encode OP_MSG response
    fn encode_op_msg_response(&self, request_id: i32, doc: Document) -> Result<Vec<u8>> {
        let mut body = vec![0u8; 5]; // flagBits (4) + section kind (1)
        body[4] = 0; // Section kind 0 (body)

        // Serialize BSON document
        let mut doc_bytes = Vec::new();
        doc.to_writer(&mut doc_bytes)?;
        body.extend_from_slice(&doc_bytes);

        // Create header
        let message_length = (16 + body.len()) as i32;
        let response_to = request_id;
        let op_code = 2013i32; // OP_MSG

        let mut message = Vec::new();
        message.extend_from_slice(&message_length.to_le_bytes());
        message.extend_from_slice(&0i32.to_le_bytes()); // responseID (0 = server)
        message.extend_from_slice(&response_to.to_le_bytes());
        message.extend_from_slice(&op_code.to_le_bytes());
        message.extend_from_slice(&body);

        Ok(message)
    }


    /// Convert BSON to JSON
    fn bson_to_json(&self, bson_opt: Option<&Bson>) -> serde_json::Value {
        match bson_opt {
            Some(bson) => bson.clone().into_relaxed_extjson(),
            None => serde_json::Value::Null,
        }
    }


    /// Convert JSON action to BSON document for response
    fn json_to_bson_doc(&self, json: &serde_json::Value, namespace: &str) -> Result<Document> {
        let action_type = json
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing action type")?;

        match action_type {
            "find_response" => {
                let documents = json
                    .get("documents")
                    .and_then(|v| v.as_array())
                    .context("Missing documents")?;

                let cursor_docs: Vec<Bson> = documents
                    .iter()
                    .filter_map(|d| d.clone().try_into().ok())
                    .collect();

                Ok(doc! {
                    "ok": 1,
                    "cursor": {
                        "id": 0i64,
                        // The namespace must name the collection the client actually queried;
                        // this used to be hardcoded to "test.collection".
                        "ns": namespace,
                        "firstBatch": cursor_docs
                    }
                })
            }
            "insert_response" => {
                let n = json
                    .get("inserted_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1) as i32;
                Ok(doc! { "ok": 1, "n": n })
            }
            "update_response" => {
                let matched = json
                    .get("matched_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as i32;
                let modified = json
                    .get("modified_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as i32;
                Ok(doc! { "ok": 1, "n": matched, "nModified": modified })
            }
            "delete_response" => {
                let n = json
                    .get("deleted_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as i32;
                Ok(doc! { "ok": 1, "n": n })
            }
            "error_response" => {
                let code = json.get("code").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                let message = json
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error");
                Ok(mongodb_error_doc(code, message))
            }
            other => Err(anyhow::anyhow!(
                "MongoDB: unknown response action type '{}'",
                other
            )),
        }
    }

}

/// MongoDB `InternalError`: "an internal server error occurred". Paired with `ok: 0`, which is
/// what makes a driver raise rather than return a result.
const MONGODB_INTERNAL_ERROR: i32 = 1;

/// MongoDB `TemporarilyUnavailable` (6.0+): the server is saturated and the same request may
/// succeed later. Used for [`crate::utils::WireFailure::Overloaded`] so a client backs off
/// instead of recording a permanent fault. Unlike the driver-retryable codes it does not
/// assert anything about replica-set topology.
const MONGODB_TEMPORARILY_UNAVAILABLE: i32 = 365;

/// MongoDB `Overflow`: the code its own BSON validator raises for a document nested past its
/// depth limit, which is exactly the refusal this server makes.
const MONGODB_OVERFLOW: i32 = 15;

/// The `errmsg` for a command document refused by [`scan_bson_document`] — MongoDB's own
/// wording for the same refusal, and a constant: nothing from the peer's bytes is echoed.
const BSON_TOO_DEEP_ERRMSG: &str = "BSONObj exceeded maximum nested object depth";

/// OP_MSG `flagBits` bit 0: a CRC-32C of the message follows the last section.
const OP_MSG_CHECKSUM_PRESENT: u32 = 1;

/// OP_MSG `flagBits` bits 0-15 are *required*: a receiver must refuse a message carrying one it
/// does not understand. Bit 0 is the only one defined, and it is handled.
const OP_MSG_UNKNOWN_REQUIRED_FLAGS: u32 = 0xFFFE;

/// Decode an OP_MSG body — `flagBits`, then sections — into one command document.
///
/// Two section kinds exist (MongoDB wire protocol, "OP_MSG"):
///
/// * **kind 0**, exactly one per message: the command's body document.
/// * **kind 1**, zero or more: a *document sequence* — `int32 size`, a C-string identifier, then
///   BSON documents filling the rest of `size`. Drivers use it for the arrays that can be large:
///   `insert`'s `documents`, `update`'s `updates`, `delete`'s `deletes`. The identifier names a
///   field of the command, and the sequence is that field's value.
///
/// So each sequence is merged into the body as the array field it names, and the command the
/// model sees is the same whether the driver sent its documents inline or as a sequence. A
/// sequence whose field the body also carries is refused, as the wire protocol requires.
///
/// Every document — the body and each sequence member — is walked by
/// [`scan_bson_document`] before `bson` sees it, exactly as the body alone always was. A
/// sequence member is scanned two levels shallower, because merging puts it inside an array
/// inside the command, and the merged document must still be within [`MAX_BSON_DEPTH`] for
/// everything downstream that walks it recursively. The number of documents is bounded by
/// `MAX_MESSAGE_SIZE`, which bounds the body this is handed.
///
/// A checksum, when present, is stripped and not verified: NetGet does not implement CRC-32C,
/// and drivers set the bit only when asked to.
fn parse_op_msg_sections(body: &[u8]) -> Result<ParsedOpMsg> {
    if body.len() < 5 {
        return Err(anyhow::anyhow!("OP_MSG body too short"));
    }
    let flag_bits = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    if flag_bits & OP_MSG_UNKNOWN_REQUIRED_FLAGS != 0 {
        return Err(anyhow::anyhow!(
            "OP_MSG sets required flag bits this server does not understand: {:#06x}",
            flag_bits & OP_MSG_UNKNOWN_REQUIRED_FLAGS
        ));
    }
    let mut sections = &body[4..];
    if flag_bits & OP_MSG_CHECKSUM_PRESENT != 0 {
        if sections.len() < 4 {
            return Err(anyhow::anyhow!(
                "OP_MSG declares a checksum it does not carry"
            ));
        }
        sections = &sections[..sections.len() - 4];
    }

    let mut command: Option<Document> = None;
    let mut sequences: Vec<(String, Vec<Bson>)> = Vec::new();

    while let Some((&kind, rest)) = sections.split_first() {
        match kind {
            0 => {
                if command.is_some() {
                    return Err(anyhow::anyhow!(
                        "OP_MSG carries more than one kind-0 section"
                    ));
                }
                // The document's shape is walked iteratively before `bson` sees it: `bson` 3.0
                // recurses once per nested document with no limit, and a stack overflow aborts
                // the whole process (`src/utils/bson_depth.rs`). Only a document the scan has
                // seen end, inside the bytes actually present, is decoded — and only those bytes
                // are handed over, so `bson` never reserves capacity on a declared length the
                // message does not back.
                match scan_bson_document(rest) {
                    BsonScan::Complete { consumed } => {
                        command = Some(Document::from_reader(&rest[..consumed])?);
                        sections = &rest[consumed..];
                    }
                    BsonScan::TooDeep { limit } => return Ok(ParsedOpMsg::TooDeep { limit }),
                    BsonScan::Malformed => {
                        return Err(anyhow::anyhow!("OP_MSG body is not a BSON document"))
                    }
                }
            }
            1 => {
                let size_bytes: [u8; 4] = rest
                    .get(..4)
                    .and_then(|b| b.try_into().ok())
                    .context("OP_MSG document sequence truncated before its size")?;
                let size = i32::from_le_bytes(size_bytes);
                // The size counts itself; a sequence also needs at least an empty identifier.
                if size < 5 || size as usize > rest.len() {
                    return Err(anyhow::anyhow!(
                        "OP_MSG document sequence declares {} bytes with {} present",
                        size,
                        rest.len()
                    ));
                }
                let sequence = &rest[4..size as usize];
                let nul = sequence
                    .iter()
                    .position(|&b| b == 0)
                    .context("OP_MSG document sequence identifier is not terminated")?;
                let identifier = std::str::from_utf8(&sequence[..nul])
                    .context("OP_MSG document sequence identifier is not UTF-8")?
                    .to_string();
                let mut documents = Vec::new();
                let mut remaining = &sequence[nul + 1..];
                while !remaining.is_empty() {
                    match scan_bson_document_with_limit(remaining, MAX_BSON_DEPTH - 2) {
                        BsonScan::Complete { consumed } => {
                            documents.push(Bson::Document(Document::from_reader(
                                &remaining[..consumed],
                            )?));
                            remaining = &remaining[consumed..];
                        }
                        BsonScan::TooDeep { .. } => {
                            return Ok(ParsedOpMsg::TooDeep {
                                limit: MAX_BSON_DEPTH,
                            })
                        }
                        BsonScan::Malformed => {
                            return Err(anyhow::anyhow!(
                                "OP_MSG document sequence '{}' holds something that is not a \
                                 BSON document",
                                identifier
                            ))
                        }
                    }
                }
                sequences.push((identifier, documents));
                sections = &rest[size as usize..];
            }
            other => {
                return Err(anyhow::anyhow!(
                    "Unsupported OP_MSG section kind: {}",
                    other
                ));
            }
        }
    }

    let mut command = command.context("OP_MSG has no kind-0 body section")?;
    for (identifier, documents) in sequences {
        if command.contains_key(&identifier) {
            return Err(anyhow::anyhow!(
                "OP_MSG supplies '{}' both in its body and as a document sequence",
                identifier
            ));
        }
        command.insert(identifier, Bson::Array(documents));
    }
    Ok(ParsedOpMsg::Command(command))
}

/// What an OP_MSG held.
enum ParsedOpMsg {
    /// A decoded command document.
    Command(Document),
    /// Nested past [`crate::utils::bson_depth::MAX_BSON_DEPTH`]; never decoded.
    TooDeep { limit: usize },
}

/// Build a MongoDB command-failure document.
fn mongodb_error_doc(code: i32, message: &str) -> Document {
    doc! { "ok": 0, "code": code, "errmsg": message }
}

/// The reply to `hello` / `isMaster`.
///
/// A MongoDB driver refuses to use a server that does not advertise a wire-version range it
/// supports, so these fields cannot be left to the model. Wire version 17 is MongoDB 6.0.
fn hello_response(connection_id: u32) -> Document {
    doc! {
        "ok": 1,
        "isWritablePrimary": true,
        "ismaster": true,
        "helloOk": true,
        "readOnly": false,
        "minWireVersion": 0i32,
        "maxWireVersion": 17i32,
        "maxBsonObjectSize": 16 * 1024 * 1024i32,
        "maxMessageSizeBytes": MAX_MESSAGE_SIZE,
        "maxWriteBatchSize": 100_000i32,
        "logicalSessionTimeoutMinutes": 30i32,
        "connectionId": connection_id as i32,
        "localTime": bson::DateTime::now(),
    }
}

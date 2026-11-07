//! MySQL server implementation using opensrv-mysql
//!
//! **Inbound packets are bounded before they are buffered.** `opensrv-mysql` has no
//! maximum-packet check of any kind, and it is the crate that answers
//! `SELECT @@max_allowed_packet` with 67108864 — so until now this server published a ceiling
//! and enforced nothing, on an unauthenticated connection, before any model call.
//! `packet_limit` puts that number where the bytes are: see [`packet_limit::MAX_PACKET_BYTES`].
pub mod actions;
pub mod caching_sha2;
pub mod command_tap;
pub mod packet_limit;
pub mod stmt_params;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use actions::{MysqlProtocol, MYSQL_QUERY_EVENT};
use anyhow::Result;
use async_trait::async_trait;
use opensrv_mysql::{
    AsyncMysqlIntermediary, AsyncMysqlShim, Column, ColumnFlags, ColumnType, ErrorKind, InitWriter,
    OkResponse, ParamParser, QueryResultWriter, RowWriter, StatementMetaWriter, StatusFlags,
};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, trace, warn};

/// How long to wait for the client's handshake response after the greeting goes out.
///
/// MySQL is server-speaks-first: `opensrv-mysql` writes the initial handshake packet, and a
/// real client answers it at once — it has the credentials in hand already and asks nobody.
/// This is therefore a bound on "connected, took the greeting, said nothing", which is exactly
/// what an unauthenticated flood looks like.
const HANDSHAKE_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to wait for a *further* command once the session is up.
///
/// Real MySQL's `wait_timeout` defaults to **eight hours**, which is a bound in name only, so
/// copying it is not an option here the way copying Kafka's `connections.max.idle.ms` was. Ten
/// minutes instead, and the reason it is safe is what this server *is*: it holds no session
/// state a reconnect would lose — no tables, no temporary tables, no open transaction, nothing
/// the model remembers between statements (see the no-storage rule in the project CLAUDE.md).
/// A pooled connection reaped here costs `mysql_async` or a JDBC pool one transparent reconnect,
/// and ten minutes is far above any pool's keepalive interval.
const IDLE_BETWEEN_COMMANDS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Concurrent connections this server admits.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// How many further octets are read and **discarded** after a packet is refused, so the peer
/// can finish writing and then read the ERR packet.
///
/// A peer refused at [`packet_limit::MAX_PACKET_BYTES`] is by definition still writing: it is
/// part-way through a packet it declared as larger than we will take. Closing the socket while
/// data is still in the receive queue sends `RST`, and `RST` discards the response bytes
/// already written along with it — so the peer's `write` fails with `ECONNRESET` and the
/// carefully-numbered ERR packet, the one thing that tells it *why*, is never delivered.
///
/// This is nginx's `lingering_close`, and it is bounded for the same reason: draining is
/// politeness, not an obligation. Nothing is buffered — the octets are counted and dropped.
const LINGER_DRAIN_BYTES: usize = 8 * 1024 * 1024;

/// Wall-clock bound on that drain, so a peer trickling one octet at a time cannot hold the
/// connection open by staying under [`LINGER_DRAIN_BYTES`].
const LINGER_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// An ERR packet carrying error **1040, `ER_CON_COUNT_ERROR`, SQLSTATE `08004`** — which is
/// precisely what a real MySQL server sends, in precisely this position, when `max_connections`
/// is reached: in place of the initial handshake, as packet sequence 0. Every client in the
/// ecosystem already recognises it, so `mysql_async` surfaces "Too many connections" and the
/// `mysql` CLI prints `ERROR 1040 (08004)` rather than reporting a broken pipe.
///
/// Laid out by hand because it is a wire packet: a 3-byte little-endian payload length (29) and
/// a sequence byte (0), then `0xFF` marking an ERR packet, the error number 1040 little-endian,
/// the `#` SQL-state marker, the five-character state, and the message.
const CONNECTION_CAP_REFUSAL: &[u8] = b"\x1d\x00\x00\x00\xff\x10\x04#08004Too many connections";

/// Cap on prepared statements retained per connection.
///
/// The map is keyed by statement id and only pruned by an explicit COM_STMT_CLOSE, so a client
/// that PREPAREs in a loop and never closes would grow it without bound.
const MAX_PREPARED_STATEMENTS: usize = 4096;

/// Most `?` placeholders one prepared statement may declare.
///
/// Real MySQL's own limit is 65535. This is far lower because the descriptors are held in a
/// process-wide table (`PLACEHOLDER_COLUMNS`) and no statement a model or an ORM produces
/// comes anywhere near it; anything past it gets `ER_PS_MANY_PARAM` rather than a silently
/// wrong parameter count.
const MAX_PLACEHOLDERS: usize = 1024;

/// Parameter descriptors handed to `StatementMetaWriter::reply`.
///
/// They have to outlive the writer's borrow, so they cannot be built per statement; the
/// contents are identical for every statement anyway — real MySQL names each parameter `?`
/// and types it as a string. Clients bind their own types at EXECUTE, which is what
/// `stmt_params` decodes, so neither field is read back.
static PLACEHOLDER_COLUMNS: std::sync::LazyLock<Vec<Column>> = std::sync::LazyLock::new(|| {
    (0..MAX_PLACEHOLDERS)
        .map(|_| Column {
            table: String::new(),
            column: "?".to_string(),
            coltype: ColumnType::MYSQL_TYPE_VAR_STRING,
            colflags: ColumnFlags::empty(),
        })
        .collect()
});

/// MySQL server implementation
pub struct MysqlServer {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    _status_tx: mpsc::UnboundedSender<String>,
    server_id: Option<crate::state::ServerId>,
}

impl MysqlServer {
    /// Create a new MySQL server
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

    /// Spawn MySQL server with LLM integration
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        _send_first: bool,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        let listener = TcpListener::bind(listen_addr).await?;
        let actual_addr = listener.local_addr()?;

        Log::new(Some(&status_tx)).info(format!("MySQL server listening on {}", actual_addr));

        let server = Arc::new(MysqlServer::new(
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
                    "MySQL",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, addr, permit)) => {
                        Log::new(Some(&status_tx)).info(format!("MySQL connection from {}", addr));

                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(actual_addr);

                        let handler = MysqlHandler::new(
                            connection_id,
                            server.llm_client.clone(),
                            server.app_state.clone(),
                            status_tx.clone(),
                            server.server_id,
                            addr,
                        );

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

                        let conn_state_owner = server.app_state.clone();
                        let conn_server_id = server.server_id;
                        let status_tx_conn = status_tx.clone();
                        let conn_handle = tokio::spawn(async move {
                            // Held for the life of the session, so the cap counts live
                            // connections rather than accepts.
                            let _permit = permit;
                            // MySQL requires split read/write streams
                            let (reader, mut writer) = tokio::io::split(stream);
                            // `AsyncMysqlIntermediary::run_on` owns the protocol loop, so there
                            // is no `read()` of ours to wrap in a deadline — but it takes a
                            // *generic* reader, which is the seam. `IdleTimeoutReader` arms its
                            // clock only while a read is actually outstanding, so the LLM
                            // round-trip that answers a query, and a `manual` rule parking that
                            // query for a human (`src/state/intercepts.rs`, 300s by default),
                            // run with no deadline over them at all: the reader is not being
                            // polled while `MysqlHandler` is working.
                            let reader =
                                crate::server::accept_bounded::IdleTimeoutReader::with_first(
                                    reader,
                                    HANDSHAKE_RESPONSE_TIMEOUT,
                                    IDLE_BETWEEN_COMMANDS_TIMEOUT,
                                );
                            // The packet bound sits *under* opensrv-mysql, for the same reason
                            // the idle bound does: the crate owns the protocol loop, but it
                            // takes a generic reader, and a reader is where a length field can
                            // be refused before the payload behind it is read. See
                            // `packet_limit`.
                            let trip = Arc::new(packet_limit::PacketLimitTrip::default());
                            let reader = packet_limit::PacketLimitReader::new(reader, trip.clone());
                            // Above the limiter, so a refused packet never reaches it: a copy
                            // of each prepared-statement command, for `on_execute` to decode
                            // with a parser that cannot panic. See `command_tap`.
                            // Beneath the tap: long-data chunks past the bounds are withheld
                            // from the crate, which would otherwise store them without limit.
                            let reader =
                                command_tap::LongDataGate::new(reader, handler.command_tap());
                            let mut reader =
                                command_tap::CommandTapReader::new(reader, handler.command_tap());
                            // `run_on` takes the writer **by value**, and its `W` is only
                            // `AsyncWrite + Send + Unpin` — which `&mut WriteHalf` satisfies.
                            // That is the seam: lending the write half rather than giving it
                            // away leaves this task able to answer once the crate's loop has
                            // given up, which is the only moment at which a refusal decided
                            // beneath the crate can be expressed in the crate's protocol.
                            //
                            // The same seam carries the one packet a `caching_sha2_password`
                            // client waits for between its scramble and the OK packet: the
                            // crate writes that OK itself and its `authenticate` hook cannot
                            // write, so the packet is injected beneath it. See
                            // `caching_sha2`. The borrow ends with the block, leaving this
                            // task the write half for the refusal path below.
                            let outcome = {
                                let mut writer = caching_sha2::FastAuthWriter::new(
                                    &mut writer,
                                    handler.fast_auth_gate(),
                                );
                                AsyncMysqlIntermediary::run_on(handler, &mut reader, &mut writer)
                                    .await
                            };
                            if trip.tripped() {
                                Self::refuse_oversized_packet(
                                    connection_id,
                                    addr,
                                    &trip,
                                    reader.into_inner().into_inner().into_inner(),
                                    &mut writer,
                                    &status_tx_conn,
                                )
                                .await;
                            } else if let Err(e) = outcome {
                                error!("MySQL connection error: {:?}", e);
                            }
                            // Mark the connection closed so it does not stay Active forever
                            // in the server's connection map.
                            if let Some(server_id) = conn_server_id {
                                conn_state_owner
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                            }
                        });

                        // Register the per-connection task too, not just the accept loop:
                        // aborting the accept loop releases the port but leaves every
                        // in-flight session running, so `stop_server` did not actually stop
                        // the server. `register_server_task` prunes finished handles on each
                        // call, so this cannot grow without bound.
                        if let Some(server_id) = conn_server_id {
                            app_state.register_server_task(server_id, conn_handle).await;
                        }
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx)).error(format!("MySQL accept error: {}", e));
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

    /// Tell a peer, in MySQL's own vocabulary, that the packet it declared is too large.
    ///
    /// Order matters and is nginx's, not the obvious one. The ERR packet is written **first**,
    /// so it is on the wire while the peer is still writing and can be read the moment the
    /// peer looks; then the receive queue is drained, boundedly, so that the close which
    /// follows is a `FIN` and not an `RST`. A close with unread data queued discards
    /// everything already written to the socket, which would make the error number, the
    /// SQLSTATE and the sequence arithmetic above all equally invisible.
    async fn refuse_oversized_packet<R, W>(
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        trip: &packet_limit::PacketLimitTrip,
        mut reader: R,
        writer: &mut W,
        status_tx: &mpsc::UnboundedSender<String>,
    ) where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let declared = trip.declared_bytes();

        match trip.refusal() {
            packet_limit::Refusal::TooLarge => Log::new(Some(status_tx)).warn(format!(
                "MySQL connection {connection_id} decision=fail_closed_packet_too_large: \
                 {remote_addr} declared a {declared}-byte packet, limit is {} bytes; answering \
                 1153 ER_NET_PACKET_TOO_LARGE",
                packet_limit::MAX_PACKET_BYTES
            )),
            packet_limit::Refusal::OutOfOrder => Log::new(Some(status_tx)).warn(format!(
                "MySQL connection {connection_id} decision=fail_closed_packets_out_of_order: \
                 {remote_addr} sent a packet with sequence id {} that opensrv-mysql would panic \
                 on; answering 1156 ER_NET_PACKETS_OUT_OF_ORDER",
                trip.reply_sequence().wrapping_sub(1)
            )),
        }

        let err = trip.refusal_packet();
        if let Err(e) = writer.write_all(&err).await {
            debug!("MySQL {connection_id}: could not write the refusal: {e}");
            return;
        }
        if let Err(e) = writer.flush().await {
            debug!("MySQL {connection_id}: could not flush the refusal: {e}");
        }

        let mut drained = 0usize;
        let mut scratch = vec![0u8; 64 * 1024];
        let _ = tokio::time::timeout(LINGER_DRAIN_TIMEOUT, async {
            while drained < LINGER_DRAIN_BYTES {
                match reader.read(&mut scratch).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => drained = drained.saturating_add(n),
                }
            }
        })
        .await;

        trace!("MySQL {connection_id}: drained {drained} bytes after refusing the packet");
        if let Err(e) = writer.shutdown().await {
            debug!("MySQL {connection_id}: shutdown after refusal returned: {e}");
        }
    }
}

/// MySQL connection handler
pub struct MysqlHandler {
    connection_id: ConnectionId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    #[allow(dead_code)]
    server_id: Option<crate::state::ServerId>,
    #[allow(dead_code)]
    remote_addr: SocketAddr,
    /// MySQL protocol handler for action execution
    protocol: Arc<MysqlProtocol>,
    /// Prepared statements
    prepared_statements: Arc<Mutex<std::collections::HashMap<u32, PreparedStatement>>>,
    /// Next statement ID
    next_stmt_id: Arc<Mutex<u32>>,
    /// How `authenticate` asks the writer beneath `opensrv-mysql` for the one packet a
    /// `caching_sha2_password` client waits for. See [`caching_sha2`].
    fast_auth: Arc<caching_sha2::FastAuthGate>,
    /// Copies of the prepared-statement commands, taken beneath `opensrv-mysql`. See
    /// [`command_tap`].
    command_tap: Arc<command_tap::CommandTap>,
}

/// What this server keeps for one prepared statement: the text the model is shown, and what
/// the wire protocol needs to decode its executes.
#[derive(Debug, Clone)]
struct PreparedStatement {
    sql: String,
    /// Byte offsets of each `?` placeholder in `sql`; their count is what PREPARE told the
    /// client, and so how it frames every EXECUTE.
    placeholders: Vec<usize>,
    /// The parameter types the last execute bound, for an execute that does not rebind them.
    bound_types: Option<Vec<stmt_params::ParamType>>,
    /// `COM_STMT_SEND_LONG_DATA` received since the last execute, by parameter index.
    long_data: std::collections::HashMap<u16, stmt_params::LongData>,
    /// Long data named a parameter the statement does not have. `mysqld` reports that at the
    /// next execute rather than when the long data arrives (that command has no reply), and so
    /// does this.
    long_data_out_of_range: bool,
    /// A long-data chunk for this statement was withheld by `command_tap::LongDataGate`.
    long_data_too_large: bool,
}

impl MysqlHandler {
    pub fn new(
        connection_id: ConnectionId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: Option<crate::state::ServerId>,
        remote_addr: SocketAddr,
    ) -> Self {
        let protocol = Arc::new(MysqlProtocol::new(
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
            prepared_statements: Arc::new(Mutex::new(std::collections::HashMap::new())),
            next_stmt_id: Arc::new(Mutex::new(1)),
            fast_auth: Arc::new(caching_sha2::FastAuthGate::default()),
            command_tap: Arc::new(command_tap::CommandTap::default()),
        }
    }

    /// The queue the reader beneath `opensrv-mysql` fills for `on_execute`.
    pub fn command_tap(&self) -> Arc<command_tap::CommandTap> {
        self.command_tap.clone()
    }

    /// The gate this handler will arm from `authenticate`, for the writer that answers it.
    pub fn fast_auth_gate(&self) -> Arc<caching_sha2::FastAuthGate> {
        self.fast_auth.clone()
    }
}

#[async_trait]
impl<W: tokio::io::AsyncWrite + Send + Unpin> AsyncMysqlShim<W> for MysqlHandler {
    type Error = io::Error;

    /// The plugin named in the greeting.
    ///
    /// `opensrv-mysql`'s default is `mysql_native_password`, whose *client* plugin MySQL 9.0
    /// deleted — so the shipping CLI cannot load it and never reaches the query phase. See
    /// [`caching_sha2`], and note what it does not mean: nothing here checks a password.
    fn default_auth_plugin(&self) -> &str {
        caching_sha2::CACHING_SHA2_PASSWORD
    }

    /// Never ask a client to switch plugins.
    ///
    /// An empty expectation is `opensrv-mysql`'s "no auth-switch": whatever the client chose
    /// is what this connection uses. That is the honest answer for a server that verifies
    /// nothing, and it is what keeps an older `mysql_native_password` client working — it
    /// answers the greeting with its own plugin and is accepted as it always was, rather than
    /// being sent an `AuthSwitchRequest` for a plugin it may not have.
    async fn auth_plugin_for_username(&self, _user: &[u8]) -> &str {
        ""
    }

    /// Admit the connection. **Nothing is verified** — there is no password here to verify
    /// against, and the model is not consulted.
    ///
    /// The only decision taken is which shape the *end* of the connection phase has: a client
    /// that sent a 32-byte `caching_sha2_password` scramble is blocked reading for
    /// `AuthMoreData`, and gets it; every other client is answered with the OK packet alone.
    async fn authenticate(
        &self,
        _auth_plugin: &str,
        _username: &[u8],
        _salt: &[u8],
        auth_data: &[u8],
    ) -> bool {
        if caching_sha2::awaits_fast_auth_success(auth_data) {
            self.fast_auth.arm();
        }
        true
    }

    async fn on_prepare<'a>(
        &'a mut self,
        query: &'a str,
        info: StatementMetaWriter<'a, W>,
    ) -> io::Result<()> {
        Log::new(Some(&self.status_tx)).debug(format!("MySQL PREPARE: {}", query));
        self.record_stats(Some(query.len() as u64), None, Some(1), None)
            .await;

        // Store the prepared statement
        let mut next_id = self.next_stmt_id.lock().await;
        let stmt_id = *next_id;
        *next_id = next_id.wrapping_add(1);
        drop(next_id);

        let mut stmts = self.prepared_statements.lock().await;
        if stmts.len() >= MAX_PREPARED_STATEMENTS {
            drop(stmts);
            warn!(
                "MySQL connection {} exceeded {} prepared statements",
                self.connection_id, MAX_PREPARED_STATEMENTS
            );
            return info
                .error(
                    ErrorKind::ER_MAX_PREPARED_STMT_COUNT_REACHED,
                    b"Can't create more than max_prepared_stmt_count statements",
                )
                .await;
        }
        // Reply with the statement ID and the number of `?` placeholders the statement has.
        //
        // The count is not cosmetic: the client stores it and uses it to frame
        // COM_STMT_EXECUTE, and `stmt_params` decodes that packet by the same count.
        let offsets = placeholder_offsets(query);
        let placeholders = offsets.len();
        stmts.insert(
            stmt_id,
            PreparedStatement {
                sql: query.to_string(),
                placeholders: offsets,
                bound_types: None,
                long_data: std::collections::HashMap::new(),
                long_data_out_of_range: false,
                long_data_too_large: false,
            },
        );
        drop(stmts);

        if placeholders > MAX_PLACEHOLDERS {
            warn!(
                "MySQL connection {}: statement declares {} placeholders, more than the {} \
                 supported",
                self.connection_id, placeholders, MAX_PLACEHOLDERS
            );
            let mut stmts = self.prepared_statements.lock().await;
            stmts.remove(&stmt_id);
            drop(stmts);
            return info
                .error(
                    ErrorKind::ER_PS_MANY_PARAM,
                    b"Prepared statement contains too many placeholders",
                )
                .await;
        }

        self.record_stats(None, Some(0), None, Some(1)).await;
        info.reply(stmt_id, &PLACEHOLDER_COLUMNS[..placeholders], &[])
            .await
    }

    /// Execute a prepared statement, with its parameter values decoded by `stmt_params`.
    ///
    /// `ParamParser` is never iterated: `opensrv-mysql`'s iterator panics on malformed input
    /// (`stmt_params` lists the lines). The packet it would have read was copied beneath the
    /// crate by `command_tap`, and is decoded here by a parser that refuses instead.
    async fn on_execute<'a>(
        &'a mut self,
        stmt_id: u32,
        _params: ParamParser<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        Log::new(Some(&self.status_tx)).debug(format!("MySQL EXECUTE statement {}", stmt_id));

        let capture = self.command_tap.take_execute(stmt_id);

        // Apply the long data and resets that preceded this execute, then take a snapshot of
        // the statement and clear its long data — `mysqld` and the crate both discard long
        // data once an execute has used it.
        let stmt = {
            let mut stmts = self.prepared_statements.lock().await;
            for item in &capture.preceding {
                match item {
                    command_tap::Captured::LongData {
                        stmt_id: id,
                        param,
                        prefix,
                        len,
                    } => {
                        if let Some(s) = stmts.get_mut(id) {
                            if usize::from(*param) >= s.placeholders.len() {
                                s.long_data_out_of_range = true;
                            } else {
                                s.long_data.entry(*param).or_default().append(prefix, *len);
                            }
                        }
                    }
                    // A reset discards the statement's long data in the crate and in the gate,
                    // so a refusal for chunks sent before it no longer applies (see
                    // `LongDataGate`).
                    command_tap::Captured::Reset { stmt_id: id } => {
                        if let Some(s) = stmts.get_mut(id) {
                            s.long_data.clear();
                            s.long_data_out_of_range = false;
                            s.long_data_too_large = false;
                        }
                    }
                    command_tap::Captured::LongDataRefused { stmt_id: id } => {
                        if let Some(s) = stmts.get_mut(id) {
                            s.long_data_too_large = true;
                        }
                    }
                    command_tap::Captured::Execute(_) => {}
                }
            }
            stmts.get_mut(&stmt_id).map(|s| {
                let snapshot = s.clone();
                s.long_data.clear();
                s.long_data_out_of_range = false;
                s.long_data_too_large = false;
                snapshot
            })
        };

        if let Some(stmt) = stmt {
            if capture.discarded > 0 {
                error!(
                    "MySQL connection {}: {} captured EXECUTE packet(s) ahead of statement {} \
                     named another statement; discarded",
                    self.connection_id, capture.discarded, stmt_id
                );
            }
            if stmt.long_data_too_large {
                // mysqld's own code and text for this refusal, reported where it reports it.
                warn!(
                    "MySQL connection {} decision=fail_closed_long_data_too_large: long data for \
                     statement {} passed the per-statement ({} bytes) or per-connection ({} \
                     bytes) bound; the chunks past it were not stored",
                    self.connection_id,
                    stmt_id,
                    command_tap::LONG_DATA_PER_STATEMENT,
                    command_tap::LONG_DATA_PER_CONNECTION
                );
                return results
                    .error(
                        ErrorKind::ER_UNKNOWN_ERROR,
                        b"Parameter of prepared statement which is set through \
                          mysql_send_long_data() is longer than 'max_allowed_packet' bytes",
                    )
                    .await;
            }
            if stmt.long_data_out_of_range {
                warn!(
                    "MySQL connection {} decision=fail_closed_long_data_index: long data for \
                     statement {} named a parameter it does not have",
                    self.connection_id, stmt_id
                );
                return results
                    .error(
                        ErrorKind::ER_WRONG_ARGUMENTS,
                        b"Incorrect arguments to mysqld_stmt_send_long_data",
                    )
                    .await;
            }
            let Some(payload) = capture.payload else {
                // The crate parsed an execute the tap did not capture. Nothing a client does
                // reaches this except overflowing the tap's queue; refuse rather than run the
                // statement without its values.
                error!(
                    "MySQL connection {} decision=fail_closed_no_capture: no captured packet \
                     for EXECUTE of statement {} (queue overflowed: {})",
                    self.connection_id, stmt_id, capture.overflowed
                );
                let message = crate::utils::WireFailure::Unavailable.prefixed_text();
                return results
                    .error(ErrorKind::ER_UNKNOWN_ERROR, message.as_bytes())
                    .await;
            };

            let decoded = stmt_params::parse_execute(
                &payload,
                stmt.placeholders.len(),
                stmt.bound_types.as_deref(),
                &stmt.long_data,
            );
            match decoded {
                Ok(req) => {
                    if let Some(types) = &req.new_types {
                        let mut stmts = self.prepared_statements.lock().await;
                        if let Some(s) = stmts.get_mut(&stmt_id) {
                            s.bound_types = Some(types.clone());
                        }
                    }
                    let bound = BoundParams {
                        params: stmt_params::params_json(&req),
                        rendered: stmt_params::render_query(&stmt.sql, &stmt.placeholders, &req),
                    };
                    self.handle_statement(&stmt.sql, Some(bound), results).await
                }
                Err(e) => {
                    // The peer gets MySQL's own code and text for a packet it framed wrongly;
                    // what was wrong with it goes to the log.
                    Log::new(Some(&self.status_tx)).warn(format!(
                        "MySQL connection {} decision=fail_closed_malformed_execute: statement \
                         {}: {}",
                        self.connection_id, stmt_id, e
                    ));
                    results
                        .error(
                            ErrorKind::ER_MALFORMED_PACKET,
                            b"Malformed communication packet.",
                        )
                        .await
                }
            }
        } else {
            // The handle is unknown or already closed. Answering OK told the driver its
            // EXECUTE succeeded and affected zero rows, so a client reusing a stale handle —
            // after a reconnect, or a double-close — saw a successful write that never ran.
            // MySQL has a code for exactly this and drivers act on it.
            warn!(
                "MySQL EXECUTE for unknown or expired statement id {} (decision=unknown_handle)",
                stmt_id
            );
            results
                .error(
                    ErrorKind::ER_UNKNOWN_STMT_HANDLER,
                    format!(
                        "Unknown prepared statement handler ({}) given to EXECUTE",
                        stmt_id
                    )
                    .as_bytes(),
                )
                .await
        }
    }

    async fn on_close(&mut self, stmt_id: u32) {
        Log::new(Some(&self.status_tx)).debug(format!("MySQL CLOSE statement {}", stmt_id));

        let mut stmts = self.prepared_statements.lock().await;
        stmts.remove(&stmt_id);
    }

    async fn on_query<'a>(
        &'a mut self,
        query: &'a str,
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        // FileOnly: the mysql_query event's log_template already reports the query to the
        // TUI at INFO when call_llm dispatches it (see actions.rs).
        Log::new(Some(&self.status_tx)).debug(format!("MySQL QUERY: {}", query));

        self.handle_statement(query, None, results).await
    }

    async fn on_init<'a>(
        &'a mut self,
        _database: &'a str,
        writer: InitWriter<'a, W>,
    ) -> io::Result<()> {
        Log::new(Some(&self.status_tx)).debug(format!("MySQL INIT DB: {}", _database));
        self.record_stats(Some(_database.len() as u64), None, Some(1), Some(1))
            .await;

        writer.ok().await
    }
}

impl MysqlHandler {
    /// Refresh the dashboard's per-connection counters and `last_activity`.
    ///
    /// opensrv-mysql owns the socket inside `run_on` and never exposes the raw byte streams, so
    /// these are the **application-visible** payload sizes seen at the shim boundary (the SQL text
    /// received, the response cells/message produced), not the exact wire bytes — opensrv adds a
    /// 4-byte packet header and text-protocol framing on top. Good enough for the rail's `↓/↑`
    /// counters and, more importantly, for keeping `last_activity` current.
    async fn record_stats(
        &self,
        bytes_in: Option<u64>,
        bytes_out: Option<u64>,
        packets_in: Option<u64>,
        packets_out: Option<u64>,
    ) {
        if let Some(server_id) = self.server_id {
            self.app_state
                .update_connection_stats(
                    server_id,
                    self.connection_id,
                    bytes_in,
                    bytes_out,
                    packets_in,
                    packets_out,
                )
                .await;
        }
    }

    /// Ask the model to answer one statement: a `COM_QUERY`, or a `COM_STMT_EXECUTE` with the
    /// parameter values it bound.
    async fn handle_statement<'a, W: tokio::io::AsyncWrite + Send + Unpin>(
        &'a mut self,
        query: &str,
        bound: Option<BoundParams>,
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        trace!("Calling LLM for MySQL query: {}", query);

        // The SQL text is the visible inbound payload for this command (COM_QUERY, or the replayed
        // statement text for COM_STMT_EXECUTE).
        self.record_stats(Some(query.len() as u64), None, Some(1), None)
            .await;

        // Create query event
        let mut event_data = serde_json::json!({ "query": query });
        if let Some(hint) = actions::answer_with_for_query(query) {
            event_data["answer_with"] = serde_json::json!(hint);
        }
        if let Some(bound) = bound {
            event_data["params"] = bound.params;
            event_data["query_rendered"] = serde_json::json!(bound.rendered);
        }
        let event = Event::new(&MYSQL_QUERY_EVENT, event_data);

        let server_id = self
            .server_id
            .unwrap_or_else(|| crate::state::ServerId::new(0));

        let llm_result = call_llm(
            &self.llm_client,
            &self.app_state,
            server_id,
            Some(self.connection_id),
            &event,
            self.protocol.as_ref(),
        )
        .await;

        match llm_result {
            Ok(execution_result) => {
                // `close_this_connection` is a declared sync action, so it has to actually end
                // the session. opensrv drives the loop for us, so the only way to stop it is to
                // answer the current query and then return an error from the shim.
                let close_requested = execution_result
                    .protocol_results
                    .iter()
                    .any(|r| matches!(r, ActionResult::CloseConnection));

                // One query, one answer: the first response action is sent and any further one
                // is dropped, and said so. The eval saw one SELECT answered with five alternating
                // OK packets and notes; a second result for the same query has nowhere to go on
                // the wire, and dropping it silently would make the log read as though the
                // model's last answer were the one the client got.
                let responses = execution_result
                    .protocol_results
                    .iter()
                    .filter(|r| {
                        matches!(r, ActionResult::Custom { name, .. }
                            if matches!(name.as_str(), "mysql_query_response" | "mysql_error" | "mysql_ok"))
                    })
                    .count();
                if responses > 1 {
                    warn!(
                        "MySQL connection {} decision=duplicate_response_dropped: {} response \
                         actions for one query; sending the first",
                        self.connection_id, responses
                    );
                }

                // Process action results to find MySQL responses
                for result in execution_result.protocol_results {
                    match result {
                        ActionResult::Custom { name, data } => {
                            match name.as_str() {
                                "mysql_query_response" => {
                                    // Extract columns and rows from JSON data
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

                                    // Estimate the outbound payload from the cell text before the
                                    // writers consume `columns`/`rows`.
                                    let sent_bytes: u64 = columns
                                        .iter()
                                        .filter_map(|c| c.get("name"))
                                        .filter_map(|v| v.as_str())
                                        .map(|s| s.len() as u64)
                                        .sum::<u64>()
                                        + rows
                                            .iter()
                                            .filter_map(|r| r.as_array())
                                            .flatten()
                                            .map(|v| json_to_mysql_string(v).len() as u64)
                                            .sum::<u64>();
                                    self.record_stats(None, Some(sent_bytes), None, Some(1))
                                        .await;

                                    // Send result set
                                    return finish_query(
                                        send_result_set(results, columns, rows).await,
                                        close_requested,
                                    );
                                }
                                "mysql_error" => {
                                    // Extract error info from JSON data
                                    let error_code = data
                                        .get("error_code")
                                        .and_then(|v| v.as_u64())
                                        .and_then(|c| u16::try_from(c).ok())
                                        .unwrap_or(1064);
                                    let message = data
                                        .get("message")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("Unknown error");

                                    // Send a real MySQL ERR packet. `QueryResultWriter::error`
                                    // has existed since opensrv-mysql 0.4; the previous code
                                    // (and the protocol docs) claimed the library could only
                                    // send OK, which silently swallowed every LLM error.
                                    //
                                    // Non-fatal: this is the model's own deliberate
                                    // mysql_error_response, answered on the wire and the
                                    // connection continues.
                                    Log::new(Some(&self.status_tx))
                                        .warn(format!("MySQL error {}: {}", error_code, message));
                                    self.record_stats(
                                        None,
                                        Some(message.len() as u64),
                                        None,
                                        Some(1),
                                    )
                                    .await;
                                    return finish_query(
                                        results
                                            .error(mysql_error_kind(error_code), message.as_bytes())
                                            .await,
                                        close_requested,
                                    );
                                }
                                "mysql_ok" => {
                                    // Extract OK response info from JSON data
                                    let affected_rows = data
                                        .get("affected_rows")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0);
                                    let last_insert_id = data
                                        .get("last_insert_id")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0);

                                    // Send OK response (a small fixed-size packet).
                                    self.record_stats(None, Some(0), None, Some(1)).await;
                                    return finish_query(
                                        results
                                            .completed(OkResponse {
                                                header: 0,
                                                affected_rows,
                                                last_insert_id,
                                                status_flags: StatusFlags::empty(),
                                                warnings: 0,
                                                info: String::new(),
                                                session_state_info: String::new(),
                                            })
                                            .await,
                                        close_requested,
                                    );
                                }
                                _ => {
                                    // Unknown custom response, ignore
                                }
                            }
                        }
                        _ => {
                            // Other action results are informational, continue processing
                        }
                    }
                }

                // No response action matched: the handler ran but produced nothing this
                // protocol can encode — a model that refused, a static handler with an empty
                // action list, or an answer whose actions were all unrecognised.
                //
                // This used to reply with an empty OK, which a driver reads as a statement that
                // executed successfully and affected zero rows. For an INSERT, UPDATE or DELETE
                // that is a claim the write completed, and the caller carries on believing it
                // landed. The log line admitted it was "indistinguishable from a successful
                // no-op" — which is precisely why it cannot be the answer.
                //
                // Fail closed with an ERR packet instead, the same shape the backend-error arm
                // below uses. 1105 (ER_UNKNOWN_ERROR) rather than 1205: nothing here timed out,
                // so advertising a retryable condition would be wrong.
                warn!(
                    "MySQL: no response action produced for query {:?} \
                     (decision=fail_closed_no_action); replying with an ERR packet",
                    query
                );
                let message = crate::utils::WireFailure::Unavailable.prefixed_text();
                self.record_stats(None, Some(message.len() as u64), None, Some(1))
                    .await;
                finish_query(
                    results
                        .error(ErrorKind::ER_UNKNOWN_ERROR, message.as_bytes())
                        .await,
                    close_requested,
                )
            }
            Err(e) => {
                // Report the failure as a MySQL ERR packet instead of a silent empty OK, so
                // the client sees something rather than an unexplained success. The ERR packet
                // carries the error number and the SQLSTATE that goes with it, which is what
                // lets a driver classify the failure instead of guessing from a message.
                //
                // Overload gets 1205 (SQLSTATE HY000), the code every MySQL driver already
                // treats as "transient, safe to retry", rather than 1105 which reads as a
                // permanent server fault.
                let overloaded = crate::llm::is_overload_error(&e);
                let message = crate::utils::WireFailure::classify(&e).prefixed_text();
                let kind = if overloaded {
                    ErrorKind::ER_LOCK_WAIT_TIMEOUT
                } else {
                    ErrorKind::ER_UNKNOWN_ERROR
                };
                // Non-fatal: a wire fallback (ERR packet) is still delivered and the
                // connection continues.
                Log::new(Some(&self.status_tx))
                    .warn(format!("MySQL replying with error: {}", message));
                self.record_stats(None, Some(message.len() as u64), None, Some(1))
                    .await;
                results.error(kind, message.as_bytes()).await
            }
        }
    }
}

/// Map an LLM-supplied MySQL error number onto an `opensrv_mysql::ErrorKind`.
///
/// `ErrorKind::from(u16)` **panics** on any value that is not one of the ~886 codes it knows
/// (`opensrv-mysql-0.7.0/src/errorcodes.rs:2807`). The number here comes straight out of model
/// output, so calling it directly would let a hallucinated error code kill the connection task.
/// We therefore accept the error numbers a model realistically produces and fall back to
/// `ER_UNKNOWN_ERROR` (1105) for anything else.
fn mysql_error_kind(code: u16) -> ErrorKind {
    match code {
        1044 => ErrorKind::ER_DBACCESS_DENIED_ERROR,
        1045 => ErrorKind::ER_ACCESS_DENIED_ERROR,
        1046 => ErrorKind::ER_NO_DB_ERROR,
        1049 => ErrorKind::ER_BAD_DB_ERROR,
        1050 => ErrorKind::ER_TABLE_EXISTS_ERROR,
        1051 => ErrorKind::ER_BAD_TABLE_ERROR,
        1052 => ErrorKind::ER_NON_UNIQ_ERROR,
        1054 => ErrorKind::ER_BAD_FIELD_ERROR,
        1062 => ErrorKind::ER_DUP_ENTRY,
        1064 => ErrorKind::ER_PARSE_ERROR,
        1065 => ErrorKind::ER_EMPTY_QUERY,
        1136 => ErrorKind::ER_WRONG_VALUE_COUNT_ON_ROW,
        1146 => ErrorKind::ER_NO_SUCH_TABLE,
        1149 => ErrorKind::ER_SYNTAX_ERROR,
        1216 => ErrorKind::ER_NO_REFERENCED_ROW,
        1217 => ErrorKind::ER_ROW_IS_REFERENCED,
        1364 => ErrorKind::ER_NO_DEFAULT_FOR_FIELD,
        1451 => ErrorKind::ER_ROW_IS_REFERENCED_2,
        1452 => ErrorKind::ER_NO_REFERENCED_ROW_2,
        1690 => ErrorKind::ER_DATA_OUT_OF_RANGE,
        other => {
            warn!(
                "MySQL: error code {} is not in opensrv-mysql's table, reporting 1105 ER_UNKNOWN_ERROR",
                other
            );
            ErrorKind::ER_UNKNOWN_ERROR
        }
    }
}

/// The parameter values a `COM_STMT_EXECUTE` bound, as the event shows them.
struct BoundParams {
    /// `stmt_params::params_json`.
    params: serde_json::Value,
    /// `stmt_params::render_query`.
    rendered: String,
}

/// Count the `?` parameter placeholders in a SQL statement. See [`placeholder_offsets`].
pub fn count_placeholders(sql: &str) -> usize {
    placeholder_offsets(sql).len()
}

/// The byte offset of every `?` parameter placeholder in a SQL statement.
///
/// A `?` inside a string literal, a quoted identifier or a comment is data, not a
/// placeholder, so those regions are skipped. MySQL's lexical rules:
///
/// - `'…'` and `"…"` are strings (`"` is an identifier under `ANSI_QUOTES`, but either way a
///   `?` inside it is not a placeholder), with both `\` escapes and the doubled-quote form.
/// - `` `…` `` is a quoted identifier, escaped by doubling the backtick.
/// - `-- ` and `#` run to end of line; `/* … */` is a block comment. `/*! … */` version
///   comments are treated as comments too — a placeholder hidden inside one would be
///   pathological, and under-counting there is caught by the client rather than desyncing us.
///
/// Exposed for `tests/server/mysql/prepared_statement_test.rs`; the project keeps unit tests
/// out of `src/`.
pub fn placeholder_offsets(sql: &str) -> Vec<usize> {
    let bytes = sql.as_bytes();
    let mut offsets = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            q @ (b'\'' | b'"' | b'`') => {
                let escapes_with_backslash = q != b'`';
                i += 1;
                while i < bytes.len() {
                    if escapes_with_backslash && bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == q {
                        // A doubled quote stays inside the literal.
                        if bytes.get(i + 1) == Some(&q) {
                            i += 2;
                            continue;
                        }
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            b'#' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            // MySQL requires whitespace (or end of input) after `--` for it to be a comment;
            // `a--b` is two unary minuses.
            b'-' if bytes.get(i + 1) == Some(&b'-')
                && bytes.get(i + 2).is_none_or(|c| c.is_ascii_whitespace()) =>
            {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i < bytes.len() {
                    if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            b'?' => {
                offsets.push(i);
                i += 1;
            }
            _ => i += 1,
        }
    }

    offsets
}

/// Turn a successfully-written response into a connection teardown when the LLM asked for
/// `close_this_connection`. opensrv-mysql ends the session when the shim returns an error.
fn finish_query(result: io::Result<()>, close_requested: bool) -> io::Result<()> {
    match result {
        Ok(()) if close_requested => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "MySQL connection closed by close_this_connection action",
        )),
        other => other,
    }
}

/// Send a result set to the client
async fn send_result_set<'a, W: tokio::io::AsyncWrite + Send + Unpin>(
    results: QueryResultWriter<'a, W>,
    columns: Vec<serde_json::Value>,
    rows: Vec<serde_json::Value>,
) -> io::Result<()> {
    // Parse column definitions
    let mut cols = Vec::new();
    for col_def in &columns {
        let name = col_def
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("column");

        let col_type = col_def
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("VARCHAR");

        let mysql_type = match col_type.to_uppercase().as_str() {
            "INT" | "INTEGER" => ColumnType::MYSQL_TYPE_LONG,
            "BIGINT" => ColumnType::MYSQL_TYPE_LONGLONG,
            "SMALLINT" => ColumnType::MYSQL_TYPE_SHORT,
            "TINYINT" => ColumnType::MYSQL_TYPE_TINY,
            "FLOAT" => ColumnType::MYSQL_TYPE_FLOAT,
            "DOUBLE" => ColumnType::MYSQL_TYPE_DOUBLE,
            "DECIMAL" => ColumnType::MYSQL_TYPE_DECIMAL,
            "DATE" => ColumnType::MYSQL_TYPE_DATE,
            "TIME" => ColumnType::MYSQL_TYPE_TIME,
            "DATETIME" | "TIMESTAMP" => ColumnType::MYSQL_TYPE_DATETIME,
            "BLOB" | "BINARY" => ColumnType::MYSQL_TYPE_BLOB,
            "TEXT" => ColumnType::MYSQL_TYPE_STRING,
            _ => ColumnType::MYSQL_TYPE_VAR_STRING,
        };

        cols.push(Column {
            table: "".to_string(),
            column: name.to_string(),
            coltype: mysql_type,
            colflags: ColumnFlags::empty(),
        });
    }

    // Start the result set
    let mut row_writer = results.start(&cols).await?;

    // Write rows. Every row is written to exactly `cols.len()` cells: a short row is padded
    // with NULLs and a long one is truncated. opensrv-mysql returns `InvalidData` from
    // `end_row()` for a short row, and that error ends the *session*, so a model that
    // miscounted one row used to kill the connection rather than produce one odd row.
    // PostgreSQL's handler has always padded; this matches it.
    for row_data in &rows {
        let Some(row_values) = row_data.as_array() else {
            warn!("MySQL: skipping row that is not an array: {}", row_data);
            continue;
        };
        if row_values.len() != cols.len() {
            warn!(
                "MySQL: row has {} values for {} columns; padding/truncating",
                row_values.len(),
                cols.len()
            );
        }
        for (idx, col) in cols.iter().enumerate() {
            let value = row_values.get(idx).unwrap_or(&serde_json::Value::Null);
            write_cell(&mut row_writer, col, value)?;
        }
        row_writer.end_row().await?;
    }

    // Finish the result set
    row_writer.finish().await
}

/// Write one cell, encoded the way its declared column type requires.
///
/// This is only load-bearing for the **binary** protocol (`COM_STMT_EXECUTE`, i.e. every
/// prepared statement). In the text protocol opensrv-mysql writes every cell as a
/// length-encoded string whatever the column says, so handing it a `String` was fine. In the
/// binary protocol it encodes according to `Column::coltype` and returns `io::Error` for a
/// Rust type it cannot write as that type — and `String`/`&[u8]` is rejected by every numeric
/// and every temporal column (`opensrv-mysql-0.7.0/src/value/encode.rs`). So the protocol's
/// own advertised example, `{"name": "id", "type": "INT"}`, ended the session on
/// `conn.exec(...)` while working perfectly on `conn.query(...)`.
///
/// A value that cannot be represented as its column's type is sent as SQL NULL with a WARN.
/// That is deliberately not an error: a single odd cell must not cost the connection, and a
/// silently coerced wrong number would be worse than an explicit absence.
fn write_cell<W: tokio::io::AsyncWrite + Send + Unpin>(
    row: &mut RowWriter<'_, W>,
    column: &Column,
    value: &serde_json::Value,
) -> io::Result<()> {
    if value.is_null() {
        // A real SQL NULL: the NULL bitmap in binary, 0xFB in text. It used to be written as
        // the four-character string "NULL", which every client read as data.
        return row.write_col(None::<String>);
    }

    /// Send NULL and say why, rather than ending the session over one cell.
    macro_rules! unrepresentable {
        ($row:expr, $column:expr, $value:expr) => {{
            warn!(
                "MySQL: value {} cannot be sent as column '{}' ({:?}); sending NULL",
                $value, $column.column, $column.coltype
            );
            $row.write_col(None::<String>)
        }};
    }

    match column.coltype {
        // opensrv's `i32` encoder covers TINY/SHORT/INT24/LONG (and range-checks); its `i64`
        // encoder accepts LONGLONG only.
        ColumnType::MYSQL_TYPE_TINY
        | ColumnType::MYSQL_TYPE_SHORT
        | ColumnType::MYSQL_TYPE_INT24
        | ColumnType::MYSQL_TYPE_LONG => {
            match json_to_i64(value).and_then(|n| i32::try_from(n).ok()) {
                Some(n) => row.write_col(n),
                None => unrepresentable!(row, column, value),
            }
        }
        ColumnType::MYSQL_TYPE_LONGLONG => match json_to_i64(value) {
            Some(n) => row.write_col(n),
            None => unrepresentable!(row, column, value),
        },
        ColumnType::MYSQL_TYPE_FLOAT => match json_to_f64(value) {
            Some(n) => row.write_col(n as f32),
            None => unrepresentable!(row, column, value),
        },
        ColumnType::MYSQL_TYPE_DOUBLE => match json_to_f64(value) {
            Some(n) => row.write_col(n),
            None => unrepresentable!(row, column, value),
        },
        ColumnType::MYSQL_TYPE_DATE => match value.as_str().and_then(parse_date) {
            Some(d) => row.write_col(d),
            None => unrepresentable!(row, column, value),
        },
        ColumnType::MYSQL_TYPE_DATETIME | ColumnType::MYSQL_TYPE_TIMESTAMP => {
            match value.as_str().and_then(parse_datetime) {
                Some(dt) => row.write_col(dt),
                None => unrepresentable!(row, column, value),
            }
        }
        ColumnType::MYSQL_TYPE_TIME => match value.as_str().and_then(parse_time) {
            Some(d) => row.write_col(d),
            None => unrepresentable!(row, column, value),
        },
        // Every remaining type this server maps to (VAR_STRING, STRING, BLOB, DECIMAL) is one
        // opensrv's `&[u8]` encoder accepts in both protocols.
        _ => row.write_col(json_to_mysql_string(value)),
    }
}

/// Coerce a JSON value to an integer, accepting the shapes a model actually produces.
fn json_to_i64(value: &serde_json::Value) -> Option<i64> {
    match value {
        serde_json::Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_u64().and_then(|u| i64::try_from(u).ok()))
            .or_else(|| {
                n.as_f64()
                    .filter(|f| f.fract() == 0.0 && f.is_finite())
                    .map(|f| f as i64)
            }),
        serde_json::Value::String(s) => s.trim().parse::<i64>().ok(),
        serde_json::Value::Bool(b) => Some(*b as i64),
        _ => None,
    }
}

fn json_to_f64(value: &serde_json::Value) -> Option<f64> {
    match value {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.trim().parse::<f64>().ok(),
        serde_json::Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

fn parse_date(s: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").ok()
}

fn parse_datetime(s: &str) -> Option<chrono::NaiveDateTime> {
    let s = s.trim();
    for format in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
    ] {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, format) {
            return Some(dt);
        }
    }
    parse_date(s).map(|d| d.into())
}

/// `HH:MM:SS[.ffffff]` as a duration since midnight.
///
/// Bounded at 34 days because `opensrv-mysql`'s `Duration` encoder contains
/// `assert!(d <= 34)` — a longer value would *panic* the connection task rather than fail it,
/// and the value comes from model output.
fn parse_time(s: &str) -> Option<std::time::Duration> {
    let s = s.trim();
    let (whole, fraction) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    let mut parts = whole.split(':');
    let hours: u64 = parts.next()?.parse().ok()?;
    let minutes: u64 = parts.next()?.parse().ok()?;
    let seconds: u64 = parts.next().unwrap_or("0").parse().ok()?;
    if parts.next().is_some() || minutes > 59 || seconds > 59 {
        return None;
    }
    let micros: u32 = if fraction.is_empty() {
        0
    } else {
        let padded = format!("{:0<6}", &fraction[..fraction.len().min(6)]);
        padded.parse().ok()?
    };
    let total_secs = hours * 3600 + minutes * 60 + seconds;
    if total_secs / (24 * 3600) > 34 {
        return None;
    }
    Some(std::time::Duration::new(total_secs, micros * 1_000))
}

/// Convert JSON value to MySQL string representation.
///
/// `Null` is handled by the caller (`write_cell`) as a real SQL NULL and never reaches here;
/// the empty string is the safe answer if it ever does.
fn json_to_mysql_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => if *b { "1" } else { "0" }.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => v.to_string(),
    }
}

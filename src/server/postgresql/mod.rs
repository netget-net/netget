//! PostgreSQL server implementation using pgwire
pub mod actions;
pub mod guard;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::utils::task_guard::AbortOnDrop;
use crate::{console_debug, console_error};
use actions::{PostgresqlProtocol, POSTGRESQL_QUERY_EVENT};
use anyhow::Result;
use pgwire::api::auth::noop::NoopStartupHandler;
use pgwire::api::auth::StartupHandler;
use pgwire::api::portal::Portal;
use pgwire::api::query::{ExtendedQueryHandler, SimpleQueryHandler};
use pgwire::api::results::{
    DataRowEncoder, DescribePortalResponse, DescribeStatementResponse, FieldFormat, FieldInfo,
    QueryResponse, Response, Tag,
};
use pgwire::api::stmt::StoredStatement;
use pgwire::api::{ClientInfo, PgWireServerHandlers, Type};
use pgwire::error::{ErrorInfo, PgWireError, PgWireResult};
use pgwire::messages::data::DataRow;
use pgwire::tokio::process_socket;
use pgwire::types::format::FormatOptions;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tracing::{error, warn};

/// PostgreSQL server implementation
pub struct PostgresqlServer {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    #[allow(dead_code)]
    status_tx: mpsc::UnboundedSender<String>,
    server_id: Option<crate::state::ServerId>,
}

impl PostgresqlServer {
    /// Create a new PostgreSQL server
    pub fn new(
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: Option<crate::state::ServerId>,
    ) -> Self {
        Self {
            llm_client,
            app_state,
            status_tx,
            server_id,
        }
    }

    /// Spawn PostgreSQL server with LLM integration
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        _send_first: bool,
        server_id: crate::state::ServerId,
        deadlines: PgDeadlines,
    ) -> Result<SocketAddr> {
        let listener = TcpListener::bind(listen_addr).await?;
        let actual_addr = listener.local_addr()?;
        // pgwire is served from a loopback pair behind the frontend-size guard; see `guard.rs`.
        let backend = Arc::new(guard::Backend::bind().await?);

        Log::to(&status_tx).info(format!("PostgreSQL server listening on {}", actual_addr));

        let server = Arc::new(PostgresqlServer::new(
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
                    "PostgreSQL",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, addr, permit)) => {
                        console_debug!(status_tx, "PostgreSQL connection from {}", addr);

                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(actual_addr);

                        let handler_factory = Arc::new(PostgresqlHandlerFactory {
                            connection_id,
                            llm_client: server.llm_client.clone(),
                            app_state: server.app_state.clone(),
                            status_tx: status_tx.clone(),
                            server_id: server.server_id,
                            remote_addr: addr,
                            describe_cache: Arc::new(TokioMutex::new(Vec::new())),
                            described: Arc::new(TokioMutex::new(Vec::new())),
                            activity: Arc::new(
                                crate::server::accept_bounded::ConnectionActivity::new(),
                            ),
                        });
                        let activity = Arc::clone(&handler_factory.activity);

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
                        let conn_status_tx = status_tx.clone();
                        let conn_backend = Arc::clone(&backend);
                        let conn_handle = tokio::spawn(async move {
                            // Held for the life of the session, so the cap counts live
                            // connections rather than accepts.
                            let _permit = permit;

                            // First-byte bound, enforced before pgwire sees the socket.
                            //
                            // `process_socket` takes a concrete `TcpStream` and owns every read
                            // after that, so there is no reader of ours to wrap — but `peek`
                            // waits for data *without consuming it*, so the StartupMessage is
                            // still there for pgwire afterwards. That makes a real
                            // "connected and said nothing" bound possible with no proxy and no
                            // change to the crate's framing.
                            //
                            // Every return below closes the connection's row, so the dashboard
                            // never keeps an Active peer for a socket that is gone.
                            let close_row = move || {
                                let owner = conn_state_owner.clone();
                                async move {
                                    if let Some(server_id) = conn_server_id {
                                        owner
                                            .close_connection_on_server(server_id, connection_id)
                                            .await;
                                    }
                                }
                            };
                            match tokio::time::timeout(
                                deadlines.first_byte,
                                stream.peek(&mut [0u8; 1]),
                            )
                            .await
                            {
                                Ok(Ok(0)) | Ok(Err(_)) => {
                                    close_row().await;
                                    return;
                                }
                                Ok(Ok(_)) => {}
                                Err(_) => {
                                    console_debug!(
                                        conn_status_tx,
                                        "PostgreSQL connection {} sent nothing for {}s; \
                                         closing before startup",
                                        connection_id,
                                        deadlines.first_byte.as_secs()
                                    );
                                    close_row().await;
                                    return;
                                }
                            }

                            let (relay_end, pgwire_end) = match conn_backend.pair().await {
                                Ok(pair) => pair,
                                Err(e) => {
                                    Log::to(&conn_status_tx).error(format!(
                                        "PostgreSQL connection {} could not be handed to the \
                                         protocol engine: {}",
                                        connection_id, e
                                    ));
                                    close_row().await;
                                    return;
                                }
                            };
                            let relay_status = conn_status_tx.clone();
                            let mut relay = AbortOnDrop(tokio::spawn(async move {
                                if let Some(refusal) = guard::relay(
                                    stream,
                                    relay_end,
                                    guard::MAX_FRONTEND_MESSAGE_BYTES,
                                )
                                .await
                                {
                                    Log::to(&relay_status).warn(format!(
                                        "PostgreSQL connection {} closed decision={}: {}",
                                        connection_id,
                                        refusal.decision(),
                                        refusal.message()
                                    ));
                                }
                            }));

                            // `process_socket` runs in a task of its own so a **panic** inside
                            // pgwire or in our handler is contained rather than lost. (A
                            // malformed frontend message never reaches pgwire: the relay above
                            // refuses it `FATAL 08P01`; see `guard::check_typed`.)
                            //
                            // What NetGet can do is not lose the connection's bookkeeping to a
                            // panic. The panic used to unwind straight past
                            // `close_connection_on_server`, so the dashboard kept an Active row
                            // for a socket that was already gone — and PostgreSQL is not
                            // `connectionless`, so the idle sweep never collected it either.
                            // The entry now closes on every path, and the panic is reported
                            // rather than swallowed by `tokio::spawn`.
                            //
                            // Both helper tasks are held in `AbortOnDrop`. This task is the one
                            // registered with the server, so `stop_server` aborts *it*; the
                            // abort drops whatever it is awaiting, and a dropped `JoinHandle`
                            // detaches its task rather than ending it. Without the guard the
                            // pgwire session outlived the stop, still holding the peer's socket.
                            let mut inner = AbortOnDrop(tokio::spawn(async move {
                                process_socket(pgwire_end, None, handler_factory).await
                            }));

                            // Idle bound. pgwire's loop is not ours, so this watches the
                            // handler's own `ConnectionActivity` instead — and that type
                            // refuses to report a connection idle while work is in flight, so
                            // a statement waiting on the model, or parked for a human at the
                            // dashboard, can never be closed from under itself however long it
                            // takes. Only genuine silence counts.
                            //
                            // The connection is dropped rather than sent a FATAL 57P05: pgwire
                            // owns the socket and exposes no way to write into it from here.
                            let abort_handle = inner.0.abort_handle();
                            let watchdog_activity = Arc::clone(&activity);
                            let watchdog_status = conn_status_tx.clone();
                            let _watchdog = AbortOnDrop(tokio::spawn(async move {
                                crate::server::accept_bounded::watch_idle(
                                    watchdog_activity,
                                    deadlines.idle,
                                )
                                .await;
                                console_debug!(
                                    watchdog_status,
                                    "PostgreSQL connection {} idle for {}s; closing",
                                    connection_id,
                                    deadlines.idle.as_secs()
                                );
                                abort_handle.abort();
                            }));

                            let joined = (&mut inner.0).await;
                            match joined {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    error!("PostgreSQL connection error: {:?}", e);
                                }
                                Err(join_error) if join_error.is_panic() => {
                                    Log::to(&conn_status_tx).error(format!(
                                        "PostgreSQL connection {} decision=connection_aborted_decoder_panic: \
                                         pgwire or the handler panicked serving the peer. The \
                                         connection is closed; the server is unaffected.",
                                        connection_id
                                    ));
                                }
                                Err(join_error) => {
                                    error!(
                                        "PostgreSQL connection {} task ended abnormally: {}",
                                        connection_id, join_error
                                    );
                                }
                            }
                            // pgwire has ended, so its end of the pair is closed and the relay
                            // finishes: it writes a refusal if one ended the session, then closes
                            // the peer's socket.
                            let _ = tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                &mut relay.0,
                            )
                            .await;
                            // Mark the connection closed so it does not stay Active forever
                            // in the server's connection map.
                            close_row().await;
                        });

                        // Register the per-connection task too, not just the accept loop:
                        // aborting the accept loop releases the port but leaves every in-flight
                        // session running, so `stop_server` did not actually stop the server.
                        // `register_server_task` prunes finished handles on each call, so this
                        // cannot grow without bound.
                        if let Some(server_id) = conn_server_id {
                            app_state.register_server_task(server_id, conn_handle).await;
                        }
                    }
                    Err(e) => {
                        console_error!(status_tx, "PostgreSQL accept error: {}", e);
                    }
                }
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
        Ok(actual_addr)
    }
}

/// No-auth startup handler for PostgreSQL
struct PostgresqlNoopHandler;

// Implement NoopStartupHandler trait
// StartupHandler is automatically implemented for types implementing NoopStartupHandler
#[async_trait::async_trait]
impl NoopStartupHandler for PostgresqlNoopHandler {}

/// Factory for creating PostgreSQL handlers
struct PostgresqlHandlerFactory {
    connection_id: ConnectionId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: Option<crate::state::ServerId>,
    remote_addr: SocketAddr,
    /// Shared between the simple and extended handlers so a Describe resolved by one is
    /// visible to the Execute served by the other.
    describe_cache: DescribeCache,
    /// The columns each described statement told the client it returns. See [`Binding`].
    described: DescribedColumns,
    /// Read by the idle watchdog in the accept loop. pgwire owns the socket, so this is the
    /// only view NetGet has of whether the connection is doing anything.
    activity: Arc<crate::server::accept_bounded::ConnectionActivity>,
}

impl PostgresqlHandlerFactory {
    fn handler(&self) -> PostgresqlHandler {
        PostgresqlHandler {
            activity: Arc::clone(&self.activity),
            connection_id: self.connection_id,
            llm_client: self.llm_client.clone(),
            app_state: self.app_state.clone(),
            status_tx: self.status_tx.clone(),
            server_id: self.server_id,
            remote_addr: self.remote_addr,
            protocol: Arc::new(PostgresqlProtocol::new(
                self.connection_id,
                self.app_state.clone(),
                self.status_tx.clone(),
            )),
            describe_cache: Arc::clone(&self.describe_cache),
            described: Arc::clone(&self.described),
        }
    }
}

impl PgWireServerHandlers for PostgresqlHandlerFactory {
    fn simple_query_handler(&self) -> Arc<impl SimpleQueryHandler> {
        Arc::new(self.handler())
    }

    fn extended_query_handler(&self) -> Arc<impl ExtendedQueryHandler> {
        Arc::new(self.handler())
    }

    fn startup_handler(&self) -> Arc<impl StartupHandler> {
        Arc::new(PostgresqlNoopHandler)
    }
}

/// PostgreSQL connection handler
pub struct PostgresqlHandler {
    connection_id: ConnectionId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    #[allow(dead_code)]
    server_id: Option<crate::state::ServerId>,
    #[allow(dead_code)]
    remote_addr: SocketAddr,
    /// PostgreSQL protocol handler for action execution
    protocol: Arc<PostgresqlProtocol>,
    /// Describe -> Execute correlation for the extended query protocol
    describe_cache: DescribeCache,
    /// See [`PostgresqlHandlerFactory::described`].
    described: DescribedColumns,
    /// See [`PostgresqlHandlerFactory::activity`].
    activity: Arc<crate::server::accept_bounded::ConnectionActivity>,
}

/// The outcome of resolving one SQL statement through the LLM/handler pipeline.
///
/// Extended-protocol clients ask for the row description (Describe) *before* asking for the
/// rows (Execute). Because the schema is whatever the LLM decides, the two steps must agree,
/// so the resolved outcome is cached per SQL text between them. This is per-connection
/// protocol bookkeeping, not a data store: nothing is retained once the statement executes.
enum PgOutcome {
    Rows {
        /// The column descriptors the model supplied, kept as name + type rather than as
        /// `FieldInfo`, because a `FieldInfo` also carries a *format* and the format is not
        /// known here. Only the client knows it: the Bind message names the result format for
        /// each column, so the same resolved answer has to be encoded as text for one portal
        /// and as binary for another. Encoding is therefore deferred to the handler.
        columns: Arc<Vec<PgColumn>>,
        /// One entry per row, already padded and truncated to `columns.len()`.
        values: Vec<Vec<serde_json::Value>>,
    },
    Tag(String),
    Close,
}

/// A column as the model described it: a name and a PostgreSQL type OID.
#[derive(Clone, Debug)]
struct PgColumn {
    name: String,
    datatype: Type,
}

/// Cap on described-but-not-executed statements held per connection.
const MAX_PENDING_DESCRIBES: usize = 64;

/// How long to wait for the peer's first byte after it connects.
///
/// PostgreSQL is client-speaks-first: the StartupMessage (or an SSLRequest) is the first thing
/// on the wire and the server says nothing before it, so a peer that has connected and sent
/// nothing has begun nothing. This is enforced with `TcpStream::peek` *before* the socket is
/// handed to pgwire — peek waits for data without consuming it, so the startup packet pgwire
/// then reads is untouched. Sixty seconds matches `pgwire`'s own internal `STARTUP_TIMEOUT`,
/// which bounds the startup *exchange*; this bounds the silence before it begins, which pgwire
/// does not.
const FIRST_BYTE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a connection may do nothing at all once startup is over.
///
/// Real PostgreSQL's equivalent is `idle_session_timeout`, which ships disabled — so unlike
/// Kafka there is no upstream default to copy, and the number has to be argued. Ten minutes,
/// for the same reason MySQL's is: this server holds no session state a reconnect would lose
/// (no tables, no temporary tables, no open transaction — the model answers every statement),
/// so a pooled connection reaped here costs `tokio-postgres`, SQLAlchemy or pgbouncer one
/// transparent reconnect. It is also far above the default 300s a `manual` rule may park a
/// statement for, and — more importantly — a park cannot trip it at all, because
/// [`ConnectionActivity`] counts work in flight and a busy connection is never idle.
const IDLE_SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// The read deadlines one server applies: the defaults above, or the server's
/// `first_byte_timeout_secs` / `idle_timeout_secs` startup parameters.
#[derive(Debug, Clone, Copy)]
pub struct PgDeadlines {
    pub first_byte: std::time::Duration,
    pub idle: std::time::Duration,
}

impl PgDeadlines {
    pub fn from_secs(first_byte: Option<u64>, idle: Option<u64>) -> Self {
        Self {
            first_byte: first_byte
                .map(std::time::Duration::from_secs)
                .unwrap_or(FIRST_BYTE_READ_TIMEOUT),
            idle: idle
                .map(std::time::Duration::from_secs)
                .unwrap_or(IDLE_SESSION_TIMEOUT),
        }
    }
}

/// Concurrent connections this server admits.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// A v3 ErrorResponse carrying SQLSTATE **53300 `too_many_connections`** — the state real
/// PostgreSQL uses for "sorry, too many clients already", and the one this file already maps
/// backend overload onto, so a driver classifies both as transient and backs off rather than
/// recording a permanent fault. Sending it before the StartupMessage is a small liberty (a real
/// server refuses after reading startup), and libpq-family clients handle it: they write
/// startup, then read, and an ErrorResponse is a legal thing to find there.
///
/// Laid out by hand: `'E'`, a 4-byte big-endian length covering itself and everything after
/// it, then NUL-terminated fields `S`everity, `V` (non-localised severity), `C`ode and
/// `M`essage, then a final NUL ending the field list. 4 + 7 + 7 + 7 + 22 + 1 = 48 = 0x30.
const CONNECTION_CAP_REFUSAL: &[u8] =
    b"E\x00\x00\x000SFATAL\x00VFATAL\x00C53300\x00Mtoo many connections\x00\x00";

/// A connection-scoped cache shared by the simple and extended handlers, keyed by the statement
/// text and its bound parameters (see [`cache_key`]).
type DescribeCache = Arc<TokioMutex<Vec<(String, PgOutcome)>>>;

/// Per statement text, the columns its Describe told the client — kept, bounded like the cache,
/// so every later Execute of the statement answers in that shape.
type DescribedColumns = Arc<TokioMutex<Vec<(String, Arc<Vec<PgColumn>>)>>>;

/// What one resolution of a statement knows about the client's side of it.
///
/// The extended protocol separates the schema from the data: a client may Describe a prepared
/// statement before binding any parameter (tokio-postgres always does), and then Execute it any
/// number of times with different values. So a statement is resolved with whatever is known at
/// that moment, and what has already been promised constrains what comes after.
#[derive(Debug, Clone, Default)]
struct Binding {
    /// The parameter values the client bound, or `None` while it is describing the statement
    /// before any Bind. Empty for a statement with no parameters.
    parameters: Option<Vec<serde_json::Value>>,
    /// The statement's parameter types, one per `$n`.
    parameter_types: Vec<Type>,
    /// The columns already described to the client for this statement. The rows must come in
    /// exactly this shape, or the client decodes them against the wrong description.
    described: Option<Arc<Vec<PgColumn>>>,
}

/// The describe-cache key: the statement text and the parameter values it was resolved with.
fn cache_key(sql: &str, parameters: &[serde_json::Value]) -> String {
    format!("{sql}\u{0}{}", serde_json::Value::from(parameters.to_vec()))
}

impl PostgresqlHandler {
    /// Refresh the dashboard's per-connection counters and `last_activity`.
    ///
    /// `pgwire::tokio::process_socket` takes a concrete `TcpStream` and never exposes the raw
    /// byte streams, so these are the **application-visible** payload sizes seen at the handler
    /// boundary (the SQL text received, the cell text produced), not the exact wire bytes —
    /// pgwire adds a 5-byte message header, the RowDescription and per-field length prefixes on
    /// top. Good enough for the rail's `↓/↑` counters and, more importantly, for keeping
    /// `last_activity` current: without this nothing on this protocol ever called
    /// `update_connection_stats`, so every PostgreSQL peer row read `0 / 0` for its whole life
    /// however much SQL crossed it.
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

    /// Run one statement through the handler pipeline and translate the resulting action into
    /// wire-level output. Returns `Err` for `postgresql_error_response` and for LLM failures.
    async fn resolve(&self, sql: &str, binding: &Binding) -> PgWireResult<PgOutcome> {
        // Everything from here to the end of this call is the peer *waiting on us* — the LLM
        // round-trip, and a `manual` rule parking the statement for a human. The idle watchdog
        // must not count any of it, so the connection is marked busy for the whole of it and
        // the guard's `Drop` clears the mark on every exit path, including the `?`-shaped ones.
        let _busy = self.activity.busy();
        Log::to(&self.status_tx).debug(format!("PostgreSQL query: {}", sql));

        self.record_stats(Some(sql.len() as u64), None, Some(1), None)
            .await;

        let mut event_data = serde_json::json!({ "query": sql });
        if let Some(hint) = actions::answer_with_for_query(sql) {
            event_data["answer_with"] = serde_json::json!(hint);
        }
        // `$1`, `$2`, … are the statement's parameters. Their values are what the statement is
        // about, so the model is given them; until a Bind has supplied them it is told the
        // client is only asking for the result's columns.
        if !binding.parameter_types.is_empty() {
            event_data["parameter_types"] = serde_json::json!(binding
                .parameter_types
                .iter()
                .map(|t| t.name().to_string())
                .collect::<Vec<_>>());
            match &binding.parameters {
                Some(values) => event_data["parameters"] = serde_json::json!(values),
                None => {
                    event_data["parameters"] = serde_json::Value::Null;
                    event_data["describe_only"] = serde_json::json!(true);
                }
            }
        }
        if let Some(columns) = &binding.described {
            event_data["columns"] = serde_json::json!(columns
                .iter()
                .map(|c| serde_json::json!({"name": c.name, "type": c.datatype.name()}))
                .collect::<Vec<_>>());
        }
        let event = Event::new(&POSTGRESQL_QUERY_EVENT, event_data);

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
                // An ErrorResponse carrying a SQLSTATE, not silence: a client that gets
                // nothing back sits in its own read until it times out, and cannot tell an
                // unavailable backend from a slow query.
                //
                // Overload is reported as 53300 (too_many_connections, class 53 "insufficient
                // resources"), which drivers classify as transient; everything else stays
                // XX000 (internal_error). The two are deliberately distinguishable — an outage
                // must not look like a permanent fault, and neither may look like success.
                //
                // `decision=` tags mirror `radius`: the SQLSTATE alone cannot tell a backend
                // outage from a model that answered and said nothing, so the log must.
                let overloaded = crate::llm::is_overload_error(&e);
                let (decision, code) = if overloaded {
                    ("fail_closed_llm_overloaded", "53300")
                } else {
                    ("fail_closed_llm_error", "XX000")
                };
                let message = crate::utils::WireFailure::classify(&e).prefixed_text();
                let log = Log::to(&self.status_tx);
                log.error(format!(
                    "PostgreSQL connection {} decision={} sqlstate={}: {}",
                    self.connection_id,
                    decision,
                    code,
                    crate::utils::truncate_for_log(&e.to_string(), 200)
                ));
                log.debug(format!(
                    "PostgreSQL connection {} LLM error chain: {:#}",
                    self.connection_id, e
                ));
                self.record_stats(None, Some(message.len() as u64), None, Some(1))
                    .await;
                return Err(PgWireError::UserError(Box::new(ErrorInfo::new(
                    "ERROR".to_string(),
                    code.to_string(),
                    message.to_string(),
                ))));
            }
        };

        let mut close_requested = false;

        // One query, one answer. The first response action is the one sent; any further one
        // is dropped, and said so. The eval saw a model answer one SELECT with two
        // `postgresql_query_response`s (the second one complete, the first not): a second
        // result for the same query has nowhere to go on the wire, and a silent drop would
        // make it look as though the model's last word was the one the client got.
        let responses = execution_result
            .protocol_results
            .iter()
            .filter(|r| {
                matches!(r, ActionResult::Custom { name, .. }
                    if matches!(name.as_str(), "postgresql_query_response" | "postgresql_ok" | "postgresql_error"))
            })
            .count();
        if responses > 1 {
            warn!(
                "PostgreSQL connection {} decision=duplicate_response_dropped: {} response \
                 actions for one query; sending the first",
                self.connection_id, responses
            );
        }

        for result in execution_result.protocol_results {
            match result {
                ActionResult::CloseConnection => close_requested = true,
                ActionResult::Custom { name, data } => match name.as_str() {
                    "postgresql_query_response" => {
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
                        // Estimate the outbound payload from the cell text while the JSON is
                        // still in hand — a `DataRow` does not expose its encoded length.
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
                                .map(|v| json_value_to_string(v).len() as u64)
                                .sum::<u64>();
                        self.record_stats(None, Some(sent_bytes), None, Some(1))
                            .await;
                        return build_row_outcome(&columns, &rows, binding.described.as_deref())
                            .map_err(|refusal| self.unanswerable(refusal));
                    }
                    "postgresql_ok" => {
                        // A command tag carries no rows. Where the statement was described as
                        // returning some, a tag would read as "zero rows" to a client that was
                        // promised columns — a claim about the data nothing made.
                        if binding.described.as_ref().is_some_and(|c| !c.is_empty()) {
                            return Err(self.unanswerable(Unanswerable::ShapeMismatch(
                                "a command tag for a statement described as returning rows"
                                    .to_string(),
                            )));
                        }
                        let tag = data.get("tag").and_then(|v| v.as_str()).unwrap_or("OK");
                        self.record_stats(None, Some(tag.len() as u64), None, Some(1))
                            .await;
                        return Ok(PgOutcome::Tag(tag.to_string()));
                    }
                    "postgresql_error" => {
                        let severity = data
                            .get("severity")
                            .and_then(|v| v.as_str())
                            .unwrap_or("ERROR")
                            .to_string();
                        let code = data
                            .get("code")
                            .and_then(|v| v.as_str())
                            .unwrap_or("XX000")
                            .to_string();
                        let message = data
                            .get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error")
                            .to_string();

                        // A refusal the model chose, not a backend failure — tagged so the log
                        // distinguishes the two, as `radius` does.
                        Log::to(&self.status_tx).warn(format!(
                            "PostgreSQL connection {} decision=model_reject {} sqlstate={}: {}",
                            self.connection_id, severity, code, message
                        ));
                        self.record_stats(None, Some(message.len() as u64), None, Some(1))
                            .await;

                        return Err(PgWireError::UserError(Box::new(ErrorInfo::new(
                            severity, code, message,
                        ))));
                    }
                    other => {
                        warn!(
                            "PostgreSQL: no wire encoding for action result '{}', ignoring",
                            other
                        );
                    }
                },
                _ => {}
            }
        }

        if close_requested {
            return Ok(PgOutcome::Close);
        }

        // No response action matched: the handler ran but produced nothing this protocol can
        // encode — a model that refused, a static handler with an empty list, or an answer
        // whose actions were all unrecognised.
        //
        // This used to answer success. A SELECT got an empty result set, which reads as "the
        // query ran and matched no rows" — a factual claim about the data that nothing
        // supports. Worse, anything else got the command tag `OK`, so an INSERT, UPDATE or
        // DELETE the model declined was reported to the client as having completed, and a
        // caller would carry on believing the write landed.
        //
        // Neither is recoverable by the client, because success is indistinguishable from a
        // real one. Fail closed instead, with the same shape the backend-error path above uses
        // so the two are consistent on the wire. 02000 (no_data) is deliberately NOT used: it
        // would again assert something about the data rather than about netget.
        // The statement text stays in the file log: it can carry a password literal.
        let log = Log::to(&self.status_tx);
        log.error(format!(
            "PostgreSQL connection {}: no response action produced \
             (decision=fail_closed_no_action)",
            self.connection_id
        ));
        log.debug(format!(
            "PostgreSQL connection {} statement with no response action: {:?}",
            self.connection_id, sql
        ));
        self.record_stats(
            None,
            Some(crate::utils::WireFailure::Unavailable.prefixed_text().len() as u64),
            None,
            Some(1),
        )
        .await;
        Err(PgWireError::UserError(Box::new(ErrorInfo::new(
            "ERROR".to_string(),
            "XX000".to_string(),
            crate::utils::WireFailure::Unavailable
                .prefixed_text()
                .to_string(),
        ))))
    }

    /// Log why a model's answer cannot be put on the wire and return the fail-closed error.
    ///
    /// The peer gets the same `XX000` category every other unanswerable statement gets; the log
    /// gets the reason, tagged so a column-count mismatch or an unencodable value is told apart
    /// from a model that said nothing.
    fn unanswerable(&self, why: Unanswerable) -> PgWireError {
        let (decision, detail) = match &why {
            Unanswerable::ShapeMismatch(d) => ("fail_closed_column_mismatch", d.as_str()),
            Unanswerable::Value(d) => ("fail_closed_unencodable_value", d.as_str()),
        };
        Log::to(&self.status_tx).error(format!(
            "PostgreSQL connection {}: the answer cannot be sent (decision={}): {}",
            self.connection_id, decision, detail
        ));
        PgWireError::UserError(Box::new(ErrorInfo::new(
            "ERROR".to_string(),
            "XX000".to_string(),
            crate::utils::WireFailure::Unavailable
                .prefixed_text()
                .to_string(),
        )))
    }

    /// The columns an earlier Describe promised for `sql`, if any.
    async fn described_columns(&self, sql: &str) -> Option<Arc<Vec<PgColumn>>> {
        self.described
            .lock()
            .await
            .iter()
            .find(|(key, _)| key == sql)
            .map(|(_, columns)| Arc::clone(columns))
    }

    /// Remember the columns a Describe told the client `sql` returns.
    async fn remember_described(&self, sql: &str, columns: Arc<Vec<PgColumn>>) {
        let mut described = self.described.lock().await;
        described.retain(|(key, _)| key != sql);
        if described.len() >= MAX_PENDING_DESCRIBES {
            described.remove(0);
        }
        described.push((sql.to_string(), columns));
    }

    /// Resolve `sql` for a Describe, returning its columns and storing the outcome so a following
    /// Execute with the same parameters reuses it (one model call per extended-protocol
    /// statement, not one per Describe *and* one per Execute).
    ///
    /// A statement described before its parameters are bound (`binding.parameters` is `None`) is
    /// resolved for its columns only: the outcome is not cached, because the rows it would carry
    /// were answered without the values the statement is about.
    async fn resolve_for_describe(
        &self,
        sql: &str,
        binding: Binding,
        format_of: impl Fn(usize, usize) -> FieldFormat,
    ) -> PgWireResult<Vec<FieldInfo>> {
        let outcome = self.resolve(sql, &binding).await?;
        let (fields, columns) = match &outcome {
            PgOutcome::Rows { columns, .. } => (
                fields_for(columns, |idx| format_of(idx, columns.len()))
                    .as_ref()
                    .clone(),
                Arc::clone(columns),
            ),
            _ => (Vec::new(), Arc::new(Vec::new())),
        };
        self.remember_described(sql, columns).await;

        if let Some(parameters) = &binding.parameters {
            let key = cache_key(sql, parameters);
            let mut cache = self.describe_cache.lock().await;
            cache.retain(|(k, _)| *k != key);
            if cache.len() >= MAX_PENDING_DESCRIBES {
                cache.remove(0);
            }
            cache.push((key, outcome));
        }

        Ok(fields)
    }

    /// Take a previously described outcome for these parameters, or resolve fresh — in the shape
    /// an earlier Describe promised, when there was one.
    async fn take_or_resolve(&self, sql: &str, binding: Binding) -> PgWireResult<PgOutcome> {
        let key = cache_key(sql, binding.parameters.as_deref().unwrap_or(&[]));
        let cached = {
            let mut cache = self.describe_cache.lock().await;
            cache
                .iter()
                .position(|(k, _)| *k == key)
                .map(|idx| cache.remove(idx).1)
        };

        match cached {
            Some(outcome) => Ok(outcome),
            None => {
                let binding = Binding {
                    described: self.described_columns(sql).await,
                    ..binding
                };
                self.resolve(sql, &binding).await
            }
        }
    }
}

/// Why a model's answer cannot be encoded for the client.
#[derive(Debug)]
enum Unanswerable {
    /// The answer's shape is not the one the client was promised.
    ShapeMismatch(String),
    /// A cell's value cannot be represented in its column's type.
    Value(String),
}

/// Error returned when the LLM asked to close the connection.
fn terminating_error() -> PgWireError {
    PgWireError::UserError(Box::new(ErrorInfo::new(
        "FATAL".to_string(),
        "57P01".to_string(),
        "terminating connection due to administrator command".to_string(),
    )))
}

/// Map a column type name from the LLM onto a PostgreSQL type OID.
fn pg_type_for(type_name: &str) -> Type {
    match type_name.to_lowercase().as_str() {
        "int2" | "smallint" => Type::INT2,
        "int4" | "int" | "integer" => Type::INT4,
        "int8" | "bigint" => Type::INT8,
        "float4" | "real" => Type::FLOAT4,
        "float8" | "double" | "double precision" => Type::FLOAT8,
        "bool" | "boolean" => Type::BOOL,
        "date" => Type::DATE,
        "time" => Type::TIME,
        "timestamp" => Type::TIMESTAMP,
        "text" => Type::TEXT,
        _ => Type::VARCHAR,
    }
}

/// Normalise LLM-supplied columns and rows into a resolved outcome.
///
/// Nothing is encoded here: the wire format of each cell depends on what the client asked for
/// in its Bind message, which this function cannot see. See `PgOutcome::Rows`. But every value is
/// checked against its column's type here, before anything is sent, so a value that cannot be
/// represented fails the statement instead of reaching the client as something it is not —
/// `"abc"` in an `int4` column used to be sent as `0`, `"true"` in a `bool` one as `false`, and
/// `3000000000` in an `int4` one wrapped to a negative number.
///
/// `described` is the shape a Describe already promised; the answer must have that many columns,
/// and its values are checked against those types, since those are what the client decodes by.
fn build_row_outcome(
    columns: &[serde_json::Value],
    rows: &[serde_json::Value],
    described: Option<&Vec<PgColumn>>,
) -> Result<PgOutcome, Unanswerable> {
    let model_columns: Vec<PgColumn> = columns
        .iter()
        .enumerate()
        .map(|(idx, col)| {
            let name = col
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("column{}", idx + 1));
            let type_name = col.get("type").and_then(|v| v.as_str()).unwrap_or("text");
            PgColumn {
                name,
                datatype: pg_type_for(type_name),
            }
        })
        .collect();
    let columns = match described {
        Some(promised) if promised.len() != model_columns.len() => {
            return Err(Unanswerable::ShapeMismatch(format!(
                "{} column(s) answered for a statement described with {}",
                model_columns.len(),
                promised.len()
            )));
        }
        Some(promised) => promised.clone(),
        None => model_columns,
    };

    let mut values = Vec::with_capacity(rows.len());
    for row_data in rows {
        let Some(row_values) = row_data.as_array() else {
            warn!(
                "PostgreSQL: skipping row that is not an array: {}",
                row_data
            );
            continue;
        };
        // A short row is padded with NULLs and a long row is truncated: PostgreSQL requires
        // exactly one value per described column, and the LLM does occasionally miscount.
        if row_values.len() != columns.len() {
            warn!(
                "PostgreSQL: row has {} value(s) for {} column(s); padding/truncating",
                row_values.len(),
                columns.len()
            );
        }
        let mut row = Vec::with_capacity(columns.len());
        for (idx, column) in columns.iter().enumerate() {
            let value = row_values.get(idx).unwrap_or(&serde_json::Value::Null);
            row.push(coerce_cell(value, &column.datatype).map_err(|why| {
                Unanswerable::Value(format!("column {:?}: {}", column.name, why))
            })?);
        }
        values.push(row);
    }

    Ok(PgOutcome::Rows {
        columns: Arc::new(columns),
        values,
    })
}

/// A cell value as the model gave it, checked against `ty` and put in the one form
/// [`encode_value`] reads: an integer for the integer types, a number (or `"NaN"`,
/// `"Infinity"`, `"-Infinity"`) for the float types, a bool for `bool`, a string chrono parses
/// for the date and time types. Anything else is text and is sent as the model wrote it.
fn coerce_cell(value: &serde_json::Value, ty: &Type) -> Result<serde_json::Value, String> {
    use serde_json::Value;
    if value.is_null() {
        return Ok(Value::Null);
    }
    let text = || match value {
        Value::String(s) => Some(s.trim().to_string()),
        _ => None,
    };
    match *ty {
        Type::INT2 | Type::INT4 | Type::INT8 => {
            let n = match value {
                Value::Number(n) => n
                    .as_i64()
                    .or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64)),
                Value::String(_) => text().and_then(|s| s.parse::<i64>().ok()),
                _ => None,
            }
            .ok_or_else(|| format!("{value} is not an integer"))?;
            let (min, max) = match *ty {
                Type::INT2 => (i16::MIN as i64, i16::MAX as i64),
                Type::INT4 => (i32::MIN as i64, i32::MAX as i64),
                _ => (i64::MIN, i64::MAX),
            };
            if n < min || n > max {
                return Err(format!("{n} is out of range for {}", ty.name()));
            }
            Ok(serde_json::json!(n))
        }
        Type::FLOAT4 | Type::FLOAT8 => match value {
            Value::Number(n) => Ok(serde_json::json!(n.as_f64().unwrap_or(0.0))),
            Value::String(_) => {
                let s = text().unwrap_or_default();
                match s.parse::<f64>() {
                    Ok(f) if f.is_finite() => Ok(serde_json::json!(f)),
                    Ok(_) => Ok(Value::String(s)),
                    Err(_) => Err(format!("{value} is not a number")),
                }
            }
            _ => Err(format!("{value} is not a number")),
        },
        Type::BOOL => match value {
            Value::Bool(b) => Ok(Value::Bool(*b)),
            Value::Number(n) if n.as_i64() == Some(0) || n.as_i64() == Some(1) => {
                Ok(Value::Bool(n.as_i64() == Some(1)))
            }
            Value::String(_) => match text().unwrap_or_default().to_ascii_lowercase().as_str() {
                "t" | "true" | "yes" | "on" | "1" => Ok(Value::Bool(true)),
                "f" | "false" | "no" | "off" | "0" => Ok(Value::Bool(false)),
                _ => Err(format!("{value} is not a boolean")),
            },
            _ => Err(format!("{value} is not a boolean")),
        },
        Type::DATE => text()
            .filter(|s| parse_date(s).is_some())
            .map(Value::String)
            .ok_or_else(|| format!("{value} is not a date (YYYY-MM-DD)")),
        Type::TIME => text()
            .filter(|s| parse_time(s).is_some())
            .map(Value::String)
            .ok_or_else(|| format!("{value} is not a time (HH:MM:SS)")),
        Type::TIMESTAMP => text()
            .filter(|s| parse_timestamp(s).is_some())
            .map(Value::String)
            .ok_or_else(|| format!("{value} is not a timestamp (YYYY-MM-DD HH:MM:SS)")),
        _ => Ok(value.clone()),
    }
}

fn parse_date(s: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
}

fn parse_time(s: &str) -> Option<chrono::NaiveTime> {
    chrono::NaiveTime::parse_from_str(s, "%H:%M:%S%.f")
        .or_else(|_| chrono::NaiveTime::parse_from_str(s, "%H:%M"))
        .ok()
}

fn parse_timestamp(s: &str) -> Option<chrono::NaiveDateTime> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f"))
        .ok()
}

/// The result format the client asked for, for column `idx`.
///
/// `pgwire`'s `Format::format_for` indexes `Individual(codes)[idx]` unchecked, and the client
/// chooses both how many format codes to send and — through the model's answer — how many
/// columns come back, so a Bind naming fewer codes than we produce columns would panic the
/// connection task. Text is the protocol's default for an unspecified column.
fn format_for(format: &pgwire::api::portal::Format, idx: usize, columns: usize) -> FieldFormat {
    match format {
        pgwire::api::portal::Format::Individual(codes) if idx >= codes.len() => {
            warn!(
                "PostgreSQL: Bind sent {} result format code(s) for {} column(s); defaulting \
                 column {} to text",
                codes.len(),
                columns,
                idx
            );
            FieldFormat::Text
        }
        other => other.format_for(idx),
    }
}

/// Build the row description for `columns`, taking each column's wire format from `format_of`.
fn fields_for(
    columns: &[PgColumn],
    format_of: impl Fn(usize) -> FieldFormat,
) -> Arc<Vec<FieldInfo>> {
    Arc::new(
        columns
            .iter()
            .enumerate()
            .map(|(idx, col)| {
                FieldInfo::new(
                    col.name.clone(),
                    None,
                    None,
                    col.datatype.clone(),
                    format_of(idx),
                )
            })
            .collect(),
    )
}

/// Encode each row against `fields`, using the format each field carries.
fn encode_rows(
    fields: &Arc<Vec<FieldInfo>>,
    values: &[Vec<serde_json::Value>],
) -> Vec<PgWireResult<DataRow>> {
    values
        .iter()
        .map(|row| {
            let mut encoder = DataRowEncoder::new(Arc::clone(fields));
            for (idx, field) in fields.iter().enumerate() {
                let value = row.get(idx).unwrap_or(&serde_json::Value::Null);
                encode_value(&mut encoder, field.datatype(), field.format(), value)?;
            }
            Ok(encoder.take_row())
        })
        .collect()
}

/// Encode one cell, already checked by [`coerce_cell`].
///
/// `format` is not decoration: in the extended protocol tokio-postgres (and libpq, and every
/// other driver) binds with **binary** result formats by default and then decodes each cell by
/// the type in the RowDescription — so a date has to be a chrono date here, not its text, or a
/// binary `date` column carries ten ASCII bytes where the client reads a 4-byte day count.
fn encode_value(
    encoder: &mut DataRowEncoder,
    field_type: &Type,
    format: FieldFormat,
    value: &serde_json::Value,
) -> PgWireResult<()> {
    let options = FormatOptions::default();
    if value.is_null() {
        return encoder.encode_field_with_type_and_format(
            &None::<&str>,
            field_type,
            format,
            &options,
        );
    }
    let text = value.as_str().unwrap_or_default();
    let float = || {
        value
            .as_f64()
            .or_else(|| text.parse::<f64>().ok())
            .unwrap_or(f64::NAN)
    };
    match *field_type {
        Type::INT2 => encoder.encode_field_with_type_and_format(
            &(value.as_i64().unwrap_or_default() as i16),
            &Type::INT2,
            format,
            &options,
        ),
        Type::INT4 => encoder.encode_field_with_type_and_format(
            &(value.as_i64().unwrap_or_default() as i32),
            &Type::INT4,
            format,
            &options,
        ),
        Type::INT8 => encoder.encode_field_with_type_and_format(
            &value.as_i64().unwrap_or_default(),
            &Type::INT8,
            format,
            &options,
        ),
        Type::FLOAT4 => encoder.encode_field_with_type_and_format(
            &(float() as f32),
            &Type::FLOAT4,
            format,
            &options,
        ),
        Type::FLOAT8 => {
            encoder.encode_field_with_type_and_format(&float(), &Type::FLOAT8, format, &options)
        }
        Type::BOOL => encoder.encode_field_with_type_and_format(
            &value.as_bool().unwrap_or_default(),
            &Type::BOOL,
            format,
            &options,
        ),
        Type::DATE => match parse_date(text) {
            Some(d) => encoder.encode_field_with_type_and_format(&d, &Type::DATE, format, &options),
            None => encoder.encode_field_with_type_and_format(
                &None::<&str>,
                field_type,
                format,
                &options,
            ),
        },
        Type::TIME => match parse_time(text) {
            Some(t) => encoder.encode_field_with_type_and_format(&t, &Type::TIME, format, &options),
            None => encoder.encode_field_with_type_and_format(
                &None::<&str>,
                field_type,
                format,
                &options,
            ),
        },
        Type::TIMESTAMP => match parse_timestamp(text) {
            Some(ts) => {
                encoder.encode_field_with_type_and_format(&ts, &Type::TIMESTAMP, format, &options)
            }
            None => encoder.encode_field_with_type_and_format(
                &None::<&str>,
                field_type,
                format,
                &options,
            ),
        },
        _ => {
            let value_str = json_value_to_string(value);
            encoder.encode_field_with_type_and_format(
                &value_str.as_str(),
                field_type,
                format,
                &options,
            )
        }
    }
}

/// The values the client bound to `portal`'s parameters, as the model is given them.
///
/// Text-format values are strings, as PostgreSQL receives them. Binary-format values are decoded
/// by their parameter type — integers, floats, bools and text — and a binary value of any other
/// type is refused (`0A000`) rather than handed on as bytes, which nothing could read. A Bind
/// whose counts do not match the statement is the protocol error PostgreSQL answers with
/// `08P01`.
fn bound_parameters(portal: &Portal<PgStatement>) -> PgWireResult<Vec<serde_json::Value>> {
    use pgwire::api::portal::Format;
    let refuse = |code: &str, message: String| {
        PgWireError::UserError(Box::new(ErrorInfo::new(
            "ERROR".to_string(),
            code.to_string(),
            message,
        )))
    };
    let types = &portal.statement.statement.param_types;
    if portal.parameters.len() != types.len() {
        return Err(refuse(
            "08P01",
            format!(
                "bind message supplies {} parameters, but prepared statement \"{}\" requires {}",
                portal.parameters.len(),
                portal.statement.id,
                types.len()
            ),
        ));
    }
    let mut out = Vec::with_capacity(types.len());
    for (idx, raw) in portal.parameters.iter().enumerate() {
        let Some(bytes) = raw else {
            out.push(serde_json::Value::Null);
            continue;
        };
        let format = match &portal.parameter_format {
            Format::Individual(codes) if idx >= codes.len() => {
                return Err(refuse(
                    "08P01",
                    format!(
                        "bind message has {} parameter formats but {} parameters",
                        codes.len(),
                        portal.parameters.len()
                    ),
                ));
            }
            other => other.format_for(idx),
        };
        let ty = &types[idx];
        let as_text = |b: &[u8]| {
            std::str::from_utf8(b)
                .map(|s| serde_json::json!(s))
                .map_err(|_| {
                    refuse(
                        "22021",
                        format!(
                            "invalid byte sequence for encoding \"UTF8\" in parameter ${}",
                            idx + 1
                        ),
                    )
                })
        };
        if format == FieldFormat::Text {
            out.push(as_text(bytes)?);
            continue;
        }
        let wrong_length = || {
            refuse(
                "22P03",
                format!("incorrect binary data format in bind parameter {}", idx + 1),
            )
        };
        let value = match *ty {
            Type::INT2 => serde_json::json!(i16::from_be_bytes(
                bytes.as_ref().try_into().map_err(|_| wrong_length())?
            )),
            Type::INT4 => serde_json::json!(i32::from_be_bytes(
                bytes.as_ref().try_into().map_err(|_| wrong_length())?
            )),
            Type::INT8 => serde_json::json!(i64::from_be_bytes(
                bytes.as_ref().try_into().map_err(|_| wrong_length())?
            )),
            Type::FLOAT4 => serde_json::json!(f32::from_be_bytes(
                bytes.as_ref().try_into().map_err(|_| wrong_length())?
            )),
            Type::FLOAT8 => serde_json::json!(f64::from_be_bytes(
                bytes.as_ref().try_into().map_err(|_| wrong_length())?
            )),
            Type::BOOL => match bytes.as_ref() {
                [b] => serde_json::json!(*b != 0),
                _ => return Err(wrong_length()),
            },
            Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME | Type::UNKNOWN => {
                as_text(bytes)?
            }
            _ => {
                return Err(refuse(
                    "0A000",
                    format!(
                        "binary-format parameter ${} of type {} is not supported; bind it in text \
                         format",
                        idx + 1,
                        ty.name()
                    ),
                ))
            }
        };
        out.push(value);
    }
    Ok(out)
}

#[async_trait::async_trait]
impl SimpleQueryHandler for PostgresqlHandler {
    async fn do_query<C>(&self, _client: &mut C, query: &str) -> PgWireResult<Vec<Response>>
    where
        C: ClientInfo + Unpin + Send + Sync,
    {
        match self.resolve(query, &Binding::default()).await? {
            // The simple query protocol has no format negotiation: every cell is text.
            PgOutcome::Rows { columns, values } => {
                let fields = fields_for(&columns, |_| FieldFormat::Text);
                let rows = encode_rows(&fields, &values);
                Ok(vec![Response::Query(QueryResponse::new(
                    fields,
                    futures::stream::iter(rows),
                ))])
            }
            PgOutcome::Tag(tag) => Ok(vec![Response::Execution(Tag::new(&tag))]),
            PgOutcome::Close => Err(terminating_error()),
        }
    }
}

#[async_trait::async_trait]
impl ExtendedQueryHandler for PostgresqlHandler {
    type Statement = PgStatement;
    type QueryParser = PostgresqlQueryParser;

    fn query_parser(&self) -> Arc<Self::QueryParser> {
        Arc::new(PostgresqlQueryParser)
    }

    async fn do_query<C>(
        &self,
        _client: &mut C,
        portal: &Portal<Self::Statement>,
        _max_rows: usize,
    ) -> PgWireResult<Response>
    where
        C: ClientInfo + Unpin + Send + Sync,
    {
        let statement = &portal.statement.statement;
        let binding = Binding {
            parameters: Some(bound_parameters(portal)?),
            parameter_types: statement.param_types.clone(),
            described: None,
        };

        // `max_rows` is pgwire's: it sends at most that many DataRows and then PortalSuspended.
        match self.take_or_resolve(&statement.sql, binding).await? {
            // Encode each cell in the format this portal's Bind asked for - binary, for every
            // mainstream driver, on every column whose type has a binary representation.
            PgOutcome::Rows { columns, values } => {
                let fields = fields_for(&columns, |idx| {
                    format_for(&portal.result_column_format, idx, columns.len())
                });
                let rows = encode_rows(&fields, &values);
                Ok(Response::Query(QueryResponse::new(
                    fields,
                    futures::stream::iter(rows),
                )))
            }
            PgOutcome::Tag(tag) => Ok(Response::Execution(Tag::new(&tag))),
            PgOutcome::Close => Err(terminating_error()),
        }
    }

    async fn do_describe_statement<C>(
        &self,
        _client: &mut C,
        stmt: &StoredStatement<Self::Statement>,
    ) -> PgWireResult<DescribeStatementResponse>
    where
        C: ClientInfo + Unpin + Send + Sync,
    {
        // The schema is whatever the model returns, so it has to be resolved here rather than
        // guessed. Describing a *statement* happens before any Bind, so no result format has
        // been chosen yet (PostgreSQL sends format 0, text, in that RowDescription; the portal's
        // own Describe carries the real one) — and, for a statement with parameters, no value
        // has been bound either. The ParameterDescription lists one type per `$n`.
        let statement = &stmt.statement;
        let binding = Binding {
            parameters: statement.param_types.is_empty().then(Vec::new),
            parameter_types: statement.param_types.clone(),
            described: None,
        };
        let fields = self
            .resolve_for_describe(&statement.sql, binding, |_, _| FieldFormat::Text)
            .await?;
        Ok(DescribeStatementResponse::new(
            statement.param_types.clone(),
            fields,
        ))
    }

    async fn do_describe_portal<C>(
        &self,
        _client: &mut C,
        portal: &Portal<Self::Statement>,
    ) -> PgWireResult<DescribePortalResponse>
    where
        C: ClientInfo + Unpin + Send + Sync,
    {
        let statement = &portal.statement.statement;
        let binding = Binding {
            parameters: Some(bound_parameters(portal)?),
            parameter_types: statement.param_types.clone(),
            described: self.described_columns(&statement.sql).await,
        };
        let fields = self
            .resolve_for_describe(&statement.sql, binding, |idx, columns| {
                format_for(&portal.result_column_format, idx, columns)
            })
            .await?;
        Ok(DescribePortalResponse::new(fields))
    }
}

/// A parsed statement: its text, and one type per parameter (`$1` … `$n`).
#[derive(Debug, Clone)]
pub struct PgStatement {
    pub sql: String,
    pub param_types: Vec<Type>,
}

/// Query parser for PostgreSQL: keeps the text, and works out the statement's parameters.
pub struct PostgresqlQueryParser;

#[async_trait::async_trait]
impl pgwire::api::stmt::QueryParser for PostgresqlQueryParser {
    type Statement = PgStatement;

    async fn parse_sql<C>(
        &self,
        _client: &C,
        sql: &str,
        types: &[Option<Type>],
    ) -> PgWireResult<Option<Self::Statement>>
    where
        C: ClientInfo + Unpin + Send + Sync,
    {
        // pgwire stores a syntactically empty statement itself and never calls this for one, so
        // every statement reaching here is one the model answers.
        Ok(Some(PgStatement {
            sql: sql.to_string(),
            param_types: parameter_types(sql, types),
        }))
    }

    // pgwire's default `do_describe_*` read these; this server overrides both, because the
    // result schema is whatever the model answers and only resolving the statement says it.
    fn get_parameter_types(&self, stmt: &Self::Statement) -> PgWireResult<Vec<Type>> {
        Ok(stmt.param_types.clone())
    }

    fn get_result_schema(
        &self,
        _stmt: &Self::Statement,
        _column_format: Option<&pgwire::api::portal::Format>,
    ) -> PgWireResult<Vec<FieldInfo>> {
        Ok(Vec::new())
    }
}

/// One type per parameter the statement uses: the type the Parse message named for it, or
/// `text` where it named none (0, unspecified, or an OID pgwire does not know) — PostgreSQL
/// infers a type from context, which a server without a planner cannot, and an unknown-typed
/// literal resolves to `text` there too.
///
/// The count is the larger of the types the Parse named and the highest `$n` in the text, so a
/// client that names no types (tokio-postgres) is told how many values to bind.
pub fn parameter_types(sql: &str, named: &[Option<Type>]) -> Vec<Type> {
    let count = named.len().max(highest_placeholder(sql));
    (0..count)
        .map(|idx| match named.get(idx) {
            Some(Some(t)) if *t != Type::UNKNOWN => t.clone(),
            _ => Type::TEXT,
        })
        .collect()
}

/// The highest `$n` placeholder in `sql`, skipping string literals, quoted identifiers,
/// dollar-quoted strings and comments, where a `$1` is text rather than a parameter.
pub fn highest_placeholder(sql: &str) -> usize {
    let b = sql.as_bytes();
    let mut highest = 0usize;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\'' | b'"' => {
                let quote = b[i];
                i += 1;
                while i < b.len() {
                    if b[i] == quote {
                        if b.get(i + 1) == Some(&quote) {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                i += 1;
            }
            b'-' if b.get(i + 1) == Some(&b'-') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                // Block comments nest in PostgreSQL.
                let mut depth = 0usize;
                while i < b.len() {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            }
            b'$' => {
                let start = i + 1;
                let mut j = start;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                if j > start {
                    // A parameter. Bind carries an Int16 count, so anything past that is no
                    // parameter a client could bind; it is ignored rather than allocated for.
                    if let Ok(n) = sql[start..j].parse::<usize>() {
                        if n <= u16::MAX as usize {
                            highest = highest.max(n);
                        }
                    }
                    i = j;
                    continue;
                }
                // `$tag$ … $tag$` or `$$ … $$`: a dollar-quoted string.
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                    j += 1;
                }
                if j < b.len() && b[j] == b'$' && !b[start].is_ascii_digit() {
                    let tag = &b[i..=j];
                    let body = j + 1;
                    match b[body..].windows(tag.len()).position(|w| w == tag) {
                        Some(end) => i = body + end + tag.len(),
                        None => i = b.len(),
                    }
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    highest
}

/// Convert JSON value to string representation
fn json_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "".to_string(),
        serde_json::Value::Bool(b) => if *b { "t" } else { "f" }.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => value.to_string(),
    }
}

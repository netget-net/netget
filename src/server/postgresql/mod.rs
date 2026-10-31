//! PostgreSQL server implementation using pgwire
pub mod actions;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
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
use tracing::{debug, error, info, warn};

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
    ) -> Result<SocketAddr> {
        let listener = TcpListener::bind(listen_addr).await?;
        let actual_addr = listener.local_addr()?;

        info!("PostgreSQL server starting on {}", actual_addr);
        let _ = status_tx.send(format!(
            "[INFO] PostgreSQL server listening on {}",
            actual_addr
        ));

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
                            match tokio::time::timeout(
                                FIRST_BYTE_READ_TIMEOUT,
                                stream.peek(&mut [0u8; 1]),
                            )
                            .await
                            {
                                Ok(Ok(0)) | Ok(Err(_)) => return,
                                Ok(Ok(_)) => {}
                                Err(_) => {
                                    console_debug!(
                                        conn_status_tx,
                                        "PostgreSQL connection {} sent nothing for {}s; \
                                         closing before startup",
                                        connection_id,
                                        FIRST_BYTE_READ_TIMEOUT.as_secs()
                                    );
                                    return;
                                }
                            }

                            // `process_socket` runs in a task of its own so a **panic** inside
                            // pgwire is contained rather than lost.
                            //
                            // Upstream pgwire 0.35 panics decoding a malformed frontend message
                            // (a Query with no NUL, six bytes after the handshake; IMPROVEMENTS
                            // #77). The copy in `vendor/pgwire` answers those FATAL 08P01 and
                            // returns `InvalidData` instead, but a `[patch]` does not reach the
                            // crate as published to crates.io, and any other panic in pgwire or
                            // in our handler would take the same path.
                            //
                            // What NetGet can do is not lose the connection's bookkeeping to
                            // it. The panic used to unwind straight past
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
                                process_socket(stream, None, handler_factory).await
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
                                    IDLE_SESSION_TIMEOUT,
                                )
                                .await;
                                console_debug!(
                                    watchdog_status,
                                    "PostgreSQL connection {} idle for {}s; closing",
                                    connection_id,
                                    IDLE_SESSION_TIMEOUT.as_secs()
                                );
                                abort_handle.abort();
                            }));

                            let joined = (&mut inner.0).await;
                            match joined {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) if e.kind() == std::io::ErrorKind::InvalidData => {
                                    // The vendored pgwire refused a message that does not
                                    // decode and has already answered it FATAL 08P01.
                                    error!(
                                        "PostgreSQL connection {} decision=refused_malformed_message: {}",
                                        connection_id, e
                                    );
                                    let _ = conn_status_tx.send(format!(
                                        "[WARN] PostgreSQL connection {} closed: the peer sent a \
                                         malformed message ({})",
                                        connection_id, e
                                    ));
                                }
                                Ok(Err(e)) => {
                                    error!("PostgreSQL connection error: {:?}", e);
                                }
                                Err(join_error) if join_error.is_panic() => {
                                    error!(
                                        "PostgreSQL connection {} decision=connection_aborted_decoder_panic: \
                                         pgwire panicked decoding a message from the peer (a \
                                         malformed frame; IMPROVEMENTS #77). The connection is \
                                         closed; the server is unaffected.",
                                        connection_id
                                    );
                                    let _ = conn_status_tx.send(format!(
                                        "[ERROR] PostgreSQL connection {} killed by a malformed \
                                         message (pgwire decoder panic)",
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
                            // Mark the connection closed so it does not stay Active forever
                            // in the server's connection map.
                            if let Some(server_id) = conn_server_id {
                                conn_state_owner
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                            }
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

/// A connection-scoped cache shared by the simple and extended handlers.
type DescribeCache = Arc<TokioMutex<Vec<(String, PgOutcome)>>>;

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
    async fn resolve(&self, sql: &str) -> PgWireResult<PgOutcome> {
        // Everything from here to the end of this call is the peer *waiting on us* — the LLM
        // round-trip, and a `manual` rule parking the statement for a human. The idle watchdog
        // must not count any of it, so the connection is marked busy for the whole of it and
        // the guard's `Drop` clears the mark on every exit path, including the `?`-shaped ones.
        let _busy = self.activity.busy();
        debug!("PostgreSQL query: {}", sql);
        let _ = self
            .status_tx
            .send(format!("[DEBUG] PostgreSQL query: {}", sql));

        self.record_stats(Some(sql.len() as u64), None, Some(1), None)
            .await;

        let mut event_data = serde_json::json!({ "query": sql });
        if let Some(hint) = actions::answer_with_for_query(sql) {
            event_data["answer_with"] = serde_json::json!(hint);
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
                error!(
                    "PostgreSQL connection {} decision={} sqlstate={}: {}",
                    self.connection_id, decision, code, e
                );
                let message = crate::utils::WireFailure::classify(&e).prefixed_text();
                let _ = self
                    .status_tx
                    .send(format!("[ERROR] PostgreSQL {}: {}", code, message));
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
                        return build_row_outcome(&columns, &rows);
                    }
                    "postgresql_ok" => {
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

                        let _ = self.status_tx.send(format!(
                            "[ERROR] PostgreSQL error {} {}: {}",
                            severity, code, message
                        ));
                        // A refusal the model chose, not a backend failure — tagged so the log
                        // distinguishes the two, as `radius` does.
                        warn!(
                            "PostgreSQL connection {} decision=model_reject sqlstate={}: {}",
                            self.connection_id, code, message
                        );
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
        warn!(
            "PostgreSQL: no response action produced for {:?} (decision=fail_closed_no_action)",
            sql
        );
        let _ = self.status_tx.send(
            "[ERROR] PostgreSQL: no response action produced (decision=fail_closed_no_action)"
                .to_string(),
        );
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

    /// Resolve `sql`, storing the outcome so a following Execute reuses it (one LLM call per
    /// extended-protocol statement instead of one per Describe *and* one per Execute).
    async fn resolve_for_describe(
        &self,
        sql: &str,
        format_of: impl Fn(usize, usize) -> FieldFormat,
    ) -> PgWireResult<Vec<FieldInfo>> {
        let outcome = self.resolve(sql).await?;
        let fields = match &outcome {
            PgOutcome::Rows { columns, .. } => {
                fields_for(columns, |idx| format_of(idx, columns.len()))
                    .as_ref()
                    .clone()
            }
            _ => Vec::new(),
        };

        let mut cache = self.describe_cache.lock().await;
        cache.retain(|(key, _)| key != sql);
        if cache.len() >= MAX_PENDING_DESCRIBES {
            cache.remove(0);
        }
        cache.push((sql.to_string(), outcome));

        Ok(fields)
    }

    /// Take a previously described outcome, or resolve fresh if Execute arrived without one.
    async fn take_or_resolve(&self, sql: &str) -> PgWireResult<PgOutcome> {
        let cached = {
            let mut cache = self.describe_cache.lock().await;
            cache
                .iter()
                .position(|(key, _)| key == sql)
                .map(|idx| cache.remove(idx).1)
        };

        match cached {
            Some(outcome) => Ok(outcome),
            None => self.resolve(sql).await,
        }
    }
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
        _ => Type::VARCHAR,
    }
}

/// Normalise LLM-supplied columns and rows into a resolved outcome.
///
/// Nothing is encoded here: the wire format of each cell depends on what the client asked for
/// in its Bind message, which this function cannot see. See `PgOutcome::Rows`.
fn build_row_outcome(
    columns: &[serde_json::Value],
    rows: &[serde_json::Value],
) -> PgWireResult<PgOutcome> {
    let columns: Vec<PgColumn> = columns
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
        values.push(
            (0..columns.len())
                .map(|idx| {
                    row_values
                        .get(idx)
                        .cloned()
                        .unwrap_or(serde_json::Value::Null)
                })
                .collect(),
        );
    }

    Ok(PgOutcome::Rows {
        columns: Arc::new(columns),
        values,
    })
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
            encoder.finish()
        })
        .collect()
}

/// Encode one cell.
///
/// `format` is not decoration: in the extended protocol tokio-postgres (and libpq, and every
/// other driver) binds with **binary** result formats by default and then decodes each cell by
/// the type in the RowDescription. This used to hardcode `FieldFormat::Text` for every cell
/// while the client had asked for binary, so `SELECT` through `client.query(...)` came back as
/// "error deserializing column 0" for every non-text column — while `simple_query`, which has
/// no format negotiation and is always text, worked perfectly. Every test in this directory
/// used `simple_query`, so the whole extended path went unmeasured; the tests' own CLAUDE.md
/// recorded the symptom as an unexplained "Extended Query Protocol Timeout … UNRESOLVED".
fn encode_value(
    encoder: &mut DataRowEncoder,
    field_type: &Type,
    format: FieldFormat,
    value: &serde_json::Value,
) -> PgWireResult<()> {
    if value.is_null() {
        return encoder.encode_field_with_type_and_format(
            &None::<&str>,
            field_type,
            format,
            &FormatOptions::default(),
        );
    }

    match *field_type {
        Type::INT2 => encoder.encode_field_with_type_and_format(
            &(value.as_i64().unwrap_or(0) as i16),
            &Type::INT2,
            format,
            &FormatOptions::default(),
        ),
        Type::INT4 => encoder.encode_field_with_type_and_format(
            &(value.as_i64().unwrap_or(0) as i32),
            &Type::INT4,
            format,
            &FormatOptions::default(),
        ),
        Type::INT8 => encoder.encode_field_with_type_and_format(
            &value.as_i64().unwrap_or(0),
            &Type::INT8,
            format,
            &FormatOptions::default(),
        ),
        Type::FLOAT4 => encoder.encode_field_with_type_and_format(
            &(value.as_f64().unwrap_or(0.0) as f32),
            &Type::FLOAT4,
            format,
            &FormatOptions::default(),
        ),
        Type::FLOAT8 => encoder.encode_field_with_type_and_format(
            &value.as_f64().unwrap_or(0.0),
            &Type::FLOAT8,
            format,
            &FormatOptions::default(),
        ),
        Type::BOOL => encoder.encode_field_with_type_and_format(
            &value.as_bool().unwrap_or(false),
            &Type::BOOL,
            format,
            &FormatOptions::default(),
        ),
        _ => {
            let value_str = json_value_to_string(value);
            encoder.encode_field_with_type_and_format(
                &value_str.as_str(),
                field_type,
                format,
                &FormatOptions::default(),
            )
        }
    }
}

#[async_trait::async_trait]
impl SimpleQueryHandler for PostgresqlHandler {
    async fn do_query<C>(&self, _client: &mut C, query: &str) -> PgWireResult<Vec<Response>>
    where
        C: ClientInfo + Unpin + Send + Sync,
    {
        match self.resolve(query).await? {
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
    type Statement = String;
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
        let sql = &portal.statement.statement;

        match self.take_or_resolve(sql).await? {
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
        // The schema is whatever the LLM returns, so it has to be resolved here rather than
        // guessed. Previously this returned an unconditional empty field list, which told
        // every extended-protocol client that the statement produced zero columns and then
        // sent it data rows anyway.
        // Describing a *statement* happens before any Bind, so no result format has been
        // chosen yet. PostgreSQL sends format code 0 (text) in that RowDescription; the
        // portal's own Describe, below, carries the real one.
        let fields = self
            .resolve_for_describe(&stmt.statement, |_, _| FieldFormat::Text)
            .await?;
        Ok(DescribeStatementResponse::new(vec![], fields))
    }

    async fn do_describe_portal<C>(
        &self,
        _client: &mut C,
        portal: &Portal<Self::Statement>,
    ) -> PgWireResult<DescribePortalResponse>
    where
        C: ClientInfo + Unpin + Send + Sync,
    {
        let fields = self
            .resolve_for_describe(&portal.statement.statement, |idx, columns| {
                format_for(&portal.result_column_format, idx, columns)
            })
            .await?;
        Ok(DescribePortalResponse::new(fields))
    }
}

/// Query parser for PostgreSQL
pub struct PostgresqlQueryParser;

#[async_trait::async_trait]
impl pgwire::api::stmt::QueryParser for PostgresqlQueryParser {
    type Statement = String;

    async fn parse_sql<C>(
        &self,
        _client: &C,
        sql: &str,
        _types: &[Type],
    ) -> PgWireResult<Self::Statement>
    where
        C: ClientInfo + Unpin + Send + Sync,
    {
        Ok(sql.to_string())
    }
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

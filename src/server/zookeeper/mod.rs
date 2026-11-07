//! ZooKeeper server implementation.
//!
//! # Session lifecycle
//!
//! A ZooKeeper connection starts with a `ConnectRequest`, which carries **neither an xid nor
//! an opcode**:
//!
//! ```text
//! [4 len][4 protocolVersion][8 lastZxidSeen][4 timeOut][8 sessionId][4 len][16 passwd][1 readOnly?]
//! ```
//!
//! It is therefore parsed separately from every later frame, and answered with a
//! `ConnectResponse` (`protocolVersion, timeOut, sessionId, passwd[, readOnly]`). Until that
//! reply lands, a real client blocks and never issues a request — which is exactly why every
//! opcode below used to be dead code.
//!
//! The handshake is **answered in Rust and deliberately does not call the LLM**. It carries no
//! content decision (it is timeout negotiation and an opaque session id), and routing it
//! through the model would mean a model outage or a refusal could not be told apart from a
//! successful session — the fail-open shape this project treats as its most dangerous pattern.
//! Pings (opcode 11) and `closeSession` (opcode -11) are answered in Rust for the same reason:
//! a real ZooKeeper answers them itself, and an idle session must not burn one LLM call per
//! ping interval to stay alive.
//!
//! Everything a *handler* can decide — the reply body for `getData`, `getChildren`, `exists`,
//! `create`, and the error code for any of them — still goes through `call_llm` and the
//! protocol's actions.
//!
//! # No session state
//!
//! The server keeps no session table (see the no-storage rule in the root `CLAUDE.md`). A
//! client that presents a non-zero `sessionId` is taken at its word and that id is echoed back
//! along with the password it presented, so a reconnect resumes rather than being reported as
//! expired. Nothing is ever expired, because nothing is ever tracked.
//!
//! See `src/server/zookeeper/CLAUDE.md` for the remaining limitations.

pub mod actions;

use crate::console_debug;
use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use actions::{ZookeeperProtocol, ZOOKEEPER_REQUEST_EVENT};
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// How long to wait for the ConnectRequest from a peer that has only connected.
///
/// ZooKeeper is client-speaks-first: the ConnectRequest is the first frame on the wire and the
/// server says nothing before it. Every real client sends it inside its connect path. A peer
/// that has opened the socket and said nothing has not started a session, so it gets the short
/// bound — and this is the one an unauthenticated flood lives under.
const CONNECT_REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Floor under the session-derived idle bound (see [`idle_timeout_for`]).
///
/// [`MIN_SESSION_TIMEOUT_MS`] is four seconds, and doubling it leaves eight — short enough that
/// a scheduling hiccup on a loaded test runner could close a healthy session. Thirty seconds
/// costs nothing against an attacker (who never reaches this bound at all: it applies only
/// after a session exists) and removes that failure mode.
const MIN_IDLE_AFTER_CONNECT: std::time::Duration = std::time::Duration::from_secs(30);

/// Concurrent connections this server admits.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// A peer over [`MAX_CONNECTIONS`] gets a plain close, which is exactly what a real ZooKeeper
/// does.
///
/// There is no pre-session error frame in the protocol — the first thing the server may write
/// is a ConnectResponse, and writing one would *admit* the peer rather than refuse it, which is
/// the fail-open shape this codebase treats as its most dangerous pattern. Real ZooKeeper
/// hitting `maxClientCnxns` closes the socket without a reply and logs "Too many connections
/// from …"; this does the same, and the log line carries `decision=fail_closed_connection_cap`.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// The idle bound for a connection that has a session, derived from that session.
///
/// This is the protocol answering the question itself. A real ZooKeeper server expires a
/// session when it has heard nothing from the client for the *negotiated* session timeout, and
/// the client pings at a third of that interval precisely so an idle-but-live session keeps
/// proving it is alive. So the bound is not a number picked here at all — it is the value this
/// very connection negotiated, doubled, so a client that misses a ping is not punished for it,
/// and floored at [`MIN_IDLE_AFTER_CONNECT`]. With [`MAX_SESSION_TIMEOUT_MS`] at 40s the
/// widest this can be is 80 seconds.
fn idle_timeout_for(session: &ZookeeperSession) -> std::time::Duration {
    std::time::Duration::from_millis(session.timeout_ms.max(0) as u64 * 2)
        .max(MIN_IDLE_AFTER_CONNECT)
}
use tracing::{debug, error, info, trace, warn};

/// ZooKeeper's `SystemError` (-1): "this did not work", as the protocol defines it.
///
/// Used wherever a reply's `error_code` is absent. Code 0 is `Ok`, so defaulting to 0 tells a
/// client that a create or a setData it never confirmed actually happened.
const ZK_SYSTEM_ERROR: i64 = -1;

/// ZooKeeper server implementation
pub struct ZookeeperServer {
    llm_client: OllamaClient,
    #[allow(dead_code)]
    app_state: Arc<AppState>,
    #[allow(dead_code)]
    status_tx: mpsc::UnboundedSender<String>,
    server_id: Option<crate::state::ServerId>,
}

impl ZookeeperServer {
    /// Create a new ZooKeeper server
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

    /// Spawn ZooKeeper server with LLM integration
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

        crate::logging::emit::Log::to(&status_tx)
            .info(format!("ZooKeeper server listening on {}", actual_addr));
        let server = Arc::new(ZookeeperServer::new(
            llm_client,
            app_state.clone(),
            status_tx.clone(),
            Some(server_id),
        ));

        let status_tx_clone = status_tx.clone();

        // Spawn the accept loop
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "ZooKeeper",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, addr, permit)) => {
                        console_debug!(status_tx, "ZooKeeper connection from {}", addr);

                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);

                        // Clone server components for the connection handler
                        let server_clone = Arc::clone(&server);
                        let status_tx_conn = status_tx_clone.clone();
                        let app_state_conn = app_state.clone();
                        let server_id_opt = server.server_id;

                        // Spawn connection handler
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection, so the cap counts live
                                // sessions rather than accepts.
                                let _permit = permit;
                                if let Err(e) = Self::handle_connection(
                                    stream,
                                    server_clone,
                                    status_tx_conn,
                                    connection_id,
                                    app_state_conn,
                                    server_id_opt,
                                )
                                .await
                                {
                                    error!("ZooKeeper connection error: {}", e);
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        // A persistent accept error (EMFILE, ENFILE, socket torn down) recurs
                        // immediately, so continuing here spins a hot loop that floods the
                        // unbounded status channel. Give up the listener instead.
                        crate::logging::emit::Log::to(&status_tx_clone)
                            .error(format!("ZooKeeper accept failed, listener stopped: {}", e));
                        break;
                    }
                }
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(actual_addr)
    }

    /// Handle a single ZooKeeper connection
    async fn handle_connection(
        stream: TcpStream,
        server: Arc<ZookeeperServer>,
        status_tx: mpsc::UnboundedSender<String>,
        connection_id: ConnectionId,
        app_state: Arc<AppState>,
        server_id: Option<crate::state::ServerId>,
    ) -> Result<()> {
        let peer_addr = stream.peer_addr().ok();
        let local_addr = stream.local_addr().ok();

        // Track the connection so the TUI/MCP connection list and stop_server see it.
        if let (Some(server_id), Some(remote_addr)) = (server_id, peer_addr) {
            let now = crate::utils::clock::Instant::now();
            app_state
                .add_connection_to_server(
                    server_id,
                    crate::state::server::ConnectionState {
                        id: connection_id,
                        remote_addr,
                        local_addr: local_addr.unwrap_or(remote_addr),
                        bytes_sent: 0,
                        bytes_received: 0,
                        packets_sent: 0,
                        packets_received: 0,
                        last_activity: now,
                        status: crate::state::server::ConnectionStatus::Active,
                        status_changed_at: now,
                        protocol_info: crate::state::server::ProtocolConnectionInfo::empty(),
                    },
                )
                .await;
        }

        let (read_half, write_half) = tokio::io::split(stream);
        let write_half = Arc::new(tokio::sync::Mutex::new(write_half));

        // Peer messaging: the dashboard's "message this peer" / "disconnect this peer" inject
        // an action into THIS connection. Registered before the first frame is read, so the
        // operator can reach a connection that is parked on a manual rule. The wire verbs
        // return `ActionResult::Custom`, so a protocol-owned task (not the generic
        // `spawn_peer_command_task`) drains the channel and frames the reply exactly as the
        // LLM path does.
        if let Some(server_id) = server_id {
            let peer_rx = crate::server::peer_support::register_peer_channel(
                &app_state,
                server_id,
                connection_id.as_u32(),
            )
            .await;
            Self::spawn_peer_command_task(
                peer_rx,
                app_state.clone(),
                server_id,
                connection_id,
                write_half.clone(),
                status_tx.clone(),
            )
            .await;
        }
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let result = Self::run_connection(
            read_half,
            &write_half,
            server,
            connection_id,
            app_state.clone(),
            server_id,
        )
        .await;

        // Every exit path - EOF, read error, bad first frame, closeSession, close_connection -
        // lands here.
        if let Some(server_id) = server_id {
            app_state
                .remove_peer_handle(server_id, connection_id.as_u32())
                .await;
            app_state
                .close_connection_on_server(server_id, connection_id)
                .await;
        }
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        result
    }

    /// Drain injected actions for one connection.
    ///
    /// Mirrors `peer_support::handle_peer_command` (executor, access-log entry, outcome reply,
    /// close bookkeeping) with one addition: a `zookeeper_response` Custom result is framed
    /// through [`Self::custom_reply_body`] — the same function the LLM path uses — and written
    /// to the shared write half. An injected reply that names no `xid` is sent with xid -1,
    /// the only xid a real ZooKeeper server ever originates (watch notifications): nothing
    /// else can be correlated to a request the operator cannot see.
    async fn spawn_peer_command_task<W>(
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        app_state: Arc<AppState>,
        server_id: crate::state::ServerId,
        connection_id: ConnectionId,
        write_half: Arc<tokio::sync::Mutex<W>>,
        status_tx: mpsc::UnboundedSender<String>,
    ) where
        W: AsyncWriteExt + Unpin + Send + 'static,
    {
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        let protocol: Arc<ZookeeperProtocol> = Arc::new(ZookeeperProtocol::new());
        // Tracked, not detached: stop_server must abort this task too.
        let task_owner = app_state.clone();
        task_owner
            .spawn_server_task(server_id, async move {
                while let Some(command) = command_rx.recv().await {
                    let action = command.action.clone();
                    let outcome = Self::execute_injected_action(
                        protocol.as_ref(),
                        &app_state,
                        server_id,
                        connection_id,
                        &write_half,
                        &action,
                    )
                    .await;

                    let outcome_json = match &outcome {
                        Ok(outcome) => {
                            serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null)
                        }
                        Err(e) => serde_json::json!({"error": e.to_string()}),
                    };
                    app_state
                        .record_access_log(
                            AccessLogOwner::Server(server_id.as_u32()),
                            "zookeeper",
                            Some(connection_id.as_u32()),
                            "injected_action",
                            action,
                            vec![outcome_json],
                        )
                        .await;

                    match &outcome {
                        Err(e) => warn!(
                            "injected action on ZooKeeper server #{} connection {} failed: {}",
                            server_id.as_u32(),
                            connection_id,
                            e
                        ),
                        Ok(ClientSendOutcome::Disconnected) => {
                            app_state
                                .remove_peer_handle(server_id, connection_id.as_u32())
                                .await;
                            app_state
                                .close_connection_on_server(server_id, connection_id)
                                .await;
                        }
                        Ok(_) => {}
                    }
                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                    let _ = command.reply_tx.send(outcome);
                }
                debug!(
                    "peer command task for ZooKeeper server #{} connection {} ended",
                    server_id.as_u32(),
                    connection_id
                );
            })
            .await;
    }

    async fn execute_injected_action<W>(
        protocol: &ZookeeperProtocol,
        app_state: &Arc<AppState>,
        server_id: crate::state::ServerId,
        connection_id: ConnectionId,
        write_half: &Arc<tokio::sync::Mutex<W>>,
        action: &serde_json::Value,
    ) -> Result<crate::state::client_handles::ClientSendOutcome>
    where
        W: AsyncWriteExt + Unpin,
    {
        use crate::state::client_handles::ClientSendOutcome;

        let result = crate::llm::actions::executor::execute_actions(
            vec![action.clone()],
            app_state,
            Some(protocol as &dyn crate::llm::actions::protocol_trait::Server),
            Some(server_id),
            None,
        )
        .await?;

        let mut bytes_sent = 0usize;
        let mut closed = false;
        let mut details: Vec<String> = Vec::new();
        let mut stack: Vec<ActionResult> = result.protocol_results;
        stack.reverse();
        while let Some(item) = stack.pop() {
            match item {
                ActionResult::Custom { name, data } if name == "zookeeper_response" => {
                    let body = Self::custom_reply_body(&data, INJECTED_DEFAULT_XID);
                    bytes_sent += Self::write_frame(
                        write_half,
                        app_state,
                        Some(server_id),
                        connection_id,
                        &body,
                    )
                    .await?;
                }
                ActionResult::Output(bytes) => {
                    let mut write = write_half.lock().await;
                    write.write_all(&bytes).await?;
                    write.flush().await?;
                    drop(write);
                    Self::count_written(app_state, Some(server_id), connection_id, bytes.len())
                        .await;
                    bytes_sent += bytes.len();
                }
                ActionResult::Multiple(items) => {
                    for inner in items.into_iter().rev() {
                        stack.push(inner);
                    }
                }
                // Half-close; the peer reads EOF and the reader's own exit path runs.
                ActionResult::CloseConnection => {
                    let mut write = write_half.lock().await;
                    write.shutdown().await?;
                    closed = true;
                }
                ActionResult::WaitForMore | ActionResult::NoAction => {}
                other => details.push(format!("{other:?}")),
            }
        }

        if closed {
            Ok(ClientSendOutcome::Disconnected)
        } else if bytes_sent > 0 {
            Ok(ClientSendOutcome::Sent { bytes_sent })
        } else if details.is_empty() {
            Ok(ClientSendOutcome::Executed {
                detail: "executed (nothing to write)".to_string(),
            })
        } else {
            Ok(ClientSendOutcome::Executed {
                detail: crate::utils::truncate_for_log(&details.join("; "), 160),
            })
        }
    }

    async fn run_connection<R, W>(
        mut read_half: R,
        write_half: &Arc<tokio::sync::Mutex<W>>,
        server: Arc<ZookeeperServer>,
        connection_id: ConnectionId,
        app_state: Arc<AppState>,
        server_id: Option<crate::state::ServerId>,
    ) -> Result<()>
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        debug!("ZooKeeper connection {} established", connection_id);

        // A session exists only after the ConnectRequest/ConnectResponse exchange. Until then
        // the next frame is *not* a request header and must not be parsed as one.
        let mut session: Option<ZookeeperSession> = None;

        loop {
            // Both reads below are bounded by this deadline, and nothing else in the loop is.
            // The LLM round-trip that answers the request, and a `manual` rule parking it for a
            // human (`src/state/intercepts.rs`, 300s by default), happen further down once the
            // whole frame has arrived — so neither is inside a read deadline and neither can be
            // cut short by one. What is bounded is a peer that holds the connection while
            // sending nothing, and one that announces a frame length and then stalls.
            let read_timeout = match session.as_ref() {
                Some(session) => idle_timeout_for(session),
                None => CONNECT_REQUEST_READ_TIMEOUT,
            };

            // Read ZooKeeper request header (4 bytes length + payload)
            let mut len_buf = [0u8; 4];
            let header_read = match tokio::time::timeout(
                read_timeout,
                read_half.read_exact(&mut len_buf),
            )
            .await
            {
                Ok(read) => read,
                Err(_) => {
                    debug!(
                        "ZooKeeper connection {} sent nothing for {}s; closing idle \
                             connection",
                        connection_id,
                        read_timeout.as_secs()
                    );
                    break;
                }
            };
            match header_read {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("ZooKeeper client disconnected");
                    break;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }

            // The length prefix is a signed jute int and arrives from the network. Validate it
            // as i32 *before* widening: `negative as usize` sign-extends to ~1.8e19, and any
            // check performed after the cast is checking a number the sender never sent.
            let declared_len = i32::from_be_bytes(len_buf);
            if declared_len < MIN_REQUEST_BYTES || declared_len > MAX_REQUEST_BYTES {
                return Err(anyhow::anyhow!(
                    "ZooKeeper request length out of range: {} (expected {}..={})",
                    declared_len,
                    MIN_REQUEST_BYTES,
                    MAX_REQUEST_BYTES
                ));
            }
            let len = declared_len as usize;

            // Read payload
            let mut payload = vec![0u8; len];
            match tokio::time::timeout(read_timeout, read_half.read_exact(&mut payload)).await {
                Ok(read) => read?,
                Err(_) => {
                    debug!(
                        "ZooKeeper connection {} announced {} octets and stalled for {}s \
                         without delivering them; closing",
                        connection_id,
                        len,
                        read_timeout.as_secs()
                    );
                    break;
                }
            };
            if let Some(server_id) = server_id {
                app_state
                    .update_connection_stats(
                        server_id,
                        connection_id,
                        Some((4 + len) as u64),
                        None,
                        Some(1),
                        None,
                    )
                    .await;
            }

            trace!(
                "ZooKeeper connection {} received {} bytes",
                connection_id,
                len
            );

            // The first frame on a connection is the session handshake, not a request.
            if session.is_none() {
                let connect = match Self::parse_connect_request(&payload) {
                    Ok(connect) => connect,
                    Err(e) => {
                        // Refuse rather than guess. Treating an unrecognised opening frame as a
                        // request header is precisely the bug this replaced: it turned every
                        // connect into `operation: "unknown"` and left the client waiting for a
                        // ConnectResponse that never came.
                        warn!(
                            "ZooKeeper connection {}: first frame is not a ConnectRequest ({}); \
                             closing",
                            connection_id, e
                        );
                        return Err(e);
                    }
                };

                let established = ZookeeperSession::negotiate(&connect, connection_id);
                Self::write_frame(
                    write_half,
                    &app_state,
                    server_id,
                    connection_id,
                    &established.connect_response(),
                )
                .await?;

                info!(
                    "ZooKeeper connection {} session established: id={:#018x} timeout={}ms \
                     (client asked {}ms) read_only={}",
                    connection_id,
                    established.session_id,
                    established.timeout_ms,
                    connect.timeout_ms,
                    established.read_only,
                );
                session = Some(established);
                continue;
            }

            // Parse request (simplified - just extract op type)
            let request_info = Self::parse_request(&payload)?;

            // Protocol mechanics the server owns; see the module docs for why these do not
            // reach the LLM.
            match request_info.op_code {
                OP_PING => {
                    trace!("ZooKeeper connection {} ping", connection_id);
                    Self::write_frame(
                        write_half,
                        &app_state,
                        server_id,
                        connection_id,
                        &Self::reply(request_info.xid, 0, 0, &[]),
                    )
                    .await?;
                    continue;
                }
                OP_CLOSE_SESSION => {
                    debug!(
                        "ZooKeeper connection {} closed its session on request",
                        connection_id
                    );
                    Self::write_frame(
                        write_half,
                        &app_state,
                        server_id,
                        connection_id,
                        &Self::reply(request_info.xid, 0, 0, &[]),
                    )
                    .await?;
                    return Ok(());
                }
                _ => {}
            }

            // Call LLM with request event. The xid must be in the event data: it is the only
            // thing a client uses to match a reply to its request, and without it neither the
            // model nor a script/static handler can echo it back.
            let event = Event::new(
                &ZOOKEEPER_REQUEST_EVENT,
                serde_json::json!({
                    "xid": request_info.xid,
                    "operation": request_info.operation,
                    "op_code": request_info.op_code,
                    "path": request_info.path,
                }),
            );

            let server_id = server_id.unwrap_or_else(|| crate::state::ServerId::new(0));

            let protocol = Arc::new(ZookeeperProtocol::new());

            match call_llm(
                &server.llm_client,
                &app_state,
                server_id,
                Some(connection_id),
                &event,
                protocol.as_ref(),
            )
            .await
            {
                Ok(execution_result) => {
                    // Execute actions
                    let mut answered = false;
                    for result in execution_result.protocol_results {
                        match result {
                            ActionResult::Custom { name, data } if name == "zookeeper_response" => {
                                answered = true;
                                // A handler that omitted the xid gets the request's own xid
                                // rather than 0: xid 0 is never a valid reply to a real
                                // request (negative xids are reserved for pings and watch
                                // notifications) and leaves the client waiting forever.
                                // ZooKeeper error code 0 is `Ok`. Defaulting to it means a
                                // model that produced a reply without deciding an outcome
                                // tells the client the operation succeeded - and for a
                                // create or a setData, the client then proceeds as though a
                                // znode exists. -1 is `SystemError`, the code the protocol
                                // defines for "this did not work", which is the honest
                                // answer for a reply nobody finished describing.
                                let error_code = data
                                    .get("error_code")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(ZK_SYSTEM_ERROR);
                                let response = Self::custom_reply_body(&data, request_info.xid);
                                let sent = Self::write_frame(
                                    write_half,
                                    &app_state,
                                    Some(server_id),
                                    connection_id,
                                    &response,
                                )
                                .await?;

                                // Three outcomes must be told apart in the log: the handler
                                // refused (a real decision), the handler said nothing, and the
                                // LLM call failed. This is the first of the three.
                                if error_code != 0 {
                                    debug!(
                                        "ZooKeeper connection {} decision=model_reject \
                                         operation={} xid={} error_code={}",
                                        connection_id,
                                        request_info.operation,
                                        request_info.xid,
                                        error_code
                                    );
                                }
                                trace!(
                                    "ZooKeeper sent {} bytes to connection {}",
                                    sent,
                                    connection_id,
                                );
                            }
                            ActionResult::CloseConnection => {
                                debug!("ZooKeeper closing connection {}", connection_id);
                                return Ok(());
                            }
                            _ => {}
                        }
                    }

                    if !answered {
                        // The handler ran but produced no reply. ZooKeeper is strictly
                        // request/response and correlates by xid alone, so writing nothing
                        // leaves the client blocked until its own session timeout. Answer with
                        // a bare error header — no body, and nothing derived from netget's
                        // internals can appear in one.
                        crate::logging::emit::Log::to(&server.status_tx).warn(format!(
                            "ZooKeeper connection {} decision=fail_closed_no_answer operation={} \
                             xid={}: handler produced no zookeeper_response; replying \
                             ZSYSTEMERROR",
                            connection_id, request_info.operation, request_info.xid
                        ));
                        Self::write_frame(
                            write_half,
                            &app_state,
                            Some(server_id),
                            connection_id,
                            &Self::reply(request_info.xid, 0, ZSYSTEMERROR, &[]),
                        )
                        .await?;
                    }
                }
                Err(e) => {
                    // Fail closed, but audibly: the peer gets a category, the log gets the
                    // error. ZooKeeper replies carry no free-text field, so the categories are
                    // expressed as distinct error codes — ZOPERATIONTIMEOUT is the transient
                    // one a client retries, ZSYSTEMERROR the one it reports.
                    let failure = crate::utils::WireFailure::classify(&e);
                    let (code, class) = match failure {
                        crate::utils::WireFailure::Overloaded => {
                            (ZOPERATIONTIMEOUT, "fail_closed_overloaded")
                        }
                        crate::utils::WireFailure::Unavailable => {
                            (ZSYSTEMERROR, "fail_closed_llm_error")
                        }
                    };
                    let log = crate::logging::emit::Log::to(&server.status_tx);
                    log.error(format!(
                        "ZooKeeper connection {} decision={} operation={} xid={} \
                         reply_error_code={}: LLM error: {}",
                        connection_id,
                        class,
                        request_info.operation,
                        request_info.xid,
                        code,
                        crate::utils::truncate_for_log(&e.to_string(), 200)
                    ));
                    log.debug(format!(
                        "ZooKeeper connection {} xid={} full LLM error: {:#}",
                        connection_id, request_info.xid, e
                    ));
                    Self::write_frame(
                        write_half,
                        &app_state,
                        Some(server_id),
                        connection_id,
                        &Self::reply(request_info.xid, 0, code, &[]),
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }

    /// Turn a `zookeeper_response` Custom result (as produced by `ZookeeperProtocol::
    /// execute_action`) into a reply body. `default_xid` is used when the action named none.
    fn custom_reply_body(data: &serde_json::Value, default_xid: i32) -> Vec<u8> {
        let xid = data
            .get("xid")
            .and_then(|v| v.as_i64())
            .map(|v| v as i32)
            .unwrap_or(default_xid);
        let zxid = data.get("zxid").and_then(|v| v.as_i64()).unwrap_or(0);
        // Same reasoning as the reply path above: absent means failure, not success. The cast
        // is range-checked too - an out-of-range code narrowed by `as i32` could land on 0.
        let error_code = data
            .get("error_code")
            .and_then(|v| v.as_i64())
            .and_then(|v| i32::try_from(v).ok())
            .unwrap_or(ZK_SYSTEM_ERROR as i32);
        let body = data
            .get("body_hex")
            .and_then(|v| v.as_str())
            .map(hex::decode)
            .transpose()
            .unwrap_or_default()
            .unwrap_or_default();
        Self::reply(xid, zxid, error_code, &body)
    }

    /// Write one length-prefixed ZooKeeper frame through the shared write half and count it.
    /// Returns the number of bytes put on the wire (prefix included). The guard is dropped
    /// before the stats update so nothing awaits on the state while holding the socket.
    async fn write_frame<W: AsyncWriteExt + Unpin>(
        write_half: &Arc<tokio::sync::Mutex<W>>,
        app_state: &Arc<AppState>,
        server_id: Option<crate::state::ServerId>,
        connection_id: ConnectionId,
        body: &[u8],
    ) -> Result<usize> {
        {
            let mut write = write_half.lock().await;
            write.write_all(&(body.len() as i32).to_be_bytes()).await?;
            write.write_all(body).await?;
            write.flush().await?;
        }
        let sent = 4 + body.len();
        Self::count_written(app_state, server_id, connection_id, sent).await;
        Ok(sent)
    }

    async fn count_written(
        app_state: &Arc<AppState>,
        server_id: Option<crate::state::ServerId>,
        connection_id: ConnectionId,
        bytes: usize,
    ) {
        if let Some(server_id) = server_id {
            app_state
                .update_connection_stats(
                    server_id,
                    connection_id,
                    None,
                    Some(bytes as u64),
                    None,
                    Some(1),
                )
                .await;
        }
    }

    /// Build a reply body: `xid (4) + zxid (8) + error code (4) + operation-specific body`.
    fn reply(xid: i32, zxid: i64, error_code: i32, body: &[u8]) -> Vec<u8> {
        let mut response = Vec::with_capacity(16 + body.len());
        response.extend_from_slice(&xid.to_be_bytes());
        response.extend_from_slice(&zxid.to_be_bytes());
        response.extend_from_slice(&error_code.to_be_bytes());
        response.extend_from_slice(body);
        response
    }

    /// Parse the opening `ConnectRequest`.
    ///
    /// ```text
    /// protocolVersion i32 | lastZxidSeen i64 | timeOut i32 | sessionId i64
    /// passwd  (i32 length, always 16, followed by that many bytes)
    /// readOnly u8   (optional — pre-3.4 clients omit it)
    /// ```
    ///
    /// Validation is deliberately strict. The shape is distinctive (`protocolVersion` is 0 and
    /// the password buffer is exactly 16 bytes), so a frame that fails these checks is not a
    /// ZooKeeper client and gets a closed connection rather than a reply it cannot use.
    fn parse_connect_request(payload: &[u8]) -> Result<ZookeeperConnectRequest> {
        if payload.len() < CONNECT_REQUEST_LEN {
            return Err(anyhow::anyhow!(
                "ConnectRequest too short: {} bytes (expected at least {})",
                payload.len(),
                CONNECT_REQUEST_LEN
            ));
        }
        if payload.len() > CONNECT_REQUEST_LEN + 1 {
            return Err(anyhow::anyhow!(
                "ConnectRequest too long: {} bytes (expected {} or {})",
                payload.len(),
                CONNECT_REQUEST_LEN,
                CONNECT_REQUEST_LEN + 1
            ));
        }

        let protocol_version = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if protocol_version != 0 {
            return Err(anyhow::anyhow!(
                "unsupported ZooKeeper protocol version {}",
                protocol_version
            ));
        }

        let last_zxid_seen = i64::from_be_bytes([
            payload[4],
            payload[5],
            payload[6],
            payload[7],
            payload[8],
            payload[9],
            payload[10],
            payload[11],
        ]);
        let timeout_ms = i32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let session_id = i64::from_be_bytes([
            payload[16],
            payload[17],
            payload[18],
            payload[19],
            payload[20],
            payload[21],
            payload[22],
            payload[23],
        ]);

        let passwd_len = i32::from_be_bytes([payload[24], payload[25], payload[26], payload[27]]);
        if passwd_len != SESSION_PASSWD_LEN as i32 {
            return Err(anyhow::anyhow!(
                "ConnectRequest password length is {} (expected {})",
                passwd_len,
                SESSION_PASSWD_LEN
            ));
        }
        let passwd = payload[28..CONNECT_REQUEST_LEN].to_vec();

        // Pre-3.4 clients stop here; newer ones append a readOnly flag. Which of the two it
        // was decides whether the reply carries the flag, so it is remembered rather than
        // defaulted.
        let read_only = payload.get(CONNECT_REQUEST_LEN).map(|b| *b != 0);

        Ok(ZookeeperConnectRequest {
            last_zxid_seen,
            timeout_ms,
            session_id,
            passwd,
            read_only,
        })
    }

    /// Parse the ZooKeeper request header.
    ///
    /// Only the header (xid, opcode) and the leading path string are read; the rest of the
    /// Jute-encoded body is not decoded. This is called only *after* the session handshake —
    /// a `ConnectRequest` has neither an xid nor an opcode and is handled by
    /// [`Self::parse_connect_request`].
    fn parse_request(payload: &[u8]) -> Result<ZookeeperRequest> {
        if payload.len() < 8 {
            return Ok(ZookeeperRequest {
                xid: 0,
                op_code: 0,
                operation: "unknown".to_string(),
                path: String::new(),
            });
        }

        // Read xid (transaction id)
        let xid = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

        // Read op type
        let op_type = i32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

        let operation = match op_type {
            OP_CLOSE_SESSION => "closeSession",
            1 => "create",
            2 => "delete",
            3 => "exists",
            4 => "getData",
            5 => "setData",
            6 => "getACL",
            7 => "setACL",
            8 => "getChildren",
            9 => "sync",
            11 => "ping",
            12 => "getChildren2",
            13 => "check",
            14 => "multi",
            _ => "unknown",
        };

        // Try to extract the path (a jute ustring: signed length + bytes).
        //
        // The length is validated as i32 against the bytes actually remaining. Casting first
        // was a remote panic: a length of -1 became usize::MAX, `12 + usize::MAX` wrapped to
        // 11, `payload.len() >= 11` passed, and `&payload[12..11]` panicked with start > end.
        let path = if payload.len() >= 12 {
            let declared = i32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
            let available = payload.len() - 12;
            if declared > 0 && (declared as usize) <= available {
                String::from_utf8_lossy(&payload[12..12 + declared as usize]).to_string()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        Ok(ZookeeperRequest {
            xid,
            op_code: op_type,
            operation: operation.to_string(),
            path,
        })
    }
}

/// Smallest payload that can carry a request header (xid + opcode).
const MIN_REQUEST_BYTES: i32 = 8;
/// Matches ZooKeeper's own `jute.maxbuffer` default of 1 MiB.
pub const MAX_REQUEST_BYTES: i32 = 1024 * 1024;

/// xid for an injected reply that names none. -1 is the watch-notification xid, the one frame a
/// real server originates on its own; any other value would claim to answer a request.
const INJECTED_DEFAULT_XID: i32 = -1;

/// ZooKeeper API error codes used when netget itself cannot answer.
///
/// They are the two categories of `crate::utils::WireFailure` mapped onto the codes a real
/// ZooKeeper uses, and they are deliberately different: `ZOPERATIONTIMEOUT` reads as transient
/// (a client backs off and retries), `ZSYSTEMERROR` as a server-side fault. Both send a
/// header-only reply — a ZooKeeper error frame carries no body, which is also why this
/// protocol cannot leak an internal error string onto the wire.
const ZSYSTEMERROR: i32 = -1;
const ZOPERATIONTIMEOUT: i32 = -7;

/// Opcodes the server answers itself rather than handing to a handler.
const OP_PING: i32 = 11;
const OP_CLOSE_SESSION: i32 = -11;

/// `ConnectRequest` length without the optional trailing `readOnly` byte.
const CONNECT_REQUEST_LEN: usize = 44;
/// ZooKeeper session passwords are always 16 bytes.
const SESSION_PASSWD_LEN: usize = 16;

/// ZooKeeper's own defaults: `minSessionTimeout = 2 * tickTime`,
/// `maxSessionTimeout = 20 * tickTime`, with the default `tickTime` of 2000 ms.
const MIN_SESSION_TIMEOUT_MS: i32 = 4_000;
const MAX_SESSION_TIMEOUT_MS: i32 = 40_000;

struct ZookeeperRequest {
    xid: i32,
    op_code: i32,
    operation: String,
    path: String,
}

/// The opening `ConnectRequest`, as sent by the client.
struct ZookeeperConnectRequest {
    #[allow(dead_code)]
    last_zxid_seen: i64,
    timeout_ms: i32,
    session_id: i64,
    passwd: Vec<u8>,
    /// `None` when the client omitted the field (pre-3.4 wire format).
    read_only: Option<bool>,
}

/// A negotiated session. Held for the life of the connection; nothing is stored beyond it.
struct ZookeeperSession {
    session_id: i64,
    timeout_ms: i32,
    passwd: Vec<u8>,
    read_only: bool,
    /// Whether the client's `ConnectRequest` carried a `readOnly` field. The reply mirrors it:
    /// appending the byte for a client that did not send one is harmless for most clients but
    /// is not what a real server does.
    echo_read_only: bool,
}

impl ZookeeperSession {
    fn negotiate(req: &ZookeeperConnectRequest, connection_id: ConnectionId) -> Self {
        // ZooKeeper clamps the requested timeout into the server's configured range rather
        // than rejecting it; a non-positive request gets the minimum.
        let timeout_ms = if req.timeout_ms <= 0 {
            MIN_SESSION_TIMEOUT_MS
        } else {
            req.timeout_ms
                .clamp(MIN_SESSION_TIMEOUT_MS, MAX_SESSION_TIMEOUT_MS)
        };

        // A client presenting a session id is resuming. There is no session table to check it
        // against (see the module docs), so it is honoured as-is together with its password —
        // the alternative, answering with timeout 0, tells the client its session expired,
        // which would be a lie about state we never kept.
        let (session_id, passwd) = if req.session_id != 0 {
            (req.session_id, req.passwd.clone())
        } else {
            let id = Self::mint_session_id(connection_id);
            (id, Self::derive_passwd(id))
        };

        Self {
            session_id,
            timeout_ms,
            passwd,
            // Read-only mode means "serve stale reads while partitioned from the quorum".
            // There is no quorum here, so the session is always read-write.
            read_only: false,
            echo_read_only: req.read_only.is_some(),
        }
    }

    /// A session id that is unique per connection and never zero (zero means "no session").
    fn mint_session_id(connection_id: ConnectionId) -> i64 {
        let nanos = crate::utils::clock::SystemTime::now()
            .duration_since(crate::utils::clock::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let id = ((nanos << 16) ^ u64::from(connection_id.as_u32())) & 0x7fff_ffff_ffff_ffff;
        if id == 0 {
            1
        } else {
            id as i64
        }
    }

    /// The 16-byte session password. Real ZooKeeper derives it from the session id with a
    /// digest so a client cannot forge one; there is no session table here to protect, so this
    /// only has to be stable for the session and the right length.
    fn derive_passwd(session_id: i64) -> Vec<u8> {
        let base = session_id.to_be_bytes();
        let mut passwd = Vec::with_capacity(SESSION_PASSWD_LEN);
        passwd.extend_from_slice(&base);
        passwd.extend(base.iter().map(|b| b ^ 0x5a));
        passwd
    }

    /// Encode the `ConnectResponse` body (the caller adds the length prefix).
    fn connect_response(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + 4 + 8 + 4 + SESSION_PASSWD_LEN + 1);
        body.extend_from_slice(&0i32.to_be_bytes()); // protocolVersion
        body.extend_from_slice(&self.timeout_ms.to_be_bytes());
        body.extend_from_slice(&self.session_id.to_be_bytes());
        body.extend_from_slice(&(self.passwd.len() as i32).to_be_bytes());
        body.extend_from_slice(&self.passwd);
        if self.echo_read_only {
            body.push(self.read_only as u8);
        }
        body
    }
}

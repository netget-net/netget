//! MSSQL server implementation using manual TDS protocol
pub mod actions;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use actions::{MssqlProtocol, MSSQL_QUERY_EVENT};
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

/// TDS packet size we advertise in the login ENVCHANGE and honour when writing.
const TDS_PACKET_SIZE: usize = 4096;

/// The write half of one connection, shared between the session loop and the dashboard's
/// peer-command task (`server::peer_support`).
///
/// Every handler below that used to take `&mut TcpStream` only ever *wrote* through it — the
/// reads all happen in the top-level loop — so they take this instead. The mutex is what keeps
/// an injected write from landing between the continuation packets of a TDS message.
type SharedWrite = Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>;

/// How long to wait for a peer's first TDS packet after it has connected.
///
/// TDS is client-speaks-first: PRELOGIN is the first packet and the server says nothing before
/// it. `tiberius`, `sqlcmd` and every ADO.NET driver send it inside the connect path, so a peer
/// that has connected and sent nothing has begun no session — and that is the state an
/// unauthenticated flood lives in.
const FIRST_PACKET_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to wait for a *further* packet once the peer has logged in.
///
/// SQL Server has no idle-disconnect default to copy, so the number is argued the same way
/// MySQL's and PostgreSQL's are: this server holds nothing a reconnect would lose — no tables,
/// no temp tables, no open transaction, no state the model carries between batches — so a
/// pooled connection reaped here costs one transparent reconnect. Ten minutes is far above any
/// connection pool's keepalive interval and still bounds the hold.
const IDLE_BETWEEN_PACKETS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Concurrent connections this server admits.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// A peer over [`MAX_CONNECTIONS`] gets a plain close, which is what a real SQL Server does.
///
/// TDS has no message a server may send to a client still in PRELOGIN: every server packet is a
/// typed response to a request, and a TABULAR_RESULT carrying an ERROR token read in that state
/// is a framing violation, not a diagnosis. The refusal is in the log instead, tagged
/// `decision=fail_closed_connection_cap`.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// SQL Server's own "Login failed for user '%.*ls'." error. Severity 14 is what a real
/// instance sends, and every driver already maps it to an authentication failure.
const LOGIN_FAILED_ERROR: u32 = 18456;

/// Generic user-defined error number. Anything >= 50000 is a user error, which is what an
/// LLM-driven server's failures actually are.
const MSSQL_ERROR_GENERIC: u32 = 50000;

/// "Cannot process request. Not enough resources to process request." On the standard
/// transient-error list SqlClient's built-in retry logic keys off, so a client backs off and
/// retries instead of surfacing the failure to the application.
const MSSQL_ERROR_NOT_ENOUGH_RESOURCES: u32 = 49918;

/// MSSQL server implementation
pub struct MssqlServer {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    _status_tx: mpsc::UnboundedSender<String>,
    server_id: Option<crate::state::ServerId>,
}

impl MssqlServer {
    /// Create a new MSSQL server
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

    /// Spawn MSSQL server with LLM integration
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

        Log::new(Some(&status_tx)).info(format!("MSSQL server listening on {}", actual_addr));

        let server = Arc::new(MssqlServer::new(
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
                    "MSSQL",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, addr, permit)) => {
                        Log::new(Some(&status_tx)).info(format!("MSSQL connection from {}", addr));

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

                        let handler = MssqlHandler::new(
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
                                // Held for the life of the session, so the cap counts live
                                // connections rather than accepts.
                                let _permit = permit;
                                if let Err(e) = handler.handle_connection(stream).await {
                                    error!("MSSQL connection error: {:?}", e);
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx)).error(format!("MSSQL accept error: {}", e));
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

/// MSSQL connection handler
pub struct MssqlHandler {
    connection_id: ConnectionId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    #[allow(dead_code)]
    server_id: Option<crate::state::ServerId>,
    #[allow(dead_code)]
    remote_addr: SocketAddr,
    /// MSSQL protocol handler for action execution
    protocol: Arc<MssqlProtocol>,
}

impl MssqlHandler {
    pub fn new(
        connection_id: ConnectionId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: Option<crate::state::ServerId>,
        remote_addr: SocketAddr,
    ) -> Self {
        let protocol = Arc::new(MssqlProtocol::new(
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
    /// The socket is split here rather than inside the loop, because the write half has two
    /// owners: the loop's own TDS replies and the dashboard's peer-command task. Registration
    /// happens **before the first read** — TDS is client-speaks-first, so this server says
    /// nothing until PRELOGIN arrives, and a `manual` rule can then park the login (or any
    /// later batch) for minutes. The operator has to be able to reach, or hang up, a
    /// connection that is waiting on their own answer.
    async fn handle_connection(self, stream: TcpStream) -> Result<()> {
        let server_id = self.server_id;
        let connection_id = self.connection_id;
        let app_state = self.app_state.clone();

        // Owning split, never a clone: the write half outlives this stack frame inside the
        // peer-command task.
        let (mut reader, write_half) = tokio::io::split(stream);
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

        let result = self.run_session(&mut reader, &write_half).await;

        // Every exit path — EOF, a read timeout, a refused login, an attention, a write error,
        // an injected disconnect — lands here, and none of them may `?` past it. Dropping the
        // handle also ends the peer command task, which releases its clone of the write half;
        // the explicit shutdown makes the FIN immediate rather than waiting on it.
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

        result
    }

    /// The read/dispatch/reply loop. Reads come off `reader`; every write goes through the
    /// shared `write_half`, which the peer-command task also holds.
    async fn run_session(
        &self,
        reader: &mut ReadHalf<TcpStream>,
        write_half: &SharedWrite,
    ) -> Result<()> {
        info!("MSSQL connection established");

        // Set only by an `mssql_login_ack`. Nothing else in this loop may set it, so the
        // admission decision has exactly one source.
        //
        // Without this flag the `mssql_login` decision was skippable: the loop dispatched
        // packet types independently of one another, so a peer that simply never sent a
        // LOGIN7 and opened with a SQL Batch (0x01) or an RPC (0x03) got its query answered
        // and `mssql_login` never fired at all. An instruction like "only allow the user
        // `reporting`" was then enforced against every client that asked to be checked and
        // none that did not. Real drivers always log in; a hostile peer has no reason to.
        let mut authenticated = false;

        // Handle TDS protocol negotiation and queries
        loop {
            // Both reads below are bounded by this deadline, and nothing else in the loop is.
            // The LLM round-trip that decides a login or answers a batch, and a `manual` rule
            // parking either for a human (`src/state/intercepts.rs`, 300s by default), happen
            // after a whole packet has been read — outside the deadline by construction, so
            // neither can be cut short. What is bounded is a peer holding the connection while
            // sending nothing, and one that announces a packet length and then stalls.
            let read_timeout = if authenticated {
                IDLE_BETWEEN_PACKETS_TIMEOUT
            } else {
                FIRST_PACKET_READ_TIMEOUT
            };

            // Read TDS packet header (8 bytes)
            let header = match self.read_tds_header(reader, read_timeout).await {
                Ok(h) => h,
                Err(e) => {
                    debug!("Error reading TDS header: {}", e);
                    break;
                }
            };

            if header.length < 8 {
                debug!("Invalid TDS packet length: {}", header.length);
                break;
            }

            // Read packet data
            let data_len = header.length - 8;
            let mut data = vec![0u8; data_len as usize];
            match tokio::time::timeout(read_timeout, reader.read_exact(&mut data)).await {
                Ok(read) => read?,
                Err(_) => {
                    debug!(
                        "MSSQL connection {} announced a {}-byte packet and stalled for {}s \
                         without delivering it; closing",
                        self.connection_id,
                        header.length,
                        read_timeout.as_secs()
                    );
                    break;
                }
            };

            // Only the *sent* side was counted before, so every MSSQL connection in the
            // dashboard rail showed a growing ↑ against a permanently zero ↓, and
            // `last_activity` was never refreshed by an inbound packet.
            if let Some(server_id) = self.server_id {
                self.app_state
                    .update_connection_stats(
                        server_id,
                        self.connection_id,
                        Some(u64::from(header.length)),
                        None,
                        Some(1),
                        None,
                    )
                    .await;
            }

            trace!(
                "TDS packet type: 0x{:02x}, length: {}",
                header.packet_type,
                header.length
            );

            match header.packet_type {
                0x12 => {
                    // Pre-Login
                    debug!("Received Pre-Login packet (length: {})", header.length);
                    self.send_prelogin_response(write_half).await?;
                    debug!("Pre-Login response sent");
                }
                0x10 => {
                    // TDS7/TDS8 Login
                    debug!("Received Login packet");
                    if !self.handle_login(write_half, &data).await? {
                        // Refused. The ERROR token is already on the wire; TDS has no way to
                        // continue a session whose login failed, so close.
                        break;
                    }
                    authenticated = true;
                }
                0x01 | 0x03 if !authenticated => {
                    // A statement before the session was admitted. Answer with the same 18456
                    // an outright refusal produces and close, rather than serving the query:
                    // the model was never asked about this peer, so nothing has admitted it.
                    Log::new(Some(&self.status_tx)).warn(
                        "MSSQL statement refused (decision=fail_closed_not_logged_in): the \
                         client sent a batch or RPC before any LOGIN7"
                            .to_string(),
                    );
                    self.send_error(
                        write_half,
                        LOGIN_FAILED_ERROR,
                        "Login failed. The login is from an untrusted domain and cannot be \
                         used with Windows authentication.",
                        14,
                    )
                    .await?;
                    break;
                }
                0x01 => {
                    // SQL Batch
                    debug!("Received SQL Batch packet");
                    let query = self.parse_sql_batch(&data)?;
                    debug!("SQL Query: {}", query);
                    if self.handle_query(write_half, &query).await? {
                        break;
                    }
                }
                0x03 => {
                    // RPC Request (sp_executesql, sp_prepare, etc.)
                    debug!("Received RPC Request");
                    let query = self.parse_rpc_request(&data)?;
                    if !query.is_empty() {
                        debug!("RPC Query: {}", query);
                        if self.handle_query(write_half, &query).await? {
                            break;
                        }
                    } else {
                        debug!("RPC call without extractable query (ignoring)");
                        // Send empty result set for RPCs we can't parse
                        self.send_empty_result(write_half).await?;
                    }
                }
                0x0E => {
                    // Bulk Load
                    debug!("Received Bulk Load (not implemented)");
                    self.send_error(write_half, 40002, "Bulk load not supported", 16)
                        .await?;
                }
                0x07 => {
                    // Attention (cancel)
                    debug!("Received Attention signal");
                    break;
                }
                _ => {
                    debug!("Unknown TDS packet type: 0x{:02x}", header.packet_type);
                    self.send_error(write_half, 40002, "Unknown packet type", 16)
                        .await?;
                }
            }
        }

        Ok(())
    }

    /// Read TDS packet header (8 bytes)
    async fn read_tds_header(
        &self,
        reader: &mut ReadHalf<TcpStream>,
        read_timeout: std::time::Duration,
    ) -> Result<TdsHeader> {
        let mut header_bytes = [0u8; 8];
        match tokio::time::timeout(read_timeout, reader.read_exact(&mut header_bytes)).await {
            Ok(read) => read?,
            Err(_) => {
                anyhow::bail!(
                    "peer sent nothing for {}s; closing idle connection",
                    read_timeout.as_secs()
                )
            }
        };

        Ok(TdsHeader {
            packet_type: header_bytes[0],
            status: header_bytes[1],
            length: u16::from_be_bytes([header_bytes[2], header_bytes[3]]),
            spid: u16::from_be_bytes([header_bytes[4], header_bytes[5]]),
            packet_id: header_bytes[6],
            window: header_bytes[7],
        })
    }

    /// Send Pre-Login response
    async fn send_prelogin_response(&self, write_half: &SharedWrite) -> Result<()> {
        // Simplified Pre-Login response
        // Version: 16.0.0.0 (SQL Server 2022)
        // Encryption: NOT_SUP (0x02)
        let mut response = Vec::new();

        // Calculate offsets (all token headers = 3 tokens * 5 bytes + 1 terminator = 16 bytes)
        let header_size = 16u16;
        let version_offset = header_size; // 16 (0x10)
        let version_length = 6u16;
        let encryption_offset = version_offset + version_length; // 22 (0x16)
        let encryption_length = 1u16;
        let threadid_offset = encryption_offset + encryption_length; // 23 (0x17)
        let threadid_length = 4u16;

        // Version token (0x00)
        response.push(0x00);
        response.extend_from_slice(&version_offset.to_be_bytes()); // Offset: 0x00, 0x10
        response.extend_from_slice(&version_length.to_be_bytes()); // Length: 0x00, 0x06

        // Encryption token (0x01)
        response.push(0x01);
        response.extend_from_slice(&encryption_offset.to_be_bytes()); // Offset: 0x00, 0x16
        response.extend_from_slice(&encryption_length.to_be_bytes()); // Length: 0x00, 0x01

        // ThreadID token (0x03)
        response.push(0x03);
        response.extend_from_slice(&threadid_offset.to_be_bytes()); // Offset: 0x00, 0x17
        response.extend_from_slice(&threadid_length.to_be_bytes()); // Length: 0x00, 0x04

        // Terminator
        response.push(0xFF);

        // Version data (16.0.0.0)
        response.extend_from_slice(&[0x10, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Encryption: ENCRYPT_NOT_SUP (0x02) - encryption not supported
        response.push(0x02);

        // ThreadID: 0
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        self.send_tds_packet(write_half, 0x04, &response).await
    }

    /// Ask the model whether to admit this login, and refuse unless it says yes.
    ///
    /// Every TDS Login used to be accepted unconditionally: there was no `mssql_login` event
    /// and no action that could decline one, so an operator instruction like "only allow the
    /// user `reporting`" could not be enforced and the model was never consulted. Authentication
    /// decided by default is the pattern the root CLAUDE.md calls the most dangerous here.
    ///
    /// Returns `Ok(true)` when the session may proceed. Accept requires an explicit
    /// `mssql_login_ack`; a model rejection (`mssql_error_response`), an answer containing
    /// neither, and a backend failure all refuse — and are kept apart in the log, because the
    /// wire cannot distinguish them beyond the error number.
    async fn handle_login(&self, write_half: &SharedWrite, data: &[u8]) -> Result<bool> {
        let (username, database, app_name) = parse_login7(data);

        let event = Event::new(
            &actions::MSSQL_LOGIN_EVENT,
            serde_json::json!({
                "username": username,
                "database": database,
                "app_name": app_name,
            }),
        );

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
            Ok(result) => {
                for r in &result.protocol_results {
                    if let ActionResult::Custom { name, data } = r {
                        match name.as_str() {
                            "mssql_login_ack" => {
                                let db = data
                                    .get("database")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("master");
                                Log::new(Some(&self.status_tx)).info(format!(
                                    "MSSQL login accepted for user '{}' (decision=model_accept)",
                                    username
                                ));
                                self.send_login_response_with_database(write_half, db)
                                    .await?;
                                return Ok(true);
                            }
                            "mssql_error" => {
                                let number = data
                                    .get("error_number")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(LOGIN_FAILED_ERROR as u64)
                                    as u32;
                                let message = data
                                    .get("message")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Login failed.");
                                Log::new(Some(&self.status_tx)).info(format!(
                                    "MSSQL login refused for user '{}' (decision=model_reject): {}",
                                    username, message
                                ));
                                self.send_error(write_half, number, message, 14).await?;
                                return Ok(false);
                            }
                            _ => {}
                        }
                    }
                }

                // The handler ran and produced neither verdict. Refuse: silence is not consent
                // for an authentication decision.
                Log::new(Some(&self.status_tx)).warn(format!(
                    "MSSQL login refused for user '{}' (decision=fail_closed_no_action): the \
                     handler produced no mssql_login_ack",
                    username
                ));
                self.send_error(
                    write_half,
                    LOGIN_FAILED_ERROR,
                    &format!("Login failed for user '{}'.", username),
                    14,
                )
                .await?;
                Ok(false)
            }
            Err(e) => {
                // netget could not reach a decision. Refuse, and tell the client only a
                // category — never the backend error, which names the model and the URL.
                let failure = crate::utils::WireFailure::classify(&e);
                error!(
                    "MSSQL login for user '{}' decision=fail_closed_llm_error category={:?}: {:#}",
                    username, failure, e
                );
                Log::new(Some(&self.status_tx)).warn(format!(
                    "MSSQL login refused for user '{}' (decision=fail_closed_llm_error)",
                    username
                ));
                self.send_error(write_half, LOGIN_FAILED_ERROR, failure.text(), 14)
                    .await?;
                Ok(false)
            }
        }
    }

    /// Send the LOGINACK/ENVCHANGE/DONE sequence that admits a session.
    ///
    /// Only reachable from `handle_login` once the model has explicitly accepted.
    async fn send_login_response_with_database(
        &self,
        write_half: &SharedWrite,
        db_name: &str,
    ) -> Result<()> {
        let mut response = Vec::new();

        // ENVCHANGE: Database context

        let db_name_utf16: Vec<u8> = db_name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut envchange_db = Vec::new();
        envchange_db.push(0xE3); // ENVCHANGE token
        let envchange_db_len = 1 + 1 + db_name_utf16.len() + 1 + db_name_utf16.len();
        envchange_db.extend_from_slice(&(envchange_db_len as u16).to_le_bytes());
        envchange_db.push(0x01); // Type: Database
        envchange_db.push(db_name.len() as u8); // New value length (in characters)
        envchange_db.extend_from_slice(&db_name_utf16);
        envchange_db.push(db_name.len() as u8); // Old value length (in characters)
        envchange_db.extend_from_slice(&db_name_utf16);
        response.extend_from_slice(&envchange_db);

        // ENVCHANGE: Language (us_english)
        let lang = "us_english";
        let lang_utf16: Vec<u8> = lang.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        let mut envchange_lang = Vec::new();
        envchange_lang.push(0xE3); // ENVCHANGE token
        let envchange_lang_len = 1 + 1 + lang_utf16.len() + 1 + 0; // old value is empty
        envchange_lang.extend_from_slice(&(envchange_lang_len as u16).to_le_bytes());
        envchange_lang.push(0x02); // Type: Language
        envchange_lang.push(lang.len() as u8); // New value length (in characters)
        envchange_lang.extend_from_slice(&lang_utf16);
        envchange_lang.push(0x00); // Old value length (empty)
        response.extend_from_slice(&envchange_lang);

        // ENVCHANGE: Packet size ("4096" as string)
        let pkt_size_new = "4096";
        let pkt_size_old = "512"; // Default packet size
        let pkt_size_new_utf16: Vec<u8> = pkt_size_new
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let pkt_size_old_utf16: Vec<u8> = pkt_size_old
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut envchange_pkt = Vec::new();
        envchange_pkt.push(0xE3); // ENVCHANGE token
        let envchange_pkt_len = 1 + 1 + pkt_size_new_utf16.len() + 1 + pkt_size_old_utf16.len();
        envchange_pkt.extend_from_slice(&(envchange_pkt_len as u16).to_le_bytes());
        envchange_pkt.push(0x04); // Type: Packet size
        envchange_pkt.push(pkt_size_new.len() as u8); // New value length (in characters)
        envchange_pkt.extend_from_slice(&pkt_size_new_utf16);
        envchange_pkt.push(pkt_size_old.len() as u8); // Old value length (in characters)
        envchange_pkt.extend_from_slice(&pkt_size_old_utf16);
        response.extend_from_slice(&envchange_pkt);

        // INFO message
        let msg = "Login succeeded";
        let msg_utf16: Vec<u8> = msg.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        response.push(0xAB); // INFO token
        let info_len = 4 + 1 + 1 + 2 + msg_utf16.len() + 1 + 1 + 4;
        response.extend_from_slice(&(info_len as u16).to_le_bytes());
        response.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Error number
        response.push(0x01); // State
        response.push(0x00); // Class (severity)
        response.extend_from_slice(&(msg.len() as u16).to_le_bytes()); // Message length (character count)
        response.extend_from_slice(&msg_utf16);
        response.push(0x00); // Server name length
        response.push(0x00); // Procedure name length
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Line number

        // DONE token
        response.push(0xFD); // DONE token
        response.extend_from_slice(&[0x00, 0x00]); // Status
        response.extend_from_slice(&[0x00, 0x00]); // CurCmd
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // DoneRowCount

        self.send_tds_packet(write_half, 0x04, &response).await
    }

    /// Parse SQL Batch packet
    fn parse_sql_batch(&self, data: &[u8]) -> Result<String> {
        // SQL Batch format:
        // - Header (22 bytes for TDS 7.4+)
        // - SQL text (Unicode UTF-16LE)

        if data.len() < 22 {
            return Ok(String::new());
        }

        // Skip header, extract SQL text
        let sql_bytes = &data[22..];

        // Decode UTF-16LE
        let sql_u16: Vec<u16> = sql_bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        Ok(String::from_utf16_lossy(&sql_u16).trim().to_string())
    }

    /// Recover the SQL text from an RPC Request packet.
    ///
    /// RPC parameter marshalling is not decoded; the statement is found heuristically by
    /// looking for a SQL keyword in the UTF-16LE payload. Two properties matter and both were
    /// wrong before:
    ///
    /// * **One decode, not one per offset.** This used to slide a 2000-byte window forward two
    ///   bytes at a time, decoding and upper-casing it at every position: ~32,000 windows for a
    ///   maximum-size TDS packet, each allocating two strings and running eight substring
    ///   searches, with no `.await` anywhere to yield the worker. A single 64 KB packet was
    ///   seconds of CPU on a tokio worker thread, repeatable by one connection. Every window sat
    ///   on the same UTF-16 code-unit grid (the step is 2 bytes and so is a code unit), so
    ///   decoding the payload once covers exactly the same text.
    /// * **`to_ascii_uppercase`, never `to_uppercase`.** The offset of the keyword was taken
    ///   from the upper-cased string and then used to slice the *original* one. Unicode
    ///   case mapping changes byte length - U+FB01 `ﬁ` upper-cases to the two bytes `FI`, U+0149
    ///   `ŉ` to the three bytes `ʼN` - so a payload carrying one such character ahead of the
    ///   keyword sliced the original mid-character and panicked. That is reachable from the
    ///   wire, and the panic skipped `handle_connection`'s teardown, leaving the connection
    ///   `Active` in the dashboard for the life of the process. ASCII case folding never
    ///   changes a byte's width, so the offset stays valid in both strings.
    fn parse_rpc_request(&self, data: &[u8]) -> Result<String> {
        /// Keywords a statement may open with, searched for case-insensitively.
        const SQL_KEYWORDS: [&str; 7] = [
            "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER",
        ];

        if data.len() < 10 {
            return Ok(String::new());
        }

        let preview_len = std::cmp::min(data.len(), 200);
        let hex_preview: String = data[..preview_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        debug!(
            "RPC data preview (first {} bytes): {}",
            preview_len, hex_preview
        );

        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let text = String::from_utf16_lossy(&units);
        let upper = text.to_ascii_uppercase();

        // The earliest keyword anywhere in the payload, not the first keyword in list order:
        // a packet mentioning DELETE in a parameter name before its actual SELECT should not
        // have the SELECT truncated away.
        let Some(pos) = SQL_KEYWORDS.iter().filter_map(|kw| upper.find(kw)).min() else {
            return Ok(String::new());
        };

        // `upper` is ASCII-folded `text`, so byte lengths and char boundaries are identical
        // and `pos` indexes the same character in both.
        let sql: String = text[pos..]
            .chars()
            .take_while(|c| {
                c.is_ascii() && (*c == '\n' || *c == '\r' || *c == '\t' || !c.is_ascii_control())
            })
            .collect();
        let sql = sql.trim().to_string();
        if sql.is_empty() {
            return Ok(String::new());
        }

        debug!("Extracted SQL from RPC at offset {}: {}", pos, sql);
        Ok(sql)
    }

    /// Handle SQL query with LLM.
    ///
    /// Returns `true` when the LLM asked to close the connection.
    async fn handle_query(&self, write_half: &SharedWrite, query: &str) -> Result<bool> {
        trace!("Calling LLM for MSSQL query: {}", query);

        // Create query event
        let event = Event::new(
            &MSSQL_QUERY_EVENT,
            serde_json::json!({
                "query": query,
            }),
        );

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
                let close_requested = execution_result
                    .protocol_results
                    .iter()
                    .any(|r| matches!(r, ActionResult::CloseConnection));
                let mut responded = false;

                // Process action results to find MSSQL responses
                for result in execution_result.protocol_results {
                    if responded {
                        // TDS is strictly one token stream per statement, so only the first
                        // response-producing action can reach the wire. Say which ones were
                        // dropped rather than discarding them silently.
                        if let ActionResult::Custom { name, .. } = &result {
                            warn!(
                                "MSSQL: query already answered, ignoring extra action result '{}'",
                                name
                            );
                        }
                        continue;
                    }
                    match result {
                        ActionResult::Custom { name, data } => match name.as_str() {
                            "mssql_query_response" => {
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

                                self.send_result_set(write_half, columns, rows).await?;
                                responded = true;
                            }
                            "mssql_error" => {
                                let error_number = data
                                    .get("error_number")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(50000)
                                    as u32;
                                let message = data
                                    .get("message")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unknown error");
                                let severity =
                                    data.get("severity").and_then(|v| v.as_u64()).unwrap_or(16)
                                        as u8;

                                // The model chose to refuse this statement. Tagged so an
                                // operator can tell a deliberate refusal from netget failing
                                // to obtain one; the two are indistinguishable on the wire.
                                Log::new(Some(&self.status_tx)).info(format!(
                                    "MSSQL query decision=model_reject error={} severity={}",
                                    error_number, severity
                                ));
                                self.send_error(write_half, error_number, message, severity)
                                    .await?;
                                responded = true;
                            }
                            "mssql_ok" => {
                                let rows_affected = data
                                    .get("rows_affected")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0);

                                self.send_done(write_half, rows_affected).await?;
                                responded = true;
                            }
                            other => {
                                warn!(
                                    "MSSQL: no wire encoding for action result '{}', ignoring",
                                    other
                                );
                            }
                        },
                        _ => {}
                    }
                }

                if !responded {
                    // TDS clients block until a DONE or an ERROR arrives, so something must be
                    // sent. It must not be a bare DONE: in SQL that reads as "the statement ran
                    // and matched nothing", which is a meaningful *successful* answer. Nobody
                    // answered this query, so the fail-closed token is ERROR.
                    //
                    // An explicit `close_this_connection` is the one exception - that is the
                    // model deciding, not the model going quiet - so it keeps the DONE it has
                    // always produced and is tagged as its own decision.
                    if close_requested {
                        Log::new(Some(&self.status_tx))
                            .info("MSSQL query decision=model_close (closing without a result)");
                        self.send_done(write_half, 0).await?;
                    } else {
                        let message = crate::utils::WireFailure::Unavailable.prefixed_text();
                        Log::new(Some(&self.status_tx)).warn(format!(
                            "MSSQL query decision=fail_closed_no_action; replying error {}: {}",
                            MSSQL_ERROR_GENERIC, message
                        ));
                        warn!("MSSQL: no response action produced for query {:?}", query);
                        self.send_error(write_half, MSSQL_ERROR_GENERIC, message, 16)
                            .await?;
                    }
                }

                Ok(close_requested)
            }
            Err(e) => {
                // A TDS ERROR token is raised by every driver as a SqlException on the
                // statement that produced it, so it cannot be mistaken for a result set - and
                // an empty result set is a meaningful answer in SQL, which is why silence or a
                // bare DONE would be worse than useless here.
                //
                // 49918 ("Cannot process request. Not enough resources") is on the standard
                // transient-error list that SqlClient's own retry logic keys off, so capacity
                // exhaustion gets retried rather than surfaced to the application. 50000 is
                // the generic user-defined error number for everything else.
                let overloaded = crate::llm::is_overload_error(&e);
                let number = if overloaded {
                    MSSQL_ERROR_NOT_ENOUGH_RESOURCES
                } else {
                    MSSQL_ERROR_GENERIC
                };
                let message = crate::utils::WireFailure::classify(&e).prefixed_text();
                // Non-fatal: a wire fallback (TDS ERROR token) is still delivered and the
                // connection stays open, so this is recovered rather than a hard failure.
                // `decision=fail_closed_llm_error` is never `model_reject`: the model said
                // nothing at all here. The full error goes to the log only.
                error!("MSSQL: LLM error answering query {:?}: {:#}", query, e);
                Log::new(Some(&self.status_tx)).warn(format!(
                    "MSSQL query decision=fail_closed_llm_error ({}); replying error {number}: {message}",
                    if overloaded { "overloaded" } else { "unavailable" }
                ));
                self.send_error(write_half, number, message, 16).await?;
                Ok(false)
            }
        }
    }

    /// Send result set
    ///
    /// Every column is emitted as one of TDS's *nullable* (variable-length) types, because
    /// those are the only ones whose COLMETADATA carries a length byte and whose row values
    /// carry a length prefix - which is the shape this encoder produces. The previous mapping
    /// handed out FIXEDLENTYPE codes (INT4TYPE 0x38, INT8TYPE 0x7F, BITTYPE 0x32, FLT4TYPE
    /// 0x3B) while still writing length bytes, so anything other than a string column put
    /// malformed tokens on the wire.
    async fn send_result_set(
        &self,
        write_half: &SharedWrite,
        columns: Vec<serde_json::Value>,
        rows: Vec<serde_json::Value>,
    ) -> Result<()> {
        debug!(
            "send_result_set called: {} columns, {} rows",
            columns.len(),
            rows.len()
        );

        let col_types: Vec<TdsColumnType> = columns
            .iter()
            .map(|col| {
                TdsColumnType::from_name(
                    col.get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("NVARCHAR"),
                )
            })
            .collect();

        let mut response = Vec::new();

        // COLMETADATA token
        response.push(0x81);
        response.extend_from_slice(&(columns.len() as u16).to_le_bytes());

        for (col, col_type) in columns.iter().zip(&col_types) {
            let col_name = col.get("name").and_then(|v| v.as_str()).unwrap_or("column");

            response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // UserType
                                                                   // Flags is a little-endian USHORT and fNullable is bit 0, so the bytes are
                                                                   // 01 00. This used to be `[0x00, 0x02]`, i.e. bit 9 - which no TDS flag
                                                                   // occupies, so a real client (tiberius) rejected every result set with
                                                                   // "column metadata: invalid flags". It went unnoticed because NetGet's own
                                                                   // MSSQL client could not complete the handshake at all.
            response.extend_from_slice(&[0x01, 0x00]); // Flags: fNullable
            col_type.write_type_info(&mut response);

            // Column name is a B_VARCHAR: length in UTF-16 code units, then UTF-16LE.
            let name_units: Vec<u16> = col_name.encode_utf16().take(128).collect();
            response.push(name_units.len() as u8);
            for unit in &name_units {
                response.extend_from_slice(&unit.to_le_bytes());
            }
        }

        // ROW tokens
        for row in &rows {
            response.push(0xD1); // ROW token

            let row_values = row.as_array().cloned().unwrap_or_default();
            // TDS requires exactly one value per described column: pad short rows with NULL
            // and drop extras rather than desynchronising the token stream.
            for (idx, col_type) in col_types.iter().enumerate() {
                let value = row_values.get(idx).unwrap_or(&serde_json::Value::Null);
                col_type.write_value(&mut response, value);
            }
        }

        // DONE token. DONE_COUNT (0x0010) is what makes the client believe the row count.
        response.push(0xFD);
        response.extend_from_slice(&0x0010u16.to_le_bytes()); // Status: final + count valid
        response.extend_from_slice(&0x00C1u16.to_le_bytes()); // CurCmd: SELECT
        response.extend_from_slice(&(rows.len() as u64).to_le_bytes());

        debug!("Sending result set: {} bytes", response.len());
        self.send_tds_packet(write_half, 0x04, &response).await
    }

    /// Send empty result set (just DONE token)
    async fn send_empty_result(&self, write_half: &SharedWrite) -> Result<()> {
        let mut response = Vec::new();

        // DONE token
        response.push(0xFD);
        response.extend_from_slice(&[0x00, 0x00]); // Status
        response.extend_from_slice(&[0x00, 0x00]); // CurCmd
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // DoneRowCount

        self.send_tds_packet(write_half, 0x04, &response).await
    }

    /// Send error response
    async fn send_error(
        &self,
        write_half: &SharedWrite,
        error_number: u32,
        message: &str,
        severity: u8,
    ) -> Result<()> {
        let mut response = Vec::new();

        // ERROR token (0xAA)
        response.push(0xAA);

        let msg_u16: Vec<u16> = message.encode_utf16().collect();
        let msg_bytes: Vec<u8> = msg_u16.iter().flat_map(|c| c.to_le_bytes()).collect();

        let token_len = 4 + 1 + 1 + 2 + msg_bytes.len() + 1 + 1 + 4;
        response.extend_from_slice(&(token_len as u16).to_le_bytes());

        response.extend_from_slice(&error_number.to_le_bytes());
        response.push(0x01); // State
        response.push(severity); // Class (severity)
        response.extend_from_slice(&(msg_u16.len() as u16).to_le_bytes());
        response.extend_from_slice(&msg_bytes);
        response.push(0x00); // Server name length
        response.push(0x00); // Procedure name length
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Line number

        // DONE token
        response.push(0xFD);
        response.extend_from_slice(&[0x00, 0x00]); // Status
        response.extend_from_slice(&[0x00, 0x00]); // CurCmd
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        self.send_tds_packet(write_half, 0x04, &response).await
    }

    /// Send DONE token
    async fn send_done(&self, write_half: &SharedWrite, rows_affected: u64) -> Result<()> {
        let mut response = Vec::new();

        response.push(0xFD); // DONE token
                             // DONE_COUNT (0x0010) must be set or the client ignores DoneRowCount entirely, which
                             // silently discarded the `rows_affected` value the LLM supplied via mssql_ok_response.
        response.extend_from_slice(&0x0010u16.to_le_bytes()); // Status: final + count valid
        response.extend_from_slice(&0x00C1u16.to_le_bytes()); // CurCmd
        response.extend_from_slice(&rows_affected.to_le_bytes());

        self.send_tds_packet(write_half, 0x04, &response).await
    }

    /// Send a TDS message, split across packets of the negotiated size.
    ///
    /// The header length field is a `u16`, so a single oversized write used to wrap around and
    /// emit a packet whose declared length was far shorter than its payload. TDS solves this
    /// with continuation packets: every packet but the last carries status 0x00, the last
    /// carries 0x01 (EOM).
    ///
    /// The whole message is framed first and written under **one** lock on the shared write
    /// half. Locking per packet would let an injected write from the dashboard's peer task
    /// land between two continuation packets of the same message, which no TDS client can
    /// resynchronise from.
    async fn send_tds_packet(
        &self,
        write_half: &SharedWrite,
        packet_type: u8,
        data: &[u8],
    ) -> Result<()> {
        let max_payload = TDS_PACKET_SIZE - 8;
        let mut packet_id: u8 = 1;
        let mut offset = 0;
        let mut framed: Vec<u8> = Vec::with_capacity(data.len() + 8);
        let mut packets: u64 = 0;

        loop {
            let end = std::cmp::min(offset + max_payload, data.len());
            let chunk = &data[offset..end];
            let is_last = end == data.len();

            framed.push(packet_type); // Type
            framed.push(if is_last { 0x01 } else { 0x00 }); // Status: EOM on the last packet
            framed.extend_from_slice(&((8 + chunk.len()) as u16).to_be_bytes()); // Length
            framed.extend_from_slice(&[0x00, 0x00]); // SPID
            framed.push(packet_id); // PacketID
            framed.push(0x00); // Window
            framed.extend_from_slice(chunk);
            packets += 1;

            if is_last {
                break;
            }
            offset = end;
            packet_id = packet_id.wrapping_add(1).max(1);
        }

        write_counted(
            write_half,
            &framed,
            packets,
            &self.app_state,
            self.server_id,
            self.connection_id,
        )
        .await?;
        Ok(())
    }
}

/// Write one framed TDS message to the shared write half and count it.
///
/// `packets` is the number of TDS packets inside `data`, which is why this takes a count
/// rather than assuming one: a message over [`TDS_PACKET_SIZE`] is several packets in a
/// single write, and the rail's `↑` packet counter has always counted TDS packets.
///
/// The guard is dropped before `update_connection_stats`, so nothing awaits `AppState` — let
/// alone an LLM call — while holding the write half.
async fn write_counted(
    write_half: &SharedWrite,
    data: &[u8],
    packets: u64,
    app_state: &AppState,
    server_id: Option<crate::state::ServerId>,
    connection_id: ConnectionId,
) -> std::io::Result<()> {
    {
        let mut writer = write_half.lock().await;
        writer.write_all(data).await?;
        writer.flush().await?;
    }
    if let Some(server_id) = server_id {
        app_state
            .update_connection_stats(
                server_id,
                connection_id,
                None,
                Some(data.len() as u64),
                None,
                Some(packets),
            )
            .await;
    }
    Ok(())
}

/// TDS packet header
#[allow(dead_code)]
struct TdsHeader {
    packet_type: u8,
    #[allow(dead_code)]
    status: u8,
    length: u16,
    #[allow(dead_code)]
    spid: u16,
    #[allow(dead_code)]
    packet_id: u8,
    #[allow(dead_code)]
    window: u8,
}

/// Maximum bytes of NVARCHAR payload a single column value may carry.
///
/// 4000 UTF-16 code units is the largest non-MAX `nvarchar`. Declaring `nvarchar(max)` instead
/// would oblige us to emit PLP-chunked row values, which this encoder does not do.
const NVARCHAR_MAX_BYTES: usize = 8000;

/// The TDS wire representation chosen for one result-set column.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TdsColumnType {
    /// INTNTYPE (0x26) with the given byte width: 1, 2, 4 or 8.
    Int(u8),
    /// BITNTYPE (0x68).
    Bit,
    /// FLTNTYPE (0x6D), 8-byte double.
    Float,
    /// NVARCHARTYPE (0xE7), UTF-16LE with a USHORT length prefix.
    NVarChar,
}

impl TdsColumnType {
    /// Map an LLM-supplied SQL type name onto a wire type. Unknown names become NVARCHAR.
    fn from_name(type_name: &str) -> Self {
        match type_name.trim().to_uppercase().as_str() {
            "TINYINT" => TdsColumnType::Int(1),
            "SMALLINT" => TdsColumnType::Int(2),
            "INT" | "INTEGER" => TdsColumnType::Int(4),
            "BIGINT" => TdsColumnType::Int(8),
            "BIT" | "BOOL" | "BOOLEAN" => TdsColumnType::Bit,
            "FLOAT" | "REAL" | "DOUBLE" | "DECIMAL" | "NUMERIC" | "MONEY" => TdsColumnType::Float,
            _ => TdsColumnType::NVarChar,
        }
    }

    /// Write the COLMETADATA TYPE_INFO for this column.
    fn write_type_info(&self, out: &mut Vec<u8>) {
        match self {
            TdsColumnType::Int(width) => {
                out.push(0x26); // INTNTYPE
                out.push(*width);
            }
            TdsColumnType::Bit => {
                out.push(0x68); // BITNTYPE
                out.push(0x01);
            }
            TdsColumnType::Float => {
                out.push(0x6D); // FLTNTYPE
                out.push(0x08);
            }
            TdsColumnType::NVarChar => {
                out.push(0xE7); // NVARCHARTYPE
                out.extend_from_slice(&(NVARCHAR_MAX_BYTES as u16).to_le_bytes());
                out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]); // COLLATION
            }
        }
    }

    /// Write one row value, including its length prefix. JSON `null` becomes a real SQL NULL.
    fn write_value(&self, out: &mut Vec<u8>, value: &serde_json::Value) {
        match self {
            TdsColumnType::Int(width) => {
                match value_as_i64(value) {
                    Some(v) => {
                        out.push(*width);
                        match width {
                            1 => out.push(v as u8),
                            2 => out.extend_from_slice(&(v as i16).to_le_bytes()),
                            4 => out.extend_from_slice(&(v as i32).to_le_bytes()),
                            _ => out.extend_from_slice(&v.to_le_bytes()),
                        }
                    }
                    // NULL, or a value that is not an integer at all.
                    None => out.push(0x00),
                }
            }
            TdsColumnType::Bit => match value_as_bool(value) {
                Some(b) => {
                    out.push(0x01);
                    out.push(u8::from(b));
                }
                None => out.push(0x00),
            },
            TdsColumnType::Float => match value_as_f64(value) {
                Some(f) => {
                    out.push(0x08);
                    out.extend_from_slice(&f.to_le_bytes());
                }
                None => out.push(0x00),
            },
            TdsColumnType::NVarChar => {
                if value.is_null() {
                    // 0xFFFF is the NVARCHAR NULL marker. Writing the text "NULL" here, as the
                    // previous encoder did, made every NULL arrive as a four-character string.
                    out.extend_from_slice(&0xFFFFu16.to_le_bytes());
                    return;
                }
                let text = json_to_string(value);
                let mut bytes: Vec<u8> = Vec::new();
                for unit in text.encode_utf16() {
                    if bytes.len() + 2 > NVARCHAR_MAX_BYTES {
                        break;
                    }
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
                out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
                out.extend_from_slice(&bytes);
            }
        }
    }
}

fn value_as_i64(value: &serde_json::Value) -> Option<i64> {
    match value {
        serde_json::Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        serde_json::Value::Bool(b) => Some(i64::from(*b)),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn value_as_f64(value: &serde_json::Value) -> Option<f64> {
    match value {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn value_as_bool(value: &serde_json::Value) -> Option<bool> {
    match value {
        serde_json::Value::Bool(b) => Some(*b),
        serde_json::Value::Number(n) => n.as_i64().map(|v| v != 0),
        serde_json::Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Convert a JSON value to its NVARCHAR text form.
fn json_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => if *b { "1" } else { "0" }.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => value.to_string(),
    }
}

/// Pull the username, database and application name out of a LOGIN7 packet body.
///
/// MS-TDS 2.2.6.4: a fixed 36-byte prelude, then a table of `(offset, length)` pairs in
/// UTF-16 code units, each offset measured from the start of the LOGIN7 data. Only three of
/// the fields matter for an access decision, and the password is deliberately *not* among
/// them — it is not needed to decide, and putting a credential into an event would send it
/// to the model and into the event log.
///
/// Everything is best-effort: a truncated or malformed packet yields empty strings rather
/// than an error, because the caller's job is to refuse a login it cannot justify, and an
/// unparseable login is exactly that. It must never be the reason a login is *granted*.
#[cfg(not(target_arch = "wasm32"))]
fn parse_login7(data: &[u8]) -> (String, String, String) {
    /// Offsets of the (offset, length) pairs within the LOGIN7 body, per MS-TDS 2.2.6.4.
    const IB_USERNAME: usize = 40;
    const IB_APPNAME: usize = 48;
    const IB_DATABASE: usize = 68;

    let field = |pair_at: usize| -> String {
        // Each pair is two little-endian u16s: offset, then length in UTF-16 characters.
        let Some(bytes) = data.get(pair_at..pair_at + 4) else {
            return String::new();
        };
        let offset = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        let chars = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        if chars == 0 {
            return String::new();
        }
        let Some(raw) = data.get(offset..offset + chars * 2) else {
            return String::new();
        };
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    };

    (field(IB_USERNAME), field(IB_DATABASE), field(IB_APPNAME))
}

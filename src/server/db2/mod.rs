//! IBM Db2 server implementation (DRDA wire protocol).
//!
//! Speaks enough DRDA/DDM that a Db2 client can complete the connection handshake
//! (EXCSAT/ACCSEC/SECCHK/ACCRDB) and execute a basic statement (EXCSQLIMM), with
//! the LLM playing the database: it decides whether a login is accepted and what
//! SQLCA a statement produces. The wire codec is [`drda`]; **no storage** exists —
//! the model answers every request.
//!
//! **Fail closed.** An LLM outage during the security check is a refusal
//! (SECCHKRM at severity ERROR), never an accept; a failure during a statement is
//! an error SQLCARD, never a success. See `AGENTS.md` for what DRDA is and is not
//! implemented here; Apache Derby's JDBC driver and IBM's CLI driver both connect to it
//! (`tests/server/db2/real_client_test.rs`).

pub mod actions;
pub mod drda;

/// How long to wait for a peer's first DRDA request after it has connected.
///
/// DRDA is client-speaks-first with no server greeting: a real driver sends EXCSAT the moment
/// the socket is up, and nothing legitimate happens before it. A peer that has connected and
/// sent nothing is holding a task and a connection slot on the strength of no request at all.
const FIRST_REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to wait for a *further* request once the security check has been accepted.
///
/// Much longer, because an authenticated Db2 session legitimately sits idle: every driver in
/// front of one (JDBC, pureQuery, `ibm_db`) pools connections and holds them open between
/// statements, and the pools' own idle-reap defaults are in minutes. Five minutes bounds the
/// hold without closing sessions a real pool considers healthy — and an unauthenticated peer
/// never reaches this bound, which is the half that matters for an attacker.
const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// DSSes one command may chain under its correlator (the command and its command data). Real
/// commands chain two or three; past this the connection is dropped rather than buffered.
const MAX_DSS_PER_COMMAND: usize = 16;

/// Concurrent connections this server admits.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// A peer over [`MAX_CONNECTIONS`] gets a plain close, and that is the honest answer here.
///
/// Every DDM reply is a DSS carrying the *request's* correlation identifier, and this peer has
/// sent no request — so there is no well-formed refusal to write. Bytes invented for the slot
/// would be parsed as a reply to a request that does not exist and reported as a protocol
/// violation, which tells the operator less than the refusal already logged at WARN with
/// `decision=fail_closed_connection_cap`.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::server::db2::actions::{Db2Protocol, DB2_CONNECT_EVENT, DB2_QUERY_EVENT};
use crate::state::app_state::AppState;

/// Db2 server.
pub struct Db2Server;

impl Db2Server {
    /// Spawn the Db2 server. Binds with `?` (bind failure surfaces as
    /// `ServerStatus::Error`) and registers the accept-loop `JoinHandle` so
    /// `stop_server` can release the socket.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        let listener = TcpListener::bind(listen_addr).await?;
        let actual_addr = listener.local_addr()?;

        Log::new(Some(&status_tx)).info(format!("Db2 server listening on {}", actual_addr));

        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Db2",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(actual_addr);
                        debug!("Db2 connection {} from {}", connection_id, remote_addr);

                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();
                        let conn_state = ServerConnectionState {
                            id: connection_id,
                            remote_addr,
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
                        app_state
                            .add_connection_to_server(server_id, conn_state)
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        let mut handler = Db2Handler {
                            connection_id,
                            server_id,
                            llm_client: llm_client.clone(),
                            app_state: app_state.clone(),
                            status_tx: status_tx.clone(),
                            protocol: Arc::new(Db2Protocol::new(
                                connection_id,
                                app_state.clone(),
                                status_tx.clone(),
                            )),
                            authenticated: false,
                        };

                        let conn_owner = app_state.clone();
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection, so the cap counts live
                                // sessions rather than accepts.
                                let _permit = permit;
                                if let Err(e) = handler.run(stream).await {
                                    debug!("Db2 connection {} ended: {}", connection_id, e);
                                }
                                conn_owner
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                            })
                            .await;
                    }
                    Err(e) => {
                        error!("Db2 accept error: {}", e);
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
}

/// Per-connection Db2/DRDA handler.
struct Db2Handler {
    connection_id: ConnectionId,
    server_id: crate::state::ServerId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<Db2Protocol>,
    /// Set once the security check (SECCHK) has been accepted.
    authenticated: bool,
}

impl Db2Handler {
    async fn run(&mut self, stream: tokio::net::TcpStream) -> Result<()> {
        // Split read/write as the codebase requires (never clone the stream). The
        // write half is shared through an `Arc<Mutex<..>>` so the dashboard's
        // peer-command task can inject writes / a disconnect alongside the
        // reader's own replies without racing on the socket.
        let (reader, write_half) = tokio::io::split(stream);
        let write_half = Arc::new(Mutex::new(write_half));

        // Peer messaging: register a command channel for THIS connection so the
        // dashboard's "[ message this peer ]" / "[ disconnect this peer ]" rows
        // work. Injected actions go through the same central executor the LLM
        // path uses. Db2's own wire verbs are correlator-bound `Custom` results,
        // so only `close_connection` reaches the wire here (see CLAUDE.md).
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

        let result = self.run_loop(reader, &write_half).await;

        // Every exit path — clean EOF, a read/parse error, or an injected
        // disconnect — releases the peer handle so the rail stops offering a
        // dead connection. Idempotent with the peer task's own close path.
        self.app_state
            .remove_peer_handle(self.server_id, self.connection_id.as_u32())
            .await;
        result
    }

    /// The read/dispatch/reply loop. Writes go through the shared `write_half`.
    async fn run_loop(
        &mut self,
        mut reader: tokio::io::ReadHalf<tokio::net::TcpStream>,
        write_half: &Arc<Mutex<tokio::io::WriteHalf<tokio::net::TcpStream>>>,
    ) -> Result<()> {
        let mut buf: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 8192];
        let mut command: Vec<drda::ParsedDss> = Vec::new();
        // After a refused SECCHK the rest of its request chain is ignored, as Derby's server
        // does: the refusal ends the reply chain, and the ACCRDB chained behind it gets no
        // answer of its own. Answering it (even with RDBATHRM) after an unchained SECCHKRM is a
        // reply nobody asked for, which IBM's CLI driver reports as a data stream syntax error.
        let mut discarding = false;

        loop {
            // Ensure a full DSS is buffered before parsing.
            while buf.len() < 6 || buf.len() < drda::dss_declared_len(&buf).unwrap_or(6) {
                // The deadline wraps this `read()` and nothing else. The LLM round-trip that
                // decides the login or the statement result, and a `manual` rule parking
                // either for a human (`src/state/intercepts.rs`, 300s by default), both happen
                // below once a whole DSS has arrived — so a slow answer is never cut short by
                // a read deadline. What is bounded is a peer that holds the connection while
                // sending nothing, or that stalls part-way through a DSS it announced.
                let read_timeout = if self.authenticated {
                    IDLE_BETWEEN_REQUESTS_TIMEOUT
                } else {
                    FIRST_REQUEST_READ_TIMEOUT
                };
                let n = match tokio::time::timeout(read_timeout, reader.read(&mut tmp)).await {
                    Ok(read) => read?,
                    Err(_) => {
                        debug!(
                            "Db2 connection {} sent nothing for {}s; closing idle connection",
                            self.connection_id,
                            read_timeout.as_secs()
                        );
                        return Ok(());
                    }
                };
                if n == 0 {
                    return Ok(()); // clean EOF
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() >= 2 {
                    if let Some(total) = drda::dss_declared_len(&buf) {
                        if total < 6 {
                            warn!("Db2: impossible DSS length {}, dropping connection", total);
                            return Ok(());
                        }
                    }
                }
            }

            let (parsed, consumed) = match drda::parse_dss(&buf) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Db2: DRDA parse error: {}", e);
                    return Ok(());
                }
            };
            buf.drain(0..consumed);

            self.app_state
                .update_connection_stats(
                    self.server_id,
                    self.connection_id,
                    Some(consumed as u64),
                    None,
                    Some(1),
                    None,
                )
                .await;

            // A command is its RQSDSS plus the DSSes chained to it under the same correlator
            // (its command data: SQLSTT, SQLDTA, SQLATTR). It is answered once, when its last
            // DSS has arrived, and the reply is chained when that DSS was chained to a further
            // command.
            let continues = parsed.format & 0x50 == 0x50;
            let chained = parsed.format & 0x40 != 0;
            command.push(parsed);
            if continues {
                if command.len() > MAX_DSS_PER_COMMAND {
                    warn!(
                        "Db2: a command chained more than {MAX_DSS_PER_COMMAND} DSSes under one \
                         correlator decision=refused_oversized; dropping the connection"
                    );
                    return Ok(());
                }
                continue;
            }
            let this = std::mem::take(&mut command);
            if discarding {
                debug!("Db2: ignoring the rest of a request chain after a refused SECCHK");
                discarding = chained;
                continue;
            }
            let reply = self.dispatch(&this).await;
            let refused_login = this[0].codepoint == drda::cp::SECCHK && !self.authenticated;
            discarding = refused_login && chained;
            let reply = reply.map(|bytes| drda::chain_reply(bytes, chained && !refused_login));
            if let Some(bytes) = reply {
                self.app_state
                    .update_connection_stats(
                        self.server_id,
                        self.connection_id,
                        None,
                        Some(bytes.len() as u64),
                        None,
                        Some(1),
                    )
                    .await;
                let mut writer = write_half.lock().await;
                writer.write_all(&bytes).await?;
                writer.flush().await?;
            }
        }
    }

    /// Handle one DRDA command and its command data, returning the reply bytes to send (if
    /// any).
    async fn dispatch(&mut self, command: &[drda::ParsedDss]) -> Option<Vec<u8>> {
        use drda::cp;
        let req = command.first()?;
        let data = &command[1..];
        let corr = req.correlator;
        debug!(
            "Db2: DRDA command 0x{:04X} (correlator {})",
            req.codepoint, corr
        );

        match req.codepoint {
            cp::EXCSAT => Some(self.reply_excsatrd(corr, &req.body)),
            cp::RDBCMM => Some(end_unit_of_work(corr, 1)),
            cp::RDBRLLBCK => Some(end_unit_of_work(corr, 2)),
            cp::ACCSEC => Some(self.reply_accsecrd(corr, &req.body)),
            cp::SECCHK => Some(self.handle_secchk(corr, &req.body).await),
            cp::ACCRDB => Some(self.reply_accrdbrm(corr, &req.body)),
            cp::EXCSQLIMM | cp::EXCSQLSTT => {
                // The SQL text is the SQLSTT command data chained to the command, or (this
                // server's own byte-literal form) a parameter embedded in it.
                let sqlstt = drda::find_param(&req.body, cp::SQLSTT).or_else(|| {
                    data.iter()
                        .find(|d| d.codepoint == cp::SQLSTT)
                        .map(|d| d.body.clone())
                });
                match sqlstt {
                    Some(sqlstt) => {
                        let sql = drda::decode_sqlstt(&sqlstt);
                        Some(self.handle_query(corr, sql).await)
                    }
                    // EXCSQLSTT of a prepared section: nothing was prepared here.
                    None if req.codepoint == cp::EXCSQLSTT => Some(cmdnsprm(corr, req.codepoint)),
                    // A bare EXCSQLIMM: its SQLSTT may still follow as a DSS of its own.
                    None => None,
                }
            }
            cp::EXCSQLSET => Some(self.session_settings(corr, data)),
            cp::SQLSTT => {
                let sql = drda::decode_sqlstt(&req.body);
                Some(self.handle_query(corr, sql).await)
            }
            other => Some(cmdnsprm(corr, other)),
        }
    }

    /// EXCSQLSET: the special registers a driver sets for itself on connecting (`SET CLIENT
    /// WRKSTNNAME`, `SET CURRENT LOCALE LC_CTYPE`, ...). They are acknowledged without the
    /// model - there is no session state here for them to change, and refusing them fails
    /// every statement IBM's CLI driver sends after them - but only once the security check
    /// has been accepted.
    fn session_settings(&self, corr: u16, data: &[drda::ParsedDss]) -> Vec<u8> {
        if !self.authenticated {
            warn!("Db2 EXCSQLSET decision=fail_closed_not_authenticated");
            let card = drda::sqlcard_error(-30082, "08001");
            return drda::encode_dss(drda::DSSFMT_OBJDSS, false, corr, &card);
        }
        for d in data.iter().filter(|d| d.codepoint == drda::cp::SQLSTT) {
            info!(
                "Db2 EXCSQLSET decision=session_setting {}",
                crate::utils::truncate_for_log(&drda::decode_sqlstt(&d.body), 200)
            );
        }
        drda::encode_dss(drda::DSSFMT_OBJDSS, false, corr, &drda::sqlcard_success())
    }

    /// EXCSAT -> EXCSATRD: advertise the server's attributes.
    fn reply_excsatrd(&self, corr: u16, body: &[u8]) -> Vec<u8> {
        use drda::cp;
        let mut inner = Vec::new();
        inner.extend_from_slice(&drda::encode_scalar_str(cp::EXTNAM, "netget-db2"));
        inner.extend_from_slice(&drda::encode_scalar_str(cp::SRVCLSNM, "QDB2/NETGET"));
        inner.extend_from_slice(&drda::encode_scalar_str(cp::SRVNAM, "NETGET"));
        inner.extend_from_slice(&drda::encode_scalar_str(cp::SRVRLSLV, "SQL11055"));
        // Answer each manager the requester listed with the level served here: up to 7 for
        // AGENT (0x1403), SQLAM (0x2407), RDB (0x240F) and SECMGR (0x1440), 0 (not supported)
        // for the rest - UNICODEMGR among them, so DDM strings stay EBCDIC. A driver reads an
        // empty list as a server with no SQL application manager at all.
        let mut levels = Vec::new();
        if let Some(asked) = drda::find_param(body, cp::MGRLVLLS) {
            for pair in asked.chunks_exact(4) {
                let manager = u16::from_be_bytes([pair[0], pair[1]]);
                let level = match manager {
                    0x1403 | 0x2407 | 0x240F | 0x1440 => {
                        u16::from_be_bytes([pair[2], pair[3]]).min(7)
                    }
                    _ => 0,
                };
                levels.extend_from_slice(&manager.to_be_bytes());
                levels.extend_from_slice(&level.to_be_bytes());
            }
        }
        inner.extend_from_slice(&drda::encode_scalar(cp::MGRLVLLS, &levels));
        let rd = drda::encode_object(cp::EXCSATRD, &inner);
        drda::encode_dss(drda::DSSFMT_RPYDSS, false, corr, &rd)
    }

    /// ACCSEC -> ACCSECRD.
    ///
    /// Only the mechanisms whose SECCHK this server can read are accepted: USRIDPWD (3) and
    /// USRIDONL (4), which carry USRID and PASSWORD in the clear. Any other - an encrypted one
    /// such as EUSRIDPWD (9), whose SECCHK carries only an encrypted SECTKN - is answered with
    /// the list this server supports and SECCHKCD 0x01 (mechanism not supported), so the
    /// requester can retry with one of them. Accepting a mechanism the server cannot process
    /// would put a login in front of the model whose user id it never sees; IBM's CLI driver
    /// asks for EUSRIDPWD by default.
    fn reply_accsecrd(&self, corr: u16, body: &[u8]) -> Vec<u8> {
        use drda::cp;
        let requested = drda::find_param(body, cp::SECMEC).unwrap_or_else(|| vec![0x00, 0x03]);
        let supported = matches!(requested.as_slice(), [0x00, 0x03] | [0x00, 0x04]);
        let mut inner = if supported {
            drda::encode_scalar(cp::SECMEC, &requested)
        } else {
            warn!(
                "Db2 ACCSEC decision=refused_secmec: the requester asked for security mechanism \
                 {requested:02X?}; offering USRIDPWD (3) and USRIDONL (4)"
            );
            drda::encode_scalar(cp::SECMEC, &[0x00, 0x03, 0x00, 0x04])
        };
        if !supported {
            inner.extend_from_slice(&drda::encode_scalar(cp::SECCHKCD, &[0x01]));
        }
        let rd = drda::encode_object(cp::ACCSECRD, &inner);
        drda::encode_dss(drda::DSSFMT_RPYDSS, false, corr, &rd)
    }

    /// SECCHK -> SECCHKRM: the LLM decides accept/reject. Fail-closed: an LLM
    /// outage is a refusal (severity ERROR), distinct in the logs from a model
    /// denial.
    async fn handle_secchk(&mut self, corr: u16, body: &[u8]) -> Vec<u8> {
        use drda::cp;
        let user_id = drda::find_param(body, cp::USRID)
            .map(|b| drda::ebcdic_to_ascii(&b))
            .unwrap_or_default();
        let rdb_name = drda::find_param(body, cp::RDBNAM)
            .map(|b| drda::ebcdic_to_ascii(&b))
            .unwrap_or_default();
        let has_password = drda::find_param(body, cp::PASSWORD)
            .map(|b| !b.is_empty())
            .unwrap_or(false);

        let event = Event::new(
            &DB2_CONNECT_EVENT,
            serde_json::json!({
                "user_id": user_id,
                "rdb_name": rdb_name,
                "has_password": has_password,
            }),
        );

        match call_llm(
            &self.llm_client,
            &self.app_state,
            self.server_id,
            Some(self.connection_id),
            &event,
            self.protocol.as_ref(),
        )
        .await
        {
            Ok(result) => match first_custom(&result.protocol_results) {
                Some(("db2_accept_connection", _)) => {
                    self.authenticated = true;
                    info!("Db2 SECCHK decision=model_accept user={user_id} rdb={rdb_name}");
                    let _ = self
                        .status_tx
                        .send(format!("→ Db2 login accepted for {user_id}"));
                    secchkrm(corr, drda::svrcod::INFO, drda::secchkcd::SUCCESS)
                }
                Some(("db2_reject_connection", data)) => {
                    let code = match data.get("sec_check_code").and_then(|v| v.as_str()) {
                        Some("userid_unknown") => drda::secchkcd::USERID_UNKNOWN,
                        Some("userid_missing") => drda::secchkcd::USERID_MISSING,
                        _ => drda::secchkcd::PASSWORD_INVALID,
                    };
                    info!("Db2 SECCHK decision=model_reject user={user_id} secchkcd=0x{code:02X}");
                    let _ = self
                        .status_tx
                        .send("↩ Db2 login denied by model".to_string());
                    secchkrm(corr, drda::svrcod::ERROR, code)
                }
                _ => {
                    // The handler ran and produced neither verdict. Refuse: silence is not
                    // consent for an authentication decision.
                    warn!(
                        "Db2 SECCHK decision=fail_closed_no_action user={user_id}: the handler \
                         produced no db2_accept_connection; refusing"
                    );
                    secchkrm(corr, drda::svrcod::ERROR, drda::secchkcd::PASSWORD_INVALID)
                }
            },
            Err(e) => {
                // Fail closed, and never an accept. The SECCHKRM here is byte-identical to the
                // no-action refusal above and differs from a model denial only in a code the
                // model chose - DRDA has no field that could carry "netget could not reach a
                // decision" - so the log is the only place the three can be told apart. That is
                // the `radius` rule, and why these tags are stable strings rather than prose.
                error!(
                    "Db2 SECCHK decision=fail_closed_llm_error user={user_id}: LLM error: {:#}",
                    e
                );
                let _ = self.status_tx.send(format!(
                    "✗ Db2 auth backend error: {}",
                    crate::utils::truncate_for_log(&e.to_string(), 200)
                ));
                secchkrm(corr, drda::svrcod::ERROR, drda::secchkcd::PASSWORD_INVALID)
            }
        }
    }

    /// ACCRDB -> ACCRDBRM: grant access to the RDB once authenticated.
    ///
    /// Without an accepted SECCHK the answer is RDBATHRM (not authorized to the RDB) at
    /// severity ERROR. An ACCRDBRM is never the refusal, whatever its severity: IBM's CLI
    /// driver keys on the code point and would report the connection open.
    fn reply_accrdbrm(&self, corr: u16, body: &[u8]) -> Vec<u8> {
        use drda::cp;
        if !self.authenticated {
            warn!("Db2 ACCRDB decision=fail_closed_not_authenticated: answering RDBATHRM");
            let mut inner = drda::encode_scalar(cp::SVRCOD, &drda::svrcod::ERROR.to_be_bytes());
            if let Some(rdbnam) = drda::find_param(body, cp::RDBNAM) {
                inner.extend_from_slice(&drda::encode_scalar(cp::RDBNAM, &rdbnam));
            }
            let rm = drda::encode_object(cp::RDBATHRM, &inner);
            return drda::encode_dss(drda::DSSFMT_RPYDSS, false, corr, &rm);
        }
        let severity = drda::svrcod::INFO;
        let mut inner = Vec::new();
        inner.extend_from_slice(&drda::encode_scalar(cp::SVRCOD, &severity.to_be_bytes()));
        inner.extend_from_slice(&drda::encode_scalar_str(cp::PRDID, "SQL11055"));
        inner.extend_from_slice(&drda::encode_scalar_str(cp::TYPDEFNAM, "QTDSQLASC"));
        // The CCSIDs of the character data this server sends (SQLCA fields): UTF-8.
        let mut ovr = drda::encode_scalar(cp::CCSIDSBC, &1208u16.to_be_bytes());
        ovr.extend_from_slice(&drda::encode_scalar(cp::CCSIDMBC, &1208u16.to_be_bytes()));
        inner.extend_from_slice(&drda::encode_scalar(cp::TYPDEFOVR, &ovr));
        let rm = drda::encode_object(cp::ACCRDBRM, &inner);
        drda::encode_dss(drda::DSSFMT_RPYDSS, false, corr, &rm)
    }

    /// Handle a statement: emit db2_query, then reply SQLCARD with the model's SQLCA.
    async fn handle_query(&mut self, corr: u16, sql: String) -> Vec<u8> {
        if !self.authenticated {
            warn!(
                "Db2 statement decision=fail_closed_not_authenticated: a statement arrived \
                 before an accepted SECCHK; replying SQLCODE -30082"
            );
            let card = drda::sqlcard_error(-30082, "08001");
            return drda::encode_dss(drda::DSSFMT_OBJDSS, false, corr, &card);
        }

        let event = Event::new(
            &DB2_QUERY_EVENT,
            serde_json::json!({
                "sql_text": sql,
                "statement_type": "execute_immediate",
            }),
        );

        match call_llm(
            &self.llm_client,
            &self.app_state,
            self.server_id,
            Some(self.connection_id),
            &event,
            self.protocol.as_ref(),
        )
        .await
        {
            Ok(result) => {
                let card = match first_custom(&result.protocol_results) {
                    Some(("db2_query_ok", data)) => {
                        let sqlcode = data.get("sqlcode").and_then(|v| v.as_i64()).unwrap_or(0);
                        debug!("Db2 statement decision=model_answer sqlcode={sqlcode}");
                        let rows = data.get("rows_affected").and_then(|v| v.as_i64());
                        if let (0, Some(rows)) = (sqlcode, rows) {
                            // The row count travels in SQLERRD3, which needs a full SQLCA.
                            drda::sqlcard(0, "00000", rows.clamp(0, i32::MAX as i64) as i32)
                        } else if sqlcode == 0 {
                            drda::sqlcard_success()
                        } else if sqlcode > 0 {
                            // Positive SQLCODE (e.g. 100 = not found): warning SQLCA.
                            drda::sqlcard_error(sqlcode as i32, "02000")
                        } else {
                            drda::sqlcard_error(sqlcode as i32, "42000")
                        }
                    }
                    Some(("db2_query_error", data)) => {
                        let sqlcode =
                            data.get("sqlcode").and_then(|v| v.as_i64()).unwrap_or(-104) as i32;
                        let sqlstate = data
                            .get("sqlstate")
                            .and_then(|v| v.as_str())
                            .unwrap_or("42601");
                        debug!(
                            "Db2 statement decision=model_reject sqlcode={sqlcode} \
                             sqlstate={sqlstate}"
                        );
                        drda::sqlcard_error(sqlcode, sqlstate)
                    }
                    _ => {
                        // Fail closed: no usable answer -> error SQLCA, never a success. -901
                        // is Db2's own "unexpected system error", which is what this is.
                        warn!(
                            "Db2 statement decision=fail_closed_no_action: the handler produced \
                             no db2_query_ok or db2_query_error; returning SQLCODE -901"
                        );
                        drda::sqlcard_error(-901, "58004")
                    }
                };
                drda::encode_dss(drda::DSSFMT_OBJDSS, false, corr, &card)
            }
            Err(e) => {
                // The same SQLCA as the no-action path above, for the same reason as SECCHK:
                // the SQLCA extended group that would carry message text is sent NULL, so the
                // wire cannot carry the distinction and the log has to.
                error!(
                    "Db2 statement decision=fail_closed_llm_error: LLM error: {:#}",
                    e
                );
                let _ = self.status_tx.send(format!(
                    "✗ Db2 query backend error: {}",
                    crate::utils::truncate_for_log(&e.to_string(), 200)
                ));
                let card = drda::sqlcard_error(-901, "58004");
                drda::encode_dss(drda::DSSFMT_OBJDSS, false, corr, &card)
            }
        }
    }
}

/// CMDNSPRM (command not supported) at severity ERROR, so the client gets a real reply instead
/// of hanging. One per command: the command data chained to it is not answered separately.
fn cmdnsprm(corr: u16, codepoint: u16) -> Vec<u8> {
    use drda::cp;
    warn!("Db2: unsupported DRDA command 0x{:04X}", codepoint);
    let mut inner = drda::encode_scalar(cp::SVRCOD, &drda::svrcod::ERROR.to_be_bytes());
    inner.extend_from_slice(&drda::encode_scalar(0x000C, &codepoint.to_be_bytes()));
    let rm = drda::encode_object(cp::CMDNSPRM, &inner);
    drda::encode_dss(drda::DSSFMT_RPYDSS, false, corr, &rm)
}

/// RDBCMM / RDBRLLBCK -> ENDUOWRM + SQLCARD. There is no storage, so there is nothing to commit
/// or undo; the reply says the unit of work ended (`uowdsp` 1 committed, 2 rolled back), which
/// is what a JDBC driver in autocommit sends after every statement and waits for.
fn end_unit_of_work(corr: u16, uowdsp: u8) -> Vec<u8> {
    use drda::cp;
    let mut inner = drda::encode_scalar(cp::SVRCOD, &drda::svrcod::WARNING.to_be_bytes());
    inner.extend_from_slice(&drda::encode_scalar(cp::UOWDSP, &[uowdsp]));
    let rm = drda::encode_object(cp::ENDUOWRM, &inner);
    let mut out = drda::encode_dss(drda::DSSFMT_RPYDSS, false, corr, &rm);
    out.extend(drda::encode_dss(
        drda::DSSFMT_OBJDSS,
        false,
        corr,
        &drda::sqlcard_success(),
    ));
    out
}

/// Build a SECCHKRM (security-check reply message) with the given severity and
/// security-check code.
fn secchkrm(corr: u16, svrcod: u16, secchkcd: u8) -> Vec<u8> {
    use drda::cp;
    let mut inner = Vec::new();
    inner.extend_from_slice(&drda::encode_scalar(cp::SVRCOD, &svrcod.to_be_bytes()));
    inner.extend_from_slice(&drda::encode_scalar(cp::SECCHKCD, &[secchkcd]));
    let rm = drda::encode_object(cp::SECCHKRM, &inner);
    drda::encode_dss(drda::DSSFMT_RPYDSS, false, corr, &rm)
}

/// Find the first `Custom` action result, returning its name and data.
fn first_custom(results: &[ActionResult]) -> Option<(&str, &serde_json::Value)> {
    results.iter().find_map(|r| match r {
        ActionResult::Custom { name, data } => Some((name.as_str(), data)),
        _ => None,
    })
}

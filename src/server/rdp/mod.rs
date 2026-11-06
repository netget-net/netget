//! RDP server — the TPKT + X.224 connection-negotiation slice of [MS-RDPBCGR].
//!
//! Scope (be honest, per `src/server/rdp/CLAUDE.md`): this reads a client's TPKT-framed X.224
//! Connection Request, parses the `Cookie: mstshash=` routing token and the RDP_NEG_REQ
//! (`requestedProtocols`), and answers with an X.224 Connection Confirm the LLM chooses —
//! RDP_NEG_RSP selecting a security protocol, or RDP_NEG_FAILURE. It STOPS there. It does not
//! implement MCS/GCC, the security exchange, the capability exchange, or any bitmap, so no
//! desktop frame is produced and a real client does not reach a session. A client completing the
//! negotiation is real, verifiable progress against [MS-RDPBCGR] 2.2.1.1/2.2.1.2 and nothing more
//! is claimed.
//!
//! The negotiation decision is genuine LLM reasoning: which security protocol to select given
//! what the client offered, or whether to demand one it did not (a rejection).

pub mod actions;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::{console_debug, console_info, console_warn};
use actions::{
    build_negotiation_failure, protocol_value_to_names, RdpProtocol, DEFAULT_FAILURE_CODE,
    RDP_CONNECTION_REQUEST_EVENT, TYPE_RDP_NEG_FAILURE, TYPE_RDP_NEG_REQ, TYPE_RDP_NEG_RSP,
    X224_TPDU_CONNECTION_REQUEST,
};
use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, warn};

/// Largest X.224 Connection Request accepted, in bytes. A real CR is well under 512 bytes
/// (routing cookie + RDP_NEG_REQ + optional correlation info); the TPKT length field is
/// client-controlled, so it is bounded before anything is allocated.
pub const MAX_X224_LEN: usize = 2048;

/// What one client sent in its X.224 Connection Request.
struct ConnectionRequest {
    /// Username from a `Cookie: mstshash=...` routing token, empty if absent.
    cookie_username: String,
    /// `requestedProtocols` bitmask (0 when no RDP_NEG_REQ was present = standard RDP security).
    requested_protocols: u32,
    /// The RDP_NEG_REQ flags octet (0 when absent).
    flags: u8,
}

/// RDP server (negotiation slice).
pub struct RdpServer;

/// How long to wait for the first byte from a peer that has only connected.
///
/// RDP is client-speaks-first: the X.224 Connection Request is the very first thing on the
/// wire, sent by `mstsc`, FreeRDP or rdesktop from inside their own connect path with no user
/// interaction in between. Thirty seconds is far longer than that takes, and a peer that has
/// sent nothing has negotiated nothing.
const FIRST_BYTE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for the rest of a frame the peer has already begun.
///
/// Shorter than the first bound, because it is a narrower claim: these bytes belong to a TPKT
/// frame whose header has already arrived, and a Connection Request is at most
/// [`MAX_X224_LEN`] bytes that a real client writes in one go. Nothing legitimate pauses in the
/// middle of it, so fifteen seconds is generous for a slow link and still bounds a peer that
/// sends `0x03` and stops.
///
/// This server's whole session is one request and one reply, so there is no third case: the
/// model round-trip happens after the request has been read in full, and the connection closes
/// after the Connection Confirm.
const IN_FRAME_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Concurrent connections this server admits.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. Each connection may buffer up to
/// [`MAX_X224_LEN`], so this is the multiplier that turns that per-connection bound into a
/// total one.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes: nothing.
///
/// RDP's own refusal is an X.224 Connection Confirm carrying `RDP_NEG_FAILURE`, and it cannot
/// be sent here: it is a *reply*, and a capped peer is refused before its Connection Request
/// has been read, so there is no `srcRef` to answer and no requested protocol to fail. A
/// fabricated Connection Confirm would also be a positive assertion — it tells the client which
/// security protocol to speak next — which is precisely what a refusal must not do. The peer
/// gets a clean EOF and the refusal is recorded where it can carry a reason: `accept_bounded`
/// logs it at WARN with `decision=fail_closed_connection_cap`.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// The read half of an RDP connection, with both deadlines applied to every read.
///
/// [`crate::server::accept_bounded::IdleTimeoutReader`] rather than one `tokio::time::timeout`,
/// because the Connection Request is read in two steps — the four-byte TPKT header, then the
/// X.224 body whose length that header declares — and a peer that sends the header and stalls
/// would otherwise be unbounded. Its deadline is armed lazily, only while a read is pending, so
/// the model round-trip that follows runs with no clock against it.
type RdpReader = crate::server::accept_bounded::IdleTimeoutReader<tokio::io::ReadHalf<TcpStream>>;

impl RdpServer {
    /// Bind and spawn the accept loop. Awaits the bind so failure is returned as `Err`; registers
    /// the accept-loop `JoinHandle` so `stop_server` releases the socket.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        // Keep the address last on the line: the E2E harness parses the port from after "on ".
        console_info!(
            status_tx,
            "RDP server (negotiation slice) listening on {}",
            local_addr
        );

        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "RDP",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);

                        Log::to(&status_tx)
                            .info(format!("RDP client connected from {}", remote_addr));

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection: releasing it here would
                                // cap the accept rate rather than the number of live
                                // connections.
                                let _permit = permit;
                                if let Err(e) = Self::handle_connection(
                                    stream,
                                    connection_id,
                                    remote_addr,
                                    local_addr_conn,
                                    server_id,
                                    state_clone,
                                    status_clone,
                                    llm_clone,
                                )
                                .await
                                {
                                    error!("RDP connection error: {}", e);
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        error!("RDP accept failed: {}", e);
                        let _ = status_tx.send(format!("✗ RDP accept failed, stopping: {}", e));
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

    /// One connection: read the X.224 CR, consult the model, write the CC, then close.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        stream: TcpStream,
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        server_id: crate::state::ServerId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        llm_client: OllamaClient,
    ) -> Result<()> {
        let (read_half, write_half) = tokio::io::split(stream);
        // Every read below goes through the deadline pair; nothing else does.
        let mut read_half: RdpReader = crate::server::accept_bounded::IdleTimeoutReader::with_first(
            read_half,
            FIRST_BYTE_READ_TIMEOUT,
            IN_FRAME_READ_TIMEOUT,
        );
        let write_half = Arc::new(Mutex::new(write_half));

        let now = crate::utils::clock::Instant::now();
        let conn_state = ConnectionState {
            id: connection_id,
            remote_addr,
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
        app_state
            .add_connection_to_server(server_id, conn_state)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Peer messaging: the dashboard's "message this peer" / "disconnect this peer" inject
        // actions into THIS connection through the same executor the LLM path uses. Registered
        // before the negotiation LLM call, because a manual `*` rule can park that call for
        // minutes and the operator must be able to reach the connection while it waits. Every
        // RDP wire verb returns ActionResult::Output (or CloseConnection), so the generic peer
        // task covers the whole vocabulary — there is no Custom-result gap.
        let protocol: Arc<RdpProtocol> = Arc::new(RdpProtocol::new());
        let peer_rx = crate::server::peer_support::register_peer_channel(
            &app_state,
            server_id,
            connection_id.as_u32(),
        )
        .await;
        crate::server::peer_support::spawn_peer_command_task(
            peer_rx,
            protocol.clone(),
            app_state.clone(),
            server_id,
            connection_id.as_u32(),
            write_half.clone(),
            status_tx.clone(),
        );

        let result = Self::negotiate(
            &mut read_half,
            &write_half,
            connection_id,
            server_id,
            &app_state,
            &status_tx,
            &llm_client,
            &protocol,
        )
        .await;

        // Every exit path lands here: malformed framing, LLM error/fail-closed, or a clean CC.
        app_state
            .remove_peer_handle(server_id, connection_id.as_u32())
            .await;
        app_state
            .remove_connection_from_server(server_id, connection_id)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        result
    }

    /// Read and parse the CR, raise the event, and write the model's (or fail-closed) CC.
    #[allow(clippy::too_many_arguments)]
    async fn negotiate(
        read_half: &mut RdpReader,
        write_half: &Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        llm_client: &OllamaClient,
        protocol: &Arc<RdpProtocol>,
    ) -> Result<()> {
        let (request, bytes_in) = match read_connection_request(read_half).await {
            Ok(req) => req,
            Err(e) => {
                // Malformed framing: the stream cannot be resynchronised, so close.
                console_warn!(status_tx, "RDP malformed connection request: {}", e);
                return Ok(());
            }
        };
        app_state
            .update_connection_stats(
                server_id,
                connection_id,
                Some(bytes_in as u64),
                None,
                Some(1),
                None,
            )
            .await;

        let protocol_names = protocol_value_to_names(request.requested_protocols);
        console_debug!(
            status_tx,
            "RDP CR: user='{}', requested={:?}, flags={:#04x}",
            request.cookie_username,
            protocol_names,
            request.flags
        );

        let event = Event::new(
            &RDP_CONNECTION_REQUEST_EVENT,
            serde_json::json!({
                "cookie_username": request.cookie_username,
                "requested_protocols": protocol_names,
                "requested_protocols_flags": request.flags,
            }),
        );

        let response_bytes = match call_llm(
            llm_client,
            app_state,
            server_id,
            Some(connection_id),
            &event,
            protocol.as_ref(),
        )
        .await
        {
            Ok(execution) => {
                for message in execution.messages {
                    let _ = status_tx.send(message);
                }
                // Take the first Output the model produced (an accept or a reject CC).
                let mut chosen = None;
                for result in execution.protocol_results {
                    if let ActionResult::Output(bytes) = result {
                        chosen = Some(bytes);
                        break;
                    }
                }
                match chosen {
                    Some(bytes) => {
                        // `decision=` matters most here, because the wire cannot carry the
                        // distinction: a model that deliberately answers
                        // `reject_rdp_connection` with SSL_REQUIRED_BY_SERVER produces bytes
                        // identical to the fail-closed default below. `model_accept` vs
                        // `model_reject` is read off the RDP_NEG type octet of the message the
                        // executor actually built, not off what the model was asked for.
                        let decision = match negotiation_kind(&bytes) {
                            Some(TYPE_RDP_NEG_RSP) => "model_accept",
                            Some(TYPE_RDP_NEG_FAILURE) => "model_reject",
                            _ => "model_other",
                        };
                        debug!(
                            "RDP {} decision={} ({} bytes)",
                            connection_id,
                            decision,
                            bytes.len()
                        );
                        console_debug!(status_tx, "RDP {} decision={}", connection_id, decision);
                        bytes
                    }
                    None => {
                        // Fail closed: no usable action came back. Do NOT fall through to a
                        // permissive default (e.g. silently accepting standard RDP). Send an
                        // explicit negotiation failure and close — indistinguishable on the
                        // wire from the model deliberately rejecting with the same code, which
                        // is exactly why the tag below is the only record that separates them.
                        let tag = if execution.failures.is_empty() {
                            "fail_closed_model_silent"
                        } else {
                            "fail_closed_action_error"
                        };
                        warn!(
                            "RDP {} decision={}: no usable negotiation action; \
                             answering SSL_REQUIRED_BY_SERVER",
                            connection_id, tag
                        );
                        console_warn!(
                            status_tx,
                            "RDP {} decision={}: no usable negotiation action, failing closed (SSL_REQUIRED_BY_SERVER)",
                            connection_id,
                            tag
                        );
                        build_negotiation_failure(DEFAULT_FAILURE_CODE)
                    }
                }
            }
            Err(e) => {
                // The peer gets the same RDP_NEG_FAILURE whatever went wrong — there is no
                // free-text field in an X.224 Connection Confirm in which a `WireFailure`
                // category could be carried, and inventing a failureCode to encode "the
                // backend is busy" would be telling the client something [MS-RDPBCGR] does not
                // mean. So the category stays in the log, next to the error.
                warn!(
                    "RDP {} decision=fail_closed_llm_error ({:?}): {}",
                    connection_id,
                    crate::utils::WireFailure::classify(&e),
                    e
                );
                console_warn!(
                    status_tx,
                    "RDP {} decision=fail_closed_llm_error, failing closed (SSL_REQUIRED_BY_SERVER): {}",
                    connection_id,
                    e
                );
                build_negotiation_failure(DEFAULT_FAILURE_CODE)
            }
        };

        {
            let mut writer = write_half.lock().await;
            writer.write_all(&response_bytes).await?;
            writer.flush().await?;
        }
        app_state
            .update_connection_stats(
                server_id,
                connection_id,
                None,
                Some(response_bytes.len() as u64),
                None,
                Some(1),
            )
            .await;
        console_debug!(
            status_tx,
            "RDP sent {}-byte Connection Confirm to {}",
            response_bytes.len(),
            connection_id
        );

        // The slice ends at negotiation: we do not implement MCS/GCC, so there is nothing further
        // to exchange. Half-close so the client sees a clean end after the CC.
        {
            let mut writer = write_half.lock().await;
            let _ = writer.shutdown().await;
        }
        debug!("RDP negotiation complete for {}, closing", connection_id);
        Ok(())
    }
}

/// The RDP_NEG_* type octet of an encoded Connection Confirm, if it carries one.
///
/// Layout ([MS-RDPBCGR] 2.2.1.2): TPKT(4) + LI(1) + code(1) + dstRef(2) + srcRef(2) + class(1),
/// then the 8-byte RDP_NEG_* structure at offset 11. Reading it back is what lets the log say
/// whether the model accepted or refused without trusting the action name — the executor is
/// what decides, and only the bytes it produced know.
fn negotiation_kind(confirm: &[u8]) -> Option<u8> {
    confirm.get(11).copied()
}

/// Read one TPKT-framed X.224 Connection Request and parse its RDP negotiation fields.
///
/// Every length is bounded before allocation: the TPKT length field is client-controlled.
async fn read_connection_request(read_half: &mut RdpReader) -> Result<(ConnectionRequest, usize)> {
    // TPKT header: version(1)=0x03, reserved(1), length(2, big-endian, total incl. this header).
    let mut tpkt = [0u8; 4];
    read_half.read_exact(&mut tpkt).await?;
    if tpkt[0] != 0x03 {
        return Err(anyhow!("not a TPKT frame (first byte {:#04x})", tpkt[0]));
    }
    let total_len = u16::from_be_bytes([tpkt[2], tpkt[3]]) as usize;
    if total_len < 11 || total_len > MAX_X224_LEN {
        // 11 = TPKT(4) + minimal X.224 CR header(7).
        return Err(anyhow!("implausible TPKT length {total_len}"));
    }

    let x224_len = total_len - 4;
    let mut x224 = vec![0u8; x224_len];
    read_half.read_exact(&mut x224).await?;

    // X.224 CR header: LI(1), code(1), dstRef(2), srcRef(2), class(1) = 7 bytes.
    if x224.len() < 7 {
        return Err(anyhow!("X.224 CR too short ({} bytes)", x224.len()));
    }
    let code = x224[1];
    if code != X224_TPDU_CONNECTION_REQUEST {
        return Err(anyhow!(
            "X.224 TPDU is not a Connection Request (code {:#04x})",
            code
        ));
    }

    // Variable part after the fixed 7-byte header: optional routing cookie then optional
    // RDP_NEG_REQ (and possibly RDP_CORRELATION_INFO, which we ignore).
    let variable = &x224[7..];
    let (cookie_username, after_cookie) = parse_routing_cookie(variable);
    let (requested_protocols, flags) = parse_rdp_neg_req(after_cookie);

    // Total wire bytes consumed: the 4-byte TPKT header plus the X.224 body.
    let bytes_in = 4 + x224.len();
    Ok((
        ConnectionRequest {
            cookie_username,
            requested_protocols,
            flags,
        },
        bytes_in,
    ))
}

/// Parse an optional `Cookie: mstshash=<user>\r\n` (or `Cookie: msts=<token>\r\n`) routing token.
///
/// Returns the extracted `mstshash` username (empty if none or if it was a non-mstshash routing
/// token) and the slice of `data` following the token.
fn parse_routing_cookie(data: &[u8]) -> (String, &[u8]) {
    const COOKIE_PREFIX: &[u8] = b"Cookie: ";
    if !data.starts_with(COOKIE_PREFIX) {
        return (String::new(), data);
    }
    // Find the terminating CRLF.
    let Some(crlf) = data.windows(2).position(|w| w == b"\r\n") else {
        return (String::new(), data);
    };
    let line = &data[COOKIE_PREFIX.len()..crlf];
    let rest = &data[crlf + 2..];

    const MSTSHASH: &[u8] = b"mstshash=";
    let username = if line.starts_with(MSTSHASH) {
        String::from_utf8_lossy(&line[MSTSHASH.len()..]).to_string()
    } else {
        String::new()
    };
    (username, rest)
}

/// Parse an optional 8-byte RDP_NEG_REQ (type 0x01) at the start of `data`.
///
/// Returns `(requestedProtocols, flags)`, defaulting to `(0, 0)` — standard RDP security — when
/// no RDP_NEG_REQ is present, which is exactly what an absent structure means in [MS-RDPBCGR].
fn parse_rdp_neg_req(data: &[u8]) -> (u32, u8) {
    if data.len() < 8 || data[0] != TYPE_RDP_NEG_REQ {
        return (0, 0);
    }
    let flags = data[1];
    // data[2..4] is the length field (always 0x0008); requestedProtocols is little-endian.
    let requested = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    (requested, flags)
}

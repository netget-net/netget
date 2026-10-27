//! Modbus TCP server.
//!
//! Owns framing and the connection state machine; the model owns the data. See
//! `src/server/modbus/CLAUDE.md`.

pub mod actions;
pub mod codec;

use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;

use actions::{
    ModbusProtocol, MODBUS_READ_BITS_EVENT, MODBUS_READ_REGISTERS_EVENT,
    MODBUS_WRITE_REQUEST_EVENT, RESULT_BITS, RESULT_EXCEPTION, RESULT_REGISTERS, RESULT_WRITE_ACK,
};
use codec::{ModbusRequest, MAX_ADU_LEN};

/// Per-connection LLM processing state, mirroring `src/server/tcp/mod.rs`.
#[derive(Debug, Clone, PartialEq)]
enum ConnectionState {
    /// No request in flight; ready to process.
    Idle,
    /// An LLM call is in flight; arriving bytes are queued into `buffer`.
    Processing,
    /// A partial ADU is buffered and we are waiting for the rest of it.
    Accumulating,
}

struct ConnectionData {
    state: ConnectionState,
    /// Doubles as the framing accumulator and the queue for bytes that arrive mid-call.
    buffer: Vec<u8>,
    write_half: Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
    /// Signalled by [`ModbusServer::close`] so the connection's reader stops too.
    ///
    /// `close` mostly runs on the answering task (`answer`), not on the reader, and shutting the
    /// write half only half-closes the socket. Without this signal the reader goes on reading
    /// from a peer the server has already dropped — holding the read half, and with it the
    /// connection-cap permit, until the peer hangs up or stays quiet for the whole idle bound. A
    /// peer could then occupy a slot by sending one malformed header and keeping its end open.
    closed: Arc<tokio::sync::Notify>,
}

/// How much one connection may accumulate before we give up on it: eight ADUs' worth.
///
/// The buffer is both the framing accumulator and the queue for bytes that arrive while a
/// request is with the model. It is enforced on *append*, in `admit_read`, which is the only
/// code that grows the buffer — the framing loop only drains it. The placement is the point:
/// while a request is with the model the framing loop does not run at all, so a bound checked
/// there would leave the queue unbounded for the whole LLM call, which at the shipped
/// `--llm-queue-timeout` of 120s is long enough for a peer to push gigabytes into it.
///
/// Outside a model call a peer cannot reach it: an incomplete ADU is at most `MAX_ADU_LEN - 1`
/// octets, so only bytes queued behind an in-flight request add up to it.
pub const MAX_BUFFERED: usize = MAX_ADU_LEN * 8;

/// How long to wait for a peer's first bytes after it connects.
///
/// Modbus TCP is client-speaks-first — the server says nothing until it has a request — and a
/// client sends its first PDU inside its own connect path (`tokio-modbus` and `mbpoll` both do).
/// So a peer that has connected and sent nothing has begun no transaction at all, which is the
/// state an unauthenticated flood lives in: Modbus has no authentication step of any kind.
///
/// This is the default; the `first_byte_timeout_secs` startup parameter overrides it.
pub const FIRST_BYTE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a peer that has already sent something may send nothing further.
///
/// Modbus TCP defines no keepalive, so there is no protocol interval to sit above; what there
/// is, is polling. A SCADA master polls on a sub-second to few-second cycle, so any real client
/// speaks orders of magnitude more often than this.
///
/// The number is set by *this* server rather than by Modbus: a request is answered on its own
/// task, so the reader keeps reading while a request is being answered, and a peer waiting for
/// its own reply is silent on this socket for the whole of that work — including a `manual`
/// rule parked for a human, 300 seconds by default. Ten minutes leaves that a factor of two.
/// Real Modbus/TCP gateways commonly reap an idle connection at 60 seconds; being ten times more
/// patient is the deliberate price of letting a human answer.
///
/// This is the default; the `idle_timeout_secs` startup parameter overrides it. An operator
/// exposing the port to strangers with no human in the loop wants it near the gateway figure.
pub const IDLE_BETWEEN_REQUESTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Concurrent connections this server admits.
///
/// Each admitted connection may buffer [`MAX_BUFFERED`] bytes and holds a read task, a peer
/// handle and an `AppState` row, so the cap is what turns those per-connection bounds into total
/// ones. A real PLC admits single digits; 256 is the shared default and is still far below what
/// an attacker needs for socket exhaustion to matter.
pub const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes: **nothing**.
///
/// Modbus has no way to say it. Every server message is an exception or a data response, and both
/// are replies — they carry the transaction identifier, unit id and function code of a request
/// this peer has not sent. Inventing one means inventing a transaction, which is worse than
/// silence for the same reason twenty protocols here are deliberately silent on an LLM failure.
/// So the refusal is a plain close and the reason lives in the log, under the
/// `decision=fail_closed_connection_cap` tag `accept_bounded` writes.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// Why a request is being answered the way it is.
///
/// The wire cannot carry the distinction: a model that deliberately refuses with exception
/// 0x04 and a model that never answered at all both put `04` on the wire. So the log
/// carries it instead, with stable tokens - `decision=fail_closed_` finds every request the
/// model did not actually answer. Mirrors `src/server/radius/`, which is the reference for
/// this split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// The model supplied the values, or accepted the write.
    ModelAnswer,
    /// The model deliberately refused, with a Modbus exception of its choosing.
    ModelReject,
    /// The model answered a read with the addresses this device has, and at least one of the
    /// addresses asked for is not among them: exception 2, decided by the model's own map.
    ModelAddressAbsent,
    /// The specification determined the answer; the model was never asked.
    SpecReject,
    /// Addressed to a unit id this device does not answer for.
    UnitMismatch,
    /// The LLM backend failed. Nobody decided anything.
    FailClosedLlmError,
    /// The model was asked and returned nothing this request could use.
    FailClosedNoAction,
    /// The model answered a different question: bits for a register read, a write ack for
    /// a read, or the wrong number of values for the quantity requested.
    FailClosedWrongShape,
    /// The stream stopped being Modbus: a protocol id other than 0, or an MBAP length outside
    /// `2..=254`. Not a request, so nothing is answered; the connection is closed.
    FailClosedFramingError,
    /// More than [`MAX_BUFFERED`] octets queued on one connection. Closed, not answered.
    FailClosedBufferOverflow,
}

impl Decision {
    fn as_str(self) -> &'static str {
        match self {
            Decision::ModelAnswer => "model_answer",
            Decision::ModelReject => "model_reject",
            Decision::ModelAddressAbsent => "model_address_absent",
            Decision::SpecReject => "spec_reject",
            Decision::UnitMismatch => "unit_mismatch",
            Decision::FailClosedLlmError => "fail_closed_llm_error",
            Decision::FailClosedNoAction => "fail_closed_no_action",
            Decision::FailClosedWrongShape => "fail_closed_wrong_shape",
            Decision::FailClosedFramingError => "fail_closed_framing_error",
            Decision::FailClosedBufferOverflow => "fail_closed_buffer_overflow",
        }
    }

    fn is_fail_closed(self) -> bool {
        matches!(
            self,
            Decision::FailClosedLlmError
                | Decision::FailClosedNoAction
                | Decision::FailClosedWrongShape
                | Decision::FailClosedFramingError
                | Decision::FailClosedBufferOverflow
        )
    }
}

/// Modbus TCP server.
pub struct ModbusServer;

impl ModbusServer {
    /// Bind, start accepting, and register the accept loop so `stop_server` releases the port.
    ///
    /// Returns `Err` if the socket cannot be bound, so `server_startup` records
    /// `ServerStatus::Error` rather than a server that is not listening.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        unit_id_filter: Option<u8>,
        server_id: crate::state::ServerId,
        first_byte_timeout: std::time::Duration,
        idle_timeout: std::time::Duration,
    ) -> Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        Log::new(Some(&status_tx)).info(format!("Modbus server listening on {local_addr}"));

        let connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let protocol = Arc::new(ModbusProtocol::new());

        let task_registrar = app_state.clone();
        let accept_handle = tokio::spawn(async move {
            Log::new(Some(&status_tx)).info(format!("Modbus accept loop started on {local_addr}"));

            let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Modbus",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        info!(
                            "Modbus accepted connection {} from {}",
                            connection_id, remote_addr
                        );

                        let (mut read_half, write_half) = tokio::io::split(stream);
                        let write_half = Arc::new(Mutex::new(write_half));

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
                                    remote_addr,
                                    local_addr: local_addr_conn,
                                    bytes_sent: 0,
                                    bytes_received: 0,
                                    packets_sent: 0,
                                    packets_received: 0,
                                    last_activity: now,
                                    status: ConnectionStatus::Active,
                                    status_changed_at: now,
                                    protocol_info: ProtocolConnectionInfo::new(serde_json::json!({
                                        "state": "Idle",
                                        "unit_id_filter": unit_id_filter,
                                    })),
                                },
                            )
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        // Register before spawning the reader, so a client that writes
                        // immediately after connect() cannot have its first frame dropped.
                        let closed = Arc::new(tokio::sync::Notify::new());
                        connections.lock().await.insert(
                            connection_id,
                            ConnectionData {
                                state: ConnectionState::Idle,
                                buffer: Vec::new(),
                                write_half: write_half.clone(),
                                closed: closed.clone(),
                            },
                        );

                        // Peer messaging: the dashboard's "disconnect this peer" injects
                        // `close_connection` into THIS connection through the same executor
                        // the LLM path uses. The four Modbus wire verbs are request-bound
                        // (they return `ActionResult::Custom` and are framed against the
                        // request's transaction id), so an injected one is reported as
                        // executed without writing — a Modbus server never initiates.
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

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let conns_clone = connections.clone();
                        let protocol_clone = protocol.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection: dropping it early
                                // releases the slot while the peer is still here, which
                                // silently un-caps the server.
                                let _permit = permit;
                                let mut read_buf = vec![0u8; 4096];
                                let log = Log::new(Some(&status_clone));
                                // "Has said nothing at all" and "has gone quiet mid-session"
                                // are different claims and get different deadlines.
                                let mut spoke_once = false;
                                loop {
                                    let read_deadline = if spoke_once {
                                        idle_timeout
                                    } else {
                                        first_byte_timeout
                                    };
                                    // The deadline wraps this read and nothing else. Modbus has
                                    // no message a server may send unprompted, so a peer
                                    // dropped for silence is closed without a byte — the
                                    // reason is the log line.
                                    let timed_read = tokio::select! {
                                        // `close` has already torn the connection down; stop
                                        // reading so the socket and the permit go with it.
                                        _ = closed.notified() => break,
                                        r = tokio::time::timeout(
                                            read_deadline,
                                            read_half.read(&mut read_buf),
                                        ) => r,
                                    };
                                    let read_result = match timed_read {
                                        Ok(v) => v,
                                        Err(_) => {
                                            log.info(format!(
                                                "Modbus connection {connection_id} sent nothing \
                                                 for {}s; closing \
                                                 decision=fail_closed_idle_timeout",
                                                read_deadline.as_secs()
                                            ));
                                            conns_clone.lock().await.remove(&connection_id);
                                            state_clone
                                                .remove_peer_handle(
                                                    server_id,
                                                    connection_id.as_u32(),
                                                )
                                                .await;
                                            state_clone
                                                .close_connection_on_server(
                                                    server_id,
                                                    connection_id,
                                                )
                                                .await;
                                            let _ = status_clone.send("__UPDATE_UI__".to_string());
                                            break;
                                        }
                                    };
                                    match read_result {
                                        Ok(0) => {
                                            conns_clone.lock().await.remove(&connection_id);
                                            state_clone
                                                .remove_peer_handle(
                                                    server_id,
                                                    connection_id.as_u32(),
                                                )
                                                .await;
                                            state_clone
                                                .close_connection_on_server(
                                                    server_id,
                                                    connection_id,
                                                )
                                                .await;
                                            log.info(format!(
                                                "Modbus connection {connection_id} closed"
                                            ));
                                            let _ = status_clone.send("__UPDATE_UI__".to_string());
                                            break;
                                        }
                                        Ok(n) => {
                                            spoke_once = true;
                                            let data = read_buf[..n].to_vec();
                                            // Summary + full payload FileOnly: the modbus_* event
                                            // templates render the equivalent line to the TUI.
                                            log.debug(format!(
                                                "Modbus received {} bytes on {}",
                                                n, connection_id
                                            ));
                                            log.trace(format!(
                                                "Modbus received (hex): {}",
                                                hex::encode(&data)
                                            ));
                                            state_clone
                                                .update_connection_stats(
                                                    server_id,
                                                    connection_id,
                                                    Some(n as u64),
                                                    None,
                                                    Some(1),
                                                    None,
                                                )
                                                .await;

                                            // Into the accumulator here, in the order the reads
                                            // arrived. Appending in a task spawned per read let
                                            // a later read's bytes land ahead of an earlier
                                            // one's — the back of an ADU in front of its MBAP
                                            // header — because nothing orders spawned tasks.
                                            if !Self::admit_read(
                                                connection_id,
                                                server_id,
                                                &data,
                                                &state_clone,
                                                &conns_clone,
                                                &status_clone,
                                            )
                                            .await
                                            {
                                                continue;
                                            }

                                            // The answer runs in its own task so the loop can
                                            // go back to reading: what arrives meanwhile is
                                            // appended by `admit_read` and framed by that task.
                                            let llm = llm_clone.clone();
                                            let st = state_clone.clone();
                                            let stx = status_clone.clone();
                                            let cs = conns_clone.clone();
                                            let pr = protocol_clone.clone();
                                            // Tracked, not detached: stop_server must abort this task too.
                                            let task_owner = state_clone.clone();
                                            task_owner
                                                .spawn_server_task(server_id, async move {
                                                    Self::answer(
                                                        connection_id,
                                                        server_id,
                                                        unit_id_filter,
                                                        llm,
                                                        st,
                                                        stx,
                                                        cs,
                                                        pr,
                                                    )
                                                    .await;
                                                })
                                                .await;
                                        }
                                        Err(e) => {
                                            error!("Modbus read error on {}: {}", connection_id, e);
                                            conns_clone.lock().await.remove(&connection_id);
                                            state_clone
                                                .remove_peer_handle(
                                                    server_id,
                                                    connection_id.as_u32(),
                                                )
                                                .await;
                                            state_clone
                                                .close_connection_on_server(
                                                    server_id,
                                                    connection_id,
                                                )
                                                .await;
                                            break;
                                        }
                                    }
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        error!("Modbus accept error: {}", e);
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

    /// Append one read to the connection's accumulator, in the order the reader got it, and
    /// say whether it starts an answer.
    ///
    /// Called by the reader itself, never from a spawned task: appending in a task per read let
    /// a later read's task run first, so its bytes landed ahead of the earlier read's — the
    /// back of an ADU in front of its MBAP header, which is a framing error and a closed
    /// connection. `true` moves the connection to `Processing`, and the caller must run exactly
    /// one [`Self::answer`]; `false` means an answer is already running and will frame these
    /// bytes when it loops (or the connection has gone, or was closed for buffering too much).
    async fn admit_read(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        data: &[u8],
        app_state: &Arc<AppState>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> bool {
        let mut conns = connections.lock().await;
        let Some(conn) = conns.get_mut(&connection_id) else {
            return false; // Closed: the bytes have nowhere to go.
        };
        conn.buffer.extend_from_slice(data);

        // Enforced here, on append, rather than in the framing loop: while a request is with
        // the model this is the *only* code touching the buffer, so a loop-only check would let
        // a flooding peer grow the queue without bound for the whole duration of the call.
        if conn.buffer.len() > MAX_BUFFERED {
            error!(
                "Modbus {} queued {} bytes, past the {} one connection may buffer; closing \
                 decision={}",
                connection_id,
                conn.buffer.len(),
                MAX_BUFFERED,
                Decision::FailClosedBufferOverflow.as_str()
            );
            conn.buffer.clear();
            drop(conns);
            Self::close(connection_id, server_id, app_state, connections, status_tx).await;
            return false;
        }

        if conn.state == ConnectionState::Processing {
            drop(conns);
            Log::new(Some(status_tx)).debug(format!(
                "Queued {} bytes for Modbus {connection_id}",
                data.len()
            ));
            return false;
        }
        conn.state = ConnectionState::Processing;
        true
    }

    /// Frame and answer every complete ADU in the accumulator of a connection
    /// [`Self::admit_read`] has moved to `Processing`, including bytes appended while it runs,
    /// then park it `Accumulating` (a partial ADU) or `Idle` under the lock that found nothing
    /// more to frame.
    ///
    /// One of these runs per connection at a time: only the move into `Processing` starts one,
    /// and it leaves `Processing` only when it ends.
    #[allow(clippy::too_many_arguments)]
    async fn answer(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        unit_id_filter: Option<u8>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: Arc<ModbusProtocol>,
    ) {
        let log = Log::new(Some(&status_tx));

        loop {
            // Pull one complete ADU out of the accumulator.
            let parsed = {
                let mut conns = connections.lock().await;
                let Some(conn) = conns.get_mut(&connection_id) else {
                    return;
                };

                // No MAX_BUFFERED check here: this loop only drains the buffer, and the append
                // above is the one place it grows.
                match codec::try_parse_adu(&conn.buffer) {
                    Ok(Some((adu, consumed))) => {
                        conn.buffer.drain(..consumed);
                        Ok(Some(adu))
                    }
                    Ok(None) => {
                        // Nothing more to do: park in Accumulating (or Idle when the
                        // accumulator is empty) and let the next read wake us.
                        conn.state = if conn.buffer.is_empty() {
                            ConnectionState::Idle
                        } else {
                            ConnectionState::Accumulating
                        };
                        Ok(None)
                    }
                    Err(e) => Err(e),
                }
            };

            let adu = match parsed {
                Ok(Some(adu)) => adu,
                Ok(None) => return,
                Err(e) => {
                    // Neither error is answerable: we no longer know where the next frame
                    // starts, so the only honest signal is to close.
                    log.error(format!(
                        "Modbus framing error on {connection_id}: {e}; closing decision={}",
                        Decision::FailClosedFramingError.as_str()
                    ));
                    Self::close(
                        connection_id,
                        server_id,
                        &app_state,
                        &connections,
                        &status_tx,
                    )
                    .await;
                    return;
                }
            };

            let function_code = adu.pdu.first().copied().unwrap_or(0);

            // Unit routing, when the operator pinned this server to one unit id.
            if let Some(expected) = unit_id_filter {
                if adu.unit_id != expected {
                    warn!(
                        "Modbus {} addressed unit {} but this device answers for unit {} \
                         decision={}",
                        connection_id,
                        adu.unit_id,
                        expected,
                        Decision::UnitMismatch.as_str()
                    );
                    let pdu =
                        codec::encode_exception(function_code, codec::EXC_GATEWAY_TARGET_FAILED);
                    Self::send_pdu(
                        connection_id,
                        server_id,
                        adu.transaction_id,
                        adu.unit_id,
                        &pdu,
                        &app_state,
                        &connections,
                        &status_tx,
                    )
                    .await;
                    continue;
                }
            }

            // Spec-determined failures are answered here, with no model round-trip: an
            // unknown function code is always 0x01, a zero quantity always 0x03.
            let request = match codec::parse_request(&adu.pdu) {
                Ok(r) => r,
                Err(exception_code) => {
                    debug!(
                        "Modbus {} rejecting fc={:#04x} with exception {:#04x} ({}) decision={}",
                        connection_id,
                        function_code,
                        exception_code,
                        codec::exception_name(exception_code),
                        Decision::SpecReject.as_str()
                    );
                    let pdu = codec::encode_exception(function_code, exception_code);
                    Self::send_pdu(
                        connection_id,
                        server_id,
                        adu.transaction_id,
                        adu.unit_id,
                        &pdu,
                        &app_state,
                        &connections,
                        &status_tx,
                    )
                    .await;
                    continue;
                }
            };

            let (event_type, mut event_data) = Self::build_event(&adu, &request);
            event_data["unit_id"] = serde_json::json!(adu.unit_id);
            let event = Event::new(event_type, event_data);

            let (decision, pdu) = match call_llm(
                &llm_client,
                &app_state,
                server_id,
                Some(connection_id),
                &event,
                protocol.as_ref(),
            )
            .await
            {
                Ok(execution_result) => {
                    for msg in execution_result.messages {
                        let _ = status_tx.send(msg);
                    }
                    Self::pdu_from_results(
                        connection_id,
                        &request,
                        &execution_result.protocol_results,
                    )
                }
                Err(e) => {
                    // Non-fatal: the client still gets a device-failure exception (wire
                    // fallback), so this is WARN not ERROR. The error text stays in the
                    // log; the wire gets only the exception code.
                    log.warn(format!("Modbus LLM error on {connection_id}: {e}"));
                    // Fail closed and say so on the wire. Writing nothing would leave the
                    // client blocked until its own timeout with no diagnostic.
                    (
                        Decision::FailClosedLlmError,
                        codec::encode_exception(
                            request.function_code(),
                            codec::EXC_SERVER_DEVICE_FAILURE,
                        ),
                    )
                }
            };

            // Log the decision before writing it, and make the fail-closed paths loud.
            // On this protocol a fabricated value has physical consequences, so an
            // operator has to be able to tell "the device said so" from "nobody
            // answered" - and the wire cannot: both can be exception 0x04.
            let summary = format!(
                "Modbus {} {} unit={} @{} x{} decision={}",
                connection_id,
                request.function_name(),
                adu.unit_id,
                request.start_address(),
                request.quantity(),
                decision.as_str()
            );
            if decision.is_fail_closed() {
                log.error(format!(
                    "{summary} (answered with an exception because no usable answer was \
                     produced)"
                ));
            } else {
                log.debug(&summary);
            }

            Self::send_pdu(
                connection_id,
                server_id,
                adu.transaction_id,
                adu.unit_id,
                &pdu,
                &app_state,
                &connections,
                &status_tx,
            )
            .await;
        }
    }

    /// Choose the event type and build its data from a decoded request.
    fn build_event(
        adu: &codec::Adu,
        request: &ModbusRequest,
    ) -> (&'static crate::protocol::EventType, serde_json::Value) {
        let mut data = serde_json::json!({
            "unit_id": adu.unit_id,
            "function_code": request.function_code(),
            "function": request.function_name(),
            "start_address": request.start_address(),
            "quantity": request.quantity(),
            "answer_with": actions::answer_with_for_request(request),
        });

        match request {
            ModbusRequest::ReadCoils { .. } => {
                data["bit_type"] = serde_json::json!("coil");
                (&MODBUS_READ_BITS_EVENT, data)
            }
            ModbusRequest::ReadDiscreteInputs { .. } => {
                data["bit_type"] = serde_json::json!("discrete_input");
                (&MODBUS_READ_BITS_EVENT, data)
            }
            ModbusRequest::ReadHoldingRegisters { .. } => {
                data["register_type"] = serde_json::json!("holding");
                (&MODBUS_READ_REGISTERS_EVENT, data)
            }
            ModbusRequest::ReadInputRegisters { .. } => {
                data["register_type"] = serde_json::json!("input");
                (&MODBUS_READ_REGISTERS_EVENT, data)
            }
            ModbusRequest::WriteSingleCoil { value, .. } => {
                data["coil_values"] = serde_json::json!([value]);
                (&MODBUS_WRITE_REQUEST_EVENT, data)
            }
            ModbusRequest::WriteMultipleCoils { values, .. } => {
                data["coil_values"] = serde_json::json!(values);
                (&MODBUS_WRITE_REQUEST_EVENT, data)
            }
            ModbusRequest::WriteSingleRegister { value, .. } => {
                data["register_values"] = serde_json::json!([value]);
                (&MODBUS_WRITE_REQUEST_EVENT, data)
            }
            ModbusRequest::WriteMultipleRegisters { values, .. } => {
                data["register_values"] = serde_json::json!(values);
                (&MODBUS_WRITE_REQUEST_EVENT, data)
            }
        }
    }

    /// Turn the model's structured answer into the PDU to put on the wire.
    ///
    /// Fails closed: anything that is not a usable answer to *this* request becomes a
    /// `server device failure` exception rather than a plausible-looking default. A
    /// silent LLM and a model that answered the wrong question are both faults, and the
    /// client is told so.
    fn pdu_from_results(
        connection_id: ConnectionId,
        request: &ModbusRequest,
        results: &[ActionResult],
    ) -> (Decision, Vec<u8>) {
        let fc = request.function_code();

        for result in results {
            let ActionResult::Custom { name, data } = result else {
                continue;
            };

            match name.as_str() {
                RESULT_EXCEPTION => {
                    // `execute_action` has already checked this against the exception
                    // codes the specification defines, so the fallback is unreachable
                    // today. It is written as a fail-closed default rather than a cast so
                    // it stays correct if another producer of this result ever appears:
                    // `n as u8` would silently turn 0x104 into 0x04.
                    let code = data
                        .get("exception_code")
                        .and_then(|v| v.as_u64())
                        .filter(|n| *n <= u8::MAX as u64)
                        .map(|n| n as u8)
                        .unwrap_or(codec::EXC_SERVER_DEVICE_FAILURE);
                    return (Decision::ModelReject, codec::encode_exception(fc, code));
                }
                RESULT_BITS => {
                    if !request.is_bit_read() {
                        error!(
                            "Modbus {}: send_modbus_bits answered a {} request; bits only \
                             answer function codes 1 and 2",
                            connection_id,
                            request.function_name()
                        );
                        return (
                            Decision::FailClosedWrongShape,
                            codec::encode_exception(fc, codec::EXC_SERVER_DEVICE_FAILURE),
                        );
                    }
                    let values: Vec<bool> = if let Some(map) = data.get("bits") {
                        match Self::read_from_map(connection_id, request, map, |v| v.as_bool()) {
                            Ok(values) => values,
                            Err(absent) => return absent,
                        }
                    } else {
                        data.get("values")
                            .and_then(|v| v.as_array())
                            .map(|a| a.iter().filter_map(|v| v.as_bool()).collect())
                            .unwrap_or_default()
                    };
                    if values.len() != request.quantity() as usize {
                        error!(
                            "Modbus {}: model returned {} bit value(s) for a request of {}; \
                             answering with a device failure rather than a truncated frame",
                            connection_id,
                            values.len(),
                            request.quantity()
                        );
                        return (
                            Decision::FailClosedWrongShape,
                            codec::encode_exception(fc, codec::EXC_SERVER_DEVICE_FAILURE),
                        );
                    }
                    // Unreachable while the count check above holds — `parse_request` caps a
                    // coil read at 2000 bits — but the codec is what owns the bound, so its
                    // refusal is answered rather than unwrapped.
                    return match codec::encode_bits_response(fc, &values) {
                        Ok(pdu) => (Decision::ModelAnswer, pdu),
                        Err(e) => {
                            error!(
                                "Modbus {}: cannot encode a bit response: {}",
                                connection_id, e
                            );
                            (
                                Decision::FailClosedWrongShape,
                                codec::encode_exception(fc, codec::EXC_SERVER_DEVICE_FAILURE),
                            )
                        }
                    };
                }
                RESULT_REGISTERS => {
                    if !request.is_register_read() {
                        error!(
                            "Modbus {}: send_modbus_registers answered a {} request; registers \
                             only answer function codes 3 and 4",
                            connection_id,
                            request.function_name()
                        );
                        return (
                            Decision::FailClosedWrongShape,
                            codec::encode_exception(fc, codec::EXC_SERVER_DEVICE_FAILURE),
                        );
                    }
                    // Filtered, never cast. `n as u16` would turn a model's 65736 into
                    // 200 and put it on the wire as a plant reading, which on this
                    // protocol is a fabricated measurement with physical consequences.
                    // Anything out of range is dropped here, which makes the count wrong,
                    // which the check below turns into an exception.
                    let in_range = |v: &serde_json::Value| {
                        v.as_u64()
                            .filter(|n| *n <= u16::MAX as u64)
                            .map(|n| n as u16)
                    };
                    let values: Vec<u16> = if let Some(map) = data.get("registers") {
                        match Self::read_from_map(connection_id, request, map, in_range) {
                            Ok(values) => values,
                            Err(absent) => return absent,
                        }
                    } else {
                        data.get("values")
                            .and_then(|v| v.as_array())
                            .map(|a| a.iter().filter_map(in_range).collect())
                            .unwrap_or_default()
                    };
                    if values.len() != request.quantity() as usize {
                        error!(
                            "Modbus {}: model returned {} register value(s) for a request of \
                             {}; answering with a device failure rather than a truncated frame",
                            connection_id,
                            values.len(),
                            request.quantity()
                        );
                        return (
                            Decision::FailClosedWrongShape,
                            codec::encode_exception(fc, codec::EXC_SERVER_DEVICE_FAILURE),
                        );
                    }
                    // Unreachable while the count check above holds — `parse_request` caps a
                    // register read at 125 — but the codec is what owns the bound.
                    return match codec::encode_registers_response(fc, &values) {
                        Ok(pdu) => (Decision::ModelAnswer, pdu),
                        Err(e) => {
                            error!(
                                "Modbus {}: cannot encode a register response: {}",
                                connection_id, e
                            );
                            (
                                Decision::FailClosedWrongShape,
                                codec::encode_exception(fc, codec::EXC_SERVER_DEVICE_FAILURE),
                            )
                        }
                    };
                }
                RESULT_WRITE_ACK => {
                    if !request.is_write() {
                        error!(
                            "Modbus {}: send_modbus_write_ack answered a {} request, which is \
                             a read",
                            connection_id,
                            request.function_name()
                        );
                        return (
                            Decision::FailClosedWrongShape,
                            codec::encode_exception(fc, codec::EXC_SERVER_DEVICE_FAILURE),
                        );
                    }
                    return (Decision::ModelAnswer, codec::encode_write_ack(request));
                }
                _ => {}
            }
        }

        error!(
            "Modbus {}: no usable action returned for {}; answering with exception 0x04 \
             (server device failure)",
            connection_id,
            request.function_name()
        );
        (
            Decision::FailClosedNoAction,
            codec::encode_exception(fc, codec::EXC_SERVER_DEVICE_FAILURE),
        )
    }

    /// The requested window of an address-keyed answer, in address order.
    ///
    /// The model answers a read with the addresses the device has; a requested address with no
    /// entry is one the device does not have, which Modbus answers with exception 2 (illegal
    /// data address) for the whole request. `Err` carries that answer, ready to send. A value
    /// `read` cannot use is left out, so the count check after this refuses the answer as the
    /// wrong shape rather than sending a value the model did not give.
    fn read_from_map<T>(
        connection_id: ConnectionId,
        request: &ModbusRequest,
        map: &serde_json::Value,
        read: impl Fn(&serde_json::Value) -> Option<T>,
    ) -> std::result::Result<Vec<T>, (Decision, Vec<u8>)> {
        let start = u32::from(request.start_address());
        let end = start + u32::from(request.quantity());
        let mut values = Vec::with_capacity(request.quantity() as usize);
        for address in start..end {
            match map.get(address.to_string()) {
                Some(value) => values.extend(read(value)),
                None => {
                    debug!(
                        "Modbus {}: address {} of {} is not among the addresses the model gave; \
                         answering exception 2 (illegal data address)",
                        connection_id,
                        address,
                        request.function_name()
                    );
                    return Err((
                        Decision::ModelAddressAbsent,
                        codec::encode_exception(
                            request.function_code(),
                            codec::EXC_ILLEGAL_DATA_ADDRESS,
                        ),
                    ));
                }
            }
        }
        Ok(values)
    }

    /// Frame a PDU and write it, updating counters and the dual logs.
    #[allow(clippy::too_many_arguments)]
    async fn send_pdu(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        transaction_id: u16,
        unit_id: u8,
        pdu: &[u8],
        app_state: &Arc<AppState>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        // A PDU the framer refuses is dropped rather than sent in a frame whose MBAP length
        // field disagrees with it. Every PDU reaching here is built by this module's own
        // encoders, which are bounded, so this is a ratchet rather than a live path.
        let adu = match codec::encode_adu(transaction_id, unit_id, pdu) {
            Ok(adu) => adu,
            Err(e) => {
                error!(
                    "Modbus {} decision=fail_closed_encode: refusing to frame a {}-octet PDU: {}",
                    connection_id,
                    pdu.len(),
                    e
                );
                return;
            }
        };

        let write_half = {
            let conns = connections.lock().await;
            conns.get(&connection_id).map(|c| c.write_half.clone())
        };
        let Some(write_half) = write_half else {
            return;
        };

        let mut write = write_half.lock().await;
        if let Err(e) = write.write_all(&adu).await {
            error!("Modbus write failed on {}: {}", connection_id, e);
            return;
        }
        if let Err(e) = write.flush().await {
            error!("Modbus flush failed on {}: {}", connection_id, e);
            return;
        }
        drop(write);

        app_state
            .update_connection_stats(
                server_id,
                connection_id,
                None,
                Some(adu.len() as u64),
                None,
                Some(1),
            )
            .await;

        // Summary + full payload FileOnly: the send_modbus_* action template already
        // reports the send to the TUI.
        let log = Log::new(Some(status_tx));
        log.debug(format!(
            "Modbus sent {} bytes to {} (txid={}, fc={:#04x})",
            adu.len(),
            connection_id,
            transaction_id,
            pdu.first().copied().unwrap_or(0)
        ));
        log.trace(format!("Modbus sent (hex): {}", hex::encode(&adu)));
    }

    /// Drop a connection from both the local map and `AppState`.
    async fn close(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        app_state: &Arc<AppState>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        let removed = {
            let mut conns = connections.lock().await;
            conns.remove(&connection_id)
        };
        let write_half = removed.map(|c| {
            // `notify_one` stores a permit when the reader is not parked on `notified()` at this
            // instant, so the wake-up cannot be lost to a read that is mid-flight.
            c.closed.notify_one();
            c.write_half
        });
        if let Some(write_half) = write_half {
            let mut w = write_half.lock().await;
            let _ = w.shutdown().await;
        }
        app_state
            .remove_peer_handle(server_id, connection_id.as_u32())
            .await;
        app_state
            .close_connection_on_server(server_id, connection_id)
            .await;
        Log::new(Some(status_tx)).info(format!("Modbus connection {connection_id} closed"));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }
}

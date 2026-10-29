//! Bitcoin P2P protocol server implementation
pub mod actions;

use anyhow::{Context, Result};
use bitcoin::consensus::Decodable;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::Magic;
use std::collections::HashMap;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::debug;

use super::connection::ConnectionId;
use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::read_queue::{Admitted, Held, ReadQueue};
use crate::server::BitcoinProtocol;
use crate::state::app_state::AppState;
use actions::{BITCOIN_CONNECTION_OPENED_EVENT, BITCOIN_MESSAGE_RECEIVED_EVENT};

/// Per-connection data for Bitcoin protocol
struct ConnectionData {
    /// The Idle → Processing → Accumulating machine and the bytes waiting behind the message
    /// being answered. Every decision on it is made under the connection map's lock; see
    /// [`crate::server::read_queue`]. P2P messages are framed, so the answering task always
    /// takes everything waiting and parses it message by message.
    reads: ReadQueue,
    write_half: Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
    #[allow(dead_code)]
    handshake_complete: bool,
}

/// Bitcoin Core's own cap on a P2P message body, and the largest single message this server
/// will accept before closing the peer.
///
/// Module level rather than inside `try_parse_bitcoin_message`, so `metadata()` can declare
/// the constant the parser actually enforces instead of repeating the number.
pub const MAX_MESSAGE_BYTES: usize = 4_000_000;

/// The most a connection may queue behind the message being answered.
///
/// Everything a peer sends while a message is answered — by the model, a script, or a person
/// behind a `manual` rule — waits in the connection's queue, so without a ceiling a peer
/// streaming for the length of one answer decides how much memory its connection costs. Two of
/// the largest message Core sends leaves room for one whole message pipelined behind another
/// still arriving; past it the peer is not waiting for answers, and the connection is closed
/// (`decision=fail_closed_queue_overflow`) rather than the queue trimmed, which would cut a
/// message in half.
pub const MAX_QUEUED_BYTES: usize = 2 * MAX_MESSAGE_BYTES;

/// What [`BitcoinServer::admit_read`] decided about one read.
enum ReadDecision {
    /// The read starts an answer, which parses these bytes.
    Answer(Vec<u8>),
    /// The read waits behind the answer in flight, or its connection has already gone.
    Wait,
    /// The queue passed [`MAX_QUEUED_BYTES`] and the connection was closed; stop reading.
    Closed,
}

/// How long to wait for a peer's first bytes after it connects.
///
/// Bitcoin Core's own number for the same thing: `DEFAULT_PEER_CONNECT_TIMEOUT` is 60 seconds,
/// after which a peer that has not completed the version handshake is disconnected. This bound
/// is on the first *byte* rather than on the handshake, so it is strictly more permissive than
/// Core's and cannot close a peer Core would keep.
const FIRST_BYTE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a peer that has already sent something may send nothing further.
///
/// Bitcoin has a keepalive and every node uses it: Core pings on a `PING_INTERVAL` of **2
/// minutes** and disconnects a peer that has sent nothing for `TIMEOUT_INTERVAL`, **20 minutes**.
/// Thirty minutes therefore sits above Core's own inactivity limit — a peer this server closes
/// is one Core would already have dropped — and fifteen times above the interval at which a live
/// node speaks.
///
/// The margin over 20 minutes matters for a reason specific to NetGet: a message is answered on
/// its own task, so the reader keeps reading while a message is being answered, and a
/// peer waiting on a model round-trip — or on a `manual` rule parked for a human — is silent on
/// this socket for the whole of that work.
const IDLE_BETWEEN_MESSAGES_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1800);

/// Concurrent connections this server admits.
///
/// **125**, which is Bitcoin Core's `-maxconnections` default rather than this project's shared
/// 256: a P2P node's connection count is part of how it behaves, and a Bitcoin server that
/// admitted twice what Core does would be conspicuous. Each admitted connection may buffer a
/// message of up to [`MAX_MESSAGE_BYTES`] (4 MB) before anything is handshaked, so the cap is
/// also what turns that per-connection bound into a total one — at 125 it is 500 MB rather than
/// a gigabyte.
const MAX_CONNECTIONS: usize = 125;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes: **nothing**.
///
/// Bitcoin P2P has no "busy" message and no error message of any kind — `reject` was removed in
/// Core 0.20 and never applied to a connection anyway — and every message this server could send
/// is a positive assertion about a node that has not handshaked. Core itself simply drops the
/// connection when it is over `-maxconnections`. So the refusal is a plain close and the reason
/// lives in the log, under the `decision=fail_closed_connection_cap` tag `accept_bounded` writes.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// Bitcoin P2P protocol server
pub struct BitcoinServer;

impl BitcoinServer {
    /// Spawn the Bitcoin P2P server with integrated LLM actions
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        network: String,
    ) -> Result<SocketAddr> {
        // Parse network magic
        let magic = match network.to_lowercase().as_str() {
            "mainnet" | "main" => Magic::BITCOIN,
            "testnet" | "test" => Magic::TESTNET3,
            "signet" => Magic::SIGNET,
            "regtest" => Magic::REGTEST,
            _ => {
                Log::new(Some(&status_tx)).info(format!(
                    "Unknown network '{}', defaulting to mainnet",
                    network
                ));
                Magic::BITCOIN
            }
        };

        // Create and bind TCP server
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        Log::new(Some(&status_tx)).info(format!(
            "Bitcoin P2P server listening on {} (network: {:?})",
            local_addr, magic
        ));

        let connections = Arc::new(Mutex::new(HashMap::new()));
        let protocol = Arc::new(BitcoinProtocol::new());

        // Spawn accept loop
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Bitcoin",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        Log::new(Some(&status_tx)).info(format!(
                            "Accepted Bitcoin P2P connection {} from {}",
                            connection_id, remote_addr
                        ));

                        // Split stream
                        let (read_half, write_half) = tokio::io::split(stream);
                        let write_half_arc = Arc::new(Mutex::new(write_half));

                        // Add connection to ServerInstance
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

                        // Peer messaging: the dashboard's "message this peer" / "disconnect
                        // this peer" inject actions into THIS connection through the same
                        // executor the LLM path uses. Registered before the opened event so a
                        // manual `*` rule parking that event leaves the operator able to reach
                        // the connection while it waits.
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
                            write_half_arc.clone(),
                            status_tx.clone(),
                        );

                        // Register the connection *before* either task is spawned.
                        //
                        // This used to happen inside `handle_connection_opened`, which runs in
                        // its own task alongside the reader task below — so a peer that sent
                        // its first message promptly raced the insert. The read finds no entry,
                        // and the bytes are dropped with no event, no queue and no log line: the
                        // read loop reports "received N bytes" and nothing further ever happens.
                        //
                        // A Bitcoin peer sends `version` immediately on connect, so this was hit
                        // constantly — three E2E tests waited out their 120s read timeouts, and
                        // flakily, since it is a race.
                        //
                        // Registered `Processing`: the opened event is answered first, and
                        // whatever the peer sends meanwhile queues behind that answer rather
                        // than racing it onto the wire. `handle_connection_opened` hands the
                        // queue over when it is done.
                        connections.lock().await.insert(
                            connection_id,
                            ConnectionData {
                                reads: ReadQueue::answering(),
                                write_half: write_half_arc.clone(),
                                handshake_complete: false,
                            },
                        );

                        // Handle connection opened event
                        let llm_client_clone = llm_client.clone();
                        let app_state_clone = app_state.clone();
                        let status_tx_clone = status_tx.clone();
                        let connections_clone = connections.clone();
                        let write_half_for_conn = write_half_arc.clone();
                        let protocol_clone = protocol.clone();
                        let magic_clone = magic;
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                Self::handle_connection_opened(
                                    connection_id,
                                    server_id,
                                    llm_client_clone,
                                    app_state_clone,
                                    status_tx_clone,
                                    connections_clone,
                                    write_half_for_conn,
                                    protocol_clone,
                                    magic_clone,
                                )
                                .await;
                            })
                            .await;

                        // Spawn reader task
                        let llm_client_clone = llm_client.clone();
                        let app_state_clone = app_state.clone();
                        let status_tx_clone = status_tx.clone();
                        let connections_clone = connections.clone();
                        let protocol_clone = protocol.clone();
                        let magic_clone = magic;
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection. The reader is the task
                                // that lives as long as the socket does — the connection-opened
                                // task above answers one event and ends — so the slot is
                                // released exactly when the peer is gone.
                                let _permit = permit;
                                let mut buffer = vec![0u8; 8192];
                                let mut read_half = read_half;
                                // "Has said nothing at all" and "has gone quiet mid-session"
                                // are different claims and get different deadlines.
                                let mut spoke_once = false;

                                loop {
                                    let read_deadline = if spoke_once {
                                        IDLE_BETWEEN_MESSAGES_TIMEOUT
                                    } else {
                                        FIRST_BYTE_READ_TIMEOUT
                                    };
                                    // The deadline wraps this read and nothing else:
                                    // `answer` runs on its own task, so a
                                    // model round-trip and a `manual` rule parked for a human
                                    // are outside it by construction.
                                    let read_result = match tokio::time::timeout(
                                        read_deadline,
                                        read_half.read(&mut buffer),
                                    )
                                    .await
                                    {
                                        Ok(v) => v,
                                        Err(_) => {
                                            // Nothing on the wire: Bitcoin P2P has no message a
                                            // node may send to explain a disconnect, and Core
                                            // itself just drops. The reason is the log line.
                                            Log::new(Some(&status_tx_clone)).info(format!(
                                                "Bitcoin connection {} sent nothing for {}s; \
                                                 closing decision=fail_closed_idle_timeout",
                                                connection_id,
                                                read_deadline.as_secs()
                                            ));
                                            Self::teardown_connection(
                                                &connections_clone,
                                                &app_state_clone,
                                                server_id,
                                                connection_id,
                                            )
                                            .await;
                                            let _ =
                                                status_tx_clone.send("__UPDATE_UI__".to_string());
                                            break;
                                        }
                                    };
                                    match read_result {
                                        Ok(0) => {
                                            // Connection closed
                                            Self::teardown_connection(
                                                &connections_clone,
                                                &app_state_clone,
                                                server_id,
                                                connection_id,
                                            )
                                            .await;
                                            Log::new(Some(&status_tx_clone)).info(format!(
                                                "Bitcoin connection {} closed",
                                                connection_id
                                            ));
                                            let _ =
                                                status_tx_clone.send("__UPDATE_UI__".to_string());
                                            break;
                                        }
                                        Ok(n) => {
                                            spoke_once = true;
                                            let data = &buffer[..n];
                                            app_state_clone
                                                .update_connection_stats(
                                                    server_id,
                                                    connection_id,
                                                    Some(n as u64),
                                                    None,
                                                    Some(1),
                                                    None,
                                                )
                                                .await;

                                            // Byte-count summary and full hex payload are
                                            // FileOnly: the bitcoin_message_received event
                                            // template reports the message to the TUI, so
                                            // streaming raw bytes here would duplicate it and
                                            // load the unbounded status channel.
                                            let log = Log::new(Some(&status_tx_clone));
                                            log.debug(format!(
                                                "Bitcoin P2P received {} bytes on {}",
                                                n, connection_id
                                            ));
                                            log.trace(format!(
                                                "Bitcoin P2P data (hex): {}",
                                                hex::encode(data)
                                            ));

                                            // Into the connection's state machine here, in the
                                            // order the reads arrived: either it starts an
                                            // answer, or it waits behind the one in flight.
                                            // Deciding that in a task spawned per read let two
                                            // tasks race for it — a later read could be parsed
                                            // and answered first, or two reads could both find
                                            // the connection Idle and be parsed apart, each
                                            // half of a message on its own.
                                            let payload = match Self::admit_read(
                                                connection_id,
                                                server_id,
                                                data,
                                                &connections_clone,
                                                &app_state_clone,
                                                &status_tx_clone,
                                            )
                                            .await
                                            {
                                                ReadDecision::Answer(payload) => payload,
                                                ReadDecision::Wait => continue,
                                                ReadDecision::Closed => break,
                                            };

                                            // The answer runs in its own task so the loop can
                                            // go back to reading: what arrives meanwhile is
                                            // queued behind it by `admit_read`.
                                            let llm_clone = llm_client_clone.clone();
                                            let state_clone = app_state_clone.clone();
                                            let status_clone = status_tx_clone.clone();
                                            let conns_clone = connections_clone.clone();
                                            let protocol_clone = protocol_clone.clone();
                                            // Tracked, not detached: stop_server must abort this task too.
                                            let task_owner = app_state_clone.clone();
                                            task_owner
                                                .spawn_server_task(server_id, async move {
                                                    Self::answer(
                                                        connection_id,
                                                        server_id,
                                                        payload,
                                                        llm_clone,
                                                        state_clone,
                                                        status_clone,
                                                        conns_clone,
                                                        protocol_clone,
                                                        magic_clone,
                                                    )
                                                    .await;
                                                })
                                                .await;
                                        }
                                        Err(e) => {
                                            Log::new(Some(&status_tx_clone)).error(format!(
                                                "Read error on Bitcoin connection {}: {}",
                                                connection_id, e
                                            ));
                                            Self::teardown_connection(
                                                &connections_clone,
                                                &app_state_clone,
                                                server_id,
                                                connection_id,
                                            )
                                            .await;
                                            let _ =
                                                status_tx_clone.send("__UPDATE_UI__".to_string());
                                            break;
                                        }
                                    }
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("Accept error on Bitcoin server: {}", e));
                        break;
                    }
                }
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    /// Answer the opened event for a new connection, then the messages the peer sent while it
    /// was being answered.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection_opened(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        write_half: Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        protocol: Arc<BitcoinProtocol>,
        magic: Magic,
    ) {
        // The connection is registered by the accept loop before this task and the reader task
        // are spawned — inserting it here raced the reader and silently dropped whatever the
        // peer sent first. Deliberately not re-inserted: doing so would reset the state machine
        // and discard any bytes the reader has already queued. (`connections` is still used
        // below, to remove the entry when the model closes the connection.)

        // Create connection opened event
        let event = Event::new(&BITCOIN_CONNECTION_OPENED_EVENT, serde_json::json!({}));

        // Call LLM to decide what to do (wait or send version message)
        match call_llm(
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
                debug!("LLM Bitcoin connection opened response received");

                // Display messages
                for msg in execution_result.messages {
                    let _ = status_tx.send(msg);
                }

                // The model answering with no action is a real answer here - most of the
                // Bitcoin handshake is peer-driven and "say nothing, wait for their version"
                // is correct - so it stays silent. It is still tagged, because in the log it
                // must not look like the LLM-error path below.
                if execution_result.protocol_results.is_empty() {
                    Log::new(Some(&status_tx)).debug(format!(
                        "Bitcoin connection {} opened decision=model_no_action (no message sent)",
                        connection_id
                    ));
                }

                // Handle protocol results
                for protocol_result in execution_result.protocol_results {
                    match protocol_result {
                        ActionResult::Output(output_data) => {
                            if let Err(e) = Self::send_bitcoin_message(
                                &write_half,
                                &output_data,
                                connection_id,
                                server_id,
                                &app_state,
                                &status_tx,
                                magic,
                            )
                            .await
                            {
                                Log::new(Some(&status_tx))
                                    .error(format!("Failed to send Bitcoin message: {}", e));
                            }
                        }
                        ActionResult::CloseConnection => {
                            Self::close_from_model(
                                &write_half,
                                &connections,
                                &app_state,
                                server_id,
                                connection_id,
                            )
                            .await;
                            Log::new(Some(&status_tx)).info(format!(
                                "Closed Bitcoin connection {} after connection opened \
                                 decision=model_close",
                                connection_id
                            ));
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                Self::fail_closed(
                    &write_half,
                    &connections,
                    &app_state,
                    &status_tx,
                    server_id,
                    connection_id,
                    &e,
                    "connection opened",
                )
                .await;
            }
        }

        // Hand over whatever the peer sent while the opened event was being answered — a
        // Bitcoin peer sends `version` at once, so usually that. The connection was registered
        // `Processing` for exactly this: those messages waited behind the opened answer instead
        // of being answered ahead of it, which put our `verack` on the wire before our own
        // `version`. Taken and left `Processing` under one lock, or the reader could find the
        // connection `Idle` in between. A connection the opened answer closed is gone from the
        // map, and nothing is answered.
        let queued = {
            let mut conns = connections.lock().await;
            let Some(conn) = conns.get_mut(&connection_id) else {
                return;
            };
            conn.reads.next_or_idle(true)
        };
        if let Some(queued) = queued {
            Self::answer(
                connection_id,
                server_id,
                queued,
                llm_client,
                app_state,
                status_tx,
                connections,
                protocol,
                magic,
            )
            .await;
        }
    }

    /// The LLM call itself failed. Bitcoin P2P has no error frame a modern peer will act on -
    /// BIP61 `reject` was removed from Bitcoin Core in 0.20 and is ignored by everything on
    /// the network today - so the only signal that reaches the peer is a disconnect, which is
    /// exactly what a real node does when it cannot serve a connection. Half-close the write
    /// side so the peer reads EOF at once and moves on to another peer, instead of blocking
    /// until its own timeout.
    ///
    /// Nothing derived from the error is written to the socket: FIN carries no text, and the
    /// error goes to the log and the status stream, where an operator looks. The overload and
    /// non-overload categories cannot be distinguished on the wire because Bitcoin has only
    /// this one shape, so they are distinguished in the log instead - `decision=` is stable so
    /// an operator can grep for it.
    #[allow(clippy::too_many_arguments)]
    async fn fail_closed(
        write_half: &Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        connection_id: ConnectionId,
        err: &anyhow::Error,
        context: &str,
    ) {
        let decision = match crate::utils::WireFailure::classify(err) {
            crate::utils::WireFailure::Overloaded => "fail_closed_llm_overloaded",
            crate::utils::WireFailure::Unavailable => "fail_closed_llm_error",
        };
        let log = Log::new(Some(status_tx));
        // The error text belongs here, never on the wire.
        log.warn(format!(
            "LLM error on Bitcoin {} for connection {} decision={}: {}",
            context, connection_id, decision, err
        ));
        Self::close_from_model(write_half, connections, app_state, server_id, connection_id).await;
        log.info(format!(
            "Closed Bitcoin connection {} decision={}",
            connection_id, decision
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Take one read into the connection's state machine, in the order the reader got it.
    ///
    /// Returns the bytes the answer this read starts should parse, [`ReadDecision::Wait`] when
    /// they wait behind the answer already in flight (or the connection has gone), or
    /// [`ReadDecision::Closed`] when waiting would take the queue past [`MAX_QUEUED_BYTES`] and
    /// the connection has been closed for it. Called by the reader
    /// itself, never from a spawned task: the decision has to be made in arrival order and under
    /// one lock. When each read's task made it, two reads could both find the connection `Idle`
    /// and be parsed and answered at once, and a later read's task could run first — its `pong`
    /// went out ahead of the earlier one's, and a message split across two reads was parsed as
    /// two halves.
    async fn admit_read(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        data: &[u8],
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> ReadDecision {
        let mut conns = connections.lock().await;
        let Some(conn) = conns.get_mut(&connection_id) else {
            // Never silent. A miss here means the connection was torn down after the read
            // (peer reset, or close_this_connection on the answering task) - legitimate, but
            // indistinguishable from a registration race, which is exactly what made the
            // bitcoin accept-order bug so hard to find: the read loop logged "received N
            // bytes" and then nothing at all.
            debug!(
                "Bitcoin connection {} is no longer registered; dropping {} received bytes",
                connection_id,
                data.len()
            );
            return ReadDecision::Wait;
        };
        // Framed messages: the answer always takes everything waiting, held fragment first.
        let (queued, write_half) = match conn.reads.admit(data, true) {
            Admitted::Start(payload) => return ReadDecision::Answer(payload),
            Admitted::Queued(queued) => (queued, conn.write_half.clone()),
        };
        drop(conns);
        if queued > MAX_QUEUED_BYTES {
            // Nothing on the wire explains it: P2P has no message for a disconnect, and Core
            // itself just drops a peer. Shutting the write half makes the peer read EOF now
            // rather than wait on answers that are never coming.
            Log::new(Some(status_tx)).warn(format!(
                "Bitcoin connection {connection_id} queued {queued} bytes behind the message \
                 being answered (limit {MAX_QUEUED_BYTES}); closing \
                 decision=fail_closed_queue_overflow"
            ));
            let _ = write_half.lock().await.shutdown().await;
            Self::teardown_connection(connections, app_state, server_id, connection_id).await;
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            return ReadDecision::Closed;
        }
        debug!(
            "Queued {} bytes for Bitcoin connection {} ({} queued)",
            data.len(),
            connection_id,
            queued
        );
        let _ = status_tx.send(format!(
            "⏸ Queued {} bytes for {}",
            data.len(),
            connection_id
        ));
        ReadDecision::Wait
    }

    /// Parse and answer `payload` on a connection [`Self::admit_read`] has moved to
    /// `Processing`, message by message, then everything queued behind it, until nothing is
    /// left but an incomplete message (held for the next read) or nothing at all.
    ///
    /// One of these runs per connection at a time: only the move into `Processing` starts one,
    /// and it leaves `Processing` only when it ends.
    #[allow(clippy::too_many_arguments)]
    async fn answer(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        payload: Vec<u8>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: Arc<BitcoinProtocol>,
        magic: Magic,
    ) {
        let mut buffer = payload;

        loop {
            // Try to parse Bitcoin message
            let parsed_message = Self::try_parse_bitcoin_message(&buffer, magic);

            match parsed_message {
                Ok(Some((message, remaining))) => {
                    // Consume what we just parsed. Leaving `buffer` untouched (the old
                    // behaviour, which dropped `remaining`) meant that whenever a peer
                    // pipelined a second message the loop re-parsed the *first* one and
                    // called the LLM on it again, without end.
                    buffer = remaining;

                    // Successfully parsed a message
                    let payload = message.payload();
                    let message_type = Self::get_message_type_name(payload);
                    Log::new(Some(&status_tx)).info(format!(
                        "Received Bitcoin message: {} from {}",
                        message_type, connection_id
                    ));

                    // Update connection info with message type
                    app_state
                        .update_bitcoin_connection_info(
                            server_id,
                            connection_id,
                            message_type.clone(),
                        )
                        .await;

                    // Get write_half for context
                    let write_half = {
                        let conns = connections.lock().await;
                        conns.get(&connection_id).map(|c| c.write_half.clone())
                    };

                    let Some(write_half) = write_half else {
                        return; // Connection not found
                    };

                    // Serialize message for LLM
                    let message_json = Self::serialize_message_to_json(payload);

                    // Create data received event
                    let event = Event::new(
                        &BITCOIN_MESSAGE_RECEIVED_EVENT,
                        serde_json::json!({
                            "message_type": message_type.clone(),
                            "message": message_json,
                        }),
                    );

                    // Call LLM
                    match call_llm(
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
                            debug!("LLM Bitcoin response received");

                            // Display messages
                            for msg in execution_result.messages {
                                let _ = status_tx.send(msg);
                            }

                            // As on the opened event: no action is a legitimate answer for
                            // most message types (an `addr` or an `inv` needs no reply), so
                            // stay silent - but tag it, so the log never confuses it with the
                            // LLM-error path below.
                            if execution_result.protocol_results.is_empty() {
                                Log::new(Some(&status_tx)).debug(format!(
                                    "Bitcoin {} on {} decision=model_no_action (no reply sent)",
                                    message_type, connection_id
                                ));
                            }

                            // Handle protocol results
                            let mut should_close = false;

                            for protocol_result in execution_result.protocol_results {
                                match protocol_result {
                                    ActionResult::Output(output_data) => {
                                        if let Err(e) = Self::send_bitcoin_message(
                                            &write_half,
                                            &output_data,
                                            connection_id,
                                            server_id,
                                            &app_state,
                                            &status_tx,
                                            magic,
                                        )
                                        .await
                                        {
                                            Log::new(Some(&status_tx)).error(format!(
                                                "Failed to send Bitcoin response: {}",
                                                e
                                            ));
                                        }
                                    }
                                    ActionResult::CloseConnection => {
                                        should_close = true;
                                    }
                                    _ => {}
                                }
                            }

                            // Handle close_connection
                            if should_close {
                                Self::close_from_model(
                                    &write_half,
                                    &connections,
                                    &app_state,
                                    server_id,
                                    connection_id,
                                )
                                .await;
                                let _ = status_tx.send("__UPDATE_UI__".to_string());
                                Log::new(Some(&status_tx)).info(format!(
                                    "Closed Bitcoin connection {} decision=model_close",
                                    connection_id
                                ));
                                return;
                            }

                            // Fold anything that arrived during the LLM call onto the bytes
                            // not consumed yet and go round again, or go Idle when there is
                            // nothing at all — under one lock. Checked and set separately, a
                            // read queued in between (the connection still `Processing`) was
                            // stranded by the move to `Idle` until the peer sent something else.
                            let more = {
                                let mut conns = connections.lock().await;
                                let Some(conn) = conns.get_mut(&connection_id) else {
                                    return;
                                };
                                if buffer.is_empty() {
                                    conn.reads.next_or_idle(true)
                                } else {
                                    Some(conn.reads.take_all())
                                }
                            };
                            let Some(more) = more else {
                                return;
                            };
                            if !more.is_empty() {
                                Log::new(Some(&status_tx)).debug(format!(
                                    "Processing {} queued bytes for Bitcoin connection {}",
                                    more.len(),
                                    connection_id
                                ));
                            }
                            buffer.extend_from_slice(&more);
                        }
                        Err(e) => {
                            // This used to reset the state to Idle and write nothing, leaving
                            // a peer that had just sent us a `version` or a `ping` blocked
                            // until its own timeout with no indication anything went wrong.
                            Self::fail_closed(
                                &write_half,
                                &connections,
                                &app_state,
                                &status_tx,
                                server_id,
                                connection_id,
                                &e,
                                &format!("{} message", message_type),
                            )
                            .await;
                            return;
                        }
                    }
                }
                Ok(None) => {
                    // Need more data to complete message.
                    //
                    // try_parse_bitcoin_message only reports "incomplete" for a header that
                    // validates, so the outstanding bytes are bounded by MAX_MESSAGE_BYTES and
                    // this cannot be used to grow the buffer without limit.
                    Log::new(Some(&status_tx)).debug(format!(
                        "Incomplete Bitcoin message ({} bytes buffered), waiting for more on {}",
                        buffer.len(),
                        connection_id
                    ));
                    // Held at the head of the queue, ahead of anything that landed meanwhile;
                    // if something did land, it may be the rest of the message, so the answer
                    // goes round again with the joined bytes rather than wait for a read that
                    // may never come.
                    let held = {
                        let mut conns = connections.lock().await;
                        let Some(conn) = conns.get_mut(&connection_id) else {
                            return;
                        };
                        conn.reads.hold_for_more(&buffer)
                    };
                    match held {
                        Held::Resume(joined) => buffer = joined,
                        Held::Waiting(_) => return,
                    }
                }
                Err(e) => {
                    // Parse error
                    Log::new(Some(&status_tx)).error(format!(
                        "Failed to parse Bitcoin message on {}: {}",
                        connection_id, e
                    ));
                    if let Some(conn) = connections.lock().await.get_mut(&connection_id) {
                        conn.reads.abandon();
                    }
                    return;
                }
            }
        }
    }

    /// Try to parse one Bitcoin P2P message off the front of `data`.
    ///
    /// Returns `Ok(None)` **only** when the bytes so far are a valid prefix of a message whose
    /// declared length has not arrived yet. Everything else - bad magic, an absurd length, a
    /// body that will not decode - is `Err`, so the caller drops the connection instead of
    /// buffering forever. The previous version mapped every decode failure to `Ok(None)`,
    /// which turned a stream of garbage into unbounded memory growth: the caller kept the
    /// whole thing as "incomplete" and re-parsed it on every read.
    fn try_parse_bitcoin_message(
        data: &[u8],
        magic: Magic,
    ) -> Result<Option<(RawNetworkMessage, Vec<u8>)>> {
        // magic(4) | command(12) | length(4) | checksum(4)
        const HEADER_LEN: usize = 24;

        if data.len() < HEADER_LEN {
            return Ok(None);
        }

        // Validate the header before trusting the length field.
        let got_magic = Magic::from_bytes(
            data[0..4]
                .try_into()
                .expect("4-byte slice is always convertible"),
        );
        if got_magic != magic {
            return Err(anyhow::anyhow!(
                "Magic bytes mismatch: expected {:?}, got {:?}",
                magic,
                got_magic
            ));
        }

        let payload_len = u32::from_le_bytes(
            data[16..20]
                .try_into()
                .expect("4-byte slice is always convertible"),
        ) as usize;
        if payload_len > MAX_MESSAGE_BYTES {
            return Err(anyhow::anyhow!(
                "Bitcoin message declares {} byte payload, over the {} byte limit",
                payload_len,
                MAX_MESSAGE_BYTES
            ));
        }

        let total = HEADER_LEN + payload_len;
        if data.len() < total {
            // Genuinely incomplete, and bounded: at most MAX_MESSAGE_BYTES outstanding.
            return Ok(None);
        }

        let mut cursor = Cursor::new(&data[..total]);
        let message = RawNetworkMessage::consensus_decode(&mut cursor)
            .map_err(|e| anyhow::anyhow!("Malformed Bitcoin message: {}", e))?;

        Ok(Some((message, data[total..].to_vec())))
    }

    /// Get message type name from NetworkMessage
    fn get_message_type_name(payload: &NetworkMessage) -> String {
        match payload {
            NetworkMessage::Version(_) => "version".to_string(),
            NetworkMessage::Verack => "verack".to_string(),
            NetworkMessage::Addr(_) => "addr".to_string(),
            NetworkMessage::Inv(_) => "inv".to_string(),
            NetworkMessage::GetData(_) => "getdata".to_string(),
            NetworkMessage::NotFound(_) => "notfound".to_string(),
            NetworkMessage::GetBlocks(_) => "getblocks".to_string(),
            NetworkMessage::GetHeaders(_) => "getheaders".to_string(),
            NetworkMessage::MemPool => "mempool".to_string(),
            NetworkMessage::Tx(_) => "tx".to_string(),
            NetworkMessage::Block(_) => "block".to_string(),
            NetworkMessage::Headers(_) => "headers".to_string(),
            NetworkMessage::SendHeaders => "sendheaders".to_string(),
            NetworkMessage::GetAddr => "getaddr".to_string(),
            NetworkMessage::Ping(_) => "ping".to_string(),
            NetworkMessage::Pong(_) => "pong".to_string(),
            NetworkMessage::MerkleBlock(_) => "merkleblock".to_string(),
            NetworkMessage::FilterLoad(_) => "filterload".to_string(),
            NetworkMessage::FilterAdd(_) => "filteradd".to_string(),
            NetworkMessage::FilterClear => "filterclear".to_string(),
            NetworkMessage::GetCFilters(_) => "getcfilters".to_string(),
            NetworkMessage::CFilter(_) => "cfilter".to_string(),
            NetworkMessage::GetCFHeaders(_) => "getcfheaders".to_string(),
            NetworkMessage::CFHeaders(_) => "cfheaders".to_string(),
            NetworkMessage::GetCFCheckpt(_) => "getcfcheckpt".to_string(),
            NetworkMessage::CFCheckpt(_) => "cfcheckpt".to_string(),
            NetworkMessage::SendCmpct(_) => "sendcmpct".to_string(),
            NetworkMessage::CmpctBlock(_) => "cmpctblock".to_string(),
            NetworkMessage::GetBlockTxn(_) => "getblocktxn".to_string(),
            NetworkMessage::BlockTxn(_) => "blocktxn".to_string(),
            NetworkMessage::Alert(_) => "alert".to_string(),
            NetworkMessage::Reject(_) => "reject".to_string(),
            NetworkMessage::FeeFilter(_) => "feefilter".to_string(),
            NetworkMessage::WtxidRelay => "wtxidrelay".to_string(),
            NetworkMessage::AddrV2(_) => "addrv2".to_string(),
            NetworkMessage::SendAddrV2 => "sendaddrv2".to_string(),
            NetworkMessage::Unknown { command, .. } => format!("unknown({})", command),
        }
    }

    /// Serialize NetworkMessage to JSON for LLM
    fn serialize_message_to_json(payload: &NetworkMessage) -> serde_json::Value {
        match payload {
            NetworkMessage::Version(v) => serde_json::json!({
                "version": v.version,
                "services": v.services.to_u64(),
                "timestamp": v.timestamp,
                "receiver": v.receiver.socket_addr().ok().map(|a| a.to_string()),
                "sender": v.sender.socket_addr().ok().map(|a| a.to_string()),
                "nonce": v.nonce,
                "user_agent": v.user_agent,
                "start_height": v.start_height,
                "relay": v.relay,
            }),
            NetworkMessage::Ping(nonce) => serde_json::json!({ "nonce": nonce }),
            NetworkMessage::Pong(nonce) => serde_json::json!({ "nonce": nonce }),
            NetworkMessage::Addr(addrs) => {
                let addr_strings: Vec<Option<String>> = addrs
                    .iter()
                    .map(|(_, addr)| addr.socket_addr().ok().map(|a| a.to_string()))
                    .collect();
                serde_json::json!({ "count": addrs.len(), "addresses": addr_strings })
            }
            NetworkMessage::GetAddr => serde_json::json!({}),
            NetworkMessage::Verack => serde_json::json!({}),
            NetworkMessage::Inv(inv) => {
                serde_json::json!({ "count": inv.len(), "inventory": inv.iter().map(|i| format!("{:?}", i)).collect::<Vec<_>>() })
            }
            // For other message types, provide basic info
            _ => serde_json::json!({ "type": Self::get_message_type_name(payload) }),
        }
    }

    /// Forget a connection on every exit path of its reader task (EOF, read error): drop the
    /// state-machine entry, the dashboard's peer handle and the tracked connection.
    async fn teardown_connection(
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        app_state: &Arc<AppState>,
        server_id: crate::state::ServerId,
        connection_id: ConnectionId,
    ) {
        connections.lock().await.remove(&connection_id);
        app_state
            .remove_peer_handle(server_id, connection_id.as_u32())
            .await;
        app_state
            .close_connection_on_server(server_id, connection_id)
            .await;
    }

    /// `close_this_connection` from the model. Half-closes the write side so the peer reads
    /// EOF - previously this only dropped the map entry and the socket stayed open until the
    /// peer hung up - then runs the same teardown as the reader's exit paths. The reader task
    /// sees EOF once the peer closes and tears down again; every step is idempotent.
    async fn close_from_model(
        write_half: &Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        app_state: &Arc<AppState>,
        server_id: crate::state::ServerId,
        connection_id: ConnectionId,
    ) {
        {
            let mut write = write_half.lock().await;
            let _ = write.shutdown().await;
        }
        Self::teardown_connection(connections, app_state, server_id, connection_id).await;
    }

    /// Send a Bitcoin message (raw bytes that will be wrapped in Bitcoin message format)
    #[allow(clippy::too_many_arguments)]
    async fn send_bitcoin_message(
        write_half: &Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        data: &[u8],
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        _magic: Magic,
    ) -> Result<()> {
        {
            let mut write = write_half.lock().await;
            write
                .write_all(data)
                .await
                .context("Failed to write Bitcoin message")?;
            write
                .flush()
                .await
                .context("Failed to flush Bitcoin message")?;
        }
        app_state
            .update_connection_stats(
                server_id,
                connection_id,
                None,
                Some(data.len() as u64),
                None,
                Some(1),
            )
            .await;

        // Byte-count summary and full hex payload are FileOnly; the one lifecycle
        // line to the TUI is the INFO below.
        let log = Log::new(Some(status_tx));
        log.debug(format!(
            "Bitcoin P2P sent {} bytes to {}",
            data.len(),
            connection_id
        ));
        log.trace(format!("Bitcoin P2P sent (hex): {}", hex::encode(data)));
        log.info(format!("Sent Bitcoin message to {}", connection_id));

        Ok(())
    }
}

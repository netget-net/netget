//! QUIC server implementation using Quinn
pub mod actions;

use crate::utils::quic::{
    ConnectionGuard, EndpointGuard, EXCHANGE_TIMEOUT, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT,
    MAX_CONNECTIONS, MAX_STREAMS, RAW_ALPN,
};
use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{stream::FuturesUnordered, StreamExt};
use quinn::{Endpoint, ServerConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error};

use super::connection::ConnectionId;
use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use actions::{
    QuicProtocol, QUIC_CONNECTION_OPENED_EVENT, QUIC_DATAGRAM_RECEIVED_EVENT,
    QUIC_DATA_RECEIVED_EVENT, QUIC_STREAM_OPENED_EVENT,
};

/// Stream state for LLM processing
#[derive(Debug, Clone, PartialEq)]
enum StreamState {
    Idle,
    Processing,
    Accumulating,
}

/// Per-stream data for LLM handling.
///
/// There is deliberately no `memory` field. One used to sit here, read at the top of
/// each pass and written straight back unchanged at the bottom — it was never put into
/// an event, never passed to `call_llm`, and never read by anything else. Per-server
/// memory lives in `AppState` and `call_llm` reads it from there.
struct StreamData {
    state: StreamState,
    queued_data: Vec<u8>,
    send_stream: Arc<Mutex<quinn::SendStream>>,
}

/// How many bytes may pile up for one stream while an LLM call is in flight.
///
/// Data that arrives mid-call is queued and merged into the next turn, and nothing else
/// bounds it: a peer that keeps writing while the model thinks grows this `Vec` for as
/// long as it likes. The queue only exists to hold a message that was split across
/// reads, so a megabyte is far past any legitimate use — and the merged buffer is what
/// ends up in an LLM prompt, where it is useless long before that.
///
/// Over the cap the stream is reset with the raw application's overload code.
pub const MAX_STREAM_QUEUE_BYTES: usize = 1024 * 1024;
/// Application-local codes for netget-quic. These retain their historical numeric
/// values for existing raw peers; they do not imply HTTP/3 framing or semantics.
const RAW_INTERNAL_ERROR: u32 = 0x0102;
const RAW_EXCESSIVE_LOAD: u32 = 0x0107;

fn wire_failure_code(failure: crate::utils::WireFailure) -> quinn::VarInt {
    quinn::VarInt::from_u32(match failure {
        crate::utils::WireFailure::Overloaded => RAW_EXCESSIVE_LOAD,
        crate::utils::WireFailure::Unavailable => RAW_INTERNAL_ERROR,
    })
}

/// QUIC server that listens for incoming connections
pub struct QuicServer;

impl QuicServer {
    /// Spawn the QUIC server with integrated LLM actions
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        tls_config: Option<Arc<rustls::ServerConfig>>,
    ) -> Result<SocketAddr> {
        // Use provided TLS config or generate default
        let mut server_crypto = match tls_config {
            Some(config) => (*config).clone(),
            None => {
                // Generate default self-signed certificate
                let config = crate::server::tls_cert_manager::generate_default_tls_config()
                    .context("Failed to generate default TLS config")?;
                (*config).clone()
            }
        };

        // Raw stream bytes must not advertise HTTP/3.
        server_crypto.alpn_protocols = vec![RAW_ALPN.to_vec()];
        server_crypto.max_early_data_size = 0;

        // Create QUIC server configuration
        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .context("Failed to create QUIC crypto config")?,
        ));

        server_config.transport_config(crate::utils::quic::transport(
            IDLE_TIMEOUT,
            MAX_STREAMS as u32,
            0,
        ));
        server_config.migration(false);

        // Bind endpoint
        let endpoint = EndpointGuard(
            Endpoint::server(server_config, listen_addr)
                .context("Failed to create QUIC endpoint")?,
        );
        let local_addr = endpoint
            .0
            .local_addr()
            .context("Failed to get local address")?;

        Log::new(Some(&status_tx)).info(format!(
            "QUIC server (action-based) listening on {}",
            local_addr
        ));

        let task_registrar = app_state.clone();
        let accept_handle = tokio::spawn(async move {
            let mut sessions = FuturesUnordered::new();
            loop {
                tokio::select! {
                    incoming=endpoint.0.accept()=>{
                        let Some(incoming)=incoming else{break;};
                        if sessions.len()>=MAX_CONNECTIONS {incoming.refuse();continue;}
                        sessions.push(Self::session(incoming,local_addr,llm_client.clone(),app_state.clone(),status_tx.clone(),server_id));
                    }
                    _=sessions.next(),if !sessions.is_empty()=>{}
                }
            }
        });
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;
        Ok(local_addr)
    }

    async fn session(
        incoming: quinn::Incoming,
        local_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) {
        let connection = match tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await {
            Ok(Ok(c)) => ConnectionGuard(c),
            _ => return,
        };
        let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);
        use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
        let now = crate::utils::clock::Instant::now();
        app_state
            .add_connection_to_server(
                server_id,
                ConnectionState {
                    id: connection_id,
                    remote_addr: connection.0.remote_address(),
                    local_addr,
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    last_activity: now,
                    status: ConnectionStatus::Active,
                    status_changed_at: now,
                    protocol_info: ProtocolConnectionInfo::new(
                        serde_json::json!({"alpn":"netget-quic"}),
                    ),
                },
            )
            .await;
        let _ = status_tx.send("__UPDATE_UI__".into());
        let protocol = Arc::new(QuicProtocol::new());
        let event = Event::new(&QUIC_CONNECTION_OPENED_EVENT, serde_json::json!({}));
        // A slow connection notification must not consume a connection slot forever.
        let _ = tokio::time::timeout(
            EXCHANGE_TIMEOUT,
            call_llm(
                &llm_client,
                &app_state,
                server_id,
                Some(connection_id),
                &event,
                protocol.as_ref(),
            ),
        )
        .await;
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let mut work = FuturesUnordered::new();
        // One datagram turn at a time. While it runs, datagrams wait in Quinn's bounded
        // receive buffer and the oldest are dropped past it — which RFC 9221 permits, and
        // which is the only bound that cannot be outrun by a sender.
        let mut datagram_turn = FuturesUnordered::new();
        loop {
            tokio::select! {
                datagram=connection.0.read_datagram(),if datagram_turn.is_empty()=>{
                    let Ok(datagram)=datagram else{break;};
                    datagram_turn.push(Self::handle_datagram(
                        datagram,
                        connection.0.clone(),
                        connection_id,
                        server_id,
                        llm_client.clone(),
                        app_state.clone(),
                        status_tx.clone(),
                        protocol.clone(),
                    ));
                }
                _=datagram_turn.next(),if !datagram_turn.is_empty()=>{}
                result=connection.0.accept_bi(),if work.len()<MAX_STREAMS=>{
                    let Ok((send,recv))=result else{break;};
                    tracing::trace!(stream = %recv.id(), "QUIC stream accepted");
                    let stream_map=streams.clone();let llm=llm_client.clone();let state=app_state.clone();let status=status_tx.clone();let proto=protocol.clone();
                    let stopped=send.stopped();
                    work.push(async move {
                        // A sibling stream may already be queued for the fair AppState
                        // lock. Awaiting it in the accept branch would stop polling that
                        // sibling forever; keep all stream state waits in the collection.
                        let stream_id=ConnectionId::new(state.get_next_unified_id().await);
                        tokio::select! {
                            _=stopped=>{},
                            _=tokio::time::timeout(EXCHANGE_TIMEOUT,Self::handle_stream_with_actions(stream_id,connection_id,server_id,send,recv,llm,state,status,stream_map.clone(),proto))=>{}
                        }
                        // A timed-out future may have inserted a stream before cancellation.
                        if let Some(stream)=stream_map.lock().await.remove(&stream_id) {
                            let _=stream.send_stream.lock().await.reset(quinn::VarInt::from_u32(3));
                        }
                    });
                }
                _=work.next(),if !work.is_empty()=>{}
                _=connection.0.closed()=>break,
            }
        }
        drop(work);
        drop(datagram_turn);
        drop(streams);
        app_state
            .close_connection_on_server(server_id, connection_id)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".into());
    }

    /// Answer one RFC 9221 DATAGRAM frame. The handler's `send_quic_datagram` actions go back
    /// as DATAGRAM frames on the same connection; anything larger than the peer accepts is
    /// refused here, where the connection's limit is known.
    #[allow(clippy::too_many_arguments)]
    async fn handle_datagram(
        datagram: Bytes,
        connection: quinn::Connection,
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<QuicProtocol>,
    ) {
        app_state
            .update_connection_stats(
                server_id,
                connection_id,
                Some(datagram.len() as u64),
                None,
                Some(1),
                None,
            )
            .await;
        let (data, encoding) = actions::encode_quic_payload(&datagram);
        let event = Event::new(
            &QUIC_DATAGRAM_RECEIVED_EVENT,
            serde_json::json!({
                "data": data,
                "encoding": encoding,
                "bytes": datagram.len(),
                "max_datagram_size": connection.max_datagram_size(),
            }),
        );
        let result = tokio::time::timeout(
            EXCHANGE_TIMEOUT,
            call_llm(
                &llm_client,
                &app_state,
                server_id,
                Some(connection_id),
                &event,
                protocol.as_ref(),
            ),
        )
        .await;
        let results = match result {
            Ok(Ok(r)) => r.protocol_results,
            Ok(Err(e)) => {
                // A datagram has no reply channel to fail on: answering it is optional, so a
                // backend failure is silence, logged with the reason.
                let decision = if crate::llm::is_overload_error(&e) {
                    "fail_closed_llm_overloaded"
                } else {
                    "fail_closed_llm_error"
                };
                Log::new(Some(&status_tx)).error(format!(
                    "QUIC datagram on connection {connection_id} decision={decision}: {e}"
                ));
                return;
            }
            Err(_) => {
                Log::new(Some(&status_tx)).warn(format!(
                    "QUIC datagram on connection {connection_id} decision=fail_closed_timeout"
                ));
                return;
            }
        };
        for result in results {
            let ActionResult::Custom { name, data } = result else {
                continue;
            };
            if name != actions::DATAGRAM_RESULT {
                continue;
            }
            let Some(bytes) = data.as_str().and_then(|h| hex::decode(h).ok()) else {
                continue;
            };
            let n = bytes.len();
            match connection.send_datagram(Bytes::from(bytes)) {
                Ok(()) => {
                    app_state
                        .update_connection_stats(
                            server_id,
                            connection_id,
                            None,
                            Some(n as u64),
                            None,
                            Some(1),
                        )
                        .await;
                }
                Err(e) => Log::new(Some(&status_tx)).warn(format!(
                    "QUIC datagram of {n} bytes not sent on connection {connection_id} \
                     (peer limit {:?}): {e}",
                    connection.max_datagram_size()
                )),
            }
        }
    }

    /// Handle a QUIC stream with LLM actions.
    ///
    /// Statistics are recorded against `connection_id`, not `stream_id`: only the
    /// QUIC connection is registered in the server's connection map, so an update
    /// keyed by a stream id would silently do nothing. Keeping `last_activity`
    /// fresh matters here more than for HTTP/1.1 — `cleanup_old_connections`
    /// evicts a connection idle for 10s, and a QUIC connection carrying a slow
    /// stream easily exceeds that.
    #[allow(clippy::too_many_arguments)]
    async fn handle_stream_with_actions(
        stream_id: ConnectionId,
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        send_stream: quinn::SendStream,
        mut recv_stream: quinn::RecvStream,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        streams: Arc<Mutex<HashMap<ConnectionId, StreamData>>>,
        protocol: Arc<QuicProtocol>,
    ) {
        let send_stream_arc = Arc::new(Mutex::new(send_stream));

        // Add stream to tracking
        streams.lock().await.insert(
            stream_id,
            StreamData {
                state: StreamState::Idle,
                queued_data: Vec::new(),
                send_stream: send_stream_arc.clone(),
            },
        );

        // Notify LLM of new stream
        let event = Event::new(
            &QUIC_STREAM_OPENED_EVENT,
            serde_json::json!({
                "stream_id": stream_id.to_string()
            }),
        );

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
                for msg in execution_result.messages {
                    let _ = status_tx.send(msg);
                }

                // Handle any initial actions
                for protocol_result in execution_result.protocol_results {
                    if matches!(protocol_result, ActionResult::CloseConnection) {
                        let _ = send_stream_arc.lock().await.finish();
                        let _ = recv_stream.stop(0u32.into());
                        streams.lock().await.remove(&stream_id);
                        return;
                    }
                    if let ActionResult::Output(output_data) = protocol_result {
                        let write_result = {
                            let mut send = send_stream_arc.lock().await;
                            send.write_all(&output_data).await
                        };
                        if let Err(e) = write_result {
                            error!("Failed to send initial data on stream {}: {}", stream_id, e);
                        } else {
                            Log::new(Some(&status_tx)).debug(format!(
                                "QUIC sent {} bytes on stream {}",
                                output_data.len(),
                                stream_id
                            ));
                            app_state
                                .update_connection_stats(
                                    server_id,
                                    connection_id,
                                    None,
                                    Some(output_data.len() as u64),
                                    None,
                                    Some(1),
                                )
                                .await;
                        }
                    }
                }
            }
            Err(e) => {
                // Non-fatal, and deliberately not a reset: whatever the model would have
                // said here is an unsolicited greeting, not a reply the peer is blocked on
                // — the client writes first on a raw QUIC stream. Killing the stream over a
                // missing banner would be worse than not sending one, and the next
                // `quic_data_received` gets its own chance (and its own reset on failure).
                // Same shape as TCP's banner path.
                Log::new(Some(&status_tx)).warn(format!(
                    "LLM error on stream {} opened (decision=llm_error, no greeting sent, \
                     stream left open): {}",
                    stream_id, e
                ));
            }
        }

        // Read loop
        let mut buffer = vec![0u8; 65536];
        loop {
            match recv_stream.read(&mut buffer).await {
                Ok(Some(n)) => {
                    let data = Bytes::copy_from_slice(&buffer[..n]);

                    // Count every inbound read exactly once, before dispatch: the
                    // handler below may queue the data instead of processing it.
                    app_state
                        .update_connection_stats(
                            server_id,
                            connection_id,
                            Some(n as u64),
                            None,
                            Some(1),
                            None,
                        )
                        .await;

                    // Data summary + full payload are FileOnly: the quic_data_received
                    // event template renders the equivalent lines to the TUI, so streaming
                    // the payload here too would duplicate it and load the unbounded
                    // status channel.
                    let log = Log::new(Some(&status_tx));
                    if data
                        .iter()
                        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                    {
                        let data_str = String::from_utf8_lossy(&data);
                        // `truncate_for_log` rather than `&s[..100]`: the ASCII guard above
                        // makes byte-slicing safe *today*, but the guard and the slice are
                        // twenty lines apart and a byte-index cut on a `&str` is the panic
                        // shape CLAUDE.md records (fixed tree-wide in b9aa1058).
                        let preview = crate::utils::truncate_for_log(&data_str, 100);
                        log.debug(format!(
                            "QUIC received {} bytes on stream {}: {}",
                            n, stream_id, preview
                        ));
                        log.trace(format!("QUIC data (text): {:?}", data_str));
                    } else {
                        log.debug(format!(
                            "QUIC received {} bytes on stream {} (binary data)",
                            n, stream_id
                        ));
                        log.trace(format!("QUIC data (hex): {}", hex::encode(&data)));
                    }

                    // Handle data directly (await to ensure processing completes before stream removal)
                    Self::handle_data_with_actions(
                        stream_id,
                        connection_id,
                        server_id,
                        data,
                        llm_client.clone(),
                        app_state.clone(),
                        status_tx.clone(),
                        streams.clone(),
                        protocol.clone(),
                    )
                    .await;
                    if !streams.lock().await.contains_key(&stream_id) {
                        break;
                    }
                }
                Ok(None) => {
                    // Stream finished
                    Log::new(Some(&status_tx)).info(format!("QUIC stream {} finished", stream_id));
                    streams.lock().await.remove(&stream_id);
                    break;
                }
                Err(e) => {
                    Log::new(Some(&status_tx))
                        .error(format!("Read error on stream {}: {}", stream_id, e));
                    streams.lock().await.remove(&stream_id);
                    break;
                }
            }
        }
        let _ = send_stream_arc.lock().await.finish();
    }

    /// Handle data received on a stream with LLM actions
    #[allow(clippy::too_many_arguments)]
    async fn handle_data_with_actions(
        stream_id: ConnectionId,
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        data: Bytes,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        streams: Arc<Mutex<HashMap<ConnectionId, StreamData>>>,
        protocol: Arc<QuicProtocol>,
    ) {
        // Check stream state
        let current_state = {
            let streams_lock = streams.lock().await;
            if let Some(stream_data) = streams_lock.get(&stream_id) {
                stream_data.state.clone()
            } else {
                return; // Stream not found
            }
        };

        // If processing, queue the data — bounded, so a peer that keeps writing while the
        // model thinks cannot grow this buffer without limit.
        if current_state == StreamState::Processing {
            let over_limit = {
                let mut streams_lock = streams.lock().await;
                match streams_lock.get_mut(&stream_id) {
                    Some(stream) => {
                        if stream.queued_data.len() + data.len() > MAX_STREAM_QUEUE_BYTES {
                            true
                        } else {
                            stream.queued_data.extend_from_slice(&data);
                            false
                        }
                    }
                    // Stream went away while we were between locks.
                    None => return,
                }
            };

            if over_limit {
                let log = Log::new(Some(&status_tx));
                log.warn(format!(
                    "Stream {} queued more than {} bytes while an LLM call was in flight                      (decision=refused_queue_too_large, raw_error_code=0x{:x}); resetting",
                    stream_id, MAX_STREAM_QUEUE_BYTES, RAW_EXCESSIVE_LOAD
                ));
                let send_stream = {
                    let streams_lock = streams.lock().await;
                    streams_lock.get(&stream_id).map(|s| s.send_stream.clone())
                };
                if let Some(send_stream) = send_stream {
                    let mut send = send_stream.lock().await;
                    let _ = send.reset(quinn::VarInt::from_u32(RAW_EXCESSIVE_LOAD));
                }
                streams.lock().await.remove(&stream_id);
                return;
            }

            Log::new(Some(&status_tx)).debug(format!(
                "Queued {} bytes for stream {}",
                data.len(),
                stream_id
            ));
            return;
        }

        // Merge any queued data with new data. The stream can disappear between
        // the state check above and this lock (peer reset, close_this_stream on
        // another task), so this must not unwrap.
        let mut all_data = {
            let mut streams_lock = streams.lock().await;
            let Some(stream_data) = streams_lock.get_mut(&stream_id) else {
                debug!(
                    "Stream {} closed before its data could be processed",
                    stream_id
                );
                return;
            };
            stream_data.state = StreamState::Processing;
            let mut merged = stream_data.queued_data.clone();
            merged.extend_from_slice(&data);
            stream_data.queued_data.clear();
            Bytes::from(merged)
        };

        loop {
            // Get send_stream for context
            let send_stream = {
                let streams_lock = streams.lock().await;
                streams_lock.get(&stream_id).map(|s| s.send_stream.clone())
            };

            let Some(send_stream) = send_stream else {
                return; // Stream not found
            };

            // Format data for the event parameter. Printable ASCII is passed
            // through as text, anything else is hex-encoded. `encoding` names
            // which of the two the model is looking at, and uses the same
            // vocabulary send_quic_data accepts, so the model can echo the
            // payload back byte-for-byte by passing both fields straight
            // through. (It used to say "text" where the outbound side had no
            // encoding field at all, which made binary un-echoable.)
            let (data_str, encoding) = crate::server::quic::actions::encode_quic_payload(&all_data);

            // Create data received event
            let event = Event::new(
                &QUIC_DATA_RECEIVED_EVENT,
                serde_json::json!({
                    "stream_id": stream_id.to_string(),
                    "data": data_str,
                    "encoding": encoding
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
                    debug!("LLM QUIC response received");

                    // Display messages
                    for msg in execution_result.messages {
                        let _ = status_tx.send(msg);
                    }

                    // Handle protocol results
                    let action_count = execution_result.protocol_results.len();
                    let mut should_close = false;
                    let mut should_wait = false;

                    for protocol_result in execution_result.protocol_results {
                        match protocol_result {
                            ActionResult::Output(output_data) => {
                                let write_result = {
                                    let mut send = send_stream.lock().await;
                                    send.write_all(&output_data).await
                                };
                                if let Err(e) = write_result {
                                    error!(
                                        "Failed to send response on stream {}: {}",
                                        stream_id, e
                                    );
                                } else {
                                    app_state
                                        .update_connection_stats(
                                            server_id,
                                            connection_id,
                                            None,
                                            Some(output_data.len() as u64),
                                            None,
                                            Some(1),
                                        )
                                        .await;
                                    // Sent-data summary + payload are FileOnly: the
                                    // send_quic_data action template already reports the send
                                    // to the TUI.
                                    let log = Log::new(Some(&status_tx));
                                    if output_data
                                        .iter()
                                        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                                    {
                                        let data_str = String::from_utf8_lossy(&output_data);
                                        let preview =
                                            crate::utils::truncate_for_log(&data_str, 100);
                                        log.debug(format!(
                                            "QUIC sent {} bytes on stream {}: {}",
                                            output_data.len(),
                                            stream_id,
                                            preview
                                        ));
                                        log.trace(format!("QUIC sent (text): {:?}", data_str));
                                    } else {
                                        log.debug(format!(
                                            "QUIC sent {} bytes on stream {} (binary data)",
                                            output_data.len(),
                                            stream_id
                                        ));
                                        log.trace(format!(
                                            "QUIC sent (hex): {}",
                                            hex::encode(&output_data)
                                        ));
                                    }
                                    log.debug(format!(
                                        "Sent {} bytes on stream {}",
                                        output_data.len(),
                                        stream_id
                                    ));
                                }
                            }
                            ActionResult::CloseConnection => {
                                should_close = true;
                            }
                            ActionResult::WaitForMore => {
                                should_wait = true;
                            }
                            _ => {}
                        }
                    }

                    // Handle wait_for_more
                    if should_wait {
                        streams
                            .lock()
                            .await
                            .entry(stream_id)
                            .and_modify(|s| s.state = StreamState::Accumulating);
                        Log::new(Some(&status_tx))
                            .debug(format!("Waiting for more data on stream {}", stream_id));
                        return;
                    }

                    // Handle close_stream
                    if should_close {
                        streams.lock().await.remove(&stream_id);
                        Log::new(Some(&status_tx)).info(format!("Closed stream {}", stream_id));
                        return;
                    }

                    // The model was reached and chose to say nothing. That is a real
                    // answer for a stream protocol — the peer may simply not be owed a
                    // reply yet — and it is NOT the same as the backend failing, so it is
                    // tagged separately in the log and leaves the stream open.
                    if action_count == 0 {
                        Log::new(Some(&status_tx)).debug(format!(
                            "No actions returned for QUIC data on stream {} \
                             (decision=model_no_actions); stream left open",
                            stream_id
                        ));
                    }

                    // Check for queued data
                    let has_queued = {
                        let streams_lock = streams.lock().await;
                        streams_lock
                            .get(&stream_id)
                            .map(|s| !s.queued_data.is_empty())
                            .unwrap_or(false)
                    };

                    if has_queued {
                        // Take the queue and make it the next iteration's payload.
                        // Leaving it in place re-sent the SAME bytes to the model on
                        // every pass and never emptied the queue: one response per
                        // iteration, forever, for a single line of input.
                        let queued = {
                            let mut streams_lock = streams.lock().await;
                            match streams_lock.get_mut(&stream_id) {
                                Some(stream) => std::mem::take(&mut stream.queued_data),
                                None => return,
                            }
                        };
                        if queued.is_empty() {
                            streams
                                .lock()
                                .await
                                .entry(stream_id)
                                .and_modify(|s| s.state = StreamState::Idle);
                            return;
                        }
                        all_data = Bytes::from(queued);
                    } else {
                        // Go to Idle state
                        streams
                            .lock()
                            .await
                            .entry(stream_id)
                            .and_modify(|s| s.state = StreamState::Idle);
                        return;
                    }
                }
                Err(e) => {
                    // Say *something* on the wire. This path used to reset the stream
                    // state to Idle and write nothing, so a peer that had just sent a
                    // request blocked until its own timeout with no indication anything
                    // had gone wrong.
                    //
                    // The category, and only the category, reaches the peer: a
                    // RESET_STREAM carrying an application-local error code. `e` is logged and
                    // never rendered into anything the peer can read.
                    let failure = crate::utils::WireFailure::classify(&e);
                    let code = wire_failure_code(failure);
                    let log = Log::new(Some(&status_tx));
                    log.warn(format!(
                        "LLM error for QUIC data on stream {} (decision=llm_error, category={}, \
                         raw_error_code=0x{:x}): {}",
                        stream_id,
                        failure.text(),
                        code.into_inner(),
                        e
                    ));

                    // RESET_STREAM drops anything still buffered for this stream. In a
                    // request/response exchange the peer has already consumed the previous
                    // round's reply before sending the request we just failed on, so the
                    // loss window is the reply we are not going to produce anyway.
                    {
                        let mut send = send_stream.lock().await;
                        let _ = send.reset(code);
                    }
                    streams.lock().await.remove(&stream_id);
                    log.info(format!(
                        "Reset QUIC stream {} after LLM error (decision=llm_error)",
                        stream_id
                    ));
                    return;
                }
            }
        }
    }
}

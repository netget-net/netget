//! BitTorrent DHT client implementation
pub mod actions;

pub use actions::TorrentDhtClientProtocol;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{error, info, trace, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::torrent_dht::actions::DHT_RESPONSE_EVENT;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// DHT query/response types
#[derive(Debug, Deserialize, Serialize)]
struct DhtMessage {
    #[serde(rename = "t")]
    transaction_id: serde_bencode::value::Value,
    #[serde(rename = "y")]
    message_type: String, // "q" = query, "r" = response, "e" = error
    #[serde(rename = "q")]
    query_type: Option<String>, // "ping", "find_node", "get_peers", "announce_peer"
    #[serde(rename = "a")]
    arguments: Option<serde_bencode::value::Value>,
    #[serde(rename = "r")]
    response: Option<serde_bencode::value::Value>,
    #[serde(rename = "e")]
    error: Option<serde_bencode::value::Value>,
}

/// Decode a KRPC field the model was told is hex, and say plainly when it is not.
///
/// The model sees "20 bytes hex" in the parameter description, so the error has to name the
/// field and what was wrong with it — a bare `hex::decode` failure gives it nothing to
/// correct. `expect_len` is the decoded length BEP 5 fixes for that field, where it fixes one.
fn decode_krpc_hex(field: &str, value: &str, expect_len: Option<usize>) -> Result<Vec<u8>> {
    let bytes = hex::decode(value).map_err(|e| {
        anyhow::anyhow!(
            "'{}' must be hex-encoded ({} characters for {} bytes): {}",
            field,
            expect_len.map(|n| n * 2).unwrap_or(0),
            expect_len.unwrap_or(0),
            e
        )
    })?;
    if let Some(expected) = expect_len {
        if bytes.len() != expected {
            return Err(anyhow::anyhow!(
                "'{}' decoded to {} bytes; BEP 5 requires exactly {}",
                field,
                bytes.len(),
                expected
            ));
        }
    }
    Ok(bytes)
}

/// A fresh two-byte KRPC transaction id.
///
/// A counter rather than a random value: it is only ever compared for equality against the
/// reply, and a monotonic one makes a packet capture readable. Two bytes is what BEP 5's own
/// examples use and what every client in the wild sends.
fn next_transaction_id() -> [u8; 2] {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes()
}

/// BitTorrent DHT client
pub struct TorrentDhtClient;

impl TorrentDhtClient {
    /// Connect to a BitTorrent DHT node with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // Parse remote address
        let remote_sock_addr: SocketAddr = remote_addr
            .parse()
            .context(format!("Invalid DHT node address: {}", remote_addr))?;

        // Create UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket for DHT")?;

        let local_addr = socket.local_addr()?;

        info!(
            "BitTorrent DHT client {} initialized (local: {}, remote: {})",
            client_id, local_addr, remote_sock_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] BitTorrent DHT client {} connected",
            client_id
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let socket_arc = Arc::new(socket);

        // Command channel for injected actions (the dashboard's [ send ]). Registered
        // BEFORE the connected-event LLM call below, which a manual `*` routing rule can
        // park for minutes - the operator must be able to reach the client while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // Spawn read loop for DHT responses
        let socket_clone = socket_arc.clone();
        let app_state_clone = app_state.clone();
        let status_tx_clone = status_tx.clone();
        let llm_client_clone = llm_client.clone();
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match socket_clone.recv_from(&mut buf).await {
                    Ok((len, peer)) => {
                        trace!(
                            "DHT client {} received {} bytes from {}",
                            client_id,
                            len,
                            peer
                        );

                        // Bound the nesting before serde_bencode sees it. A typed decode is
                        // no protection: serde's derive skips unknown fields with
                        // `IgnoredAny`, which serde_bencode forwards to `deserialize_any`,
                        // so `DhtMessage` reaches the same uncounted recursion as a raw
                        // `Value` would. One 65 KB datagram of `l` bytes overflows the
                        // stack, and a stack overflow is SIGSEGV — it takes the whole
                        // process with it, not just this task. The socket is unconnected,
                        // so any host that can reach the port can send it.
                        if let Err(e) = crate::utils::bencode::check_bencode_structure(&buf[..len])
                        {
                            warn!(
                                "DHT client {} rejected {} byte datagram from {}: {}",
                                client_id, len, peer, e
                            );
                            continue;
                        }

                        // Parse bencode response
                        match serde_bencode::from_bytes::<DhtMessage>(&buf[..len]) {
                            Ok(msg) => {
                                trace!("DHT message: {:?}", msg);

                                // Call LLM with response
                                if let Some(instruction) =
                                    app_state_clone.get_instruction_for_client(client_id).await
                                {
                                    let protocol = Arc::new(crate::client::torrent_dht::actions::TorrentDhtClientProtocol::new());
                                    let event = Event::new(
                                        &DHT_RESPONSE_EVENT,
                                        serde_json::json!({
                                            "message_type": msg.message_type,
                                            "query_type": msg.query_type,
                                            "response": format!("{:?}", msg.response),
                                            "error": format!("{:?}", msg.error),
                                            "peer": peer.to_string(),
                                        }),
                                    );

                                    let memory = app_state_clone
                                        .get_memory_for_client(client_id)
                                        .await
                                        .unwrap_or_default();

                                    match call_llm_for_client(
                                        &llm_client_clone,
                                        &app_state_clone,
                                        client_id.to_string(),
                                        &instruction,
                                        &memory,
                                        Some(&event),
                                        protocol.as_ref(),
                                        &status_tx_clone,
                                    )
                                    .await
                                    {
                                        Ok(ClientLlmResult {
                                            actions,
                                            memory_updates,
                                        }) => {
                                            // Update memory
                                            if let Some(mem) = memory_updates {
                                                app_state_clone
                                                    .set_memory_for_client(client_id, mem)
                                                    .await;
                                            }

                                            // Execute actions
                                            for action in actions {
                                                if let Err(e) = Self::execute_dht_action(
                                                    client_id,
                                                    action,
                                                    &socket_clone,
                                                    remote_sock_addr,
                                                    protocol.as_ref(),
                                                )
                                                .await
                                                {
                                                    error!("Failed to execute DHT action: {}", e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("LLM error for DHT client {}: {}", client_id, e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to parse DHT message: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("DHT client {} recv error: {}", client_id, e);
                        app_state_clone
                            .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                            .await;
                        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                        break;
                    }
                }
            }
            // Every exit path lands here: drop the command handle so the dashboard stops
            // offering [ send ] on a dead client, and a late send fails fast.
            app_state_clone.remove_client_handle(client_id).await;
            let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
        });
        // Kept so an injected `disconnect` can actually stop the receive loop and release
        // the UDP socket - a connectionless client has no wire close to send.
        let read_abort = task_handle.abort_handle();
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // `recv_from` is cancellation-safe, but the read loop awaits `call_llm_for_client`
        // inline, so a `select!` arm there would stall for the whole LLM round-trip. Drain
        // commands in their own registered task instead; both share the `Arc<UdpSocket>`.
        let cmd_state = app_state.clone();
        let cmd_status = status_tx.clone();
        let cmd_socket = socket_arc.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(
                command_rx,
                Arc::new(TorrentDhtClientProtocol::new()),
                cmd_socket,
                remote_sock_addr,
                client_id,
                cmd_state,
                cmd_status,
                read_abort,
            )
            .await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol =
                Arc::new(crate::client::torrent_dht::actions::TorrentDhtClientProtocol::new());
            let event = Event::new(
                &DHT_RESPONSE_EVENT,
                serde_json::json!({
                    "status": "connected",
                    "local_addr": local_addr.to_string(),
                    "remote_addr": remote_sock_addr.to_string(),
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();
            let socket_clone = socket_arc.clone();
            let app_state_clone = app_state.clone();
            let status_tx_clone = status_tx.clone();

            // Registered with AppState so stop_client can abort this task —
            // dropping a JoinHandle only detaches it in Tokio.
            let task_registrar = app_state.clone();
            let task_handle = tokio::spawn(async move {
                match call_llm_for_client(
                    &llm_client,
                    &app_state_clone,
                    client_id.to_string(),
                    &instruction,
                    &memory,
                    Some(&event),
                    protocol.as_ref(),
                    &status_tx_clone,
                )
                .await
                {
                    Ok(ClientLlmResult {
                        actions,
                        memory_updates,
                    }) => {
                        if let Some(mem) = memory_updates {
                            app_state_clone.set_memory_for_client(client_id, mem).await;
                        }

                        for action in actions {
                            if let Err(e) = Self::execute_dht_action(
                                client_id,
                                action,
                                &socket_clone,
                                remote_sock_addr,
                                protocol.as_ref(),
                            )
                            .await
                            {
                                error!("Failed to execute DHT action: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error: {}", e);
                    }
                }
            });
            task_registrar
                .register_client_task(client_id, task_handle)
                .await;
        }

        Ok(local_addr)
    }

    /// Drain injected commands until the channel closes (client removed) or an injected
    /// `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot serve this client:
    /// its verbs produce `ClientActionResult::Custom` and the transport is a datagram socket,
    /// not an `AsyncWrite`. The action still goes through [`Self::apply_action`] - the same
    /// function the LLM path uses - so the bencode encoding exists exactly once.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: tokio::sync::mpsc::Receiver<ClientCommand>,
        protocol: Arc<TorrentDhtClientProtocol>,
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        read_abort: tokio::task::AbortHandle,
    ) {
        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => Self::apply_action(client_id, result, &socket, remote_addr)
                    .await
                    .map(|applied| match applied {
                        Applied::Disconnect => ClientSendOutcome::Disconnected,
                        Applied::Sent(0) => ClientSendOutcome::Executed {
                            detail: "executed (no datagram sent)".to_string(),
                        },
                        Applied::Sent(bytes_sent) => ClientSendOutcome::Sent { bytes_sent },
                        Applied::Nothing(detail) => ClientSendOutcome::Executed { detail },
                        Applied::Refused(error) => ClientSendOutcome::Rejected { error },
                    }),
            };

            let outcome_json = match &outcome {
                Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({"error": e.to_string()}),
            };
            app_state
                .record_access_log(
                    AccessLogOwner::Client(client_id.as_u32()),
                    protocol.protocol_name(),
                    None,
                    "injected_action",
                    action,
                    vec![outcome_json],
                )
                .await;

            let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
            if let Err(e) = &outcome {
                Log::to(&status_tx).warn(format!(
                    "DHT client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                // No wire close exists for UDP, so "disconnected" means: stop receiving,
                // release the socket, drop the handle so [ send ] is greyed out again.
                read_abort.abort();
                app_state.remove_client_handle(client_id).await;
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }
        }
    }

    /// Execute a DHT action
    async fn execute_dht_action(
        client_id: ClientId,
        action: serde_json::Value,
        socket: &UdpSocket,
        remote_addr: SocketAddr,
        protocol: &dyn crate::llm::actions::client_trait::Client,
    ) -> Result<()> {
        let result = protocol.execute_action(action)?;
        Self::apply_action(client_id, result, socket, remote_addr).await?;
        Ok(())
    }

    /// Put one executed action on the wire. Shared by the LLM path and injected commands
    /// so the bencode query encoding exists exactly once.
    async fn apply_action(
        client_id: ClientId,
        result: ClientActionResult,
        socket: &UdpSocket,
        remote_addr: SocketAddr,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } if name == "dht_query" => {
                use serde_bencode::value::Value as Bencode;

                let query_type = data
                    .get("query_type")
                    .and_then(|v| v.as_str())
                    .context("Missing query_type")?;
                let node_id = data
                    .get("node_id")
                    .and_then(|v| v.as_str())
                    .context("Missing node_id")?;

                // Every query used to carry the literal transaction id "aa", so a node's
                // replies could not be matched to the query that provoked them and two
                // queries in flight were indistinguishable. `t` is the only correlation key
                // KRPC has.
                // A field the caller got wrong is `Refused`, not `Err`: nothing is broken,
                // the request was simply not answerable, and the model needs to be told
                // which field and why rather than seeing a transport failure.
                macro_rules! decode_or_refuse {
                    ($field:expr, $value:expr, $len:expr) => {
                        match decode_krpc_hex($field, $value, $len) {
                            Ok(bytes) => bytes,
                            Err(e) => return Ok(Applied::Refused(e.to_string())),
                        }
                    };
                }

                let transaction_id = match data.get("transaction_id").and_then(|v| v.as_str()) {
                    Some(hex_id) => decode_or_refuse!("transaction_id", hex_id, None),
                    None => next_transaction_id().to_vec(),
                };

                // Build DHT query message.
                //
                // `id`, `target` and `info_hash` are declared to the model as "20 bytes hex"
                // and are now decoded as such. They used to be placed as JSON strings and
                // bencoded as their own UTF-8 bytes, so a model that obeyed the description
                // put **40** bytes on the wire where BEP 5 requires 20 — the `send_tcp_data`
                // defect shape, documented as hex and never decoded. It also meant this
                // client could not talk to NetGet's own DHT *server*, which hex-decodes all
                // three. The examples were the only part that matched the old behaviour, and
                // they were not even valid hex ("abcdefghij…" contains g-j).
                let mut args = std::collections::HashMap::new();
                args.insert(
                    b"id".to_vec(),
                    Bencode::Bytes(decode_or_refuse!("node_id", node_id, Some(20))),
                );

                if let Some(target) = data.get("target").and_then(|v| v.as_str()) {
                    args.insert(
                        b"target".to_vec(),
                        Bencode::Bytes(decode_or_refuse!("target", target, Some(20))),
                    );
                }

                if let Some(info_hash) = data.get("info_hash").and_then(|v| v.as_str()) {
                    args.insert(
                        b"info_hash".to_vec(),
                        Bencode::Bytes(decode_or_refuse!("info_hash", info_hash, Some(20))),
                    );
                }

                let mut message = std::collections::HashMap::new();
                message.insert(b"t".to_vec(), Bencode::Bytes(transaction_id));
                message.insert(b"y".to_vec(), Bencode::Bytes(b"q".to_vec()));
                message.insert(
                    b"q".to_vec(),
                    Bencode::Bytes(query_type.as_bytes().to_vec()),
                );
                message.insert(b"a".to_vec(), Bencode::Dict(args));

                // Encode as bencode
                let encoded = serde_bencode::to_bytes(&Bencode::Dict(message))?;

                // Send query
                let sent = socket.send_to(&encoded, remote_addr).await?;
                trace!("DHT client {} sent {} query", client_id, query_type);
                Ok(Applied::Sent(sent))
            }
            ClientActionResult::Disconnect => {
                info!("DHT client {} disconnecting", client_id);
                Ok(Applied::Disconnect)
            }
            ClientActionResult::WaitForMore => Ok(Applied::Nothing("wait_for_more".to_string())),
            ClientActionResult::Custom { name, .. } => Ok(Applied::Nothing(format!(
                "custom result '{name}' is not a DHT query; nothing sent"
            ))),
            other => Ok(Applied::Nothing(format!(
                "action result {other:?} produced no datagram"
            ))),
        }
    }
}

/// What [`TorrentDhtClient::apply_action`] did with one action.
#[derive(Debug)]
enum Applied {
    /// Datagram bytes actually handed to `send_to` (0 when nothing was sent).
    Sent(usize),
    /// Ran, but produced no datagram; the string says why.
    Nothing(String),
    /// The action's own parameters were wrong -- a `node_id` that is not hex, an
    /// `info_hash` of the wrong length. Nothing was written and nothing is broken; the
    /// caller simply asked for something impossible, exactly as when it names a verb the
    /// protocol does not have. It therefore comes back as `Rejected`, not as a transport
    /// error, so the dashboard shows the model what to correct.
    Refused(String),
    /// The session should end.
    Disconnect,
}

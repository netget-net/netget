//! BitTorrent DHT server implementation
//!
//! UDP-based Kademlia DHT for distributed peer discovery (BEP 5)

pub mod actions;

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::utils::WireFailure;
use crate::{console_debug, console_trace};
use actions::TorrentDhtProtocol;

/// BEP 5 error code 201 — "Generic Error".
const KRPC_GENERIC_ERROR: i64 = 201;
/// BEP 5 error code 202 — "Server Error". Used for the transient (overloaded) case so a
/// querying node distinguishes "come back later" from a permanent fault on this node.
const KRPC_SERVER_ERROR: i64 = 202;

/// Bound converted values independently of the wire decoder's preflight.
pub const MAX_DHT_VALUE_DEPTH: usize = crate::utils::bencode::MAX_BENCODE_DEPTH;

/// BitTorrent DHT server
pub struct TorrentDhtServer;

impl TorrentDhtServer {
    /// Spawn BitTorrent DHT server with LLM actions
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        let local_addr = socket.local_addr()?;
        info!(
            "BitTorrent DHT server (action-based) listening on {}",
            local_addr
        );
        let _ = status_tx.send(format!(
            "[INFO] BitTorrent DHT server listening on {}",
            local_addr
        ));

        let protocol = Arc::new(TorrentDhtProtocol::new());

        let task_registrar = app_state.clone();
        let accept_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65535];

            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((n, peer_addr)) => {
                        let data = buffer[..n].to_vec();
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);

                        // Add connection to ServerInstance
                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();
                        let conn_state = ServerConnectionState {
                            id: connection_id,
                            remote_addr: peer_addr,
                            local_addr,
                            bytes_sent: 0,
                            bytes_received: n as u64,
                            packets_sent: 0,
                            packets_received: 1,
                            last_activity: now,
                            status: ConnectionStatus::Active,
                            status_changed_at: now,
                            protocol_info: ProtocolConnectionInfo::empty(),
                        };
                        app_state
                            .add_connection_to_server(server_id, conn_state)
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        console_debug!(
                            status_tx,
                            "BitTorrent DHT received {} bytes from {}",
                            n,
                            peer_addr
                        );

                        // TRACE: Log full payload
                        let hex_str = hex::encode(&data);
                        console_trace!(status_tx, "BitTorrent DHT data (hex): {}", hex_str);

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let socket_clone = socket.clone();
                        let protocol_clone = protocol.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Parse bencode KRPC message
                                match Self::parse_krpc_message(&data) {
                                    Ok((query_type, params)) => {
                                        Log::to(&status_clone).debug(format!(
                                            "BitTorrent DHT query type: {}",
                                            query_type
                                        ));

                                        // Create event for LLM
                                        let event_type = match query_type.as_str() {
                                            "ping" => &actions::DHT_PING_QUERY_EVENT,
                                            "find_node" => &actions::DHT_FIND_NODE_QUERY_EVENT,
                                            "get_peers" => &actions::DHT_GET_PEERS_QUERY_EVENT,
                                            "announce_peer" => {
                                                &actions::DHT_ANNOUNCE_PEER_QUERY_EVENT
                                            }
                                            // An unrecognised `q` still reaches the ping
                                            // handler, whose reply shape (`{"id": ...}`) is the
                                            // KRPC minimum. `query_type` in the event data says
                                            // what actually arrived, so a handler can answer
                                            // with send_dht_error_response code 204 instead.
                                            other => {
                                                tracing::warn!(
                                                    "BitTorrent DHT: unsupported query '{}', \
                                                 routing to dht_ping_query",
                                                    other
                                                );
                                                &actions::DHT_PING_QUERY_EVENT
                                            }
                                        };
                                        // Kept out of the event so a failure reply can still echo
                                        // `t`: a KRPC reply that does not carry the querying
                                        // node's transaction id is dropped, and the peer waits
                                        // out its own timeout exactly as if we had said nothing.
                                        let transaction_id_hex = params
                                            .get("transaction_id")
                                            .and_then(|v| v.as_str())
                                            .map(|s| s.to_string());

                                        let event =
                                            Event::new(event_type, serde_json::json!(params));

                                        Log::to(&status_clone).debug(format!(
                                            "BitTorrent DHT calling LLM for {} query",
                                            query_type
                                        ));

                                        // Call LLM
                                        match call_llm(
                                            &llm_clone,
                                            &state_clone,
                                            server_id,
                                            None,
                                            &event,
                                            protocol_clone.as_ref(),
                                        )
                                        .await
                                        {
                                            Ok(execution_result) => {
                                                for message in &execution_result.messages {
                                                    Log::to(&status_clone).info(message);
                                                }

                                                Log::to(&status_clone).debug(format!(
                                                    "BitTorrent DHT got {} protocol results",
                                                    execution_result.protocol_results.len()
                                                ));

                                                // An explicit refusal by the model is a KRPC
                                                // error reply it asked for itself; keep it
                                                // distinguishable in the log from our own
                                                // fail-closed reply, which says nothing about
                                                // what the model thought.
                                                let model_rejected =
                                                    execution_result.raw_actions.iter().any(|a| {
                                                        a.get("type").and_then(|t| t.as_str())
                                                            == Some("send_dht_error_response")
                                                    });

                                                let mut sent_any = false;
                                                for protocol_result in
                                                    execution_result.protocol_results
                                                {
                                                    if let Some(output_data) =
                                                        protocol_result.get_all_output().first()
                                                    {
                                                        if let Err(e) = socket_clone
                                                            .send_to(output_data, peer_addr)
                                                            .await
                                                        {
                                                            error!(
                                                                "Failed to send DHT response: {}",
                                                                e
                                                            );
                                                        } else {
                                                            sent_any = true;
                                                            Log::to(&status_clone).debug(format!(
                                                            "BitTorrent DHT sent {} bytes to {}",
                                                            output_data.len(),
                                                            peer_addr
                                                        ));

                                                            let hex_str = hex::encode(output_data);
                                                            Log::to(&status_clone).trace(format!(
                                                                "BitTorrent DHT sent (hex): {}",
                                                                hex_str
                                                            ));
                                                        }
                                                    }
                                                }

                                                if sent_any {
                                                    debug!(
                                                        "BitTorrent DHT {} from {} decision={}",
                                                        query_type,
                                                        peer_addr,
                                                        if model_rejected {
                                                            "model_reject"
                                                        } else {
                                                            "model_answer"
                                                        }
                                                    );
                                                } else {
                                                    // The model produced nothing that reaches the
                                                    // wire. Staying silent would leave the
                                                    // querying node blocked until its own
                                                    // timeout, so answer with a category.
                                                    tracing::warn!(
                                                        "BitTorrent DHT {} from {} decision=\
                                                     fail_closed_no_action",
                                                        query_type,
                                                        peer_addr
                                                    );
                                                    let _ = status_clone.send(format!(
                                                    "[WARN] BitTorrent DHT {} from {}: no action \
                                                     from the model, replying KRPC error",
                                                    query_type, peer_addr
                                                ));
                                                    Self::send_failure_reply(
                                                        &socket_clone,
                                                        peer_addr,
                                                        transaction_id_hex.as_deref(),
                                                        WireFailure::Unavailable,
                                                        &status_clone,
                                                    )
                                                    .await;
                                                }
                                            }
                                            Err(e) => {
                                                // The error itself goes to the log and the status
                                                // stream only — the peer gets a bare BEP 5 error
                                                // code and a fixed category string.
                                                let failure = WireFailure::classify(&e);
                                                error!(
                                                    "BitTorrent DHT {} from {} \
                                                 decision=fail_closed_llm_error \
                                                 category={:?}: {}",
                                                    query_type, peer_addr, failure, e
                                                );
                                                let _ = status_clone.send(format!(
                                                "[ERROR] BitTorrent DHT LLM call failed for {} \
                                                 from {}: {}",
                                                query_type, peer_addr, e
                                            ));
                                                Self::send_failure_reply(
                                                    &socket_clone,
                                                    peer_addr,
                                                    transaction_id_hex.as_deref(),
                                                    failure,
                                                    &status_clone,
                                                )
                                                .await;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        Log::to(&status_clone)
                                            .error(format!("Failed to parse KRPC message: {}", e));
                                    }
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        error!("BitTorrent DHT receive error: {}", e);
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

    /// Answer a query netget cannot serve with a BEP 5 error reply carrying only a category.
    ///
    /// `{"t": <echoed>, "y": "e", "e": [code, text]}`. The code separates the two categories
    /// so a querying node can back off rather than record a permanent fault here: 202
    /// ("Server Error") for a saturated backend, 201 ("Generic Error") for everything else.
    /// The text comes from [`WireFailure::text`], which is `&'static str` — the backend
    /// error, the model name and any path stay in the log.
    async fn send_failure_reply(
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        transaction_id_hex: Option<&str>,
        failure: WireFailure,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        // Without `t` there is nothing for the querying node to correlate the reply with, and
        // BEP 5 requires it on every message; an unaddressed datagram is worse than silence.
        let Some(transaction_id) = transaction_id_hex.and_then(|t| hex::decode(t).ok()) else {
            tracing::warn!(
                "BitTorrent DHT: cannot send failure reply to {} — query carried no usable \
                 transaction id",
                peer_addr
            );
            return;
        };

        let code = if failure.is_overloaded() {
            KRPC_SERVER_ERROR
        } else {
            KRPC_GENERIC_ERROR
        };

        let mut response = std::collections::HashMap::new();
        response.insert(
            b"t".to_vec(),
            serde_bencode::value::Value::Bytes(transaction_id),
        );
        response.insert(
            b"y".to_vec(),
            serde_bencode::value::Value::Bytes(b"e".to_vec()),
        );
        response.insert(
            b"e".to_vec(),
            serde_bencode::value::Value::List(vec![
                serde_bencode::value::Value::Int(code),
                serde_bencode::value::Value::Bytes(failure.text().as_bytes().to_vec()),
            ]),
        );

        let encoded = match serde_bencode::to_bytes(&serde_bencode::value::Value::Dict(response)) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("BitTorrent DHT: failed to encode KRPC error reply: {}", e);
                return;
            }
        };

        match socket.send_to(&encoded, peer_addr).await {
            Ok(sent) => {
                debug!(
                    "BitTorrent DHT sent KRPC error {} ({} bytes) to {}",
                    code, sent, peer_addr
                );
                let _ = status_tx.send(format!(
                    "[DEBUG] BitTorrent DHT sent KRPC error {} to {}",
                    code, peer_addr
                ));
            }
            Err(e) => {
                error!(
                    "BitTorrent DHT: failed to send KRPC error reply to {}: {}",
                    peer_addr, e
                );
            }
        }
    }

    fn parse_krpc_message(data: &[u8]) -> Result<(String, serde_json::Value)> {
        use serde_bencode::value::Value;

        // Bound the nesting before serde_bencode sees it. `serde_bencode` recurses once per
        // `l`/`d` with no depth counter, so a datagram of 65,000 `l` bytes — which is what
        // fits in one UDP packet and costs an attacker one sendto() — overflows the worker
        // thread's stack. That is a SIGSEGV, not a panic: the task this runs in cannot
        // contain it and the whole netget process dies. Measured against 0.2.4.
        crate::utils::bencode::check_bencode_structure(data)
            .map_err(|e| anyhow::anyhow!("Rejected KRPC datagram: {}", e))?;

        // Decode bencode
        let value: Value = serde_bencode::from_bytes(data)?;

        if let Value::Dict(dict) = value {
            // Get message type (q = query, r = response, e = error)
            let msg_type = dict
                .get::<[u8]>(b"y")
                .and_then(|v| {
                    if let Value::Bytes(bytes) = v {
                        String::from_utf8(bytes.clone()).ok()
                    } else {
                        None
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("Missing 'y' field"))?;

            if msg_type == "q" {
                // Query message
                let query_type = dict
                    .get::<[u8]>(b"q")
                    .and_then(|v| {
                        if let Value::Bytes(bytes) = v {
                            String::from_utf8(bytes.clone()).ok()
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| anyhow::anyhow!("Missing 'q' field"))?;

                // Get transaction ID
                let transaction_id = dict.get::<[u8]>(b"t").and_then(|v| {
                    if let Value::Bytes(bytes) = v {
                        Some(hex::encode(bytes))
                    } else {
                        None
                    }
                });

                // Get arguments.
                //
                // `query_type` is always present so a handler can tell an announce_peer
                // from an unsupported method, both of which reach the ping event.
                let mut params = serde_json::Map::new();
                params.insert("query_type".to_string(), serde_json::json!(&query_type));
                if let Some(transaction_id) = transaction_id {
                    params.insert(
                        "transaction_id".to_string(),
                        serde_json::json!(transaction_id),
                    );
                }

                if let Some(Value::Dict(args)) = dict.get::<[u8]>(b"a") {
                    for (k, v) in args {
                        let key = String::from_utf8_lossy(k).to_string();
                        // `id`, `target` and `info_hash` are always 20 raw bytes and are
                        // documented as hex. bencode_to_json would render them as text
                        // whenever all 20 bytes happened to be printable ASCII, so the
                        // same field arrived hex-encoded or not depending on the client's
                        // random ID — and hex::decode on the response side then failed.
                        let value = match (key.as_str(), v) {
                            ("id" | "target" | "info_hash", Value::Bytes(bytes)) => {
                                serde_json::json!(hex::encode(bytes))
                            }
                            _ => Self::bencode_to_json(v)?,
                        };
                        params.insert(key, value);
                    }
                }

                Ok((query_type, serde_json::Value::Object(params)))
            } else {
                Err(anyhow::anyhow!("Not a query message"))
            }
        } else {
            Err(anyhow::anyhow!("Invalid KRPC message"))
        }
    }

    /// Convert a bencode value without relying on where it was decoded or constructed.
    /// Lists and dictionaries each count as one level; scalars consume no depth.
    pub fn bencode_to_json(value: &serde_bencode::value::Value) -> Result<serde_json::Value> {
        Self::bencode_to_json_bounded(value, 0)
    }

    fn bencode_to_json_bounded(
        value: &serde_bencode::value::Value,
        depth: usize,
    ) -> Result<serde_json::Value> {
        use serde_bencode::value::Value;

        if matches!(value, Value::List(_) | Value::Dict(_)) && depth >= MAX_DHT_VALUE_DEPTH {
            anyhow::bail!("DHT value nesting exceeds the {MAX_DHT_VALUE_DEPTH} level limit");
        }

        Ok(match value {
            Value::Int(i) => serde_json::json!(i),
            Value::Bytes(bytes) => {
                // Try to decode as UTF-8 string, otherwise hex encode
                if let Ok(s) = String::from_utf8(bytes.clone()) {
                    if s.chars()
                        .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                    {
                        serde_json::json!(s)
                    } else {
                        serde_json::json!(hex::encode(bytes))
                    }
                } else {
                    serde_json::json!(hex::encode(bytes))
                }
            }
            Value::List(list) => {
                let json_list = list
                    .iter()
                    .map(|v| Self::bencode_to_json_bounded(v, depth + 1))
                    .collect::<Result<Vec<_>>>()?;
                serde_json::Value::Array(json_list)
            }
            Value::Dict(dict) => {
                let mut json_obj = serde_json::Map::new();
                for (k, v) in dict {
                    let key = String::from_utf8_lossy(k).to_string();
                    json_obj.insert(key, Self::bencode_to_json_bounded(v, depth + 1)?);
                }
                serde_json::Value::Object(json_obj)
            }
        })
    }
}

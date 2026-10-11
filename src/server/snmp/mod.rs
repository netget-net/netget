//! SNMP agent implementation using rasn-snmp library
pub mod actions;
pub mod notify;
pub mod usm;

use crate::server::connection::ConnectionId;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

// SNMP protocol support
use rasn::{ber, types::Integer};
use rasn_snmp::{v1, v2, v2c};

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::SnmpProtocol;
use crate::state::app_state::AppState;
use crate::{console_debug, console_trace};
use actions::SNMP_REQUEST_EVENT;

/// Parsed SNMP message information
#[derive(Debug)]
pub struct ParsedSnmpInfo {
    pub description: String,
    pub request_type: String,
    pub version: u8,
    pub request_id: i32,
    pub community: Vec<u8>,
    pub requested_oids: Vec<String>,
}

/// How an answer is wrapped: in the community message it came in (v1/v2c), or in a USM
/// message for the user and level it was authenticated at (v3).
#[derive(Clone)]
pub enum Framing {
    Community {
        version: u8,
        community: Vec<u8>,
    },
    Usm {
        agent: Arc<usm::Agent>,
        request: Arc<usm::Request>,
    },
}

/// SNMP server that forwards requests to LLM
/// SNMP `error-status` genErr (RFC 1157 §4.1.1, RFC 3416 §3): "the agent could not produce
/// this response for reasons not covered by any other status".
///
/// Any non-zero error-status makes the Response PDU an error report rather than an answer, so
/// no manager can read this as a value for the requested OID.
pub const SNMP_ERROR_GEN_ERR: u8 = 5;
/// `error-status` tooBig (RFC 3416 §4.2.1): the answer would not fit the manager's msgMaxSize.
pub const SNMP_ERROR_TOO_BIG: u8 = 1;

/// How deeply a datagram may nest BER constructed values before we refuse to decode it.
///
/// A real SNMP message is four levels deep: Message SEQUENCE > PDU > VarBindList > VarBind.
/// Sixteen leaves generous headroom for anything a manager legitimately sends while keeping
/// `rasn`'s recursion to a depth no stack cares about.
pub const MAX_BER_DEPTH: usize = 16;

/// `rasn` 0.18 decodes a *constructed* OCTET STRING by calling
/// `ber::de::parser::parse_encoded_value` on each of its segments, and a segment may itself be
/// constructed — so the function calls itself, with no depth counter anywhere on the path.
/// `v1::Message` and `v2c::Message` both carry `community` as an OCTET STRING, so the nesting a
/// datagram declares is the recursion depth we get, and the only bound is the datagram size.
///
/// `24 80` (constructed OCTET STRING, indefinite length) is two bytes and buys one level. The
/// end-of-contents markers can be omitted entirely — the decoder descends while input remains
/// and only discovers the missing EOC on the way back up — so a single 64 KB UDP datagram
/// reaches roughly 32000 frames. Measured here: 30000 levels aborts the process with
/// `fatal runtime error: stack overflow`.
///
/// That is not a recoverable fault. A Rust stack overflow is a guard-page `SIGSEGV`/`SIGABRT`,
/// not a panic: `tokio::spawn` cannot isolate it and `catch_unwind` cannot see it, so one
/// unauthenticated datagram takes down every other server the NetGet process is running.
///
/// The screen below therefore walks the TLV structure *iteratively* — an explicit stack, no
/// recursion of its own — and rejects the datagram before `rasn` ever sees it. It also rejects
/// a definite length that reaches past the end of the datagram, which is the same class of
/// mistake read from the other side: trust the length the peer declared and you buffer or index
/// on a number the peer chose.
///
/// Returns `Err` with a reason suitable for the log. Never panics, never loops: `pos` strictly
/// increases on every iteration and every read is bounds-checked.
pub fn check_ber_structure(data: &[u8], max_depth: usize) -> std::result::Result<(), String> {
    // `None` = indefinite length, closed by an end-of-contents marker.
    // `Some(end)` = definite length, closed when `pos` reaches `end`.
    let mut open: Vec<Option<usize>> = Vec::new();
    let mut pos = 0usize;

    loop {
        // Close every definite-length level this position has run past.
        while let Some(Some(end)) = open.last() {
            if pos >= *end {
                open.pop();
            } else {
                break;
            }
        }

        if pos >= data.len() {
            break;
        }

        // An end-of-contents marker closes the innermost indefinite level.
        if data[pos] == 0x00 && data.get(pos + 1) == Some(&0x00) {
            if matches!(open.last(), Some(None)) {
                open.pop();
                pos += 2;
                continue;
            }
            // A stray 00 00 outside any indefinite level is malformed; let rasn produce the
            // real diagnostic rather than guessing at it here.
            return Ok(());
        }

        // --- identifier octets ---
        let first = data[pos];
        let constructed = (first & 0x20) != 0;
        pos += 1;
        if first & 0x1f == 0x1f {
            // High-tag-number form: continuation octets until one without the high bit.
            loop {
                let Some(&b) = data.get(pos) else {
                    return Err("truncated BER tag".to_string());
                };
                pos += 1;
                if b & 0x80 == 0 {
                    break;
                }
            }
        }

        // --- length octets ---
        let Some(&len_first) = data.get(pos) else {
            return Err("truncated BER length".to_string());
        };
        pos += 1;

        let length: Option<usize> = if len_first == 0x80 {
            None // indefinite
        } else if len_first & 0x80 == 0 {
            Some(len_first as usize)
        } else {
            let n = (len_first & 0x7f) as usize;
            // A length-of-length beyond 8 octets cannot describe anything a datagram holds.
            if n > 8 {
                return Err(format!("BER length field of {n} octets is not decodable"));
            }
            let Some(bytes) = data.get(pos..pos + n) else {
                return Err("truncated BER long-form length".to_string());
            };
            pos += n;
            let mut v: u64 = 0;
            for &b in bytes {
                v = (v << 8) | b as u64;
            }
            // Bound the *declared* length against the whole datagram, not against whatever
            // happens to be left: `usize::try_from` alone would accept 4 GB on a 64-bit box.
            let v = usize::try_from(v).map_err(|_| "BER length overflows usize".to_string())?;
            if v > data.len() {
                return Err(format!(
                    "BER element declares {v} bytes in a {} byte datagram",
                    data.len()
                ));
            }
            Some(v)
        };

        match (constructed, length) {
            (true, definite) => {
                let end = match definite {
                    Some(len) => {
                        let end = pos.checked_add(len).ok_or("BER length overflows")?;
                        if end > data.len() {
                            return Err(format!(
                                "BER element ends at {end}, past the {} byte datagram",
                                data.len()
                            ));
                        }
                        Some(end)
                    }
                    None => None,
                };
                open.push(end);
                if open.len() > max_depth {
                    return Err(format!(
                        "BER nesting deeper than {max_depth} levels; a real SNMP message is 4"
                    ));
                }
                // Contents of a constructed value are the next elements: do not skip them.
            }
            (false, Some(len)) => {
                pos = pos.checked_add(len).ok_or("BER length overflows")?;
                if pos > data.len() {
                    return Err("BER primitive runs past the end of the datagram".to_string());
                }
            }
            (false, None) => {
                // Indefinite length on a primitive is invalid BER.
                return Err("indefinite length on a primitive BER value".to_string());
            }
        }
    }

    Ok(())
}

pub struct SnmpServer;

impl SnmpServer {
    /// Spawn SNMP agent with integrated LLM actions
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        usm: Option<Arc<usm::Agent>>,
    ) -> Result<SocketAddr> {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        if let Some(agent) = &usm {
            info!(
                "SNMP agent serves SNMPv3 as engine {} (boots {})",
                hex::encode(&agent.engine_id),
                agent.boots
            );
        }
        let local_addr = socket.local_addr()?;
        info!("SNMP agent (action-based) listening on {}", local_addr);

        let protocol = Arc::new(SnmpProtocol::new());

        let task_registrar = app_state.clone();
        let accept_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65535];

            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((n, peer_addr)) => {
                        let data = buffer[..n].to_vec();
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);

                        // Add connection to ServerInstance (SNMP "connection" = recent peer)
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

                        // DEBUG: Log summary
                        console_debug!(status_tx, "SNMP received {} bytes from {}", n, peer_addr);

                        // TRACE: Log full payload
                        let hex_str = hex::encode(&data);
                        console_trace!(status_tx, "SNMP data (hex): {}", hex_str);

                        // SNMPv3: the USM decides first — discovery, unknown users, wrong
                        // digests and stale clocks are answered with its reports and never
                        // reach the handler.
                        let mut v3_request: Option<Arc<usm::Request>> = None;
                        if check_ber_structure(&data, MAX_BER_DEPTH).is_ok() && usm::is_v3(&data) {
                            let Some(agent) = &usm else {
                                warn!(
                                    "SNMP dropping an SNMPv3 message from {} \
                                     (decision=dropped_v3_not_configured): no v3_users configured",
                                    peer_addr
                                );
                                let _ = status_tx.send(format!(
                                    "[WARN] SNMP dropped an SNMPv3 message from {}: no v3_users are configured",
                                    peer_addr
                                ));
                                continue;
                            };
                            match agent.receive(&data) {
                                usm::Inbound::Report(bytes, kind) => {
                                    info!(
                                        "SNMP v3 report {} to {} (decision=usm_report)",
                                        kind.name(),
                                        peer_addr
                                    );
                                    let _ = status_tx.send(format!(
                                        "[INFO] SNMP v3 {} report to {}",
                                        kind.name(),
                                        peer_addr
                                    ));
                                    if let Err(e) = socket.send_to(&bytes, peer_addr).await {
                                        error!("SNMP v3 report to {} failed: {}", peer_addr, e);
                                    }
                                    continue;
                                }
                                usm::Inbound::Drop(reason) => {
                                    warn!(
                                        "SNMP dropping an SNMPv3 message from {} \
                                         (decision=dropped_v3): {}",
                                        peer_addr, reason
                                    );
                                    let _ = status_tx.send(format!(
                                        "[WARN] SNMP dropped an SNMPv3 message from {}: {}",
                                        peer_addr, reason
                                    ));
                                    continue;
                                }
                                usm::Inbound::Request(request) => {
                                    if !matches!(
                                        request.pdu,
                                        v2::Pdus::GetRequest(_)
                                            | v2::Pdus::GetNextRequest(_)
                                            | v2::Pdus::GetBulkRequest(_)
                                            | v2::Pdus::SetRequest(_)
                                    ) {
                                        warn!(
                                            "SNMP dropping a v3 {} from {} \
                                             (decision=dropped_v3_notification): SNMPv3 \
                                             notifications are not served",
                                            Self::get_v2_pdu_type(&request.pdu),
                                            peer_addr
                                        );
                                        continue;
                                    }
                                    v3_request = Some(Arc::from(request));
                                }
                            }
                        }

                        // A trap or an inform is a notification, not a request: it has no
                        // variables to answer and goes to the handler as one event.
                        if v3_request.is_none() && check_ber_structure(&data, MAX_BER_DEPTH).is_ok()
                        {
                            if let Some(received) = notify::parse(&data) {
                                let llm = llm_client.clone();
                                let state = app_state.clone();
                                let status = status_tx.clone();
                                let socket = socket.clone();
                                let protocol = protocol.clone();
                                app_state
                                    .spawn_server_task(server_id, async move {
                                        Self::handle_notification(
                                            received, peer_addr, llm, state, status, socket,
                                            protocol, server_id,
                                        )
                                        .await;
                                    })
                                    .await;
                                continue;
                            }
                        }

                        // Parse the SNMP message
                        let parsed = match v3_request
                            .as_ref()
                            .map(|r| Self::describe_v3(r))
                            .map_or_else(|| Self::parse_snmp_message(&data), Ok)
                        {
                            Ok(p) => p,
                            Err(e) => {
                                // Silent on the wire — there is no request-id to answer, and a
                                // Response PDU without one is not addressable to anything. The
                                // operator still has to be able to see it, so it goes to the
                                // status stream as well as the log.
                                warn!(
                                    "SNMP dropping unparseable datagram from {} \
                                     (decision=dropped_malformed_request): {}",
                                    peer_addr, e
                                );
                                let _ = status_tx.send(format!(
                                    "[WARN] SNMP dropped a malformed {} byte datagram from {}: {}",
                                    n, peer_addr, e
                                ));
                                continue;
                            }
                        };

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let socket_clone = socket.clone();
                        let protocol_clone = protocol.clone();
                        let request_id = parsed.request_id;
                        let framing = match (&usm, v3_request) {
                            (Some(agent), Some(request)) => Framing::Usm {
                                agent: agent.clone(),
                                request,
                            },
                            _ => Framing::Community {
                                version: parsed.version,
                                community: parsed.community.clone(),
                            },
                        };
                        let requested_oids = parsed.requested_oids.clone();

                        // Spawn task to handle request with LLM
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner.spawn_server_task(server_id, async move {
                            // Clone for BER encoding later
                            let requested_oids_clone = requested_oids.clone();

                            // Create SNMP request event. request_id and the community
                            // string are echoed into the response automatically - they are
                            // exposed here so a handler can inspect or log them.
                            let answer_with = actions::answer_with_for_request(
                                &parsed.request_type,
                                &parsed.requested_oids,
                            );
                            let mut data = serde_json::json!({
                                "request_type": parsed.request_type,
                                "answer_with": answer_with,
                                "oids": parsed.requested_oids,
                                "community": String::from_utf8_lossy(&parsed.community).to_string(),
                                "request_id": parsed.request_id,
                                "version": match parsed.version { 0 => "v1", 3 => "v3", _ => "v2c" },
                                "client_ip": peer_addr.ip().to_string()
                            });
                            if let Framing::Usm { request, .. } = &framing {
                                data["user"] = serde_json::json!(request.user);
                                data["security_level"] = serde_json::json!(request.level.name());
                                data["context_name"] = serde_json::json!(
                                    String::from_utf8_lossy(&request.context_name)
                                );
                            }
                            let event = Event::new(&SNMP_REQUEST_EVENT, data);

                            debug!("SNMP calling LLM for request from {}", peer_addr);
                            let _ = status_clone.send(format!(
                                "[DEBUG] SNMP calling LLM for request from {}",
                                peer_addr
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
                                    // Display messages from LLM
                                    for message in &execution_result.messages {
                                        info!("{}", message);
                                        let _ = status_clone.send(format!("[INFO] {}", message));
                                    }

                                    debug!(
                                        "SNMP got {} protocol results",
                                        execution_result.protocol_results.len()
                                    );
                                    let _ = status_clone.send(format!(
                                        "[DEBUG] SNMP got {} protocol results",
                                        execution_result.protocol_results.len()
                                    ));

                                    // A model that answers with nothing — `ignore_request`, or
                                    // simply no action at all — is a real decision, and the
                                    // only place it can be recorded is the log: on the wire it
                                    // is indistinguishable from the agent being down. Tag it so
                                    // it can be told apart from a backend failure, the way
                                    // `radius` does.
                                    if !execution_result
                                        .protocol_results
                                        .iter()
                                        .any(|r| !r.get_all_output().is_empty())
                                    {
                                        info!(
                                            "SNMP answering nothing to request {} from {} \
                                             (decision=model_silent)",
                                            request_id, peer_addr
                                        );
                                        let _ = status_clone.send(format!(
                                            "SNMP: no reply to {} (model chose silence)",
                                            peer_addr
                                        ));
                                    }

                                    // Handle protocol results (send SNMP response)
                                    for protocol_result in execution_result.protocol_results {
                                        if let Some(output_data) =
                                            protocol_result.get_all_output().first()
                                        {
                                            // Parse JSON response and convert to SNMP BER format
                                            let json_str = String::from_utf8_lossy(output_data);

                                            // An error-status reply is the model refusing this
                                            // OID; a value reply is the model answering. Both
                                            // are legitimate and neither is a failure, but a
                                            // log that cannot tell them apart — or tell either
                                            // from the fail-closed genErr below — is useless
                                            // when something goes wrong.
                                            let model_rejected = serde_json::from_str::<
                                                serde_json::Value,
                                            >(
                                                json_str.trim()
                                            )
                                            .ok()
                                            .and_then(|v| v.get("error").and_then(|e| e.as_bool()))
                                            .unwrap_or(false);
                                            info!(
                                                "SNMP answering request {} from {} (decision={})",
                                                request_id,
                                                peer_addr,
                                                if model_rejected {
                                                    "model_reject"
                                                } else {
                                                    "model_answer"
                                                }
                                            );
                                            match Self::build_snmp_response(
                                                &json_str,
                                                &framing,
                                                request_id,
                                                &requested_oids_clone,
                                            ) {
                                                Ok(snmp_response) => {
                                                    if let Err(e) = socket_clone
                                                        .send_to(&snmp_response, peer_addr)
                                                        .await
                                                    {
                                                        error!(
                                                            "Failed to send SNMP response: {}",
                                                            e
                                                        );
                                                    } else {
                                                        // DEBUG: Log summary
                                                        debug!(
                                                            "SNMP sent {} bytes to {}",
                                                            snmp_response.len(),
                                                            peer_addr
                                                        );
                                                        let _ = status_clone.send(format!(
                                                            "[DEBUG] SNMP sent {} bytes to {}",
                                                            snmp_response.len(),
                                                            peer_addr
                                                        ));

                                                        // TRACE: Log full payload
                                                        let hex_dump: String = snmp_response
                                                            .iter()
                                                            .map(|b| format!("{:02X}", b))
                                                            .collect::<Vec<_>>()
                                                            .join(" ");
                                                        trace!("SNMP sent (hex): {}", hex_dump);
                                                        let _ = status_clone.send(format!(
                                                            "[TRACE] SNMP sent (hex): {}",
                                                            hex_dump
                                                        ));

                                                        let _ = status_clone.send(format!(
                                                            "→ SNMP response to {} ({} bytes)",
                                                            peer_addr,
                                                            snmp_response.len()
                                                        ));
                                                    }
                                                }
                                                Err(e) => {
                                                    error!(
                                                        "Failed to build SNMP BER response: {}",
                                                        e
                                                    );
                                                    let _ = status_clone.send(format!(
                                                        "✗ SNMP encoding error: {}",
                                                        e
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    // SNMP is UDP, but unlike bare UDP it carries a
                                    // request-id, so a reply is unambiguously *this*
                                    // request's answer and cannot be mistaken for anything
                                    // else. Silence would leave the manager retrying until
                                    // its own timeout and then reporting the agent as down -
                                    // which is not what happened.
                                    //
                                    // genErr(5) is the generic "the agent could not produce
                                    // this value" status. It is the only honest choice: the
                                    // alternative, a Response PDU with error-status 0, means
                                    // the varbinds *are* the answer, so an empty one would
                                    // read as "this OID has no value" rather than "nobody
                                    // looked". SNMP has no retryable error-status for a GET
                                    // (resourceUnavailable(13) is defined for SET), so the
                                    // overload distinction lives in the log rather than on
                                    // the wire.
                                    //
                                    // The wire therefore carries one code for both cases; the
                                    // `decision=` tag is what separates a backend outage from
                                    // the model's own `send_snmp_error`, which logs
                                    // `decision=model_reject` above and reaches the wire
                                    // through an entirely different path.
                                    let overloaded = crate::llm::is_overload_error(&e);
                                    let decision = if overloaded {
                                        "fail_closed_llm_overload"
                                    } else {
                                        "fail_closed_llm_error"
                                    };
                                    error!(
                                        "SNMP LLM call failed for request {} from {} (decision={}): {}",
                                        request_id, peer_addr, decision, e
                                    );
                                    let _ = status_clone.send(format!(
                                        "[ERROR] SNMP replying genErr to {} for request {} (decision={}): {}",
                                        peer_addr, request_id, decision, e
                                    ));
                                    match Self::build_response_message(
                                        &framing,
                                        request_id,
                                        SNMP_ERROR_GEN_ERR,
                                        0,
                                        vec![],
                                    ) {
                                        Ok(pdu) => {
                                            if let Err(send_err) =
                                                socket_clone.send_to(&pdu, peer_addr).await
                                            {
                                                error!(
                                                    "Failed to send SNMP genErr response to {}: {}",
                                                    peer_addr, send_err
                                                );
                                            }
                                        }
                                        Err(build_err) => {
                                            error!(
                                                "Failed to build SNMP genErr response for {}: {}",
                                                peer_addr, build_err
                                            );
                                            let _ = status_clone.send(format!(
                                                "[ERROR] SNMP could not encode genErr for {}: {}",
                                                peer_addr, build_err
                                            ));
                                        }
                                    }
                                }
                            }
                        }).await;
                    }
                    Err(e) => {
                        error!("SNMP receive error: {}", e);
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

    /// Ask the handler about a trap or inform; acknowledge an inform only if it says so.
    #[allow(clippy::too_many_arguments)]
    async fn handle_notification(
        received: notify::Received,
        peer_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        socket: Arc<UdpSocket>,
        protocol: Arc<SnmpProtocol>,
        server_id: crate::state::ServerId,
    ) {
        let mut data = received.data;
        data["client_ip"] = serde_json::json!(peer_addr.ip().to_string());
        let event = Event::new(&actions::SNMP_NOTIFICATION_EVENT, data);
        let acknowledged = match call_llm(
            &llm_client,
            &app_state,
            server_id,
            None,
            &event,
            protocol.as_ref(),
        )
        .await
        {
            Ok(result) => result.protocol_results.iter().any(|r| {
                matches!(r, ActionResult::Custom { name, .. } if name == "acknowledge_notification")
            }),
            Err(e) => {
                // Not acknowledging is the only safe failure: an inform's sender then retries.
                warn!(
                    "SNMP {} from {} decision=fail_closed_llm_error: {}",
                    received.kind, peer_addr, e
                );
                return;
            }
        };
        let Some(ack) = received.acknowledgement else {
            info!(
                "SNMP trap from {} decision={}",
                peer_addr,
                if acknowledged {
                    "model_accept"
                } else {
                    "model_ignore"
                }
            );
            return;
        };
        if !acknowledged {
            info!(
                "SNMP inform from {} decision=model_ignore: not acknowledged",
                peer_addr
            );
            return;
        }
        match socket.send_to(&ack, peer_addr).await {
            Ok(_) => {
                info!(
                    "SNMP inform from {} decision=model_accept: acknowledged",
                    peer_addr
                );
                let _ = status_tx.send(format!("[INFO] SNMP inform from {peer_addr} acknowledged"));
            }
            Err(e) => error!("SNMP inform acknowledgement to {} failed: {}", peer_addr, e),
        }
    }

    /// The request summary for an SNMPv3 request the USM has already accepted.
    fn describe_v3(request: &usm::Request) -> ParsedSnmpInfo {
        ParsedSnmpInfo {
            description: format!(
                "SNMPv3 {} from user {} ({})",
                Self::get_v2_pdu_type(&request.pdu),
                request.user,
                request.level.name()
            ),
            request_type: Self::get_v2_pdu_type(&request.pdu),
            version: 3,
            request_id: Self::get_v2_request_id(&request.pdu),
            community: Vec::new(),
            requested_oids: Self::get_v2_requested_oids(&request.pdu),
        }
    }

    /// A Response PDU (tag 0xA2) on its own, for the USM to wrap.
    fn build_response_pdu(
        request_id: i32,
        error_status: u8,
        error_index: u8,
        var_binds: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let mut list = vec![0x30];
        list.extend_from_slice(&Self::encode_length(
            var_binds.iter().map(|v| v.len()).sum(),
        ));
        for v in var_binds {
            list.extend_from_slice(&v);
        }
        let body = [
            Self::encode_integer(request_id),
            Self::encode_integer(error_status as i32),
            Self::encode_integer(error_index as i32),
            list,
        ]
        .concat();
        let mut pdu = vec![0xA2];
        pdu.extend_from_slice(&Self::encode_length(body.len()));
        pdu.extend_from_slice(&body);
        pdu
    }

    /// Parse SNMP message and extract relevant information
    pub fn parse_snmp_message(data: &[u8]) -> Result<ParsedSnmpInfo> {
        // Screen the TLV structure before rasn sees it. Its BER decoder recurses once per
        // level of constructed nesting with no bound, and a stack overflow is fatal to the
        // whole process rather than to this datagram. See `check_ber_structure`.
        if let Err(reason) = check_ber_structure(data, MAX_BER_DEPTH) {
            return Err(anyhow::anyhow!(
                "Rejected malformed SNMP message ({} bytes): {}",
                data.len(),
                reason
            ));
        }

        // Try to decode as SNMPv2c first (most common)
        if let Ok(msg) = ber::decode::<v2c::Message<v2::Pdus>>(data) {
            let request_type = Self::get_v2_pdu_type(&msg.data);
            let request_id = Self::get_v2_request_id(&msg.data);
            let requested_oids = Self::get_v2_requested_oids(&msg.data);
            return Ok(ParsedSnmpInfo {
                description: Self::format_v2c_message(&msg),
                request_type,
                version: 1, // v2c uses version 1 in the packet
                request_id,
                community: msg.community.to_vec(),
                requested_oids,
            });
        }

        // Try SNMPv1
        if let Ok(msg) = ber::decode::<v1::Message<v1::Pdus>>(data) {
            let request_type = Self::get_v1_pdu_type(&msg.data);
            let request_id = Self::get_v1_request_id(&msg.data);
            let requested_oids = Self::get_v1_requested_oids(&msg.data);
            return Ok(ParsedSnmpInfo {
                description: Self::format_v1_message(&msg),
                request_type,
                version: 0,
                request_id,
                community: msg.community.to_vec(),
                requested_oids,
            });
        }

        // If we can't parse it, return error
        Err(anyhow::anyhow!(
            "Failed to parse SNMP message: {} bytes",
            data.len()
        ))
    }

    /// Get request ID for v2
    fn get_v2_request_id(pdu: &v2::Pdus) -> i32 {
        match pdu {
            v2::Pdus::GetRequest(p) => p.0.request_id,
            v2::Pdus::GetNextRequest(p) => p.0.request_id,
            v2::Pdus::GetBulkRequest(p) => p.0.request_id,
            v2::Pdus::SetRequest(p) => p.0.request_id,
            v2::Pdus::Response(p) => p.0.request_id,
            v2::Pdus::InformRequest(p) => p.0.request_id,
            v2::Pdus::Trap(p) => p.0.request_id,
            v2::Pdus::Report(p) => p.0.request_id,
        }
    }

    /// Get requested OIDs for v2
    fn get_v2_requested_oids(pdu: &v2::Pdus) -> Vec<String> {
        let bindings = match pdu {
            v2::Pdus::GetRequest(p) => &p.0.variable_bindings,
            v2::Pdus::GetNextRequest(p) => &p.0.variable_bindings,
            v2::Pdus::GetBulkRequest(p) => &p.0.variable_bindings,
            v2::Pdus::SetRequest(p) => &p.0.variable_bindings,
            _ => return vec![],
        };

        bindings.iter().map(|vb| vb.name.to_string()).collect()
    }

    /// Get request ID for v1
    fn get_v1_request_id(pdu: &v1::Pdus) -> i32 {
        let integer = match pdu {
            v1::Pdus::GetRequest(p) => &p.0.request_id,
            v1::Pdus::GetNextRequest(p) => &p.0.request_id,
            v1::Pdus::GetResponse(p) => &p.0.request_id,
            v1::Pdus::SetRequest(p) => &p.0.request_id,
            _ => return 0,
        };

        // Convert Integer to i32
        match integer {
            Integer::Primitive(val) => *val as i32,
            Integer::Variable(big) => {
                // Try to convert BigInt to i32, default to 0 if out of range
                big.to_string().parse::<i32>().unwrap_or(0)
            }
        }
    }

    /// Get requested OIDs for v1
    fn get_v1_requested_oids(pdu: &v1::Pdus) -> Vec<String> {
        let bindings = match pdu {
            v1::Pdus::GetRequest(p) => &p.0.variable_bindings,
            v1::Pdus::GetNextRequest(p) => &p.0.variable_bindings,
            v1::Pdus::SetRequest(p) => &p.0.variable_bindings,
            _ => return vec![],
        };

        bindings.iter().map(|vb| vb.name.to_string()).collect()
    }

    /// Get PDU type for v2
    fn get_v2_pdu_type(pdu: &v2::Pdus) -> String {
        match pdu {
            v2::Pdus::GetRequest(_) => "GetRequest",
            v2::Pdus::GetNextRequest(_) => "GetNextRequest",
            v2::Pdus::GetBulkRequest(_) => "GetBulkRequest",
            v2::Pdus::SetRequest(_) => "SetRequest",
            v2::Pdus::Response(_) => "Response",
            v2::Pdus::InformRequest(_) => "InformRequest",
            v2::Pdus::Trap(_) => "Trap",
            v2::Pdus::Report(_) => "Report",
        }
        .to_string()
    }

    /// Get PDU type for v1
    fn get_v1_pdu_type(pdu: &v1::Pdus) -> String {
        match pdu {
            v1::Pdus::GetRequest(_) => "GetRequest",
            v1::Pdus::GetNextRequest(_) => "GetNextRequest",
            v1::Pdus::GetResponse(_) => "GetResponse",
            v1::Pdus::SetRequest(_) => "SetRequest",
            v1::Pdus::Trap(_) => "Trap",
        }
        .to_string()
    }

    /// Format SNMPv2c message with OIDs
    fn format_v2c_message(msg: &v2c::Message<v2::Pdus>) -> String {
        let mut info = "SNMPv2c Message:\n".to_string();
        info.push_str(&format!(
            "  Community: {}\n",
            String::from_utf8_lossy(&msg.community)
        ));

        match &msg.data {
            v2::Pdus::GetRequest(pdu) => {
                info.push_str("  Type: GetRequest\n");
                info.push_str(&format!("  Request ID: {}\n", pdu.0.request_id));
                info.push_str(&Self::format_v2_var_binds(&pdu.0.variable_bindings));
            }
            v2::Pdus::GetNextRequest(pdu) => {
                info.push_str("  Type: GetNextRequest\n");
                info.push_str(&format!("  Request ID: {}\n", pdu.0.request_id));
                info.push_str(&Self::format_v2_var_binds(&pdu.0.variable_bindings));
            }
            v2::Pdus::GetBulkRequest(pdu) => {
                info.push_str("  Type: GetBulkRequest\n");
                info.push_str(&format!("  Request ID: {}\n", pdu.0.request_id));
                info.push_str(&format!("  Non-repeaters: {}\n", pdu.0.non_repeaters));
                info.push_str(&format!("  Max-repetitions: {}\n", pdu.0.max_repetitions));
                info.push_str(&Self::format_v2_var_binds(&pdu.0.variable_bindings));
            }
            _ => {
                info.push_str(&format!("  Type: {}\n", Self::get_v2_pdu_type(&msg.data)));
            }
        }

        info
    }

    /// Format SNMPv1 message with OIDs
    fn format_v1_message(msg: &v1::Message<v1::Pdus>) -> String {
        let mut info = "SNMPv1 Message:\n".to_string();
        info.push_str(&format!(
            "  Community: {}\n",
            String::from_utf8_lossy(&msg.community)
        ));

        match &msg.data {
            v1::Pdus::GetRequest(pdu) => {
                info.push_str("  Type: GetRequest\n");
                info.push_str(&format!("  Request ID: {}\n", pdu.0.request_id));
                info.push_str(&Self::format_v1_var_binds(&pdu.0.variable_bindings));
            }
            v1::Pdus::GetNextRequest(pdu) => {
                info.push_str("  Type: GetNextRequest\n");
                info.push_str(&format!("  Request ID: {}\n", pdu.0.request_id));
                info.push_str(&Self::format_v1_var_binds(&pdu.0.variable_bindings));
            }
            _ => {
                info.push_str(&format!("  Type: {}\n", Self::get_v1_pdu_type(&msg.data)));
            }
        }

        info
    }

    /// Format v2 variable bindings
    fn format_v2_var_binds(bindings: &[v2::VarBind]) -> String {
        let mut result = String::from("  Requested OIDs:\n");
        if bindings.is_empty() {
            result.push_str("    (none - requesting all)\n");
        } else {
            for (i, bind) in bindings.iter().enumerate() {
                result.push_str(&format!("    [{}] {}\n", i + 1, bind.name));
            }
        }
        result
    }

    /// Format v1 variable bindings
    fn format_v1_var_binds(bindings: &[v1::VarBind]) -> String {
        let mut result = String::from("  Requested OIDs:\n");
        if bindings.is_empty() {
            result.push_str("    (none - requesting all)\n");
        } else {
            for (i, bind) in bindings.iter().enumerate() {
                result.push_str(&format!("    [{}] {}\n", i + 1, bind.name));
            }
        }
        result
    }

    /// Build SNMP response from LLM output using manual BER encoding
    pub fn build_snmp_response(
        llm_response: &str,
        framing: &Framing,
        request_id: i32,
        requested_oids: &[String],
    ) -> Result<Vec<u8>> {
        let trimmed = llm_response.trim();

        // Try to parse as JSON first
        if let Ok(response_data) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if !response_data.is_object() {
                // Not an object, fall through to plain text handling
            } else if response_data.get("variables").is_some()
                || response_data.get("error").is_some()
            {
                // SNMP-specific format with variables
                // Check for error
                if response_data["error"].as_bool().unwrap_or(false) {
                    let error_msg = response_data["error_message"]
                        .as_str()
                        .unwrap_or("Unknown error");
                    // SNMP carries the reason as a numeric error-status; the text is for
                    // our logs only, since the wire format has nowhere to put it.
                    let error_status = response_data["error_status"].as_u64().unwrap_or(5) as u8;
                    let error_index = response_data["error_index"].as_u64().unwrap_or(0) as u8;
                    debug!(
                        "LLM reported SNMP error status {}: {}",
                        error_status, error_msg
                    );
                    return Self::build_response_message(
                        framing,
                        request_id,
                        error_status,
                        error_index,
                        vec![],
                    );
                }

                // Build response with variable bindings
                let mut var_binds = Vec::new();

                if let Some(variables) = response_data["variables"].as_array() {
                    for var in variables {
                        let oid_str = var["oid"].as_str().unwrap_or("");
                        let value_type = var["type"].as_str().unwrap_or("null");
                        let value = &var["value"];

                        // DEBUG: Log the actual value being returned
                        let value_str = match value_type {
                            "string" => format!("\"{}\"", value.as_str().unwrap_or("")),
                            "integer" => format!("{}", value.as_i64().unwrap_or(0)),
                            "counter" | "gauge" | "timeticks" => {
                                format!("{}", value.as_u64().unwrap_or(0))
                            }
                            "null" | _ => "null".to_string(),
                        };
                        debug!(
                            "SNMP response: {} = {} ({})",
                            oid_str, value_str, value_type
                        );

                        // Encode each variable binding
                        let var_bind = Self::encode_var_bind(oid_str, value_type, value)?;
                        var_binds.push(var_bind);
                    }
                }

                // Build the complete SNMP response message
                return Self::build_response_message(framing, request_id, 0, 0, var_binds);
            } else if let Some(output) = response_data.get("output") {
                // Standard LlmResponse format - extract output field and process as text
                if let Some(output_str) = output.as_str() {
                    debug!(
                        "LLM returned LlmResponse format, using 'output' field: {}",
                        output_str
                    );

                    // Use the first requested OID
                    let oid = requested_oids
                        .first()
                        .map(|s| s.as_str())
                        .unwrap_or("1.3.6.1.2.1.1.1.0");

                    // Try to parse as integer first
                    let var_bind = if let Ok(num) = output_str.trim().parse::<i32>() {
                        debug!("SNMP response: {} = {} (integer)", oid, num);
                        Self::encode_var_bind(oid, "integer", &serde_json::Value::from(num))?
                    } else {
                        // Treat as string
                        debug!("SNMP response: {} = \"{}\" (string)", oid, output_str);
                        Self::encode_var_bind(oid, "string", &serde_json::Value::from(output_str))?
                    };

                    return Self::build_response_message(framing, request_id, 0, 0, vec![var_bind]);
                }
                // If output is null or not a string, fall through to plain text handling
            }
            // If JSON parsed but not recognized format, fall through to plain text handling
        }

        // Fallback: treat as plain text value
        // Use the first requested OID if available, otherwise use a default
        let oid = requested_oids
            .first()
            .map(|s| s.as_str())
            .unwrap_or("1.3.6.1.2.1.1.1.0");

        debug!(
            "LLM returned plain text (not JSON), treating as simple value for OID {}: {}",
            oid, trimmed
        );

        // Try to parse as integer first
        let var_bind = if let Ok(num) = trimmed.parse::<i32>() {
            debug!("SNMP response: {} = {} (integer)", oid, num);
            Self::encode_var_bind(oid, "integer", &serde_json::Value::from(num))?
        } else {
            // Treat as string
            debug!("SNMP response: {} = \"{}\" (string)", oid, trimmed);
            Self::encode_var_bind(oid, "string", &serde_json::Value::from(trimmed))?
        };

        Self::build_response_message(framing, request_id, 0, 0, vec![var_bind])
    }

    /// Encode a BER definite length.
    ///
    /// Short form for < 128, then one, two or three length bytes. The previous code only
    /// handled the short form and `0x81` with a `len as u8`, so any value 256 bytes or
    /// longer - a long sysDescr, or simply a response with several variable bindings -
    /// silently wrapped to a wrong length and produced a packet the client rejected.
    fn encode_length(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len <= 0xFF {
            vec![0x81, len as u8]
        } else if len <= 0xFFFF {
            vec![0x82, (len >> 8) as u8, len as u8]
        } else {
            vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
        }
    }

    /// Encode a single variable binding
    fn encode_var_bind(
        oid_str: &str,
        value_type: &str,
        value: &serde_json::Value,
    ) -> Result<Vec<u8>> {
        let mut result = Vec::new();

        // Encode OID
        let oid_bytes = Self::encode_oid(oid_str)?;

        // Encode value based on type
        let value_bytes = match value_type {
            "string" => {
                let s = value.as_str().unwrap_or("");
                Self::encode_octet_string(s.as_bytes())
            }
            "integer" => {
                let n = value.as_i64().unwrap_or(0) as i32;
                Self::encode_integer(n)
            }
            "counter" => {
                let n = value.as_u64().unwrap_or(0) as u32;
                Self::encode_counter(n)
            }
            "gauge" => {
                let n = value.as_u64().unwrap_or(0) as u32;
                Self::encode_gauge(n)
            }
            "timeticks" => {
                let n = value.as_u64().unwrap_or(0) as u32;
                Self::encode_timeticks(n)
            }
            "null" | _ => {
                vec![0x05, 0x00] // NULL
            }
        };

        // Construct SEQUENCE for variable binding
        result.push(0x30); // SEQUENCE tag
        let len = oid_bytes.len() + value_bytes.len();
        result.extend_from_slice(&Self::encode_length(len));
        result.extend_from_slice(&oid_bytes);
        result.extend_from_slice(&value_bytes);

        Ok(result)
    }

    /// Encode OID
    fn encode_oid(oid_str: &str) -> Result<Vec<u8>> {
        // Every component must be a number. Skipping unparseable ones (the previous
        // behaviour) turned a typo into a different, silently wrong OID.
        let mut parts: Vec<u32> = Vec::new();
        for component in oid_str.split('.').filter(|s| !s.is_empty()) {
            parts.push(component.parse().map_err(|_| {
                anyhow::anyhow!(
                    "Invalid OID {oid_str:?}: component {component:?} is not a number. \
                     Use dotted decimal, e.g. \"1.3.6.1.2.1.1.1.0\""
                )
            })?);
        }

        if parts.len() < 2 {
            return Err(anyhow::anyhow!(
                "Invalid OID {oid_str:?}: at least two components are required, \
                 e.g. \"1.3.6.1.2.1.1.1.0\""
            ));
        }

        // First arc is 0, 1 or 2; the second is below 40 unless the first is 2.
        if parts[0] > 2 {
            return Err(anyhow::anyhow!(
                "Invalid OID {oid_str:?}: the first component must be 0, 1 or 2, got {}",
                parts[0]
            ));
        }
        if parts[0] < 2 && parts[1] >= 40 {
            return Err(anyhow::anyhow!(
                "Invalid OID {oid_str:?}: with a first component of {}, the second must be \
                 below 40, got {}",
                parts[0],
                parts[1]
            ));
        }

        let mut encoded = Vec::new();

        // First two components share one base-128 value: first * 40 + second.
        let first_arc = parts[0] * 40 + parts[1];
        Self::push_base128(&mut encoded, first_arc);

        // Encode remaining components
        for &part in &parts[2..] {
            Self::push_base128(&mut encoded, part);
        }

        // Wrap with OID tag
        let mut result = vec![0x06]; // OBJECT IDENTIFIER tag
        result.extend_from_slice(&Self::encode_length(encoded.len()));
        result.extend_from_slice(&encoded);

        Ok(result)
    }

    /// Append one OID sub-identifier in base-128, high bit set on all but the last byte.
    fn push_base128(out: &mut Vec<u8>, value: u32) {
        if value < 128 {
            out.push(value as u8);
            return;
        }

        let mut bytes = Vec::new();
        let mut val = value;
        while val > 0 {
            bytes.push((val & 0x7F) as u8);
            val >>= 7;
        }
        bytes.reverse();

        let last = bytes.len() - 1;
        for (i, &byte) in bytes.iter().enumerate() {
            if i < last {
                out.push(byte | 0x80);
            } else {
                out.push(byte);
            }
        }
    }

    /// Encode integer
    fn encode_integer(value: i32) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let mut result = vec![0x02]; // INTEGER tag

        // Skip leading zeros/ones for minimal encoding
        let mut start = 0;
        if value >= 0 {
            while start < 3 && bytes[start] == 0 && (bytes[start + 1] & 0x80) == 0 {
                start += 1;
            }
        } else {
            while start < 3 && bytes[start] == 0xFF && (bytes[start + 1] & 0x80) != 0 {
                start += 1;
            }
        }

        let len = 4 - start;
        result.push(len as u8);
        result.extend_from_slice(&bytes[start..]);

        result
    }

    /// Encode octet string
    fn encode_octet_string(value: &[u8]) -> Vec<u8> {
        let mut result = vec![0x04]; // OCTET STRING tag
        result.extend_from_slice(&Self::encode_length(value.len()));
        result.extend_from_slice(value);
        result
    }

    /// Encode counter (application tag 1)
    fn encode_counter(value: u32) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let mut result = vec![0x41]; // Counter tag (application class, tag 1)

        // Skip leading zeros
        let mut start = 0;
        while start < 3 && bytes[start] == 0 {
            start += 1;
        }

        let len = 4 - start;
        result.push(len as u8);
        result.extend_from_slice(&bytes[start..]);

        result
    }

    /// Encode gauge (application tag 2)
    fn encode_gauge(value: u32) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let mut result = vec![0x42]; // Gauge tag (application class, tag 2)

        // Skip leading zeros
        let mut start = 0;
        while start < 3 && bytes[start] == 0 {
            start += 1;
        }

        let len = 4 - start;
        result.push(len as u8);
        result.extend_from_slice(&bytes[start..]);

        result
    }

    /// Encode timeticks (application tag 3)
    fn encode_timeticks(value: u32) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let mut result = vec![0x43]; // TimeTicks tag (application class, tag 3)

        // Skip leading zeros
        let mut start = 0;
        while start < 3 && bytes[start] == 0 {
            start += 1;
        }

        let len = 4 - start;
        result.push(len as u8);
        result.extend_from_slice(&bytes[start..]);

        result
    }

    /// Build complete SNMP response message
    fn build_response_message(
        framing: &Framing,
        request_id: i32,
        error_status: u8,
        error_index: u8,
        var_binds: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let (version, community) = match framing {
            Framing::Community { version, community } => (*version, community.as_slice()),
            Framing::Usm { agent, request } => {
                let pdu =
                    Self::build_response_pdu(request_id, error_status, error_index, var_binds);
                let pdus: v2::Pdus = ber::decode(&pdu)
                    .map_err(|e| anyhow::anyhow!("response PDU does not decode: {e}"))?;
                let message = agent.respond(request, pdus)?;
                // RFC 3416 §4.2.1: an answer larger than the manager can take is tooBig, with
                // no variable bindings.
                if message.len() as i64 > request.max_size {
                    let pdu = Self::build_response_pdu(request_id, SNMP_ERROR_TOO_BIG, 0, vec![]);
                    let pdus: v2::Pdus = ber::decode(&pdu)
                        .map_err(|e| anyhow::anyhow!("tooBig PDU does not decode: {e}"))?;
                    return agent.respond(request, pdus);
                }
                return Ok(message);
            }
        };
        let mut message = Vec::new();

        // Encode version
        let version_bytes = Self::encode_integer(version as i32);

        // Encode community
        let community_bytes = Self::encode_octet_string(community);

        // Build GetResponse PDU (tag 0xA2)
        let mut pdu = vec![0xA2]; // GetResponse tag (context-specific, constructed, tag 2)

        // Encode request ID
        let request_id_bytes = Self::encode_integer(request_id);

        // Encode error status
        let error_status_bytes = Self::encode_integer(error_status as i32);

        // Encode error index
        let error_index_bytes = Self::encode_integer(error_index as i32);

        // Encode variable bindings list
        let mut var_binds_list = vec![0x30]; // SEQUENCE tag
        let var_binds_total_len: usize = var_binds.iter().map(|v| v.len()).sum();
        var_binds_list.extend_from_slice(&Self::encode_length(var_binds_total_len));

        for var_bind in var_binds {
            var_binds_list.extend_from_slice(&var_bind);
        }

        // Calculate PDU length
        let pdu_len = request_id_bytes.len()
            + error_status_bytes.len()
            + error_index_bytes.len()
            + var_binds_list.len();
        pdu.extend_from_slice(&Self::encode_length(pdu_len));

        pdu.extend_from_slice(&request_id_bytes);
        pdu.extend_from_slice(&error_status_bytes);
        pdu.extend_from_slice(&error_index_bytes);
        pdu.extend_from_slice(&var_binds_list);

        // Build complete message
        message.push(0x30); // SEQUENCE tag
        let message_len = version_bytes.len() + community_bytes.len() + pdu.len();
        message.extend_from_slice(&Self::encode_length(message_len));

        message.extend_from_slice(&version_bytes);
        message.extend_from_slice(&community_bytes);
        message.extend_from_slice(&pdu);

        Ok(message)
    }
}

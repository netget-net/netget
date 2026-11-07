//! ICMP (Internet Control Message Protocol) client implementation
//!
//! This module provides functionality to send ICMP messages and receive responses.
//! It uses raw IP sockets via socket2 and pnet for ICMP packet handling.

pub mod actions;

use anyhow::{Context, Result};
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
// Note: pnet doesn't provide timestamp_reply packet types
use crate::logging::emit::Log;
use crate::utils::clock::Instant;
use pnet::packet::icmp::{destination_unreachable::DestinationUnreachablePacket, IcmpPacket};
use pnet::packet::icmp::{IcmpCode, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error};

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
// Imported anonymously: `socket2::Protocol` already owns the name here, and only the
// trait's methods (`protocol_name`) are needed.
use crate::llm::actions::protocol_trait::Protocol as _;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};
use crate::{console_debug, console_info};

pub use actions::IcmpClientProtocol;
use actions::{
    ICMP_CLIENT_CONNECTED_EVENT, ICMP_DEST_UNREACHABLE_EVENT, ICMP_ECHO_REPLY_EVENT,
    ICMP_TIME_EXCEEDED_EVENT,
};

/// Per-client data for LLM handling.
///
/// Deliberately just the memory. There used to be a `ConnectionState`
/// (`Idle`/`Processing`/`Accumulating`) here, copied from the connection-oriented servers and
/// carrying `#[allow(dead_code)]` on two of its three variants: it was written once at
/// construction and never read or transitioned, while this client's own CLAUDE.md described it
/// as the thing that "prevents concurrent LLM calls on same client". Nothing prevented
/// anything. It is gone rather than wired up, because the mechanism that actually serialises
/// this client is its single receive loop awaiting each `call_llm_for_client` inline.
struct ClientData {
    memory: String,
}

/// ICMP client that sends requests and receives responses
pub struct IcmpClient;

/// Pending ICMP request tracking
#[derive(Clone)]
struct PendingRequest {
    sent_at: Instant,
    identifier: u16,
    sequence: u16,
    destination_ip: Ipv4Addr,
}

/// How long a request waits for its reply before `icmp_timeout` is raised.
const ICMP_REPLY_TIMEOUT_SECS: u64 = 5;

/// Largest payload that still fits an ICMP message inside one unfragmented IPv4 datagram:
/// 65535 total, less the 20-byte IPv4 header and the 8-byte ICMP header.
const MAX_ICMP_PAYLOAD: usize = 65535 - 20 - 8;

impl IcmpClient {
    /// Connect ICMP client with LLM action handling
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // Parse target IP from remote_addr
        let target_ip: Ipv4Addr = remote_addr
            .split(':')
            .next()
            .context("Invalid remote address format")?
            .parse()
            .context("Invalid IPv4 address")?;

        console_info!(status_tx, "ICMP client connecting to {}", target_ip);

        // Create raw ICMP socket
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .context("Failed to create raw ICMP socket (need root/CAP_NET_RAW)")?;

        // `build_echo_request` produces a *complete* IPv4 packet, header included. Without
        // IP_HDRINCL the kernel prepends a header of its own and our 20 bytes become the first
        // 20 bytes of the ICMP message, so the target sees ICMP type 0x45 (69, unassigned) and
        // no ping this client sent could ever have been answered. It is also what makes the
        // advertised `ttl` parameter mean anything: without the option the kernel picks the TTL
        // and traceroute is impossible.
        socket
            .set_header_included_v4(true)
            .context("Failed to set IP_HDRINCL on the raw ICMP socket")?;

        // Set socket to non-blocking
        socket
            .set_nonblocking(true)
            .context("Failed to set socket non-blocking")?;

        let local_addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

        // Shared state for pending requests
        let pending_requests: Arc<Mutex<HashMap<(u16, u16), PendingRequest>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            memory: String::new(),
        }));

        let socket = Arc::new(socket);
        let protocol = Arc::new(IcmpClientProtocol::new());

        // Command channel for injected actions (the dashboard's [ send ]). Registered, and
        // drained by a live task, BEFORE the connected-event LLM call below: that call is
        // awaited inline here, so a manual `*` routing rule parks it - and the whole point
        // of the channel is that the operator can still reach the client while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        // Filled in once the receive loop exists (it is spawned after the connected-event
        // call), so an injected `disconnect` can actually stop it and release the socket.
        let read_abort: Arc<std::sync::OnceLock<tokio::task::AbortHandle>> =
            Arc::new(std::sync::OnceLock::new());
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            protocol.clone(),
            socket.clone(),
            pending_requests.clone(),
            target_ip,
            client_id,
            app_state.clone(),
            status_tx.clone(),
            read_abort.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &ICMP_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "local_addr": local_addr.to_string(),
                    "target_ip": target_ip.to_string(),
                }),
            );

            // Copy the memory out and drop the guard *before* the call. A
            // `client_data.lock().await.memory` written inline in the scrutinee keeps its
            // temporary guard alive for the whole `match`, so the `Ok` arm below - which locks
            // again to store `memory_updates` - waited on a lock only it could release.
            // `tokio::sync::Mutex` is not reentrant: that is a permanent hang, and it fired on
            // every successful call that returned memory.
            let memory_snapshot = client_data.lock().await.memory.clone();

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &memory_snapshot,
                Some(&event),
                protocol.as_ref(),
                &status_tx,
            )
            .await
            {
                Ok(result) => {
                    // Update memory if provided
                    if let Some(new_memory) = result.memory_updates {
                        client_data.lock().await.memory = new_memory;
                    }

                    // Execute initial actions
                    if let Err(e) = Self::execute_actions(
                        result.actions,
                        &socket,
                        &pending_requests,
                        target_ip,
                        &status_tx,
                        protocol.as_ref(),
                    )
                    .await
                    {
                        // Early return: drop the command handle so the dashboard does not
                        // offer [ send ] into a client that never started.
                        app_state.remove_client_handle(client_id).await;
                        return Err(e);
                    }
                }
                Err(e) => {
                    // ICMP defines no way to tell a peer "I cannot answer" - see the server's
                    // CLAUDE.md - so nothing goes on the wire and the log carries the decision.
                    error!(
                        "ICMP client {} decision=fail_closed_llm_error on icmp_connected                          (nothing sent): {}",
                        client_id, e
                    );
                }
            }
        }

        // An injected `disconnect` that arrived while the connected-event call was parked
        // has already dropped the command handle. Honour it rather than starting a receive
        // loop the operator just asked to stop.
        if !app_state.has_client_handle(client_id).await {
            return Ok(local_addr);
        }

        // Spawn receive loop
        let socket_clone = socket.clone();
        let llm_clone = llm_client.clone();
        let state_clone = app_state.clone();
        let status_clone = status_tx.clone();
        let protocol_clone = protocol.clone();
        let pending_clone = pending_requests.clone();
        let client_data_clone = client_data.clone();

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let mut buffer = vec![std::mem::MaybeUninit::uninit(); 65535];

            loop {
                // Try to receive packet (non-blocking)
                match socket_clone.recv_from(&mut buffer) {
                    Ok((n, _src_addr)) => {
                        let data = unsafe {
                            std::slice::from_raw_parts(buffer.as_ptr() as *const u8, n).to_vec()
                        };

                        // Parse IP packet
                        let ip_packet = match Ipv4Packet::new(&data) {
                            Some(p) => p,
                            None => continue,
                        };

                        // Check if it's ICMP
                        if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
                            continue;
                        }

                        // Parse ICMP packet
                        let icmp_packet = match IcmpPacket::new(ip_packet.payload()) {
                            Some(p) => p,
                            None => continue,
                        };

                        let source_ip = ip_packet.get_source();
                        let ttl = ip_packet.get_ttl();
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_payload = icmp_packet.payload();

                        console_debug!(
                            status_clone,
                            "ICMP client received {} from {}",
                            icmp_type_to_string(icmp_type),
                            source_ip
                        );

                        // Process based on ICMP type
                        let event_opt = match icmp_type {
                            IcmpTypes::EchoReply => {
                                if let Some(echo_reply) = EchoReplyPacket::new(icmp_payload) {
                                    let identifier = echo_reply.get_identifier();
                                    let sequence = echo_reply.get_sequence_number();
                                    let payload_hex = hex::encode(echo_reply.payload());

                                    // Calculate RTT
                                    let rtt_ms = {
                                        let mut pending = pending_clone.lock().await;
                                        if let Some(req) = pending.remove(&(identifier, sequence)) {
                                            req.sent_at.elapsed().as_millis() as u64
                                        } else {
                                            0
                                        }
                                    };

                                    Some(Event::new(
                                        &ICMP_ECHO_REPLY_EVENT,
                                        serde_json::json!({
                                            "source_ip": source_ip.to_string(),
                                            "identifier": identifier,
                                            "sequence": sequence,
                                            "rtt_ms": rtt_ms,
                                            "ttl": ttl,
                                            "payload_hex": payload_hex,
                                        }),
                                    ))
                                } else {
                                    None
                                }
                            }
                            IcmpTypes::DestinationUnreachable => {
                                if let Some(dest_unreach) =
                                    DestinationUnreachablePacket::new(icmp_payload)
                                {
                                    let code = dest_unreach.get_icmp_code().0;
                                    Some(Event::new(
                                        &ICMP_DEST_UNREACHABLE_EVENT,
                                        serde_json::json!({
                                            "source_ip": source_ip.to_string(),
                                            "code": code,
                                        }),
                                    ))
                                } else {
                                    None
                                }
                            }
                            IcmpTypes::TimeExceeded => {
                                if let Some(time_exceeded) = TimeExceededPacket::new(icmp_payload) {
                                    let code = time_exceeded.get_icmp_code().0;
                                    Some(Event::new(
                                        &ICMP_TIME_EXCEEDED_EVENT,
                                        serde_json::json!({
                                            "source_ip": source_ip.to_string(),
                                            "code": code,
                                        }),
                                    ))
                                } else {
                                    None
                                }
                            }
                            /* TODO: Timestamp support requires pnet to add timestamp_reply packet types
                            IcmpTypes::TimestampReply => {
                                if let Some(_ts_reply) = TimestampReplyPacket::new(icmp_payload) {
                                    // Could add timestamp reply event here
                                    None
                                } else {
                                    None
                                }
                            }
                            */
                            _ => None,
                        };

                        if let Some(event) = event_opt {
                            // Get instruction for LLM call
                            if let Some(instruction) =
                                state_clone.get_instruction_for_client(client_id).await
                            {
                                // Snapshot the memory and release the lock before the call -
                                // holding the guard in the scrutinee deadlocks the `Ok` arm
                                // below. See the connected-event path.
                                let memory_snapshot = client_data_clone.lock().await.memory.clone();

                                // Call LLM
                                match call_llm_for_client(
                                    &llm_clone,
                                    &state_clone,
                                    client_id.to_string(),
                                    &instruction,
                                    &memory_snapshot,
                                    Some(&event),
                                    protocol_clone.as_ref(),
                                    &status_clone,
                                )
                                .await
                                {
                                    Ok(result) => {
                                        // Update memory if provided
                                        if let Some(new_memory) = result.memory_updates {
                                            client_data_clone.lock().await.memory = new_memory;
                                        }

                                        // Execute actions
                                        if let Err(e) = Self::execute_actions(
                                            result.actions,
                                            &socket_clone,
                                            &pending_clone,
                                            target_ip,
                                            &status_clone,
                                            protocol_clone.as_ref(),
                                        )
                                        .await
                                        {
                                            error!("Failed to execute ICMP action: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            "ICMP client {} decision=fail_closed_llm_error on                                              {} (nothing sent): {}",
                                            client_id,
                                            event.event_type.id,
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No data available. Sweep for requests that will never be
                        // answered before sleeping.
                        //
                        // `icmp_timeout` is advertised in get_event_types(), so the model
                        // can be told it exists and write a handler for it -- and nothing
                        // raised it, so that handler waited forever. PendingRequest has
                        // carried `sent_at`, `identifier`, `sequence` and
                        // `destination_ip` for exactly this all along, every one of them
                        // marked #[allow(dead_code)]: the event was designed and never
                        // wired up. A ping that gets no reply IS the interesting result
                        // for a reachability check, and it was the one outcome the model
                        // was never told about.
                        let expired: Vec<PendingRequest> = {
                            let mut pending = pending_clone.lock().await;
                            let now = Instant::now();
                            let stale: Vec<(u16, u16)> = pending
                                .iter()
                                .filter(|(_, r)| {
                                    now.duration_since(r.sent_at)
                                        > std::time::Duration::from_secs(ICMP_REPLY_TIMEOUT_SECS)
                                })
                                .map(|(k, _)| *k)
                                .collect();
                            stale.iter().filter_map(|k| pending.remove(k)).collect()
                        };
                        for req in expired {
                            tracing::info!(
                                "ICMP client {} request to {} (id {}, seq {}) timed out",
                                client_id,
                                req.destination_ip,
                                req.identifier,
                                req.sequence
                            );
                            if let Some(instruction) =
                                state_clone.get_instruction_for_client(client_id).await
                            {
                                let event = Event::new(
                                    &crate::client::icmp::actions::ICMP_TIMEOUT_EVENT,
                                    serde_json::json!({
                                        "destination_ip": req.destination_ip.to_string(),
                                        "identifier": req.identifier,
                                        "sequence": req.sequence,
                                        "waited_ms": req.sent_at.elapsed().as_millis() as u64,
                                    }),
                                );
                                // Same guard-in-the-scrutinee deadlock as the two calls
                                // above: the `.clone()` copied the string but did nothing about
                                // the lock, which stayed held for the whole `match`.
                                let memory_snapshot = client_data_clone.lock().await.memory.clone();

                                match call_llm_for_client(
                                    &llm_clone,
                                    &state_clone,
                                    client_id.to_string(),
                                    &instruction,
                                    &memory_snapshot,
                                    Some(&event),
                                    protocol_clone.as_ref(),
                                    &status_clone,
                                )
                                .await
                                {
                                    Ok(result) => {
                                        if let Some(new_memory) = result.memory_updates {
                                            client_data_clone.lock().await.memory = new_memory;
                                        }
                                        if let Err(e) = Self::execute_actions(
                                            result.actions,
                                            &socket_clone,
                                            &pending_clone,
                                            target_ip,
                                            &status_clone,
                                            protocol_clone.as_ref(),
                                        )
                                        .await
                                        {
                                            error!(
                                                "ICMP client {} timeout action failed: {}",
                                                client_id, e
                                            );
                                        }
                                    }
                                    Err(e) => error!(
                                        "ICMP client {} decision=fail_closed_llm_error on \
                                         icmp_timeout (nothing sent): {}",
                                        client_id, e
                                    ),
                                }
                            }
                        }
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                        continue;
                    }
                    Err(e) => {
                        error!("ICMP receive error: {}", e);
                        break;
                    }
                }
            }
            // Every exit path lands here: drop the command handle so the dashboard stops
            // offering [ send ] on a dead client, and a late send fails fast.
            state_clone.remove_client_handle(client_id).await;
            let _ = status_clone.send("__UPDATE_UI__".to_string());
        });
        let _ = read_abort.set(task_handle.abort_handle());
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }

    /// Drain injected commands until the channel closes (client removed) or an injected
    /// `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot serve this client:
    /// `send_echo_request` yields `ClientActionResult::Custom` and the transport is a raw
    /// `socket2::Socket`, not an `AsyncWrite`. The action goes through [`Self::apply_action`]
    /// - the same function the connected-event path and the receive loop use.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: tokio::sync::mpsc::Receiver<ClientCommand>,
        protocol: Arc<IcmpClientProtocol>,
        socket: Arc<Socket>,
        pending_requests: Arc<Mutex<HashMap<(u16, u16), PendingRequest>>>,
        target_ip: Ipv4Addr,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        read_abort: Arc<std::sync::OnceLock<tokio::task::AbortHandle>>,
    ) {
        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => {
                    Self::apply_action(result, &socket, &pending_requests, target_ip, &status_tx)
                        .await
                        .map(|applied| match applied {
                            Applied::Disconnect => ClientSendOutcome::Disconnected,
                            Applied::Sent(0) => ClientSendOutcome::Executed {
                                detail: "executed (no packet sent)".to_string(),
                            },
                            Applied::Sent(bytes_sent) => ClientSendOutcome::Sent { bytes_sent },
                            Applied::Nothing(detail) => ClientSendOutcome::Executed { detail },
                        })
                }
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
                    "ICMP client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                // ICMP is connectionless, so "disconnected" means: stop receiving, release
                // the raw socket, drop the handle so [ send ] is greyed out again.
                if let Some(abort) = read_abort.get() {
                    abort.abort();
                }
                app_state.remove_client_handle(client_id).await;
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }
        }
    }

    /// Execute actions from LLM
    async fn execute_actions(
        actions: Vec<serde_json::Value>,
        socket: &Arc<Socket>,
        pending_requests: &Arc<Mutex<HashMap<(u16, u16), PendingRequest>>>,
        target_ip: Ipv4Addr,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &IcmpClientProtocol,
    ) -> Result<()> {
        for action in actions {
            let result = protocol.execute_action(action)?;
            if matches!(
                Self::apply_action(result, socket, pending_requests, target_ip, status_tx).await?,
                Applied::Disconnect
            ) {
                debug!("ICMP client disconnect requested");
                break;
            }
        }

        Ok(())
    }

    /// Apply one executed action. Shared by the connected-event path, the receive loop and
    /// injected commands so the echo-request encoding exists exactly once.
    async fn apply_action(
        result: ClientActionResult,
        socket: &Arc<Socket>,
        pending_requests: &Arc<Mutex<HashMap<(u16, u16), PendingRequest>>>,
        target_ip: Ipv4Addr,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } => {
                if name == "send_echo_request" {
                    let dest_ip: Ipv4Addr = data["destination_ip"]
                        .as_str()
                        .unwrap_or(&target_ip.to_string())
                        .parse()?;
                    let identifier =
                        crate::client::wire_values::number::<u16>(&data, "identifier", 1234)?;
                    let sequence = crate::client::wire_values::number::<u16>(&data, "sequence", 1)?;
                    let payload_hex = data["payload_hex"].as_str().unwrap_or("");
                    let ttl = crate::client::wire_values::number::<u8>(&data, "ttl", 64)?;

                    let payload = if payload_hex.is_empty() {
                        Vec::new()
                    } else {
                        hex::decode(payload_hex)?
                    };

                    // An echo request cannot be larger than one unfragmented IPv4 datagram;
                    // past this `set_total_length(ip_size as u16)` wraps and the header stops
                    // describing the buffer.
                    anyhow::ensure!(
                        payload.len() <= MAX_ICMP_PAYLOAD,
                        "payload_hex decodes to {} bytes; an ICMP echo request carries at most {}",
                        payload.len(),
                        MAX_ICMP_PAYLOAD
                    );

                    // Build and send echo request
                    let mut packet = Self::build_echo_request(
                        Ipv4Addr::UNSPECIFIED,
                        dest_ip,
                        identifier,
                        sequence,
                        &payload,
                        ttl,
                    );

                    // Last thing before the syscall: Darwin and FreeBSD want two header fields
                    // in host byte order on an IP_HDRINCL socket. After this the buffer is no
                    // longer a well-formed RFC 791 header, so nothing may parse it again.
                    crate::server::icmp::prepare_ipv4_for_raw_send(&mut packet);

                    let dest_addr = SocketAddr::new(std::net::IpAddr::V4(dest_ip), 0);
                    let sent = socket.send_to(&packet, &dest_addr.into())?;

                    // Track pending request
                    {
                        let mut pending = pending_requests.lock().await;
                        pending.insert(
                            (identifier, sequence),
                            PendingRequest {
                                sent_at: Instant::now(),
                                identifier,
                                sequence,
                                destination_ip: dest_ip,
                            },
                        );
                    }

                    console_debug!(
                        status_tx,
                        "ICMP sent echo request to {} (id={}, seq={})",
                        dest_ip,
                        identifier,
                        sequence
                    );
                    /* TODO: Timestamp support requires pnet to add timestamp packet types
                    } else if name == "send_timestamp_request" {
                        // TODO: Implement timestamp request
                        debug!("Timestamp request not yet implemented");
                    */
                    Ok(Applied::Sent(sent))
                } else {
                    Ok(Applied::Nothing(format!(
                        "custom result '{name}' is not an ICMP request; nothing sent"
                    )))
                }
            }
            ClientActionResult::WaitForMore => {
                // Just continue listening
                debug!("ICMP client waiting for more responses");
                Ok(Applied::Nothing("wait_for_more".to_string()))
            }
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            other => Ok(Applied::Nothing(format!(
                "action result {other:?} produced no packet"
            ))),
        }
    }

    /// Build an ICMP echo request packet with IP header.
    ///
    /// `pub` so `tests/client/icmp/action_codec_test.rs` can assert the bytes against RFC 792
    /// without a raw socket: this is the only ICMP the client ever emits, and every other test
    /// of it needs root.
    pub fn build_echo_request(
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
        ttl: u8,
    ) -> Vec<u8> {
        use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
        use pnet::packet::ipv4::checksum;

        // ICMP echo request: 8 bytes header + payload
        let icmp_size = 8 + payload.len();
        let mut icmp_buffer = vec![0u8; icmp_size];

        {
            let mut echo_req = MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
            echo_req.set_icmp_type(IcmpTypes::EchoRequest);
            echo_req.set_icmp_code(IcmpCode::new(0));
            echo_req.set_identifier(identifier);
            echo_req.set_sequence_number(sequence);
            echo_req.set_payload(payload);
        }

        // Calculate ICMP checksum
        let icmp_checksum = {
            let icmp_packet = MutableIcmpPacket::new(&mut icmp_buffer).unwrap();
            pnet::packet::icmp::checksum(&icmp_packet.to_immutable())
        };

        {
            let mut echo_req = MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
            echo_req.set_checksum(icmp_checksum);
        }

        // Wrap in IP packet
        let ip_size = 20 + icmp_size;
        let mut ip_buffer = vec![0u8; ip_size];

        {
            let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_dscp(0);
            ip_packet.set_ecn(0);
            ip_packet.set_total_length(ip_size as u16);
            ip_packet.set_identification(0);
            ip_packet.set_flags(0);
            ip_packet.set_fragment_offset(0);
            ip_packet.set_ttl(ttl);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip_packet.set_source(source_ip);
            ip_packet.set_destination(dest_ip);
            ip_packet.set_payload(&icmp_buffer);

            // Calculate IP checksum
            let ip_checksum = checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(ip_checksum);
        }

        ip_buffer
    }
}

/// Convert ICMP type to human-readable string
fn icmp_type_to_string(icmp_type: pnet::packet::icmp::IcmpType) -> &'static str {
    match icmp_type {
        IcmpTypes::EchoReply => "ECHO_REPLY",
        IcmpTypes::EchoRequest => "ECHO_REQUEST",
        IcmpTypes::DestinationUnreachable => "DEST_UNREACHABLE",
        IcmpTypes::SourceQuench => "SOURCE_QUENCH",
        IcmpTypes::RedirectMessage => "REDIRECT",
        IcmpTypes::TimeExceeded => "TIME_EXCEEDED",
        IcmpTypes::ParameterProblem => "PARAMETER_PROBLEM",
        IcmpTypes::Timestamp => "TIMESTAMP",
        IcmpTypes::TimestampReply => "TIMESTAMP_REPLY",
        IcmpTypes::InformationRequest => "INFO_REQUEST",
        IcmpTypes::InformationReply => "INFO_REPLY",
        IcmpTypes::AddressMaskRequest => "ADDRMASK_REQUEST",
        IcmpTypes::AddressMaskReply => "ADDRMASK_REPLY",
        IcmpTypes::Traceroute => "TRACEROUTE",
        _ => "UNKNOWN",
    }
}

/// What [`IcmpClient::apply_action`] did with one action.
#[derive(Debug)]
enum Applied {
    /// Packet bytes actually handed to `send_to` (0 when nothing was sent).
    Sent(usize),
    /// Ran, but put nothing on the wire; the string says why.
    Nothing(String),
    /// The session should end.
    Disconnect,
}

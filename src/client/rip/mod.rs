//! RIP (Routing Information Protocol) client implementation
pub mod actions;

pub use actions::RipClientProtocol;

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::rip::actions::{RIP_CLIENT_CONNECTED_EVENT, RIP_CLIENT_RESPONSE_RECEIVED_EVENT};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// RIP protocol version
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum RipVersion {
    V1 = 1,
    V2 = 2,
}

/// RIP command types
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum RipCommand {
    Request = 1,
    Response = 2,
}

/// RIP route entry (24 bytes for RIPv2)
#[derive(Debug, Clone)]
pub struct RipRouteEntry {
    pub address_family: u16,
    pub route_tag: u16, // RIPv2 only (0 for RIPv1)
    pub ip_address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr, // RIPv2 only (0.0.0.0 for RIPv1)
    pub next_hop: Ipv4Addr,    // RIPv2 only (0.0.0.0 for RIPv1)
    pub metric: u32,
}

impl RipRouteEntry {
    /// Create a new RIP route entry
    pub fn new(ip: Ipv4Addr, metric: u32) -> Self {
        Self {
            address_family: 2, // AF_INET
            route_tag: 0,
            ip_address: ip,
            subnet_mask: Ipv4Addr::new(0, 0, 0, 0),
            next_hop: Ipv4Addr::new(0, 0, 0, 0),
            metric,
        }
    }

    /// Create a RIPv2 route entry with subnet mask
    pub fn new_v2(ip: Ipv4Addr, subnet_mask: Ipv4Addr, next_hop: Ipv4Addr, metric: u32) -> Self {
        Self {
            address_family: 2,
            route_tag: 0,
            ip_address: ip,
            subnet_mask,
            next_hop,
            metric,
        }
    }

    /// Encode route entry to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);
        bytes.extend_from_slice(&self.address_family.to_be_bytes());
        bytes.extend_from_slice(&self.route_tag.to_be_bytes());
        bytes.extend_from_slice(&self.ip_address.octets());
        bytes.extend_from_slice(&self.subnet_mask.octets());
        bytes.extend_from_slice(&self.next_hop.octets());
        bytes.extend_from_slice(&self.metric.to_be_bytes());
        bytes
    }

    /// Decode route entry from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err(anyhow::anyhow!("RIP route entry too short"));
        }

        Ok(Self {
            address_family: u16::from_be_bytes([data[0], data[1]]),
            route_tag: u16::from_be_bytes([data[2], data[3]]),
            ip_address: Ipv4Addr::new(data[4], data[5], data[6], data[7]),
            subnet_mask: Ipv4Addr::new(data[8], data[9], data[10], data[11]),
            next_hop: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            metric: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
        })
    }
}

/// RIP message structure
#[derive(Debug, Clone)]
pub struct RipMessage {
    pub command: RipCommand,
    pub version: RipVersion,
    pub routes: Vec<RipRouteEntry>,
}

impl RipMessage {
    /// Create a RIP request message
    pub fn request(version: RipVersion) -> Self {
        // Request for entire routing table: address family 0, metric 16
        Self {
            command: RipCommand::Request,
            version,
            routes: vec![RipRouteEntry {
                address_family: 0,
                route_tag: 0,
                ip_address: Ipv4Addr::new(0, 0, 0, 0),
                subnet_mask: Ipv4Addr::new(0, 0, 0, 0),
                next_hop: Ipv4Addr::new(0, 0, 0, 0),
                metric: 16,
            }],
        }
    }

    /// Encode RIP message to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Command (1 byte)
        bytes.push(self.command as u8);

        // Version (1 byte)
        bytes.push(self.version as u8);

        // Must be zero (2 bytes)
        bytes.extend_from_slice(&[0, 0]);

        // Route entries (20 bytes each)
        for route in &self.routes {
            bytes.extend_from_slice(&route.encode());
        }

        bytes
    }

    /// Decode RIP message from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(anyhow::anyhow!("RIP message too short"));
        }

        let command = match data[0] {
            1 => RipCommand::Request,
            2 => RipCommand::Response,
            _ => return Err(anyhow::anyhow!("Invalid RIP command: {}", data[0])),
        };

        let version = match data[1] {
            1 => RipVersion::V1,
            2 => RipVersion::V2,
            _ => return Err(anyhow::anyhow!("Invalid RIP version: {}", data[1])),
        };

        // Parse route entries
        let mut routes = Vec::new();
        let mut offset = 4;

        while offset + 20 <= data.len() {
            routes.push(RipRouteEntry::decode(&data[offset..offset + 20])?);
            offset += 20;
        }

        Ok(Self {
            command,
            version,
            routes,
        })
    }
}

/// Connection state for LLM processing
#[derive(Debug, Clone, PartialEq)]
enum ConnectionState {
    Idle,
    Processing,
    Accumulating,
}

/// Per-client data for LLM handling
struct ClientData {
    state: ConnectionState,
    queued_responses: Vec<RipMessage>,
    memory: String,
}

/// RIP client that queries RIP routers
pub struct RipClient;

impl RipClient {
    /// Connect to a RIP router with integrated LLM actions
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
            .context(format!("Invalid RIP router address: {}", remote_addr))?;

        // Bind to any available local port (not 520, as that requires root)
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket")?;

        let local_addr = socket.local_addr()?;

        info!(
            "RIP client {} bound to {} (target: {})",
            client_id, local_addr, remote_sock_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] RIP client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let socket_arc = Arc::new(socket);

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            state: ConnectionState::Idle,
            queued_responses: Vec::new(),
            memory: String::new(),
        }));

        let protocol = Arc::new(crate::client::rip::actions::RipClientProtocol::new());

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
            socket_arc.clone(),
            remote_sock_addr,
            client_id,
            app_state.clone(),
            status_tx.clone(),
            read_abort.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with connected event
        let event = Event::new(
            &RIP_CLIENT_CONNECTED_EVENT,
            serde_json::json!({
                "remote_addr": remote_sock_addr.to_string(),
            }),
        );

        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            // Snapshot the memory into a local BEFORE the match. Passing
            // `&client_data.lock().await.memory` directly as an argument would put the
            // `MutexGuard` in the match scrutinee, and scrutinee temporaries live until the
            // end of the whole `match` — so the guard would be held across the LLM await and
            // the `Ok` arm's own `client_data.lock()` below would deadlock on it.
            let memory = client_data.lock().await.memory.clone();
            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                protocol.as_ref(),
                &status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    // Update memory
                    if let Some(mem) = memory_updates {
                        client_data.lock().await.memory = mem;
                    }

                    // Execute initial actions
                    for action in actions {
                        match protocol.as_ref().execute_action(action) {
                            Ok(result) => {
                                match Self::apply_action(
                                    client_id,
                                    result,
                                    &socket_arc,
                                    remote_sock_addr,
                                )
                                .await
                                {
                                    Ok(Applied::Disconnect) => {
                                        info!("RIP client {} disconnecting", client_id);
                                        app_state.remove_client_handle(client_id).await;
                                        app_state
                                            .update_client_status(
                                                client_id,
                                                ClientStatus::Disconnected,
                                            )
                                            .await;
                                        return Ok(local_addr);
                                    }
                                    Ok(_) => {}
                                    Err(e) => error!("Failed to send RIP request: {}", e),
                                }
                            }
                            Err(e) => error!(
                                "RIP client {} could not execute action after connect: {}",
                                client_id, e
                            ),
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for RIP client {}: {}", client_id, e);
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
        let socket_clone = socket_arc.clone();
        let client_data_clone = client_data.clone();
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 1500]; // Max UDP packet size

            loop {
                match socket_clone.recv_from(&mut buffer).await {
                    Ok((n, peer)) => {
                        trace!(
                            "RIP client {} received {} bytes from {}",
                            client_id,
                            n,
                            peer
                        );

                        // Parse RIP message
                        match RipMessage::decode(&buffer[..n]) {
                            Ok(msg) => {
                                let mut client_data_lock = client_data_clone.lock().await;

                                match client_data_lock.state {
                                    ConnectionState::Idle => {
                                        // Process immediately
                                        client_data_lock.state = ConnectionState::Processing;
                                        drop(client_data_lock);

                                        // Drain anything the Processing/Accumulating arms
                                        // parked, oldest first, and only then go back to Idle
                                        // — the TCP reference loops back over `queued_data`
                                        // the same way, where this used to `clear()` the queue
                                        // unread.
                                        //
                                        // Today the queue cannot actually fill: this task is
                                        // the only producer and it is parked on the LLM call
                                        // below, so `Processing`/`Accumulating` are
                                        // unreachable. The drain is here so the arms mean what
                                        // they say if a second producer ever appears, not
                                        // because datagrams are being lost now.
                                        let mut current = msg;
                                        loop {
                                            // Call LLM with response event
                                            if let Some(instruction) = app_state
                                                .get_instruction_for_client(client_id)
                                                .await
                                            {
                                                let routes: Vec<_> = current
                                                .routes
                                                .iter()
                                                .map(|r| {
                                                    serde_json::json!({
                                                        "ip_address": r.ip_address.to_string(),
                                                        "subnet_mask": r.subnet_mask.to_string(),
                                                        "next_hop": r.next_hop.to_string(),
                                                        "metric": r.metric,
                                                    })
                                                })
                                                .collect();

                                                let event = Event::new(
                                                    &RIP_CLIENT_RESPONSE_RECEIVED_EVENT,
                                                    serde_json::json!({
                                                        "version": current.version as u8,
                                                        "command": match current.command {
                                                            RipCommand::Request => "request",
                                                            RipCommand::Response => "response",
                                                        },
                                                        "route_count": routes.len(),
                                                        "routes": routes,
                                                    }),
                                                );

                                                // Snapshot before the match: a `MutexGuard` built
                                                // in the scrutinee lives to the end of the whole
                                                // `match`, so it would be held across the LLM
                                                // await and the `Ok` arm's own `lock()` below
                                                // would deadlock on it.
                                                let memory =
                                                    client_data_clone.lock().await.memory.clone();
                                                match call_llm_for_client(
                                                    &llm_client,
                                                    &app_state,
                                                    client_id.to_string(),
                                                    &instruction,
                                                    &memory,
                                                    Some(&event),
                                                    protocol.as_ref(),
                                                    &status_tx,
                                                )
                                                .await
                                                {
                                                    Ok(ClientLlmResult {
                                                        actions,
                                                        memory_updates,
                                                    }) => {
                                                        // Update memory
                                                        if let Some(mem) = memory_updates {
                                                            client_data_clone.lock().await.memory =
                                                                mem;
                                                        }

                                                        // Execute actions
                                                        for action in actions {
                                                            match protocol.as_ref().execute_action(action) {
                                                            Ok(result) => {
                                                                match Self::apply_action(client_id, result, &socket_clone, remote_sock_addr).await {
                                                                    Ok(Applied::Disconnect) => {
                                                                        info!("RIP client {} disconnecting", client_id);
                                                                        app_state.remove_client_handle(client_id).await;
                                                                        app_state.update_client_status(client_id, ClientStatus::Disconnected).await;
                                                                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                                                                        return;
                                                                    }
                                                                    Ok(_) => {}
                                                                    Err(e) => error!("Failed to send RIP request: {}", e),
                                                                }
                                                            }
                                                            Err(e) => error!("RIP client {} could not execute action: {}", client_id, e),
                                                        }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                            "LLM error for RIP client {}: {}",
                                                            client_id, e
                                                        );
                                                    }
                                                }
                                            }

                                            // Take the next datagram that queued up while the
                                            // model was deciding, oldest first. Only when the
                                            // queue is empty does the client go back to Idle.
                                            let mut client_data_lock =
                                                client_data_clone.lock().await;
                                            if client_data_lock.queued_responses.is_empty() {
                                                client_data_lock.state = ConnectionState::Idle;
                                                break;
                                            }
                                            current = client_data_lock.queued_responses.remove(0);
                                        }
                                    }
                                    ConnectionState::Processing => {
                                        // Queue response
                                        client_data_lock.queued_responses.push(msg);
                                        client_data_lock.state = ConnectionState::Accumulating;
                                    }
                                    ConnectionState::Accumulating => {
                                        // Continue queuing
                                        client_data_lock.queued_responses.push(msg);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to parse RIP message: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("RIP client {} recv error: {}", client_id, e);
                        app_state
                            .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                }
            }
            // Every exit path lands here: drop the command handle so the dashboard stops
            // offering [ send ] on a dead client, and a late send fails fast.
            app_state.remove_client_handle(client_id).await;
            let _ = status_tx.send("__UPDATE_UI__".to_string());
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
    /// `send_rip_request` yields `ClientActionResult::Custom` and the transport is a datagram
    /// socket, not an `AsyncWrite`. The action goes through [`Self::apply_action`] - the same
    /// function the LLM path uses - so the RIP encoding exists exactly once.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: tokio::sync::mpsc::Receiver<ClientCommand>,
        protocol: Arc<crate::client::rip::actions::RipClientProtocol>,
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
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
                Ok(result) => Self::apply_action(client_id, result, &socket, remote_addr)
                    .await
                    .map(|applied| match applied {
                        Applied::Disconnect => ClientSendOutcome::Disconnected,
                        Applied::Sent(0) => ClientSendOutcome::Executed {
                            detail: "executed (no datagram sent)".to_string(),
                        },
                        Applied::Sent(bytes_sent) => ClientSendOutcome::Sent { bytes_sent },
                        Applied::Nothing(detail) => ClientSendOutcome::Executed { detail },
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
                    "RIP client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                // UDP has no wire close, so "disconnected" means: stop receiving, release
                // the socket, drop the handle so [ send ] is greyed out again. If the
                // receive loop has not been spawned yet (the connected-event call is still
                // parked), the missing handle makes `connect_with_llm_actions` skip it.
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

    /// Put one executed action on the wire. Shared by the connected-event path, the receive
    /// loop and injected commands so the RIP request encoding exists exactly once.
    async fn apply_action(
        client_id: ClientId,
        result: ClientActionResult,
        socket: &UdpSocket,
        remote_addr: SocketAddr,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } if name == "send_rip_request" => {
                let version = data["version"]
                    .as_u64()
                    .context("send_rip_request is missing 'version'")?;
                // Refuse a version we cannot encode rather than silently sending v2 and
                // logging the number the caller asked for — RFC 1058 defines 1, RFC 2453
                // defines 2, and there is no third.
                let rip_version = match version {
                    1 => RipVersion::V1,
                    2 => RipVersion::V2,
                    other => {
                        return Err(anyhow::anyhow!(
                            "send_rip_request: unsupported RIP version {other} (must be 1 or 2)"
                        ))
                    }
                };
                let bytes = RipMessage::request(rip_version).encode();
                let sent = socket.send_to(&bytes, remote_addr).await?;
                debug!(
                    "RIP client {} sent request (version {}, {} bytes)",
                    client_id, rip_version as u8, sent
                );
                Ok(Applied::Sent(sent))
            }
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::WaitForMore => Ok(Applied::Nothing("wait_for_more".to_string())),
            ClientActionResult::Custom { name, .. } => Ok(Applied::Nothing(format!(
                "custom result '{name}' is not a RIP request; nothing sent"
            ))),
            other => Ok(Applied::Nothing(format!(
                "action result {other:?} produced no datagram"
            ))),
        }
    }
}

/// What [`RipClient::apply_action`] did with one action.
#[derive(Debug)]
enum Applied {
    /// Datagram bytes actually handed to `send_to` (0 when nothing was sent).
    Sent(usize),
    /// Ran, but produced no datagram; the string says why.
    Nothing(String),
    /// The session should end.
    Disconnect,
}

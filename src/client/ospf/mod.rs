//! OSPF client implementation - Query mode for topology discovery
//!
//! This OSPF client joins an OSPF network to query and monitor routers.
//! It can send Hello packets, request LSDB info, and parse LSAs for topology analysis.
//!
//! **Prerequisites**: Root/CAP_NET_RAW privileges for raw socket access
//! **Use case**: Network topology discovery, OSPF monitoring, route analysis

pub mod actions;

pub use actions::OspfClientProtocol;

use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::ospf::actions::{
    OSPF_CLIENT_CONNECTED_EVENT, OSPF_CLIENT_DD_RECEIVED_EVENT, OSPF_CLIENT_HELLO_RECEIVED_EVENT,
    OSPF_CLIENT_LSU_RECEIVED_EVENT,
};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::{Event, StartupParams};
use crate::server::socket_helpers::create_ospf_raw_socket;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

// OSPF Constants
const OSPF_VERSION: u8 = 2;
const OSPF_HEADER_LEN: usize = 24;
const IP_HEADER_MIN_LEN: usize = 20;

// OSPF Packet Types
const OSPF_TYPE_HELLO: u8 = 1;
const OSPF_TYPE_DATABASE_DESCRIPTION: u8 = 2;
const OSPF_TYPE_LINK_STATE_REQUEST: u8 = 3;
const OSPF_TYPE_LINK_STATE_UPDATE: u8 = 4;
const OSPF_TYPE_LINK_STATE_ACK: u8 = 5;

// OSPF Multicast addresses
const OSPF_ALL_SPF_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 5);
const OSPF_ALL_DROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 6);

/// Connection state for LLM processing
#[derive(Debug, Clone, PartialEq)]
enum ConnectionState {
    Idle,
    Processing,
    Accumulating,
}

/// Queued OSPF packet with metadata
struct QueuedPacket {
    packet_type: u8,
    ospf_data: Vec<u8>,
    src_ip: Ipv4Addr,
    sender_router_id: String,
    sender_area_id: String,
}

/// Per-client data for LLM handling
struct ClientData {
    state: ConnectionState,
    queued_packets: Vec<QueuedPacket>,
    memory: String,
}

/// OSPF client
pub struct OspfClient;

impl OspfClient {
    /// Connect to OSPF network with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        // Parse interface IP from remote_addr
        // Format expected: "interface_ip" or "interface_ip:0"
        let interface_ip = remote_addr
            .split(':')
            .next()
            .ok_or_else(|| anyhow!("Invalid remote_addr format"))?
            .parse::<Ipv4Addr>()
            .context("Failed to parse interface IP")?;

        // Extract configuration
        let (router_id, area_id) = if let Some(ref params) = startup_params {
            let router_id = params
                .get_optional_string("router_id")?
                .unwrap_or_else(|| interface_ip.to_string());
            let area_id = params
                .get_optional_string("area_id")?
                .unwrap_or_else(|| "0.0.0.0".to_string());
            (router_id, area_id)
        } else {
            (interface_ip.to_string(), "0.0.0.0".to_string())
        };

        // Create raw OSPF socket
        let raw_socket = create_ospf_raw_socket(interface_ip, true, false)
            .context("Failed to create OSPF raw socket (requires root)")?;
        let socket_fd = raw_socket.as_raw_fd();

        info!(
            "OSPF client {} connected on interface {} (router_id={}, area={})",
            client_id, interface_ip, router_id, area_id
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] OSPF client {} on {} (requires root)",
            client_id, interface_ip
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let local_addr = SocketAddr::new(IpAddr::V4(interface_ip), 0);

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            state: ConnectionState::Idle,
            queued_packets: Vec::new(),
            memory: String::new(),
        }));

        // Wrap socket for async I/O
        let async_socket = AsyncFd::new(raw_socket)?;

        // Send connected event to LLM
        let connected_event = Event::new(
            &OSPF_CLIENT_CONNECTED_EVENT,
            serde_json::json!({
                "interface_ip": interface_ip.to_string(),
                "router_id": router_id.clone(),
            }),
        );

        let llm_clone = llm_client.clone();
        let app_state_clone = app_state.clone();
        let status_tx_clone = status_tx.clone();
        let protocol = Arc::new(OspfClientProtocol::new());
        let protocol_for_loop = protocol.clone();
        let protocol_for_commands = protocol.clone();

        // Command channel for injected actions (the dashboard's [ send ]). Registered BEFORE
        // the connected-event LLM call below, which a manual `*` routing rule can park for
        // minutes - the operator must be able to reach the client while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            if let Some(instruction) = app_state_clone.get_instruction_for_client(client_id).await {
                match call_llm_for_client(
                    &llm_clone,
                    &app_state_clone,
                    client_id.to_string(),
                    &instruction,
                    "",
                    Some(&connected_event),
                    protocol.as_ref(),
                    &status_tx_clone,
                )
                .await
                {
                    Ok(result) => {
                        if let Some(memory) = result.memory_updates {
                            app_state_clone
                                .set_memory_for_client(client_id, memory)
                                .await;
                        }
                        // Executed, not counted. This is the model's one chance to act before
                        // any packet arrives — `send_hello` to discover neighbours is the
                        // protocol's own worked example — and the answer used to be dropped.
                        Self::run_actions(
                            result.actions,
                            protocol.as_ref(),
                            socket_fd,
                            client_id,
                            &app_state_clone,
                            &status_tx_clone,
                        )
                        .await;
                    }
                    Err(e) => {
                        error!("OSPF client {} LLM call failed: {}", client_id, e);
                        let _ = status_tx_clone
                            .send(format!("✗ OSPF client {} LLM error: {}", client_id, e));
                    }
                }
            }
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // Spawn receive loop
        let socket_fd_for_send = socket_fd;
        let app_state_for_commands = app_state.clone();
        let status_tx_for_commands = status_tx.clone();
        let protocol = protocol_for_loop;
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65535];

            loop {
                let mut guard = match async_socket.readable().await {
                    Ok(guard) => guard,
                    Err(e) => {
                        error!("OSPF client {} socket error: {}", client_id, e);
                        break;
                    }
                };

                match guard.try_io(|inner| {
                    let fd = inner.as_raw_fd();
                    unsafe {
                        let n = libc::recv(
                            fd,
                            buffer.as_mut_ptr() as *mut libc::c_void,
                            buffer.len(),
                            0,
                        );

                        if n < 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(n as usize)
                        }
                    }
                }) {
                    Ok(Ok(n)) => {
                        if n == 0 {
                            continue;
                        }

                        // Skip IP header
                        if n < IP_HEADER_MIN_LEN {
                            continue;
                        }

                        let ip_header_len = ((buffer[0] & 0x0F) * 4) as usize;
                        if n < ip_header_len + OSPF_HEADER_LEN {
                            continue;
                        }

                        // Extract source IP from IP header
                        let src_ip = Ipv4Addr::new(buffer[12], buffer[13], buffer[14], buffer[15]);

                        // Extract OSPF packet
                        let ospf_data = &buffer[ip_header_len..n];
                        let version = ospf_data[0];
                        let packet_type = ospf_data[1];

                        if version != OSPF_VERSION {
                            continue;
                        }

                        // Extract router ID and area ID
                        let sender_router_id = format!(
                            "{}.{}.{}.{}",
                            ospf_data[4], ospf_data[5], ospf_data[6], ospf_data[7]
                        );

                        let sender_area_id = format!(
                            "{}.{}.{}.{}",
                            ospf_data[8], ospf_data[9], ospf_data[10], ospf_data[11]
                        );

                        debug!(
                            "OSPF client {} received type={} from {} ({})",
                            client_id, packet_type, src_ip, sender_router_id
                        );

                        // Handle packet with LLM
                        let mut client_data_lock = client_data.lock().await;

                        match client_data_lock.state {
                            ConnectionState::Idle => {
                                // Process immediately
                                client_data_lock.state = ConnectionState::Processing;
                                drop(client_data_lock);

                                Self::process_ospf_packet(
                                    packet_type,
                                    ospf_data.to_vec(),
                                    src_ip,
                                    sender_router_id,
                                    sender_area_id,
                                    llm_client.clone(),
                                    app_state.clone(),
                                    status_tx.clone(),
                                    protocol.clone(),
                                    client_id,
                                    client_data.clone(),
                                    socket_fd_for_send,
                                )
                                .await;
                            }
                            ConnectionState::Processing => {
                                // Queue packet with metadata
                                client_data_lock.queued_packets.push(QueuedPacket {
                                    packet_type,
                                    ospf_data: ospf_data.to_vec(),
                                    src_ip,
                                    sender_router_id: sender_router_id.clone(),
                                    sender_area_id: sender_area_id.clone(),
                                });
                                client_data_lock.state = ConnectionState::Accumulating;
                                trace!("OSPF client {} queued packet", client_id);
                            }
                            ConnectionState::Accumulating => {
                                // Continue queuing with metadata
                                client_data_lock.queued_packets.push(QueuedPacket {
                                    packet_type,
                                    ospf_data: ospf_data.to_vec(),
                                    src_ip,
                                    sender_router_id: sender_router_id.clone(),
                                    sender_area_id: sender_area_id.clone(),
                                });
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        error!("OSPF client {} recv error: {}", client_id, e);
                    }
                    Err(_would_block) => continue,
                }
            }

            warn!("OSPF client {} receive loop terminated", client_id);
            app_state
                .update_client_status(client_id, ClientStatus::Disconnected)
                .await;
            // Every exit path lands here: drop the command handle so the dashboard stops
            // offering [ send ] on a dead client, and a late send fails fast.
            app_state.remove_client_handle(client_id).await;
            let _ = status_tx.send(format!("[CLIENT] OSPF client {} disconnected", client_id));
            let _ = status_tx.send("__UPDATE_UI__".to_string());
        });
        // Kept so an injected `disconnect` can actually stop the receive loop and release
        // the raw socket - OSPF has no wire close to send.
        let read_abort = task_handle.abort_handle();
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // The receive loop awaits `call_llm_for_client` inline, so a `select!` arm there
        // would stall for the whole LLM round-trip. Drain commands in their own registered
        // task instead; both use the same raw socket fd.
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            protocol_for_commands,
            socket_fd_for_send,
            client_id,
            app_state_for_commands,
            status_tx_for_commands,
            read_abort,
        ));
        task_registrar
            .register_client_task(client_id, cmd_task)
            .await;

        Ok(local_addr)
    }

    /// Drain injected commands until the channel closes (client removed) or an injected
    /// `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot serve this client:
    /// every OSPF verb yields `ClientActionResult::Custom` and the transport is a raw IP
    /// socket driven through `libc::sendto`, not an `AsyncWrite`. The action goes through
    /// [`Self::apply_action`] - the same function the receive loop uses.
    async fn command_loop(
        mut command_rx: tokio::sync::mpsc::Receiver<ClientCommand>,
        protocol: Arc<OspfClientProtocol>,
        socket_fd: i32,
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
                Ok(result) => {
                    Self::apply_action(client_id, result, socket_fd).map(|applied| match applied {
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
                    "OSPF client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
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

    /// Apply one executed action. Shared by the receive loop and injected commands so the
    /// OSPF packet building and `sendto` exist exactly once.
    /// Carry out what the model answered with. Returns `true` if it asked to disconnect.
    ///
    /// Shared by the connected-event task and the receive loop. The connected-event path used
    /// to be an `if let Err(..) = call_llm_for_client(..)` with no success arm at all, so the
    /// model's answer to "you are on the wire now" — the one moment it is asked what to do
    /// before any packet arrives, and the moment its own docs show it choosing `send_hello` to
    /// discover neighbours — was dropped entirely. Everything below already existed inline in
    /// `process_ospf_packet`; extracting it is what lets the other caller reach it.
    async fn run_actions(
        actions: Vec<serde_json::Value>,
        protocol: &OspfClientProtocol,
        socket_fd: i32,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> bool {
        for action in actions {
            match protocol.execute_action(action) {
                Ok(action_result) => {
                    match Self::apply_action(client_id, action_result, socket_fd) {
                        Ok(Applied::Disconnect) => {
                            app_state.remove_client_handle(client_id).await;
                            app_state
                                .update_client_status(client_id, ClientStatus::Disconnected)
                                .await;
                            let _ = status_tx
                                .send(format!("[CLIENT] OSPF client {} disconnected", client_id));
                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                            return true;
                        }
                        Ok(Applied::Nothing(detail)) => {
                            trace!("OSPF client {}: {}", client_id, detail);
                        }
                        Ok(Applied::Sent(_)) => {}
                        Err(e) => {
                            error!("Failed to execute OSPF action: {}", e);
                            let _ = status_tx.send(format!("✗ OSPF action error: {}", e));
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to execute action: {}", e);
                    let _ = status_tx.send(format!(
                        "✗ OSPF client {} rejected action: {}",
                        client_id, e
                    ));
                }
            }
        }
        false
    }

    fn apply_action(
        client_id: ClientId,
        result: ClientActionResult,
        socket_fd: i32,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } if name.starts_with("ospf_") => {
                let sent = Self::handle_ospf_action(&name, &data, socket_fd)?;
                Ok(Applied::Sent(sent))
            }
            ClientActionResult::Disconnect => {
                info!("OSPF client {} disconnecting", client_id);
                Ok(Applied::Disconnect)
            }
            ClientActionResult::WaitForMore => Ok(Applied::Nothing("wait_for_more".to_string())),
            ClientActionResult::Custom { name, .. } => Ok(Applied::Nothing(format!(
                "custom result '{name}' is not an OSPF verb; nothing sent"
            ))),
            other => Ok(Applied::Nothing(format!(
                "action result {other:?} produced no packet"
            ))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_ospf_packet(
        packet_type: u8,
        ospf_data: Vec<u8>,
        src_ip: Ipv4Addr,
        sender_router_id: String,
        sender_area_id: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<OspfClientProtocol>,
        client_id: ClientId,
        client_data: Arc<Mutex<ClientData>>,
        socket_fd: i32,
    ) {
        let event = match packet_type {
            OSPF_TYPE_HELLO => {
                Self::parse_hello_packet(&ospf_data, &src_ip, &sender_router_id, &sender_area_id)
            }
            OSPF_TYPE_DATABASE_DESCRIPTION => Self::parse_dd_packet(&ospf_data, &sender_router_id),
            OSPF_TYPE_LINK_STATE_UPDATE => Self::parse_lsu_packet(&ospf_data, &sender_router_id),
            OSPF_TYPE_LINK_STATE_REQUEST => {
                debug!("OSPF LSR from {}", sender_router_id);
                None
            }
            OSPF_TYPE_LINK_STATE_ACK => {
                trace!("OSPF LSAck from {}", sender_router_id);
                None
            }
            _ => {
                warn!("OSPF unknown type: {}", packet_type);
                None
            }
        };

        if let Some(event) = event {
            // Get current memory and instruction
            let memory = client_data.lock().await.memory.clone();

            if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
                // Call LLM
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
                    Ok(result) => {
                        // Update memory if provided
                        if let Some(new_memory) = result.memory_updates {
                            client_data.lock().await.memory = new_memory;
                        }

                        // Execute actions
                        if Self::run_actions(
                            result.actions,
                            protocol.as_ref(),
                            socket_fd,
                            client_id,
                            &app_state,
                            &status_tx,
                        )
                        .await
                        {
                            return;
                        }
                    }
                    Err(e) => {
                        error!("OSPF client {} LLM call failed: {}", client_id, e);
                        let _ =
                            status_tx.send(format!("✗ OSPF client {} LLM error: {}", client_id, e));
                    }
                }
            }
        }

        // Process queued packets if any
        let mut client_data_lock = client_data.lock().await;
        match client_data_lock.state {
            ConnectionState::Processing => {
                // No queued packets, back to idle
                client_data_lock.state = ConnectionState::Idle;
            }
            ConnectionState::Accumulating => {
                // Process first queued packet
                let has_queued = !client_data_lock.queued_packets.is_empty();
                if has_queued {
                    let queued_packet = client_data_lock.queued_packets.remove(0);
                    client_data_lock.state = ConnectionState::Processing;
                    drop(client_data_lock);

                    // Recursively process the queued packet with all metadata
                    trace!("OSPF client {} processing queued packet", client_id);
                    Box::pin(Self::process_ospf_packet(
                        queued_packet.packet_type,
                        queued_packet.ospf_data,
                        queued_packet.src_ip,
                        queued_packet.sender_router_id,
                        queued_packet.sender_area_id,
                        llm_client,
                        app_state,
                        status_tx,
                        protocol,
                        client_id,
                        client_data,
                        socket_fd,
                    ))
                    .await;
                } else {
                    client_data_lock.state = ConnectionState::Idle;
                }
            }
            ConnectionState::Idle => {}
        }
    }

    fn parse_hello_packet(
        data: &[u8],
        src_ip: &Ipv4Addr,
        sender_router_id: &str,
        sender_area_id: &str,
    ) -> Option<Event> {
        if data.len() < OSPF_HEADER_LEN + 20 {
            return None;
        }

        // Parse Hello fields
        let network_mask = format!("{}.{}.{}.{}", data[24], data[25], data[26], data[27]);
        let hello_interval = u16::from_be_bytes([data[28], data[29]]);
        let priority = data[31];
        let router_dead_interval = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
        let dr = format!("{}.{}.{}.{}", data[36], data[37], data[38], data[39]);
        let bdr = format!("{}.{}.{}.{}", data[40], data[41], data[42], data[43]);

        // Parse neighbors
        let mut neighbor_list = Vec::new();
        let mut offset = 44;
        while offset + 4 <= data.len() {
            let neighbor_id = format!(
                "{}.{}.{}.{}",
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3]
            );
            neighbor_list.push(neighbor_id);
            offset += 4;
        }

        Some(Event::new(
            &OSPF_CLIENT_HELLO_RECEIVED_EVENT,
            serde_json::json!({
                "neighbor_id": sender_router_id,
                "neighbor_ip": src_ip.to_string(),
                "area_id": sender_area_id,
                "network_mask": network_mask,
                "hello_interval": hello_interval,
                "router_dead_interval": router_dead_interval,
                "router_priority": priority,
                "dr": dr,
                "bdr": bdr,
                "neighbors": neighbor_list,
            }),
        ))
    }

    fn parse_dd_packet(data: &[u8], sender_router_id: &str) -> Option<Event> {
        if data.len() < OSPF_HEADER_LEN + 8 {
            return None;
        }

        // Parse DD header (8 bytes after OSPF header)
        let mtu = u16::from_be_bytes([data[24], data[25]]);
        let options = data[26];
        let flags = data[27];
        let sequence = u32::from_be_bytes([data[28], data[29], data[30], data[31]]);

        let init = (flags & 0x04) != 0;
        let more = (flags & 0x02) != 0;
        let master = (flags & 0x01) != 0;

        debug!(
            "OSPF DD: mtu={}, options={:02x}, seq={}, I={}, M={}, MS={}",
            mtu, options, sequence, init, more, master
        );

        Some(Event::new(
            &OSPF_CLIENT_DD_RECEIVED_EVENT,
            serde_json::json!({
                "neighbor_id": sender_router_id,
                "sequence": sequence,
                "init": init,
                "more": more,
                "master": master,
            }),
        ))
    }

    fn parse_lsu_packet(data: &[u8], sender_router_id: &str) -> Option<Event> {
        if data.len() < OSPF_HEADER_LEN + 4 {
            return None;
        }

        // Parse LSU header (4 bytes: number of LSAs)
        let advertised_count = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

        // Walk the LSAs by each header's own length field rather than trusting the
        // advertised count, so a peer cannot make us read past the packet.
        //
        // This client exists for topology discovery and the Link State Update is the packet
        // that carries the topology - yet the event used to report only how many LSAs had
        // arrived and threw the LSAs themselves away, so the model was told "6 LSAs" and
        // never what was in them. These are also the exact fields send_link_state_ack needs
        // in order to acknowledge them.
        let body = &data[28..];
        let mut lsas = Vec::new();
        let mut offset = 0usize;
        while offset + 20 <= body.len() && lsas.len() < 64 {
            let header = crate::server::ospf::actions::OspfProtocol::parse_lsa_headers(
                &body[offset..offset + 20],
                1,
            );
            let Some(header) = header.into_iter().next() else {
                break;
            };
            let declared = header["length"].as_u64().unwrap_or(0) as usize;
            lsas.push(header);
            // A length below the header size would not advance us; stop rather than spin.
            if declared < 20 {
                break;
            }
            offset += declared;
        }

        debug!(
            "OSPF LSU: {} LSAs advertised, {} parsed, from {}",
            advertised_count,
            lsas.len(),
            sender_router_id
        );

        Some(Event::new(
            &OSPF_CLIENT_LSU_RECEIVED_EVENT,
            serde_json::json!({
                "neighbor_id": sender_router_id,
                "advertised_lsa_count": advertised_count,
                "lsa_count": lsas.len(),
                "lsa_headers": lsas,
            }),
        ))
    }

    /// Build and send one OSPF packet. Returns the number of bytes `sendto` accepted, so
    /// an injected action can report a truthful `ClientSendOutcome::Sent`.
    fn handle_ospf_action(
        action_name: &str,
        data: &serde_json::Value,
        socket_fd: i32,
    ) -> Result<usize> {
        let packet = match action_name {
            "ospf_send_hello" => {
                crate::server::ospf::actions::OspfProtocol::build_hello_packet(data)?
            }
            "ospf_send_dd" => {
                crate::server::ospf::actions::OspfProtocol::build_database_description_packet(data)?
            }
            "ospf_send_lsr" => {
                crate::server::ospf::actions::OspfProtocol::build_link_state_request_packet(data)?
            }
            "ospf_send_lsack" => {
                crate::server::ospf::actions::OspfProtocol::build_link_state_ack_packet(data)?
            }
            _ => return Err(anyhow!("Unknown OSPF action: {}", action_name)),
        };

        // Parse destination
        let destination_str = data
            .get("destination")
            .and_then(|d| d.as_str())
            .unwrap_or("multicast");

        let dest_ip = match destination_str {
            "multicast" => OSPF_ALL_SPF_ROUTERS,
            "dr_multicast" => OSPF_ALL_DROUTERS,
            ip_str => match ip_str.parse::<Ipv4Addr>() {
                Ok(ip) => ip,
                Err(_) => {
                    // Falling back silently sent a packet the model meant for one router to
                    // every OSPF speaker on the segment. Still send it - a typo should not
                    // swallow the action - but say where it actually went.
                    warn!(
                        "OSPF client: destination '{}' is not an IP address; sending to \
                         224.0.0.5 (all SPF routers) instead",
                        ip_str
                    );
                    OSPF_ALL_SPF_ROUTERS
                }
            },
        };

        // Send packet
        let sent = Self::send_ospf_packet(socket_fd, dest_ip, &packet)?;

        debug!("OSPF sent {} bytes to {}", sent, dest_ip);
        Ok(sent)
    }

    fn send_ospf_packet(socket_fd: i32, dest_ip: Ipv4Addr, ospf_data: &[u8]) -> Result<usize> {
        unsafe {
            let mut dest_addr = std::mem::zeroed::<libc::sockaddr_in>();
            #[cfg(target_os = "macos")]
            {
                dest_addr.sin_family = libc::AF_INET as libc::sa_family_t;
                dest_addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            }
            #[cfg(not(target_os = "macos"))]
            {
                dest_addr.sin_family = libc::AF_INET as u16;
            }
            dest_addr.sin_port = 0; // Raw IP, no port
            dest_addr.sin_addr.s_addr = u32::from(dest_ip).to_be();

            let n = libc::sendto(
                socket_fd,
                ospf_data.as_ptr() as *const libc::c_void,
                ospf_data.len(),
                0,
                &dest_addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            );

            if n < 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            Ok(n as usize)
        }
    }
}

/// What [`OspfClient::apply_action`] did with one action.
#[derive(Debug)]
enum Applied {
    /// Packet bytes `sendto` accepted (0 when nothing was sent).
    Sent(usize),
    /// Ran, but put nothing on the wire; the string says why.
    Nothing(String),
    /// The session should end.
    Disconnect,
}

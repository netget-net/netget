//! DHCP client implementation
pub mod actions;

pub use actions::DhcpClientProtocol;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace};

use actions::{DHCP_CLIENT_CONNECTED_EVENT, DHCP_CLIENT_RESPONSE_RECEIVED_EVENT};

use dhcproto::{v4, Decodable, Decoder};

/// Connection state for LLM processing
#[derive(Debug, Clone, PartialEq)]
enum ConnectionState {
    Idle,
    Processing,
}

/// Per-client data for LLM handling
struct ClientData {
    state: ConnectionState,
    memory: String,
}

/// What applying one executed action did. Shared by the LLM paths and the
/// command channel so an injected action reports the same truth the LLM path
/// puts on the wire.
enum Applied {
    /// A datagram reached the wire, with its real byte count.
    Sent(usize),
    /// The action ran but wrote nothing.
    Executed(String),
    /// The session should end.
    Disconnect,
}

/// DHCP client that sends requests and processes responses via LLM
pub struct DhcpClient;

impl DhcpClient {
    /// Connect to DHCP server with LLM-controlled actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // Parse remote_addr (DHCP server address)
        let server_addr: SocketAddr = remote_addr.parse().context("Invalid DHCP server address")?;

        // Bind to DHCP client port (68) when we may, an ephemeral port otherwise.
        //
        // Port 68 is privileged, so an unprivileged NetGet cannot have it - and a hard
        // failure there made the DHCP client unusable (and untestable) for every
        // non-root run, including the dashboard's own [ + new client ]. Falling back
        // mirrors the BOOTP client. The cost is real and worth stating: a server that
        // replies by broadcasting to port 68, as RFC 2131 allows when the BROADCAST
        // flag is set, will not be heard on an ephemeral port; unicast replies to our
        // source port are.
        let socket = Arc::new(match UdpSocket::bind("0.0.0.0:68").await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    "DHCP client {} could not bind port 68 ({}); using an ephemeral port \
                     - replies broadcast to port 68 will not be received",
                    client_id,
                    e
                );
                UdpSocket::bind("0.0.0.0:0")
                    .await
                    .context("Failed to bind a UDP socket for the DHCP client")?
            }
        });

        // Enable broadcast
        socket.set_broadcast(true)?;

        let local_addr = socket.local_addr()?;

        info!(
            "DHCP client {} bound to {}, targeting server {}",
            client_id, local_addr, server_addr
        );
        let _ = status_tx.send(format!(
            "[CLIENT] DHCP client {} connected, targeting server {}",
            client_id, server_addr
        ));

        // Update client status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            state: ConnectionState::Idle,
            memory: String::new(),
        }));

        // Spawn event: dhcp_connected
        let event = Event::new(
            &DHCP_CLIENT_CONNECTED_EVENT,
            serde_json::json!({
                "server_addr": server_addr.to_string(),
                "local_addr": local_addr.to_string()
            }),
        );

        debug!("DHCP client {} calling LLM for connected event", client_id);

        // Command channel: lets the dashboard (and any programmatic caller) inject
        // actions into this client via AppState::send_to_client.
        //
        // Registered BEFORE the connected event is handled: a `manual` routing rule can
        // park that event at the dashboard for minutes, and until registration the UI
        // reports "no command channel" - reading as a protocol limitation when it is
        // only a queue.
        let mut command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // Call LLM for initial connection event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = Arc::new(DhcpClientProtocol::new());

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &client_data.lock().await.memory,
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

                    // Execute actions from LLM response
                    for action in actions {
                        match protocol.as_ref().execute_action(action) {
                            Ok(action_result) => {
                                match Self::apply_action_result(
                                    action_result,
                                    &socket,
                                    server_addr,
                                    client_id,
                                )
                                .await
                                {
                                    Ok(Applied::Disconnect) => {
                                        info!("DHCP client {} disconnecting", client_id);
                                        app_state.remove_client_handle(client_id).await;
                                        return Ok(local_addr);
                                    }
                                    Ok(_) => {}
                                    Err(e) => {
                                        error!(
                                            "DHCP client {} could not send after connect: {}",
                                            client_id, e
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                error!("DHCP client {} action execution failed: {}", client_id, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("DHCP client {} LLM call failed: {}", client_id, e);
                }
            }
        }

        // Spawn receive loop
        let socket_clone = socket.clone();
        let llm_clone = llm_client.clone();
        let state_clone = app_state.clone();
        let status_clone = status_tx.clone();
        let client_data_clone = client_data.clone();

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 1500];
            let cmd_protocol = Arc::new(DhcpClientProtocol::new());

            loop {
                // `UdpSocket::recv_from` is cancellation-safe, so the command arm can
                // share this select! with the read - losing the race never drops a
                // datagram.
                let recv_result = tokio::select! {
                    result = socket_clone.recv_from(&mut buffer) => result,
                    Some(cmd) = command_rx.recv() => {
                        if Self::handle_injected_command(
                            cmd,
                            &socket_clone,
                            server_addr,
                            &cmd_protocol,
                            &state_clone,
                            &status_clone,
                            client_id,
                        )
                        .await
                        {
                            state_clone
                                .update_client_status(client_id, ClientStatus::Disconnected)
                                .await;
                            let _ = status_clone.send(format!(
                                "[CLIENT] DHCP client {} disconnected (injected action)",
                                client_id
                            ));
                            let _ = status_clone.send("__UPDATE_UI__".to_string());
                            break;
                        }
                        continue;
                    }
                };

                match recv_result {
                    Ok((n, peer_addr)) => {
                        let data = buffer[..n].to_vec();

                        debug!(
                            "DHCP client {} received {} bytes from {}",
                            client_id, n, peer_addr
                        );
                        trace!("DHCP response (hex): {}", hex::encode(&data));

                        // Handle data with LLM
                        let mut client_data_lock = client_data_clone.lock().await;

                        match client_data_lock.state {
                            ConnectionState::Idle => {
                                // Process immediately
                                client_data_lock.state = ConnectionState::Processing;
                                drop(client_data_lock);

                                // Parse DHCP response
                                let parsed_info = Self::parse_dhcp_response(&data);


                                let event_data = if let Some((message_type, details)) = parsed_info
                                {
                                    serde_json::json!({
                                        "message_type": message_type,
                                        "details": details
                                    })
                                } else {
                                    serde_json::json!({
                                        "message_type": "unknown",
                                        "data_hex": hex::encode(&data),
                                        "data_length": n
                                    })
                                };

                                let event =
                                    Event::new(&DHCP_CLIENT_RESPONSE_RECEIVED_EVENT, event_data);

                                // Call LLM with response event
                                if let Some(instruction) =
                                    state_clone.get_instruction_for_client(client_id).await
                                {
                                    let protocol = Arc::new(DhcpClientProtocol::new());

                                    match call_llm_for_client(
                                        &llm_clone,
                                        &state_clone,
                                        client_id.to_string(),
                                        &instruction,
                                        &client_data_clone.lock().await.memory,
                                        Some(&event),
                                        protocol.as_ref(),
                                        &status_clone,
                                    )
                                    .await
                                    {
                                        Ok(ClientLlmResult {
                                            actions,
                                            memory_updates,
                                        }) => {
                                            // Update memory
                                            if let Some(mem) = memory_updates {
                                                client_data_clone.lock().await.memory = mem;
                                            }

                                            // Execute actions from LLM
                                            for action in actions {
                                                match protocol.as_ref().execute_action(action) {
                                                    Ok(action_result) => {
                                                        match Self::apply_action_result(
                                                            action_result,
                                                            &socket_clone,
                                                            peer_addr,
                                                            client_id,
                                                        )
                                                        .await
                                                        {
                                                            Ok(Applied::Disconnect) => {
                                                                info!(
                                                                    "DHCP client {} disconnecting",
                                                                    client_id
                                                                );
                                                                state_clone
                                                                    .update_client_status(
                                                                        client_id,
                                                                        ClientStatus::Disconnected,
                                                                    )
                                                                    .await;
                                                                let _ = status_clone.send(
                                                                    "__UPDATE_UI__".to_string(),
                                                                );
                                                                break;
                                                            }
                                                            Ok(_) => {}
                                                            Err(e) => {
                                                                error!("DHCP client {} failed to send: {}", client_id, e);
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!("DHCP client {} action execution failed: {}", client_id, e);
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                "DHCP client {} LLM call failed: {}",
                                                client_id, e
                                            );
                                        }
                                    }
                                }

                                // Reset to idle state
                                client_data_clone.lock().await.state = ConnectionState::Idle;
                            }
                            ConnectionState::Processing => {
                                // Queue data for later processing
                                debug!(
                                    "DHCP client {} is processing, queueing response",
                                    client_id
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!("DHCP client {} receive error: {}", client_id, e);
                        state_clone
                            .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                            .await;
                        let _ = status_clone.send("__UPDATE_UI__".to_string());
                        break;
                    }
                }
            }

            // Every exit path lands here: drop the command handle so the dashboard
            // stops offering [ send ] on a dead client (a late send then fails fast).
            state_clone.remove_client_handle(client_id).await;
            let _ = status_clone.send("__UPDATE_UI__".to_string());
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }

    /// Put one executed action on the wire. Shared by the connected-event path, the
    /// receive loop and injected commands, so the packet encoding and the choice of
    /// destination exist exactly once.
    ///
    /// `unicast_target` is where a non-broadcast datagram goes: the configured server
    /// on the connect path, the peer that just answered us in the receive loop.
    async fn apply_action_result(
        result: ClientActionResult,
        socket: &Arc<UdpSocket>,
        unicast_target: SocketAddr,
        client_id: ClientId,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } => {
                {
                    let (packet, label) = match name.as_str() {
                        "dhcp_discover" => (Self::build_discover_packet(&data)?, "DISCOVER"),
                        "dhcp_request" => (Self::build_request_packet(&data)?, "REQUEST"),
                        // INFORM is sent by a client that already has an address, so it
                        // is always unicast to the server.
                        "dhcp_inform" => (Self::build_inform_packet(&data)?, "INFORM"),
                        _ => {
                            return Ok(Applied::Executed(format!(
                                "custom result '{name}' is not a DHCP wire verb"
                            )))
                        }
                    };

                    let broadcast = label != "INFORM"
                        && data
                            .get("broadcast")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true);
                    let target: SocketAddr = if broadcast {
                        "255.255.255.255:67"
                            .parse()
                            .expect("literal broadcast address")
                    } else {
                        unicast_target
                    };

                    // The byte count reported to an injected caller is the one the
                    // kernel accepted, not the length we hoped to send.
                    let sent = socket.send_to(&packet, target).await?;
                    debug!(
                        "DHCP client {} sent {} ({} bytes) to {}",
                        client_id, label, sent, target
                    );
                    trace!("DHCP {} (hex): {}", label, hex::encode(&packet));
                    Ok(Applied::Sent(sent))
                }

            }
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::WaitForMore => Ok(Applied::Executed("wait_for_more".to_string())),
            ClientActionResult::NoAction => Ok(Applied::Executed("no_action".to_string())),
            other => Ok(Applied::Executed(format!("no wire effect: {other:?}"))),
        }
    }

    /// Apply one injected action, record it in the access log exactly as
    /// `command_support::handle_stream_client_command` does for stream clients, and
    /// reply on the command's oneshot. Returns `true` when the receive loop should
    /// stop.
    ///
    /// Bespoke rather than the generic helper because every DHCP verb yields
    /// `ClientActionResult::Custom` and the destination is a property of the action
    /// (its `broadcast` flag), not of a write half.
    async fn handle_injected_command(
        command: ClientCommand,
        socket: &Arc<UdpSocket>,
        unicast_target: SocketAddr,
        protocol: &Arc<DhcpClientProtocol>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> bool {
        use crate::llm::actions::protocol_trait::Protocol;

        let action = command.action.clone();
        let outcome = match protocol.as_ref().execute_action(action.clone()) {
            Err(e) => Ok(ClientSendOutcome::Rejected {
                error: e.to_string(),
            }),
            Ok(result) => Self::apply_action_result(result, socket, unicast_target, client_id)
                .await
                .map(|applied| match applied {
                    Applied::Sent(bytes_sent) => ClientSendOutcome::Sent { bytes_sent },
                    Applied::Executed(detail) => ClientSendOutcome::Executed { detail },
                    Applied::Disconnect => ClientSendOutcome::Disconnected,
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
            error!("DHCP client {} injected action failed: {}", client_id, e);
            let _ = status_tx.send(format!(
                "[WARN] Client {} injected action failed: {}",
                client_id, e
            ));
        }
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        crate::client::command_support::reply(command, outcome);
        disconnect
    }

    fn build_discover_packet(params: &serde_json::Value) -> Result<Vec<u8>> {
        use dhcproto::Encodable;
        use std::net::Ipv4Addr;

        // Generate random transaction ID
        let xid = rand::random::<u32>();

        // Get MAC address from params or generate random one
        let mac_str = params
            .get("mac_address")
            .and_then(|v| v.as_str())
            .unwrap_or("00:00:00:00:00:00");

        let chaddr = Self::parse_mac_address(mac_str)?;

        // Build DHCP DISCOVER
        let mut msg = v4::Message::default();
        msg.set_opcode(v4::Opcode::BootRequest)
            .set_xid(xid)
            .set_flags(v4::Flags::default().set_broadcast())
            .set_chaddr(&chaddr);

        // Add DHCP options
        msg.opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));

        // Optional: requested IP
        if let Some(requested_ip) = params.get("requested_ip").and_then(|v| v.as_str()) {
            if let Ok(ip) = requested_ip.parse::<Ipv4Addr>() {
                msg.opts_mut()
                    .insert(v4::DhcpOption::RequestedIpAddress(ip));
            }
        }

        // Encode to bytes
        let bytes = msg.to_vec()?;
        Ok(bytes)
    }

    fn build_request_packet(params: &serde_json::Value) -> Result<Vec<u8>> {
        use dhcproto::Encodable;
        use std::net::Ipv4Addr;

        // Generate random transaction ID
        let xid = rand::random::<u32>();

        // Get MAC address
        let mac_str = params
            .get("mac_address")
            .and_then(|v| v.as_str())
            .unwrap_or("00:00:00:00:00:00");

        let chaddr = Self::parse_mac_address(mac_str)?;

        // Get requested IP (required for REQUEST)
        let requested_ip = params
            .get("requested_ip")
            .and_then(|v| v.as_str())
            .context("Missing 'requested_ip' parameter")?
            .parse::<Ipv4Addr>()?;

        // Get server IP (optional)
        let server_ip = params
            .get("server_ip")
            .and_then(|v| v.as_str())
            .map(|s| s.parse::<Ipv4Addr>())
            .transpose()?;

        // Build DHCP REQUEST
        let mut msg = v4::Message::default();
        msg.set_opcode(v4::Opcode::BootRequest)
            .set_xid(xid)
            .set_flags(v4::Flags::default().set_broadcast())
            .set_chaddr(&chaddr);

        // Add DHCP options
        msg.opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Request));
        msg.opts_mut()
            .insert(v4::DhcpOption::RequestedIpAddress(requested_ip));

        if let Some(server) = server_ip {
            msg.opts_mut()
                .insert(v4::DhcpOption::ServerIdentifier(server));
        }

        // Encode to bytes
        let bytes = msg.to_vec()?;
        Ok(bytes)
    }

    fn build_inform_packet(params: &serde_json::Value) -> Result<Vec<u8>> {
        use dhcproto::Encodable;
        use std::net::Ipv4Addr;

        // Generate random transaction ID
        let xid = rand::random::<u32>();

        // Get MAC address
        let mac_str = params
            .get("mac_address")
            .and_then(|v| v.as_str())
            .unwrap_or("00:00:00:00:00:00");

        let chaddr = Self::parse_mac_address(mac_str)?;

        // Get current IP (required for INFORM)
        let current_ip = params
            .get("current_ip")
            .and_then(|v| v.as_str())
            .context("Missing 'current_ip' parameter")?
            .parse::<Ipv4Addr>()?;

        // Build DHCP INFORM
        let mut msg = v4::Message::default();
        msg.set_opcode(v4::Opcode::BootRequest)
            .set_xid(xid)
            .set_ciaddr(current_ip) // Set client IP address
            .set_chaddr(&chaddr);

        // Add DHCP options
        msg.opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Inform));

        // Encode to bytes
        let bytes = msg.to_vec()?;
        Ok(bytes)
    }

    fn parse_mac_address(mac_str: &str) -> Result<Vec<u8>> {
        let parts: Vec<&str> = mac_str.split(':').collect();
        if parts.len() != 6 {
            anyhow::bail!("Invalid MAC address format: {}", mac_str);
        }

        let mut mac = Vec::with_capacity(16); // DHCP chaddr is 16 bytes
        for part in parts {
            let byte = u8::from_str_radix(part, 16).context("Invalid hex in MAC address")?;
            mac.push(byte);
        }

        // Pad to 16 bytes (DHCP chaddr field)
        while mac.len() < 16 {
            mac.push(0);
        }

        Ok(mac)
    }

    fn parse_dhcp_response(data: &[u8]) -> Option<(String, serde_json::Value)> {
        use std::net::Ipv4Addr;

        match v4::Message::decode(&mut Decoder::new(data)) {
            Ok(msg) => {
                // `hlen` is read straight off the wire without validation, and
                // `Message::chaddr()` slices a fixed [u8; 16] with it - a datagram
                // declaring hlen > 16 panics inside dhcproto. This is the client's
                // receive path, so a malicious or merely broken DHCP server could
                // take the client task down. Reject instead. Mirrors the server-side
                // guard in src/server/dhcp/mod.rs.
                if msg.hlen() as usize > 16 {
                    tracing::warn!(
                        "Dropping DHCP response with invalid hlen {} (max 16)",
                        msg.hlen()
                    );
                    return None;
                }

                // Extract message type
                let message_type = msg.opts().get(v4::OptionCode::MessageType).and_then(|opt| {
                    if let v4::DhcpOption::MessageType(mt) = opt {
                        Some(*mt)
                    } else {
                        None
                    }
                });

                let message_type_str = message_type
                    .as_ref()
                    .map(|mt| format!("{:?}", mt))
                    .unwrap_or_else(|| "Unknown".to_string());

                // Extract key fields
                let offered_ip = msg.yiaddr();
                let server_ip = msg
                    .opts()
                    .get(v4::OptionCode::ServerIdentifier)
                    .and_then(|opt| {
                        if let v4::DhcpOption::ServerIdentifier(ip) = opt {
                            Some(*ip)
                        } else {
                            None
                        }
                    });

                let subnet_mask = msg.opts().get(v4::OptionCode::SubnetMask).and_then(|opt| {
                    if let v4::DhcpOption::SubnetMask(mask) = opt {
                        Some(*mask)
                    } else {
                        None
                    }
                });

                let router = msg.opts().get(v4::OptionCode::Router).and_then(|opt| {
                    if let v4::DhcpOption::Router(routers) = opt {
                        routers.first().copied()
                    } else {
                        None
                    }
                });

                let dns_servers =
                    msg.opts()
                        .get(v4::OptionCode::DomainNameServer)
                        .and_then(|opt| {
                            if let v4::DhcpOption::DomainNameServer(dns) = opt {
                                Some(dns.clone())
                            } else {
                                None
                            }
                        });

                let lease_time = msg
                    .opts()
                    .get(v4::OptionCode::AddressLeaseTime)
                    .and_then(|opt| {
                        if let v4::DhcpOption::AddressLeaseTime(time) = opt {
                            Some(*time)
                        } else {
                            None
                        }
                    });

                // Build details JSON
                let mut details = serde_json::json!({
                    "transaction_id": format!("0x{:08x}", msg.xid()),
                    "client_mac": hex::encode(msg.chaddr())
                });

                if offered_ip != Ipv4Addr::UNSPECIFIED {
                    details["offered_ip"] = serde_json::json!(offered_ip.to_string());
                }

                if let Some(server) = server_ip {
                    details["server_ip"] = serde_json::json!(server.to_string());
                }

                if let Some(mask) = subnet_mask {
                    details["subnet_mask"] = serde_json::json!(mask.to_string());
                }

                if let Some(gw) = router {
                    details["router"] = serde_json::json!(gw.to_string());
                }

                if let Some(dns) = dns_servers {
                    let dns_strs: Vec<String> = dns.iter().map(|ip| ip.to_string()).collect();
                    details["dns_servers"] = serde_json::json!(dns_strs);
                }

                if let Some(lease) = lease_time {
                    details["lease_time"] = serde_json::json!(lease);
                }

                Some((message_type_str, details))
            }
            Err(e) => {
                tracing::warn!("Failed to parse DHCP response: {}", e);
                None
            }
        }
    }
}

//! TURN client implementation
pub mod actions;

pub use actions::TurnClientProtocol;

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::turn::actions::{
    TURN_CLIENT_ALLOCATED_EVENT, TURN_CLIENT_CONNECTED_EVENT, TURN_CLIENT_DATA_RECEIVED_EVENT,
    TURN_CLIENT_PERMISSION_CREATED_EVENT, TURN_CLIENT_REFRESHED_EVENT,
};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

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
    queued_events: Vec<Event>,
    memory: String,
    relay_address: Option<SocketAddr>,
    /// Transaction ID (hex) -> the peer a CreatePermission request named.
    ///
    /// A CreatePermission Success Response carries no XOR-PEER-ADDRESS — RFC 8656
    /// section 9.4 says it is empty — so the only way to know which peer was
    /// permitted is to remember what we asked for. Without this the
    /// `turn_permission_created` event reported `"peer_address": "unknown"` on a
    /// field its own declaration marks `required: true`, i.e. a fabricated
    /// constant where the model expected a fact.
    ///
    /// Bounded at `MAX_PENDING_PERMISSIONS` so a model issuing create_permission
    /// in a loop cannot grow it without limit; a request evicted early simply
    /// reports the peer as unknown again, which is the old behaviour and no worse.
    pending_permissions: HashMap<String, SocketAddr>,
}

/// Cap on outstanding CreatePermission requests remembered for correlation.
const MAX_PENDING_PERMISSIONS: usize = 256;

/// TURN client that connects to a remote TURN server
pub struct TurnClient;

impl TurnClient {
    /// Connect to a TURN server with integrated LLM actions
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
            .context(format!("Invalid TURN server address: {}", remote_addr))?;

        // Create UDP socket (TURN uses UDP transport)
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket")?;

        let local_addr = socket.local_addr()?;

        info!(
            "TURN client {} bound to {} (server: {})",
            client_id, local_addr, remote_sock_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        Log::new(Some(&status_tx)).info(format!(
            "TURN client {} connected to {}",
            client_id, remote_sock_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Send initial connected event to LLM
        let protocol = Arc::new(crate::client::turn::actions::TurnClientProtocol::new());
        let event = Event::new(
            &TURN_CLIENT_CONNECTED_EVENT,
            serde_json::json!({
                "remote_addr": remote_sock_addr.to_string(),
            }),
        );

        let socket_arc = Arc::new(socket);

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            state: ConnectionState::Idle,
            queued_events: Vec::new(),
            memory: String::new(),
            relay_address: None,
            pending_permissions: HashMap::new(),
        }));

        // Command channel for injected actions (the dashboard's [ send ]).
        // Registered BEFORE the connected-event LLM call: a manual `*` routing rule can
        // park that call for minutes, and the operator must be able to reach the client
        // while it waits. It gets its own task rather than a `select!` arm in the read
        // loop, so an injected Allocate/Send does not queue behind an in-flight LLM call;
        // the socket is an `Arc<UdpSocket>` and `send_to` takes `&self`, so both tasks can
        // write to it.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            socket_arc.clone(),
            remote_sock_addr,
            protocol.clone(),
            client_data.clone(),
            client_id,
            app_state.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                "",
                Some(&event),
                protocol.as_ref(),
                &status_tx,
            )
            .await
            {
                Ok(result) => {
                    debug!(
                        "TURN client {} initial LLM call returned {} actions",
                        client_id,
                        result.actions.len()
                    );

                    // Run them. They were counted, logged and dropped, so a client told
                    // to "connect and allocate a relay" connected and then sat there --
                    // nothing ever reached the socket, and the server saw no request at
                    // all. They go through `handle_action_result`, the same function the
                    // read loop and the injected-command path use, so the wire encoding
                    // exists once.
                    use crate::llm::actions::client_trait::Client;
                    for action in result.actions {
                        let executed = match protocol.as_ref().execute_action(action) {
                            Ok(executed) => executed,
                            Err(e) => {
                                error!("TURN client {} rejected action: {}", client_id, e);
                                continue;
                            }
                        };
                        if let Err(e) = Self::handle_action_result(
                            executed,
                            &socket_arc,
                            remote_sock_addr,
                            &client_data,
                            &status_tx,
                            client_id,
                        )
                        .await
                        {
                            error!("TURN client {} initial action failed: {}", client_id, e);
                        }
                    }
                }
                Err(e) => {
                    error!("TURN client {} initial LLM call failed: {}", client_id, e);
                }
            }
        }

        // Spawn read loop for receiving TURN responses
        let socket_clone = socket_arc.clone();
        let llm_clone = llm_client.clone();
        let app_state_clone = app_state.clone();
        let status_clone = status_tx.clone();
        let client_data_clone = client_data.clone();
        let protocol_clone = protocol.clone();

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 2048]; // TURN messages typically < 2KB

            loop {
                match socket_clone.recv_from(&mut buffer).await {
                    Ok((n, peer_addr)) => {
                        let data = buffer[..n].to_vec();
                        trace!(
                            "TURN client {} received {} bytes from {}",
                            client_id,
                            n,
                            peer_addr
                        );

                        // Parse TURN/STUN message
                        let (transaction_id, message_type, _is_valid) =
                            Self::parse_turn_header(&data);

                        let transaction_id_hex = transaction_id
                            .map(|tid| hex::encode(tid))
                            .unwrap_or_default();

                        debug!(
                            "TURN client {} received {} (transaction: {})",
                            client_id, message_type, transaction_id_hex
                        );

                        // Determine event based on message type
                        let event = match message_type.as_str() {
                            "AllocateResponse" => {
                                // Extract relay address from XOR-RELAYED-ADDRESS attribute
                                if let Some(relay_addr) = Self::extract_xor_relayed_address(&data) {
                                    let lifetime = Self::extract_lifetime(&data).unwrap_or(600);

                                    // Store relay address
                                    client_data_clone.lock().await.relay_address = Some(relay_addr);

                                    // Also on the client record, so the relay this
                                    // allocation actually got is visible to the dashboard,
                                    // to MCP and to anything reading `protocol_data`. It
                                    // used to live only in this task's private `ClientData`,
                                    // where nothing outside the read loop could see it —
                                    // which is also why no test could observe whether the
                                    // response had been parsed at all.
                                    app_state_clone
                                        .with_client_mut(client_id, |client| {
                                            client.set_protocol_field(
                                                "relay_address".to_string(),
                                                serde_json::json!(relay_addr.to_string()),
                                            );
                                        })
                                        .await;

                                    Some(Event::new(
                                        &TURN_CLIENT_ALLOCATED_EVENT,
                                        serde_json::json!({
                                            "relay_address": relay_addr.to_string(),
                                            "lifetime_seconds": lifetime,
                                            "transaction_id": transaction_id_hex,
                                        }),
                                    ))
                                } else {
                                    None
                                }
                            }
                            "RefreshResponse" => {
                                let lifetime = Self::extract_lifetime(&data).unwrap_or(600);
                                Some(Event::new(
                                    &TURN_CLIENT_REFRESHED_EVENT,
                                    serde_json::json!({
                                        "lifetime_seconds": lifetime,
                                    }),
                                ))
                            }
                            "CreatePermissionResponse" => {
                                // RFC 8656 section 9.4: the Success Response is empty, so
                                // the peer is recovered from the transaction ID we recorded
                                // when the request went out. This used to report the literal
                                // string "unknown" for a field declared `required: true`.
                                let peer_address = client_data_clone
                                    .lock()
                                    .await
                                    .pending_permissions
                                    .remove(&transaction_id_hex);

                                match peer_address {
                                    Some(peer) => Some(Event::new(
                                        &TURN_CLIENT_PERMISSION_CREATED_EVENT,
                                        serde_json::json!({
                                            "peer_address": peer.to_string(),
                                            "transaction_id": transaction_id_hex,
                                        }),
                                    )),
                                    None => {
                                        // Nothing we sent matches this transaction ID, so
                                        // either it is a stray or a forgery. Raising the
                                        // event with a made-up peer would tell the model a
                                        // permission exists that it never asked for.
                                        warn!(
                                            "TURN client {} ignoring CreatePermission response \
                                             for unknown transaction {}",
                                            client_id, transaction_id_hex
                                        );
                                        None
                                    }
                                }
                            }
                            "DataIndication" => {
                                // Extract peer address and data from DATA and XOR-PEER-ADDRESS
                                if let (Some(peer_addr), Some(relay_data)) = (
                                    Self::extract_xor_peer_address(&data),
                                    Self::extract_data_attribute(&data),
                                ) {
                                    Some(Event::new(
                                        &TURN_CLIENT_DATA_RECEIVED_EVENT,
                                        serde_json::json!({
                                            "peer_address": peer_addr.to_string(),
                                            "data_hex": hex::encode(&relay_data),
                                            "data_length": relay_data.len(),
                                        }),
                                    ))
                                } else {
                                    None
                                }
                            }
                            "AllocateError" | "RefreshError" | "CreatePermissionError" => {
                                let error_code = Self::extract_error_code(&data).unwrap_or(400);
                                Log::new(Some(&status_clone)).error(format!(
                                    "TURN client {} received error: {} (code: {})",
                                    client_id, message_type, error_code
                                ));
                                None
                            }
                            _ => {
                                debug!(
                                    "TURN client {} ignoring message type: {}",
                                    client_id, message_type
                                );
                                None
                            }
                        };

                        if let Some(event) = event {
                            // Handle event with LLM
                            let mut client_data_lock = client_data_clone.lock().await;

                            match client_data_lock.state {
                                ConnectionState::Idle => {
                                    // Process immediately
                                    client_data_lock.state = ConnectionState::Processing;
                                    drop(client_data_lock);

                                    // Call LLM
                                    if let Some(instruction) =
                                        app_state_clone.get_instruction_for_client(client_id).await
                                    {
                                        // Copy the memory out and drop the guard BEFORE the
                                        // call. `&client_data_clone.lock().await.memory` as a
                                        // match scrutinee kept the guard alive for the whole
                                        // round-trip *and* the whole arm, so the re-lock in
                                        // the Ok arm below deadlocked this read loop against
                                        // itself on a non-reentrant tokio Mutex. It never
                                        // fired only because `memory_updates` is currently
                                        // hardcoded `None` in `action_helper` — a latent hang
                                        // waiting on an unrelated feature being finished.
                                        let memory = client_data_clone.lock().await.memory.clone();
                                        match call_llm_for_client(
                                            &llm_clone,
                                            &app_state_clone,
                                            client_id.to_string(),
                                            &instruction,
                                            &memory,
                                            Some(&event),
                                            protocol_clone.as_ref(),
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

                                                // Execute actions
                                                for action in actions {
                                                    use crate::llm::actions::client_trait::Client;
                                                    match protocol_clone
                                                        .as_ref()
                                                        .execute_action(action)
                                                    {
                                                        Ok(action_result) => {
                                                            match Self::handle_action_result(
                                                                action_result,
                                                                &socket_clone,
                                                                remote_sock_addr,
                                                                &client_data_clone,
                                                                &status_clone,
                                                                client_id,
                                                            )
                                                            .await
                                                            {
                                                                Ok(outcome) => debug!(
                                                                    "TURN client {} action outcome: {:?}",
                                                                    client_id, outcome
                                                                ),
                                                                Err(e) => error!("TURN client {} action execution failed: {}", client_id, e),
                                                            }
                                                        }
                                                        Err(e) => {
                                                            error!("TURN client {} action parsing failed: {}", client_id, e);
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                error!(
                                                    "LLM error for TURN client {}: {}",
                                                    client_id, e
                                                );
                                            }
                                        }
                                    }

                                    // Process queued events if any
                                    let mut client_data_lock = client_data_clone.lock().await;
                                    if !client_data_lock.queued_events.is_empty() {
                                        client_data_lock.queued_events.clear();
                                    }
                                    client_data_lock.state = ConnectionState::Idle;
                                }
                                ConnectionState::Processing => {
                                    // Queue event
                                    client_data_lock.queued_events.push(event);
                                    client_data_lock.state = ConnectionState::Accumulating;
                                }
                                ConnectionState::Accumulating => {
                                    // Continue queuing
                                    client_data_lock.queued_events.push(event);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("TURN client {} read error: {}", client_id, e);
                        app_state_clone
                            .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                            .await;
                        let _ = status_clone.send("__UPDATE_UI__".to_string());
                        break;
                    }
                }
            }
            // Every exit path lands here: drop the command handle so the dashboard stops
            // offering [ send ] on a dead client. This also closes the command channel,
            // which ends `command_loop`.
            app_state_clone.remove_client_handle(client_id).await;
            let _ = status_clone.send("__UPDATE_UI__".to_string());
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }

    /// Drain injected commands until the channel closes (client removed, or the read loop
    /// exited and dropped the handle) or an injected `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot run this client's
    /// vocabulary - every TURN verb yields `ClientActionResult::Custom` and has to be encoded
    /// as a STUN/TURN message - so the action goes through [`Self::handle_action_result`],
    /// the same function the LLM path uses, and the outcome is recorded and replied exactly
    /// the way the generic arm does it.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        protocol: Arc<TurnClientProtocol>,
        client_data: Arc<Mutex<ClientData>>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::client_trait::Client;
        use crate::llm::actions::protocol_trait::Protocol;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.as_ref().execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(action_result) => {
                    Self::handle_action_result(
                        action_result,
                        &socket,
                        remote_addr,
                        &client_data,
                        &status_tx,
                        client_id,
                    )
                    .await
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
                    "TURN client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                // The Refresh(lifetime=0) that deletes the allocation has already gone out
                // (that is what `handle_action_result` does for Disconnect). TURN runs over
                // an unconnected UDP socket, so there is nothing further to close: stop
                // accepting commands, drop the handle and mark the client disconnected. The
                // recv loop's socket is released when the client is removed (`stop_client`
                // aborts both registered tasks).
                app_state.remove_client_handle(client_id).await;
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }
        }
    }

    /// Encode one executed action as a TURN message and put it on the wire.
    ///
    /// Shared by the LLM path and injected commands so the STUN/TURN encoding exists exactly
    /// once. The returned [`ClientSendOutcome`] reports what actually reached the wire:
    /// `Sent` carries the real datagram length, `Executed` means the result produced no TURN
    /// message, and `Err` means the datagram could not be built or sent.
    async fn handle_action_result(
        action_result: crate::llm::actions::client_trait::ClientActionResult,
        socket: &Arc<UdpSocket>,
        remote_addr: SocketAddr,
        client_data: &Arc<Mutex<ClientData>>,
        status_tx: &mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<ClientSendOutcome> {
        use crate::llm::actions::client_trait::ClientActionResult;

        match action_result {
            ClientActionResult::Custom { name, data } => match name.as_str() {
                "allocate" => {
                    let lifetime = data
                        .get("lifetime_seconds")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(600);

                    let message = Self::build_allocate_request(
                        u32::try_from(lifetime).context("TURN lifetime exceeds u32")?,
                    )?;
                    let sent = socket.send_to(&message, remote_addr).await?;

                    Log::new(Some(status_tx)).debug(format!(
                        "TURN client {} sent Allocate request (lifetime: {}s)",
                        client_id, lifetime
                    ));
                    Ok(ClientSendOutcome::Sent { bytes_sent: sent })
                }
                "create_permission" => {
                    let peer_address = data
                        .get("peer_address")
                        .and_then(|v| v.as_str())
                        .context("Missing peer_address")?;

                    let peer_addr: SocketAddr =
                        peer_address.parse().context("Invalid peer_address")?;

                    let (message, transaction_id) =
                        Self::build_create_permission_request(peer_addr)?;

                    // Remember the peer before the datagram leaves, so a fast
                    // response cannot arrive at the read loop first and find
                    // nothing to correlate against.
                    {
                        let mut state = client_data.lock().await;
                        if state.pending_permissions.len() >= MAX_PENDING_PERMISSIONS {
                            state.pending_permissions.clear();
                        }
                        state.pending_permissions.insert(transaction_id, peer_addr);
                    }

                    let sent = socket.send_to(&message, remote_addr).await?;

                    Log::new(Some(status_tx)).debug(format!(
                        "TURN client {} sent CreatePermission for {}",
                        client_id, peer_addr
                    ));
                    Ok(ClientSendOutcome::Sent { bytes_sent: sent })
                }
                "send_indication" => {
                    let peer_address = data
                        .get("peer_address")
                        .and_then(|v| v.as_str())
                        .context("Missing peer_address")?;

                    let peer_addr: SocketAddr =
                        peer_address.parse().context("Invalid peer_address")?;

                    let send_data = data
                        .get("data")
                        .and_then(|v| v.as_array())
                        .map(|arr| crate::client::wire_values::bytes(arr))
                        .context("Missing or invalid data")??;

                    let message = Self::build_send_indication(peer_addr, &send_data)?;
                    let sent = socket.send_to(&message, remote_addr).await?;

                    Log::new(Some(status_tx)).debug(format!(
                        "TURN client {} sent {} bytes via SendIndication to {}",
                        client_id,
                        send_data.len(),
                        peer_addr
                    ));
                    Ok(ClientSendOutcome::Sent { bytes_sent: sent })
                }
                "refresh" => {
                    let lifetime = data
                        .get("lifetime_seconds")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(600);

                    let message = Self::build_refresh_request(
                        u32::try_from(lifetime).context("TURN lifetime exceeds u32")?,
                    )?;
                    let sent = socket.send_to(&message, remote_addr).await?;

                    Log::new(Some(status_tx)).debug(format!(
                        "TURN client {} sent Refresh request (lifetime: {}s)",
                        client_id, lifetime
                    ));
                    Ok(ClientSendOutcome::Sent { bytes_sent: sent })
                }
                other => {
                    debug!("TURN client {} unknown custom action: {}", client_id, other);
                    Ok(ClientSendOutcome::Executed {
                        detail: format!("custom result '{other}' builds no TURN message"),
                    })
                }
            },
            ClientActionResult::Disconnect => {
                // Send Refresh with lifetime=0 to delete allocation
                let message = Self::build_refresh_request(0)?;
                socket.send_to(&message, remote_addr).await?;

                Log::new(Some(status_tx)).info(format!(
                    "TURN client {} disconnecting (sent Refresh with lifetime=0)",
                    client_id
                ));
                Ok(ClientSendOutcome::Disconnected)
            }
            other => Ok(ClientSendOutcome::Executed {
                detail: format!("{other:?} sends no TURN message"),
            }),
        }
    }

    /// Build TURN Allocate Request message
    fn build_allocate_request(lifetime_seconds: u32) -> Result<Vec<u8>> {
        let mut message = Vec::new();

        // STUN message type: Allocate Request (0x0003)
        message.extend_from_slice(&0x0003u16.to_be_bytes());

        // Message length (will update later)
        let length_pos = message.len();
        message.extend_from_slice(&0u16.to_be_bytes());

        // Magic cookie
        message.extend_from_slice(&0x2112A442u32.to_be_bytes());

        // Transaction ID (12 random bytes)
        let transaction_id: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
        message.extend_from_slice(&transaction_id);

        // LIFETIME attribute (0x000D)
        let attr_type = 0x000Du16;
        let attr_length = 4u16;
        message.extend_from_slice(&attr_type.to_be_bytes());
        message.extend_from_slice(&attr_length.to_be_bytes());
        message.extend_from_slice(&lifetime_seconds.to_be_bytes());

        // REQUESTED-TRANSPORT attribute (0x0019) - UDP (17)
        let attr_type = 0x0019u16;
        let attr_length = 4u16;
        message.extend_from_slice(&attr_type.to_be_bytes());
        message.extend_from_slice(&attr_length.to_be_bytes());
        message.push(17); // UDP protocol number
        message.extend_from_slice(&[0, 0, 0]); // Reserved

        // Update message length
        let total_length =
            u16::try_from(message.len() - 20).context("TURN message exceeds u16 length")?;
        message[length_pos..length_pos + 2].copy_from_slice(&total_length.to_be_bytes());

        Ok(message)
    }

    /// Build TURN CreatePermission Request message.
    ///
    /// Returns the message and its transaction ID (hex), because the Success
    /// Response is empty and correlating the reply back to a peer is only
    /// possible if the caller keeps that ID.
    fn build_create_permission_request(peer_addr: SocketAddr) -> Result<(Vec<u8>, String)> {
        let mut message = Vec::new();

        // STUN message type: CreatePermission Request (0x0008)
        message.extend_from_slice(&0x0008u16.to_be_bytes());

        // Message length (will update later)
        let length_pos = message.len();
        message.extend_from_slice(&0u16.to_be_bytes());

        // Magic cookie
        message.extend_from_slice(&0x2112A442u32.to_be_bytes());

        // Transaction ID
        let transaction_id: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
        message.extend_from_slice(&transaction_id);

        // XOR-PEER-ADDRESS attribute (0x0012)
        Self::add_xor_peer_address(&mut message, peer_addr, &transaction_id)?;

        // Update message length
        let total_length =
            u16::try_from(message.len() - 20).context("TURN message exceeds u16 length")?;
        message[length_pos..length_pos + 2].copy_from_slice(&total_length.to_be_bytes());

        Ok((message, hex::encode(&transaction_id)))
    }

    /// Build TURN SendIndication message
    fn build_send_indication(peer_addr: SocketAddr, data: &[u8]) -> Result<Vec<u8>> {
        let mut message = Vec::new();

        // STUN message type: SendIndication (0x0016)
        message.extend_from_slice(&0x0016u16.to_be_bytes());

        // Message length (will update later)
        let length_pos = message.len();
        message.extend_from_slice(&0u16.to_be_bytes());

        // Magic cookie
        message.extend_from_slice(&0x2112A442u32.to_be_bytes());

        // Transaction ID
        let transaction_id: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
        message.extend_from_slice(&transaction_id);

        // XOR-PEER-ADDRESS attribute (0x0012)
        Self::add_xor_peer_address(&mut message, peer_addr, &transaction_id)?;

        // DATA attribute (0x0013)
        let attr_type = 0x0013u16;
        let attr_length = u16::try_from(data.len()).context("TURN data exceeds u16 length")?;
        message.extend_from_slice(&attr_type.to_be_bytes());
        message.extend_from_slice(&attr_length.to_be_bytes());
        message.extend_from_slice(data);

        // Add padding if needed (attributes must be 4-byte aligned)
        let padding = (4 - (data.len() % 4)) % 4;
        message.extend_from_slice(&vec![0u8; padding]);

        // Update message length
        let total_length =
            u16::try_from(message.len() - 20).context("TURN message exceeds u16 length")?;
        message[length_pos..length_pos + 2].copy_from_slice(&total_length.to_be_bytes());

        Ok(message)
    }

    /// Build TURN Refresh Request message
    fn build_refresh_request(lifetime_seconds: u32) -> Result<Vec<u8>> {
        let mut message = Vec::new();

        // STUN message type: Refresh Request (0x0004)
        message.extend_from_slice(&0x0004u16.to_be_bytes());

        // Message length (will update later)
        let length_pos = message.len();
        message.extend_from_slice(&0u16.to_be_bytes());

        // Magic cookie
        message.extend_from_slice(&0x2112A442u32.to_be_bytes());

        // Transaction ID
        let transaction_id: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
        message.extend_from_slice(&transaction_id);

        // LIFETIME attribute (0x000D)
        let attr_type = 0x000Du16;
        let attr_length = 4u16;
        message.extend_from_slice(&attr_type.to_be_bytes());
        message.extend_from_slice(&attr_length.to_be_bytes());
        message.extend_from_slice(&lifetime_seconds.to_be_bytes());

        // Update message length
        let total_length =
            u16::try_from(message.len() - 20).context("TURN message exceeds u16 length")?;
        message[length_pos..length_pos + 2].copy_from_slice(&total_length.to_be_bytes());

        Ok(message)
    }

    /// Add XOR-PEER-ADDRESS attribute to message
    fn add_xor_peer_address(
        message: &mut Vec<u8>,
        peer_addr: SocketAddr,
        transaction_id: &[u8],
    ) -> Result<()> {
        let attr_type = 0x0012u16;

        match peer_addr {
            SocketAddr::V4(addr) => {
                let attr_length = 8u16; // Family (2) + Port (2) + IPv4 (4)
                message.extend_from_slice(&attr_type.to_be_bytes());
                message.extend_from_slice(&attr_length.to_be_bytes());

                // Reserved byte + Family (0x01 for IPv4)
                message.push(0x00);
                message.push(0x01);

                // X-Port (port XOR'd with most significant 16 bits of magic cookie)
                let port = addr.port();
                let xor_port = port ^ 0x2112;
                message.extend_from_slice(&xor_port.to_be_bytes());

                // X-Address (IP XOR'd with magic cookie)
                let ip_bytes = addr.ip().octets();
                let magic_cookie = 0x2112A442u32.to_be_bytes();
                for i in 0..4 {
                    message.push(ip_bytes[i] ^ magic_cookie[i]);
                }
            }
            SocketAddr::V6(addr) => {
                let attr_length = 20u16; // Family (2) + Port (2) + IPv6 (16)
                message.extend_from_slice(&attr_type.to_be_bytes());
                message.extend_from_slice(&attr_length.to_be_bytes());

                // Reserved byte + Family (0x02 for IPv6)
                message.push(0x00);
                message.push(0x02);

                // X-Port
                let port = addr.port();
                let xor_port = port ^ 0x2112;
                message.extend_from_slice(&xor_port.to_be_bytes());

                // X-Address (IPv6 XOR'd with magic cookie + transaction ID)
                let ip_bytes = addr.ip().octets();
                let magic_cookie = 0x2112A442u32.to_be_bytes();

                for i in 0..4 {
                    message.push(ip_bytes[i] ^ magic_cookie[i]);
                }
                for i in 4..16 {
                    message.push(ip_bytes[i] ^ transaction_id[i - 4]);
                }
            }
        }

        Ok(())
    }

    /// Parse TURN/STUN message header (similar to server implementation)
    fn parse_turn_header(data: &[u8]) -> (Option<Vec<u8>>, String, bool) {
        if data.len() < 20 {
            return (None, "invalid".to_string(), false);
        }

        // Check magic cookie
        let magic_cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if magic_cookie != 0x2112A442 {
            return (None, "invalid".to_string(), false);
        }

        // Extract message type
        let message_type_raw = u16::from_be_bytes([data[0], data[1]]);

        // RFC 8489 section 5: the 14-bit type interleaves method and class as
        //   0b00 M11 M10 M9 M8 M7 C1 M6 M5 M4 C0 M3 M2 M1 M0
        // so C0 is bit 4, C1 is bit 8, and class == C1<<1 | C0.
        //
        // This used to read `((raw & 0x0110) >> 4) | ((raw & 0x0100) >> 7)`, which
        // shifts bit 8 by 4 rather than 8 and works out to C0 + 18*C1. Every class
        // with C1 set therefore decoded to 18 or 19 and fell through the table
        // below to "Unknown". Since a *client* receives nothing but responses and
        // indications, that meant this client could not parse a single reply: an
        // Allocate success (0x0103) decoded to 18, `relay_address` was never
        // stored, and turn_allocated / turn_refreshed / turn_permission_created /
        // turn_data_received could not fire however correct the server was. The
        // sibling server has this right (`src/server/turn/mod.rs`); the two
        // disagreed, and the client was the wrong one.
        //
        // The table below was wrong to match: it expected class 1 for a success
        // response and 2 for an error, which are the *indication* and *success*
        // values. Both are corrected together, because fixing either alone leaves
        // the client just as deaf.
        let c0 = (message_type_raw >> 4) & 0x1;
        let c1 = (message_type_raw >> 8) & 0x1;
        let class = (c1 << 1) | c0;
        let method = (message_type_raw & 0x000F)
            | ((message_type_raw & 0x00E0) >> 1)
            | ((message_type_raw & 0x3E00) >> 2);

        // Class: 0 = request, 1 = indication, 2 = success response, 3 = error.
        let message_type = match (class, method) {
            (0, 3) => "AllocateRequest",
            (2, 3) => "AllocateResponse",
            (3, 3) => "AllocateError",
            (0, 4) => "RefreshRequest",
            (2, 4) => "RefreshResponse",
            (3, 4) => "RefreshError",
            (0, 8) => "CreatePermissionRequest",
            (2, 8) => "CreatePermissionResponse",
            (3, 8) => "CreatePermissionError",
            (1, 6) => "SendIndication",
            (1, 7) => "DataIndication",
            _ => "Unknown",
        };

        let transaction_id = data[8..20].to_vec();

        (Some(transaction_id), message_type.to_string(), true)
    }

    /// Walk the attributes of a STUN/TURN message, bounded by what actually arrived.
    ///
    /// **This is the only place attribute offsets are computed.** Four hand-rolled
    /// copies of this walk used to exist — one each in `extract_xor_address`,
    /// `extract_lifetime`, `extract_data_attribute` and `extract_error_code` — and
    /// every one of them bounded the cursor against `20 + message_length`, a
    /// 16-bit field the sender chooses, while indexing a buffer capped at 2048
    /// bytes. Twenty bytes on the wire —
    /// `00 07 FF FF 21 12 A4 42 <12-byte transaction id>` — index `data[20]` on a
    /// 20-byte slice and **panic**. `tokio::spawn` swallows that panic, so the
    /// read loop died silently while `AppState` went on reporting the client
    /// `Connected` and the dashboard went on offering `[ send ]`: permanently deaf,
    /// with nothing in the UI to say so. The socket is bound to `0.0.0.0:0` and the
    /// loop never checks that a datagram came from the TURN server, so any host
    /// that could reach the ephemeral port could send it.
    ///
    /// The rule, which the sibling server already followed, is to trust the
    /// shorter of the declared length and what arrived.
    fn attributes(data: &[u8]) -> Vec<(u16, &[u8])> {
        if data.len() < 20 {
            return Vec::new();
        }

        let declared = u16::from_be_bytes([data[2], data[3]]) as usize;
        let end = 20usize.saturating_add(declared).min(data.len());

        let mut attributes = Vec::new();
        let mut pos = 20usize;
        while pos + 4 <= end {
            let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let value_start = pos + 4;
            let value_end = match value_start.checked_add(attr_len) {
                Some(v) if v <= end => v,
                // Truncated or lying length: stop, keep what we parsed.
                _ => break,
            };
            attributes.push((attr_type, &data[value_start..value_end]));

            // Attributes are padded to a 4-byte boundary. A zero-length attribute
            // still advances by the 4-byte header, so this cannot spin.
            let padded = attr_len.saturating_add(3) & !3usize;
            pos = match value_start.checked_add(padded) {
                Some(p) => p,
                None => break,
            };
        }
        attributes
    }

    /// First attribute of `attr_type`, if present.
    fn attribute<'a>(data: &'a [u8], attr_type: u16) -> Option<&'a [u8]> {
        Self::attributes(data)
            .into_iter()
            .find(|(t, _)| *t == attr_type)
            .map(|(_, v)| v)
    }

    /// Extract XOR-RELAYED-ADDRESS attribute from TURN message
    fn extract_xor_relayed_address(data: &[u8]) -> Option<SocketAddr> {
        Self::extract_xor_address(data, 0x0016) // XOR-RELAYED-ADDRESS = 0x0016
    }

    /// Extract XOR-PEER-ADDRESS attribute from TURN message
    fn extract_xor_peer_address(data: &[u8]) -> Option<SocketAddr> {
        Self::extract_xor_address(data, 0x0012) // XOR-PEER-ADDRESS = 0x0012
    }

    /// Extract XOR'd address attribute from TURN message
    fn extract_xor_address(data: &[u8], attr_type: u16) -> Option<SocketAddr> {
        let attr_data = Self::attribute(data, attr_type)?;
        if attr_data.len() < 4 {
            return None;
        }

        let family = attr_data[1];
        let xor_port = u16::from_be_bytes([attr_data[2], attr_data[3]]);
        let port = xor_port ^ 0x2112;

        match family {
            0x01 => {
                // IPv4
                if attr_data.len() < 8 {
                    return None;
                }

                let magic_cookie = 0x2112A442u32.to_be_bytes();
                let xor_ip = &attr_data[4..8];
                let ip_bytes = [
                    xor_ip[0] ^ magic_cookie[0],
                    xor_ip[1] ^ magic_cookie[1],
                    xor_ip[2] ^ magic_cookie[2],
                    xor_ip[3] ^ magic_cookie[3],
                ];

                let ip = std::net::Ipv4Addr::from(ip_bytes);
                Some(SocketAddr::from((ip, port)))
            }
            0x02 => {
                // IPv6
                if attr_data.len() < 20 {
                    return None;
                }

                let magic_cookie = 0x2112A442u32.to_be_bytes();
                let transaction_id = &data[8..20];
                let xor_ip = &attr_data[4..20];

                let mut ip_bytes = [0u8; 16];
                for i in 0..4 {
                    ip_bytes[i] = xor_ip[i] ^ magic_cookie[i];
                }
                for i in 4..16 {
                    ip_bytes[i] = xor_ip[i] ^ transaction_id[i - 4];
                }

                let ip = std::net::Ipv6Addr::from(ip_bytes);
                Some(SocketAddr::from((ip, port)))
            }
            _ => None,
        }
    }

    /// Extract LIFETIME attribute from TURN message
    fn extract_lifetime(data: &[u8]) -> Option<u32> {
        let value = Self::attribute(data, 0x000D)?;
        if value.len() < 4 {
            return None;
        }
        Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }

    /// Extract DATA attribute from TURN message
    fn extract_data_attribute(data: &[u8]) -> Option<Vec<u8>> {
        Self::attribute(data, 0x0013).map(|v| v.to_vec())
    }

    /// Extract ERROR-CODE attribute from TURN message
    ///
    /// RFC 8489 section 14.8: two reserved bytes, then a 3-bit class and a
    /// number 0-99.
    fn extract_error_code(data: &[u8]) -> Option<u16> {
        let value = Self::attribute(data, 0x0009)?;
        if value.len() < 4 {
            return None;
        }
        let class = (value[2] & 0x07) as u16;
        let number = value[3] as u16;
        Some(class * 100 + number)
    }
}

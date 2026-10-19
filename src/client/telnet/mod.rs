//! Telnet client implementation with option negotiation
pub mod actions;

pub use actions::TelnetClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::telnet::actions::{
    TELNET_CLIENT_CONNECTED_EVENT, TELNET_CLIENT_DATA_RECEIVED_EVENT,
};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::patterns;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// Telnet protocol constants
const IAC: u8 = 255; // Interpret As Command
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;
const SB: u8 = 250; // Subnegotiation Begin
const SE: u8 = 240; // Subnegotiation End

/// Per-client data for LLM handling.
///
/// There used to be an `Idle`/`Processing`/`Accumulating` state machine and a `queued_data`
/// buffer here, copied from the TCP *server*. **Nothing could reach either.** The read loop is
/// one sequential task: it reads, handles the data inline — LLM call included — and only then
/// comes back to read again, so the state was always `Idle` at the point it was examined and
/// `queued_data` was never appended to. The `Processing` and `Accumulating` arms were
/// unreachable, and the line clearing `queued_data` after every turn read as "data arriving
/// mid-call is dropped" when in fact no data could arrive mid-call at all.
///
/// The server-side machine exists because a server has two LLM entry points and genuinely can
/// be re-entered. Copying its shape here bought nothing and described a concurrency this
/// client does not have. (The root `CLAUDE.md` notes the same thing about
/// `state/machine.rs`: a generic `StateMachine<S>` nothing uses, hand-rolled everywhere.)
struct ClientData {
    memory: String,
}

/// Telnet client that connects to a remote Telnet server
pub struct TelnetClient;

/// How many reads may wait while the model answers an earlier one (at most 8 KiB each);
/// past it the reader stops and TCP holds the server back.
const READ_QUEUE_CHUNKS: usize = crate::protocol::metadata::MAX_BATCH_EVENTS;

/// What the reader task hands the answering loop.
enum Inbound {
    Data(Vec<u8>),
    Closed,
    Failed(String),
}

impl TelnetClient {
    /// Connect to a Telnet server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // Resolve and connect
        let stream = TcpStream::connect(&remote_addr)
            .await
            .context(format!("Failed to connect to {}", remote_addr))?;

        let local_addr = stream.local_addr()?;
        let remote_sock_addr = stream.peer_addr()?;

        info!(
            "Telnet client {} {} {} (local: {})",
            client_id,
            patterns::TELNET_CLIENT_CONNECTED,
            remote_sock_addr,
            local_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] Telnet client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Split stream
        let (mut read_half, write_half) = tokio::io::split(stream);
        let write_half_arc = Arc::new(Mutex::new(write_half));

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            memory: String::new(),
        }));

        // Clone for connected event
        let write_half_for_connected = write_half_arc.clone();

        // Command channel: lets the dashboard (and any programmatic caller)
        // inject actions into this loop via AppState::send_to_client.
        //
        // Registered BEFORE the connected event is handled: a `manual` routing
        // rule can park that event at the dashboard for minutes, and until
        // registration the UI reports "no command channel" — reading as a
        // protocol limitation when it is only a queue.
        let mut command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // Call LLM with telnet_connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &TELNET_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": remote_sock_addr.to_string(),
                }),
            );

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &client_data.lock().await.memory,
                Some(&event),
                &crate::client::telnet::actions::TelnetClientProtocol,
                &status_tx,
            )
            .await
            {
                Ok(result) => {
                    // Update memory if provided
                    if let Some(new_memory) = result.memory_updates {
                        client_data.lock().await.memory = new_memory;
                    }

                    // Execute actions from LLM response
                    for action in result.actions {
                        if let Some(action_type) = action["type"].as_str() {
                            match action_type {
                                "send_command" => {
                                    if let Some(command) = action["command"].as_str() {
                                        let command_line = format!("{}\r\n", command);
                                        let mut write_guard = write_half_for_connected.lock().await;
                                        if let Err(e) =
                                            write_guard.write_all(command_line.as_bytes()).await
                                        {
                                            error!("Failed to send command after connect: {}", e);
                                        } else if let Err(e) = write_guard.flush().await {
                                            error!("Failed to flush after connect: {}", e);
                                        } else {
                                            info!(
                                                "{} {}",
                                                patterns::TELNET_CLIENT_SENT_COMMAND,
                                                command
                                            );
                                        }
                                    }
                                }
                                "send_text" => {
                                    if let Some(text) = action["text"].as_str() {
                                        let mut write_guard = write_half_for_connected.lock().await;
                                        if let Err(e) = write_guard.write_all(text.as_bytes()).await
                                        {
                                            error!("Failed to send text after connect: {}", e);
                                        } else if let Err(e) = write_guard.flush().await {
                                            error!("Failed to flush after connect: {}", e);
                                        } else {
                                            info!("{} {}", patterns::TELNET_CLIENT_SENT_TEXT, text);
                                        }
                                    }
                                }
                                "disconnect" => {
                                    info!("LLM requested disconnect after connect");
                                    return Ok(local_addr);
                                }
                                "wait_for_more" => {
                                    // Just wait for data
                                }
                                _ => {
                                    trace!("Unknown action type after connect: {}", action_type);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error on telnet_connected event: {}", e);
                }
            }
        }

        // Clone for telnet negotiation handler
        let write_half_for_negotiation = write_half_arc.clone();
        let status_tx_for_negotiation = status_tx.clone();

        // The reader runs on its own task so that what the server sends while the model is
        // answering keeps its read boundaries in a bounded queue rather than merging in the
        // kernel buffer: with batching on, everything waiting is answered in one call (one
        // event per read), with it off one read per call. Registered, so stop_client aborts it.
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Inbound>(READ_QUEUE_CHUNKS);
        let reader = app_state
            .spawn_client_task(client_id, async move {
                let mut buffer = vec![0u8; 8192];
                loop {
                    let message = match read_half.read(&mut buffer).await {
                        Ok(0) => Inbound::Closed,
                        Ok(n) => Inbound::Data(buffer[..n].to_vec()),
                        Err(e) => Inbound::Failed(e.to_string()),
                    };
                    let last = !matches!(message, Inbound::Data(_));
                    if inbound_tx.send(message).await.is_err() || last {
                        break;
                    }
                }
            })
            .await;

        // Spawn the answering loop.
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            'session: loop {
                let first = tokio::select! {
                    inbound = inbound_rx.recv() => inbound.unwrap_or(Inbound::Closed),
                    Some(cmd) = command_rx.recv() => {
                        let disconnect = crate::client::command_support::handle_stream_client_command(
                            &crate::client::telnet::actions::TelnetClientProtocol,
                            &write_half_arc,
                            cmd,
                            client_id,
                            &app_state,
                            &status_tx,
                        )
                        .await;
                        if disconnect {
                            app_state
                                .update_client_status(client_id, ClientStatus::Disconnected)
                                .await;
                            let _ = status_tx.send(format!(
                                "[CLIENT] Telnet client {} disconnected (injected action)",
                                client_id
                            ));
                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                            break;
                        }
                        continue;
                    }
                };

                // This read, plus — with batching on — every read already waiting.
                let mut reads: Vec<Vec<u8>> = Vec::new();
                let mut ended: Option<Inbound> = None;
                match first {
                    Inbound::Data(data) => reads.push(data),
                    other => ended = Some(other),
                }
                if ended.is_none()
                    && app_state
                        .client_conversation_settings(client_id)
                        .await
                        .is_some_and(|(_, batching)| batching)
                {
                    while reads.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                        match inbound_rx.try_recv() {
                            Ok(Inbound::Data(data)) => reads.push(data),
                            Ok(other) => {
                                ended = Some(other);
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                }

                // Negotiation is answered per read, here, before any model call; what is left
                // of each read becomes one event.
                let mut events = Vec::with_capacity(reads.len());
                for raw_data in &reads {
                    trace!(
                        "Telnet client {} received {} bytes",
                        client_id,
                        raw_data.len()
                    );
                    let (data, telnet_commands) = Self::parse_telnet_data(raw_data);
                    for cmd in &telnet_commands {
                        if let Some(response) =
                            Self::handle_telnet_command(cmd, client_id, &status_tx_for_negotiation)
                        {
                            match write_half_for_negotiation
                                .lock()
                                .await
                                .write_all(&response)
                                .await
                            {
                                Ok(()) => trace!(
                                    "Telnet client {} sent negotiation response: {:?}",
                                    client_id,
                                    response
                                ),
                                Err(e) => error!(
                                    "Telnet client {} could not answer negotiation: {}",
                                    client_id, e
                                ),
                            }
                        }
                    }
                    // Only meaningful content reaches the model.
                    if data.is_empty() && telnet_commands.is_empty() {
                        continue;
                    }
                    // Lossy: after IAC stripping what is left is the server's text, and a
                    // stray byte must not cost the model the whole line.
                    //
                    // `data` only. This event used to carry `raw_hex` as well - the whole
                    // read hex-encoded, up to 16 KB of hex per turn - which the repo's
                    // action/event rules forbid outright ("never put raw bytes or base64 in
                    // action parameters or event data"): models cannot reliably parse it, the
                    // negotiation it exposed is handled here rather than by the model, and it
                    // doubled the prompt for nothing.
                    events.push(Event::new(
                        &TELNET_CLIENT_DATA_RECEIVED_EVENT,
                        serde_json::json!({ "data": String::from_utf8_lossy(&data).to_string() }),
                    ));
                }

                if !events.is_empty() {
                    if let Some(instruction) = app_state.get_instruction_for_client(client_id).await
                    {
                        let protocol =
                            Arc::new(crate::client::telnet::actions::TelnetClientProtocol::new());
                        let memory = client_data.lock().await.memory.clone();
                        match crate::client::llm_budget::call_llm_for_client_batch(
                            &llm_client,
                            &app_state,
                            client_id.to_string(),
                            &instruction,
                            &memory,
                            &events,
                            protocol.as_ref(),
                            &status_tx,
                        )
                        .await
                        {
                            Ok(ClientLlmResult {
                                actions,
                                memory_updates,
                            }) => {
                                if let Some(mem) = memory_updates {
                                    client_data.lock().await.memory = mem;
                                }

                                for action in actions {
                                    use crate::llm::actions::client_trait::Client;
                                    use crate::llm::actions::client_trait::ClientActionResult;
                                    match protocol.as_ref().execute_action(action) {
                                        Ok(ClientActionResult::SendData(bytes)) => {
                                            // A failed write was silently swallowed here, so
                                            // the model's command vanished and the client went
                                            // on waiting for a reply to something that never
                                            // left the host.
                                            let mut write_guard = write_half_arc.lock().await;
                                            if let Err(e) = write_guard.write_all(&bytes).await {
                                                error!(
                                                    "Telnet client {} failed to send {} bytes: {}",
                                                    client_id,
                                                    bytes.len(),
                                                    e
                                                );
                                            } else if let Err(e) = write_guard.flush().await {
                                                error!(
                                                    "Telnet client {} failed to flush: {}",
                                                    client_id, e
                                                );
                                            } else {
                                                trace!(
                                                    "Telnet client {} sent {} bytes",
                                                    client_id,
                                                    bytes.len()
                                                );
                                            }
                                        }
                                        Ok(ClientActionResult::Disconnect) => {
                                            // This used to `break` out of the loop over actions
                                            // only, so the model's disconnect was ignored and
                                            // the session went on.
                                            info!("Telnet client {} disconnecting", client_id);
                                            app_state
                                                .update_client_status(
                                                    client_id,
                                                    ClientStatus::Disconnected,
                                                )
                                                .await;
                                            let _ = status_tx.send(format!(
                                                "[CLIENT] Telnet client {} disconnected",
                                                client_id
                                            ));
                                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                                            break 'session;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            Err(e) => {
                                error!("LLM error for Telnet client {}: {}", client_id, e);
                            }
                        }
                    }
                }

                match ended {
                    Some(Inbound::Closed) => {
                        info!(
                            "Telnet client {} {}",
                            client_id,
                            patterns::TELNET_CLIENT_DISCONNECTED
                        );
                        app_state
                            .update_client_status(client_id, ClientStatus::Disconnected)
                            .await;
                        let _ = status_tx
                            .send(format!("[CLIENT] Telnet client {} disconnected", client_id));
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    Some(Inbound::Failed(e)) => {
                        error!("Telnet client {} read error: {}", client_id, e);
                        app_state
                            .update_client_status(client_id, ClientStatus::Error(e))
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    _ => {}
                }
            }
            reader.abort();
            // The loop owns the only receiver; dropping the registered handle
            // makes later send_to_client calls fail fast instead of timing out.
            app_state.remove_client_handle(client_id).await;
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }

    /// Parse Telnet data, separating actual data from Telnet commands
    /// Returns (data, telnet_commands)
    fn parse_telnet_data(raw: &[u8]) -> (Vec<u8>, Vec<TelnetCommand>) {
        let mut data = Vec::new();
        let mut commands = Vec::new();
        let mut i = 0;

        while i < raw.len() {
            if raw[i] == IAC {
                // Telnet command
                if i + 1 >= raw.len() {
                    break;
                }

                let cmd = raw[i + 1];

                match cmd {
                    IAC => {
                        // Escaped IAC (255 255 means literal 255)
                        data.push(IAC);
                        i += 2;
                    }
                    WILL | WONT | DO | DONT => {
                        // Option negotiation
                        if i + 2 < raw.len() {
                            let option = raw[i + 2];
                            commands.push(TelnetCommand::Negotiation {
                                command: cmd,
                                option,
                            });
                            i += 3;
                        } else {
                            i += 2;
                        }
                    }
                    SB => {
                        // Subnegotiation - find SE
                        let mut sb_end = i + 2;
                        while sb_end < raw.len() {
                            if raw[sb_end] == IAC && sb_end + 1 < raw.len() && raw[sb_end + 1] == SE
                            {
                                break;
                            }
                            sb_end += 1;
                        }
                        commands.push(TelnetCommand::Subnegotiation);
                        i = sb_end + 2;
                    }
                    _ => {
                        // Other command
                        commands.push(TelnetCommand::Other(cmd));
                        i += 2;
                    }
                }
            } else {
                // Regular data
                data.push(raw[i]);
                i += 1;
            }
        }

        (data, commands)
    }

    /// Handle a Telnet command and return response if needed
    fn handle_telnet_command(
        cmd: &TelnetCommand,
        client_id: ClientId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Option<Vec<u8>> {
        match cmd {
            TelnetCommand::Negotiation { command, option } => {
                let cmd_name = match *command {
                    WILL => "WILL",
                    WONT => "WONT",
                    DO => "DO",
                    DONT => "DONT",
                    _ => "UNKNOWN",
                };

                let option_name = Self::get_option_name(*option);
                debug!(
                    "Telnet client {} received {} {}",
                    client_id, cmd_name, option_name
                );

                let _ = status_tx.send(format!(
                    "[CLIENT] Telnet {} negotiation: {} {}",
                    client_id, cmd_name, option_name
                ));

                // Basic negotiation strategy: refuse all options
                match *command {
                    WILL => {
                        // Server offers to do something - respond with DONT (refuse)
                        Some(vec![IAC, DONT, *option])
                    }
                    DO => {
                        // Server asks us to do something - respond with WONT (refuse)
                        Some(vec![IAC, WONT, *option])
                    }
                    _ => None,
                }
            }
            TelnetCommand::Subnegotiation => {
                debug!("Telnet client {} received subnegotiation", client_id);
                None
            }
            TelnetCommand::Other(code) => {
                debug!("Telnet client {} received command code {}", client_id, code);
                None
            }
        }
    }

    /// Get human-readable name for Telnet option
    fn get_option_name(option: u8) -> &'static str {
        match option {
            0 => "BINARY",
            1 => "ECHO",
            3 => "SUPPRESS_GO_AHEAD",
            5 => "STATUS",
            6 => "TIMING_MARK",
            24 => "TERMINAL_TYPE",
            31 => "WINDOW_SIZE",
            32 => "TERMINAL_SPEED",
            33 => "REMOTE_FLOW_CONTROL",
            34 => "LINEMODE",
            36 => "ENVIRONMENT_VARIABLES",
            _ => "UNKNOWN",
        }
    }
}

/// Telnet command types
#[derive(Debug, Clone)]
enum TelnetCommand {
    Negotiation { command: u8, option: u8 },
    Subnegotiation,
    Other(u8),
}

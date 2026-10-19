//! IRC client implementation
pub mod actions;

pub use actions::IrcClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

use crate::client::irc::actions::{IRC_CLIENT_CONNECTED_EVENT, IRC_CLIENT_MESSAGE_RECEIVED_EVENT};
use crate::client::llm_budget::call_llm_for_client_batch;
use crate::server::irc::wire::{
    cap_line, read_irc_line, reject_line_breaks, reject_not_a_word, IrcLine, MAX_IRC_READ_LINE,
};

use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// Per-client data shared between the answering loop and the injected-command loop.
///
/// There is deliberately no Idle/Processing/Accumulating state machine here. One used to
/// exist, with a `queued_messages` vector that was cleared without ever being handed to the
/// model. Lines that arrive during a model call now wait in the reader task's bounded queue
/// ([`READ_QUEUE_LINES`]) and are all answered, together when the client batches.
struct ClientData {
    memory: String,
    nickname: String,
}

/// How many lines may wait while the model answers an earlier one (at most
/// `MAX_IRC_READ_LINE` bytes each); past it the reader stops reading and TCP holds the server
/// back.
const READ_QUEUE_LINES: usize = crate::protocol::metadata::MAX_BATCH_EVENTS;

/// What the reader task hands the answering loop.
enum Inbound {
    Line(String),
    Closed,
    Failed(String),
}

/// IRC client that connects to an IRC server
pub struct IrcClient;

impl IrcClient {
    /// Connect to an IRC server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Parse startup params
        let nickname = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("nickname"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| "netget_user".to_string());
        let username = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("username"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| "netget".to_string());
        let realname = startup_params
            .as_ref()
            .map(|p| p.get_optional_string("realname"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| "NetGet IRC Client".to_string());

        // These three are interpolated straight into NICK/USER lines below, so they are held
        // to the same framing rules as anything the model produces: a `nickname` containing
        // CRLF would forge a command before the session has even registered, and one
        // containing a space would shift USER's positional parameters. `realname` is the
        // trailing parameter, where spaces belong.
        reject_not_a_word("nickname", &nickname)?;
        reject_not_a_word("username", &username)?;
        reject_line_breaks("realname", &realname)?;

        // Resolve and connect
        let stream = TcpStream::connect(&remote_addr)
            .await
            .context(format!("Failed to connect to {}", remote_addr))?;

        let local_addr = stream.local_addr()?;
        let remote_sock_addr = stream.peer_addr()?;

        info!(
            "IRC client {} connecting to {} (local: {})",
            client_id, remote_sock_addr, local_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] IRC client {} connected to {}",
            client_id, remote_sock_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Split stream
        let (read_half, write_half) = tokio::io::split(stream);
        let write_half_arc = Arc::new(Mutex::new(write_half));

        // Send IRC registration
        let mut writer = write_half_arc.lock().await;
        writer
            .write_all(format!("NICK {}\r\n", nickname).as_bytes())
            .await?;
        writer
            .write_all(format!("USER {} 0 * :{}\r\n", username, realname).as_bytes())
            .await?;
        drop(writer);

        debug!(
            "IRC client {} sent registration (nick: {})",
            client_id, nickname
        );

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            memory: String::new(),
            nickname: nickname.clone(),
        }));

        // Command channel for injected actions (the dashboard's [ send_privmsg ] /
        // [ send_notice ] / [ send_raw ] rows). Registered BEFORE the read loop and therefore
        // before the connected-event LLM call, which a manual `*` rule can park for minutes -
        // the operator must be able to reach the client while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // `read_line` is not cancellation-safe, so commands are drained by their own task
        // rather than a `select!` arm in the read loop. Both tasks share the write half.
        let cmd_state = app_state.clone();
        let cmd_tx = status_tx.clone();
        let cmd_write = write_half_arc.clone();
        let cmd_data = client_data.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(
                command_rx, cmd_write, cmd_data, client_id, cmd_state, cmd_tx,
            )
            .await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // The reader runs on its own task and answers PING itself, so a server's keepalive is
        // answered at once rather than after whatever model call is running, and every other
        // line waits in a bounded queue in arrival order: with batching on, the lines that
        // arrived while the model answered are answered together, with it off one per call.
        // Past `READ_QUEUE_LINES` the reader stops reading and TCP holds the server back.
        // Registered, so stop_client aborts it with the answering loop.
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Inbound>(READ_QUEUE_LINES);
        let reader_write = write_half_arc.clone();
        let reader = app_state
            .spawn_client_task(client_id, async move {
                let mut reader = BufReader::new(read_half);
                loop {
                    // Bounded. The peer here is a *server*, and an unbounded `read_line` lets
                    // one that never sends a newline grow this buffer until the netget process
                    // is out of memory - the same one-connection OOM the server side had.
                    let message = match read_irc_line(&mut reader, MAX_IRC_READ_LINE).await {
                        Ok((IrcLine::Line(line), _)) => {
                            let line = line.trim_end().to_string();
                            trace!("IRC client {} received: {}", client_id, line);
                            // Handle PING immediately.
                            //
                            // `line.replace("PING", "PONG")` was wrong in a way that only shows
                            // on real servers: `replace` rewrites *every* occurrence, so a token
                            // containing the letters PING - which ircds do send, they are
                            // opaque cookies - came back corrupted and the server dropped the
                            // link for failing its own ping. Only the command word is a
                            // command.
                            if let Some(rest) = line.strip_prefix("PING ") {
                                let pong = format!("PONG {rest}\r\n");
                                if reader_write
                                    .lock()
                                    .await
                                    .write_all(pong.as_bytes())
                                    .await
                                    .is_ok()
                                {
                                    trace!("IRC client {} sent PONG", client_id);
                                }
                                continue;
                            }
                            Inbound::Line(line)
                        }
                        Ok((IrcLine::Eof, _)) => Inbound::Closed,
                        Ok((IrcLine::TooLong, n)) => Inbound::Failed(format!(
                            "IRC server sent {n} bytes with no newline (limit \
                             {MAX_IRC_READ_LINE})"
                        )),
                        Err(e) => Inbound::Failed(e.to_string()),
                    };
                    let last = !matches!(message, Inbound::Line(_));
                    if inbound_tx.send(message).await.is_err() || last {
                        break;
                    }
                }
            })
            .await;

        // Clone for spawned task
        let write_half_clone = write_half_arc.clone();
        let client_data_clone = client_data.clone();
        let nickname_clone = nickname.clone();

        // Spawn the answering loop.
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let mut registered = false;

            loop {
                let line = match inbound_rx.recv().await.unwrap_or(Inbound::Closed) {
                    Inbound::Line(line) => line,
                    Inbound::Closed => {
                        info!("IRC client {} disconnected", client_id);
                        app_state
                            .update_client_status(client_id, ClientStatus::Disconnected)
                            .await;
                        let _ = status_tx
                            .send(format!("[CLIENT] IRC client {} disconnected", client_id));
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    Inbound::Failed(e) => {
                        error!("IRC client {} read error: {}", client_id, e);
                        app_state
                            .update_client_status(client_id, ClientStatus::Error(e))
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                };

                // Check for registration complete (001 welcome message)
                if !registered && line.contains(" 001 ") {
                    registered = true;
                    info!("IRC client {} registration complete", client_id);

                    // Call LLM with connected event
                    if let Some(instruction) = app_state.get_instruction_for_client(client_id).await
                    {
                        let protocol = Arc::new(IrcClientProtocol::new());
                        let event = Event::new(
                            &IRC_CLIENT_CONNECTED_EVENT,
                            serde_json::json!({
                                "remote_addr": remote_sock_addr.to_string(),
                                "nickname": nickname_clone,
                            }),
                        );

                        if let Err(e) = Self::handle_llm_call(
                            &llm_client,
                            &app_state,
                            client_id,
                            &instruction,
                            &client_data_clone,
                            &[event],
                            protocol,
                            &write_half_clone,
                            &status_tx,
                        )
                        .await
                        {
                            error!("IRC client {} LLM error on connect: {}", client_id, e);
                        }
                    }
                    continue;
                }

                // Skip if not yet registered
                if !registered {
                    continue;
                }

                // This line, plus - with batching on - every line already waiting: what the
                // server sent while the model answered the previous one. An end of the
                // connection found while sweeping is handled after this turn.
                let mut lines = vec![line];
                let mut ended: Option<Inbound> = None;
                if app_state
                    .client_conversation_settings(client_id)
                    .await
                    .is_some_and(|(_, batching)| batching)
                {
                    while lines.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                        match inbound_rx.try_recv() {
                            Ok(Inbound::Line(more)) => lines.push(more),
                            Ok(other) => {
                                ended = Some(other);
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                }

                // One event per line, answered in one model call when there are several.
                if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
                    let protocol = Arc::new(IrcClientProtocol::new());
                    let events: Vec<Event> = lines
                        .iter()
                        .map(|line| {
                            let parsed = Self::parse_irc_message(line);
                            Event::new(
                                &IRC_CLIENT_MESSAGE_RECEIVED_EVENT,
                                serde_json::json!({
                                    "source": parsed.source,
                                    "command": parsed.command,
                                    "target": parsed.target,
                                    "message": parsed.message,
                                    "raw_message": line,
                                }),
                            )
                        })
                        .collect();

                    if let Err(e) = Self::handle_llm_call(
                        &llm_client,
                        &app_state,
                        client_id,
                        &instruction,
                        &client_data_clone,
                        &events,
                        protocol,
                        &write_half_clone,
                        &status_tx,
                    )
                    .await
                    {
                        error!("IRC client {} LLM error: {}", client_id, e);
                    }
                }

                match ended {
                    Some(Inbound::Closed) => {
                        info!("IRC client {} disconnected", client_id);
                        app_state
                            .update_client_status(client_id, ClientStatus::Disconnected)
                            .await;
                        let _ = status_tx
                            .send(format!("[CLIENT] IRC client {} disconnected", client_id));
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    Some(Inbound::Failed(e)) => {
                        error!("IRC client {} read error: {}", client_id, e);
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
            // Every exit path (EOF - including the one an injected or LLM QUIT provokes - and
            // read error) lands here: drop the command handle so the dashboard stops offering
            // [ send ] on a dead connection (a late send then fails fast).
            app_state.remove_client_handle(client_id).await;
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }

    /// Drain injected commands until the channel closes (client removed) or an injected
    /// `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot run this client's
    /// vocabulary because every wire verb (`send_privmsg`, `send_notice`, `send_raw`,
    /// `join_channel`, ...) yields `ClientActionResult::Custom`, so the result goes through
    /// [`Self::apply_action`] - the same function the LLM path uses - and the outcome is
    /// recorded and replied exactly the way the generic arm does it.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        write_half: Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        client_data: Arc<Mutex<ClientData>>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::client_trait::Client;
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        let protocol = IrcClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => Self::apply_action(result, &write_half, &client_data)
                    .await
                    .map(|applied| match applied {
                        Applied::Disconnect => ClientSendOutcome::Disconnected,
                        Applied::Sent(0) => ClientSendOutcome::Executed {
                            detail: "executed (nothing to write)".to_string(),
                        },
                        Applied::Sent(bytes_sent) => ClientSendOutcome::Sent { bytes_sent },
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
                error!("IRC client {} injected action failed: {}", client_id, e);
                let _ = status_tx.send(format!(
                    "[WARN] Client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                // QUIT is already on the wire; half-close so the server reads EOF and the
                // read loop runs its normal disconnect path.
                let _ = write_half.lock().await.shutdown().await;
                break;
            }
        }
    }

    /// Parse an IRC message into components
    fn parse_irc_message(line: &str) -> ParsedMessage {
        let mut parts = line.split_whitespace();

        let source = if line.starts_with(':') {
            parts.next().map(|s| s.trim_start_matches(':').to_string())
        } else {
            None
        };

        let command = parts.next().map(|s| s.to_uppercase()).unwrap_or_default();

        let remaining: Vec<&str> = parts.collect();
        let (target, message) = if command == "PRIVMSG" || command == "NOTICE" {
            let target = remaining.first().map(|s| s.to_string());
            let message = if let Some(idx) = remaining.iter().position(|s| s.starts_with(':')) {
                let msg_parts: Vec<&str> = remaining[idx..].iter().map(|s| *s).collect();
                Some(msg_parts.join(" ").trim_start_matches(':').to_string())
            } else {
                None
            };
            (target, message)
        } else {
            (None, None)
        };

        ParsedMessage {
            source,
            command,
            target,
            message,
        }
    }

    /// Ask the model about one or more events and execute its actions
    async fn handle_llm_call(
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        client_id: ClientId,
        instruction: &str,
        client_data: &Arc<Mutex<ClientData>>,
        events: &[Event],
        protocol: Arc<IrcClientProtocol>,
        write_half: &Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let memory = client_data.lock().await.memory.clone();

        // Several events are the lines that arrived during the previous call: one model call
        // answers them all, or they are answered one by one when the client does not batch
        // or a rule decides one of them.
        match call_llm_for_client_batch(
            llm_client,
            app_state,
            client_id.to_string(),
            instruction,
            &memory,
            events,
            protocol.as_ref(),
            status_tx,
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

                // Execute actions
                for action in actions {
                    use crate::llm::actions::client_trait::Client;
                    match protocol.as_ref().execute_action(action) {
                        Ok(result) => {
                            if let Applied::Disconnect =
                                Self::apply_action(result, write_half, client_data).await?
                            {
                                info!("IRC client {} disconnecting", client_id);
                                return Err(anyhow::anyhow!("Disconnect requested"));
                            }
                        }
                        Err(e) => {
                            warn!("IRC client {} action execution error: {}", client_id, e);
                        }
                    }
                }
            }
            Err(e) => {
                return Err(e);
            }
        }

        Ok(())
    }

    /// Put one executed action on the wire. Shared by the LLM path and injected commands so
    /// the encoding of every IRC verb exists exactly once.
    async fn apply_action(
        result: crate::llm::actions::client_trait::ClientActionResult,
        write_half: &Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        client_data: &Arc<Mutex<ClientData>>,
    ) -> Result<Applied> {
        use crate::llm::actions::client_trait::ClientActionResult;

        match result {
            ClientActionResult::Custom { name, data } => {
                Self::execute_irc_action(&name, data, write_half, client_data).await
            }
            ClientActionResult::Disconnect => {
                Self::execute_irc_action(
                    "disconnect",
                    serde_json::Value::Null,
                    write_half,
                    client_data,
                )
                .await
            }
            // WaitForMore, NoAction, SendData (unused by this vocabulary), nested Multiple.
            _ => Ok(Applied::Sent(0)),
        }
    }

    /// Execute IRC-specific actions.
    ///
    /// The fields arriving here have already been through [`crate::server::irc::wire`]'s
    /// checks in `IrcClientProtocol::execute_action`, which is the gate both the LLM path and
    /// the injected-command path pass through. This function's own contribution is the RFC
    /// 1459 512-byte cap, which is about the finished line rather than any one field.
    async fn execute_irc_action(
        name: &str,
        data: serde_json::Value,
        write_half: &Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        client_data: &Arc<Mutex<ClientData>>,
    ) -> Result<Applied> {
        // Build and validate the line *before* taking the write lock: a rejected action must
        // not hold the socket, and must not have written half a line first.
        let (wire, disconnect) = match name {
            "join_channel" => {
                let channel = data["channel"].as_str().context("Missing channel")?;
                debug!("IRC: JOIN {}", channel);
                (format!("JOIN {}\r\n", channel), false)
            }
            "part_channel" => {
                let channel = data["channel"].as_str().context("Missing channel")?;
                debug!("IRC: PART {}", channel);
                match data["message"].as_str() {
                    Some(msg) => (format!("PART {} :{}\r\n", channel, msg), false),
                    None => (format!("PART {}\r\n", channel), false),
                }
            }
            "change_nick" => {
                let new_nick = data["new_nick"].as_str().context("Missing new_nick")?;
                client_data.lock().await.nickname = new_nick.to_string();
                debug!("IRC: NICK {}", new_nick);
                (format!("NICK {}\r\n", new_nick), false)
            }
            "send_privmsg" => {
                let target = data["target"].as_str().context("Missing target")?;
                let message = data["message"].as_str().context("Missing message")?;
                debug!("IRC: PRIVMSG {} :{}", target, message);
                (format!("PRIVMSG {} :{}\r\n", target, message), false)
            }
            "send_notice" => {
                let target = data["target"].as_str().context("Missing target")?;
                let message = data["message"].as_str().context("Missing message")?;
                debug!("IRC: NOTICE {} :{}", target, message);
                (format!("NOTICE {} :{}\r\n", target, message), false)
            }
            "send_raw" => {
                let command = data["command"].as_str().context("Missing command")?;
                debug!("IRC: RAW {}", command);
                (format!("{}\r\n", command), false)
            }
            "disconnect" => {
                let quit_message = data["quit_message"].as_str().unwrap_or("Leaving");
                debug!("IRC: QUIT");
                (format!("QUIT :{}\r\n", quit_message), true)
            }
            _ => {
                warn!("Unknown IRC action: {}", name);
                return Ok(Applied::Sent(0));
            }
        };

        // RFC 1459 caps a message at 512 bytes including the CRLF. A server that receives a
        // longer one truncates or drops it, so sending the full thing loses the tail either
        // way; cutting it here keeps the line well-formed and puts the loss in our own log.
        let wire = cap_line(name, wire);

        let mut writer = write_half.lock().await;
        writer.write_all(&wire).await?;
        writer.flush().await?;

        Ok(if disconnect {
            Applied::Disconnect
        } else {
            Applied::Sent(wire.len())
        })
    }
}

/// What [`IrcClient::apply_action`] did with one action.
enum Applied {
    /// Bytes written (0 when the action produced no wire output).
    Sent(usize),
    /// QUIT was written and the session should end.
    Disconnect,
}

/// Parsed IRC message
#[derive(Debug)]
struct ParsedMessage {
    source: Option<String>,
    command: String,
    target: Option<String>,
    message: Option<String>,
}

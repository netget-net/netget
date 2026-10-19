pub mod actions;

use crate::client::llm_budget::call_llm_for_client_batch;
use crate::client::pop3::actions::{
    POP3_CLIENT_CONNECTED_EVENT, POP3_CLIENT_RESPONSE_RECEIVED_EVENT,
};
use crate::llm::actions::client_trait::Client;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client::{ClientId, ClientStatus};
use anyhow::Result;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

pub use actions::Pop3ClientProtocol;

/// Serialized POP3 writes and their reply expectations share one lock. The reader
/// cannot observe a written command without its corresponding framing expectation.
pub struct CommandWriter<W> {
    writer: W,
    replies: std::collections::VecDeque<bool>,
    failed: bool,
}

impl<W: tokio::io::AsyncWrite + Unpin> CommandWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            replies: Default::default(),
            failed: false,
        }
    }

    pub async fn send(&mut self, command: &str) -> Result<usize> {
        if self.failed {
            anyhow::bail!("POP3 writer is unusable after an interrupted write");
        }
        if command.is_empty() || command.contains(['\r', '\n']) {
            anyhow::bail!("POP3 command must be one nonempty line");
        }
        if self.replies.len() >= 1024 {
            anyhow::bail!("too many outstanding POP3 commands");
        }
        let mut words = command.split_ascii_whitespace();
        let verb = words
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty POP3 command"))?;
        let multiline = match verb.to_ascii_uppercase().as_str() {
            "RETR" | "TOP" | "CAPA" => true,
            "LIST" | "UIDL" => words.next().is_none(),
            _ => false,
        };
        self.failed = true;
        self.replies.push_back(multiline);
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            self.writer.write_all(command.as_bytes()).await?;
            self.writer.write_all(b"\r\n").await?;
            self.writer.flush().await
        })
        .await
        .map_err(|_| anyhow::anyhow!("POP3 command write deadline exceeded"))??;
        self.failed = false;
        Ok(command.len() + 2)
    }

    pub fn next_response_is_multiline(&mut self, response: &str) -> Result<bool> {
        if self.failed {
            anyhow::bail!("POP3 command write failed before its reply");
        }
        let multiline = self
            .replies
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("unsolicited POP3 response"))?;
        if !(response == "+OK"
            || response.starts_with("+OK ")
            || response == "-ERR"
            || response.starts_with("-ERR "))
        {
            anyhow::bail!("invalid POP3 response status");
        }
        Ok(multiline && response.starts_with("+OK"))
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        self.writer.shutdown().await
    }
}

pub struct Pop3Client;

impl Pop3Client {
    /// Connect to POP3 server with LLM integration
    ///
    /// `use_tls: true` is **refused**, not ignored. This client speaks POP3 over a plain
    /// `TcpStream` and has no TLS at all, and the very next thing a POP3 session does is
    /// send `USER` and `PASS` in the clear. Connecting anyway would hand the password to a
    /// cleartext socket while the parameter list, and this protocol's own CLAUDE.md, said
    /// the session was encrypted. `imap` had the identical defect and takes the identical
    /// exit; the project's rule is that declining out loud beats hiding a capability,
    /// because the caller gets a reason they can act on.
    ///
    /// `use_tls: false` remains valid and means what it says.
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        if let Some(params) = &startup_params {
            if params.get_optional_bool("use_tls")?.unwrap_or(false) {
                return Err(anyhow::anyhow!(
                    "POP3 client: `use_tls: true` was requested, but this client does not \
                     implement TLS - it speaks POP3 over a plain TCP socket. Connecting \
                     anyway would put the USER/PASS exchange for {remote_addr} on the wire \
                     in cleartext while reporting an encrypted session. Pass \
                     `use_tls: false` to accept a plaintext connection deliberately, or \
                     terminate TLS in front of the server."
                ));
            }
        }
        Self::connect_plain(remote_addr, llm_client, app_state, status_tx, client_id).await
    }

    async fn connect_plain(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        let stream = TcpStream::connect(&remote_addr).await?;
        let local_addr = stream.local_addr()?;

        info!("POP3 client {} connected to {}", client_id, remote_addr);

        // Update client status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;

        let (read_half, write_half) = tokio::io::split(stream);
        let reader = BufReader::new(read_half);
        let write_half = Arc::new(tokio::sync::Mutex::new(CommandWriter::new(write_half)));

        let protocol = Arc::new(Pop3ClientProtocol);

        // Command channel for injected actions (the dashboard's [ send_pop3_command ]).
        // Registered BEFORE the connected-event LLM call, which a manual `*` rule can park
        // for minutes - the operator must be able to reach the client while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // `read_line` is not cancellation-safe, so the commands are drained by their own task
        // rather than a `select!` arm in the read loop. Both tasks share the write half.
        let cmd_state = app_state.clone();
        let cmd_tx = status_tx.clone();
        let cmd_write = write_half.clone();
        let cmd_protocol = protocol.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(
                command_rx,
                cmd_protocol,
                cmd_write,
                client_id,
                cmd_state,
                cmd_tx,
            )
            .await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Spawn read loop
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let cleanup_state = app_state.clone();
            let cleanup_status = status_tx.clone();
            let result = Self::read_loop(
                reader,
                write_half,
                llm_client,
                app_state,
                status_tx,
                client_id,
                protocol,
                remote_addr,
            )
            .await;
            let status = match result {
                Ok(()) => ClientStatus::Disconnected,
                Err(e) => {
                    error!("POP3 client {} read loop error: {}", client_id, e);
                    ClientStatus::Error(e.to_string())
                }
            };
            cleanup_state.update_client_status(client_id, status).await;
            cleanup_state.remove_client_handle(client_id).await;
            let _ = cleanup_status.send("__UPDATE_UI__".to_string());
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
    /// vocabulary because `send_pop3_command` yields `ClientActionResult::Custom`, so the
    /// action goes through [`Self::apply_action`] - the same function the LLM path uses -
    /// and the outcome is recorded and replied exactly the way the generic arm does it.
    async fn command_loop<W>(
        mut command_rx: tokio::sync::mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        protocol: Arc<Pop3ClientProtocol>,
        write_half: Arc<tokio::sync::Mutex<CommandWriter<W>>>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) where
        W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.as_ref().execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => Self::apply_action(result, &write_half, client_id)
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
                Err(e) => json!({"error": e.to_string()}),
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
                error!("POP3 client {} injected action failed: {}", client_id, e);
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

    async fn read_loop<R, W>(
        mut reader: BufReader<R>,
        write_half: Arc<tokio::sync::Mutex<CommandWriter<W>>>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        protocol: Arc<Pop3ClientProtocol>,
        remote_addr: String,
    ) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
        W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Read greeting from server
        let mut line = String::new();
        if crate::client::response_reader::read_expected_response_line(&mut reader, &mut line)
            .await?
            == 0
        {
            anyhow::bail!("POP3 server closed before its greeting");
        }
        let greeting = line.trim().to_string();

        debug!("POP3 client {} received greeting: {}", client_id, greeting);

        let is_ok = greeting.starts_with("+OK");

        // Get client instruction and memory
        let (instruction, memory) = app_state
            .with_client_mut(client_id, |client| {
                (client.instruction.to_string(), client.memory.clone())
            })
            .await
            .unwrap_or_default();

        // Send connected event to LLM
        let event = Event::new(
            &POP3_CLIENT_CONNECTED_EVENT,
            json!({
                "pop3_server": remote_addr,
                "greeting": greeting,
                "is_ok": is_ok,
            }),
        );

        // Initial LLM call with greeting
        if let Err(e) = Self::handle_llm_response(
            std::slice::from_ref(&event),
            &llm_client,
            &app_state,
            &status_tx,
            client_id,
            &protocol,
            &write_half,
            &instruction,
            &memory,
        )
        .await
        {
            error!(
                "POP3 client {} failed to process greeting: {}",
                client_id, e
            );
            return Err(e);
        }

        // Responses are framed on a registered task of its own, so what the server answers
        // while the model is still on an earlier response -- the replies to the rest of a
        // multi-command answer (USER then PASS, LIST then RETR), or to an injected command --
        // waits in a bounded queue as whole responses. With batching on everything waiting is
        // answered in one model call, one event per response; with it off, one per call.
        let (inbound_tx, mut inbound_rx) =
            mpsc::channel::<Result<Option<String>>>(crate::protocol::metadata::MAX_BATCH_EVENTS);
        let framing_writer = write_half.clone();
        let framer = app_state
            .spawn_client_task(client_id, async move {
                let mut line = String::new();
                loop {
                    let next: Result<Option<String>> = async {
                        loop {
                            line.clear();
                            if crate::client::response_reader::read_response_line(
                                &mut reader,
                                &mut line,
                            )
                            .await?
                                == 0
                            {
                                return Ok(None);
                            }
                            let response = line.trim().to_string();
                            if response.is_empty() {
                                continue;
                            }
                            debug!("POP3 client {} received response: {}", client_id, response);
                            // Check if this is a multiline response
                            let is_multiline = framing_writer
                                .lock()
                                .await
                                .next_response_is_multiline(&response)?;
                            return Ok(Some(if is_multiline {
                                crate::client::response_reader::read_dot_response(
                                    &mut reader,
                                    response,
                                )
                                .await?
                            } else {
                                response
                            }));
                        }
                    }
                    .await;
                    let last = !matches!(next, Ok(Some(_)));
                    if inbound_tx.send(next).await.is_err() || last {
                        break;
                    }
                }
            })
            .await;

        let result = async {
            loop {
                let mut responses = Vec::new();
                let mut ended = None;
                match inbound_rx.recv().await.unwrap_or(Ok(None)) {
                    Ok(Some(response)) => responses.push(response),
                    other => ended = Some(other),
                }
                if !responses.is_empty()
                    && app_state
                        .client_conversation_settings(client_id)
                        .await
                        .is_some_and(|(_, batching)| batching)
                {
                    while responses.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                        match inbound_rx.try_recv() {
                            Ok(Ok(Some(response))) => responses.push(response),
                            Ok(other) => {
                                ended = Some(other);
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                }

                if !responses.is_empty() {
                    // Get updated instruction and memory
                    let (instruction, memory) = app_state
                        .with_client_mut(client_id, |client| {
                            (client.instruction.to_string(), client.memory.clone())
                        })
                        .await
                        .unwrap_or_default();

                    let events: Vec<Event> = responses
                        .into_iter()
                        .map(|full_response| {
                            let is_ok = full_response.starts_with("+OK");
                            Event::new(
                                &POP3_CLIENT_RESPONSE_RECEIVED_EVENT,
                                json!({
                                    "response": full_response,
                                    "is_ok": is_ok,
                                }),
                            )
                        })
                        .collect();

                    if let Err(e) = Self::handle_llm_response(
                        &events,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        client_id,
                        &protocol,
                        &write_half,
                        &instruction,
                        &memory,
                    )
                    .await
                    {
                        error!(
                            "POP3 client {} failed to process response: {}",
                            client_id, e
                        );
                        return Ok(());
                    }
                }

                match ended {
                    Some(Ok(None)) => {
                        debug!("POP3 client {} connection closed by server", client_id);
                        return Ok(());
                    }
                    Some(Err(e)) => return Err(e),
                    _ => {}
                }
            }
        }
        .await;
        framer.abort();
        result?;

        info!("POP3 client {} disconnected", client_id);
        Ok(())
    }

    /// Ask the model about one or more events -- several only when batching gathered them --
    /// and put its answer on the wire.
    async fn handle_llm_response<W>(
        events: &[Event],
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        client_id: ClientId,
        protocol: &Arc<Pop3ClientProtocol>,
        write_half: &Arc<tokio::sync::Mutex<CommandWriter<W>>>,
        instruction: &str,
        memory: &str,
    ) -> Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        // Call LLM
        let llm_result = call_llm_for_client_batch(
            llm_client,
            app_state,
            client_id.to_string(),
            instruction,
            memory,
            events,
            protocol.as_ref(),
            status_tx,
        )
        .await?;

        // Update memory if returned
        if let Some(new_memory) = llm_result.memory_updates {
            app_state
                .with_client_mut(client_id, |client| {
                    client.memory = new_memory.clone();
                })
                .await;
        }

        // Execute actions
        for action in llm_result.actions {
            let action_result = protocol.as_ref().execute_action(action)?;
            if let Applied::Disconnect =
                Self::apply_action(action_result, write_half, client_id).await?
            {
                return Ok(());
            }
        }

        Ok(())
    }

    /// Put one executed action on the wire. Shared by the LLM path and injected commands so
    /// the encoding of `send_pop3_command` exists exactly once.
    async fn apply_action<W>(
        action_result: crate::llm::actions::client_trait::ClientActionResult,
        write_half: &Arc<tokio::sync::Mutex<CommandWriter<W>>>,
        client_id: ClientId,
    ) -> Result<Applied>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use crate::llm::actions::client_trait::ClientActionResult;

        match action_result {
            ClientActionResult::Custom { name, data } => {
                if name != "pop3_command" {
                    return Ok(Applied::Sent(0));
                }
                let command = data["command"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Missing command in action data"))?;

                debug!("POP3 client {} sending command: {}", client_id, command);

                let mut writer = write_half.lock().await;
                Ok(Applied::Sent(writer.send(command).await?))
            }
            ClientActionResult::Disconnect => {
                debug!("POP3 client {} disconnecting", client_id);
                // Send QUIT command before closing
                let mut writer = write_half.lock().await;
                writer.send("QUIT").await?;
                Ok(Applied::Disconnect)
            }
            // WaitForMore, NoAction, SendData (unused by this vocabulary), nested Multiple.
            _ => Ok(Applied::Sent(0)),
        }
    }
}

/// What [`Pop3Client::apply_action`] did with one action.
enum Applied {
    /// Bytes written (0 when the action produced no wire output).
    Sent(usize),
    /// QUIT was written and the session should end.
    Disconnect,
}

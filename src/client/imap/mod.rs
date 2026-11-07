//! IMAP client implementation
pub mod actions;

pub use actions::ImapClientProtocol;

use anyhow::{Context, Result};
use async_imap::{Client as ImapAsyncClient, Session};
use futures::StreamExt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, error, info, trace, warn};

use crate::client::imap::actions::{
    IMAP_CLIENT_CONNECTED_EVENT, IMAP_MAILBOX_SELECTED_EVENT, IMAP_MESSAGE_FETCHED_EVENT,
    IMAP_SEARCH_RESULTS_EVENT,
};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// The authenticated async-imap session. Named because it appears in four signatures.
type ImapSession = Session<tokio_util::compat::Compat<TcpStream>>;

/// IMAP client that connects to an IMAP server
pub struct ImapClient;

impl ImapClient {
    /// Connect to an IMAP server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Extract authentication credentials from startup params
        let (username, password) = if let Some(params) = startup_params {
            let username = params.get_string("username")?;
            let password = params.get_string("password")?;

            // `use_tls` is declared, and this protocol's CLAUDE.md described it as working
            // ("Upgrade to TLS if port 993 or use_tls=true"). Nothing read it, and this client
            // has no TLS support at all — `async_imap` is driven over a plain `TcpStream`. So
            // asking for TLS produced a cleartext session carrying the password above, with
            // both the parameter list and the documentation saying otherwise.
            //
            // Refusing is the fix, not silence. The project's rule is that hiding a capability
            // is worse than declining it out loud: the caller gets a reason they can act on,
            // and nobody hands credentials to a plaintext socket believing it is encrypted.
            // `use_tls: false` remains valid and means what it says.
            if params.get_optional_bool("use_tls")?.unwrap_or(false) {
                return Err(anyhow::anyhow!(
                    "IMAP client: `use_tls: true` was requested, but this client does not \
                     implement TLS — it speaks IMAP over a plain TCP socket. Connecting anyway \
                     would send the password for `{username}` in cleartext while reporting an \
                     encrypted session. Pass `use_tls: false` to accept a plaintext connection \
                     deliberately, or terminate TLS in front of the server."
                ));
            }
            (username, password)
        } else {
            return Err(anyhow::anyhow!(
                "IMAP client requires startup parameters: username, password"
            ));
        };

        info!(
            "IMAP client {} connecting to {} (user: {})",
            client_id, remote_addr, username
        );

        // Connect to IMAP server via TCP
        let tcp_stream = TcpStream::connect(&remote_addr)
            .await
            .context(format!("Failed to connect to IMAP at {}", remote_addr))?;

        let local_addr = tcp_stream.local_addr()?;

        // Convert tokio stream to futures-compatible stream
        let compat_stream = tcp_stream.compat();

        // Create IMAP client
        let imap_client = ImapAsyncClient::new(compat_stream);

        // Authenticate
        let session = match imap_client.login(&username, &password).await {
            Ok(session) => {
                info!("IMAP client {} authenticated successfully", client_id);
                session
            }
            Err((e, _)) => {
                error!("IMAP client {} authentication failed: {}", client_id, e);
                return Err(anyhow::anyhow!("IMAP login failed: {}", e));
            }
        };

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] IMAP client {} connected and authenticated",
            client_id
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Get initial instruction
        let instruction = if let Some(inst) = app_state.get_instruction_for_client(client_id).await
        {
            inst
        } else {
            return Err(anyhow::anyhow!("No instruction for IMAP client"));
        };

        // Spawn task to handle IMAP session with LLM integration
        let session_arc = Arc::new(Mutex::new(session));
        let protocol = Arc::new(actions::ImapClientProtocol::new());

        // The dashboard's `[ send ]` channel, registered BEFORE the connected-event LLM call
        // that the task below makes. A dashboard-created client defaults to a `*` -> manual
        // rule, so that call can park for minutes waiting for a human; registering after it
        // would leave the rail reading "no command channel" for the whole park.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let command_task = tokio::spawn(Self::command_loop(
            session_arc.clone(),
            protocol.clone(),
            command_rx,
            client_id,
            llm_client.clone(),
            app_state.clone(),
            status_tx.clone(),
        ));
        app_state
            .register_client_task(client_id, command_task)
            .await;

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            // Call LLM with connected event
            let event = Event::new(
                &IMAP_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": remote_addr,
                    "capabilities": vec!["IMAP4rev1"],
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

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
                        app_state.set_memory_for_client(client_id, mem).await;
                    }

                    // Execute initial actions from LLM
                    for action in actions {
                        if let Err(e) = Self::execute_imap_action(
                            client_id,
                            &session_arc,
                            &protocol,
                            &llm_client,
                            &app_state,
                            &status_tx,
                            action,
                        )
                        .await
                        {
                            error!("Failed to execute IMAP action: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for IMAP client {}: {}", client_id, e);
                }
            }
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }

    /// Drain injected commands (the dashboard's `[ send ]`) until the channel closes - which
    /// happens when the client is removed - or an injected `disconnect` ends the session.
    ///
    /// This is a task of its own rather than a `select!` arm because there is nothing to
    /// select against: `async_imap` owns the socket and this client has no read loop. The
    /// task is also what keeps the session usable after the connected-event handler returns.
    ///
    /// Injected actions go through [`Self::apply_action`] - the same function the LLM path
    /// uses - so the IMAP command encoding exists exactly once.
    ///
    /// Outcome semantics: `async_imap` writes and reads the tagged commands itself, so this
    /// loop can honestly claim no byte count. A verb that ran reports `Executed` naming it;
    /// a verb the server refused is an `Err`, never a quieter `Sent`.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        session: Arc<Mutex<ImapSession>>,
        protocol: Arc<ImapClientProtocol>,
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let mut disconnect = false;

            let outcome: Result<ClientSendOutcome> = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(ClientActionResult::Disconnect) => {
                    disconnect = true;
                    Ok(ClientSendOutcome::Disconnected)
                }
                Ok(ClientActionResult::WaitForMore) => Ok(ClientSendOutcome::Executed {
                    detail: "wait_for_more: nothing was asked of the server".to_string(),
                }),
                Ok(ClientActionResult::NoAction) => Ok(ClientSendOutcome::Executed {
                    detail: "no_action".to_string(),
                }),
                Ok(ClientActionResult::Custom { name, data }) => {
                    match Self::apply_action(client_id, &session, &name, &data, &status_tx).await {
                        Ok(followup) => {
                            // Report the result to the model from a task of its own. A
                            // dashboard-created client defaults to a `*` -> manual rule, so
                            // awaiting that call here would wedge this loop for the whole
                            // park -- far past the dashboard's 30s send timeout, on an action
                            // that in fact succeeded.
                            if let Some(event) = followup {
                                let (t_session, t_protocol, t_llm, t_state, t_status) = (
                                    session.clone(),
                                    protocol.clone(),
                                    llm_client.clone(),
                                    app_state.clone(),
                                    status_tx.clone(),
                                );
                                let task = tokio::spawn(async move {
                                    Self::report_event(
                                        client_id,
                                        &t_session,
                                        &t_protocol,
                                        &t_llm,
                                        &t_state,
                                        &t_status,
                                        event,
                                        0,
                                    )
                                    .await;
                                });
                                app_state.register_client_task(client_id, task).await;
                            }
                            Ok(ClientSendOutcome::Executed {
                                detail: format!(
                                    "{name} completed (async_imap frames the tagged command, so \
                                     there is no byte count to report)"
                                ),
                            })
                        }
                        Err(e) => Err(e.context(format!("injected IMAP action '{name}'"))),
                    }
                }
                Ok(other) => Ok(ClientSendOutcome::Executed {
                    detail: format!("unsupported action result {other:?}"),
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

            if let Err(e) = &outcome {
                Log::to(&status_tx).warn(format!(
                    "IMAP client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                // Best-effort LOGOUT so the server sees a clean close rather than a dropped
                // socket. Bounded, because the session is unusable either way once we stop
                // draining it and a server that never answers must not strand this task
                // holding the client's command handle.
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    session.lock().await.logout(),
                )
                .await;
                break;
            }
        }

        // Every exit lands here: drop the handle so the rail stops offering [ send ] on a
        // session nothing is draining any more.
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// How many times an action may be answered by an event that produces another action
    /// before this client stops asking. Each IMAP verb reports its result back to the model,
    /// and the model may reasonably chain SELECT -> SEARCH -> FETCH; without a bound, a model
    /// that answers `fetch_message` with `fetch_message` would loop on the LLM forever.
    const MAX_FOLLOWUP_DEPTH: u8 = 8;

    /// Execute a single IMAP action and potentially trigger more LLM calls
    async fn execute_imap_action(
        client_id: ClientId,
        session: &Arc<Mutex<ImapSession>>,
        protocol: &Arc<ImapClientProtocol>,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        action: serde_json::Value,
    ) -> Result<()> {
        Self::execute_imap_action_at_depth(
            client_id, session, protocol, llm_client, app_state, status_tx, action, 0,
        )
        .await
    }

    /// The recursive half of [`Self::execute_imap_action`].
    ///
    /// Boxed because it is genuinely self-referential: running an action raises an event, the
    /// event is answered by the model with more actions, and those actions come back here.
    /// An `async fn` that awaits itself has an infinitely-sized future type (E0391), so the
    /// recursion has to go through a `Pin<Box<dyn Future>>`.
    #[allow(clippy::too_many_arguments)]
    fn execute_imap_action_at_depth<'a>(
        client_id: ClientId,
        session: &'a Arc<Mutex<ImapSession>>,
        protocol: &'a Arc<ImapClientProtocol>,
        llm_client: &'a OllamaClient,
        app_state: &'a Arc<AppState>,
        status_tx: &'a mpsc::UnboundedSender<String>,
        action: serde_json::Value,
        depth: u8,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            match protocol.execute_action(action)? {
                ClientActionResult::Custom { name, data } => {
                    let followup =
                        Self::apply_action(client_id, session, &name, &data, status_tx).await?;

                    // Tell the model what the verb produced, and run whatever it answers with.
                    // Without this the client executed the action and said nothing, so the
                    // model could never chain SELECT -> SEARCH -> FETCH.
                    if let Some(event) = followup {
                        if depth >= Self::MAX_FOLLOWUP_DEPTH {
                            warn!(
                                "IMAP client {} reached the follow-up depth limit ({}); not \
                                 reporting {} to the model",
                                client_id,
                                Self::MAX_FOLLOWUP_DEPTH,
                                event.event_type.id
                            );
                            return Ok(());
                        }
                        Self::report_event(
                            client_id, session, protocol, llm_client, app_state, status_tx, event,
                            depth,
                        )
                        .await;
                    }
                }
                ClientActionResult::Disconnect => {
                    info!("IMAP client {} disconnecting", client_id);
                    // Stop offering [ send ] on a session that is going away.
                    app_state.remove_client_handle(client_id).await;
                    app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                }
                ClientActionResult::WaitForMore => {
                    debug!("IMAP client {} waiting for more events", client_id);
                }
                _ => {}
            }

            Ok(())
        })
    }

    /// Report an event to the model and run whatever it answers with.
    ///
    /// Kept out of [`Self::apply_action`] on purpose: the IMAP verbs must stay callable
    /// without an LLM round-trip, both because the injected-command path has its own timing
    /// and because a core that calls back into itself cannot be typed (see the boxing note
    /// on `execute_imap_action_at_depth`).
    #[allow(clippy::too_many_arguments)]
    async fn report_event(
        client_id: ClientId,
        session: &Arc<Mutex<ImapSession>>,
        protocol: &Arc<ImapClientProtocol>,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        event: Event,
        depth: u8,
    ) {
        let instruction = app_state
            .get_instruction_for_client(client_id)
            .await
            .unwrap_or_default();
        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        match call_llm_for_client(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            protocol.as_ref(),
            status_tx,
        )
        .await
        {
            Ok(ClientLlmResult {
                actions,
                memory_updates,
            }) => {
                if let Some(mem) = memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }
                for action in actions {
                    if let Err(e) = Self::execute_imap_action_at_depth(
                        client_id,
                        session,
                        protocol,
                        llm_client,
                        app_state,
                        status_tx,
                        action,
                        depth + 1,
                    )
                    .await
                    {
                        error!("Failed to execute IMAP action: {}", e);
                    }
                }
            }
            Err(e) => {
                // Nothing is written to the wire here: IMAP is client-driven, so the peer is
                // not waiting on a reply and silence costs it nothing. The log carries the
                // reason.
                error!(
                    "LLM error for IMAP client {} on {}: {}",
                    client_id, event.event_type.id, e
                );
            }
        }
    }

    /// Run one IMAP verb against the session.
    ///
    /// Returns the event the verb produced, for the caller to report to the model — this
    /// function never calls the LLM itself. Verbs with nothing to report return `None`.
    async fn apply_action(
        client_id: ClientId,
        session: &Arc<Mutex<ImapSession>>,
        action_name: &str,
        action_data: &serde_json::Value,
        _status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Option<Event>> {
        match action_name {
            "select_mailbox" => {
                let mailbox = action_data
                    .get("mailbox")
                    .and_then(|v| v.as_str())
                    .context("Missing mailbox")?;

                trace!("IMAP client {} selecting mailbox: {}", client_id, mailbox);

                let mut session_guard = session.lock().await;
                let mailbox_info = session_guard
                    .select(mailbox)
                    .await
                    .context("Failed to select mailbox")?;

                let exists = mailbox_info.exists;
                let recent = mailbox_info.recent;

                info!(
                    "IMAP client {} selected mailbox '{}' ({} messages, {} recent)",
                    client_id, mailbox, exists, recent
                );

                drop(session_guard);

                Ok(Some(Event::new(
                    &IMAP_MAILBOX_SELECTED_EVENT,
                    serde_json::json!({
                        "mailbox": mailbox,
                        "exists": exists,
                        "recent": recent,
                    }),
                )))
            }
            "search_messages" => {
                let criteria = action_data
                    .get("criteria")
                    .and_then(|v| v.as_str())
                    .context("Missing criteria")?;

                trace!("IMAP client {} searching: {}", client_id, criteria);

                let mut session_guard = session.lock().await;
                let message_ids = session_guard
                    .search(criteria)
                    .await
                    .context("Failed to search messages")?;

                let id_list: Vec<u32> = message_ids.iter().cloned().collect();
                info!(
                    "IMAP client {} found {} messages matching '{}'",
                    client_id,
                    id_list.len(),
                    criteria
                );

                drop(session_guard);

                Ok(Some(Event::new(
                    &IMAP_SEARCH_RESULTS_EVENT,
                    serde_json::json!({
                        "criteria": criteria,
                        "message_ids": id_list,
                    }),
                )))
            }
            "fetch_message" => {
                let message_id = action_data
                    .get("message_id")
                    .and_then(|v| v.as_str())
                    .context("Missing message_id")?;

                let parts = action_data
                    .get("parts")
                    .and_then(|v| v.as_str())
                    .unwrap_or("BODY[]");

                trace!(
                    "IMAP client {} fetching message {}: {}",
                    client_id,
                    message_id,
                    parts
                );

                let mut session_guard = session.lock().await;
                let messages = session_guard
                    .fetch(message_id, parts)
                    .await
                    .context("Failed to fetch message")?;

                // Collect messages from stream
                let mut message_list = vec![];
                let mut messages = Box::pin(messages);
                while let Some(Ok(fetch)) = messages.next().await {
                    message_list.push(fetch);
                }

                // Drop the stream first to release the borrow
                drop(messages);
                drop(session_guard);

                // Process fetched messages
                let mut messages = Vec::with_capacity(message_list.len());
                for fetch in message_list {
                    let body = fetch
                        .body()
                        .map(|b| String::from_utf8_lossy(b).to_string())
                        .unwrap_or_default();

                    let envelope = fetch.envelope();
                    let subject = envelope
                        .and_then(|e| e.subject.as_ref())
                        .and_then(|s| std::str::from_utf8(s).ok())
                        .unwrap_or("(no subject)");

                    let from = envelope
                        .and_then(|e| e.from.as_ref())
                        .and_then(|addrs| addrs.first())
                        .and_then(|addr| addr.mailbox.as_ref())
                        .and_then(|m| std::str::from_utf8(m).ok())
                        .unwrap_or("(unknown)");

                    info!(
                        "IMAP client {} fetched message {}: {} from {}",
                        client_id, message_id, subject, from
                    );

                    messages.push(serde_json::json!({
                        "subject": subject,
                        "from": from,
                        // The body used to be read and dropped on the floor. It is capped
                        // because a large message would otherwise dominate the prompt.
                        "body": crate::utils::truncate_for_llm(&body, 8192),
                    }));
                }

                Ok(Some(Event::new(
                    &IMAP_MESSAGE_FETCHED_EVENT,
                    serde_json::json!({
                        "message_id": message_id,
                        "messages": messages,
                    }),
                )))
            }
            "mark_as_read" => {
                let message_id = action_data
                    .get("message_id")
                    .and_then(|v| v.as_str())
                    .context("Missing message_id")?;

                trace!(
                    "IMAP client {} marking message {} as read",
                    client_id,
                    message_id
                );

                let mut session_guard = session.lock().await;
                let _ = session_guard
                    .store(message_id, "+FLAGS (\\Seen)")
                    .await
                    .context("Failed to mark message as read")?;

                info!(
                    "IMAP client {} marked message {} as read",
                    client_id, message_id
                );
                Ok(None)
            }
            "mark_as_unread" => {
                let message_id = action_data
                    .get("message_id")
                    .and_then(|v| v.as_str())
                    .context("Missing message_id")?;

                trace!(
                    "IMAP client {} marking message {} as unread",
                    client_id,
                    message_id
                );

                let mut session_guard = session.lock().await;
                let _ = session_guard
                    .store(message_id, "-FLAGS (\\Seen)")
                    .await
                    .context("Failed to mark message as unread")?;

                info!(
                    "IMAP client {} marked message {} as unread",
                    client_id, message_id
                );
                Ok(None)
            }
            "delete_message" => {
                let message_id = action_data
                    .get("message_id")
                    .and_then(|v| v.as_str())
                    .context("Missing message_id")?;

                trace!("IMAP client {} deleting message {}", client_id, message_id);

                let mut session_guard = session.lock().await;
                // Mark for deletion
                let _ = session_guard
                    .store(message_id, "+FLAGS (\\Deleted)")
                    .await
                    .context("Failed to mark message for deletion")?;

                // Expunge
                let _ = session_guard
                    .expunge()
                    .await
                    .context("Failed to expunge deleted messages")?;

                info!("IMAP client {} deleted message {}", client_id, message_id);
                Ok(None)
            }
            "list_mailboxes" => {
                trace!("IMAP client {} listing mailboxes", client_id);

                let mut session_guard = session.lock().await;
                let mailboxes = session_guard
                    .list(Some(""), Some("*"))
                    .await
                    .context("Failed to list mailboxes")?;

                // Collect mailboxes from stream
                let mut mailbox_list = vec![];
                let mut mailboxes = Box::pin(mailboxes);
                while let Some(Ok(mailbox)) = mailboxes.next().await {
                    mailbox_list.push(mailbox);
                }

                let mailbox_names: Vec<String> = mailbox_list
                    .iter()
                    .map(|m: &async_imap::types::Name| m.name().to_string())
                    .collect();

                info!(
                    "IMAP client {} listed {} mailboxes",
                    client_id,
                    mailbox_names.len()
                );

                debug!("Mailboxes: {:?}", mailbox_names);
                Ok(None)
            }
            _ => {
                debug!("Unknown IMAP action: {}", action_name);
                Ok(None)
            }
        }
    }
}

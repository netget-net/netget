//! AMQP client implementation using lapin library
pub mod actions;

pub use actions::AmqpClientProtocol;

use crate::client::amqp::actions::AMQP_CLIENT_CONNECTED_EVENT;
use crate::client::llm_budget::{call_llm_for_client, call_llm_for_client_batch};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};
use anyhow::{Context, Result};
use lapin::options::BasicPublishOptions;
use lapin::BasicProperties;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

/// The live broker connection plus every channel opened on it.
///
/// The channels are held here rather than dropped because a `lapin::Channel` closes when it
/// goes out of scope — an `open_channel` whose handle was dropped would have opened and shut
/// the channel in one breath, and the next `publish` would have had nothing to publish on.
/// How many LLM turns one AMQP event may drive before the chain is cut.
///
/// The concern that kept these answers unexecuted was real — every delivery raises
/// `amqp_message_received`, so a busy queue could drive a chain per message — but the remedy
/// for an unbounded chain is a bound, not silence. Each event starts its own bounded chain.
const MAX_FOLLOWUP_DEPTH: u8 = 4;

struct AmqpSession {
    conn: lapin::Connection,
    channels: Mutex<Vec<lapin::Channel>>,
}

impl AmqpSession {
    /// A channel to publish on: the most recently opened one, or a freshly opened one when
    /// nothing has opened a channel yet. Returns the channel and whether it was just opened.
    async fn channel_for_publish(&self) -> Result<(lapin::Channel, bool)> {
        // The guard is scoped to this block on purpose: the `create_channel().await` below
        // must not run while it is held.
        let existing = {
            let channels = self.channels.lock().await;
            channels
                .last()
                .filter(|channel| channel.status().connected())
                .cloned()
        };
        if let Some(channel) = existing {
            return Ok((channel, false));
        }
        let channel = self
            .conn
            .create_channel()
            .await
            .context("could not open an AMQP channel to publish on")?;
        self.channels.lock().await.push(channel.clone());
        Ok((channel, true))
    }
}

/// What [`apply_action`] did with one executed action.
enum AmqpApplied {
    /// The method completed on the wire, but lapin reports no byte count for it.
    Executed(String),
    /// A `Connection.Close` was sent to the broker.
    Disconnect,
}

/// AMQP client that connects to an AMQP broker (RabbitMQ, etc.)
pub struct AmqpClient;

impl AmqpClient {
    /// Connect to an AMQP broker with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        info!("AMQP client {} connecting to {}", client_id, remote_addr);

        // Connect to AMQP broker using lapin
        let conn = lapin::Connection::connect(
            &format!("amqp://{}", remote_addr),
            lapin::ConnectionProperties::default(),
        )
        .await
        .context(format!(
            "Failed to connect to AMQP broker at {}",
            remote_addr
        ))?;

        // Get local address (placeholder since lapin doesn't expose it)
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

        info!(
            "AMQP client {} connected to {} (local: {})",
            client_id, remote_addr, local_addr
        );

        let session = Arc::new(AmqpSession {
            conn,
            channels: Mutex::new(Vec::new()),
        });

        // Update client state
        state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] AMQP client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ]). Registered BEFORE
        // the connected-event LLM call below: a manual `*` rule parks that call until a human
        // answers it, and [ send ] has to work for the whole park.
        let command_rx =
            crate::client::command_support::register_command_channel(&state, client_id).await;
        let cmd_session = session.clone();
        let cmd_state = state.clone();
        let cmd_status_tx = status_tx.clone();
        let cmd_llm = llm_client.clone();
        let cmd_task = tokio::spawn(async move {
            command_loop(
                command_rx,
                cmd_session,
                client_id,
                cmd_state,
                cmd_llm,
                cmd_status_tx,
            )
            .await;
        });
        state.register_client_task(client_id, cmd_task).await;

        let protocol = AmqpClientProtocol::new();

        // Call LLM with amqp_connected event
        if let Some(instruction) = state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &AMQP_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "broker_addr": remote_addr.clone(),
                }),
            );

            match call_llm_for_client(
                &llm_client,
                &state,
                client_id.to_string(),
                &instruction,
                "",
                Some(&event),
                &protocol,
                &status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    if let Some(mem) = memory_updates {
                        state.set_memory_for_client(client_id, mem).await;
                    }
                    // Actually run what the model answered with. This used to be
                    // `Ok(_result) => info!("AMQP client ready after connect event")` — the
                    // actions were parsed, logged and thrown away, so `open_channel` on the
                    // connect event (the shape the protocol's own static-mode startup example
                    // shows) did nothing at all.
                    for action in actions {
                        match protocol.execute_action(action) {
                            Ok(result) => match apply_action(
                                result,
                                &session,
                                0,
                                client_id,
                                &state,
                                &llm_client,
                                &status_tx,
                            )
                            .await
                            {
                                Ok(AmqpApplied::Executed(detail)) => {
                                    debug!("AMQP client {}: {}", client_id, detail);
                                }
                                Ok(AmqpApplied::Disconnect) => {
                                    info!(
                                        "AMQP client {} disconnecting after connect event",
                                        client_id
                                    );
                                    break;
                                }
                                Err(e) => error!(
                                    "AMQP client {} could not apply action: {}",
                                    client_id, e
                                ),
                            },
                            Err(e) => {
                                error!("AMQP client {} rejected action: {}", client_id, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error on amqp_connected event: {}", e);
                }
            }
        }

        // Supervise the connection: hold the session alive and notice when the broker (or an
        // injected disconnect) closes it.
        //
        // This replaces `let _ = conn.run();`, which was a **blocking** call made from inside
        // a tokio task: `Connection::run` parks the current thread until the io loop ends, so
        // it burned a runtime worker for the lifetime of every AMQP client and never observed
        // the connection closing either.
        let supervisor_state = state.clone();
        let supervisor_status_tx = status_tx.clone();
        let supervisor_session = session.clone();
        let task_registrar = state.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if !supervisor_session.conn.status().connected() {
                    break;
                }
                if supervisor_state.get_client(client_id).await.is_none() {
                    break;
                }
            }
            info!("AMQP client {} connection closed", client_id);
            supervisor_state
                .update_client_status(client_id, ClientStatus::Disconnected)
                .await;
            // Drop the command handle so the dashboard stops offering [ send ] on a dead
            // connection; this also closes the command channel and ends `command_loop`.
            supervisor_state.remove_client_handle(client_id).await;
            let _ = supervisor_status_tx
                .send(format!("[CLIENT] AMQP client {} disconnected", client_id));
            let _ = supervisor_status_tx.send("__UPDATE_UI__".to_string());
        });
        task_registrar.register_client_task(client_id, handle).await;

        Ok(local_addr)
    }
}

/// Apply one executed action to the live broker connection.
///
/// Shared by the connected-event path and by injected commands, so the mapping from the
/// client's vocabulary onto lapin exists exactly once.
/// Returns an explicitly boxed future rather than being an `async fn`: the chain
/// `apply_action` -> `raise_amqp_event` -> `apply_action` is a cycle whose opaque return types
/// cannot be inferred (E0391).
#[allow(clippy::too_many_arguments)]
fn apply_action<'a>(
    action_result: ClientActionResult,
    session: &'a Arc<AmqpSession>,
    depth: u8,
    client_id: ClientId,
    state: &'a Arc<AppState>,
    llm_client: &'a OllamaClient,
    status_tx: &'a mpsc::UnboundedSender<String>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<AmqpApplied>> + Send + 'a>> {
    Box::pin(async move {
        match action_result {
            ClientActionResult::Custom { name, data } => {
                match name.as_str() {
                    "open_channel" => {
                        let channel = session
                            .conn
                            .create_channel()
                            .await
                            .context("Channel.Open failed")?;
                        let id = channel.id();
                        session.channels.lock().await.push(channel);
                        info!("AMQP client {} opened channel {}", client_id, id);

                        // amqp_channel_opened is advertised in get_event_types(), so the model can
                        // be told it exists and write a handler for it -- and nothing raised it.
                        raise_amqp_event(
                            &crate::client::amqp::actions::AMQP_CLIENT_CHANNEL_OPENED_EVENT,
                            serde_json::json!({ "channel_id": id }),
                            session,
                            depth,
                            client_id,
                            state,
                            llm_client,
                            status_tx,
                        )
                        .await;

                        Ok(AmqpApplied::Executed(format!(
                            "Channel.Open/Open-Ok completed; channel {id} is open"
                        )))
                    }
                    "consume" => {
                        let queue = data
                            .get("queue_name")
                            .and_then(|v| v.as_str())
                            .context("Missing queue_name for consume")?
                            .to_string();
                        let (channel, _) = session.channel_for_publish().await?;
                        let consumer = channel
                            .basic_consume(
                                queue.as_str().into(),
                                format!("netget-{client_id}").as_str().into(),
                                lapin::options::BasicConsumeOptions::default(),
                                lapin::types::FieldTable::default(),
                            )
                            .await
                            .context("Basic.Consume failed")?;

                        // Each delivery raises amqp_message_received. Without a consumer that
                        // event was unreachable: it is advertised in get_event_types(), so the
                        // model could be told messages would arrive and then never hear one.
                        let consume_session = session.clone();
                        let consume_state = state.clone();
                        let consume_llm = llm_client.clone();
                        let consume_tx = status_tx.clone();
                        let consume_queue = queue.clone();
                        // Deliveries that arrive while the model answers wait, whole, in lapin's
                        // consumer buffer. With batching on, everything already there is taken
                        // into the next call (one event per delivery); with it off, one per
                        // call. Each is acked here as it is taken, so none waits on the model.
                        let handle = tokio::spawn(async move {
                            use futures::{FutureExt, StreamExt};
                            let mut consumer = consumer;
                            let message = |delivery: lapin::message::Delivery| {
                                let body = String::from_utf8_lossy(&delivery.data).to_string();
                                let event = Event::new(
                                    &crate::client::amqp::actions::AMQP_CLIENT_MESSAGE_RECEIVED_EVENT,
                                    serde_json::json!({
                                        "queue_name": consume_queue,
                                        "message_body": body,
                                    }),
                                );
                                (delivery, event)
                            };
                            while let Some(delivery) = consumer.next().await {
                                let Ok(delivery) = delivery else { continue };
                                let mut taken = vec![message(delivery)];
                                // Read per delivery: batching is hot-changeable.
                                if consume_state
                                    .client_conversation_settings(client_id)
                                    .await
                                    .is_some_and(|(_, batching)| batching)
                                {
                                    while taken.len() < crate::protocol::metadata::MAX_BATCH_EVENTS
                                    {
                                        match consumer.next().now_or_never() {
                                            Some(Some(Ok(next))) => taken.push(message(next)),
                                            Some(Some(Err(_))) => continue,
                                            _ => break,
                                        }
                                    }
                                }
                                let mut events = Vec::with_capacity(taken.len());
                                for (delivery, event) in taken {
                                    let _ = delivery
                                        .ack(lapin::options::BasicAckOptions::default())
                                        .await;
                                    events.push(event);
                                }
                                raise_amqp_events(
                                    &events,
                                    &consume_session,
                                    0,
                                    client_id,
                                    &consume_state,
                                    &consume_llm,
                                    &consume_tx,
                                )
                                .await;
                            }
                        });
                        state.register_client_task(client_id, handle).await;

                        Ok(AmqpApplied::Executed(format!(
                            "Basic.Consume on '{queue}' accepted; deliveries raise \
                     amqp_message_received"
                        )))
                    }
                    "publish" => {
                        let exchange = data
                            .get("exchange")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let routing_key = data
                            .get("routing_key")
                            .and_then(|v| v.as_str())
                            .context("publish result has no 'routing_key'")?
                            .to_string();
                        let payload = data
                            .get("payload")
                            .and_then(|v| v.as_str())
                            .context("publish result has no 'payload'")?
                            .to_string();

                        let (channel, opened_now) = session.channel_for_publish().await?;
                        let channel_id = channel.id();
                        // The returned PublisherConfirm is dropped: confirm mode is not enabled, so
                        // there is no ack to wait for. The await above is what puts Basic.Publish and
                        // its content frames on the socket.
                        channel
                    .basic_publish(
                        exchange.as_str().into(),
                        routing_key.as_str().into(),
                        BasicPublishOptions::default(),
                        payload.as_bytes(),
                        BasicProperties::default(),
                    )
                    .await
                    .with_context(|| {
                        format!("Basic.Publish to exchange {exchange:?} key {routing_key:?} failed")
                    })?;
                        info!(
                    "AMQP client {} published {} bytes to exchange {:?} key {:?} on channel {}",
                    client_id,
                    payload.len(),
                    exchange,
                    routing_key,
                    channel_id
                );
                        Ok(AmqpApplied::Executed(format!(
                    "Basic.Publish of {} bytes to exchange {:?} routing key {:?} on channel {}{}",
                    payload.len(),
                    exchange,
                    routing_key,
                    channel_id,
                    if opened_now {
                        " (opened for this publish)"
                    } else {
                        ""
                    }
                )))
                    }
                    other => Err(anyhow::anyhow!(
                        "AMQP client cannot apply custom result '{}'",
                        other
                    )),
                }
            }
            ClientActionResult::Disconnect => {
                session
                    .conn
                    .close(200, "Goodbye".into())
                    .await
                    .context("Connection.Close failed")?;
                Ok(AmqpApplied::Disconnect)
            }
            ClientActionResult::WaitForMore => Ok(AmqpApplied::Executed(
                "waiting for the next AMQP frame; nothing sent".to_string(),
            )),
            ClientActionResult::NoAction => {
                Ok(AmqpApplied::Executed("no_action: nothing sent".to_string()))
            }
            ClientActionResult::SendData(_) => Err(anyhow::anyhow!(
                "AMQP frames are built by lapin; there is no raw-byte channel"
            )),
            ClientActionResult::Multiple(_) => Err(anyhow::anyhow!(
                "AMQP client does not support Multiple action results"
            )),
        }
    })
}

/// Drain injected commands (the dashboard's \[ send \]) until the channel closes — the client
/// was removed, or the supervisor saw the connection go — or an injected `disconnect` ends
/// the session.
///
/// This client had no loop at all before, so the loop is new; what it executes is not. Every
/// action goes through the protocol's own `execute_action` and then [`apply_action`], the same
/// pair the connected-event path uses.
async fn command_loop(
    mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
    session: Arc<AmqpSession>,
    client_id: ClientId,
    state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
) {
    use crate::llm::actions::protocol_trait::Protocol;
    use crate::state::client_handles::ClientSendOutcome;
    use crate::state::AccessLogOwner;

    let protocol = AmqpClientProtocol::new();

    while let Some(command) = command_rx.recv().await {
        let action = command.action.clone();
        let outcome: Result<ClientSendOutcome> = match protocol.execute_action(action.clone()) {
            Err(e) => Ok(ClientSendOutcome::Rejected {
                error: e.to_string(),
            }),
            Ok(result) => {
                match apply_action(
                    result,
                    &session,
                    0,
                    client_id,
                    &state,
                    &llm_client,
                    &status_tx,
                )
                .await
                {
                    // Never `Sent`: the AMQP method really did complete on the wire, but lapin
                    // frames and writes it internally and reports no byte count, so there is no
                    // honest number to put in `bytes_sent`.
                    Ok(AmqpApplied::Executed(detail)) => Ok(ClientSendOutcome::Executed { detail }),
                    Ok(AmqpApplied::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                    Err(e) => Err(e),
                }
            }
        };

        let outcome_json = match &outcome {
            Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
            Err(e) => serde_json::json!({"error": e.to_string()}),
        };
        state
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
            error!("AMQP client {} injected action failed: {}", client_id, e);
            let _ = status_tx.send(format!(
                "[WARN] Client {} injected action failed: {}",
                client_id, e
            ));
        }
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        crate::client::command_support::reply(command, outcome);

        if disconnect {
            // The supervisor drops the handle on its way out too; doing it here as well means
            // the dashboard stops offering [ send ] the moment Connection.Close went out.
            state.remove_client_handle(client_id).await;
            break;
        }
    }
}

/// Raise one AMQP event at the model and carry out what it answers with, bounded by
/// [`MAX_FOLLOWUP_DEPTH`].
///
/// This used to execute nothing, on the grounds that "the connect path and the command loop
/// own the session, and a delivery-driven action chain would be unbounded on a busy queue".
/// The ownership half was not true — the session is an `Arc<AmqpSession>` and `apply_action`
/// already took it by reference — and the unboundedness half is answered by a depth limit.
/// As written, a model told to consume a queue and republish what it saw was asked on every
/// delivery and ignored every time.
#[allow(clippy::too_many_arguments)]
async fn raise_amqp_event(
    event_type: &'static std::sync::LazyLock<crate::protocol::EventType>,
    data: serde_json::Value,
    session: &Arc<AmqpSession>,
    depth: u8,
    client_id: ClientId,
    state: &Arc<AppState>,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
) {
    raise_amqp_events(
        &[Event::new(event_type, data)],
        session,
        depth,
        client_id,
        state,
        llm_client,
        status_tx,
    )
    .await;
}

/// [`raise_amqp_event`] for several events answered in one model call — the deliveries a
/// batching consumer found waiting. The chain that follows is bounded the same way.
#[allow(clippy::too_many_arguments)]
async fn raise_amqp_events(
    events: &[Event],
    session: &Arc<AmqpSession>,
    depth: u8,
    client_id: ClientId,
    state: &Arc<AppState>,
    llm_client: &OllamaClient,
    status_tx: &mpsc::UnboundedSender<String>,
) {
    let Some(instruction) = state.get_instruction_for_client(client_id).await else {
        return;
    };
    let memory = state
        .get_memory_for_client(client_id)
        .await
        .unwrap_or_default();
    match call_llm_for_client_batch(
        llm_client,
        state,
        client_id.to_string(),
        &instruction,
        &memory,
        events,
        &AmqpClientProtocol::new(),
        status_tx,
    )
    .await
    {
        Ok(result) => {
            if let Some(mem) = result.memory_updates {
                state.set_memory_for_client(client_id, mem).await;
            }
            if result.actions.is_empty() {
                return;
            }
            if depth >= MAX_FOLLOWUP_DEPTH {
                warn!(
                    "AMQP client {} stopped a follow-up chain at depth {}: {} action(s) not \
                     executed",
                    client_id,
                    depth,
                    result.actions.len()
                );
                let _ = status_tx.send(format!(
                    "[CLIENT] ⚠ amqp client {} hit the follow-up depth limit ({}); {} action(s) \
                     were not executed",
                    client_id,
                    MAX_FOLLOWUP_DEPTH,
                    result.actions.len()
                ));
                return;
            }
            let protocol = AmqpClientProtocol::new();
            for action in result.actions {
                match protocol.execute_action(action) {
                    Ok(action_result) => {
                        if let Err(e) = apply_action(
                            action_result,
                            session,
                            depth + 1,
                            client_id,
                            state,
                            llm_client,
                            status_tx,
                        )
                        .await
                        {
                            error!("AMQP client {} follow-up action failed: {:#}", client_id, e);
                        }
                    }
                    Err(e) => warn!("AMQP client {} rejected follow-up action: {}", client_id, e),
                }
            }
        }
        Err(e) => error!("AMQP client {} LLM error on event: {}", client_id, e),
    }
}

//! Redis client implementation
pub mod actions;
pub mod cluster;
mod cluster_driver;
pub mod pubsub;
pub mod resp;

pub use actions::RedisClientProtocol;

use crate::llm::actions::client_trait::{Client, ClientActionResult};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace};

use crate::client::llm_budget::{call_llm_for_client, call_llm_for_client_batch};
use crate::client::redis::actions::{
    REDIS_CLIENT_CONNECTED_EVENT, REDIS_CLIENT_MESSAGE_EVENT, REDIS_CLIENT_RESPONSE_RECEIVED_EVENT,
    REDIS_CLIENT_SUBSCRIPTION_EVENT,
};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::patterns;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};
use pubsub::{Classified, Session};

/// Redis client that connects to a Redis server
pub struct RedisClient;

/// The startup parameters `connect` reads.
#[derive(Debug, Default, Clone, Copy)]
pub struct RedisClientOptions {
    /// Cluster mode: route by hash slot, follow MOVED/ASK (`cluster.rs`).
    pub cluster: bool,
    /// Send `HELLO 3` on connect.
    pub resp3: bool,
}

/// How many replies may wait while the model answers an earlier one; past it the reader stops
/// and TCP holds the server back.
const READ_QUEUE_REPLIES: usize = crate::protocol::metadata::MAX_BATCH_EVENTS;

/// What the reader task hands the answering loop.
enum Inbound {
    Reply(resp::Reply),
    Closed,
    Failed(String),
}

/// How long the server has to answer the `HELLO 3` sent on connect.
const HELLO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// What one executed action puts on the wire.
enum Wire {
    /// Commands for this connection, in order.
    Commands(Vec<Vec<Vec<u8>>>),
    /// A `PUBLISH`/`SPUBLISH`, which a subscribed RESP2 connection sends on a side connection.
    Publish(Vec<Vec<u8>>),
    /// Drop every subscription this connection holds.
    UnsubscribeAll,
    Disconnect,
    Nothing,
}

/// Turn an executed action into what it sends. The one place the client's Custom results are
/// decoded, shared by the stream connection and cluster mode.
fn wire_for(action_result: ClientActionResult, client_id: ClientId) -> Result<Wire> {
    let strings = |v: &serde_json::Value| -> Result<Vec<Vec<u8>>> {
        v.as_array()
            .ok_or_else(|| anyhow::anyhow!("a command is an array of strings"))?
            .iter()
            .map(|a| {
                a.as_str()
                    .map(|s| s.as_bytes().to_vec())
                    .ok_or_else(|| anyhow::anyhow!("a command argument is a string"))
            })
            .collect()
    };
    Ok(match action_result {
        ClientActionResult::Custom { name, data } => match name.as_str() {
            "redis_command" => {
                let command = data
                    .get("command")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing command in action data"))?;
                Wire::Commands(vec![resp::split_command(command)?])
            }
            "redis_commands" => Wire::Commands(
                data.get("commands")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| anyhow::anyhow!("Missing commands in action data"))?
                    .iter()
                    .map(strings)
                    .collect::<Result<_>>()?,
            ),
            "redis_publish" => Wire::Publish(strings(
                data.get("args")
                    .ok_or_else(|| anyhow::anyhow!("Missing args in action data"))?,
            )?),
            "redis_unsubscribe_all" => Wire::UnsubscribeAll,
            other => {
                debug!(
                    "Redis client {} ignoring unhandled custom result: {}",
                    client_id, other
                );
                Wire::Nothing
            }
        },
        ClientActionResult::Disconnect => Wire::Disconnect,
        other => {
            debug!(
                "Redis client {} ignoring unhandled action result: {:?}",
                client_id, other
            );
            Wire::Nothing
        }
    })
}

/// The event one reply raises: a delivered message, a subscription confirmation, or an
/// ordinary reply.
fn event_for(reply: &resp::Reply, session: &Session) -> Event {
    match session.classify(reply) {
        Classified::Message {
            kind,
            pattern,
            channel,
            message,
        } => {
            let mut data = serde_json::json!({
                "kind": kind,
                "channel": channel,
                "message": message,
                "subscriptions": session.snapshot(),
                "protocol": if reply.reply_type == "push" { 3 } else { 2 },
            });
            if let Some(p) = pattern {
                data["pattern"] = serde_json::Value::String(p);
            }
            Event::new(&REDIS_CLIENT_MESSAGE_EVENT, data)
        }
        Classified::Subscription {
            kind,
            channel,
            count,
        } => Event::new(
            &REDIS_CLIENT_SUBSCRIPTION_EVENT,
            serde_json::json!({
                "kind": kind,
                "channel": channel,
                "count": count,
                "subscriptions": session.snapshot(),
            }),
        ),
        Classified::Reply => Event::new(&REDIS_CLIENT_RESPONSE_RECEIVED_EVENT, reply.event_data()),
    }
}

impl RedisClient {
    /// Connect to a Redis server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        options: RedisClientOptions,
    ) -> Result<SocketAddr> {
        if options.cluster {
            anyhow::ensure!(
                !options.resp3,
                "resp3 is not available in cluster mode: cluster connections speak RESP2"
            );
            return cluster_driver::connect(
                remote_addr,
                llm_client,
                app_state,
                status_tx,
                client_id,
            )
            .await;
        }

        // Connect to Redis server
        let stream = TcpStream::connect(&remote_addr)
            .await
            .context(format!("Failed to connect to Redis at {}", remote_addr))?;

        let local_addr = stream.local_addr()?;
        let remote_sock_addr = stream.peer_addr()?;

        info!(
            "Redis client {} {} {} (local: {})",
            client_id,
            patterns::REDIS_CLIENT_CONNECTED,
            remote_sock_addr,
            local_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] Redis client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Split stream
        let (read_half, write_half) = tokio::io::split(stream);
        let write_half_arc = Arc::new(Mutex::new(write_half));
        let mut reader = BufReader::new(read_half);
        let protocol = Arc::new(RedisClientProtocol::new());
        let session = Arc::new(Session::new(remote_addr.clone()));

        // RESP3 is agreed before the model hears the client is connected, so its first command
        // already runs on the protocol it asked for. A server that refuses fails the connect.
        if options.resp3 {
            write_half_arc
                .lock()
                .await
                .write_all(&resp::encode_command(&[b"HELLO".to_vec(), b"3".to_vec()]))
                .await?;
            let reply = tokio::time::timeout(HELLO_TIMEOUT, resp::read_reply(&mut reader))
                .await
                .context("the server did not answer HELLO 3")??
                .context("the server closed the connection instead of answering HELLO 3")?;
            session.classify(&reply);
            anyhow::ensure!(
                session.is_resp3(),
                "the server refused RESP3: HELLO 3 was answered with {}",
                reply.response
            );
            info!("Redis client {} speaks RESP3", client_id);
        }

        // Command channel for injected actions (the dashboard's [ execute_redis_command ]).
        // Registered BEFORE the connected-event LLM call, which a manual `*` rule can park
        // for minutes - the operator must be able to reach the client while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // `read_reply` is not cancellation-safe, so the commands are drained by their own task
        // rather than a `select!` arm in the read loop. Both tasks share the write half.
        let cmd_state = app_state.clone();
        let cmd_tx = status_tx.clone();
        let cmd_write = write_half_arc.clone();
        let cmd_protocol = protocol.clone();
        let cmd_session = session.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(
                command_rx,
                cmd_protocol,
                cmd_write,
                client_id,
                cmd_state,
                cmd_tx,
                cmd_session,
            )
            .await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with redis_connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &REDIS_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": remote_sock_addr.to_string(),
                }),
            );

            // `initial_memory` is written before `connect()` runs
            // (`src/cli/client_startup.rs`), so it is available here; passing an empty string
            // discarded whatever the operator or the model had set up.
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
                Ok(result) => {
                    // A `set_memory` on the connect turn used to be dropped on the floor -
                    // `result.memory_updates` was never read - so the model could not carry
                    // anything from its first turn into the next one. mysql and postgresql
                    // both do this correctly.
                    if let Some(mem) = result.memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }
                    for action in result.actions {
                        match protocol.execute_action(action) {
                            Ok(action_result) => {
                                match Self::apply_action(
                                    action_result,
                                    &write_half_arc,
                                    client_id,
                                    &session,
                                )
                                .await
                                {
                                    Ok(Applied::Disconnect) => {
                                        info!("LLM requested disconnect after connect");
                                        let _ = write_half_arc.lock().await.shutdown().await;
                                        app_state.remove_client_handle(client_id).await;
                                        app_state
                                            .update_client_status(
                                                client_id,
                                                ClientStatus::Disconnected,
                                            )
                                            .await;
                                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                                        return Ok(local_addr);
                                    }
                                    Ok(Applied::Sent(_)) => {}
                                    Err(e) => {
                                        error!("Failed to send Redis command after connect: {}", e)
                                    }
                                }
                            }
                            Err(e) => {
                                error!(
                                    "Redis client {} could not execute action after connect: {}",
                                    client_id, e
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error on redis_connected event: {}", e);
                }
            }
        }

        // The reader runs on its own task so that what the server sends while the model is
        // answering — pub/sub deliveries above all — waits as whole replies on a bounded queue
        // rather than unread in the socket. With batching on, the answering loop takes every
        // reply already waiting into one call (one event each); with it off, one per call.
        // `read_reply` is not cancellation-safe, which a task of its own also respects: it is
        // never raced in a `select!`, only aborted when the session ends. Registered, so
        // stop_client aborts it too.
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Inbound>(READ_QUEUE_REPLIES);
        let reader_task = app_state
            .spawn_client_task(client_id, async move {
                loop {
                    // One complete RESP reply per event — a bulk string or an array is never
                    // split across events. See `resp.rs` for the framing and its bounds.
                    let message = match resp::read_reply(&mut reader).await {
                        Ok(None) => Inbound::Closed,
                        Ok(Some(reply)) => Inbound::Reply(reply),
                        // A socket error, or a reply that is not RESP or breaks a bound in
                        // `resp.rs`. Either way this connection's framing is gone.
                        Err(e) => Inbound::Failed(e.to_string()),
                    };
                    let last = !matches!(message, Inbound::Reply(_));
                    if inbound_tx.send(message).await.is_err() || last {
                        break;
                    }
                }
            })
            .await;

        // The answering loop. Registered with AppState so stop_client can abort it and
        // release the socket.
        let task_registrar = app_state.clone();
        let handle = tokio::spawn(async move {
            while let Some(first) = inbound_rx.recv().await {
                // This reply, plus — with batching on — every reply already waiting.
                let mut replies = Vec::new();
                let mut ended = None;
                match first {
                    Inbound::Reply(reply) => replies.push(reply),
                    other => ended = Some(other),
                }
                if ended.is_none()
                    && app_state
                        .client_conversation_settings(client_id)
                        .await
                        .is_some_and(|(_, batching)| batching)
                {
                    while replies.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                        match inbound_rx.try_recv() {
                            Ok(Inbound::Reply(reply)) => replies.push(reply),
                            Ok(other) => {
                                ended = Some(other);
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                }

                for reply in &replies {
                    trace!(
                        "Redis client {} received {}: {}",
                        client_id,
                        reply.reply_type,
                        crate::utils::truncate::truncate_for_log(&reply.response, 200)
                    );
                }

                if !replies.is_empty() {
                    if let Some(instruction) = app_state.get_instruction_for_client(client_id).await
                    {
                        // A delivered message and a subscription confirmation are their own
                        // events; everything else is a reply. Classified in arrival order,
                        // because classifying a confirmation updates the subscription set.
                        let events: Vec<Event> =
                            replies.iter().map(|r| event_for(r, &session)).collect();

                        let memory = app_state
                            .get_memory_for_client(client_id)
                            .await
                            .unwrap_or_default();

                        match call_llm_for_client_batch(
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
                                // Update memory
                                if let Some(mem) = memory_updates {
                                    app_state.set_memory_for_client(client_id, mem).await;
                                }

                                // Execute actions
                                //
                                // `disconnect_requested` rather than a bare `break`: the break
                                // here left only the `for action in actions` loop, so the read
                                // loop carried straight on and the socket stayed open. Nor did
                                // it shut the write half, drop the command handle or set
                                // `Disconnected` - all of which the connect-time path above
                                // does. The model could ask this client to disconnect and
                                // nothing at all happened.
                                let mut disconnect_requested = false;
                                for action in actions {
                                    match protocol.execute_action(action) {
                                        Ok(action_result) => {
                                            match Self::apply_action(
                                                action_result,
                                                &write_half_arc,
                                                client_id,
                                                &session,
                                            )
                                            .await
                                            {
                                                Ok(Applied::Disconnect) => {
                                                    info!(
                                                        "Redis client {} disconnecting",
                                                        client_id
                                                    );
                                                    disconnect_requested = true;
                                                    break;
                                                }
                                                Ok(Applied::Sent(_)) => {}
                                                Err(e) => {
                                                    error!(
                                                        "Redis client {} write failed: {}",
                                                        client_id, e
                                                    );
                                                }
                                            }
                                        }
                                        // Do not swallow. `_ => {}` here meant an action the
                                        // client cannot execute — including one it never
                                        // advertised — was indistinguishable from success:
                                        // nothing went on the wire and nothing said so. Two
                                        // tests passed at HEAD while sending `wait_for_more`,
                                        // which this client does not implement.
                                        Err(e) => {
                                            error!(
                                                "Redis client {} could not execute action: {}",
                                                client_id, e
                                            );
                                            let _ = status_tx.send(format!(
                                                "[ERROR] Redis client {} action failed: {}",
                                                client_id, e
                                            ));
                                        }
                                    }
                                }

                                if disconnect_requested {
                                    // The same teardown the connect-time path runs: half-close
                                    // so the server sees EOF, drop the command handle so the
                                    // dashboard stops offering [ send ] on a client whose loop
                                    // is gone, and record the status.
                                    let _ = write_half_arc.lock().await.shutdown().await;
                                    app_state.remove_client_handle(client_id).await;
                                    app_state
                                        .update_client_status(client_id, ClientStatus::Disconnected)
                                        .await;
                                    let _ = status_tx.send(format!(
                                        "[CLIENT] Redis client {} disconnected",
                                        client_id
                                    ));
                                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("LLM error for Redis client {}: {}", client_id, e);
                            }
                        }
                    }
                }

                match ended {
                    None | Some(Inbound::Reply(_)) => {}
                    Some(Inbound::Closed) => {
                        info!(
                            "Redis client {} {}",
                            client_id,
                            patterns::REDIS_CLIENT_DISCONNECTED
                        );
                        app_state
                            .update_client_status(client_id, ClientStatus::Disconnected)
                            .await;
                        let _ = status_tx
                            .send(format!("[CLIENT] Redis client {} disconnected", client_id));
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    Some(Inbound::Failed(e)) => {
                        error!("Redis client {} read error: {}", client_id, e);
                        app_state
                            .update_client_status(client_id, ClientStatus::Error(e))
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                }
            }
            reader_task.abort();
            // Every exit path lands here: drop the command handle so the dashboard stops
            // offering [ send ] on a dead connection (a late send then fails fast). This
            // also closes the command channel, which ends `command_loop`.
            app_state.remove_client_handle(client_id).await;
            let _ = status_tx.send("__UPDATE_UI__".to_string());
        });
        task_registrar.register_client_task(client_id, handle).await;

        Ok(local_addr)
    }

    /// Drain injected commands until the channel closes (client removed) or an injected
    /// `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot run this client's
    /// vocabulary because `execute_redis_command` yields `ClientActionResult::Custom`, so the
    /// action goes through [`Self::apply_action`] - the same function the LLM path uses -
    /// and the outcome is recorded and replied exactly the way the generic arm does it.
    async fn command_loop<W>(
        mut command_rx: tokio::sync::mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        protocol: Arc<RedisClientProtocol>,
        write_half: Arc<Mutex<W>>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        session: Arc<Session>,
    ) where
        W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => Self::apply_action(result, &write_half, client_id, &session)
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
                error!("Redis client {} injected action failed: {}", client_id, e);
                let _ = status_tx.send(format!(
                    "[WARN] Client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                // Half-close so the server reads EOF and the read loop runs its normal
                // disconnect path.
                let _ = write_half.lock().await.shutdown().await;
                break;
            }
        }
    }

    /// Put one executed action on the wire. Shared by the connected-event path, the read
    /// loop and injected commands so the RESP encoding of every client verb exists exactly
    /// once.
    async fn apply_action<W>(
        action_result: ClientActionResult,
        write_half: &Arc<Mutex<W>>,
        client_id: ClientId,
        session: &Session,
    ) -> Result<Applied>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let commands = match wire_for(action_result, client_id)? {
            Wire::Disconnect => return Ok(Applied::Disconnect),
            Wire::Nothing => return Ok(Applied::Sent(0)),
            Wire::Commands(commands) => commands,
            Wire::UnsubscribeAll => session.unsubscribe_all_commands(),
            Wire::Publish(args) if session.subscribed_resp2() => {
                // Redis refuses PUBLISH on a RESP2 connection in subscribed mode, so it goes
                // over a short second connection to the same server.
                let receivers =
                    pubsub::publish_on_side_connection(&session.remote_addr, &args).await?;
                info!(
                    "Redis client {} published on a side connection (this one is subscribed): \
                     {} receiver(s)",
                    client_id, receivers
                );
                return Ok(Applied::Sent(resp::encode_command(&args).len()));
            }
            Wire::Publish(args) => vec![args],
        };
        let mut sent = 0;
        for args in commands {
            let cmd_bytes = resp::encode_command(&args);
            session.note_sent(&args);
            let mut writer = write_half.lock().await;
            writer.write_all(&cmd_bytes).await?;
            writer.flush().await?;
            info!(
                "{} {}",
                patterns::REDIS_CLIENT_SENT_COMMAND,
                crate::utils::truncate_for_log(
                    &args
                        .iter()
                        .map(|a| String::from_utf8_lossy(a).to_string())
                        .collect::<Vec<_>>()
                        .join(" "),
                    256
                )
            );
            sent += cmd_bytes.len();
        }
        Ok(Applied::Sent(sent))
    }
}

/// What [`RedisClient::apply_action`] did with one action.
enum Applied {
    /// Bytes written (0 when the action produced no wire output).
    Sent(usize),
    /// The session should end.
    Disconnect,
}

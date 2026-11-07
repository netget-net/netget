//! Memcached client: NetGet dials a memcached server and the model drives the text protocol.
//!
//! Three tasks per connection, all registered with the client so `stop_client` ends them:
//!
//! * **transport** owns the socket and the FIFO of requests in flight. It writes requests,
//!   reads replies one whole response at a time (`wire::parse_reply`), and queues each for
//!   the model. It never waits on the model, so a turn parked for a human cannot stall it.
//! * **turns** asks the model about each queued reply, in order, and hands every action it
//!   returns back to the transport. The chain request → reply → model → request continues
//!   through that queue, so it needs no recursion and no depth counter.
//! * **commands** executes actions injected from outside (the dashboard's `[ send ]`, MCP
//!   `send_to_client`) through the same path the model's actions take.

pub mod actions;
pub mod wire;

pub use actions::MemcachedClientProtocol;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::memcached::actions::{
    request_from_action, MEMCACHED_CONNECTED_EVENT, MEMCACHED_COUNTER_EVENT,
    MEMCACHED_DELETED_EVENT, MEMCACHED_ERROR_EVENT, MEMCACHED_EXISTS_EVENT, MEMCACHED_MISS_EVENT,
    MEMCACHED_NOT_FOUND_EVENT, MEMCACHED_NOT_STORED_EVENT, MEMCACHED_OK_EVENT,
    MEMCACHED_STATS_EVENT, MEMCACHED_STORED_EVENT, MEMCACHED_TOUCHED_EVENT, MEMCACHED_VALUE_EVENT,
    MEMCACHED_VERSION_EVENT, REQUEST_RESULT,
};
use crate::client::memcached::wire::{parse_reply, stats_json, Expect, Reply, Request};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// Replies that may wait for the model while a turn is running. The transport never blocks
/// on this queue: when it is full a reply is dropped with `decision=turn_queue_full`.
const TURN_QUEUE_CAPACITY: usize = 256;

/// Requests written and not yet answered. A model that pipelines past this is refused rather
/// than letting the FIFO grow without bound.
const MAX_IN_FLIGHT: usize = 128;

/// Requests waiting for the transport to write them.
const OUTBOUND_CAPACITY: usize = 64;

/// What the turn and command tasks ask the transport to do.
enum Outbound {
    Request {
        request: Request,
        ack: oneshot::Sender<Result<usize, String>>,
    },
    Disconnect {
        ack: oneshot::Sender<()>,
    },
}

/// One thing the model is asked about.
enum Turn {
    Connected,
    Reply { expect: Expect, reply: Reply },
}

/// What one action did.
enum Applied {
    Sent(usize),
    Nothing,
    Disconnect,
}

pub struct MemcachedClient;

impl MemcachedClient {
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // A client that lost its target must fail, never guess one.
        if remote_addr.trim().is_empty() {
            return Err(anyhow!(
                "memcached client needs a remote_addr (host:port); refusing to connect \
                 without one"
            ));
        }
        let stream = TcpStream::connect(&remote_addr)
            .await
            .with_context(|| format!("Failed to connect to memcached at {remote_addr}"))?;
        let local_addr = stream.local_addr()?;
        let peer = stream.peer_addr()?;
        info!("Memcached client {client_id} connected to {peer} (local {local_addr})");
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] Memcached client {client_id} connected"));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let protocol = Arc::new(MemcachedClientProtocol::new());
        let (outbound_tx, outbound_rx) = mpsc::channel::<Outbound>(OUTBOUND_CAPACITY);
        let (turn_tx, turn_rx) = mpsc::channel::<Turn>(TURN_QUEUE_CAPACITY);

        // Registered before the connected turn can run, so the operator can reach the client
        // while that turn is parked on a manual rule.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        app_state
            .spawn_client_task(
                client_id,
                command_loop(
                    command_rx,
                    protocol.clone(),
                    outbound_tx.clone(),
                    client_id,
                    app_state.clone(),
                    status_tx.clone(),
                ),
            )
            .await;

        let turn_abort = app_state
            .spawn_client_task(
                client_id,
                run_turns(
                    turn_rx,
                    outbound_tx,
                    protocol,
                    llm_client,
                    app_state.clone(),
                    status_tx.clone(),
                    client_id,
                    peer.to_string(),
                ),
            )
            .await;

        let _ = turn_tx.try_send(Turn::Connected);
        app_state
            .spawn_client_task(
                client_id,
                run_transport(
                    stream,
                    outbound_rx,
                    turn_tx,
                    app_state.clone(),
                    status_tx,
                    client_id,
                    turn_abort,
                ),
            )
            .await;

        Ok(local_addr)
    }
}

/// Own the socket for the life of the connection.
async fn run_transport(
    stream: TcpStream,
    mut outbound_rx: mpsc::Receiver<Outbound>,
    turn_tx: mpsc::Sender<Turn>,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
    turn_abort: tokio::task::AbortHandle,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut pending: VecDeque<Expect> = VecDeque::new();
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut chunk = vec![0u8; 16 * 1024];

    let status = loop {
        tokio::select! {
            read = reader.read(&mut chunk) => {
                let n = match read {
                    Ok(0) => {
                        info!("Memcached client {client_id} closed by server");
                        break ClientStatus::Disconnected;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        error!("Memcached client {client_id} read error: {e}");
                        break ClientStatus::Error(e.to_string());
                    }
                };
                buf.extend_from_slice(&chunk[..n]);
                if let Err(e) = drain_replies(&mut buf, &mut pending, &turn_tx, client_id) {
                    error!("Memcached client {client_id} protocol error: {e}");
                    break ClientStatus::Error(e);
                }
            }
            out = outbound_rx.recv() => match out {
                None => break ClientStatus::Disconnected,
                Some(Outbound::Disconnect { ack }) => {
                    let _ = writer.shutdown().await;
                    let _ = ack.send(());
                    info!("Memcached client {client_id} disconnected on request");
                    break ClientStatus::Disconnected;
                }
                Some(Outbound::Request { request, ack }) => {
                    if pending.len() >= MAX_IN_FLIGHT {
                        let _ = ack.send(Err(format!(
                            "{MAX_IN_FLIGHT} requests are already waiting for a reply"
                        )));
                        continue;
                    }
                    let bytes = request.encode();
                    let written = async {
                        writer.write_all(&bytes).await?;
                        writer.flush().await
                    }
                    .await;
                    match written {
                        Ok(()) => {
                            debug!(
                                "Memcached client {client_id} sent {} ({} bytes)",
                                request.command(),
                                bytes.len()
                            );
                            pending.push_back(request.expect());
                            let _ = ack.send(Ok(bytes.len()));
                        }
                        Err(e) => {
                            let _ = ack.send(Err(format!("write failed: {e}")));
                            error!("Memcached client {client_id} write error: {e}");
                            break ClientStatus::Error(e.to_string());
                        }
                    }
                }
            }
        }
    };

    turn_abort.abort();
    app_state.remove_client_handle(client_id).await;
    app_state.update_client_status(client_id, status).await;
    let _ = status_tx.send(format!(
        "[CLIENT] Memcached client {client_id} disconnected"
    ));
    let _ = status_tx.send("__UPDATE_UI__".to_string());
}

/// Take every complete reply off the front of `buf`, pairing each with its request.
fn drain_replies(
    buf: &mut Vec<u8>,
    pending: &mut VecDeque<Expect>,
    turn_tx: &mpsc::Sender<Turn>,
    client_id: ClientId,
) -> Result<(), String> {
    while !buf.is_empty() {
        let Some(expect) = pending.front() else {
            return Err(format!(
                "server sent {} octets with no request in flight",
                buf.len()
            ));
        };
        match parse_reply(buf, expect).map_err(|e| e.to_string())? {
            None => return Ok(()),
            Some((reply, used)) => {
                buf.drain(..used);
                let expect = pending.pop_front().expect("front() was Some");
                if turn_tx.try_send(Turn::Reply { expect, reply }).is_err() {
                    warn!(
                        "Memcached client {client_id} dropped a reply: the model is \
                         {TURN_QUEUE_CAPACITY} replies behind decision=turn_queue_full"
                    );
                }
            }
        }
    }
    Ok(())
}

/// The events one reply becomes. A `get` becomes one per requested key, in request order.
fn events_for(expect: &Expect, reply: Reply) -> Vec<Event> {
    use crate::utils::sanitize::line_field;
    match (expect, reply) {
        (Expect::Values { keys, .. }, Reply::Values { items, .. }) => keys
            .iter()
            .map(|key| match items.iter().find(|i| &i.key == key) {
                None => Event::new(&MEMCACHED_MISS_EVENT, json!({ "key": key })),
                Some(item) => match std::str::from_utf8(&item.data) {
                    Ok(text) => {
                        let mut data = json!({
                            "key": key,
                            "value": text,
                            "flags": item.flags,
                        });
                        if let Some(cas) = item.cas {
                            data["cas"] = json!(cas);
                        }
                        Event::new(&MEMCACHED_VALUE_EVENT, data)
                    }
                    Err(_) => Event::new(
                        &MEMCACHED_ERROR_EVENT,
                        json!({
                            "kind": "non_text_value",
                            "message": format!(
                                "the value stored under {key:?} is {} bytes that are not \
                                 valid UTF-8; this client carries values as text only and \
                                 does not re-encode them",
                                item.data.len()
                            ),
                            "command": "get",
                            "key": key,
                        }),
                    ),
                },
            })
            .collect(),
        (Expect::Stats { group }, Reply::Stats { entries }) => {
            let mut data = json!({ "stats": stats_json(&entries) });
            if let Some(g) = group {
                data["group"] = json!(g);
            }
            vec![Event::new(&MEMCACHED_STATS_EVENT, data)]
        }
        (expect, Reply::Error { kind, message }) => {
            let (command, key) = match expect {
                Expect::Values { keys, with_cas } => (
                    if *with_cas { "gets" } else { "get" },
                    keys.first().cloned(),
                ),
                Expect::Status { command, key } => (*command, key.clone()),
                Expect::Stats { .. } => ("stats", None),
            };
            let mut data = json!({
                "kind": kind,
                "message": line_field(&message),
                "command": command,
            });
            if let Some(k) = key {
                data["key"] = json!(k);
            }
            vec![Event::new(&MEMCACHED_ERROR_EVENT, data)]
        }
        (Expect::Status { command, key }, Reply::Status { line }) => {
            let key = key.clone().unwrap_or_default();
            let command = *command;
            let event = match (command, line.as_str()) {
                (_, "STORED") => Event::new(
                    &MEMCACHED_STORED_EVENT,
                    json!({"command": command, "key": key}),
                ),
                (_, "NOT_STORED") => Event::new(
                    &MEMCACHED_NOT_STORED_EVENT,
                    json!({"command": command, "key": key}),
                ),
                (_, "EXISTS") => Event::new(
                    &MEMCACHED_EXISTS_EVENT,
                    json!({"command": command, "key": key}),
                ),
                (_, "NOT_FOUND") => Event::new(
                    &MEMCACHED_NOT_FOUND_EVENT,
                    json!({"command": command, "key": key}),
                ),
                ("delete", "DELETED") => Event::new(&MEMCACHED_DELETED_EVENT, json!({"key": key})),
                ("touch", "TOUCHED") => Event::new(&MEMCACHED_TOUCHED_EVENT, json!({"key": key})),
                ("flush_all", "OK") => Event::new(&MEMCACHED_OK_EVENT, json!({"command": command})),
                ("version", line) if line.starts_with("VERSION ") => Event::new(
                    &MEMCACHED_VERSION_EVENT,
                    json!({"version": line_field(&line["VERSION ".len()..])}),
                ),
                ("incr" | "decr", line) if line.parse::<u64>().is_ok() => Event::new(
                    &MEMCACHED_COUNTER_EVENT,
                    json!({
                        "command": command,
                        "key": key,
                        "value": line.parse::<u64>().unwrap_or_default(),
                    }),
                ),
                (_, line) => Event::new(
                    &MEMCACHED_ERROR_EVENT,
                    json!({
                        "kind": "unexpected_reply",
                        "message": format!(
                            "the server answered {:?}, which is not a reply to {command}",
                            line_field(line)
                        ),
                        "command": command,
                        "key": key,
                    }),
                ),
            };
            vec![event]
        }
        // `parse_reply` only produces a reply of the shape its `Expect` asks for.
        (_, other) => {
            warn!("Memcached reply {other:?} does not match its request {expect:?}");
            Vec::new()
        }
    }
}

/// Answer queued replies with the model, one at a time and in arrival order.
#[allow(clippy::too_many_arguments)]
async fn run_turns(
    mut turn_rx: mpsc::Receiver<Turn>,
    outbound_tx: mpsc::Sender<Outbound>,
    protocol: Arc<MemcachedClientProtocol>,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
    remote_addr: String,
) {
    while let Some(turn) = turn_rx.recv().await {
        let events = match turn {
            Turn::Connected => vec![Event::new(
                &MEMCACHED_CONNECTED_EVENT,
                json!({ "remote_addr": remote_addr }),
            )],
            Turn::Reply { expect, reply } => events_for(&expect, reply),
        };
        for event in events {
            let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
                continue;
            };
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
                    if let Some(mem) = result.memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }
                    info!(
                        "Memcached client {client_id} {} decision={} actions={}",
                        event.id(),
                        if result.actions.is_empty() {
                            "model_silent"
                        } else {
                            "model_actions"
                        },
                        result.actions.len()
                    );
                    for action in result.actions {
                        match apply_action(protocol.as_ref(), &outbound_tx, action).await {
                            Ok(Applied::Disconnect) => return,
                            Ok(_) => {}
                            Err(e) => {
                                Log::to(&status_tx).error(format!(
                                    "Memcached client {client_id} action failed: {e}"
                                ));
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Memcached client {client_id} {} decision=llm_error: {e}",
                        event.id()
                    );
                }
            }
        }
    }
}

/// Execute one action and hand its request to the transport. Shared by the model's turns and
/// injected commands, so both take exactly one path onto the wire.
async fn apply_action(
    protocol: &MemcachedClientProtocol,
    outbound_tx: &mpsc::Sender<Outbound>,
    action: serde_json::Value,
) -> Result<Applied> {
    match protocol.execute_action(action)? {
        ClientActionResult::Custom { name, data } if name == REQUEST_RESULT => {
            let request = request_from_action(&data)?
                .ok_or_else(|| anyhow!("a request action produced no request"))?;
            let (ack, done) = oneshot::channel();
            outbound_tx
                .send(Outbound::Request { request, ack })
                .await
                .map_err(|_| anyhow!("the connection is closed"))?;
            let bytes = done
                .await
                .map_err(|_| anyhow!("the connection closed before the request was written"))?
                .map_err(|e| anyhow!(e))?;
            Ok(Applied::Sent(bytes))
        }
        ClientActionResult::Disconnect => {
            let (ack, done) = oneshot::channel();
            if outbound_tx.send(Outbound::Disconnect { ack }).await.is_ok() {
                let _ = done.await;
            }
            Ok(Applied::Disconnect)
        }
        _ => Ok(Applied::Nothing),
    }
}

/// Drain injected commands until the channel closes or one of them disconnects.
async fn command_loop(
    mut command_rx: mpsc::Receiver<ClientCommand>,
    protocol: Arc<MemcachedClientProtocol>,
    outbound_tx: mpsc::Sender<Outbound>,
    client_id: ClientId,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
) {
    while let Some(command) = command_rx.recv().await {
        let action = command.action.clone();
        let outcome = match apply_action(protocol.as_ref(), &outbound_tx, action.clone()).await {
            Ok(Applied::Sent(bytes_sent)) => ClientSendOutcome::Sent { bytes_sent },
            Ok(Applied::Nothing) => ClientSendOutcome::Executed {
                detail: "executed (nothing to write)".to_string(),
            },
            Ok(Applied::Disconnect) => ClientSendOutcome::Disconnected,
            Err(e) => ClientSendOutcome::Rejected {
                error: e.to_string(),
            },
        };
        app_state
            .record_access_log(
                AccessLogOwner::Client(client_id.as_u32()),
                protocol.protocol_name(),
                None,
                "injected_action",
                action,
                vec![serde_json::to_value(&outcome).unwrap_or_default()],
            )
            .await;
        let disconnect = matches!(outcome, ClientSendOutcome::Disconnected);
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        crate::client::command_support::reply(command, Ok(outcome));
        if disconnect {
            break;
        }
    }
}

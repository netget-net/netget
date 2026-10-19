//! ZeroMQ client socket (REQ, DEALER, PUSH or SUB) over ZMTP 3.1 with the NULL mechanism.
pub mod actions;
use crate::client::llm_budget::call_llm_for_client_batch;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::zeromq::wire::{self, Incoming};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::ZeromqClientProtocol;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::{
    io::{AsyncWriteExt, WriteHalf},
    net::TcpStream,
    sync::mpsc,
};

pub const DEFAULT_SOCKET_TYPE: &str = "req";
/// How long a received message may wait between frames once it has started; the connection
/// itself may stay quiet indefinitely, as a ZeroMQ socket does.
const READ_IDLE: Duration = Duration::from_secs(365 * 24 * 3600);

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let socket_type = actions::socket_type(
        &params
            .map(|p| p.get_optional_string("socket_type"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| DEFAULT_SOCKET_TYPE.into()),
    )?;
    let identity = params
        .map(|p| p.get_optional_string("identity"))
        .transpose()?
        .flatten();
    if let Some(id) = &identity {
        anyhow::ensure!(
            !id.is_empty() && id.len() <= 255 && !id.starts_with('\0'),
            "identity must be 1 to 255 bytes and not start with NUL"
        );
    }
    let mut stream = tokio::time::timeout(
        wire::HANDSHAKE_TIMEOUT,
        TcpStream::connect(&ctx.remote_addr),
    )
    .await
    .context("ZeroMQ connect deadline")??;
    let local = stream.local_addr()?;
    let (peer_type, _) = wire::handshake(
        &mut stream,
        socket_type,
        identity.as_deref().map(str::as_bytes),
    )
    .await?;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let (mut reader, writer) = tokio::io::split(stream);
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (incoming_tx, incoming_rx) = mpsc::channel::<Result<Incoming>>(16);
    let reader_task = tokio::spawn(async move {
        loop {
            let item = wire::read_incoming(&mut reader, READ_IDLE).await;
            let end = !matches!(item, Ok(Some(_)));
            let sent = match item {
                Ok(Some(i)) => incoming_tx.send(Ok(i)).await,
                Ok(None) => {
                    incoming_tx
                        .send(Err(anyhow::anyhow!("ZeroMQ server closed the connection")))
                        .await
                }
                Err(e) => incoming_tx.send(Err(e)).await,
            };
            if end || sent.is_err() {
                return;
            }
        }
    });
    ctx.state
        .register_client_task(ctx.client_id, reader_task)
        .await;
    let (internal_tx, internal_rx) = mpsc::channel::<Value>(16);
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(64);
    event_tx.try_send(Event::new(
        &actions::CONNECTED_EVENT,
        json!({"socket_type": socket_type, "peer_socket_type": peer_type}),
    ))?;
    let events_ctx = ctx.clone();
    let dispatcher = tokio::spawn(async move {
        let protocol = ZeromqClientProtocol;
        // An event that would not have joined the previous batch starts the next one.
        let mut carried = None;
        while let Some(first) = match carried.take() {
            Some(item) => Some(item),
            None => event_rx.recv().await,
        } {
            // With batching on, everything raised while the model was answering is answered
            // in this one call; with it off, one event per call. Only events the model itself
            // will answer together are drained: one a script, static or manual rule answers
            // stays in the bounded queue, as it would without batching.
            let mut batch = vec![first];
            while batch.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                let mut ids: Vec<&str> = batch.iter().map(|item| item.id()).collect();
                if ids.len() == 1
                    && !crate::llm::action_helper::client_batch_goes_to_the_model(
                        &events_ctx.state,
                        events_ctx.client_id,
                        &ids,
                    )
                    .await
                {
                    break;
                }
                let Ok(next) = event_rx.try_recv() else {
                    break;
                };
                ids.push(next.id());
                if !crate::llm::action_helper::client_batch_goes_to_the_model(
                    &events_ctx.state,
                    events_ctx.client_id,
                    &ids,
                )
                .await
                {
                    carried = Some(next);
                    break;
                }
                drop(ids);
                batch.push(next);
            }
            let instruction = events_ctx
                .state
                .get_instruction_for_client(events_ctx.client_id)
                .await
                .unwrap_or_default();
            let memory = events_ctx
                .state
                .get_memory_for_client(events_ctx.client_id)
                .await
                .unwrap_or_default();
            match call_llm_for_client_batch(
                &events_ctx.llm_client,
                &events_ctx.state,
                events_ctx.client_id.to_string(),
                &instruction,
                &memory,
                &batch,
                &protocol,
                &events_ctx.status_tx,
            )
            .await
            {
                Ok(result) => {
                    if let Some(memory) = result.memory_updates {
                        events_ctx
                            .state
                            .set_memory_for_client(events_ctx.client_id, memory)
                            .await;
                    }
                    for action in result.actions {
                        if internal_tx.send(action).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => Log::new(Some(&events_ctx.status_tx))
                    .warn(format!("ZeroMQ client handler: {e}")),
            }
        }
    });
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let result = session(
            &session_ctx,
            socket_type,
            writer,
            incoming_rx,
            external,
            internal_rx,
            event_tx,
        )
        .await;
        if result.is_err() {
            dispatcher_abort.abort();
        }
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx)).warn(format!("ZeroMQ client ended: {e}"));
                ClientStatus::Error(e.to_string())
            }
        };
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, status)
            .await;
        session_ctx
            .state
            .remove_client_handle(session_ctx.client_id)
            .await;
        let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    Ok(local)
}

/// The bytes one action puts on the wire, or why this socket cannot send it.
fn encode(socket_type: &str, awaiting: bool, action: &Value) -> Result<Vec<u8>> {
    match action["type"].as_str().unwrap_or_default() {
        "zmq_send" => {
            anyhow::ensure!(socket_type != "SUB", "a SUB socket cannot send messages");
            anyhow::ensure!(
                !(socket_type == "REQ" && awaiting),
                "a REQ socket must receive its reply before sending again"
            );
            let mut frames = wire::frames_from_text(
                action["frames"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
                action["encoding"].as_str(),
            )?;
            if socket_type == "REQ" {
                frames.insert(0, Vec::new());
            }
            Ok(wire::encode_message(&frames))
        }
        kind @ ("zmq_subscribe" | "zmq_unsubscribe") => {
            anyhow::ensure!(socket_type == "SUB", "only a SUB socket subscribes");
            let mut body = vec![u8::from(kind == "zmq_subscribe")];
            body.extend_from_slice(action["topic"].as_str().unwrap_or_default().as_bytes());
            Ok(wire::encode_frame(&body, false, false))
        }
        other => anyhow::bail!("Unknown ZeroMQ client action {other}"),
    }
}

async fn session(
    ctx: &ConnectContext,
    socket_type: &'static str,
    mut writer: WriteHalf<TcpStream>,
    mut incoming: mpsc::Receiver<Result<Incoming>>,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<Value>,
    events: mpsc::Sender<Event>,
) -> Result<()> {
    let mut awaiting = false;
    loop {
        let (action, mut injected) = tokio::select! {
            item = incoming.recv() => {
                let Some(item) = item else { return Ok(()) };
                match item? {
                    Incoming::Command(name, body) => {
                        if name == "PING" && body.len() >= 2 {
                            writer.write_all(&wire::encode_command("PONG", &body[2..])).await?;
                        }
                    }
                    Incoming::Message(mut frames) => {
                        if socket_type == "REQ" {
                            // A reply carries the envelope back; anything unasked is dropped.
                            if !awaiting || frames.first().is_none_or(|f| !f.is_empty()) {
                                continue;
                            }
                            frames.remove(0);
                            awaiting = false;
                        } else if socket_type == "PUSH" {
                            continue;
                        }
                        let (text, encoding) = wire::frames_to_text(&frames);
                        events
                            .try_send(Event::new(
                                &actions::MESSAGE_EVENT,
                                json!({"frames": text, "encoding": encoding}),
                            ))
                            .context("ZeroMQ event queue full; consumer stalled")?;
                    }
                }
                continue;
            }
            command = external.recv() => match command {
                Some(c) => (c.action.clone(), Some(c)),
                None => return Ok(()),
            },
            action = internal.recv() => match action {
                Some(a) => (a, None),
                None => return Ok(()),
            },
        };
        let checked = ZeromqClientProtocol.execute_action(action.clone());
        if let Ok(ClientActionResult::Disconnect) = checked {
            if let Some(command) = injected.take() {
                crate::client::command_support::reply(command, Ok(ClientSendOutcome::Disconnected));
            }
            return Ok(());
        }
        let bytes = checked.and_then(|_| encode(socket_type, awaiting, &action));
        let bytes = match bytes {
            Ok(bytes) => bytes,
            Err(e) => {
                if let Some(command) = injected.take() {
                    crate::client::command_support::reply(
                        command,
                        Ok(ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        }),
                    );
                } else {
                    Log::new(Some(&ctx.status_tx)).warn(format!("ZeroMQ action refused: {e}"));
                }
                continue;
            }
        };
        if injected.is_some() {
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "ZeroMQ",
                    None,
                    "injected_action",
                    action.clone(),
                    vec![],
                )
                .await;
        }
        tokio::time::timeout(wire::HANDSHAKE_TIMEOUT, writer.write_all(&bytes))
            .await
            .context("ZMTP write deadline")??;
        if action["type"] == "zmq_send" && socket_type == "REQ" {
            awaiting = true;
        }
        if let Some(command) = injected.take() {
            crate::client::command_support::reply(
                command,
                Ok(ClientSendOutcome::Sent {
                    bytes_sent: bytes.len(),
                }),
            );
        }
    }
}

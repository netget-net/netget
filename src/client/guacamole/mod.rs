//! Guacamole client of guacd. `connect()` runs the handshake (a refusal fails the connect);
//! then a reader task answers sync and acks blobs in Rust and raises the first frame, the
//! remote clipboard and errors; the session task sends the handler's input.
pub mod actions;
use crate::client::llm_budget::call_llm_for_client_batch;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::guacamole::wire;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::GuacamoleClientProtocol;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

/// Connecting and the handshake, until guacd says `ready`.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
/// Streams guacd may have open to this client at once.
pub const MAX_STREAMS: usize = 64;
/// A handler chain (answer → event → answer …) stops after this many follow-ups.
pub const MAX_FOLLOWUP_DEPTH: usize = 8;

pub async fn connect(ctx: ConnectContext) -> Result<std::net::SocketAddr> {
    let params = ctx
        .startup_params
        .as_ref()
        .context("startup_params.arguments is required")?;
    let protocol = params
        .get_optional_string("protocol")?
        .unwrap_or_else(|| actions::DEFAULT_PROTOCOL.into());
    let arguments = params.get_object("arguments")?.clone();
    let width = params
        .get_optional_u64("width")?
        .unwrap_or(u64::from(actions::DEFAULT_WIDTH))
        .clamp(1, 8192);
    let height = params
        .get_optional_u64("height")?
        .unwrap_or(u64::from(actions::DEFAULT_HEIGHT))
        .clamp(1, 8192);
    let tcp = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        tokio::net::TcpStream::connect(&ctx.remote_addr),
    )
    .await
    .context("connect timed out")??;
    let local = tcp.local_addr()?;
    let (r, mut w) = tcp.into_split();
    let mut reader = wire::Reader::new(r);
    let connection_id = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        w.write_all(wire::encode("select", &[&protocol]).as_bytes())
            .await?;
        let args = reader.next().await?.context("guacd closed before args")?;
        if args.opcode == "error" {
            bail!(
                "guacd refused {protocol}: {} ({})",
                args.arg(0),
                args.arg(1)
            );
        }
        ensure!(args.opcode == "args", "expected args, got {}", args.opcode);
        let mut out = wire::encode("size", &[&width.to_string(), &height.to_string(), "96"]);
        out.push_str(&wire::encode("audio", &[]));
        out.push_str(&wire::encode("video", &[]));
        out.push_str(&wire::encode("image", &["image/png", "image/jpeg"]));
        out.push_str(&wire::encode("timezone", &["UTC"]));
        let values: Vec<String> = args
            .args
            .iter()
            .map(|name| {
                if name.starts_with("VERSION_") {
                    wire::VERSION.to_string()
                } else {
                    match arguments.get(name) {
                        Some(Value::String(s)) => s.clone(),
                        Some(Value::Null) | None => String::new(),
                        Some(v) => v.to_string(),
                    }
                }
            })
            .collect();
        let refs: Vec<&str> = values.iter().map(String::as_str).collect();
        out.push_str(&wire::encode("connect", &refs));
        w.write_all(out.as_bytes()).await?;
        let ready = reader.next().await?.context("guacd closed before ready")?;
        match ready.opcode.as_str() {
            "ready" => Ok(ready.arg(0).to_string()),
            "error" => bail!(
                "guacd refused the connection: {} ({})",
                ready.arg(0),
                ready.arg(1)
            ),
            other => bail!("expected ready, got {other}"),
        }
    })
    .await
    .context("the Guacamole handshake timed out")??;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "Guacamole client: {protocol} session {connection_id} through {}",
        ctx.remote_addr
    ));
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;

    // The writer: everything goes out through one channel.
    let (wtx, mut wrx) = mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        while let Some(m) = wrx.recv().await {
            if w.write_all(m.as_bytes()).await.is_err() {
                break;
            }
        }
        let _ = w.shutdown().await;
    });
    ctx.state.register_client_task(ctx.client_id, writer).await;

    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<(Value, usize)>(32);
    let (event_tx, mut event_rx) = mpsc::channel::<(Event, usize)>(32);
    let (ended_tx, ended_rx) = tokio::sync::oneshot::channel::<String>();

    // The reader: Rust's half of the conversation, and the events.
    let reader_events = event_tx.clone();
    let reader_w = wtx.clone();
    let reader_status = ctx.status_tx.clone();
    let read = tokio::spawn(async move {
        let mut updates = 0u64;
        let mut size = (width, height);
        let mut name: Option<String> = None;
        let mut ready_sent = false;
        let mut streams: HashMap<String, Vec<u8>> = HashMap::new();
        let reason = loop {
            let ins = match reader.next().await {
                Ok(Some(i)) => i,
                Ok(None) => break "guacd closed the connection".to_string(),
                Err(e) => break format!("{e:#}"),
            };
            let mut event = None;
            match ins.opcode.as_str() {
                "sync" => {
                    let _ = reader_w.send(wire::encode("sync", &[ins.arg(0)]));
                    if !ready_sent {
                        ready_sent = true;
                        event = Some(Event::new(
                            &actions::READY_EVENT,
                            json!({"connection_id": connection_id, "protocol": protocol,
                                   "width": size.0, "height": size.1, "name": name}),
                        ));
                    }
                }
                "size" if ins.arg(0) == "0" => {
                    size = (
                        ins.arg(1).parse().unwrap_or(size.0),
                        ins.arg(2).parse().unwrap_or(size.1),
                    );
                }
                "name" => name = Some(ins.arg(0).to_string()),
                "img" | "rect" | "copy" | "cfill" | "png" | "jpeg" | "transfer" => updates += 1,
                "clipboard" => {
                    if streams.len() < MAX_STREAMS {
                        streams.insert(ins.arg(0).to_string(), Vec::new());
                    }
                    let _ = reader_w.send(wire::encode("ack", &[ins.arg(0), "OK", "0"]));
                }
                "blob" => {
                    if let Some(buf) = streams.get_mut(ins.arg(0)) {
                        if let Ok(b) = wire::unbase64(ins.arg(1)) {
                            if buf.len() + b.len() <= wire::MAX_CLIPBOARD {
                                buf.extend(b);
                            }
                        }
                    }
                    let _ = reader_w.send(wire::encode("ack", &[ins.arg(0), "OK", "0"]));
                }
                "end" => {
                    if let Some(buf) = streams.remove(ins.arg(0)) {
                        event = Some(Event::new(
                            &actions::CLIPBOARD_EVENT,
                            json!({"text": String::from_utf8_lossy(&buf), "display_updates": updates}),
                        ));
                    }
                }
                "error" => {
                    event = Some(Event::new(
                        &actions::ERROR_EVENT,
                        json!({"message": ins.arg(0), "status": ins.arg(1).parse::<u32>().unwrap_or(0)}),
                    ));
                }
                "disconnect" => break "guacd disconnected".into(),
                "nop" => {}
                // Image streams' other parts (blob on img streams is acked above), cursor, …
                _ => {}
            }
            if let Some(e) = event {
                if reader_events.send((e, 0)).await.is_err() {
                    break "client ended".into();
                }
            }
        };
        Log::new(Some(&reader_status)).info(format!("Guacamole client: {reason}"));
        let _ = ended_tx.send(reason);
    });
    ctx.state.register_client_task(ctx.client_id, read).await;

    // The dispatcher answers what the reader raised. guacd pushes the clipboard and errors
    // whenever it likes, so they can pile up in `event_rx` while the model is answering; with
    // batching on, everything waiting is answered in one call, with it off one event per call.
    let events_ctx = ctx.clone();
    let dispatcher = tokio::spawn(async move {
        while let Some(first) = event_rx.recv().await {
            let mut batch = vec![first];
            if events_ctx
                .state
                .client_conversation_settings(events_ctx.client_id)
                .await
                .is_some_and(|(_, batching)| batching)
            {
                while batch.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                    match event_rx.try_recv() {
                        Ok(next) => batch.push(next),
                        Err(_) => break,
                    }
                }
            }
            let depth = batch.iter().map(|(_, d)| *d).max().unwrap_or(0);
            let events: Vec<Event> = batch.into_iter().map(|(e, _)| e).collect();
            for event in &events {
                events_ctx
                    .state
                    .record_access_log(
                        AccessLogOwner::Client(events_ctx.client_id.as_u32()),
                        "Guacamole",
                        None,
                        event.id(),
                        event.data.clone(),
                        vec![],
                    )
                    .await;
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
                &events,
                &GuacamoleClientProtocol,
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
                        if internal_tx.send((action, depth + 1)).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => Log::new(Some(&events_ctx.status_tx))
                    .warn(format!("Guacamole client handler: {e}")),
            }
        }
    });
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;

    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let reason = session(&session_ctx, &wtx, external, internal_rx, ended_rx).await;
        let _ = wtx.send(wire::encode("disconnect", &[]));
        dispatcher_abort.abort();
        Log::new(Some(&session_ctx.status_tx)).info(format!("Guacamole client ended: {reason}"));
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, ClientStatus::Disconnected)
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

async fn session(
    ctx: &ConnectContext,
    wtx: &mpsc::UnboundedSender<String>,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, usize)>,
    mut ended: tokio::sync::oneshot::Receiver<String>,
) -> String {
    let log = Log::new(Some(&ctx.status_tx));
    loop {
        let (action, depth, mut injected) = tokio::select! {
            reason = &mut ended => return reason.unwrap_or_else(|_| "reader stopped".into()),
            command = external.recv() => match command {
                Some(c) => (c.action.clone(), 0, Some(c)),
                None => return "client removed".into(),
            },
            action = internal.recv() => match action {
                Some((a, depth)) => (a, depth, None),
                None => return "handler stopped".into(),
            },
        };
        let reply = |injected: &mut Option<ClientCommand>, outcome: ClientSendOutcome| {
            if let Some(command) = injected.take() {
                crate::client::command_support::reply(command, Ok(outcome));
            }
        };
        match GuacamoleClientProtocol.execute_action(action.clone()) {
            Ok(ClientActionResult::Disconnect) => {
                reply(&mut injected, ClientSendOutcome::Disconnected);
                return "disconnect requested".into();
            }
            Ok(_) => {}
            Err(e) => {
                log.warn(format!("Guacamole client action refused: {e:#}"));
                reply(
                    &mut injected,
                    ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    },
                );
                continue;
            }
        }
        if depth > MAX_FOLLOWUP_DEPTH {
            log.warn(format!(
                "Guacamole client: handler chain stopped after {MAX_FOLLOWUP_DEPTH} follow-ups"
            ));
            continue;
        }
        ctx.state
            .record_access_log(
                AccessLogOwner::Client(ctx.client_id.as_u32()),
                "Guacamole",
                None,
                if injected.is_some() {
                    "injected_action"
                } else {
                    "handler_action"
                },
                action.clone(),
                vec![],
            )
            .await;
        let out = match actions::instructions(&action) {
            Ok(o) => o,
            Err(e) => {
                reply(
                    &mut injected,
                    ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    },
                );
                continue;
            }
        };
        let n = out.len();
        if wtx.send(out).is_err() {
            reply(
                &mut injected,
                ClientSendOutcome::Rejected {
                    error: "connection closed".into(),
                },
            );
            return "write failed".into();
        }
        reply(&mut injected, ClientSendOutcome::Sent { bytes_sent: n });
    }
}

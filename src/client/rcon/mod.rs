//! Source/Minecraft RCON client: login on connect, then one EXECCOMMAND per action, with the
//! output of a Source server collected up to the mirrored empty-packet sentinel.
pub mod actions;
use crate::client::llm_budget::call_llm_for_client_batch;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::rcon::wire::{self, Packet};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::RconClientProtocol;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};

async fn send<W: AsyncWrite + Unpin>(writer: &mut W, packets: &[Packet]) -> Result<usize> {
    let bytes: Vec<u8> = packets.iter().flat_map(Packet::encode).collect();
    tokio::time::timeout(wire::IO_TIMEOUT, writer.write_all(&bytes))
        .await
        .context("RCON write deadline")??;
    Ok(bytes.len())
}

async fn next<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Packet> {
    wire::read_packet(reader, wire::IO_TIMEOUT, wire::MAX_PACKET)
        .await?
        .context("RCON server closed the connection")
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let password = params
        .map(|p| p.get_optional_string("password"))
        .transpose()?
        .flatten()
        .context("password startup parameter is required for RCON")?;
    anyhow::ensure!(
        !password.is_empty() && password.len() <= wire::MAX_BODY_OUT && !password.contains('\0'),
        "password must be 1 to {} bytes without NUL",
        wire::MAX_BODY_OUT
    );
    let source = match params
        .map(|p| p.get_optional_string("dialect"))
        .transpose()?
        .flatten()
        .as_deref()
        .unwrap_or(crate::server::rcon::DEFAULT_DIALECT)
    {
        "source" => true,
        "minecraft" => false,
        other => anyhow::bail!("dialect must be source or minecraft, not {other}"),
    };
    let stream = tokio::time::timeout(wire::IO_TIMEOUT, TcpStream::connect(&ctx.remote_addr))
        .await
        .context("RCON connect deadline")??;
    let local = stream.local_addr()?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    // Login id 0: srcds echoes the request id, and some servers (gorcon's rcontest among them)
    // always answer 0, so 0 is the one id both agree on.
    send(
        &mut writer,
        &[Packet::new(0, wire::SERVERDATA_AUTH, password.into_bytes())],
    )
    .await?;
    loop {
        let reply = next(&mut reader).await?;
        // srcds precedes the AUTH_RESPONSE with an empty RESPONSE_VALUE; skip it.
        if reply.kind == wire::SERVERDATA_RESPONSE_VALUE && reply.body.is_empty() {
            continue;
        }
        anyhow::ensure!(
            reply.kind == wire::SERVERDATA_AUTH_RESPONSE,
            "RCON server answered the login with packet type {}",
            reply.kind
        );
        anyhow::ensure!(reply.id != -1, "RCON server refused the password");
        anyhow::ensure!(
            reply.id == 0,
            "RCON login answered with id {}, expected 0",
            reply.id
        );
        break;
    }
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<Value>(16);
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(16);
    event_tx.try_send(Event::new(&actions::CONNECTED_EVENT, json!({"remote_addr": ctx.remote_addr, "dialect": if source { "source" } else { "minecraft" }})))?;
    let events_ctx = ctx.clone();
    let dispatcher = tokio::spawn(async move {
        let protocol = RconClientProtocol;
        while let Some(first) = event_rx.recv().await {
            // The session keeps running the model's earlier actions (and injected ones) while
            // this call is out, so their results queue here. With batching on, everything
            // already waiting is answered in one call; with it off, one result per call.
            let mut events = vec![first];
            if events_ctx
                .state
                .client_conversation_settings(events_ctx.client_id)
                .await
                .is_some_and(|(_, batching)| batching)
            {
                while events.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                    match event_rx.try_recv() {
                        Ok(event) => events.push(event),
                        Err(_) => break,
                    }
                }
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
                Err(e) => {
                    Log::new(Some(&events_ctx.status_tx)).warn(format!("RCON client handler: {e}"))
                }
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
            source,
            &mut reader,
            &mut writer,
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
                Log::new(Some(&session_ctx.status_tx)).warn(format!("RCON client ended: {e}"));
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

fn answer(injected: &mut Option<ClientCommand>, outcome: Result<ClientSendOutcome>) {
    if let Some(command) = injected.take() {
        crate::client::command_support::reply(command, outcome);
    }
}

/// Run one command and collect its output.
async fn run<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    source: bool,
    id: i32,
    command: &str,
    injected: &mut Option<ClientCommand>,
) -> Result<Value> {
    let sentinel = id + 1;
    let mut request = vec![Packet::new(
        id,
        wire::SERVERDATA_EXECCOMMAND,
        command.as_bytes().to_vec(),
    )];
    if source {
        request.push(Packet::new(
            sentinel,
            wire::SERVERDATA_RESPONSE_VALUE,
            Vec::new(),
        ));
    }
    let sent = send(writer, &request).await?;
    answer(injected, Ok(ClientSendOutcome::Sent { bytes_sent: sent }));
    let mut output = Vec::new();
    let mut packets = 0;
    loop {
        let packet = next(reader).await?;
        // Packets for earlier ids (a late sentinel echo) are not part of this answer.
        if packet.id < id {
            continue;
        }
        if source && packet.id == sentinel {
            break;
        }
        anyhow::ensure!(
            packet.id == id && packet.kind == wire::SERVERDATA_RESPONSE_VALUE,
            "unexpected RCON packet id {} type {}",
            packet.id,
            packet.kind
        );
        packets += 1;
        output.extend_from_slice(&packet.body);
        anyhow::ensure!(
            output.len() <= wire::MAX_RESPONSE_BYTES,
            "RCON output exceeds {} bytes",
            wire::MAX_RESPONSE_BYTES
        );
        if !source {
            break;
        }
    }
    Ok(json!({"command": command, "output": String::from_utf8_lossy(&output), "packets": packets}))
}

async fn session<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    ctx: &ConnectContext,
    source: bool,
    reader: &mut R,
    writer: &mut W,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<Value>,
    events: mpsc::Sender<Event>,
) -> Result<()> {
    let mut next_id: i32 = 2;
    loop {
        let (action, mut injected) = tokio::select! {
            command = external.recv() => match command {
                Some(c) => (c.action.clone(), Some(c)),
                None => return Ok(()),
            },
            action = internal.recv() => match action {
                Some(a) => (a, None),
                None => return Ok(()),
            },
        };
        let command = match RconClientProtocol.execute_action(action.clone()) {
            Ok(ClientActionResult::Disconnect) => {
                let _ = writer.shutdown().await;
                answer(&mut injected, Ok(ClientSendOutcome::Disconnected));
                return Ok(());
            }
            Ok(_) => actions::validate_command(&action),
            Err(e) => Err(e),
        };
        let command = match command {
            Ok(command) => command,
            Err(e) => {
                answer(
                    &mut injected,
                    Ok(ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    }),
                );
                continue;
            }
        };
        if injected.is_some() {
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "RCON",
                    None,
                    "injected_action",
                    json!({"command": command}),
                    vec![],
                )
                .await;
        }
        let id = next_id;
        next_id = next_id.checked_add(2).unwrap_or(2);
        let result = run(reader, writer, source, id, &command, &mut injected).await;
        if let Err(e) = &result {
            answer(&mut injected, Err(anyhow::anyhow!(e.to_string())));
        }
        events
            .try_send(Event::new(&actions::RESPONSE_EVENT, result?))
            .context("RCON event queue full; consumer stalled")?;
    }
}

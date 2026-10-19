//! LMTP (RFC 2033) client: LHLO on connect, then one MAIL/RCPT/DATA transaction per
//! `lmtp_send`, reading the per-recipient replies LMTP returns after DATA.
pub mod actions;
use crate::client::llm_budget::call_llm_for_client_batch;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::lmtp::wire::{self, Reply};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::LmtpClientProtocol;
use actions::Outgoing;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncBufRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::mpsc,
};

async fn send<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> Result<()> {
    tokio::time::timeout(wire::IO_TIMEOUT, writer.write_all(bytes))
        .await
        .context("LMTP write deadline")??;
    Ok(())
}

async fn command<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    line: &str,
) -> Result<Reply> {
    send(writer, format!("{line}\r\n").as_bytes()).await?;
    wire::read_reply(reader).await
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let domain = ctx
        .startup_params
        .as_ref()
        .map(|p| p.get_optional_string("lhlo_domain"))
        .transpose()?
        .flatten()
        .unwrap_or_else(|| actions::DEFAULT_LHLO_DOMAIN.to_string());
    anyhow::ensure!(
        !domain.is_empty() && domain.len() <= 255 && domain.chars().all(|c| c.is_ascii_graphic()),
        "lhlo_domain must be printable ASCII without spaces"
    );
    let stream = tokio::time::timeout(wire::IO_TIMEOUT, TcpStream::connect(&ctx.remote_addr))
        .await
        .context("LMTP connect deadline")??;
    let local = stream.local_addr()?;
    let (read, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let greeting = wire::read_reply(&mut reader).await?;
    anyhow::ensure!(
        greeting.code == 220,
        "LMTP server refused the session: {} {}",
        greeting.code,
        greeting.text()
    );
    let lhlo = command(&mut reader, &mut writer, &format!("LHLO {domain}")).await?;
    anyhow::ensure!(
        lhlo.code == 250,
        "LMTP server refused LHLO: {} {}",
        lhlo.code,
        lhlo.text()
    );
    let capabilities: Vec<String> = lhlo.lines.iter().skip(1).cloned().collect();
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<Value>(16);
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(16);
    event_tx.try_send(Event::new(
        &actions::CONNECTED_EVENT,
        json!({"remote_addr": ctx.remote_addr, "greeting": greeting.text(), "capabilities": capabilities}),
    ))?;
    let events_ctx = ctx.clone();
    let dispatcher = tokio::spawn(async move {
        let protocol = LmtpClientProtocol;
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
                    Log::new(Some(&events_ctx.status_tx)).warn(format!("LMTP client handler: {e}"))
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
            &domain,
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
                Log::new(Some(&session_ctx.status_tx)).warn(format!("LMTP client ended: {e}"));
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

fn answer(command: &mut Option<ClientCommand>, outcome: Result<ClientSendOutcome>) {
    if let Some(command) = command.take() {
        crate::client::command_support::reply(command, outcome);
    }
}

/// One transaction. `injected` is answered once every byte of it is on the wire.
async fn transact<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    message: &Outgoing,
    domain: &str,
    injected: &mut Option<ClientCommand>,
) -> Result<Value> {
    let mut sent = 0usize;
    let mail_line = format!("MAIL FROM:<{}>", message.from);
    sent += mail_line.len() + 2;
    let mail = command(reader, writer, &mail_line).await?;
    let mut recipients = Vec::new();
    let mut accepted = Vec::new();
    let mut data_reply = None;
    if mail.positive() {
        for to in &message.to {
            let line = format!("RCPT TO:<{to}>");
            sent += line.len() + 2;
            let rcpt = command(reader, writer, &line).await?;
            if rcpt.positive() {
                accepted.push(recipients.len());
            }
            recipients.push(json!({"recipient": to, "rcpt": rcpt.to_json(), "delivery": null, "delivered": false}));
        }
        if !accepted.is_empty() {
            sent += 6;
            let data = command(reader, writer, "DATA").await?;
            if data.code == 354 {
                let payload = wire::dot_stuff(&message.compose(domain));
                sent += payload.len();
                send(writer, &payload).await?;
                answer(injected, Ok(ClientSendOutcome::Sent { bytes_sent: sent }));
                for index in &accepted {
                    let delivery = wire::read_reply(reader).await?;
                    recipients[*index]["delivered"] = json!(delivery.positive());
                    recipients[*index]["delivery"] = delivery.to_json();
                }
            }
            data_reply = Some(data.to_json());
        }
    }
    let completed = data_reply.as_ref().is_some_and(|d| d["code"] == 354);
    if !completed {
        // Nothing was delivered: clear the server's transaction state before the next one.
        sent += 6;
        let reset = command(reader, writer, "RSET").await?;
        answer(injected, Ok(ClientSendOutcome::Sent { bytes_sent: sent }));
        anyhow::ensure!(reset.positive(), "LMTP server refused RSET: {}", reset.code);
    }
    let delivered: Vec<Value> = recipients
        .iter()
        .filter(|r| r["delivered"] == true)
        .map(|r| r["recipient"].clone())
        .collect();
    Ok(json!({
        "from": message.from,
        "mail": mail.to_json(),
        "recipients": recipients,
        "data": data_reply,
        "delivered": delivered,
    }))
}

async fn session<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    ctx: &ConnectContext,
    domain: &str,
    reader: &mut R,
    writer: &mut W,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<Value>,
    events: mpsc::Sender<Event>,
) -> Result<()> {
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
            idle = tokio::io::AsyncBufReadExt::fill_buf(reader) => {
                // LMTP servers speak only in reply, except a 421 before closing.
                if idle?.is_empty() {
                    return Ok(());
                }
                let reply = wire::read_reply(reader).await?;
                anyhow::ensure!(reply.code == 421, "Unsolicited LMTP reply {}", reply.code);
                return Ok(());
            }
        };
        let message = match LmtpClientProtocol.execute_action(action) {
            Ok(ClientActionResult::Custom { name, data }) if name == "lmtp_send" => {
                Outgoing::from_action(&data)
            }
            Ok(ClientActionResult::Disconnect) => {
                let quit = command(reader, writer, "QUIT").await;
                let _ = writer.shutdown().await;
                answer(&mut injected, quit.map(|_| ClientSendOutcome::Disconnected));
                return Ok(());
            }
            Ok(_) => Err(anyhow::anyhow!("Unsupported LMTP action result")),
            Err(e) => Err(e),
        };
        let message = match message {
            Ok(message) => message,
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
                    "LMTP",
                    None,
                    "injected_action",
                    json!({"from": message.from, "to": message.to, "subject": message.subject}),
                    vec![],
                )
                .await;
        }
        let result = transact(reader, writer, &message, domain, &mut injected).await;
        if let Err(e) = &result {
            answer(&mut injected, Err(anyhow::anyhow!(e.to_string())));
        }
        let result = result?;
        events
            .try_send(Event::new(&actions::RESULT_EVENT, result))
            .context("LMTP event queue full; consumer stalled")?;
    }
}

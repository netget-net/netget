pub mod actions;
pub mod wire;
use self::wire::Request;
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::BeanstalkdClientProtocol;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::mpsc,
};

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let stream = tokio::time::timeout(wire::DEADLINE, TcpStream::connect(&ctx.remote_addr))
        .await
        .context("Beanstalkd connect deadline")??;
    let local = stream.local_addr()?;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<(Value, u8)>(16);
    let (event_tx, mut event_rx) = mpsc::channel::<(Event, u8)>(16);
    event_tx.try_send((
        Event::new(
            &actions::CONNECTED_EVENT,
            json!({"remote_addr":ctx.remote_addr}),
        ),
        0,
    ))?;
    let events_ctx = ctx.clone();
    let dispatcher = tokio::spawn(async move {
        let protocol = BeanstalkdClientProtocol;
        while let Some((event, depth)) = event_rx.recv().await {
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
            match call_llm_for_client(
                &events_ctx.llm_client,
                &events_ctx.state,
                events_ctx.client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
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
                        if depth >= wire::MAX_FOLLOWUPS && action["type"] != "disconnect" {
                            Log::new(Some(&events_ctx.status_tx)).warn(format!(
                                "Beanstalkd client: follow-up limit ({}) reached; {} not sent",
                                wire::MAX_FOLLOWUPS,
                                action["type"]
                            ));
                            continue;
                        }
                        if internal_tx.send((action, depth + 1)).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => Log::new(Some(&events_ctx.status_tx))
                    .warn(format!("Beanstalkd client handler: {e}")),
            }
        }
    });
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let result = session(&session_ctx, stream, external, internal_rx, event_tx).await;
        // A clean EOF can follow the last response immediately. Let the
        // registered dispatcher drain those events; its action channel is now closed
        // and it owns no socket. Removing the client still aborts both tasks.
        if result.is_err() {
            dispatcher_abort.abort();
        }
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx))
                    .warn(format!("Beanstalkd client ended: {e}"));
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
async fn session(
    ctx: &ConnectContext,
    stream: TcpStream,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, u8)>,
    events: mpsc::Sender<(Event, u8)>,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    loop {
        // An idle connection also notices EOF; Beanstalkd has no unsolicited server messages.
        let (action, depth, command) = tokio::select! {
            command=external.recv()=>match command {Some(c)=>(c.action.clone(),0,Some(c)),None=>return Ok(())},
            action=internal.recv()=>match action {Some((a,d))=>(a,d,None),None=>return Ok(())},
            idle=tokio::io::AsyncBufReadExt::fill_buf(&mut reader)=>{
                anyhow::ensure!(idle?.is_empty(),"Unsolicited Beanstalkd response"); return Ok(());
            }
        };
        let result = BeanstalkdClientProtocol.execute_action(action.clone());
        let request = match result {
            Ok(ClientActionResult::Custom { name, data }) if name == "beanstalkd_request" => {
                Request::from_action(&data)
            }
            Ok(ClientActionResult::Disconnect) => {
                let result = writer
                    .shutdown()
                    .await
                    .map(|_| ClientSendOutcome::Disconnected)
                    .map_err(Into::into);
                if let Some(command) = command {
                    crate::client::command_support::reply(command, result);
                }
                return Ok(());
            }
            Err(e) => Err(e),
            _ => Err(anyhow::anyhow!("Unsupported action result")),
        };
        let request = match request {
            Ok(r) => r,
            Err(e) => {
                if let Some(command) = command {
                    crate::client::command_support::reply(
                        command,
                        Ok(ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        }),
                    );
                }
                continue;
            }
        };
        let bytes = request.bytes.clone();
        let write_result = tokio::time::timeout(wire::DEADLINE, writer.write_all(&bytes))
            .await
            .context("Beanstalkd write deadline")
            .and_then(|v| v.map_err(Into::into));
        if command.is_some() {
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "Beanstalkd",
                    None,
                    "injected_action",
                    action.clone(),
                    vec![json!({"sent":write_result.is_ok()})],
                )
                .await;
        }
        if let Some(command) = command {
            crate::client::command_support::reply(
                command,
                match &write_result {
                    Ok(()) => Ok(ClientSendOutcome::Sent {
                        bytes_sent: bytes.len(),
                    }),
                    Err(e) => Err(anyhow::anyhow!(e.to_string())),
                },
            );
        }
        write_result?;
        if matches!(
            request.command,
            crate::server::beanstalkd::wire::Command::Quit
        ) {
            writer.shutdown().await?;
            return Ok(());
        }
        let response = {
            let pending = wire::response(&mut reader, &request);
            tokio::pin!(pending);
            loop {
                tokio::select! {
                    biased;
                    response=&mut pending => break response?,
                    command=external.recv()=>{
                        let Some(command)=command else { return Ok(()); };
                        match BeanstalkdClientProtocol.execute_action(command.action.clone()) {
                            Ok(ClientActionResult::Disconnect)=>{
                                let result=writer.shutdown().await.map(|_|ClientSendOutcome::Disconnected).map_err(Into::into);
                                crate::client::command_support::reply(command,result);
                                return Ok(());
                            },
                            result=>{
                                let error=match result {
                                    Err(e)=>e.to_string(),
                                    _=>"Beanstalkd request already pending; retry after its response".into(),
                                };
                                crate::client::command_support::reply(command,Ok(ClientSendOutcome::Rejected{error}));
                            }
                        }
                    }
                }
            }
        };
        events
            .try_send((
                Event::new(
                    &actions::RESPONSE_EVENT,
                    json!({"request":action.clone(),"response":response}),
                ),
                depth,
            ))
            .context("Beanstalkd event queue full; consumer stalled")?;
    }
}

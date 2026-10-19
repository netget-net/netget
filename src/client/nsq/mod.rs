pub mod actions;
pub mod wire;
use crate::client::llm_budget::call_llm_for_client_batch;
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::nsq::wire::{self as nsq, Command, Frame};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::NsqClientProtocol;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::{collections::HashSet, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt, WriteHalf},
    net::TcpStream,
    sync::mpsc,
};
pub const DEFAULT_HEARTBEAT_MS: i64 = 30000;
type HandlerEvent = (Event, u8);
type HandlerAction = (Value, u8);

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let heartbeat_ms = match &ctx.startup_params {
        Some(p) => p
            .get_optional_i64("heartbeat_interval_ms")?
            .unwrap_or(DEFAULT_HEARTBEAT_MS),
        None => DEFAULT_HEARTBEAT_MS,
    };
    anyhow::ensure!(
        (1000..=60000).contains(&heartbeat_ms),
        "NSQ heartbeat_interval_ms must be 1000..60000"
    );
    let stream = tokio::time::timeout(wire::DEADLINE, TcpStream::connect(&ctx.remote_addr))
        .await
        .context("NSQ connect deadline")??;
    let local = stream.local_addr()?;
    // Available before IDENTIFY or a connected event can park on a human.
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (reader, writer) = tokio::io::split(stream);
    let (frames_tx, frames_rx) = mpsc::channel::<Result<Option<Frame>>>(16);
    let reader_task = tokio::spawn(async move {
        let mut reader = reader;
        loop {
            let result = wire::frame(&mut reader).await;
            let done = !matches!(&result, Ok(Some(_)));
            if frames_tx.send(result).await.is_err() || done {
                break;
            }
        }
    });
    let reader_abort = reader_task.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, reader_task)
        .await;
    let (action_tx, action_rx) = mpsc::channel::<HandlerAction>(16);
    let (event_tx, mut event_rx) = mpsc::channel::<HandlerEvent>(16);
    let handler_ctx = ctx.clone();
    let handler = tokio::spawn(async move {
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
                let mut ids: Vec<&str> = batch.iter().map(|item| item.0.id()).collect();
                if ids.len() == 1
                    && !crate::llm::action_helper::client_batch_goes_to_the_model(
                        &handler_ctx.state,
                        handler_ctx.client_id,
                        &ids,
                    )
                    .await
                {
                    break;
                }
                let Ok(next) = event_rx.try_recv() else {
                    break;
                };
                ids.push(next.0.id());
                if !crate::llm::action_helper::client_batch_goes_to_the_model(
                    &handler_ctx.state,
                    handler_ctx.client_id,
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
            // A follow-up is as deep as the deepest event it answers.
            let depth = batch.iter().map(|(_, d)| *d).max().unwrap_or(0);
            let events: Vec<Event> = batch.into_iter().map(|(e, _)| e).collect();
            let instruction = handler_ctx
                .state
                .get_instruction_for_client(handler_ctx.client_id)
                .await
                .unwrap_or_default();
            let memory = handler_ctx
                .state
                .get_memory_for_client(handler_ctx.client_id)
                .await
                .unwrap_or_default();
            match call_llm_for_client_batch(
                &handler_ctx.llm_client,
                &handler_ctx.state,
                handler_ctx.client_id.to_string(),
                &instruction,
                &memory,
                &events,
                &NsqClientProtocol,
                &handler_ctx.status_tx,
            )
            .await
            {
                Ok(result) => {
                    if let Some(memory) = result.memory_updates {
                        handler_ctx
                            .state
                            .set_memory_for_client(handler_ctx.client_id, memory)
                            .await;
                    }
                    for action in result.actions {
                        if depth >= wire::MAX_FOLLOWUPS && action["type"] != "disconnect" {
                            Log::new(Some(&handler_ctx.status_tx))
                                .warn("NSQ handler followup limit reached");
                            continue;
                        }
                        if action_tx.send((action, depth + 1)).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => Log::new(Some(&handler_ctx.status_tx)).warn(format!("NSQ handler: {e}")),
            }
        }
    });
    ctx.state.register_client_task(ctx.client_id, handler).await;
    let session_ctx = ctx.clone();
    let session = tokio::spawn(async move {
        let result = session(
            &session_ctx,
            writer,
            external,
            action_rx,
            frames_rx,
            event_tx,
            heartbeat_ms,
        )
        .await;
        reader_abort.abort();
        // The handler has no socket. Drain final responses/errors even when EOF follows.
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx)).warn(format!("NSQ ended: {e}"));
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
    ctx.state.register_client_task(ctx.client_id, session).await;
    Ok(local)
}
struct Pending {
    command: Command,
    action: Value,
    depth: u8,
    deadline: tokio::time::Instant,
}
struct Flow {
    identified: bool,
    subscription: Option<(String, String)>,
    closing: bool,
    late_message_seen: bool,
    ready_high_water: u64,
    in_flight: HashSet<String>,
    pending: Option<Pending>,
    max_ready: u64,
}
impl Flow {
    fn check(&self, command: &Command) -> Result<()> {
        anyhow::ensure!(self.identified, "NSQ IDENTIFY still pending");
        anyhow::ensure!(
            !self.closing
                || matches!(
                    command,
                    Command::Fin(_) | Command::Req { .. } | Command::Touch(_) | Command::Nop
                ),
            "NSQ connection is closing"
        );
        match command {
            Command::Sub { .. } => {
                anyhow::ensure!(self.subscription.is_none(), "Already subscribed to NSQ")
            }
            Command::Rdy(n) => {
                anyhow::ensure!(self.subscription.is_some(), "Subscribe before RDY");
                anyhow::ensure!(*n <= self.max_ready, "RDY exceeds negotiated maximum");
            }
            Command::Fin(_) | Command::Req { .. } | Command::Touch(_) | Command::Cls => {
                anyhow::ensure!(
                    self.subscription.is_some(),
                    "Subscribe before message commands or CLS"
                )
            }
            _ => {}
        }
        anyhow::ensure!(
            self.pending.is_none() || !wire::expects_reply(command),
            "NSQ request already pending; retry after its response"
        );
        Ok(())
    }
}
fn emit(events: &mpsc::Sender<HandlerEvent>, event: Event, depth: u8) -> Result<()> {
    events
        .try_send((event, depth))
        .context("NSQ event queue full; handler stalled")
}
/// Write a complete command with a deadline; an injected disconnect may cancel it
/// and close the stream. Returns false when the caller must end the session.
pub async fn write_interruptible<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    external: &mut mpsc::Receiver<ClientCommand>,
) -> Result<bool> {
    let (complete, disconnect) = {
        let pending = tokio::time::timeout(wire::DEADLINE, writer.write_all(bytes));
        tokio::pin!(pending);
        loop {
            tokio::select! {
                biased;
                result = &mut pending => {
                    result.context("NSQ write deadline")??;
                    break (true,None);
                }
                command = external.recv() => {
                    let Some(command) = command else {break (false,None);};
                    if command.action["type"] == "disconnect" {break (false,Some(command));}
                    crate::client::command_support::reply(command,Ok(ClientSendOutcome::Rejected{error:"NSQ write is pending; retry after it completes".into()}));
                }
            }
        }
    };
    if !complete {
        writer.shutdown().await?;
        if let Some(command) = disconnect {
            crate::client::command_support::reply(command, Ok(ClientSendOutcome::Disconnected));
        }
    }
    Ok(complete)
}
async fn session(
    ctx: &ConnectContext,
    mut writer: WriteHalf<TcpStream>,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<HandlerAction>,
    mut frames: mpsc::Receiver<Result<Option<Frame>>>,
    events: mpsc::Sender<HandlerEvent>,
    heartbeat_ms: i64,
) -> Result<()> {
    let mut flow = Flow {
        identified: false,
        subscription: None,
        closing: false,
        late_message_seen: false,
        ready_high_water: 0,
        in_flight: HashSet::new(),
        pending: None,
        max_ready: nsq::MAX_RDY_COUNT,
    };
    let identify = wire::identify(heartbeat_ms);
    let mut bytes = nsq::MAGIC_V2.to_vec();
    bytes.extend(nsq::encode_command(&identify));
    if !write_interruptible(&mut writer, &bytes, &mut external).await? {
        return Ok(());
    }
    flow.pending = Some(Pending {
        command: identify,
        action: json!({"operation":"identify"}),
        depth: 0,
        deadline: tokio::time::Instant::now() + wire::DEADLINE,
    });
    let mut last_frame = tokio::time::Instant::now();
    loop {
        let deadline = flow
            .pending
            .as_ref()
            .map(|p| p.deadline)
            .unwrap_or(last_frame + Duration::from_millis(heartbeat_ms as u64 * 2 + 1000));
        let (action, depth, command) = tokio::select! {
            frame=frames.recv()=>{
                let Some(frame)=frame else{return Ok(());};
                let Some(frame)=frame? else {anyhow::ensure!(flow.pending.is_none(),"NSQ EOF during pending reply");return Ok(());};
                last_frame=tokio::time::Instant::now();
                match frame.frame_type {
                    nsq::FRAME_RESPONSE if frame.data==nsq::HEARTBEAT=>{if !write_interruptible(&mut writer,b"NOP\n",&mut external).await? {return Ok(());}},
                    nsq::FRAME_RESPONSE=>{
                        let pending=flow.pending.take().context("Unsolicited NSQ response")?;
                        match &pending.command {
                            Command::Identify(_)=>{
                                let features:Value=serde_json::from_slice(&frame.data).context("NSQ feature negotiation JSON")?;
                                anyhow::ensure!(features.is_object(),"NSQ negotiation must be an object");
                                for key in ["tls_v1","snappy","deflate","auth_required"] {
                                    anyhow::ensure!(features.get(key).is_none_or(|v|v.as_bool()==Some(false)),"NSQ {key} is unsupported; plain TCP without auth required");
                                }
                                flow.max_ready=features["max_rdy_count"].as_u64().context("Missing NSQ max_rdy_count")?.min(nsq::MAX_RDY_COUNT);
                                anyhow::ensure!(flow.max_ready>0,"NSQ maximum RDY must be positive");
                                flow.identified=true;
                                ctx.state.update_client_status(ctx.client_id,ClientStatus::Connected).await;
                                emit(&events,Event::new(&actions::CONNECTED_EVENT,json!({"remote_addr":ctx.remote_addr,"features":features})),0)?;
                            },
                            Command::Sub{topic,channel}=>{
                                anyhow::ensure!(frame.data==b"OK","NSQ SUB expected OK");
                                flow.subscription=Some((topic.clone(),channel.clone()));
                                emit(&events,Event::new(&actions::RESPONSE_EVENT,json!({"request":pending.action,"command":"SUB","status":"OK"})),pending.depth)?;
                            },
                            Command::Cls=>{
                                anyhow::ensure!(frame.data==b"CLOSE_WAIT","NSQ CLS expected CLOSE_WAIT");
                                flow.closing=true;
                                emit(&events,Event::new(&actions::RESPONSE_EVENT,json!({"request":pending.action,"command":"CLS","status":"CLOSE_WAIT"})),pending.depth)?;
                            },
                            c=>{
                                anyhow::ensure!(frame.data==b"OK","NSQ publish expected OK");
                                emit(&events,Event::new(&actions::RESPONSE_EVENT,json!({"request":pending.action,"command":c.name(),"status":"OK"})),pending.depth)?;
                            },
                        }
                    },
                    nsq::FRAME_ERROR=>{
                        let text=std::str::from_utf8(&frame.data).context("NSQ error is not UTF-8")?;
                        let (code,description)=text.split_once(' ').context("Malformed NSQ error")?;
                        anyhow::ensure!(code.starts_with("E_") && code.bytes().all(|b|b.is_ascii_uppercase()||b==b'_'),"Malformed NSQ error code");
                        let fatal=nsq::is_fatal(code);
                        let pending=if fatal{flow.pending.take()}else{None};
                        let depth=pending.as_ref().map(|p|p.depth).unwrap_or(0);
                        emit(&events,Event::new(&actions::ERROR_EVENT,json!({"code":code,"description":description,"fatal":fatal,"request":pending.map(|p|p.action)})),depth)?;
                        if fatal{return Err(anyhow::anyhow!("NSQ peer refused {code}: {description}"));}
                    },
                    nsq::FRAME_MESSAGE=>{
                        let (topic,channel)=flow.subscription.as_ref().context("NSQ message before subscription")?;
                        // RDY reductions cannot retract deliveries already selected by the
                        // daemon or travelling in the opposite TCP direction. Retain a
                        // bounded admission ceiling from the largest grant on this socket.
                        anyhow::ensure!(flow.in_flight.len()<(flow.ready_high_water as usize),"NSQ message exceeds granted RDY concurrency");
                        // nsqd 1.3.0's command and message loops share only the writer
                        // lock. A pump iteration selected before StartClose may send
                        // one message after CLOSE_WAIT; its next iteration sees RDY0.
                        anyhow::ensure!(!flow.closing || !flow.late_message_seen,"NSQ delivered more than one message after CLOSE_WAIT");
                        if flow.closing { flow.late_message_seen=true; }
                        let msg=nsq::parse_message(&frame.data).context("NSQ truncated message")?;
                        let id=std::str::from_utf8(&msg.id).context("NSQ message id not ASCII")?;
                        anyhow::ensure!(id.bytes().all(|b|b.is_ascii_hexdigit()),"NSQ message id must be hexadecimal");
                        anyhow::ensure!(flow.in_flight.insert(id.into()),"Duplicate NSQ in-flight message id");
                        let body=std::str::from_utf8(&msg.body).ok();
                        emit(&events,Event::new(&actions::MESSAGE_EVENT,json!({"topic":topic,"channel":channel,"message_id":id,"timestamp_ns":msg.timestamp_ns,"attempts":msg.attempts,"body":body,"body_bytes":msg.body.len(),"body_utf8":body.is_some()})),0)?;
                    },
                    _=>anyhow::bail!("Unknown NSQ frame type"),
                }
                continue;
            },
            command=external.recv()=>match command{Some(c)=>(c.action.clone(),0,Some(c)),None=>return Ok(())},
            action=internal.recv(),if flow.pending.is_none()=>match action{Some((a,d))=>(a,d,None),None=>return Ok(())},
            _=tokio::time::sleep_until(deadline)=>anyhow::bail!("NSQ peer reply/heartbeat deadline"),
        };
        if action["type"] == "disconnect" {
            writer.shutdown().await?;
            if let Some(c) = command {
                crate::client::command_support::reply(c, Ok(ClientSendOutcome::Disconnected));
            }
            return Ok(());
        }
        let request = wire::request(&action).and_then(|c| {
            flow.check(&c)?;
            Ok(c)
        });
        let request = match request {
            Ok(c) => c,
            Err(e) => {
                if let Some(c) = command {
                    crate::client::command_support::reply(
                        c,
                        Ok(ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        }),
                    );
                } else {
                    Log::new(Some(&ctx.status_tx)).warn(format!("NSQ action rejected: {e}"));
                }
                continue;
            }
        };
        let bytes = nsq::encode_command(&request);
        let result = write_interruptible(&mut writer, &bytes, &mut external).await;
        if command.is_some() {
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "NSQ",
                    None,
                    "injected_action",
                    action.clone(),
                    vec![json!({"sent":matches!(&result,Ok(true))})],
                )
                .await;
        }
        if let Some(c) = command {
            crate::client::command_support::reply(
                c,
                match &result {
                    Ok(true) => Ok(ClientSendOutcome::Sent {
                        bytes_sent: bytes.len(),
                    }),
                    Ok(false) => Ok(ClientSendOutcome::Rejected {
                        error: "NSQ write cancelled by disconnect".into(),
                    }),
                    Err(e) => Err(anyhow::anyhow!(e.to_string())),
                },
            );
        }
        if !result? {
            return Ok(());
        }
        match &request {
            Command::Rdy(n) => flow.ready_high_water = flow.ready_high_water.max(*n),
            Command::Fin(id) | Command::Req { id, .. } => {
                flow.in_flight.remove(id);
            }
            _ => {}
        }
        if wire::expects_reply(&request) {
            flow.pending = Some(Pending {
                command: request,
                action,
                depth,
                deadline: tokio::time::Instant::now() + wire::DEADLINE,
            });
        }
    }
}

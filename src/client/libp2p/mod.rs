//! libp2p client (the dialler): Noise as initiator, yamux, identify and ping, and the
//! application protocols' streams as events. Shares the server's stack (`server::libp2p`).
pub mod actions;
pub mod ipfs;
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::libp2p::bitswap::{self, WantSet};
use crate::server::libp2p::host::{self, Config, Note, Peer, Spawn, Task};
use crate::server::libp2p::{identity_from_params, protocols_from_params, wire, yamux};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::Libp2pClientProtocol;
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Connecting, before the libp2p upgrade starts.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A handler chain (answer → event → answer …) stops after this many follow-ups.
pub const MAX_FOLLOWUP_DEPTH: usize = 8;

fn remote_json(r: &host::Remote) -> Value {
    json!({"agent_version": r.agent_version, "protocol_version": r.protocol_version,
           "protocols": r.protocols, "listen_addrs": r.listen_addrs, "observed_addr": r.observed_addr})
}

pub async fn connect(ctx: ConnectContext) -> Result<std::net::SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let (addr, from_addr) = wire::parse_dial_target(&ctx.remote_addr)?;
    let named = params
        .map(|p| p.get_optional_string("peer_id"))
        .transpose()?
        .flatten()
        .map(|s| wire::unbase58(&s).context("peer_id is not a base58 peer id"))
        .transpose()?;
    if let (Some(a), Some(b)) = (&from_addr, &named) {
        ensure!(a == b, "the /p2p/ id in remote_addr and peer_id differ");
    }
    let expected = from_addr.or(named);
    let identity = identity_from_params(
        params
            .map(|p| p.get_optional_string("private_key_seed"))
            .transpose()?
            .flatten(),
    )?;
    let protocols = protocols_from_params(
        params
            .map(|p| p.get_optional_array("protocols"))
            .transpose()?
            .flatten(),
    )?;
    let ipfs = params
        .map(|p| p.get_optional_bool("ipfs"))
        .transpose()?
        .flatten()
        .unwrap_or(crate::server::libp2p::actions::IPFS_DEFAULT);
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(&addr))
        .await
        .context("connect timed out")??;
    let local = tcp.local_addr()?;
    let remote_addr = tcp.peer_addr()?;
    let cfg = Arc::new(Config {
        identity,
        protocols,
        listen_addrs: Vec::new(),
        // A dialler receives blocks on streams the remote opens, so it accepts Bitswap; it
        // serves no DHT, so it does not claim to.
        bitswap: ipfs,
        kad: false,
        directory: Default::default(),
        dag: Default::default(),
    });
    let wants: Arc<std::sync::Mutex<WantSet>> = Default::default();
    let bitswap_session: Arc<ipfs::Session> = Default::default();
    let conn = host::upgrade_outbound(tcp, &cfg, expected.as_deref()).await?;
    let remote_peer = wire::peer_id_string(&conn.remote_peer);
    let session = yamux::session(conn, true);
    let (notes_tx, mut notes) = mpsc::channel(crate::server::libp2p::NOTE_QUEUE);
    let peer = Arc::new(Peer {
        opener: session.opener.clone(),
        remote_peer: remote_peer.clone(),
        remote_addr,
        streams: Default::default(),
        notes: notes_tx.clone(),
    });
    let state = ctx.state.clone();
    let client_id = ctx.client_id;
    let spawn: Spawn = Arc::new(move |task: Task| -> Task {
        let state = state.clone();
        Box::pin(async move {
            let handle = tokio::spawn(task);
            state.register_client_task(client_id, handle).await;
        })
    });
    let reader = session.reader;
    let ended = notes_tx.clone();
    spawn(Box::pin(async move {
        let r = reader.await;
        let _ = ended
            .send(Note::Ended(r.err().map(|e| format!("{e:#}"))))
            .await;
    }))
    .await;
    let writer = session.writer;
    spawn(Box::pin(async move {
        let _ = writer.await;
    }))
    .await;
    spawn(Box::pin(host::accept_streams(
        session.incoming,
        cfg.clone(),
        peer.clone(),
        spawn.clone(),
    )))
    .await;
    let remote = host::identify(&peer).await;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "libp2p client {} connected to {remote_peer} at {remote_addr}",
        cfg.identity.peer_id_string()
    ));
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<(Value, usize)>(32);
    let (event_tx, mut event_rx) = mpsc::channel::<(Event, usize)>(64);
    let mut connected = match &remote {
        Ok(r) => remote_json(r),
        Err(e) => {
            json!({"agent_version": "", "protocols": [], "listen_addrs": [], "identify_error": format!("{e:#}")})
        }
    };
    connected["peer_id"] = json!(remote_peer);
    event_tx.try_send((Event::new(&actions::CONNECTED_EVENT, connected), 0))?;

    // Notes from the streams become events; a stream the remote closed gets our half closed
    // once its messages have been handled; the end of the connection ends the session.
    let (ended_tx, ended_rx) = tokio::sync::oneshot::channel::<String>();
    let notes_events = event_tx.clone();
    let notes_peer = peer.clone();
    let notes_wants = wants.clone();
    let notes_session = bitswap_session.clone();
    let notes_log = ctx.status_tx.clone();
    spawn(Box::pin(async move {
        let mut ended_tx = Some(ended_tx);
        while let Some(note) = notes.recv().await {
            match note {
                Note::Message {
                    stream_id,
                    protocol,
                    data,
                } if bitswap::is_bitswap(&protocol) => {
                    let log = Log::new(Some(&notes_log));
                    match ipfs::received(&data, &notes_wants, &notes_session) {
                        Ok((events, refused)) => {
                            for why in refused {
                                log.warn(format!(
                                    "libp2p client operation=bitswap decision=refused_block: {why}"
                                ));
                            }
                            for e in events {
                                if notes_events.send((e, 0)).await.is_err() {
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            log.warn(format!(
                                "libp2p client operation=bitswap decision=refused_malformed: {e:#}"
                            ));
                            if let Some((_, w)) = notes_peer.writer(stream_id) {
                                w.reset();
                            }
                        }
                    }
                }
                Note::Message {
                    stream_id,
                    protocol,
                    data,
                } => {
                    let (text, encoding) = wire::shown(&data);
                    let e = Event::new(
                        &actions::MESSAGE_EVENT,
                        json!({"stream_id": stream_id, "protocol": protocol, "data": text, "encoding": encoding}),
                    );
                    if notes_events.send((e, 0)).await.is_err() {
                        return;
                    }
                }
                // A clean close keeps our half open for the handler's reply; a failed stream
                // is gone.
                Note::Closed { stream_id, error: Some(_), .. } => notes_peer.forget(stream_id),
                Note::Closed { .. } => {}
                Note::Ended(e) => {
                    if let Some(tx) = ended_tx.take() {
                        let _ = tx.send(e.unwrap_or_else(|| "the remote closed the connection".into()));
                    }
                }
            }
        }
    }))
    .await;

    let events_ctx = ctx.clone();
    spawn(Box::pin(async move {
        while let Some((event, depth)) = event_rx.recv().await {
            // call_llm_for_client records the event (with what was answered) itself.
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
                &Libp2pClientProtocol,
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
                    .warn(format!("libp2p client handler: {e}")),
            }
        }
    }))
    .await;

    let session_ctx = ctx.clone();
    let session_spawn = spawn.clone();
    spawn(Box::pin(async move {
        let reason = run(
            &session_ctx,
            &peer,
            &session_spawn,
            &wants,
            &bitswap_session,
            external,
            internal_rx,
            event_tx,
            ended_rx,
        )
        .await;
        peer.opener.go_away();
        let log = Log::new(Some(&session_ctx.status_tx));
        if ipfs {
            log.info(format!(
                "libp2p client operation=bitswap_ledger {}",
                bitswap_session.summary()
            ));
        }
        log.info(format!("libp2p client ended: {reason}"));
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, ClientStatus::Disconnected)
            .await;
        session_ctx
            .state
            .remove_client_handle(session_ctx.client_id)
            .await;
        let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
    }))
    .await;
    Ok(local)
}

/// Perform actions until the client is told to stop or the connection ends; why it ended.
#[allow(clippy::too_many_arguments)]
async fn run(
    ctx: &ConnectContext,
    peer: &Arc<Peer>,
    spawn: &Spawn,
    wants: &std::sync::Mutex<WantSet>,
    bitswap_session: &ipfs::Session,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, usize)>,
    events: mpsc::Sender<(Event, usize)>,
    mut ended: tokio::sync::oneshot::Receiver<String>,
) -> String {
    let log = Log::new(Some(&ctx.status_tx));
    loop {
        let (action, depth, mut injected) = tokio::select! {
            reason = &mut ended => return reason.unwrap_or_else(|_| "connection dropped".into()),
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
        match Libp2pClientProtocol.execute_action(action.clone()) {
            Ok(ClientActionResult::Disconnect) => {
                reply(&mut injected, ClientSendOutcome::Disconnected);
                return "disconnect requested".into();
            }
            Ok(_) => {}
            Err(e) => {
                log.warn(format!("libp2p client action refused: {e:#}"));
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
                "libp2p client: handler chain stopped after {MAX_FOLLOWUP_DEPTH} follow-ups"
            ));
            continue;
        }
        if injected.is_some() {
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "libp2p",
                    None,
                    "injected_action",
                    action.clone(),
                    vec![],
                )
                .await;
        }
        let operation = action["type"].as_str().unwrap_or_default().to_string();
        let stream = || action["stream_id"].as_u64().unwrap_or(0) as u32;
        // Ok(Some(event data)) raises libp2p_response; Ok(None) needs no answer.
        let result: Result<Option<Value>> = async {
            match operation.as_str() {
                "libp2p_send" => {
                    host::send(peer, stream(), &wire::data_bytes(&action)?)?;
                    Ok(None)
                }
                "libp2p_close_stream" => {
                    let (_, w) = peer
                        .writer(stream())
                        .with_context(|| format!("no open stream {}", stream()))?;
                    w.close();
                    Ok(None)
                }
                "libp2p_open_stream" => {
                    let protocol = action["protocol"].as_str().unwrap_or_default();
                    Ok(Some(match host::open_app_stream(peer, protocol).await? {
                        Some((id, reader)) => {
                            spawn(reader).await;
                            if !action["data"].is_null() {
                                host::send(peer, id, &wire::data_bytes(&action)?)?;
                            }
                            json!({"operation": operation, "ok": true, "stream_id": id, "protocol": protocol})
                        }
                        None => json!({"operation": operation, "ok": false, "protocol": protocol,
                                       "error": format!("the remote does not support {protocol}")}),
                    }))
                }
                "libp2p_ping" => Ok(Some(match host::ping(peer).await {
                    Ok(rtt) => json!({"operation": operation, "ok": true, "rtt_ms": rtt.as_secs_f64() * 1000.0}),
                    Err(e) => json!({"operation": operation, "ok": false, "error": format!("{e:#}")}),
                })),
                "ipfs_bitswap_want" => {
                    let detail = ipfs::want(peer, bitswap_session, wants, &action).await?;
                    Log::new(Some(&ctx.status_tx)).info(format!("libp2p client: {detail}"));
                    Ok(None)
                }
                "ipfs_bitswap_cancel" => {
                    ipfs::cancel(peer, bitswap_session, wants, &action).await?;
                    Ok(None)
                }
                "ipfs_fetch" => {
                    let r = ipfs::fetch(peer, bitswap_session, &action).await;
                    log.info(format!(
                        "libp2p client operation=ipfs_fetch decision={} cid={} kind={} size={} blocks={} {}",
                        if r["ok"] == true { "fetched" } else { "failed" },
                        r["cid"].as_str().unwrap_or_default(),
                        r["kind"].as_str().unwrap_or("-"),
                        r["size"],
                        r["blocks"],
                        bitswap_session.summary()
                    ));
                    Ok(Some(r))
                }
                "ipfs_kad_find_node" | "ipfs_kad_get_providers" => Ok(Some(match ipfs::kad_ask(peer, &action).await {
                    Ok(mut r) => {
                        r["operation"] = json!(operation);
                        r["ok"] = json!(true);
                        r
                    }
                    Err(e) => json!({"operation": operation, "ok": false, "error": format!("{e:#}")}),
                })),
                "libp2p_identify" => Ok(Some(match host::identify(peer).await {
                    Ok(r) => json!({"operation": operation, "ok": true, "result": remote_json(&r)}),
                    Err(e) => json!({"operation": operation, "ok": false, "error": format!("{e:#}")}),
                })),
                other => anyhow::bail!("unknown action {other}"),
            }
        }
        .await;
        match result {
            Ok(data) => {
                reply(
                    &mut injected,
                    ClientSendOutcome::Executed {
                        detail: data
                            .as_ref()
                            .map(Value::to_string)
                            .unwrap_or_else(|| format!("{operation} done")),
                    },
                );
                if let Some(data) = data {
                    let kind = if operation == "ipfs_fetch" {
                        &*actions::FETCHED_EVENT
                    } else {
                        &*actions::RESPONSE_EVENT
                    };
                    if events.try_send((Event::new(kind, data), depth)).is_err() {
                        return "event queue full; consumer stalled".into();
                    }
                }
            }
            Err(e) => {
                log.warn(format!("libp2p client {operation} failed: {e:#}"));
                reply(
                    &mut injected,
                    ClientSendOutcome::Rejected {
                        error: format!("{e:#}"),
                    },
                );
            }
        }
    }
}

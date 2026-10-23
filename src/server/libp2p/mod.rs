//! libp2p host (server role): accepts TCP connections, upgrades them to Noise and yamux,
//! answers identify and ping in Rust, and hands every message on the application protocols'
//! streams to the model, one connection's events at a time.
pub mod actions;
pub mod bitswap;
pub mod host;
pub mod ipfs;
pub mod kad;
pub mod noise;
mod serve_ipfs;
pub mod unixfs;
pub mod wire;
pub mod yamux;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::{
    accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS},
    connection::ConnectionId,
};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use anyhow::{Context, Result};
use host::{Config, Note, Peer, Spawn, Task};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Notes (messages, closes) queued for one connection's model before its streams wait.
pub const NOTE_QUEUE: usize = 64;

/// The identity a `private_key_seed` names: SHA-256 of the text is the Ed25519 seed, so the
/// same text always gives the same peer id. None: a new key.
pub fn identity_from_params(seed: Option<String>) -> Result<noise::Identity> {
    match seed {
        Some(text) => {
            anyhow::ensure!(!text.is_empty(), "private_key_seed must not be empty");
            use sha2::Digest;
            Ok(noise::Identity::from_seed(
                sha2::Sha256::digest(text.as_bytes()).into(),
            ))
        }
        None => Ok(noise::Identity::random()),
    }
}

pub fn protocols_from_params(list: Option<&Vec<Value>>) -> Result<Vec<String>> {
    let Some(list) = list else {
        return Ok(host::DEFAULT_PROTOCOLS
            .iter()
            .map(|s| s.to_string())
            .collect());
    };
    list.iter()
        .map(|v| {
            let p = v.as_str().context("protocols must be strings")?;
            anyhow::ensure!(
                p.starts_with('/') && p.len() <= 256 && !p.contains('\n'),
                "{p:?} is not a protocol id such as /netget/chat/1.0.0"
            );
            anyhow::ensure!(
                ![wire::IDENTIFY, wire::IDENTIFY_PUSH, wire::PING].contains(&p),
                "{p} is answered by NetGet itself"
            );
            anyhow::ensure!(
                !bitswap::is_bitswap(p) && !kad::is_kad(p),
                "{p} is IPFS: set the ipfs startup parameter instead"
            );
            Ok(p.to_string())
        })
        .collect()
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let seed = params
        .map(|p| p.get_optional_string("private_key_seed"))
        .transpose()?
        .flatten();
    let protocols = protocols_from_params(
        params
            .map(|p| p.get_optional_array("protocols"))
            .transpose()?
            .flatten(),
    )?;
    let identity = identity_from_params(seed)?;
    let ipfs = params
        .map(|p| p.get_optional_bool("ipfs"))
        .transpose()?
        .flatten()
        .unwrap_or(actions::IPFS_DEFAULT);
    let content = params
        .map(|p| p.get_optional_array("ipfs_content"))
        .transpose()?
        .flatten()
        .cloned()
        .unwrap_or_default();
    anyhow::ensure!(
        content.is_empty() || ipfs,
        "ipfs_content is served over Bitswap: set ipfs to true"
    );
    let dag: Arc<unixfs::Shared> = Default::default();
    for (i, description) in content.into_iter().enumerate() {
        let built = tokio::task::spawn_blocking(move || unixfs::add(&description))
            .await
            .map_err(|e| anyhow::anyhow!("ipfs_content[{i}] did not finish: {e}"))?
            .with_context(|| format!("ipfs_content[{i}]"))?;
        let added = dag.insert(built)?;
        Log::new(Some(&ctx.status_tx))
            .info(format!("libp2p host {}", serve_ipfs::added_line(&added)));
    }
    let listener = tokio::net::TcpListener::bind(ctx.legacy_listen_addr()).await?;
    let local = listener.local_addr()?;
    let cfg = Arc::new(Config {
        listen_addrs: vec![wire::multiaddr_bytes(&local)],
        identity,
        protocols,
        bitswap: ipfs,
        kad: ipfs,
        directory: Default::default(),
        dag,
    });
    Log::new(Some(&ctx.status_tx)).info(format!(
        "libp2p host listening on {}/p2p/{} ({})",
        wire::multiaddr_string(&local),
        cfg.identity.peer_id_string(),
        cfg.served_protocols().join(", ")
    ));
    let server_id = ctx.server_id;
    let state = ctx.state.clone();
    let accept =
        tokio::spawn(async move {
            let limiter = ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
            loop {
                let (stream, peer, permit) =
                    match accept_bounded(&listener, &limiter, b"", "libp2p", Some(&ctx.status_tx))
                        .await
                    {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                let child = ctx.clone();
                let cfg = cfg.clone();
                ctx.state
                    .spawn_server_task(server_id, async move {
                        let _permit = permit;
                        connection(child, cfg, stream, peer, local).await;
                    })
                    .await;
            }
        });
    state.register_server_task(server_id, accept).await;
    Ok(local)
}

fn spawner(ctx: &SpawnContext) -> Spawn {
    let state = ctx.state.clone();
    let server_id = ctx.server_id;
    Arc::new(move |task: Task| -> Task {
        let state = state.clone();
        Box::pin(async move {
            state.spawn_server_task(server_id, task).await;
        })
    })
}

async fn connection(
    ctx: SpawnContext,
    cfg: Arc<Config>,
    tcp: TcpStream,
    remote: SocketAddr,
    local: SocketAddr,
) {
    let log = Log::new(Some(&ctx.status_tx));
    let conn = match host::upgrade_inbound(tcp, &cfg).await {
        Ok(c) => c,
        Err(e) => {
            log.warn(format!("libp2p connection from {remote} refused: {e:#}"));
            return;
        }
    };
    let remote_peer = wire::peer_id_string(&conn.remote_peer);
    let id = ConnectionId::new(ctx.state.get_next_unified_id().await);
    let now = crate::utils::clock::Instant::now();
    ctx.state
        .add_connection_to_server(
            ctx.server_id,
            ConnectionState {
                id,
                remote_addr: remote,
                local_addr: local,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                last_activity: now,
                status: ConnectionStatus::Active,
                status_changed_at: now,
                protocol_info: ProtocolConnectionInfo::new(json!({"peer_id": remote_peer})),
            },
        )
        .await;
    let close = |reason: String| {
        let ctx = ctx.clone();
        async move {
            ctx.state
                .update_connection_status(ctx.server_id, id, ConnectionStatus::Closed)
                .await;
            ctx.state
                .remove_peer_handle(ctx.server_id, id.as_u32())
                .await;
            Log::new(Some(&ctx.status_tx)).info(format!("libp2p connection {id} closed: {reason}"));
            let _ = ctx.status_tx.send("__UPDATE_UI__".into());
        }
    };
    let session = yamux::session(conn, false);
    let (notes_tx, mut notes) = mpsc::channel(NOTE_QUEUE);
    let peer = Arc::new(Peer {
        opener: session.opener.clone(),
        remote_peer: remote_peer.clone(),
        remote_addr: remote,
        streams: Default::default(),
        notes: notes_tx.clone(),
    });
    let spawn = spawner(&ctx);
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

    let remote_info = host::identify(&peer).await;
    let (agent, protocols, listen) = match &remote_info {
        Ok(r) => (
            r.agent_version.clone(),
            r.protocols.clone(),
            r.listen_addrs.clone(),
        ),
        Err(e) => {
            log.warn(format!("libp2p connection {id}: identify failed: {e:#}"));
            (String::new(), Vec::new(), Vec::new())
        }
    };
    log.info(format!(
        "libp2p connection {id}: peer {remote_peer} ({agent}) connected"
    ));
    if cfg.kad {
        let addrs = listen
            .iter()
            .filter_map(|a| wire::multiaddr_from_text(a).ok())
            .take(kad::MAX_ADDRS)
            .collect();
        cfg.directory
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(remote_peer.clone(), addrs);
    }
    let mut peer_rx =
        crate::server::peer_support::register_peer_channel(&ctx.state, ctx.server_id, id.as_u32())
            .await;
    let connected = Event::new(
        &actions::CONNECTED_EVENT,
        json!({"peer_id": remote_peer, "remote_addr": wire::multiaddr_string(&remote),
               "agent_version": agent, "protocols": protocols, "listen_addrs": listen}),
    );
    let mut ledger = serve_ipfs::Ledger::default();
    let mut dag_rx = cfg.dag.subscribe();
    answer(&ctx, id, &peer, &spawn, &cfg, &mut ledger, connected, None).await;

    let reason = loop {
        tokio::select! {
            note = notes.recv() => match note {
                Some(Note::Message { stream_id, protocol, data }) => {
                    ctx.state
                        .update_connection_stats(ctx.server_id, id, Some(data.len() as u64), None, Some(1), None)
                        .await;
                    if bitswap::is_bitswap(&protocol) {
                        serve_ipfs::bitswap(&ctx, id, &peer, &cfg, &mut ledger, stream_id, &data).await;
                        continue;
                    }
                    if kad::is_kad(&protocol) {
                        serve_ipfs::kad(&ctx, id, &peer, &cfg, stream_id, &protocol, &data).await;
                        continue;
                    }
                    let (text, encoding) = wire::shown(&data);
                    let event = Event::new(
                        &actions::MESSAGE_EVENT,
                        json!({"peer_id": remote_peer, "stream_id": stream_id, "protocol": protocol,
                               "data": text, "encoding": encoding}),
                    );
                    answer(&ctx, id, &peer, &spawn, &cfg, &mut ledger, event, Some(stream_id)).await;
                }
                Some(Note::Closed { stream_id, error, .. }) => {
                    // Every message on it has been answered (notes are in order): close ours.
                    if let Some((_, w)) = peer.writer(stream_id) {
                        if let Some(e) = error {
                            log.warn(format!("libp2p connection {id}: stream {stream_id} reset: {e}"));
                        } else {
                            w.close();
                        }
                    }
                    peer.forget(stream_id);
                }
                Some(Note::Ended(e)) => break e.unwrap_or_else(|| "peer went away".into()),
                None => break "connection dropped".into(),
            },
            command = peer_rx.recv() => {
                let Some(command) = command else { continue };
                inject(&ctx, id, &peer, &spawn, &cfg, &mut ledger, command).await;
            }
            // Content was added (on any connection): wants this peer still has may be met.
            Ok(()) = dag_rx.changed(), if cfg.bitswap => {
                serve_ipfs::store_changed(&ctx, id, &peer, &cfg, &mut ledger).await;
            }
        }
    };
    peer.opener.go_away();
    if cfg.bitswap {
        log.info(format!(
            "libp2p connection {id} operation=bitswap_ledger peer={remote_peer} {}",
            ledger.summary()
        ));
    }
    if cfg.kad {
        cfg.directory
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&remote_peer);
    }
    close(reason).await;
}

/// Ask the model about one event and carry out its answer. `stream` is the stream the
/// event arrived on, which `libp2p_send` and `libp2p_close_stream` default to.
#[allow(clippy::too_many_arguments)]
async fn answer(
    ctx: &SpawnContext,
    id: ConnectionId,
    peer: &Arc<Peer>,
    spawn: &Spawn,
    cfg: &Config,
    ledger: &mut serve_ipfs::Ledger,
    event: Event,
    stream: Option<u32>,
) {
    let log = Log::new(Some(&ctx.status_tx));
    let Some(todo) = ask(ctx, id, &event).await else {
        // Fail closed: the stream being answered is reset, so the peer is not left waiting.
        if let Some((_, w)) = stream.and_then(|s| peer.writer(s)) {
            w.reset();
        }
        return;
    };
    for action in todo {
        if let Err(e) = apply(ctx, id, peer, spawn, cfg, ledger, &action, stream).await {
            log.warn(format!(
                "libp2p connection {id}: {} failed: {e:#}",
                action["type"]
            ));
        }
    }
}

/// Ask the model about one event: the actions it answered with, in order, or None when it
/// failed (logged `decision=fail_closed_llm_error`; the caller fails closed).
async fn ask(ctx: &SpawnContext, id: ConnectionId, event: &Event) -> Option<Vec<Value>> {
    let log = Log::new(Some(&ctx.status_tx));
    let op = event.id().to_string();
    let result = match call_llm(
        &ctx.llm_client,
        &ctx.state,
        ctx.server_id,
        Some(id),
        event,
        &actions::Libp2pProtocol,
    )
    .await
    {
        Ok(r) if r.failures.is_empty() => r,
        Ok(_) | Err(_) => {
            log.error(format!(
                "libp2p connection {id} operation={op} decision=fail_closed_llm_error"
            ));
            return None;
        }
    };
    let mut todo = Vec::new();
    let mut stack = result.protocol_results;
    while let Some(r) = stack.pop() {
        match r {
            ActionResult::Custom { data, .. } => todo.push(data),
            ActionResult::Multiple(items) => stack.extend(items),
            _ => {}
        }
    }
    todo.reverse();
    let decision = if todo.is_empty() {
        "model_silent"
    } else {
        "model_answer"
    };
    log.info(format!(
        "libp2p connection {id} operation={op} decision={decision}"
    ));
    Some(todo)
}

/// Carry out one validated action on this connection; a description of what happened.
#[allow(clippy::too_many_arguments)]
async fn apply(
    ctx: &SpawnContext,
    id: ConnectionId,
    peer: &Arc<Peer>,
    spawn: &Spawn,
    cfg: &Config,
    ledger: &mut serve_ipfs::Ledger,
    action: &Value,
    stream: Option<u32>,
) -> Result<String> {
    let target = || -> Result<u32> {
        action["stream_id"]
            .as_u64()
            .map(|s| s as u32)
            .or(stream)
            .context("no stream to use: give stream_id, or open one with libp2p_open_stream")
    };
    match action["type"].as_str().unwrap_or_default() {
        actions::SEND => {
            let data = wire::data_bytes(action)?;
            let s = target()?;
            host::send(peer, s, &data)?;
            ctx.state
                .update_connection_stats(
                    ctx.server_id,
                    id,
                    None,
                    Some(data.len() as u64),
                    None,
                    Some(1),
                )
                .await;
            Ok(format!("sent {} bytes on stream {s}", data.len()))
        }
        actions::OPEN => {
            let protocol = action["protocol"].as_str().unwrap_or_default();
            match host::open_app_stream(peer, protocol).await? {
                None => anyhow::bail!("the peer does not support {protocol}"),
                Some((s, reader)) => {
                    spawn(reader).await;
                    if !action["data"].is_null() {
                        host::send(peer, s, &wire::data_bytes(action)?)?;
                    }
                    Ok(format!("opened stream {s} on {protocol}"))
                }
            }
        }
        actions::CLOSE => {
            let s = target()?;
            let (_, w) = peer
                .writer(s)
                .with_context(|| format!("no open stream {s}"))?;
            w.close();
            Ok(format!("closed stream {s}"))
        }
        actions::DISCONNECT => {
            peer.opener.go_away();
            Ok("disconnecting".into())
        }
        actions::ADD => {
            anyhow::ensure!(
                cfg.bitswap,
                "ipfs_add serves over Bitswap: start the host with ipfs true"
            );
            let added = serve_ipfs::add_content(cfg, action.clone()).await?;
            let line = serve_ipfs::added_line(&added);
            Log::new(Some(&ctx.status_tx)).info(format!("libp2p connection {id} {line}"));
            Ok(line)
        }
        actions::BLOCKS => {
            // Outside a wantlist's answer: for the wants this peer still has.
            anyhow::ensure!(cfg.bitswap, "ipfs is off on this host");
            serve_ipfs::supply_tracked(ctx, id, peer, ledger, action).await
        }
        t @ actions::KAD_REPLY => {
            anyhow::bail!("{t} answers a DHT request, and can only be given as that answer")
        }
        other => anyhow::bail!("unknown action {other}"),
    }
}

/// An action injected from the dashboard or MCP for this peer.
#[allow(clippy::too_many_arguments)]
async fn inject(
    ctx: &SpawnContext,
    id: ConnectionId,
    peer: &Arc<Peer>,
    spawn: &Spawn,
    cfg: &Config,
    ledger: &mut serve_ipfs::Ledger,
    command: ClientCommand,
) {
    let action = command.action.clone();
    let outcome = match actions::check(&action) {
        Err(e) => ClientSendOutcome::Rejected {
            error: e.to_string(),
        },
        Ok(()) => match apply(ctx, id, peer, spawn, cfg, ledger, &action, None).await {
            Ok(_) if action["type"] == actions::DISCONNECT => ClientSendOutcome::Disconnected,
            Ok(detail) => ClientSendOutcome::Executed { detail },
            Err(e) => ClientSendOutcome::Rejected {
                error: format!("{e:#}"),
            },
        },
    };
    let _ = command.reply_tx.send(Ok(outcome));
}

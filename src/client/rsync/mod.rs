//! rsync client: each model action is one connection to the daemon (rsync opens a connection
//! per transfer too) — the @RSYNCD handshake, the arguments, the file list, the requests and
//! the end-of-run exchange, at protocol 29 (`src/server/rsync/wire.rs`).
pub mod actions;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::rsync::wire::{self, Entry, Kind, MuxReader, Request};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::RsyncClientProtocol;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

/// A whole operation, connect to close.
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
const TURNS: usize = 64;

#[derive(Clone)]
struct Settings {
    daemon: SocketAddr,
    auth: Option<(String, String)>,
    max_fetch: u64,
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let get = |k: &str| -> Result<Option<String>> {
        Ok(params
            .map(|p| p.get_optional_string(k))
            .transpose()?
            .flatten())
    };
    let auth = match (get("username")?, get("password")?) {
        (Some(u), Some(p)) => {
            ensure!(!u.contains([' ', '\n', '\r']), "username is one word");
            Some((u, p))
        }
        (None, None) => None,
        _ => bail!("username and password are given together"),
    };
    let max_fetch = params
        .map(|p| p.get_optional_u64("max_fetch_bytes"))
        .transpose()?
        .flatten()
        .unwrap_or(actions::DEFAULT_MAX_FETCH_BYTES);
    ensure!(
        (1..=actions::MAX_FETCH_BYTES_LIMIT).contains(&max_fetch),
        "max_fetch_bytes must be between 1 and {}",
        actions::MAX_FETCH_BYTES_LIMIT
    );
    let raw = ctx
        .remote_addr
        .trim()
        .trim_start_matches("rsync://")
        .trim_end_matches('/');
    let daemon = match raw.parse::<SocketAddr>() {
        Ok(a) => a,
        Err(_) => {
            let with_port = if raw.contains(':') {
                raw.to_string()
            } else {
                format!("{raw}:873")
            };
            let found = tokio::net::lookup_host(&with_port)
                .await
                .with_context(|| format!("cannot resolve {with_port}"))?
                .next()
                .with_context(|| format!("{with_port} resolved to no address"))?;
            found
        }
    };
    let settings = Settings {
        daemon,
        auth,
        max_fetch,
    };
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "rsync client {} ready for rsync://{daemon}/",
        ctx.client_id
    ));
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURNS);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(64);
    let _ = event_tx.try_send((
        Event::new(&actions::READY_EVENT, json!({"daemon": daemon.to_string()})),
        0,
    ));
    let dispatcher = tokio::spawn(run_turns(ctx.clone(), event_rx, internal_tx));
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        run(&session_ctx, settings, external, internal, event_tx).await;
        dispatcher_abort.abort();
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
    Ok(daemon)
}

async fn run(
    ctx: &ConnectContext,
    settings: Settings,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, u32)>,
    events: mpsc::Sender<(Event, u32)>,
) {
    loop {
        let (action, depth, command) = tokio::select! {
            c = external.recv() => match c {
                Some(c) => {
                    ctx.state.record_access_log(AccessLogOwner::Client(ctx.client_id.as_u32()), "rsync", None,
                        "injected_action", c.action.clone(), vec![]).await;
                    (c.action.clone(), 0, Some(c))
                }
                None => return,
            },
            a = internal.recv() => match a {
                Some((a, d)) => (a, d, None),
                None => return,
            },
        };
        let reply = |command: Option<ClientCommand>, outcome: ClientSendOutcome| {
            if let Some(c) = command {
                crate::client::command_support::reply(c, Ok(outcome));
            }
        };
        let target = match RsyncClientProtocol.execute_action(action.clone()) {
            Ok(ClientActionResult::Disconnect) => {
                reply(command, ClientSendOutcome::Disconnected);
                return;
            }
            Ok(_) => actions::check(&action).ok().flatten(),
            Err(e) => {
                reply(
                    command,
                    ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    },
                );
                continue;
            }
        };
        let kind = action["type"].as_str().unwrap_or_default().to_string();
        let recursive = action["recursive"].as_bool().unwrap_or(false);
        let result = tokio::time::timeout(OPERATION_TIMEOUT, async {
            if kind == "rsync_push" {
                push(&settings, target.clone(), &action).await
            } else {
                operation(&settings, &kind, target.clone(), recursive).await
            }
        })
        .await;
        let (event, data): (&'static EventType, Value) = match result {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => (
                &actions::ERROR_EVENT,
                json!({"operation": kind, "path": target.map(|t| t.1), "message": format!("{e:#}")}),
            ),
            Err(_) => (
                &actions::ERROR_EVENT,
                json!({"operation": kind, "path": target.map(|t| t.1), "message": "the operation timed out"}),
            ),
        };
        Log::new(Some(&ctx.status_tx)).info(format!(
            "rsync client {}: {kind} -> {}",
            ctx.client_id, event.id
        ));
        reply(
            command,
            ClientSendOutcome::Executed {
                detail: data.to_string(),
            },
        );
        if events.try_send((Event::new(event, data), depth)).is_err() {
            tracing::warn!("rsync client {} dropped an event: the model is {TURNS} behind decision=turn_queue_full", ctx.client_id);
        }
    }
}

/// The text phase: greetings, the module line, MOTD lines, and authentication.
/// Returns the lines that were neither status nor error (listing lines, MOTD).
async fn handshake(
    rd: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    module_line: &str,
    auth: &Option<(String, String)>,
) -> Result<(bool, Vec<String>)> {
    wr.write_all(wire::GREETING.as_bytes()).await?;
    let mut lines = Vec::new();
    let greeting = read_line(rd).await?;
    ensure!(
        greeting.starts_with("@RSYNCD: "),
        "not an rsync daemon: {greeting:?}"
    );
    wr.write_all(format!("{module_line}\n").as_bytes()).await?;
    loop {
        let line = read_line(rd).await?;
        if line == "@RSYNCD: OK" {
            return Ok((true, lines));
        }
        if line == "@RSYNCD: EXIT" {
            return Ok((false, lines));
        }
        if let Some(e) = line.strip_prefix("@ERROR") {
            bail!("{}", e.trim_start_matches(':').trim());
        }
        if let Some(challenge) = line.strip_prefix("@RSYNCD: AUTHREQD ") {
            let Some((user, password)) = auth else {
                bail!("the module requires authentication and no username/password is configured");
            };
            wr.write_all(
                format!("{user} {}\n", wire::auth_response(password, challenge)).as_bytes(),
            )
            .await?;
            continue;
        }
        lines.push(line);
    }
}

async fn read_line(rd: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Result<String> {
    let mut buf = Vec::new();
    let n = tokio::io::AsyncReadExt::take(&mut *rd, wire::MAX_LINE as u64)
        .read_until(b'\n', &mut buf)
        .await?;
    ensure!(n > 0, "the daemon closed the connection");
    ensure!(
        buf.ends_with(b"\n"),
        "a line longer than {} bytes",
        wire::MAX_LINE
    );
    Ok(String::from_utf8_lossy(&buf)
        .trim_end_matches(['\n', '\r'])
        .to_string())
}

async fn operation(
    s: &Settings,
    kind: &str,
    target: Option<(String, String)>,
    recursive: bool,
) -> Result<(&'static EventType, Value)> {
    let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(s.daemon))
        .await
        .context("connecting timed out")??;
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);
    let Some((module, arg)) = target else {
        let (_, lines) = handshake(&mut rd, &mut wr, "", &None).await?;
        let mut modules = Vec::new();
        let mut motd = Vec::new();
        for l in lines {
            match l.split_once('\t') {
                Some((name, comment)) => {
                    modules.push(json!({"name": name.trim(), "comment": comment.trim()}))
                }
                None => motd.push(l),
            }
        }
        return Ok((
            &actions::MODULES_EVENT,
            json!({"modules": modules, "motd": motd.join("\n")}),
        ));
    };
    let (ok, _motd) = handshake(&mut rd, &mut wr, &module, &s.auth).await?;
    ensure!(
        ok,
        "the daemon ended the session before accepting the module"
    );
    let req = Request {
        sender: true,
        recursive,
        dirs: !recursive,
        links: true,
        ..Default::default()
    };
    let flags = if recursive { "-lr" } else { "-ld" };
    let args = format!("--server\n--sender\n{flags}\n.\n{arg}\n\n");
    wr.write_all(args.as_bytes()).await?;
    let mut seed = [0u8; 4];
    tokio::io::AsyncReadExt::read_exact(&mut rd, &mut seed)
        .await
        .context("no checksum seed")?;
    let seed = i32::from_le_bytes(seed);
    wr.write_all(&wire::le32(0)).await?; // no filter rules
    let mut mux = MuxReader::new(rd);
    let (mut entries, io_error) = mux.file_list(&req).await?;
    wire::sort(&mut entries);
    let errors: Vec<String> = mux
        .messages
        .iter()
        .filter(|(t, _)| *t == wire::MSG_ERROR_XFER || *t == wire::MSG_ERROR)
        .map(|(_, m)| m.clone())
        .collect();
    if entries.is_empty() {
        // The daemon closes after an empty list.
        let message = if errors.is_empty() {
            "nothing at that path".to_string()
        } else {
            errors.join("; ")
        };
        bail!("{message}");
    }

    // Which files to ask for: regular files, while the budget lasts.
    let fetch = kind == "rsync_fetch";
    let mut wanted = Vec::new();
    let mut skipped = Vec::new();
    let mut budget = s.max_fetch;
    if fetch {
        for (i, e) in entries.iter().enumerate() {
            if e.kind != Kind::File {
                continue;
            }
            if e.size <= budget {
                budget -= e.size;
                wanted.push(i);
            } else {
                skipped.push(e.path.clone());
            }
        }
    }
    let (first_echo_tx, first_echo) = oneshot::channel::<()>();
    let (stats_tx, stats_read) = oneshot::channel::<()>();
    let writer = async {
        let mut requests = Vec::with_capacity(wanted.len() * 22 + 4);
        for &i in &wanted {
            requests.extend_from_slice(&wire::le32(i as i32));
            requests.extend_from_slice(&(wire::ITEM_TRANSFER | wire::ITEM_IS_NEW).to_le_bytes());
            requests.extend_from_slice(&[0u8; 16]); // no basis: send everything
        }
        requests.extend_from_slice(&wire::le32(wire::NDX_DONE));
        wr.write_all(&requests).await?;
        first_echo.await.context("the reply stream ended early")?;
        wr.write_all(&[wire::le32(wire::NDX_DONE), wire::le32(wire::NDX_DONE)].concat())
            .await?;
        stats_read.await.context("the reply stream ended early")?;
        wr.write_all(&wire::le32(wire::NDX_DONE)).await?; // the final goodbye
        let _ = wr.shutdown().await;
        anyhow::Ok(())
    };
    let reader = async {
        let mut files = Vec::new();
        let mut first_echo_tx = Some(first_echo_tx);
        let mut phase = 0;
        loop {
            let ndx = mux.int().await?;
            if ndx == wire::NDX_DONE {
                phase += 1;
                if let Some(tx) = first_echo_tx.take() {
                    let _ = tx.send(());
                }
                if phase == 3 {
                    break;
                }
                continue;
            }
            let iflags = mux.short().await?;
            if iflags & wire::ITEM_BASIS_TYPE_FOLLOWS != 0 {
                mux.byte().await?;
            }
            if iflags & wire::ITEM_XNAME_FOLLOWS != 0 {
                let mut n = mux.byte().await? as usize;
                if n & 0x80 != 0 {
                    n = ((n & 0x7f) << 8) | mux.byte().await? as usize;
                }
                mux.read(n).await?;
            }
            if iflags & wire::ITEM_TRANSFER == 0 {
                continue;
            }
            ensure!(
                ndx >= 0 && (ndx as usize) < entries.len(),
                "a reply for index {ndx}"
            );
            for _ in 0..4 {
                mux.int().await?;
            }
            let e: &Entry = &entries[ndx as usize];
            let mut data = Vec::new();
            loop {
                let t = mux.int().await?;
                if t == 0 {
                    break;
                }
                ensure!(t > 0, "a block-match token with no basis file");
                ensure!(
                    data.len() as u64 + t as u64 <= e.size.max(1) * 2 + wire::CHUNK as u64,
                    "more data than the file list said"
                );
                data.extend(mux.read(t as usize).await?);
            }
            let sum = mux.read(16).await?;
            ensure!(
                sum == wire::file_sum(seed, &data),
                "{}: checksum mismatch",
                e.path
            );
            let (content, encoding) = wire::content_json(&data);
            files.push(json!({"path": e.path, "size": data.len(), "content": content, "encoding": encoding}));
        }
        for _ in 0..5 {
            mux.longint().await?;
        }
        let _ = stats_tx.send(());
        anyhow::Ok(files)
    };
    let (w, files) = tokio::join!(writer, reader);
    let files = files?;
    w?;
    let errors: Vec<String> = mux
        .messages
        .iter()
        .filter(|(t, _)| *t == wire::MSG_ERROR_XFER || *t == wire::MSG_ERROR)
        .map(|(_, m)| m.clone())
        .collect();
    ensure!(
        errors.is_empty() && io_error == 0 && mux.io_error == 0,
        "{}",
        if errors.is_empty() {
            "the daemon reported an I/O error".into()
        } else {
            errors.join("; ")
        }
    );
    let listing: Vec<Value> = entries.iter().map(wire::entry_json).collect();
    if fetch {
        Ok((
            &actions::FETCHED_EVENT,
            json!({"path": arg, "files": files, "entries": listing, "skipped": skipped}),
        ))
    } else {
        Ok((
            &actions::LISTING_EVENT,
            json!({"path": arg, "entries": listing}),
        ))
    }
}

/// A push: this client is rsync's sender, the daemon its receiver (protocol 29).
///
/// The file list goes out raw, built from the action's files plus the directories they imply
/// and "." for the destination itself. The daemon's generator then asks for files by index —
/// multiplexed, each with an item-flags word and a checksum header — and every one is answered
/// whole: the same header echoed, the data as literal tokens, MD4(seed ‖ data). Items it only
/// reports (a directory it made) are echoed back as rsync's sender does. Each NDX_DONE is
/// echoed; after the third comes the daemon's final one, and the connection closes.
async fn push(
    s: &Settings,
    target: Option<(String, String)>,
    action: &Value,
) -> Result<(&'static EventType, Value)> {
    let (module, arg) = target.context("a push needs a destination")?;
    let now = crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let mut entries = Vec::new();
    for f in action["files"].as_array().into_iter().flatten() {
        entries.push(wire::entry_from_json(f, now)?);
    }
    crate::server::rsync::complete_dirs(&mut entries, now);
    let mut root = wire::entry_from_json(&json!({"path": "root", "type": "dir"}), now)?;
    root.path = ".".into();
    entries.push(root);
    wire::sort(&mut entries);
    let req = Request {
        recursive: true,
        links: true,
        ..Default::default()
    };
    let mut list = Vec::new();
    let mut writer = wire::FlistWriter::default();
    for e in &entries {
        writer.entry(e, e.path == ".", &req, &mut list);
    }
    wire::FlistWriter::finish(&req, 0, &mut list);

    let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(s.daemon))
        .await
        .context("connecting timed out")??;
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);
    let (ok, _motd) = handshake(&mut rd, &mut wr, &module, &s.auth).await?;
    ensure!(
        ok,
        "the daemon ended the session before accepting the module"
    );
    wr.write_all(format!("--server\n-lr\n.\n{arg}\n\n").as_bytes())
        .await?;
    let mut seed = [0u8; 4];
    tokio::io::AsyncReadExt::read_exact(&mut rd, &mut seed)
        .await
        .context("no checksum seed")?;
    let seed = i32::from_le_bytes(seed);
    wr.write_all(&list).await?;

    let mut mux = MuxReader::new(rd);
    let mut sent = Vec::new();
    let mut requested = std::collections::HashSet::new();
    let mut dones = 0;
    let result: Result<()> = async {
        loop {
            let ndx = mux.int().await?;
            if ndx == wire::NDX_DONE {
                wr.write_all(&wire::le32(wire::NDX_DONE)).await?;
                dones += 1;
                if dones == 3 {
                    break;
                }
                continue;
            }
            if ndx as usize == entries.len() {
                // A protocol-29 keep-alive from a generator busy on something slow.
                mux.short().await?;
                continue;
            }
            ensure!(
                ndx >= 0 && (ndx as usize) < entries.len(),
                "the daemon asked for index {ndx} of {}",
                entries.len()
            );
            let iflags = mux.short().await?;
            let mut reply = wire::le32(ndx).to_vec();
            reply.extend_from_slice(&iflags.to_le_bytes());
            if iflags & wire::ITEM_BASIS_TYPE_FOLLOWS != 0 {
                reply.push(mux.byte().await?);
            }
            if iflags & wire::ITEM_XNAME_FOLLOWS != 0 {
                let first = mux.byte().await?;
                reply.push(first);
                let mut n = first as usize;
                if n & 0x80 != 0 {
                    let low = mux.byte().await?;
                    reply.push(low);
                    n = ((n & 0x7f) << 8) | low as usize;
                }
                reply.extend(mux.read(n).await?);
            }
            if iflags & wire::ITEM_TRANSFER == 0 {
                wr.write_all(&reply).await?;
                continue;
            }
            let entry = &entries[ndx as usize];
            ensure!(
                entry.kind == Kind::File,
                "the daemon asked to transfer {:?}, which is not a file",
                entry.path
            );
            let mut head = [0i32; 4];
            for v in head.iter_mut() {
                *v = mux.int().await?;
            }
            let [count, _blength, s2length, _remainder] = head;
            ensure!(
                (0..=wire::MAX_SUM_COUNT).contains(&count) && (0..=16).contains(&s2length),
                "a malformed checksum header"
            );
            // Block checksums of the daemon's existing copy: read, and not used, since every
            // file is sent whole.
            mux.read(count as usize * (4 + s2length as usize)).await?;
            for v in head {
                reply.extend_from_slice(&wire::le32(v));
            }
            for chunk in entry.data.chunks(wire::CHUNK) {
                reply.extend_from_slice(&wire::le32(chunk.len() as i32));
                reply.extend_from_slice(chunk);
            }
            reply.extend_from_slice(&wire::le32(0));
            reply.extend_from_slice(&wire::file_sum(seed, &entry.data));
            wr.write_all(&reply).await?;
            if requested.insert(ndx) {
                sent.push(json!({"path": entry.path, "size": entry.data.len()}));
            }
        }
        // The daemon's final NDX_DONE, then it closes.
        ensure!(
            mux.int().await? == wire::NDX_DONE,
            "no final goodbye from the daemon"
        );
        Ok(())
    }
    .await;
    let _ = wr.shutdown().await;
    let errors: Vec<String> = mux
        .messages
        .iter()
        .filter(|(t, _)| *t == wire::MSG_ERROR_XFER || *t == wire::MSG_ERROR)
        .map(|(_, m)| m.clone())
        .collect();
    if let Err(e) = result {
        // A daemon that refuses outright says why and closes; that is the answer.
        if errors.is_empty() {
            return Err(e);
        }
        bail!("{}", errors.join("; "));
    }
    let not_requested: Vec<String> = entries
        .iter()
        .enumerate()
        .filter(|(i, e)| e.kind == Kind::File && !requested.contains(&(*i as i32)))
        .map(|(_, e)| e.path.clone())
        .collect();
    let complete = errors.is_empty() && mux.io_error == 0;
    Ok((
        &actions::PUSHED_EVENT,
        json!({"path": arg, "sent": sent, "not_requested": not_requested, "errors": errors, "complete": complete}),
    ))
}

async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32)>,
    internal: mpsc::Sender<(Value, u32)>,
) {
    let protocol = RsyncClientProtocol;
    while let Some((event, depth)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            tracing::warn!("rsync client {} not asking the model about {}: {depth} turns deep decision=followup_depth", ctx.client_id, event.id());
            continue;
        }
        let instruction = ctx
            .state
            .get_instruction_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        let memory = ctx
            .state
            .get_memory_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        match call_llm_for_client(
            &ctx.llm_client,
            &ctx.state,
            ctx.client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            &protocol,
            &ctx.status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(memory) = result.memory_updates {
                    ctx.state.set_memory_for_client(ctx.client_id, memory).await;
                }
                for action in result.actions {
                    if internal.send((action, depth + 1)).await.is_err() {
                        return;
                    }
                }
            }
            Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!("rsync client handler: {e}")),
        }
    }
}

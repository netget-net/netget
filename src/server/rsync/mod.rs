//! rsync daemon (rsync://, TCP 873) at protocol 29. Rust owns the handshake, the file-list
//! encoding and order, the transfer tokens, the checksums and the end-of-run dance; the model
//! says which modules exist, what each requested path holds, and which uploaded files to take
//! (their contents are handed to it, never written to disk).
pub mod actions;
pub mod wire;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::connection::ConnectionId;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use wire::{Entry, Kind, Request};

/// Deadline for each line or request from the client.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
pub const MAX_IDLE_TIMEOUT_SECS: u64 = 3600;
/// Paths one request may name.
pub const MAX_PATHS: usize = 16;
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
/// Largest single file an upload may deliver; a bigger one is refused before it is requested.
pub const MAX_UPLOAD_FILE_BYTES: u64 = 1024 * 1024;
/// All the files of one upload together.
pub const MAX_UPLOAD_BYTES: u64 = 8 * 1024 * 1024;
/// Files one upload may deliver.
pub const MAX_UPLOAD_FILES: usize = 1000;

#[derive(Clone)]
struct Config {
    motd: Option<String>,
    idle: Duration,
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let motd = params
        .map(|p| p.get_optional_string("motd"))
        .transpose()?
        .flatten();
    let idle = params
        .map(|p| p.get_optional_u64("idle_timeout_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(IDLE_TIMEOUT.as_secs());
    ensure!(
        (1..=MAX_IDLE_TIMEOUT_SECS).contains(&idle),
        "idle_timeout_secs must be between 1 and {MAX_IDLE_TIMEOUT_SECS}"
    );
    let cfg = Config {
        motd: motd.map(|m| crate::utils::sanitize::multiline(&m)),
        idle: Duration::from_secs(idle),
    };
    let listener = TcpListener::bind(ctx.legacy_listen_addr()).await?;
    let addr = listener.local_addr()?;
    Log::new(Some(&ctx.status_tx)).info(format!("rsync daemon listening on {addr} (protocol 29)"));
    let state = ctx.state.clone();
    let server_id = ctx.server_id;
    let accept = tokio::spawn(async move {
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(
            crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS,
        );
        loop {
            let (socket, peer, permit) = match crate::server::accept_bounded::accept_bounded(
                &listener,
                &limiter,
                b"@ERROR: max connections reached -- try again later\n",
                "rsync",
                Some(&ctx.status_tx),
            )
            .await
            {
                Ok(v) => v,
                Err(_) => break,
            };
            let id = ConnectionId::new(ctx.state.get_next_unified_id().await);
            let now = crate::utils::clock::Instant::now();
            ctx.state
                .add_connection_to_server(
                    server_id,
                    ConnectionState {
                        id,
                        remote_addr: peer,
                        local_addr: addr,
                        bytes_sent: 0,
                        bytes_received: 0,
                        packets_sent: 0,
                        packets_received: 0,
                        last_activity: now,
                        status: ConnectionStatus::Active,
                        status_changed_at: now,
                        protocol_info: ProtocolConnectionInfo::empty(),
                    },
                )
                .await;
            let child = ctx.clone();
            let cfg = cfg.clone();
            ctx.state
                .spawn_server_task(server_id, async move {
                    let _permit = permit;
                    if let Err(e) = session(&child, id, socket, peer, &cfg).await {
                        Log::new(Some(&child.status_tx))
                            .warn(format!("rsync connection {id} ended: {e:#}"));
                    }
                    child
                        .state
                        .update_connection_status(server_id, id, ConnectionStatus::Closed)
                        .await;
                    let _ = child.status_tx.send("__UPDATE_UI__".into());
                })
                .await;
        }
    });
    state.register_server_task(server_id, accept).await;
    Ok(addr)
}

/// The client side of the socket: raw at protocol 29, with a read deadline and a byte count.
struct In {
    rd: BufReader<OwnedReadHalf>,
    idle: Duration,
    total: u64,
}

impl In {
    async fn exact(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(self.idle, self.rd.read_exact(&mut buf))
            .await
            .context("the client went quiet")??;
        self.total += n as u64;
        Ok(buf)
    }
    async fn int(&mut self) -> Result<i32> {
        let b = self.exact(4).await?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    async fn short(&mut self) -> Result<u16> {
        let b = self.exact(2).await?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    /// One `\n`-terminated line, `\r` dropped, at most `MAX_LINE` bytes.
    async fn line(&mut self) -> Result<String> {
        let mut out = Vec::new();
        loop {
            let b = self.exact(1).await?[0];
            match b {
                b'\n' => break,
                b'\r' => {}
                0 => bail!("a NUL byte in a text line"),
                _ => {
                    ensure!(
                        out.len() < wire::MAX_LINE,
                        "a line longer than {} bytes",
                        wire::MAX_LINE
                    );
                    out.push(b);
                }
            }
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
    /// Read and discard `n` bytes.
    async fn skip(&mut self, mut n: u64) -> Result<()> {
        while n > 0 {
            let k = n.min(64 * 1024) as usize;
            self.exact(k).await?;
            n -= k as u64;
        }
        Ok(())
    }
}

struct Out {
    wr: OwnedWriteHalf,
    total: u64,
}

impl Out {
    async fn raw(&mut self, bytes: &[u8]) -> Result<()> {
        tokio::time::timeout(WRITE_TIMEOUT, self.wr.write_all(bytes))
            .await
            .context("rsync write deadline")??;
        self.total += bytes.len() as u64;
        Ok(())
    }
    async fn data(&mut self, bytes: &[u8]) -> Result<()> {
        self.raw(&wire::data_frames(bytes)).await
    }
    async fn message(&mut self, code: u8, text: &str) -> Result<()> {
        let mut t = crate::utils::sanitize::multiline(text);
        t.truncate(4000);
        if !t.ends_with('\n') {
            t.push('\n');
        }
        self.raw(&wire::frame(code, t.as_bytes())).await
    }
}

fn now_secs() -> u32 {
    crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

async fn ask(
    ctx: &SpawnContext,
    id: ConnectionId,
    event: Event,
) -> Result<Option<(String, Value)>> {
    let execution = call_llm(
        &ctx.llm_client,
        &ctx.state,
        ctx.server_id,
        Some(id),
        &event,
        &actions::RsyncProtocol,
    )
    .await?;
    Ok(execution.protocol_results.iter().find_map(|r| match r {
        ActionResult::Custom { name, data } => Some((name.clone(), data.clone())),
        _ => None,
    }))
}

fn decision(ctx: &SpawnContext, id: ConnectionId, operation: &str, decision: &str) {
    let line = format!("rsync connection {id} operation={operation} decision={decision}");
    let log = Log::new(Some(&ctx.status_tx));
    if decision.starts_with("fail_closed") {
        log.error(line);
    } else {
        log.info(line);
    }
}

async fn session(
    ctx: &SpawnContext,
    id: ConnectionId,
    socket: TcpStream,
    peer: SocketAddr,
    cfg: &Config,
) -> Result<()> {
    let (rd, wr) = socket.into_split();
    let mut input = In {
        rd: BufReader::new(rd),
        idle: cfg.idle,
        total: 0,
    };
    let mut out = Out { wr, total: 0 };
    let mut hello = wire::GREETING.to_string();
    if let Some(motd) = &cfg.motd {
        hello.push_str(motd);
        hello.push('\n');
    }
    out.raw(hello.as_bytes()).await?;
    let greeting = input.line().await?;
    let major: i32 = greeting
        .strip_prefix("@RSYNCD: ")
        .and_then(|v| v.split(['.', ' ']).next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if major < wire::PROTOCOL {
        out.raw(b"@ERROR: protocol startup error\n").await?;
        bail!("client greeting {greeting:?}: protocol 29 or later is required");
    }
    let module = input.line().await?;
    let client = peer.to_string();
    if module.is_empty() || module == "#list" {
        return list_modules(ctx, id, &mut out, &client).await;
    }
    if module.starts_with('#') || module.contains('/') {
        out.raw(b"@ERROR: request not supported by this daemon\n")
            .await?;
        return Ok(());
    }
    out.raw(b"@RSYNCD: OK\n").await?;
    let mut args = Vec::new();
    loop {
        let a = input.line().await?;
        if a.is_empty() {
            break;
        }
        ensure!(
            args.len() < wire::MAX_ARGS,
            "more than {} arguments",
            wire::MAX_ARGS
        );
        args.push(a);
    }
    let req = wire::parse_args(&args, &module);
    let seed = req.checksum_seed.unwrap_or_else(|| loop {
        let s: i32 = rand::random();
        if s != 0 {
            break s;
        }
    });
    out.raw(&wire::le32(seed)).await?;
    if let Some(refusal) = &req.refusal {
        // Said at once: an uploading client sends its own file list next, not a filter list,
        // and an argument this daemon cannot honour must stop it before that list is read.
        decision(ctx, id, "request", "refused_options");
        out.message(wire::MSG_ERROR_XFER, &format!("ERROR: {refusal}"))
            .await?;
        // Close our side, then let the client's bytes drain so the error is not lost to a reset.
        let _ = out.wr.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let mut sink = [0u8; 4096];
            while matches!(input.rd.read(&mut sink).await, Ok(n) if n > 0) {}
        })
        .await;
        return Ok(());
    }
    if !req.sender {
        return upload(ctx, id, &mut input, &mut out, &module, &req, seed, &client).await;
    }
    // The filter list (raw at 29), read whole before anything else is sent.
    let mut filter_bytes = 0usize;
    loop {
        let n = input.int().await?;
        if n == 0 {
            break;
        }
        ensure!(n > 0, "a negative filter-rule length");
        filter_bytes += n as usize;
        ensure!(
            filter_bytes <= wire::MAX_FILTER_BYTES,
            "more than {} bytes of filter rules",
            wire::MAX_FILTER_BYTES
        );
        input.exact(n as usize).await?;
    }
    if req.paths.is_empty() || req.paths.len() > MAX_PATHS {
        out.message(
            wire::MSG_ERROR_XFER,
            "ERROR: no path, or too many paths, in the request",
        )
        .await?;
        return Ok(());
    }

    // Ask the model what each requested path holds.
    let mut model_entries: Vec<Entry> = Vec::new();
    let now = now_secs();
    for path in &req.paths {
        let event = Event::new(
            &actions::REQUEST_EVENT,
            json!({"module": module, "path": path, "recursive": req.recursive, "list_only": req.list_only, "client": client}),
        );
        match ask(ctx, id, event).await {
            Ok(Some((name, data))) if name == actions::ENTRIES => {
                for e in data["entries"].as_array().into_iter().flatten() {
                    model_entries.push(wire::entry_from_json(e, now)?);
                }
            }
            Ok(Some((name, data))) if name == actions::REFUSE => {
                decision(ctx, id, "request", "model_refused");
                let msg = data["message"].as_str().unwrap_or("refused");
                out.message(wire::MSG_ERROR_XFER, &format!("@ERROR: {msg}"))
                    .await?;
                return Ok(());
            }
            Ok(_) => {
                // Nothing said about this path: it does not exist.
            }
            Err(e) => {
                decision(ctx, id, "request", "fail_closed_llm_error");
                let text = crate::utils::wire_failure::wire_failure_text(&e);
                out.message(wire::MSG_ERROR_XFER, &format!("ERROR: {text}"))
                    .await?;
                return Ok(());
            }
        }
    }
    complete_dirs(&mut model_entries, now);
    let (list, notes, missing) = select(&model_entries, &req, now);
    for (code, text) in &notes {
        out.message(*code, text).await?;
    }
    let mut bytes = Vec::new();
    let mut writer = wire::FlistWriter::default();
    for (e, top) in &list {
        writer.entry(e, *top, &req, &mut bytes);
    }
    wire::FlistWriter::finish(&req, i32::from(missing), &mut bytes);
    out.data(&bytes).await?;
    decision(
        ctx,
        id,
        "request",
        &format!("model_answered entries={}", list.len()),
    );
    if list.is_empty() {
        // The receiver sends nothing more for an empty list; rsync's sender exits here.
        let _ = out.wr.shutdown().await;
        return Ok(());
    }

    // Requests, three NDX_DONE phases, stats, goodbye.
    let mut phase = 0;
    let mut sent_files = 0;
    loop {
        let ndx = input.int().await?;
        if ndx == wire::NDX_DONE {
            phase += 1;
            if phase > 2 {
                break;
            }
            out.data(&wire::le32(wire::NDX_DONE)).await?;
            continue;
        }
        let iflags = input.short().await?;
        let mut echo = Vec::new();
        echo.extend_from_slice(&wire::le32(ndx));
        echo.extend_from_slice(&iflags.to_le_bytes());
        if iflags & wire::ITEM_BASIS_TYPE_FOLLOWS != 0 {
            echo.extend(input.exact(1).await?);
        }
        if iflags & wire::ITEM_XNAME_FOLLOWS != 0 {
            let mut len = input.exact(1).await?;
            let mut n = len[0] as usize;
            if n & 0x80 != 0 {
                let low = input.exact(1).await?[0];
                n = ((n & 0x7f) << 8) | low as usize;
                len.push(low);
            }
            echo.extend(len);
            echo.extend(input.exact(n).await?);
        }
        if ndx as usize == list.len() && iflags == wire::ITEM_IS_NEW {
            continue; // a protocol-29 keep-alive
        }
        ensure!(
            ndx >= 0 && (ndx as usize) < list.len(),
            "request for index {ndx} of {}",
            list.len()
        );
        let entry = &list[ndx as usize].0;
        if iflags & wire::ITEM_TRANSFER == 0 || req.dry_run {
            out.data(&echo).await?;
            continue;
        }
        ensure!(
            entry.kind == Kind::File,
            "request to transfer non-regular file {:?}",
            entry.path
        );
        let count = input.int().await?;
        let blength = input.int().await?;
        let s2length = input.int().await?;
        let remainder = input.int().await?;
        ensure!(
            (0..=wire::MAX_SUM_COUNT).contains(&count)
                && (0..=16).contains(&s2length)
                && blength >= 0
                && remainder >= 0,
            "a malformed checksum header"
        );
        // Block checksums are read and not used: every file is sent whole.
        input.skip(count as u64 * (4 + s2length as u64)).await?;
        let mut reply = echo;
        for v in [count, blength, s2length, remainder] {
            reply.extend_from_slice(&wire::le32(v));
        }
        for chunk in entry.data.chunks(wire::CHUNK) {
            reply.extend_from_slice(&wire::le32(chunk.len() as i32));
            reply.extend_from_slice(chunk);
        }
        reply.extend_from_slice(&wire::le32(0));
        reply.extend_from_slice(&wire::file_sum(seed, &entry.data));
        out.data(&reply).await?;
        sent_files += 1;
    }
    let total_size: u64 = list
        .iter()
        .filter(|(e, _)| e.kind != Kind::Dir)
        .map(|(e, _)| e.size)
        .sum();
    let mut tail = wire::le32(wire::NDX_DONE).to_vec();
    let written = out.total + 4 + 4 + 20;
    for v in [input.total, written, total_size, 1, 0] {
        tail.extend(wire::longint(v));
    }
    out.data(&tail).await?;
    let goodbye = input.int().await?;
    ensure!(
        goodbye == wire::NDX_DONE,
        "expected the final goodbye, got {goodbye}"
    );
    ctx.state
        .update_connection_stats(
            ctx.server_id,
            id,
            Some(input.total),
            Some(out.total),
            None,
            None,
        )
        .await;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "rsync connection {id}: module {module}, {} entries, {sent_files} files sent",
        list.len()
    ));
    let _ = out.wr.shutdown().await;
    Ok(())
}

/// The module-relative path of an entry an uploading client listed under `dest`.
fn upload_path(dest: &str, entry: &str) -> String {
    let dest = dest.trim_end_matches('/');
    match (dest.is_empty(), entry) {
        (_, ".") => dest.to_string(),
        (true, e) => e.to_string(),
        (false, e) => format!("{dest}/{e}"),
    }
}

/// The receiving side of a push (protocol 29: the client's bytes raw, ours multiplexed).
///
/// The client's file list comes first; the model decides which files to take; each taken file
/// is requested whole (an empty checksum header, as for a new file), read as literal tokens and
/// checked against MD4(seed ‖ data); then the end-of-run exchange the stock receiver makes:
/// NDX_DONE, the client's echo, two more each way, and a final one. The files are handed to the
/// model in `rsync_upload_complete`; nothing is written anywhere.
#[allow(clippy::too_many_arguments)]
async fn upload(
    ctx: &SpawnContext,
    id: ConnectionId,
    input: &mut In,
    out: &mut Out,
    module: &str,
    req: &Request,
    seed: i32,
    client: &str,
) -> Result<()> {
    let dest = req.paths.first().cloned().unwrap_or_default();
    let mut reader = wire::MuxReader::raw(&mut input.rd);
    let (mut entries, _io_error) = tokio::time::timeout(input.idle, reader.file_list(req))
        .await
        .context("the client went quiet sending its file list")??;
    input.total += reader.consumed;
    // Indexes are positions in rsync's order, as the client numbers them too.
    wire::sort(&mut entries);
    entries.dedup_by(|a, b| a.path == b.path);

    let files: Vec<Value> = entries
        .iter()
        .map(|e| {
            let mut v = json!({
                "path": upload_path(&dest, &e.path),
                "type": e.kind.name(),
                "size": e.size,
                "mode": format!("{:o}", e.mode & 0o7777),
            });
            if e.kind == Kind::Symlink {
                v["target"] = json!(String::from_utf8_lossy(&e.data));
            }
            v
        })
        .collect();
    let regular: Vec<usize> = (0..entries.len())
        .filter(|&i| entries[i].kind == Kind::File)
        .collect();
    let event = Event::new(
        &actions::UPLOAD_REQUEST_EVENT,
        json!({
            "module": module,
            "path": dest,
            "files": files,
            "file_count": regular.len(),
            "total_bytes": regular.iter().map(|&i| entries[i].size).sum::<u64>(),
            "client": client,
        }),
    );
    // Which files to take, and why each other one is not taken.
    let mut take: Vec<usize> = Vec::new();
    let mut refused: Vec<(String, String)> = Vec::new();
    match ask(ctx, id, event).await {
        Ok(Some((name, data))) if name == actions::ACCEPT_UPLOAD => {
            let wanted: Option<std::collections::HashSet<String>> =
                data.get("paths").and_then(|p| p.as_array()).map(|l| {
                    l.iter()
                        .filter_map(|p| p.as_str().map(String::from))
                        .collect()
                });
            let mut budget = 0u64;
            for &i in &regular {
                let path = upload_path(&dest, &entries[i].path);
                let reason = if wanted.as_ref().is_some_and(|w| !w.contains(&path)) {
                    Some("refused by the daemon")
                } else if entries[i].size > MAX_UPLOAD_FILE_BYTES {
                    Some("larger than this daemon accepts")
                } else if take.len() >= MAX_UPLOAD_FILES
                    || budget + entries[i].size > MAX_UPLOAD_BYTES
                {
                    Some("over this daemon's upload limit")
                } else {
                    None
                };
                match reason {
                    Some(r) => refused.push((path, r.to_string())),
                    None => {
                        budget += entries[i].size;
                        take.push(i);
                    }
                }
            }
            decision(
                ctx,
                id,
                "upload",
                &format!(
                    "model_accepted taken={} refused={}",
                    take.len(),
                    refused.len()
                ),
            );
        }
        Ok(Some((name, data))) if name == actions::REFUSE => {
            decision(ctx, id, "upload", "model_refused");
            let msg = data["message"].as_str().unwrap_or("refused");
            out.message(wire::MSG_ERROR_XFER, &format!("@ERROR: {msg}"))
                .await?;
        }
        Ok(_) => {
            // No decision is not consent.
            decision(ctx, id, "upload", "fail_closed_no_decision");
            out.message(wire::MSG_ERROR_XFER, "ERROR: upload refused by the daemon")
                .await?;
        }
        Err(e) => {
            decision(ctx, id, "upload", "fail_closed_llm_error");
            let text = crate::utils::wire_failure::wire_failure_text(&e);
            out.message(wire::MSG_ERROR_XFER, &format!("ERROR: {text}"))
                .await?;
        }
    }
    for (path, reason) in &refused {
        out.message(
            wire::MSG_ERROR_XFER,
            &format!("rsync: [receiver] {path}: {reason}"),
        )
        .await?;
    }

    // Request each taken file and read it back, one at a time.
    let mut received: Vec<Value> = entries
        .iter()
        .filter(|e| e.kind != Kind::File)
        .map(|e| json!({"path": upload_path(&dest, &e.path), "type": e.kind.name()}))
        .collect();
    let mut failed: Vec<(String, String)> = Vec::new();
    for &i in &take {
        let entry = &entries[i];
        let path = upload_path(&dest, &entry.path);
        let mut request = wire::le32(i as i32).to_vec();
        request.extend_from_slice(&(wire::ITEM_TRANSFER | wire::ITEM_IS_NEW).to_le_bytes());
        for _ in 0..4 {
            request.extend_from_slice(&wire::le32(0));
        }
        out.data(&request).await?;
        let ndx = input.int().await?;
        ensure!(ndx == i as i32, "asked for file {i}, the client sent {ndx}");
        let iflags = input.short().await?;
        ensure!(
            iflags & wire::ITEM_TRANSFER != 0
                && iflags & (wire::ITEM_BASIS_TYPE_FOLLOWS | wire::ITEM_XNAME_FOLLOWS) == 0,
            "the client answered a whole-file request with item flags {iflags:#06x}"
        );
        let mut head = [0i32; 4];
        for v in head.iter_mut() {
            *v = input.int().await?;
        }
        ensure!(
            head == [0, 0, 0, 0],
            "the client echoed checksum header {head:?} for a request without one"
        );
        let mut data = Vec::new();
        loop {
            let token = input.int().await?;
            if token == 0 {
                break;
            }
            ensure!(
                token > 0,
                "a block reference in a file sent without a basis"
            );
            ensure!(
                data.len() as u64 + token as u64 <= MAX_UPLOAD_FILE_BYTES,
                "{path} grew past {MAX_UPLOAD_FILE_BYTES} bytes while it was sent"
            );
            data.extend(input.exact(token as usize).await?);
        }
        let sum = input.exact(16).await?;
        if sum != wire::file_sum(seed, &data) {
            out.message(
                wire::MSG_ERROR_XFER,
                &format!("rsync: [receiver] {path}: checksum mismatch, file discarded"),
            )
            .await?;
            failed.push((path, "checksum mismatch".into()));
            continue;
        }
        let (content, encoding) = wire::content_json(&data);
        received.push(json!({"path": path, "type": "file", "size": data.len(), "content": content, "encoding": encoding}));
    }

    // The end of the run, as the stock receiver makes it.
    out.data(&wire::le32(wire::NDX_DONE)).await?;
    ensure!(
        input.int().await? == wire::NDX_DONE,
        "the client did not end its phase"
    );
    let mut two = wire::le32(wire::NDX_DONE).to_vec();
    two.extend_from_slice(&wire::le32(wire::NDX_DONE));
    out.data(&two).await?;
    for _ in 0..2 {
        ensure!(
            input.int().await? == wire::NDX_DONE,
            "the client did not end the run"
        );
    }
    out.data(&wire::le32(wire::NDX_DONE)).await?;
    let _ = out.wr.shutdown().await;
    ctx.state
        .update_connection_stats(
            ctx.server_id,
            id,
            Some(input.total),
            Some(out.total),
            None,
            None,
        )
        .await;

    let taken = received.iter().filter(|f| f["type"] == "file").count();
    Log::new(Some(&ctx.status_tx)).info(format!(
        "rsync connection {id}: upload to {module}/{dest}, {taken} file(s) taken, {} refused",
        refused.len() + failed.len()
    ));
    refused.extend(failed);
    let event = Event::new(
        &actions::UPLOAD_COMPLETE_EVENT,
        json!({
            "module": module,
            "path": dest,
            "files": received,
            "refused": refused.iter().map(|(p, r)| json!({"path": p, "reason": r})).collect::<Vec<_>>(),
            "client": client,
        }),
    );
    if let Err(e) = ask(ctx, id, event).await {
        decision(ctx, id, "upload_complete", "fail_closed_llm_error");
        Log::new(Some(&ctx.status_tx)).warn(format!("rsync upload_complete handler failed: {e:#}"));
    }
    Ok(())
}

async fn list_modules(
    ctx: &SpawnContext,
    id: ConnectionId,
    out: &mut Out,
    client: &str,
) -> Result<()> {
    let event = Event::new(&actions::LIST_MODULES_EVENT, json!({"client": client}));
    let mut listing = String::new();
    match ask(ctx, id, event).await {
        Ok(Some((name, data))) if name == actions::MODULES => {
            for m in data["modules"].as_array().into_iter().flatten() {
                let name = m["name"].as_str().unwrap_or_default();
                let comment =
                    crate::utils::sanitize::line_field(m["comment"].as_str().unwrap_or_default());
                listing.push_str(&format!("{name:<15}\t{comment}\n"));
            }
            decision(ctx, id, "list_modules", "model_answered");
        }
        Ok(_) => decision(ctx, id, "list_modules", "model_silent"),
        Err(e) => {
            decision(ctx, id, "list_modules", "fail_closed_llm_error");
            let text = crate::utils::wire_failure::wire_failure_text(&e);
            out.raw(format!("@ERROR: {text}\n").as_bytes()).await?;
            return Ok(());
        }
    }
    listing.push_str("@RSYNCD: EXIT\n");
    out.raw(listing.as_bytes()).await
}

/// Add the directories the model implied but did not list (a/b/c.txt implies a and a/b), and
/// keep one entry per path (the first).
/// Drop duplicate paths and add the directories the remaining paths imply.
pub fn complete_dirs(entries: &mut Vec<Entry>, now: u32) {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    entries.retain(|e| seen.insert(e.path.clone()));
    let mut add = Vec::new();
    for e in entries.iter() {
        let mut p = e.path.as_str();
        while let Some(i) = p.rfind('/') {
            p = &p[..i];
            if seen.insert(p.to_string()) {
                add.push(
                    wire::entry_from_json(&json!({"path": p, "type": "dir"}), now)
                        .expect("a valid dir"),
                );
            }
        }
    }
    entries.extend(add);
}

/// The entries to send (each with its top-dir flag), messages for the client, and whether a
/// requested path was missing.
type Selection = (Vec<(Entry, bool)>, Vec<(u8, String)>, bool);

/// What rsync's sender would list for each requested path (flist.c send_file_list): a
/// trailing-slash directory becomes "." plus its contents; a named file its basename; a named
/// directory itself (and, with -r, its subtree). Returns the list in rsync's order, messages
/// for the client, and whether anything requested was missing.
fn select(all: &[Entry], req: &Request, now: u32) -> Selection {
    let mut out: Vec<(Entry, bool)> = Vec::new();
    let mut notes = Vec::new();
    let mut missing = false;
    let find = |p: &str| all.iter().find(|e| e.path == p);
    let under = |dir: &str, deep: bool| -> Vec<Entry> {
        all.iter()
            .filter_map(|e| {
                let rel = if dir.is_empty() {
                    e.path.as_str()
                } else {
                    e.path.strip_prefix(&format!("{dir}/"))?
                };
                (deep || !rel.contains('/')).then(|| Entry {
                    path: rel.to_string(),
                    ..e.clone()
                })
            })
            .collect()
    };
    for path in &req.paths {
        let contents = path.is_empty() || path.ends_with('/');
        let base = path.trim_end_matches('/');
        if contents {
            let dir = if base.is_empty() {
                wire::entry_from_json(&json!({"path": "root", "type": "dir"}), now)
                    .expect("a valid dir")
            } else {
                match find(base) {
                    Some(e) if e.kind == Kind::Dir => e.clone(),
                    _ => {
                        missing = true;
                        notes.push((wire::MSG_ERROR_XFER, format!("rsync: [sender] change_dir \"{base}\" failed: No such file or directory (2)")));
                        continue;
                    }
                }
            };
            if !(req.recursive || req.dirs) {
                notes.push((wire::MSG_INFO, "skipping directory .".into()));
                continue;
            }
            out.push((
                Entry {
                    path: ".".into(),
                    ..dir
                },
                true,
            ));
            out.extend(under(base, req.recursive).into_iter().map(|e| (e, false)));
            continue;
        }
        let Some(e) = find(base) else {
            missing = true;
            notes.push((
                wire::MSG_ERROR_XFER,
                format!(
                    "rsync: [sender] link_stat \"{base}\" failed: No such file or directory (2)"
                ),
            ));
            continue;
        };
        let name = base.rsplit('/').next().unwrap_or(base).to_string();
        match e.kind {
            Kind::Dir if req.recursive => {
                out.push((
                    Entry {
                        path: name.clone(),
                        ..e.clone()
                    },
                    true,
                ));
                out.extend(under(base, true).into_iter().map(|c| {
                    (
                        Entry {
                            path: format!("{name}/{}", c.path),
                            ..c
                        },
                        false,
                    )
                }));
            }
            Kind::Dir if req.dirs => out.push((
                Entry {
                    path: name,
                    ..e.clone()
                },
                false,
            )),
            Kind::Dir => notes.push((wire::MSG_INFO, format!("skipping directory {name}"))),
            _ => out.push((
                Entry {
                    path: name,
                    ..e.clone()
                },
                false,
            )),
        }
    }
    out.sort_by_cached_key(|(e, _)| wire::sort_key(&e.path, e.is_dir()));
    out.dedup_by(|a, b| a.0.path == b.0.path);
    (out, notes, missing)
}

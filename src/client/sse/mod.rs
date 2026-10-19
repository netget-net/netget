//! Server-sent events client: an HTTP/1.1 GET held open, its body parsed as an event stream,
//! and EventSource's reconnects — the server's retry hint, Last-Event-ID, no reconnect after a
//! refusal. Each event goes to the handler, which may reconnect or stop.
pub mod actions;
use crate::client::llm_budget::call_llm_for_client_batch;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::metadata::MAX_BATCH_EVENTS;
use crate::protocol::{ConnectContext, Event};
use crate::server::sse::wire::Parser;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::SseClientProtocol;
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, ReadHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Reconnects a closed stream gets by itself.
pub const MAX_RECONNECTS: u64 = 5;
pub const MAX_RECONNECTS_LIMIT: u64 = 100;
/// The reconnect delay before the server names one (EventSource's usual 3 s).
pub const DEFAULT_RETRY: Duration = Duration::from_secs(3);
/// A server's retry hint is clamped to this range.
pub const MIN_RETRY: Duration = Duration::from_millis(100);
pub const MAX_RETRY: Duration = Duration::from_secs(60);
/// A response head at most, and how long it may take.
pub const MAX_HEAD_BYTES: usize = 32 * 1024;
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// A chunk-size line, or the line ending a chunk's data, at most. Once its first byte has
/// arrived it must be complete within `IO_TIMEOUT`.
pub const MAX_CHUNK_LINE_BYTES: usize = 1024;
/// Model-requested reconnects in a row (no event in between) before the chain is stopped.
pub const MAX_FOLLOWUP_DEPTH: usize = 8;

struct Target {
    url: String,
    host: String,
    port: u16,
    path: String,
}

fn target(remote: &str) -> Result<Target> {
    let url = if remote.contains("://") {
        remote.to_string()
    } else {
        format!("http://{remote}/")
    };
    let parsed = url::Url::parse(&url).context("remote_addr is an http:// URL or host:port")?;
    ensure!(
        parsed.scheme() == "http",
        "only http:// streams are supported (no TLS)"
    );
    let host = parsed
        .host_str()
        .context("the URL names no host")?
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);
    let mut path = parsed.path().to_string();
    if let Some(q) = parsed.query() {
        path.push('?');
        path.push_str(q);
    }
    Ok(Target {
        url: parsed.into(),
        host,
        port,
        path,
    })
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let target = target(&ctx.remote_addr)?;
    let p = ctx.startup_params.as_ref();
    let last_event_id = p
        .map(|p| p.get_optional_string("last_event_id"))
        .transpose()?
        .flatten()
        .unwrap_or_default();
    ensure!(
        !last_event_id.contains(['\r', '\n', '\0']),
        "last_event_id is one line"
    );
    let max_reconnects = p
        .map(|p| p.get_optional_u64("max_reconnects"))
        .transpose()?
        .flatten()
        .unwrap_or(MAX_RECONNECTS);
    ensure!(
        max_reconnects <= MAX_RECONNECTS_LIMIT,
        "max_reconnects is 0..={MAX_RECONNECTS_LIMIT}"
    );
    let first = tokio::time::timeout(
        IO_TIMEOUT,
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    .context("SSE connect deadline")??;
    let local = first.local_addr()?;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let result = session(
            &session_ctx,
            target,
            first,
            last_event_id,
            max_reconnects,
            external,
        )
        .await;
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx)).warn(format!("SSE client ended: {e:#}"));
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

async fn ask(ctx: &ConnectContext, event: &Event) -> Vec<Value> {
    ask_all(ctx, std::slice::from_ref(event)).await
}

/// Ask the handler about several events at once — one model call when the client batches.
async fn ask_all(ctx: &ConnectContext, events: &[Event]) -> Vec<Value> {
    let state = &ctx.state;
    let instruction = state
        .get_instruction_for_client(ctx.client_id)
        .await
        .unwrap_or_default();
    let memory = state
        .get_memory_for_client(ctx.client_id)
        .await
        .unwrap_or_default();
    match call_llm_for_client_batch(
        &ctx.llm_client,
        state,
        ctx.client_id.to_string(),
        &instruction,
        &memory,
        events,
        &SseClientProtocol,
        &ctx.status_tx,
    )
    .await
    {
        Ok(result) => {
            if let Some(memory) = result.memory_updates {
                state.set_memory_for_client(ctx.client_id, memory).await;
            }
            result.actions
        }
        Err(e) => {
            Log::new(Some(&ctx.status_tx)).warn(format!("SSE client handler: {e}"));
            Vec::new()
        }
    }
}

/// What a batch of actions asks for.
enum Next {
    Continue,
    Reconnect(Option<String>),
    Stop,
}

fn apply(ctx: &ConnectContext, actions: Vec<Value>) -> Next {
    let mut next = Next::Continue;
    for action in actions {
        match SseClientProtocol.execute_action(action) {
            Ok(ClientActionResult::Disconnect) => return Next::Stop,
            Ok(ClientActionResult::Custom { data, .. }) => {
                next = Next::Reconnect(data["last_event_id"].as_str().map(str::to_owned));
            }
            Ok(_) => {}
            Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!("SSE action refused: {e}")),
        }
    }
    next
}

/// An injected command: execute it, answer the caller, say what it asks for.
async fn command(ctx: &ConnectContext, c: ClientCommand) -> Next {
    let action = c.action.clone();
    let next = match SseClientProtocol.execute_action(action.clone()) {
        Ok(ClientActionResult::Disconnect) => {
            crate::client::command_support::reply(c, Ok(ClientSendOutcome::Disconnected));
            return Next::Stop;
        }
        Ok(ClientActionResult::Custom { data, .. }) => {
            crate::client::command_support::reply(
                c,
                Ok(ClientSendOutcome::Executed {
                    detail: "reconnecting".into(),
                }),
            );
            Next::Reconnect(data["last_event_id"].as_str().map(str::to_owned))
        }
        Ok(_) => {
            crate::client::command_support::reply(
                c,
                Ok(ClientSendOutcome::Executed {
                    detail: String::new(),
                }),
            );
            Next::Continue
        }
        Err(e) => {
            crate::client::command_support::reply(
                c,
                Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
            );
            Next::Continue
        }
    };
    ctx.state
        .record_access_log(
            AccessLogOwner::Client(ctx.client_id.as_u32()),
            "SSE",
            None,
            "injected_action",
            action,
            vec![json!({"accepted": true})],
        )
        .await;
    next
}

enum Body {
    Length(u64),
    Chunked(Chunked),
    UntilClose,
}

/// Where a chunked body is. Every field survives a `body_chunk` call that the stream's
/// `select!` cancels, so the next call resumes where that one stopped.
#[derive(Default)]
struct Chunked {
    /// Data bytes of the current chunk not yet read.
    remaining: u64,
    /// The last chunk (size 0) was read.
    done: bool,
    /// The current chunk's data was read and the line ending it was not.
    crlf_due: bool,
    /// The size or terminator line read so far.
    line: Vec<u8>,
    /// When the line being read must be complete.
    deadline: Option<tokio::time::Instant>,
}

struct Response {
    status: u16,
    content_type: String,
    body: Body,
}

/// Reads into `line` up to and including a `\n`, never holding more than `limit` bytes in it.
/// Bytes already in `line` count against the limit, so a read the caller abandoned continues.
/// Returns `false` when the connection closed before the line's first byte.
async fn read_line_bounded(
    r: &mut BufReader<ReadHalf<TcpStream>>,
    line: &mut Vec<u8>,
    limit: usize,
    what: &str,
) -> Result<bool> {
    let room = limit.saturating_sub(line.len()) as u64;
    let n = (&mut *r).take(room).read_until(b'\n', line).await?;
    if line.last() == Some(&b'\n') {
        return Ok(true);
    }
    if line.is_empty() && n == 0 {
        return Ok(false);
    }
    if line.len() >= limit {
        bail!("{what} over {limit} bytes with no line end");
    }
    bail!("the connection closed inside a {what}");
}

async fn read_head(r: &mut BufReader<ReadHalf<TcpStream>>) -> Result<Response> {
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    let mut head = Vec::new();
    loop {
        let start = head.len();
        ensure!(
            start < MAX_HEAD_BYTES,
            "response head over {MAX_HEAD_BYTES} bytes with no end"
        );
        let mut line = Vec::new();
        let complete = tokio::time::timeout_at(
            deadline,
            read_line_bounded(r, &mut line, MAX_HEAD_BYTES - start, "response head"),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "response head not complete within {}s",
                IO_TIMEOUT.as_secs()
            )
        })?
        .map_err(|e| {
            if line.len() >= MAX_HEAD_BYTES - start {
                anyhow!("response head over {MAX_HEAD_BYTES} bytes with no end")
            } else {
                e
            }
        })?;
        if !complete {
            ensure!(start > 0, "the connection closed before a response");
            bail!("the connection closed inside the response head");
        }
        head.extend_from_slice(&line);
        if line == b"\r\n" || line == b"\n" {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.lines();
    let status_line = lines.next().unwrap_or_default();
    ensure!(
        status_line.starts_with("HTTP/1."),
        "not an HTTP/1.x response: {status_line:?}"
    );
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("bad status line")?;
    let mut content_type = String::new();
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "content-type" => content_type = v.to_ascii_lowercase(),
            "content-length" => length = v.parse::<u64>().ok(),
            "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
            _ => {}
        }
    }
    let body = if chunked {
        Body::Chunked(Chunked::default())
    } else if let Some(n) = length {
        Body::Length(n)
    } else {
        Body::UntilClose
    };
    Ok(Response {
        status,
        content_type,
        body,
    })
}

/// The next piece of the body; `None` at its end.
async fn body_chunk(
    r: &mut BufReader<ReadHalf<TcpStream>>,
    body: &mut Body,
    buf: &mut [u8],
) -> Result<Option<usize>> {
    match body {
        Body::Length(0) => Ok(None),
        Body::Length(left) => {
            let want = (*left).min(buf.len() as u64) as usize;
            let n = r.read(&mut buf[..want]).await?;
            if n == 0 {
                return Ok(None);
            }
            *left -= n as u64;
            Ok(Some(n))
        }
        Body::UntilClose => {
            let n = r.read(buf).await?;
            Ok((n > 0).then_some(n))
        }
        Body::Chunked(c) => {
            if c.done {
                return Ok(None);
            }
            if c.crlf_due {
                if !chunk_line(r, c, "chunk terminator").await? {
                    bail!("the connection closed inside a chunk terminator");
                }
                ensure!(
                    c.line == b"\r\n" || c.line == b"\n",
                    "chunk data not followed by CRLF"
                );
                c.line.clear();
                c.crlf_due = false;
            }
            if c.remaining == 0 {
                // An idle stream waits here between chunks for as long as the server is quiet;
                // the line's deadline starts with its first byte.
                if c.line.is_empty() && r.fill_buf().await?.is_empty() {
                    return Ok(None);
                }
                if !chunk_line(r, c, "chunk-size line").await? {
                    return Ok(None);
                }
                let text = std::str::from_utf8(&c.line).context("chunk-size line is not text")?;
                let size = text.trim().split(';').next().unwrap_or_default().trim();
                let size = u64::from_str_radix(size, 16).context("bad chunk size")?;
                c.line.clear();
                if size == 0 {
                    c.done = true;
                    return Ok(None);
                }
                c.remaining = size;
            }
            let want = c.remaining.min(buf.len() as u64) as usize;
            let n = r.read(&mut buf[..want]).await?;
            if n == 0 {
                return Ok(None);
            }
            c.remaining -= n as u64;
            if c.remaining == 0 {
                // The data goes to the parser now; its CRLF is read at the next call, and is
                // due within IO_TIMEOUT from here.
                c.crlf_due = true;
                c.deadline = Some(tokio::time::Instant::now() + IO_TIMEOUT);
            }
            Ok(Some(n))
        }
    }
}

/// One line of a chunked body's framing, bounded by `MAX_CHUNK_LINE_BYTES` and by the line's
/// deadline (set when its first byte is due or has arrived). Returns `false` at a close before
/// the line's first byte.
async fn chunk_line(
    r: &mut BufReader<ReadHalf<TcpStream>>,
    c: &mut Chunked,
    what: &str,
) -> Result<bool> {
    let deadline = *c
        .deadline
        .get_or_insert_with(|| tokio::time::Instant::now() + IO_TIMEOUT);
    let complete = tokio::time::timeout_at(
        deadline,
        read_line_bounded(r, &mut c.line, MAX_CHUNK_LINE_BYTES, what),
    )
    .await
    .map_err(|_| anyhow!("{what} not complete within {}s", IO_TIMEOUT.as_secs()))??;
    c.deadline = None;
    Ok(complete)
}

/// Whether a body error is the transport failing (a reset, say), which EventSource answers by
/// reconnecting, rather than the server breaking HTTP framing, which is not retried.
fn is_transport_error(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>().is_some()
}

async fn session(
    ctx: &ConnectContext,
    target: Target,
    first: TcpStream,
    last_event_id: String,
    max_reconnects: u64,
    mut external: mpsc::Receiver<ClientCommand>,
) -> Result<()> {
    let mut parser = Parser::with_last_event_id(&last_event_id);
    let mut stream = Some(first);
    let mut attempt: u64 = 1;
    let mut reconnects_left = max_reconnects;
    let mut chained = 0usize;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let socket = match stream.take() {
            Some(s) => s,
            None => match tokio::time::timeout(
                IO_TIMEOUT,
                TcpStream::connect((target.host.as_str(), target.port)),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    let ev = json!({"reason": "error", "error": e.to_string()});
                    match wait_or_ask(ctx, ev, &mut external, &mut chained).await {
                        Next::Reconnect(id) => {
                            if let Some(id) = id {
                                parser.last_event_id = id;
                            }
                            attempt += 1;
                            continue;
                        }
                        _ => return Ok(()),
                    }
                }
                Err(_) => bail!("SSE reconnect deadline"),
            },
        };
        parser.reset_stream();
        let (reader, mut writer) = tokio::io::split(socket);
        let mut reader = BufReader::new(reader);
        let mut request = format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nAccept: text/event-stream\r\nCache-Control: no-cache\r\nUser-Agent: NetGet/{}\r\n",
            target.path,
            target.host,
            target.port,
            env!("CARGO_PKG_VERSION")
        );
        if !parser.last_event_id.is_empty() {
            request.push_str(&format!("Last-Event-ID: {}\r\n", parser.last_event_id));
        }
        request.push_str("\r\n");
        writer.write_all(request.as_bytes()).await?;
        let resp = match read_head(&mut reader).await {
            Ok(r) => r,
            Err(e) => {
                let ev = json!({"reason": "error", "error": format!("{e:#}")});
                match wait_or_ask(ctx, ev, &mut external, &mut chained).await {
                    Next::Reconnect(id) => {
                        if let Some(id) = id {
                            parser.last_event_id = id;
                        }
                        attempt += 1;
                        continue;
                    }
                    _ => return Ok(()),
                }
            }
        };
        let mut body = resp.body;
        if resp.status != 200 || !resp.content_type.starts_with("text/event-stream") {
            // EventSource fails the connection and does not reconnect.
            let mut text = Vec::new();
            while text.len() < 1024 {
                match tokio::time::timeout(IO_TIMEOUT, body_chunk(&mut reader, &mut body, &mut buf))
                    .await
                {
                    Ok(Ok(Some(n))) => text.extend_from_slice(&buf[..n]),
                    _ => break,
                }
            }
            text.truncate(1024);
            let ev = json!({"reason": "refused", "status": resp.status,
                "body": String::from_utf8_lossy(&text)});
            match wait_or_ask(ctx, ev, &mut external, &mut chained).await {
                Next::Reconnect(id) => {
                    if let Some(id) = id {
                        parser.last_event_id = id;
                    }
                    attempt += 1;
                    continue;
                }
                _ => return Ok(()),
            }
        }
        let connected = Event::new(
            &actions::CONNECTED_EVENT,
            json!({"url": target.url, "last_event_id": parser.last_event_id, "attempt": attempt}),
        );
        let mut next = apply(ctx, ask(ctx, &connected).await);
        let mut broken = None;
        // Events parsed and not yet answered. The body goes on being read while the model
        // answers, so what the server sends during a call is parsed into this queue rather
        // than left in the socket: with batching on everything waiting is answered in the next
        // call, with it off one event per call. Past `MAX_BATCH_EVENTS` waiting the body is not
        // read and TCP holds the server back.
        let mut waiting: VecDeque<Event> = VecDeque::new();
        let mut ended = false;
        // Read the stream until it ends or the handler or a command says otherwise.
        while matches!(next, Next::Continue) {
            if waiting.is_empty() {
                if ended {
                    break;
                }
                tokio::select! {
                    c = external.recv() => match c {
                        Some(c) => next = command(ctx, c).await,
                        None => next = Next::Stop,
                    },
                    piece = body_chunk(&mut reader, &mut body, &mut buf) => {
                        take_piece(piece, &buf, &mut parser, &mut waiting, &mut ended, &mut broken)?;
                    }
                }
                continue;
            }
            let batching = ctx
                .state
                .client_conversation_settings(ctx.client_id)
                .await
                .is_some_and(|(_, batching)| batching);
            let take = if batching {
                waiting.len().min(MAX_BATCH_EVENTS)
            } else {
                1
            };
            let batch: Vec<Event> = waiting.drain(..take).collect();
            chained = 0;
            let call = ask_all(ctx, &batch);
            tokio::pin!(call);
            let answer = loop {
                tokio::select! {
                    answer = &mut call => break answer,
                    piece = body_chunk(&mut reader, &mut body, &mut buf),
                        if !ended && waiting.len() < MAX_BATCH_EVENTS =>
                    {
                        take_piece(piece, &buf, &mut parser, &mut waiting, &mut ended, &mut broken)?;
                    }
                }
            };
            next = apply(ctx, answer);
        }
        drop(writer);
        match next {
            Next::Stop => return Ok(()),
            Next::Reconnect(id) => {
                chained += 1;
                if chained > MAX_FOLLOWUP_DEPTH {
                    Log::new(Some(&ctx.status_tx)).warn(format!(
                        "SSE handler asked to reconnect {MAX_FOLLOWUP_DEPTH} times without an event between; stopping"
                    ));
                    return Ok(());
                }
                if let Some(id) = id {
                    parser.last_event_id = id;
                }
                attempt += 1;
                continue;
            }
            Next::Continue => {}
        }
        if let Some(error) = broken {
            // Broken framing is the server's fault and is not retried by itself.
            let ev = json!({"reason": "error", "error": error});
            match wait_or_ask(ctx, ev, &mut external, &mut chained).await {
                Next::Reconnect(id) => {
                    if let Some(id) = id {
                        parser.last_event_id = id;
                    }
                    attempt += 1;
                    continue;
                }
                _ => return Ok(()),
            }
        }
        // The stream closed: EventSource reconnects after the retry delay.
        if reconnects_left == 0 {
            let ev = json!({"reason": "no_more_reconnects"});
            match wait_or_ask(ctx, ev, &mut external, &mut chained).await {
                Next::Reconnect(id) => {
                    if let Some(id) = id {
                        parser.last_event_id = id;
                    }
                    attempt += 1;
                    continue;
                }
                _ => return Ok(()),
            }
        }
        reconnects_left -= 1;
        let delay = parser
            .retry_ms
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_RETRY)
            .clamp(MIN_RETRY, MAX_RETRY);
        let ended = Event::new(
            &actions::ENDED_EVENT,
            json!({"reason": "closed", "reconnecting_in_ms": delay.as_millis() as u64}),
        );
        match apply(ctx, ask(ctx, &ended).await) {
            Next::Stop => return Ok(()),
            Next::Reconnect(id) => {
                if let Some(id) = id {
                    parser.last_event_id = id;
                }
            }
            Next::Continue => tokio::time::sleep(delay).await,
        }
        attempt += 1;
    }
}

/// One piece of the body: its events join `waiting`; its end, a transport failure or broken
/// framing ends the stream (`ended`), the last also saying why (`broken`). A malformed event
/// stream is an error for the session, as before.
fn take_piece(
    piece: Result<Option<usize>>,
    buf: &[u8],
    parser: &mut Parser,
    waiting: &mut VecDeque<Event>,
    ended: &mut bool,
    broken: &mut Option<String>,
) -> Result<()> {
    let n = match piece {
        Ok(Some(n)) => n,
        Ok(None) => {
            *ended = true;
            return Ok(());
        }
        Err(e) if is_transport_error(&e) => {
            *ended = true;
            return Ok(());
        }
        Err(e) => {
            *broken = Some(format!("{e:#}"));
            *ended = true;
            return Ok(());
        }
    };
    for ev in parser.feed(&buf[..n])? {
        waiting.push_back(Event::new(
            &actions::MESSAGE_EVENT,
            json!({"event": ev.event, "data": ev.data, "id": ev.last_event_id}),
        ));
    }
    Ok(())
}

/// A stream that will not be reopened by itself: tell the handler, then wait for it or a
/// command to say reconnect or stop.
async fn wait_or_ask(
    ctx: &ConnectContext,
    data: Value,
    external: &mut mpsc::Receiver<ClientCommand>,
    chained: &mut usize,
) -> Next {
    let ended = Event::new(&actions::ENDED_EVENT, data);
    match apply(ctx, ask(ctx, &ended).await) {
        Next::Reconnect(id) => {
            *chained += 1;
            if *chained > MAX_FOLLOWUP_DEPTH {
                return Next::Stop;
            }
            return Next::Reconnect(id);
        }
        Next::Stop => return Next::Stop,
        Next::Continue => {}
    }
    loop {
        match external.recv().await {
            Some(c) => match command(ctx, c).await {
                Next::Continue => continue,
                other => return other,
            },
            None => return Next::Stop,
        }
    }
}

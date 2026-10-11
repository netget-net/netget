//! Server-sent events client: an HTTP/1.1 GET held open, its body parsed as an event stream,
//! and EventSource's reconnects — the server's retry hint, Last-Event-ID, no reconnect after a
//! refusal. Each event goes to the handler, which may reconnect or stop.
pub mod actions;
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::sse::wire::Parser;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::SseClientProtocol;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
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
    let state = &ctx.state;
    let instruction = state
        .get_instruction_for_client(ctx.client_id)
        .await
        .unwrap_or_default();
    let memory = state
        .get_memory_for_client(ctx.client_id)
        .await
        .unwrap_or_default();
    match call_llm_for_client(
        &ctx.llm_client,
        state,
        ctx.client_id.to_string(),
        &instruction,
        &memory,
        Some(event),
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
    Chunked { remaining: u64, done: bool },
    UntilClose,
}

struct Response {
    status: u16,
    content_type: String,
    body: Body,
}

async fn read_head(r: &mut BufReader<ReadHalf<TcpStream>>) -> Result<Response> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let n = tokio::time::timeout(IO_TIMEOUT, r.read_until(b'\n', &mut line))
            .await
            .context("response head deadline")??;
        if n == 0 {
            bail!("the connection closed before a response");
        }
        head.extend_from_slice(&line);
        ensure!(
            head.len() <= MAX_HEAD_BYTES,
            "response head over {MAX_HEAD_BYTES} bytes"
        );
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
        Body::Chunked {
            remaining: 0,
            done: false,
        }
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
        Body::Chunked { remaining, done } => {
            if *done {
                return Ok(None);
            }
            if *remaining == 0 {
                let mut line = String::new();
                if r.read_line(&mut line).await? == 0 {
                    return Ok(None);
                }
                let size = line.trim().split(';').next().unwrap_or_default();
                let size = u64::from_str_radix(size.trim(), 16).context("bad chunk size")?;
                if size == 0 {
                    *done = true;
                    return Ok(None);
                }
                *remaining = size;
            }
            let want = (*remaining).min(buf.len() as u64) as usize;
            let n = r.read(&mut buf[..want]).await?;
            if n == 0 {
                return Ok(None);
            }
            *remaining -= n as u64;
            if *remaining == 0 {
                let mut crlf = String::new();
                r.read_line(&mut crlf).await?;
            }
            Ok(Some(n))
        }
    }
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
        // Read the stream until it ends or the handler or a command says otherwise.
        while matches!(next, Next::Continue) {
            tokio::select! {
                c = external.recv() => match c {
                    Some(c) => next = command(ctx, c).await,
                    None => next = Next::Stop,
                },
                piece = body_chunk(&mut reader, &mut body, &mut buf) => {
                    let n = match piece {
                        Ok(Some(n)) => n,
                        Ok(None) | Err(_) => break,
                    };
                    for ev in parser.feed(&buf[..n])? {
                        chained = 0;
                        let event = Event::new(
                            &actions::MESSAGE_EVENT,
                            json!({"event": ev.event, "data": ev.data, "id": ev.last_event_id}),
                        );
                        next = apply(ctx, ask(ctx, &event).await);
                        if !matches!(next, Next::Continue) {
                            break;
                        }
                    }
                }
            }
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

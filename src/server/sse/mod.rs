//! Server-sent events server. Each connection carries one HTTP/1.1 request; the model answers
//! it with a stream (kept open, with keep-alive comments) or an ordinary response. Open streams
//! are registered per server for `sse_broadcast` and as peers for injected events.
pub mod actions;
pub mod wire;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS};
use crate::server::connection::ConnectionId;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use anyhow::Result;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify};

/// A request head at most.
pub const MAX_REQUEST_HEAD_BYTES: usize = 16 * 1024;
/// How long a request head may take to arrive.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_KEEPALIVE_SECS: u64 = 3600;
/// How long one write to a connection may make no progress, and how long a broadcast, an
/// injected event or a keepalive may take to reach one open stream (waiting for its writer
/// included). A stream that misses it is dropped: removed from the broadcast table, its write
/// side shut down, its connection ended.
pub const SUBSCRIBER_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

type Writer = Arc<Mutex<StreamWriter>>;

/// Marks a stream that missed `SUBSCRIBER_WRITE_TIMEOUT`. Every later write to it fails at once,
/// and its connection task, waiting on `notify`, ends the connection.
#[derive(Default)]
struct Stall {
    tripped: AtomicBool,
    notify: Notify,
}

impl Stall {
    fn trip(&self) {
        if !self.tripped.swap(true, Ordering::SeqCst) {
            self.notify.notify_one();
        }
    }

    fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }
}

fn stalled_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!(
            "the peer took no bytes for {}s",
            SUBSCRIBER_WRITE_TIMEOUT.as_secs()
        ),
    )
}

/// A connection's write half that fails a write making no progress for
/// `SUBSCRIBER_WRITE_TIMEOUT` and trips the connection's `Stall`. Every writer of the
/// connection goes through it — the request's own answer, broadcasts, keepalives and the
/// generic peer-command task that writes injected events — so a peer that stops reading holds
/// none of them longer than that.
pub struct StreamWriter {
    inner: WriteHalf<TcpStream>,
    stall: Arc<Stall>,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl StreamWriter {
    fn guard<T>(
        &mut self,
        cx: &mut Context<'_>,
        poll: Poll<std::io::Result<T>>,
    ) -> Poll<std::io::Result<T>> {
        match poll {
            Poll::Ready(r) => {
                self.deadline = None;
                Poll::Ready(r)
            }
            Poll::Pending => {
                let sleep = self
                    .deadline
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(SUBSCRIBER_WRITE_TIMEOUT)));
                if sleep.as_mut().poll(cx).is_ready() {
                    self.deadline = None;
                    self.stall.trip();
                    return Poll::Ready(Err(stalled_error()));
                }
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for StreamWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.stall.is_tripped() {
            return Poll::Ready(Err(stalled_error()));
        }
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.guard(cx, poll)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.stall.is_tripped() {
            return Poll::Ready(Err(stalled_error()));
        }
        let poll = Pin::new(&mut this.inner).poll_flush(cx);
        this.guard(cx, poll)
    }

    /// Passes through even on a tripped stream: shutting the write side is how one is ended.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_shutdown(cx);
        this.guard(cx, poll)
    }
}

struct Subscriber {
    path: String,
    writer: Writer,
    stall: Arc<Stall>,
}

/// Writes `bytes` to one stream within `SUBSCRIBER_WRITE_TIMEOUT`, waiting for its writer
/// included. `false` means the stream missed it or failed; the caller drops it.
async fn deliver(writer: &Writer, bytes: &[u8]) -> bool {
    let write = async {
        let mut w = writer.lock().await;
        w.write_all(bytes).await?;
        w.flush().await
    };
    matches!(
        tokio::time::timeout(SUBSCRIBER_WRITE_TIMEOUT, write).await,
        Ok(Ok(()))
    )
}

/// Shuts a dropped stream's write side, bounded like any other write to it.
async fn shut(writer: &Writer) {
    let _ = tokio::time::timeout(SUBSCRIBER_WRITE_TIMEOUT, async {
        writer.lock().await.shutdown().await
    })
    .await;
}

/// Every open stream of every running SSE server, by the server's bound address (unique among
/// running servers in a process, where server ids are not: each `AppState` counts its own) and
/// connection.
static HUBS: LazyLock<std::sync::Mutex<HashMap<SocketAddr, Arc<Mutex<HashMap<u32, Subscriber>>>>>> =
    LazyLock::new(Default::default);

fn hub(server: SocketAddr) -> Arc<Mutex<HashMap<u32, Subscriber>>> {
    HUBS.lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(server)
        .or_default()
        .clone()
}

/// Removes a server's subscriber table when its accept loop ends (stop_server aborts it).
struct HubGuard(SocketAddr);
impl Drop for HubGuard {
    fn drop(&mut self) {
        HUBS.lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

/// Send already-encoded event bytes to every open stream of a server (optionally one path),
/// to all of them at once. Returns how many streams took them. A stream that misses
/// `SUBSCRIBER_WRITE_TIMEOUT` or fails is removed from the table here and its connection
/// ended, so one peer that stops reading costs a broadcast at most that long and the others
/// still get it.
pub async fn broadcast(
    state: &crate::state::app_state::AppState,
    server_id: crate::state::ServerId,
    path: Option<&str>,
    bytes: &[u8],
) -> usize {
    let Some(addr) = state.get_server(server_id).await.and_then(|s| s.local_addr) else {
        return 0;
    };
    let hub = hub(addr);
    let targets: Vec<(u32, Writer, Arc<Stall>)> = {
        let subs = hub.lock().await;
        subs.iter()
            .filter(|(_, s)| path.is_none_or(|p| s.path == p))
            .map(|(id, s)| (*id, s.writer.clone(), s.stall.clone()))
            .collect()
    };
    let results =
        futures::future::join_all(targets.into_iter().map(|(id, writer, stall)| async move {
            let ok = deliver(&writer, bytes).await;
            (id, ok, stall)
        }))
        .await;
    let mut delivered = 0;
    for (id, ok, stall) in results {
        if ok {
            delivered += 1;
        } else {
            hub.lock().await.remove(&id);
            stall.trip();
            tracing::warn!("SSE stream {id} dropped: a broadcast did not reach it");
        }
    }
    delivered
}

fn keepalive(ctx: &SpawnContext) -> Result<Duration> {
    let secs = ctx
        .startup_params
        .as_ref()
        .map(|p| p.get_optional_u64("keepalive_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(actions::KEEPALIVE_SECS);
    anyhow::ensure!(
        (1..=MAX_KEEPALIVE_SECS).contains(&secs),
        "keepalive_secs must be 1..={MAX_KEEPALIVE_SECS}"
    );
    Ok(Duration::from_secs(secs))
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let keepalive = keepalive(&ctx)?;
    let listener = TcpListener::bind(ctx.legacy_listen_addr()).await?;
    let addr = listener.local_addr()?;
    Log::new(Some(&ctx.status_tx)).info(format!("SSE server listening on {addr}"));
    let state = ctx.state.clone();
    let server_id = ctx.server_id;
    let accept = tokio::spawn(async move {
        let _hub = HubGuard(addr);
        let limiter = ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
        loop {
            let (socket, peer, permit) = match accept_bounded(
                &listener,
                &limiter,
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "SSE",
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
            let _ = ctx.status_tx.send("__UPDATE_UI__".into());
            let child = ctx.clone();
            ctx.state
                .spawn_server_task(server_id, async move {
                    let _permit = permit;
                    if let Err(e) = connection(&child, addr, id, socket, peer, keepalive).await {
                        Log::new(Some(&child.status_tx))
                            .debug(format!("SSE connection {id} ended: {e}"));
                    }
                    hub(addr).lock().await.remove(&id.as_u32());
                    child.state.close_connection_on_server(server_id, id).await;
                    let _ = child.status_tx.send("__UPDATE_UI__".into());
                })
                .await;
        }
    });
    state.register_server_task(server_id, accept).await;
    Ok(addr)
}

struct Request {
    method: String,
    path: String,
    query: Map<String, Value>,
    headers: HashMap<String, String>,
}

fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_head(head: &[u8]) -> Option<Request> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_string();
    let target = first.next()?;
    if !first.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.into_owned(), Value::String(v.into_owned())))
        .collect();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Some(Request {
        method,
        path: path.to_string(),
        query,
        headers,
    })
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn response(status: u16, content_type: &str, body: &[u8], extra: &str) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
        status_text(status),
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn outcome(ctx: &SpawnContext, id: ConnectionId, path: &str, decision: &str) {
    let line = format!("SSE connection {id} path={path} decision={decision}");
    if decision.starts_with("fail_closed") {
        tracing::warn!("{line}");
    } else {
        tracing::info!("{line}");
    }
    let _ = ctx.status_tx.send(format!("[INFO] {line}"));
}

/// What the model's answer says to do with the request.
#[derive(Default)]
struct Answer {
    accept: bool,
    retry_ms: Option<u64>,
    respond: Option<Value>,
    stream: Vec<u8>,
    close: bool,
}

fn collect(results: Vec<ActionResult>, answer: &mut Answer) {
    for r in results {
        match r {
            ActionResult::Output(bytes) => answer.stream.extend_from_slice(&bytes),
            ActionResult::CloseConnection => answer.close = true,
            ActionResult::Multiple(items) => collect(items, answer),
            ActionResult::Custom { name, data } if name == actions::ACCEPT => {
                answer.accept = true;
                answer.retry_ms = data["retry_ms"].as_u64();
            }
            ActionResult::Custom { name, data } if name == actions::RESPOND => {
                answer.respond.get_or_insert(data);
            }
            _ => {}
        }
    }
}

async fn connection(
    ctx: &SpawnContext,
    addr: SocketAddr,
    id: ConnectionId,
    socket: TcpStream,
    peer: SocketAddr,
    keepalive: Duration,
) -> Result<()> {
    let (mut reader, writer) = tokio::io::split(socket);
    let stall = Arc::new(Stall::default());
    let writer: Writer = Arc::new(Mutex::new(StreamWriter {
        inner: writer,
        stall: stall.clone(),
        deadline: None,
    }));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + HEAD_TIMEOUT;
    let head_len = loop {
        if let Some(n) = head_end(&buf) {
            break n;
        }
        if buf.len() > MAX_REQUEST_HEAD_BYTES {
            outcome(ctx, id, "", "fail_closed_head_too_large");
            let mut w = writer.lock().await;
            w.write_all(&response(431, "text/plain", b"", "")).await?;
            return Ok(());
        }
        let want = (MAX_REQUEST_HEAD_BYTES + 1 - buf.len()).min(chunk.len());
        let n = match tokio::time::timeout_at(deadline, reader.read(&mut chunk[..want])).await {
            Ok(r) => r?,
            Err(_) => anyhow::bail!(
                "request head not complete within {}s",
                HEAD_TIMEOUT.as_secs()
            ),
        };
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    ctx.state
        .update_connection_stats(
            ctx.server_id,
            id,
            Some(buf.len() as u64),
            None,
            Some(1),
            None,
        )
        .await;
    let Some(req) = parse_head(&buf[..head_len]) else {
        outcome(ctx, id, "", "fail_closed_bad_request");
        writer
            .lock()
            .await
            .write_all(&response(400, "text/plain", b"", ""))
            .await?;
        return Ok(());
    };
    if req.method != "GET" && req.method != "HEAD" {
        outcome(ctx, id, &req.path, "fail_closed_method");
        writer
            .lock()
            .await
            .write_all(&response(405, "text/plain", b"", "Allow: GET, HEAD\r\n"))
            .await?;
        return Ok(());
    }
    let declares_body = req
        .headers
        .get("content-length")
        .is_some_and(|l| l.trim() != "0")
        || req.headers.contains_key("transfer-encoding");
    if declares_body {
        outcome(ctx, id, &req.path, "fail_closed_body_not_accepted");
        writer
            .lock()
            .await
            .write_all(&response(413, "text/plain", b"", ""))
            .await?;
        return Ok(());
    }
    let h = |k: &str| req.headers.get(k).cloned().unwrap_or_default();
    let event = Event::new(
        &actions::REQUEST_EVENT,
        json!({
            "method": req.method, "path": req.path, "query": req.query,
            "last_event_id": h("last-event-id"), "accept": h("accept"),
            "user_agent": h("user-agent"), "client_ip": peer.ip().to_string(),
        }),
    );
    let protocol = Arc::new(actions::SseProtocol);
    let mut answer = Answer::default();
    match call_llm(
        &ctx.llm_client,
        &ctx.state,
        ctx.server_id,
        Some(id),
        &event,
        protocol.as_ref(),
    )
    .await
    {
        Ok(r) => collect(r.protocol_results, &mut answer),
        Err(e) => {
            outcome(ctx, id, &req.path, "fail_closed_llm_error");
            let text = crate::utils::wire_failure::wire_failure_text(&e);
            writer
                .lock()
                .await
                .write_all(&response(
                    503,
                    "text/plain; charset=utf-8",
                    text.as_bytes(),
                    "Retry-After: 5\r\n",
                ))
                .await?;
            return Ok(());
        }
    }
    let mut w = writer.lock().await;
    if let Some(r) = answer.respond {
        outcome(ctx, id, &req.path, "model_respond");
        let status = r["status"].as_u64().unwrap_or(500) as u16;
        let body = r["body"].as_str().unwrap_or_default();
        let ct = r["content_type"]
            .as_str()
            .unwrap_or("text/plain; charset=utf-8");
        let mut bytes = response(status, ct, body.as_bytes(), "");
        if req.method == "HEAD" {
            bytes.truncate(bytes.len() - body.len());
        }
        w.write_all(&bytes).await?;
        return Ok(());
    }
    if !answer.accept && answer.stream.is_empty() {
        // An EventSource stops reconnecting on 204; nothing else says "no stream" as plainly.
        outcome(ctx, id, &req.path, "model_silent");
        w.write_all(&response(204, "text/plain", b"", "")).await?;
        return Ok(());
    }
    outcome(ctx, id, &req.path, "model_stream");
    let mut first = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\n\r\n".to_vec();
    if req.method == "HEAD" {
        w.write_all(&first).await?;
        return Ok(());
    }
    if let Some(retry) = answer.retry_ms {
        first.extend_from_slice(&wire::encode_retry(retry));
    }
    first.extend_from_slice(&answer.stream);
    if !answer.close {
        // Registered while this stream's writer is held, so a broadcast or an injected event
        // that races the first write waits for it instead of going missing or ahead of it.
        hub(addr).lock().await.insert(
            id.as_u32(),
            Subscriber {
                path: req.path.clone(),
                writer: writer.clone(),
                stall: stall.clone(),
            },
        );
        let commands = crate::server::peer_support::register_peer_channel(
            &ctx.state,
            ctx.server_id,
            id.as_u32(),
        )
        .await;
        crate::server::peer_support::spawn_peer_command_task(
            commands,
            protocol,
            ctx.state.clone(),
            ctx.server_id,
            id.as_u32(),
            writer.clone(),
            ctx.status_tx.clone(),
        );
    }
    w.write_all(&first).await?;
    w.flush().await?;
    ctx.state
        .update_connection_stats(
            ctx.server_id,
            id,
            None,
            Some(first.len() as u64),
            None,
            Some(1),
        )
        .await;
    if answer.close {
        let _ = w.shutdown().await;
        return Ok(());
    }
    drop(w);
    let _ = ctx.status_tx.send("__UPDATE_UI__".into());
    let mut tick = tokio::time::interval(keepalive);
    tick.tick().await;
    loop {
        tokio::select! {
            read = reader.read(&mut chunk) => {
                // A client says nothing more on an event stream; EOF or an error ends it.
                match read {
                    Ok(0) | Err(_) => return Ok(()),
                    Ok(_) => {}
                }
            }
            _ = stall.notify.notified() => {
                outcome(ctx, id, &req.path, "fail_closed_subscriber_stalled");
                hub(addr).lock().await.remove(&id.as_u32());
                shut(&writer).await;
                return Ok(());
            }
            _ = tick.tick() => {
                if !deliver(&writer, b": keepalive\n\n").await {
                    // Ended by the stall branch on the next turn, like any other missed write.
                    stall.trip();
                }
            }
        }
    }
}

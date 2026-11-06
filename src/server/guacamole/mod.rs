//! Guacamole protocol server in guacd's place. Rust runs the handshake, frames every
//! instruction, answers sync and keeps the connection alive; the model accepts or refuses
//! each connection and draws the display it shows, hearing typed lines, special keys,
//! clicks and the client's clipboard.
pub mod actions;
pub mod wire;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, EventType, SpawnContext};
use crate::server::{
    accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS},
    connection::ConnectionId,
};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use wire::Instruction;

/// The handshake, select to connect, must finish within this.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// A `sync` is sent this often, so a client's 15-second read timeout never fires.
pub const KEEPALIVE: Duration = Duration::from_secs(5);
/// A session the client says nothing on for this long is closed.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Characters of a typed line kept before Enter.
pub const MAX_LINE: usize = 4096;
/// Handshake instructions accepted between select and connect.
pub const MAX_HANDSHAKE_INSTRUCTIONS: usize = 16;
/// Streams a client may have open at once (clipboard).
pub const MAX_STREAMS: usize = 16;

fn secret(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["password", "passphrase", "private-key", "secret", "token"]
        .iter()
        .any(|s| n.contains(s))
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let parameters: Vec<String> = match ctx
        .startup_params
        .as_ref()
        .map(|p| p.get_optional_array("parameters"))
        .transpose()?
        .flatten()
    {
        Some(list) => list
            .iter()
            .map(|v| {
                v.as_str()
                    .filter(|s| !s.is_empty() && s.len() <= 64)
                    .map(str::to_string)
                    .context("parameters must be short names")
            })
            .collect::<Result<_>>()?,
        None => actions::DEFAULT_PARAMETERS
            .iter()
            .map(|s| s.to_string())
            .collect(),
    };
    let listener = tokio::net::TcpListener::bind(ctx.legacy_listen_addr()).await?;
    let local = listener.local_addr()?;
    Log::new(Some(&ctx.status_tx)).info(format!("Guacamole server listening on {local}"));
    let server_id = ctx.server_id;
    let state = ctx.state.clone();
    let accept = tokio::spawn(async move {
        let limiter = ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
        loop {
            let (stream, peer, permit) =
                match accept_bounded(&listener, &limiter, b"", "Guacamole", Some(&ctx.status_tx))
                    .await
                {
                    Ok(v) => v,
                    Err(_) => break,
                };
            let child = ctx.clone();
            let parameters = parameters.clone();
            ctx.state
                .spawn_server_task(server_id, async move {
                    let _permit = permit;
                    connection(child, stream, peer, local, parameters).await;
                })
                .await;
        }
    });
    state.register_server_task(server_id, accept).await;
    Ok(local)
}

fn now_ms() -> String {
    crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_else(|_| "0".into())
}

fn connection_id() -> String {
    let v: u128 = rand::random();
    let h = format!("{v:032x}");
    format!(
        "${}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// The display a session shows, as far as drawing needs to know it.
struct Display {
    id: String,
    width: u32,
    height: u32,
    next_stream: u32,
}

async fn connection(
    ctx: SpawnContext,
    tcp: TcpStream,
    remote: SocketAddr,
    local: SocketAddr,
    parameters: Vec<String>,
) {
    let log = Log::new(Some(&ctx.status_tx));
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
                protocol_info: ProtocolConnectionInfo::empty(),
            },
        )
        .await;
    let (r, mut w) = tcp.into_split();
    let mut reader = wire::Reader::new(r);
    let reason = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake(&mut reader, &mut w, &parameters),
    )
    .await
    {
        Err(_) => "handshake timed out".to_string(),
        Ok(Err(e)) => format!("handshake refused: {e:#}"),
        Ok(Ok(hello)) => session(&ctx, id, reader, w, hello).await,
    };
    ctx.state
        .update_connection_status(ctx.server_id, id, ConnectionStatus::Closed)
        .await;
    ctx.state
        .remove_peer_handle(ctx.server_id, id.as_u32())
        .await;
    log.info(format!("Guacamole connection {id} ended: {reason}"));
    let _ = ctx.status_tx.send("__UPDATE_UI__".into());
}

/// What the client said before `connect`.
struct Hello {
    data: Value,
    width: u32,
    height: u32,
}

async fn handshake(
    reader: &mut wire::Reader<tokio::net::tcp::OwnedReadHalf>,
    w: &mut tokio::net::tcp::OwnedWriteHalf,
    parameters: &[String],
) -> Result<Hello> {
    let select = reader.next().await?.context("closed before select")?;
    if select.opcode != "select" {
        bail!("expected select, got {}", select.opcode);
    }
    let protocol = select.arg(0).to_string();
    if protocol.starts_with('$') {
        w.write_all(
            wire::encode(
                "error",
                &[
                    "Joining a connection is not supported",
                    &wire::STATUS_CLIENT_FORBIDDEN.to_string(),
                ],
            )
            .as_bytes(),
        )
        .await?;
        bail!("client asked to join {protocol}");
    }
    let mut args: Vec<&str> = vec![wire::VERSION];
    args.extend(parameters.iter().map(String::as_str));
    w.write_all(wire::encode("args", &args).as_bytes()).await?;
    let (mut width, mut height, mut dpi) = (1024u32, 768u32, 96u32);
    let mut images: Vec<String> = Vec::new();
    let mut timezone = None;
    for _ in 0..MAX_HANDSHAKE_INSTRUCTIONS {
        let ins = reader
            .next()
            .await?
            .context("closed during the handshake")?;
        match ins.opcode.as_str() {
            "size" => {
                width = ins.arg(0).parse().unwrap_or(width).clamp(1, 8192);
                height = ins.arg(1).parse().unwrap_or(height).clamp(1, 8192);
                dpi = ins.arg(2).parse().unwrap_or(dpi);
            }
            "image" => images = ins.args.clone(),
            "timezone" => timezone = Some(ins.arg(0).to_string()),
            "connect" => {
                // A client speaking 1.1+ answers the version first; an older one does not.
                let values: Vec<&String> = if ins.arg(0).starts_with("VERSION_")
                    || ins.args.len() == parameters.len() + 1
                {
                    ins.args.iter().skip(1).collect()
                } else {
                    ins.args.iter().collect()
                };
                let mut shown = Map::new();
                let mut secrets = Vec::new();
                for (name, value) in parameters.iter().zip(values) {
                    if value.is_empty() {
                        continue;
                    }
                    if secret(name) {
                        secrets.push(name.clone());
                    } else {
                        shown.insert(name.clone(), json!(value));
                    }
                }
                return Ok(Hello {
                    data: json!({"protocol": protocol, "arguments": shown, "secret_arguments": secrets,
                                 "width": width, "height": height, "dpi": dpi,
                                 "image_types": images, "timezone": timezone}),
                    width,
                    height,
                });
            }
            // audio, video, name and anything newer: noted by nobody.
            _ => {}
        }
    }
    bail!("no connect within {MAX_HANDSHAKE_INSTRUCTIONS} handshake instructions")
}

fn outcome(ctx: &SpawnContext, id: ConnectionId, op: &str, decision: &str) {
    let line = format!("Guacamole connection {id} operation={op} decision={decision}");
    let log = Log::new(Some(&ctx.status_tx));
    if decision.starts_with("fail_closed") || decision == "model_silent" {
        log.error(line)
    } else {
        log.info(line)
    }
}

/// The model's actions for an event, or None when it failed.
async fn ask(
    ctx: &SpawnContext,
    id: ConnectionId,
    event_type: &'static EventType,
    data: Value,
) -> Option<Vec<Value>> {
    let op = event_type.id.clone();
    let event = Event::new(event_type, data);
    match call_llm(
        &ctx.llm_client,
        &ctx.state,
        ctx.server_id,
        Some(id),
        &event,
        &actions::GuacamoleProtocol,
    )
    .await
    {
        Ok(r) if r.failures.is_empty() => {
            let mut out = Vec::new();
            let mut stack = r.protocol_results;
            while let Some(x) = stack.pop() {
                match x {
                    ActionResult::Custom { data, .. } => out.push(data),
                    ActionResult::Multiple(items) => stack.extend(items),
                    _ => {}
                }
            }
            out.reverse();
            outcome(
                ctx,
                id,
                &op,
                if out.is_empty() {
                    "model_silent"
                } else {
                    "model_answer"
                },
            );
            Some(out)
        }
        Ok(_) => {
            outcome(ctx, id, &op, "fail_closed_invalid_reply");
            None
        }
        Err(_) => {
            outcome(ctx, id, &op, "fail_closed_llm_error");
            None
        }
    }
}

/// The instructions one drawing action becomes; `Ok(true)` asks to end the session.
fn draw(d: &mut Display, a: &Value, out: &mut String) -> Result<bool> {
    let n = |k: &str, default: u32| a[k].as_u64().map(|v| v as u32).unwrap_or(default);
    match a["type"].as_str().unwrap_or_default() {
        actions::FILL => {
            let [r, g, b] = wire::color(a["color"].as_str().unwrap_or("#000000"))?;
            let (x, y) = (n("x", 0), n("y", 0));
            let w = n("width", d.width.saturating_sub(x));
            let h = n("height", d.height.saturating_sub(y));
            out.push_str(&wire::encode(
                "rect",
                &[
                    "0",
                    &x.to_string(),
                    &y.to_string(),
                    &w.to_string(),
                    &h.to_string(),
                ],
            ));
            out.push_str(&wire::encode(
                "cfill",
                &[
                    "14",
                    "0",
                    &r.to_string(),
                    &g.to_string(),
                    &b.to_string(),
                    "255",
                ],
            ));
        }
        actions::TEXT => {
            let fg = wire::color(a["color"].as_str().unwrap_or("#ffffff"))?;
            let bg = a["background"].as_str().map(wire::color).transpose()?;
            let (png, _, _) = wire::render_text(
                a["text"].as_str().unwrap_or_default(),
                fg,
                bg,
                n("scale", 2).clamp(1, 8),
            )?;
            let stream = d.next_stream.to_string();
            d.next_stream += 1;
            out.push_str(&wire::encode(
                "img",
                &[
                    &stream,
                    "14",
                    "0",
                    "image/png",
                    &n("x", 0).to_string(),
                    &n("y", 0).to_string(),
                ],
            ));
            out.push_str(&wire::blobs(&stream, &png));
            out.push_str(&wire::encode("end", &[&stream]));
        }
        actions::CLIPBOARD => {
            let stream = d.next_stream.to_string();
            d.next_stream += 1;
            out.push_str(&wire::encode("clipboard", &[&stream, "text/plain"]));
            out.push_str(&wire::blobs(
                &stream,
                a["text"].as_str().unwrap_or_default().as_bytes(),
            ));
            out.push_str(&wire::encode("end", &[&stream]));
        }
        actions::DISCONNECT => {
            if let Some(m) = a["message"].as_str() {
                out.push_str(&wire::encode("error", &[m, "0"]));
            }
            out.push_str(&wire::encode("disconnect", &[]));
            return Ok(true);
        }
        // accept/reject only mean something on connect.
        _ => {}
    }
    Ok(false)
}

/// Draw a batch and end it with a sync; whether the session should end.
fn frame(d: &mut Display, batch: &[Value], log: &Log) -> (String, bool) {
    let mut out = String::new();
    let mut end = false;
    for a in batch {
        match draw(d, a, &mut out) {
            Ok(e) => end |= e,
            Err(e) => log.warn(format!("Guacamole: {} not drawn: {e:#}", a["type"])),
        }
    }
    if !out.is_empty() {
        out.push_str(&wire::encode("sync", &[&now_ms()]));
    }
    (out, end)
}

async fn session(
    ctx: &SpawnContext,
    id: ConnectionId,
    mut reader: wire::Reader<tokio::net::tcp::OwnedReadHalf>,
    mut w: tokio::net::tcp::OwnedWriteHalf,
    hello: Hello,
) -> String {
    let log = Log::new(Some(&ctx.status_tx));
    let Some(first) = ask(ctx, id, &actions::CONNECT_EVENT, hello.data.clone()).await else {
        let _ = w
            .write_all(
                wire::encode(
                    "error",
                    &["Internal error", &wire::STATUS_SERVER_ERROR.to_string()],
                )
                .as_bytes(),
            )
            .await;
        return "refused: the handler failed".into();
    };
    if let Some(r) = first.iter().find(|a| a["type"] == actions::REJECT) {
        let msg = r["message"].as_str().unwrap_or("Refused");
        let _ = w
            .write_all(
                wire::encode(
                    "error",
                    &[msg, &wire::STATUS_CLIENT_UNAUTHORIZED.to_string()],
                )
                .as_bytes(),
            )
            .await;
        return format!("rejected: {msg}");
    }
    if !first.iter().any(|a| a["type"] == actions::ACCEPT) {
        let _ = w
            .write_all(
                wire::encode(
                    "error",
                    &["Internal error", &wire::STATUS_SERVER_ERROR.to_string()],
                )
                .as_bytes(),
            )
            .await;
        return "refused: the handler neither accepted nor rejected".into();
    }
    let mut d = Display {
        id: connection_id(),
        width: hello.width,
        height: hello.height,
        next_stream: 1,
    };
    let mut out = wire::encode("ready", &[&d.id]);
    out.push_str(&wire::encode(
        "size",
        &["0", &d.width.to_string(), &d.height.to_string()],
    ));
    let (drawn, end) = frame(&mut d, &first, &log);
    out.push_str(&drawn);
    if drawn.is_empty() {
        out.push_str(&wire::encode("sync", &[&now_ms()]));
    }

    // One writer, fed by the session and by a keepalive, so a slow model never starves it.
    // Bounded: every `clipboard` and `blob` instruction is acknowledged at once, so a client
    // that sends without reading is cut off rather than queued for (`utils::outbox`).
    let (tx, mut rx) = crate::utils::outbox::channel(
        format!("Guacamole connection {id}"),
        crate::utils::outbox::OutboxLimits::DEFAULT,
        String::len,
    );
    let _ = tx.send(out);
    let writer_ctx = ctx.clone();
    ctx.state
        .spawn_server_task(ctx.server_id, async move {
            let mut tick = tokio::time::interval(KEEPALIVE);
            tick.tick().await;
            loop {
                tokio::select! {
                    msg = rx.recv() => match msg {
                        Some(m) => {
                            if w.write_all(m.as_bytes()).await.is_err() { break; }
                            writer_ctx.state.update_connection_stats(writer_ctx.server_id, id, None, Some(m.len() as u64), None, Some(1)).await;
                        }
                        None => break,
                    },
                    _ = tick.tick() => {
                        if w.write_all(wire::encode("sync", &[&now_ms()]).as_bytes()).await.is_err() { break; }
                    }
                }
            }
            let _ = w.shutdown().await;
        })
        .await;
    if end {
        return "the handler ended it".into();
    }
    let mut peer_rx =
        crate::server::peer_support::register_peer_channel(&ctx.state, ctx.server_id, id.as_u32())
            .await;

    let mut line = String::new();
    let mut mask = 0u32;
    let mut streams: HashMap<String, Vec<u8>> = HashMap::new();
    loop {
        let event: Option<(&'static EventType, Value)> = tokio::select! {
            ins = tokio::time::timeout(IDLE_TIMEOUT, reader.next()) => match ins {
                Err(_) => return "idle".into(),
                Ok(Err(e)) => return format!("refused: {e:#}"),
                Ok(Ok(None)) => return "closed by the client".into(),
                Ok(Ok(Some(ins))) => {
                    ctx.state.update_connection_stats(ctx.server_id, id, Some(1), None, Some(1), None).await;
                    match instruction(&ins, &mut line, &mut mask, &mut streams, &tx) {
                        Ok(Some((t, data))) => {
                            let mut v = data;
                            v["connection_id"] = json!(d.id);
                            Some((t, v))
                        }
                        Ok(None) => None,
                        Err(e) => return e.to_string(),
                    }
                }
            },
            command = peer_rx.recv() => {
                if let Some(command) = command {
                    if inject(&mut d, command, &tx, &log) {
                        return "disconnected from the dashboard".into();
                    }
                }
                None
            }
        };
        let Some((t, data)) = event else { continue };
        let Some(batch) = ask(ctx, id, t, data).await else {
            continue;
        };
        let (out, end) = frame(&mut d, &batch, &log);
        if !out.is_empty() && tx.send(out).is_err() {
            return "write failed".into();
        }
        if end {
            return "the handler ended it".into();
        }
    }
}

/// What one client instruction means: an event for the model, or nothing. An error ends
/// the session (the client said `disconnect`, or broke a bound).
fn instruction(
    ins: &Instruction,
    line: &mut String,
    mask: &mut u32,
    streams: &mut HashMap<String, Vec<u8>>,
    tx: &crate::utils::outbox::OutboxSender<String>,
) -> Result<Option<(&'static EventType, Value)>> {
    Ok(match ins.opcode.as_str() {
        "key" if ins.arg(1) == "1" => {
            let k: u32 = ins.arg(0).parse().unwrap_or(0);
            match k {
                0xff0d | 0xff8d => {
                    Some((&*actions::TEXT_EVENT, json!({"text": std::mem::take(line)})))
                }
                0xff08 => {
                    line.pop();
                    None
                }
                // Modifiers alone are not keys anyone pressed on purpose.
                0xffe1..=0xffee => None,
                k => match wire::char_of_keysym(k) {
                    Some(c) => {
                        if line.chars().count() < MAX_LINE {
                            line.push(c);
                        }
                        None
                    }
                    None => Some((
                        &*actions::KEY_EVENT,
                        json!({"key": wire::name_of_keysym(k), "pending_text": line.clone()}),
                    )),
                },
            }
        }
        "mouse" => {
            let m: u32 = ins.arg(2).parse().unwrap_or(0);
            let pressed = m & !*mask;
            *mask = m;
            let button = match pressed {
                0 => None,
                b if b & 1 != 0 => Some("left"),
                b if b & 2 != 0 => Some("middle"),
                b if b & 4 != 0 => Some("right"),
                b if b & 8 != 0 => Some("scroll_up"),
                _ => Some("scroll_down"),
            };
            button.map(|b| {
                (
                    &*actions::CLICK_EVENT,
                    json!({"x": ins.arg(0).parse::<u32>().unwrap_or(0),
                           "y": ins.arg(1).parse::<u32>().unwrap_or(0), "button": b}),
                )
            })
        }
        "clipboard" => {
            if streams.len() >= MAX_STREAMS {
                bail!("too many open streams");
            }
            streams.insert(ins.arg(0).to_string(), Vec::new());
            let _ = tx.send(wire::encode("ack", &[ins.arg(0), "OK", "0"]));
            None
        }
        "blob" => {
            if let Some(buf) = streams.get_mut(ins.arg(0)) {
                buf.extend(wire::unbase64(ins.arg(1))?);
                if buf.len() > wire::MAX_CLIPBOARD {
                    bail!("clipboard longer than {} bytes", wire::MAX_CLIPBOARD);
                }
                let _ = tx.send(wire::encode("ack", &[ins.arg(0), "OK", "0"]));
            }
            None
        }
        "end" => streams.remove(ins.arg(0)).map(|buf| {
            (
                &*actions::CLIPBOARD_EVENT,
                json!({"text": String::from_utf8_lossy(&buf)}),
            )
        }),
        "disconnect" => bail!("closed by the client (disconnect)"),
        // sync acknowledgements, nop, size, ack for our image streams, key releases.
        _ => None,
    })
}

/// An action injected from the dashboard or MCP: drawn like the model's; whether it ends
/// the session.
fn inject(
    d: &mut Display,
    command: ClientCommand,
    tx: &crate::utils::outbox::OutboxSender<String>,
    log: &Log,
) -> bool {
    let action = command.action.clone();
    let outcome = match actions::check(&action) {
        Err(e) => ClientSendOutcome::Rejected {
            error: e.to_string(),
        },
        Ok(()) => {
            let (out, end) = frame(d, std::slice::from_ref(&action), log);
            let n = out.len();
            if !out.is_empty() {
                let _ = tx.send(out);
            }
            if end {
                let _ = command.reply_tx.send(Ok(ClientSendOutcome::Disconnected));
                return true;
            }
            ClientSendOutcome::Sent { bytes_sent: n }
        }
    };
    let _ = command.reply_tx.send(Ok(outcome));
    false
}

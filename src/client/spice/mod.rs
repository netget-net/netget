//! SPICE client. Links the main channel with the password's RSA-OAEP ticket, learns the session
//! id from `SPICE_MSG_MAIN_INIT`, asks for the channel list, then links the display and inputs
//! channels into the same session. The display channel is decoded into a picture of the
//! primary surface (`display.rs`); the model's actions become scancodes and mouse messages on
//! the inputs channel; `spice_read_screen` describes the picture once the server stops drawing.
//!
//! Each channel has a reader task: it answers PING and SET_ACK itself (a client that does not
//! ACK is throttled by the server after a window of messages), feeds the display model, and
//! raises events. One session task owns the writers' use for input and the screen reads.
pub mod actions;
pub mod display;

use crate::client::llm_budget::call_llm_for_client_batch;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::spice::wire::{self, channel, common_cap, link_err, msg, msgc, Cursor};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
use actions::Input;
pub use actions::SpiceClientProtocol;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Instant;

/// Linking every channel, TCP connect to the last link result.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// The largest message body accepted from the server: a full 4096x2160 32-bit bitmap and its
/// headers. The size is a server-chosen `u32`, refused before the body is allocated.
pub const MAX_SERVER_MESSAGE_BYTES: u32 = 36 << 20;
/// Messages the connect path reads while waiting for MAIN_INIT and then CHANNELS_LIST.
const MAX_SETUP_MESSAGES: usize = 256;
const TURNS: usize = 64;

/// One channel's write side.
pub struct Channel {
    writer: Mutex<OwnedWriteHalf>,
    mini: bool,
    serial: AtomicU64,
}

impl Channel {
    async fn send(&self, msg_type: u16, body: &[u8]) -> std::io::Result<()> {
        let mut w = self.writer.lock().await;
        let serial = self.serial.fetch_add(1, Ordering::SeqCst) + 1;
        let mut buf = wire::data_header(self.mini, serial, msg_type, body.len() as u32);
        buf.extend_from_slice(body);
        w.write_all(&buf).await?;
        w.flush().await
    }

    async fn shutdown(&self) {
        let _ = self.writer.lock().await.shutdown().await;
    }
}

/// Link one channel: link message, reply, auth mechanism, ticket, result. A refused link is an
/// error naming the server's `SPICE_LINK_ERR_*`.
pub async fn link(
    server: SocketAddr,
    connection_id: u32,
    channel_type: u8,
    password: &str,
    channel_caps: Vec<u32>,
) -> Result<(OwnedReadHalf, Arc<Channel>, wire::LinkReply)> {
    let stream = TcpStream::connect(server)
        .await
        .with_context(|| format!("cannot reach {server}"))?;
    let _ = stream.set_nodelay(true);
    let (mut r, mut w) = stream.into_split();
    let mess = wire::LinkMess {
        connection_id,
        channel_type,
        channel_id: 0,
        common_caps: vec![wire::caps_word(&[
            common_cap::AUTH_SELECTION,
            common_cap::AUTH_SPICE,
            common_cap::MINI_HEADER,
        ])],
        channel_caps,
    };
    w.write_all(&mess.encode()).await?;
    let mut header = [0u8; wire::LINK_HEADER_BYTES];
    r.read_exact(&mut header)
        .await
        .context("reading the link reply")?;
    let size = wire::parse_link_header(&header, 4).map_err(|e| {
        anyhow::anyhow!(
            "the {} channel's link reply is not SPICE: {}",
            channel::name(channel_type),
            link_err::name(e.0)
        )
    })?;
    let mut body = vec![0u8; size as usize];
    r.read_exact(&mut body).await?;
    let reply = wire::LinkReply::decode(&body)?;
    if reply.error != link_err::OK {
        bail!(
            "the server refused the {} channel link: {}",
            channel::name(channel_type),
            link_err::name(reply.error)
        );
    }
    if wire::has_cap(&reply.common_caps, common_cap::AUTH_SELECTION) {
        w.write_all(&wire::AUTH_MECHANISM_SPICE.to_le_bytes())
            .await?;
    }
    let ticket = wire::encrypt_ticket(&reply.pubkey, password)?;
    w.write_all(&ticket).await?;
    let result = r.read_u32_le().await.context("reading the link result")?;
    if result != link_err::OK {
        bail!(
            "the server refused the {} channel: {}",
            channel::name(channel_type),
            link_err::name(result)
        );
    }
    let mini = wire::has_cap(&reply.common_caps, common_cap::MINI_HEADER);
    Ok((
        r,
        Arc::new(Channel {
            writer: Mutex::new(w),
            mini,
            serial: AtomicU64::new(0),
        }),
        reply,
    ))
}

/// What the connect path learned.
struct Setup {
    main: (OwnedReadHalf, Arc<Channel>),
    display: Option<(OwnedReadHalf, Arc<Channel>)>,
    inputs: Option<(OwnedReadHalf, Arc<Channel>)>,
    session_id: u32,
    mouse_mode: u32,
    agent_connected: bool,
    name: Option<String>,
    channels: Vec<&'static str>,
    /// Notifications that arrived while the channels were being linked.
    notices: Vec<(&'static str, String)>,
}

/// A `SpiceMsgNotify` as (severity name, text with control characters removed).
fn parse_notify(body: &[u8]) -> Result<(&'static str, String)> {
    let mut c = Cursor::new(body);
    let _stamp = c.u64("time stamp")?;
    let severity = c.u32("severity")?;
    let _visibility = c.u32("visibility")?;
    let _what = c.u32("what")?;
    let n = c.u32("message length")? as usize;
    let text = c.bytes(n.min(c.remaining()), "message")?;
    let text = crate::utils::sanitize::line_field(&String::from_utf8_lossy(text));
    Ok((wire::severity_name(severity), text))
}

fn guest_name(body: &[u8]) -> Result<String> {
    let mut c = Cursor::new(body);
    let n = c.u32("name length")? as usize;
    let bytes = c.bytes(n.min(c.remaining()), "name")?;
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    Ok(crate::utils::sanitize::line_field(
        &String::from_utf8_lossy(&bytes[..end]),
    ))
}

async fn establish(server: SocketAddr, password: &str) -> Result<Setup> {
    let (mut main_r, main, _) = link(
        server,
        0,
        channel::MAIN,
        password,
        vec![wire::caps_word(&[wire::main_cap::NAME_AND_UUID])],
    )
    .await?;
    let mut name = None;
    let mut init = None;
    let mut notices = Vec::new();
    for _ in 0..MAX_SETUP_MESSAGES {
        let (t, body) =
            wire::read_message(&mut main_r, main.mini, MAX_SERVER_MESSAGE_BYTES).await?;
        match t {
            msg::PING => main.send(msgc::PONG, &wire::pong_for(&body)?).await?,
            msg::MAIN_NAME => name = Some(guest_name(&body)?),
            msg::NOTIFY => notices.push(parse_notify(&body)?),
            msg::MAIN_INIT => {
                let mut c = Cursor::new(&body);
                let session_id = c.u32("session id")?;
                let _hint = c.u32("display channels hint")?;
                let supported = c.u32("supported mouse modes")?;
                let current = c.u32("current mouse mode")?;
                let agent = c.u32("agent connected")?;
                init = Some((session_id, supported, current, agent != 0));
                break;
            }
            _ => {}
        }
    }
    let (session_id, supported, mut mouse_mode, agent_connected) =
        init.context("the server sent no SPICE_MSG_MAIN_INIT")?;
    main.send(msgc::MAIN_ATTACH_CHANNELS, &[]).await?;
    if supported & wire::MOUSE_MODE_CLIENT != 0 && mouse_mode != wire::MOUSE_MODE_CLIENT {
        main.send(
            msgc::MAIN_MOUSE_MODE_REQUEST,
            &(wire::MOUSE_MODE_CLIENT as u16).to_le_bytes(),
        )
        .await?;
    }
    let mut list = None;
    for _ in 0..MAX_SETUP_MESSAGES {
        let (t, body) =
            wire::read_message(&mut main_r, main.mini, MAX_SERVER_MESSAGE_BYTES).await?;
        match t {
            msg::PING => main.send(msgc::PONG, &wire::pong_for(&body)?).await?,
            msg::MAIN_NAME => name = Some(guest_name(&body)?),
            msg::NOTIFY => notices.push(parse_notify(&body)?),
            msg::MAIN_MOUSE_MODE => {
                let mut c = Cursor::new(&body);
                let _supported = c.u16("supported")?;
                mouse_mode = u32::from(c.u16("current")?);
            }
            msg::MAIN_CHANNELS_LIST => {
                let mut c = Cursor::new(&body);
                let n = c.u32("channel count")?;
                ensure!(
                    (n as usize) * 2 <= c.remaining(),
                    "{n} channels do not fit in the list"
                );
                let mut v = Vec::new();
                for _ in 0..n {
                    v.push((c.u8("channel type")?, c.u8("channel id")?));
                }
                list = Some(v);
                break;
            }
            _ => {}
        }
    }
    let list = list.context("the server sent no SPICE_MSG_MAIN_CHANNELS_LIST")?;
    let channels: Vec<&'static str> = list.iter().map(|(t, _)| channel::name(*t)).collect();
    let display = if list.contains(&(channel::DISPLAY, 0)) {
        let (r, ch, reply) = link(server, session_id, channel::DISPLAY, password, vec![]).await?;
        let cache_pixels = (display::MAX_CACHE_BYTES / 4) as i64;
        ch.send(
            msgc::DISPLAY_INIT,
            &wire::display_init(1, cache_pixels, 1, 3 << 20),
        )
        .await?;
        if wire::has_cap(&reply.channel_caps, wire::display_cap::PREF_COMPRESSION) {
            // Ask for uncompressed images: they are the ones this client decodes exactly.
            ch.send(
                msgc::DISPLAY_PREFERRED_COMPRESSION,
                &[wire::IMAGE_COMPRESSION_OFF],
            )
            .await?;
        }
        Some((r, ch))
    } else {
        None
    };
    let inputs = if list.contains(&(channel::INPUTS, 0)) {
        let (r, ch, _) = link(server, session_id, channel::INPUTS, password, vec![]).await?;
        Some((r, ch))
    } else {
        None
    };
    Ok(Setup {
        main: (main_r, main),
        display,
        inputs,
        session_id,
        mouse_mode,
        agent_connected,
        name,
        channels,
        notices,
    })
}

/// State the reader tasks and the session task share.
struct Shared {
    display: std::sync::Mutex<display::DisplayModel>,
    mouse_mode: AtomicU32,
}

fn resolve_target(remote: &str) -> Result<String> {
    let raw = remote
        .trim()
        .trim_start_matches("spice://")
        .trim_end_matches('/');
    let has_port = raw.parse::<SocketAddr>().is_ok()
        || raw
            .rsplit_once(':')
            .is_some_and(|(h, p)| !h.ends_with(':') && p.parse::<u16>().is_ok());
    ensure!(
        has_port,
        "SPICE has no default port; name one, as in 127.0.0.1:5930"
    );
    Ok(raw.to_string())
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let password = ctx
        .startup_params
        .as_ref()
        .map(|p| p.get_optional_string("password"))
        .transpose()?
        .flatten()
        .unwrap_or_default();
    ensure!(
        password.len() <= wire::MAX_PASSWORD_LENGTH,
        "a SPICE password is at most {} bytes",
        wire::MAX_PASSWORD_LENGTH
    );
    let target = resolve_target(&ctx.remote_addr)?;
    let server = tokio::net::lookup_host(&target)
        .await
        .with_context(|| format!("cannot resolve {target}"))?
        .next()
        .with_context(|| format!("{target} resolved to no address"))?;
    let setup = tokio::time::timeout(CONNECT_TIMEOUT, establish(server, &password))
        .await
        .context("linking the SPICE channels timed out")??;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "SPICE client {} connected to {server}: session {:#010x}, channels {:?}",
        ctx.client_id, setup.session_id, setup.channels
    ));
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURNS);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(64);
    let (end_tx, end_rx) = mpsc::channel::<String>(8);
    let shared = Arc::new(Shared {
        display: std::sync::Mutex::new(display::DisplayModel::default()),
        mouse_mode: AtomicU32::new(setup.mouse_mode),
    });
    let _ = event_tx.try_send((
        Event::new(
            &actions::CONNECTED_EVENT,
            json!({
                "server": server.to_string(),
                "session_id": setup.session_id,
                "channels": setup.channels,
                "mouse_mode": mode_name(setup.mouse_mode),
                "name": setup.name,
                "agent_connected": setup.agent_connected,
            }),
        ),
        0,
    ));
    for (severity, message) in &setup.notices {
        let _ = event_tx.try_send((
            Event::new(
                &actions::NOTIFY_EVENT,
                json!({"severity": severity, "message": message}),
            ),
            0,
        ));
    }
    let dispatcher = tokio::spawn(run_turns(ctx.clone(), event_rx, internal_tx));
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;

    let main = setup.main.1.clone();
    let display_ch = setup.display.as_ref().map(|d| d.1.clone());
    let inputs_ch = setup.inputs.as_ref().map(|i| i.1.clone());
    let mut readers = Vec::new();
    for (kind, half) in [
        ("main", Some(setup.main)),
        ("display", setup.display),
        ("inputs", setup.inputs),
    ] {
        let Some((r, ch)) = half else { continue };
        let task = tokio::spawn(read_channel(
            kind,
            r,
            ch,
            shared.clone(),
            event_tx.clone(),
            end_tx.clone(),
            ctx.status_tx.clone(),
        ));
        readers.push(task.abort_handle());
        ctx.state.register_client_task(ctx.client_id, task).await;
    }
    drop(end_tx);
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let mut session = Session {
            shared,
            main,
            display: display_ch,
            inputs: inputs_ch,
            pointer: (0, 0),
            buttons: 0,
        };
        let reason = session
            .run(&session_ctx, external, internal, end_rx, event_tx.clone())
            .await;
        for r in &readers {
            r.abort();
        }
        session.close().await;
        Log::new(Some(&session_ctx.status_tx)).info(format!(
            "SPICE client {} disconnected: {reason}",
            session_ctx.client_id
        ));
        let _ = event_tx
            .send((
                Event::new(&actions::DISCONNECTED_EVENT, json!({"reason": reason})),
                0,
            ))
            .await;
        drop(event_tx);
        let _ = tokio::time::timeout(Duration::from_secs(30), async {
            while !dispatcher_abort.is_finished() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
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
    Ok(server)
}

fn mode_name(mode: u32) -> &'static str {
    if mode == wire::MOUSE_MODE_CLIENT {
        "client"
    } else {
        "server"
    }
}

/// One channel's reader: flow control and PING for every channel, then what the channel is
/// for. Ends the session (through `end`) when the channel ends.
async fn read_channel(
    kind: &'static str,
    mut r: OwnedReadHalf,
    ch: Arc<Channel>,
    shared: Arc<Shared>,
    events: mpsc::Sender<(Event, u32)>,
    end: mpsc::Sender<String>,
    status_tx: mpsc::UnboundedSender<String>,
) {
    let mut window = 0u32;
    let mut since_ack = 0u32;
    let emit = |event: &'static EventType, data: Value| {
        if events.try_send((Event::new(event, data), 0)).is_err() {
            tracing::warn!("SPICE client dropped an event: the model is {TURNS} behind decision=turn_queue_full");
        }
    };
    let reason = loop {
        let (t, body) = match wire::read_message(&mut r, ch.mini, MAX_SERVER_MESSAGE_BYTES).await {
            Ok(m) => m,
            Err(wire::ReadError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break format!("the server closed the {kind} channel");
            }
            Err(e) => break format!("the {kind} channel ended: {e}"),
        };
        if window > 0 {
            since_ack += 1;
            if since_ack >= window {
                since_ack = 0;
                if ch.send(msgc::ACK, &[]).await.is_err() {
                    break format!("the {kind} channel could not be written");
                }
            }
        }
        let handled: Result<()> = async {
            match t {
                msg::SET_ACK => {
                    let mut c = Cursor::new(&body);
                    let generation = c.u32("ack generation")?;
                    window = c.u32("ack window")?;
                    since_ack = 0;
                    ch.send(msgc::ACK_SYNC, &wire::u32_body(generation)).await?;
                }
                msg::PING => ch.send(msgc::PONG, &wire::pong_for(&body)?).await?,
                msg::NOTIFY => {
                    let (severity, text) = parse_notify(&body)?;
                    Log::new(Some(&status_tx))
                        .info(format!("SPICE notification ({severity}): {text}"));
                    emit(
                        &actions::NOTIFY_EVENT,
                        json!({"severity": severity, "message": text}),
                    );
                }
                msg::MAIN_MOUSE_MODE if kind == "main" => {
                    let mut c = Cursor::new(&body);
                    let _supported = c.u16("supported")?;
                    shared
                        .mouse_mode
                        .store(u32::from(c.u16("current")?), Ordering::SeqCst);
                }
                other if kind == "display" => {
                    let change = match shared.display.lock() {
                        Ok(mut d) => d.handle(other, &body)?,
                        Err(_) => bail!("the display model is poisoned"),
                    };
                    if let Some(display::Change::SurfaceCreated {
                        width,
                        height,
                        format,
                    }) = change
                    {
                        emit(
                            &actions::SURFACE_EVENT,
                            json!({"width": width, "height": height, "format": format}),
                        );
                    }
                }
                _ => {}
            }
            Ok(())
        }
        .await;
        if let Err(e) = handled {
            break format!("the {kind} channel ended: {e:#}");
        }
    };
    let _ = end.send(reason).await;
}

/// A screen read waiting for the server to stop drawing.
struct PendingRead {
    grid: u64,
    points: Vec<(u32, u32)>,
    settle: Duration,
    give_up: Instant,
    command: Option<ClientCommand>,
    depth: u32,
}

struct Session {
    shared: Arc<Shared>,
    main: Arc<Channel>,
    display: Option<Arc<Channel>>,
    inputs: Option<Arc<Channel>>,
    /// Where this client last put the pointer, for relative motion in server mouse mode.
    pointer: (u32, u32),
    buttons: u16,
}

impl Session {
    fn last_update(&self) -> Instant {
        self.shared
            .display
            .lock()
            .map(|d| d.last_update)
            .unwrap_or_else(|_| Instant::now())
    }

    fn reading(&self, p: &PendingRead, settled: bool) -> Value {
        let Ok(d) = self.shared.display.lock() else {
            return json!({"error": "the display model is poisoned"});
        };
        let mut data = d.describe(p.grid as usize);
        let points: Vec<Value> = p
            .points
            .iter()
            .map(|(x, y)| json!({"x": x, "y": y, "color": display::pixel_hex(&d, *x, *y)}))
            .collect();
        data["points"] = json!(points);
        data["settled"] = json!(settled);
        data["mouse_mode"] = json!(mode_name(self.shared.mouse_mode.load(Ordering::SeqCst)));
        data
    }

    async fn close(&self) {
        self.main.shutdown().await;
        if let Some(d) = &self.display {
            d.shutdown().await;
        }
        if let Some(i) = &self.inputs {
            i.shutdown().await;
        }
    }

    async fn run(
        &mut self,
        ctx: &ConnectContext,
        mut external: mpsc::Receiver<ClientCommand>,
        mut internal: mpsc::Receiver<(Value, u32)>,
        mut end: mpsc::Receiver<String>,
        events: mpsc::Sender<(Event, u32)>,
    ) -> String {
        let mut pending: Option<PendingRead> = None;
        let emit = |event: &'static EventType, data: Value, depth: u32| {
            if events.try_send((Event::new(event, data), depth)).is_err() {
                tracing::warn!("SPICE client {} dropped an event: the model is {TURNS} behind decision=turn_queue_full", ctx.client_id);
            }
        };
        loop {
            let wake = pending
                .as_ref()
                .map(|p| (self.last_update() + p.settle).min(p.give_up))
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));
            let (action, depth, command) = tokio::select! {
                reason = end.recv() => {
                    return reason.unwrap_or_else(|| "every channel ended".into());
                }
                _ = tokio::time::sleep_until(wake), if pending.is_some() => {
                    let now = Instant::now();
                    let quiet = self.last_update() + pending.as_ref().map(|p| p.settle).unwrap_or_default() <= now;
                    let expired = pending.as_ref().is_some_and(|p| p.give_up <= now);
                    if !quiet && !expired {
                        continue;
                    }
                    let Some(p) = pending.take() else { continue };
                    let data = self.reading(&p, quiet);
                    if let Some(c) = p.command {
                        crate::client::command_support::reply(c, Ok(ClientSendOutcome::Executed { detail: data.to_string() }));
                    }
                    emit(&actions::SCREEN_EVENT, data, p.depth);
                    continue;
                }
                c = external.recv() => match c {
                    Some(c) => {
                        ctx.state.record_access_log(AccessLogOwner::Client(ctx.client_id.as_u32()), "SPICE", None,
                            "injected_action", c.action.clone(), vec![]).await;
                        (c.action.clone(), 0, Some(c))
                    }
                    None => return "the client was stopped".into(),
                },
                a = internal.recv() => match a {
                    Some((a, d)) => (a, d, None),
                    None => return "the client was stopped".into(),
                },
            };
            let reply = |command: Option<ClientCommand>, outcome: ClientSendOutcome| {
                if let Some(c) = command {
                    crate::client::command_support::reply(c, Ok(outcome));
                }
            };
            let kind = action["type"].as_str().unwrap_or_default().to_string();
            match SpiceClientProtocol.execute_action(action.clone()) {
                Ok(ClientActionResult::Disconnect) => {
                    reply(command, ClientSendOutcome::Disconnected);
                    return "the client disconnected".into();
                }
                Ok(_) => {}
                Err(e) => {
                    reply(
                        command,
                        ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        },
                    );
                    continue;
                }
            }
            let Ok(input) = actions::check(&action) else {
                continue;
            };
            if let Input::ReadScreen {
                grid,
                settle_ms,
                points,
            } = input
            {
                if let Some(old) = pending.take() {
                    if let Some(c) = old.command {
                        crate::client::command_support::reply(
                            c,
                            Ok(ClientSendOutcome::Rejected {
                                error: "replaced by a newer spice_read_screen".into(),
                            }),
                        );
                    }
                }
                let settle = Duration::from_millis(settle_ms);
                pending = Some(PendingRead {
                    grid,
                    points,
                    settle,
                    give_up: Instant::now()
                        + settle
                        + Duration::from_millis(actions::MAX_SETTLE_WAIT_MS),
                    command,
                    depth,
                });
                continue;
            }
            match self.send_input(&input).await {
                Ok(n) => {
                    Log::new(Some(&ctx.status_tx)).info(format!(
                        "SPICE client {}: {kind} ({n} input messages)",
                        ctx.client_id
                    ));
                    reply(
                        command,
                        ClientSendOutcome::Executed {
                            detail: json!({"action": kind, "input_messages": n}).to_string(),
                        },
                    );
                }
                Err(e) => {
                    let message = format!("{e:#}");
                    reply(
                        command,
                        ClientSendOutcome::Executed {
                            detail: json!({"action": kind, "error": message}).to_string(),
                        },
                    );
                    emit(
                        &actions::ERROR_EVENT,
                        json!({"action": kind, "message": message}),
                        depth,
                    );
                }
            }
        }
    }

    /// Put the model's input on the inputs channel; returns how many messages it took.
    async fn send_input(&mut self, input: &Input) -> Result<usize> {
        let inputs = self
            .inputs
            .clone()
            .context("the server offered no inputs channel")?;
        let mut sent = 0;
        match input {
            Input::Keys(strokes) => {
                for ((sc, ext), released) in strokes {
                    let t = if *released {
                        msgc::INPUTS_KEY_UP
                    } else {
                        msgc::INPUTS_KEY_DOWN
                    };
                    let code = crate::server::spice::keys::key_code(*sc, *ext, *released);
                    inputs.send(t, &wire::u32_body(code)).await?;
                    sent += 1;
                }
            }
            Input::Mouse {
                x,
                y,
                action,
                button,
            } => {
                if let Some((w, h)) = self
                    .shared
                    .display
                    .lock()
                    .ok()
                    .and_then(|d| d.primary_size())
                {
                    ensure!(
                        *x < w && *y < h,
                        "({x}, {y}) is outside the {w}x{h} display"
                    );
                }
                let b = match button.as_str() {
                    "right" => wire::button::RIGHT,
                    "middle" => wire::button::MIDDLE,
                    _ => wire::button::LEFT,
                };
                if self.shared.mouse_mode.load(Ordering::SeqCst) == wire::MOUSE_MODE_CLIENT {
                    inputs
                        .send(
                            msgc::INPUTS_MOUSE_POSITION,
                            &wire::mouse_position(*x, *y, self.buttons, 0),
                        )
                        .await?;
                } else {
                    let dx = *x as i32 - self.pointer.0 as i32;
                    let dy = *y as i32 - self.pointer.1 as i32;
                    inputs
                        .send(
                            msgc::INPUTS_MOUSE_MOTION,
                            &wire::mouse_motion(dx, dy, self.buttons),
                        )
                        .await?;
                }
                self.pointer = (*x, *y);
                sent += 1;
                let mut presses: Vec<(u8, bool)> = Vec::new();
                match action.as_str() {
                    "click" => presses.extend([(b, true), (b, false)]),
                    "double_click" => {
                        presses.extend([(b, true), (b, false), (b, true), (b, false)])
                    }
                    "press" => presses.push((b, true)),
                    "release" => presses.push((b, false)),
                    "scroll_up" => {
                        presses.extend([(wire::button::UP, true), (wire::button::UP, false)])
                    }
                    "scroll_down" => {
                        presses.extend([(wire::button::DOWN, true), (wire::button::DOWN, false)])
                    }
                    _ => {}
                }
                for (button, down) in presses {
                    if down {
                        self.buttons |= wire::button::mask(button);
                    } else {
                        self.buttons &= !wire::button::mask(button);
                    }
                    let t = if down {
                        msgc::INPUTS_MOUSE_PRESS
                    } else {
                        msgc::INPUTS_MOUSE_RELEASE
                    };
                    inputs
                        .send(t, &wire::mouse_button(button, self.buttons))
                        .await?;
                    sent += 1;
                }
            }
            Input::ReadScreen { .. } => {}
        }
        Ok(sent)
    }
}

/// Answers what the readers and the session raised. The server pushes notifications and
/// surface changes whenever it likes, so they can pile up in `events` while the model is
/// answering; with batching on, everything waiting is answered in one call (one event each,
/// the newest the trigger), with it off one event per call.
async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32)>,
    internal: mpsc::Sender<(Value, u32)>,
) {
    let protocol = SpiceClientProtocol;
    let too_deep = |event: &Event, depth: u32| {
        if depth >= MAX_FOLLOWUP_DEPTH {
            tracing::warn!("SPICE client {} not asking the model about {}: {depth} turns deep decision=followup_depth", ctx.client_id, event.id());
            true
        } else {
            false
        }
    };
    while let Some((event, depth)) = events.recv().await {
        if too_deep(&event, depth) {
            continue;
        }
        let mut batch = vec![(event, depth)];
        if ctx
            .state
            .client_conversation_settings(ctx.client_id)
            .await
            .is_some_and(|(_, batching)| batching)
        {
            while batch.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                match events.try_recv() {
                    Ok((event, depth)) if !too_deep(&event, depth) => batch.push((event, depth)),
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
        let depth = batch.iter().map(|(_, d)| *d).max().unwrap_or(0);
        let batch: Vec<Event> = batch.into_iter().map(|(e, _)| e).collect();
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
        match call_llm_for_client_batch(
            &ctx.llm_client,
            &ctx.state,
            ctx.client_id.to_string(),
            &instruction,
            &memory,
            &batch,
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
            Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!("SPICE client handler: {e}")),
        }
    }
}

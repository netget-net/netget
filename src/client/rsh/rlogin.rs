//! The rlogin client: the handshake, then a terminal session the model types into.
//!
//! Output is gathered until the server pauses ([`SETTLE`]) and raised as one `rlogin_output`,
//! so a prompt that arrives in five writes is one turn for the model, not five. Urgent bytes
//! are read out of band after every read and on a timer (an urgent byte alone does not make a
//! socket readable): `TIOCPKT_WINDOW` is answered with the window-size message, as a real
//! rlogin answers it, and every control byte is reported in the next event.
use super::{actions, resolve, spawn_dispatcher, DEFAULT_SPEED, DEFAULT_TERMINAL, DEFAULT_WINDOW};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::rsh::wire;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

/// Quiet after output before it is raised to the model.
pub const SETTLE: Duration = Duration::from_millis(300);
/// Output raised at once past this many bytes, quiet or not.
pub const MAX_EVENT_BYTES: usize = 16 * 1024;
/// How often urgent data is looked for when nothing else is arriving.
pub const URGENT_POLL: Duration = Duration::from_millis(200);
/// Model turns in a row (output answered by typing) before the session stops asking.
pub const MAX_MODEL_TURNS: usize = 32;
/// After the session ends, how long its last queued output may take to reach the model.
pub const WIND_DOWN: Duration = Duration::from_secs(10);

/// One urgent byte, if one is waiting.
fn read_urgent(r: &OwnedReadHalf) -> Option<u8> {
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1];
    match socket2::SockRef::from(r.as_ref()).recv_out_of_band(&mut buf) {
        // SAFETY: recv wrote `n` (here 1) bytes into the buffer.
        Ok(1) => Some(unsafe { buf[0].assume_init() }),
        _ => None,
    }
}

/// The names of the control bits in an urgent byte, as the event reports them.
pub fn control_names(byte: u8) -> Vec<&'static str> {
    let mut out = Vec::new();
    if byte & wire::TIOCPKT_WINDOW != 0 {
        out.push("window_size_requested");
    }
    if byte & wire::TIOCPKT_FLUSHWRITE != 0 {
        out.push("flush_output");
    }
    if byte & wire::TIOCPKT_NOSTOP != 0 {
        out.push("flow_control_remote");
    }
    if byte & wire::TIOCPKT_DOSTOP != 0 {
        out.push("flow_control_local");
    }
    out
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let string = |key: &str| -> Result<Option<String>> {
        Ok(params
            .map(|p| p.get_optional_string(key))
            .transpose()?
            .flatten())
    };
    let number = |key: &str| -> Result<Option<u64>> {
        Ok(params
            .map(|p| p.get_optional_u64(key))
            .transpose()?
            .flatten())
    };
    let local_user = string("local_user")?.unwrap_or_else(super::current_user);
    let remote_user = string("remote_user")?.unwrap_or_else(|| local_user.clone());
    let terminal = string("terminal")?.unwrap_or_else(|| DEFAULT_TERMINAL.to_string());
    let speed = number("speed")?.unwrap_or(u64::from(DEFAULT_SPEED));
    let mut window = DEFAULT_WINDOW;
    if let Some(rows) = number("rows")? {
        window.rows = u16::try_from(rows).context("rows is too large")?;
    }
    if let Some(cols) = number("cols")? {
        window.cols = u16::try_from(cols).context("cols is too large")?;
    }
    wire::check_field(&local_user, wire::MAX_USER, "local_user")?;
    wire::check_field(&remote_user, wire::MAX_USER, "remote_user")?;
    let term_field = format!("{terminal}/{speed}");
    wire::check_field(&term_field, wire::MAX_TERMINAL, "terminal/speed")?;

    let target = resolve(&ctx.remote_addr).await?;
    let (stream, reserved) = tokio::time::timeout(
        super::CONNECT_TIMEOUT,
        wire::connect_maybe_reserved(target, true),
    )
    .await
    .with_context(|| format!("connecting to {target} timed out"))?
    .with_context(|| format!("connecting to {target}"))?;
    let local = stream.local_addr()?;
    let log = Log::new(Some(&ctx.status_tx));
    if !reserved {
        log.warn(format!(
            "RLOGIN client connected from ordinary port {}: a stock rlogind refuses any source \
             port outside 512-1023",
            local.port()
        ));
    }
    let (mut r, mut w) = stream.into_split();
    w.write_all(&wire::encode_fields(&[
        "",
        &local_user,
        &remote_user,
        &term_field,
    ]))
    .await?;
    let mut status = [0u8; 1];
    let n = tokio::time::timeout(wire::HANDSHAKE_TIMEOUT, r.read(&mut status))
        .await
        .context("the rlogin server did not answer the handshake")??;
    if n == 0 {
        bail!("the rlogin server closed the connection without answering");
    }
    match status[0] {
        wire::STATUS_OK => {}
        wire::STATUS_ERROR => {
            let mut line = Vec::new();
            let mut buf = [0u8; 256];
            let text = loop {
                if let Some(t) = wire::refusal_line(&line, false) {
                    break t;
                }
                match tokio::time::timeout(super::CONNECT_TIMEOUT, r.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => line.extend_from_slice(&buf[..n]),
                    _ => break wire::refusal_line(&line, true).unwrap_or_default(),
                }
            };
            bail!("the rlogin server refused the login: {}", text.trim_end());
        }
        other => bail!("not an rlogin server: status byte 0x{other:02x}"),
    }

    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<(Value, usize)>(32);
    let (event_tx, event_rx) = mpsc::channel::<(Event, usize)>(32);
    event_tx.try_send((
        Event::new(
            &actions::RLOGIN_CONNECTED_EVENT,
            json!({
                "remote_addr": target.to_string(),
                "remote_user": remote_user,
                "source_port": local.port(),
                "reserved_source_port": reserved,
            }),
        ),
        0,
    ))?;
    let protocol: Arc<dyn Client> = Arc::new(actions::RloginClientProtocol);
    let dispatcher = spawn_dispatcher(&ctx, protocol, event_rx, internal_tx).await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let result = session(&session_ctx, r, w, window, external, internal_rx, event_tx).await;
        // The session's last output (a logout, the server closing) is still queued for the
        // model: let the dispatcher finish it, briefly, before stopping it.
        let deadline = tokio::time::Instant::now() + WIND_DOWN;
        while !dispatcher.is_finished() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        dispatcher.abort();
        super::finish_client(&session_ctx, "RLOGIN", result).await;
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    Ok(local)
}

#[allow(clippy::too_many_arguments)]
async fn session(
    ctx: &ConnectContext,
    mut r: OwnedReadHalf,
    mut w: OwnedWriteHalf,
    mut window: wire::WindowSize,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, usize)>,
    events: mpsc::Sender<(Event, usize)>,
) -> Result<()> {
    let log = Log::new(Some(&ctx.status_tx));
    let protocol = actions::RloginClientProtocol;
    let mut pending: Vec<u8> = Vec::new();
    let mut control: Vec<&'static str> = Vec::new();
    let mut flush_at: Option<tokio::time::Instant> = None;
    // Whether the server has asked for window sizes: until then a resize is only remembered.
    let mut window_wanted = false;
    let mut depth = 0usize;
    let mut poll = tokio::time::interval(URGENT_POLL);
    let mut buf = vec![0u8; 8192];
    loop {
        let settle = async {
            match flush_at {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        let mut closed = false;
        let mut raise = false;
        // Whether to try a read: on readiness, and on every tick as well, because a kqueue
        // (macOS) can miss the edge for data that follows an urgent byte, and a missed edge
        // would otherwise read as the server going silent.
        let mut try_read = false;
        tokio::select! {
            ready = r.readable() => {
                if ready.is_err() { closed = true; raise = true; } else { try_read = true; }
            },
            _ = settle => raise = true,
            _ = poll.tick() => try_read = true,
            command = external.recv() => {
                let Some(command) = command else { return Ok(()) };
                depth = 0;
                let action = command.action.clone();
                ctx.state
                    .record_access_log(
                        AccessLogOwner::Client(ctx.client_id.as_u32()),
                        "RLOGIN",
                        None,
                        "injected_action",
                        action.clone(),
                        vec![],
                    )
                    .await;
                let outcome = act(&protocol, &action, &mut w, &mut window, window_wanted).await;
                let done = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
                crate::client::command_support::reply(command, outcome);
                if done { return Ok(()); }
                continue;
            }
            action = internal.recv() => {
                let Some((action, at)) = action else { return Ok(()) };
                if at > MAX_MODEL_TURNS {
                    log.warn(format!(
                        "RLOGIN client: handler chain stopped after {MAX_MODEL_TURNS} turns \
                         without an operator's input"
                    ));
                    continue;
                }
                depth = at;
                match act(&protocol, &action, &mut w, &mut window, window_wanted).await {
                    Ok(ClientSendOutcome::Disconnected) => return Ok(()),
                    Ok(ClientSendOutcome::Rejected { error }) => {
                        log.warn(format!("RLOGIN client action refused: {error}"))
                    }
                    Err(e) => return Err(e),
                    _ => {}
                }
                continue;
            }
        }
        // Urgent data first: a BSD stack refuses MSG_OOB once a read has passed the mark,
        // which is why rlogin(1) reads it from a SIGURG handler. An urgent byte alone does not
        // make the socket readable, hence the tick.
        urgent(&r, &mut w, &mut control, &mut window_wanted, &window).await?;
        if try_read {
            match r.try_read(&mut buf) {
                Ok(0) => {
                    closed = true;
                    raise = true;
                }
                Ok(n) => {
                    pending.extend_from_slice(&buf[..n]);
                    flush_at = Some(tokio::time::Instant::now() + SETTLE);
                    if pending.len() >= MAX_EVENT_BYTES {
                        raise = true;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    closed = true;
                    raise = true;
                }
            }
        }
        if raise {
            flush_at = None;
        }
        if raise && (!pending.is_empty() || closed || !control.is_empty()) {
            let data = super::text(&std::mem::take(&mut pending));
            let mut event = json!({"data": data, "closed": closed});
            if !control.is_empty() {
                event["control"] = json!(std::mem::take(&mut control));
            }
            if events
                .try_send((Event::new(&actions::RLOGIN_OUTPUT_EVENT, event), depth))
                .is_err()
            {
                bail!("RLOGIN event queue full; consumer stalled");
            }
        }
        if closed {
            return Ok(());
        }
    }
}

/// Take any urgent byte waiting: note its control bits, and answer a window request with the
/// window size, as rlogin(1) does.
async fn urgent(
    r: &OwnedReadHalf,
    w: &mut OwnedWriteHalf,
    control: &mut Vec<&'static str>,
    window_wanted: &mut bool,
    window: &wire::WindowSize,
) -> Result<()> {
    while let Some(byte) = read_urgent(r) {
        control.extend(control_names(byte));
        if byte & wire::TIOCPKT_WINDOW != 0 {
            *window_wanted = true;
            w.write_all(&window.encode()).await?;
        }
    }
    Ok(())
}

/// Execute one action on the session.
async fn act(
    protocol: &actions::RloginClientProtocol,
    action: &Value,
    w: &mut OwnedWriteHalf,
    window: &mut wire::WindowSize,
    window_wanted: bool,
) -> Result<ClientSendOutcome> {
    match protocol.execute_action(action.clone()) {
        Ok(ClientActionResult::Disconnect) => {
            let _ = w.shutdown().await;
            Ok(ClientSendOutcome::Disconnected)
        }
        Ok(ClientActionResult::SendData(bytes)) => {
            w.write_all(&bytes).await?;
            Ok(ClientSendOutcome::Sent {
                bytes_sent: bytes.len(),
            })
        }
        Ok(_) => {
            // rlogin_set_window: the only action that sends nothing by itself.
            *window = actions::window_of(action)?;
            if window_wanted {
                w.write_all(&window.encode()).await?;
                Ok(ClientSendOutcome::Sent {
                    bytes_sent: wire::WINDOW_MESSAGE_LEN,
                })
            } else {
                Ok(ClientSendOutcome::Executed {
                    detail: "window size remembered; the server has not asked for one".into(),
                })
            }
        }
        Err(e) => Ok(ClientSendOutcome::Rejected {
            error: e.to_string(),
        }),
    }
}

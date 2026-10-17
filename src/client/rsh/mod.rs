//! The BSD r-service clients: rsh and rexec (one connection per command, here) and rlogin (a
//! terminal session, in [`rlogin`]). The wire is the server's ([`crate::server::rsh::wire`]).
//!
//! The trust model asks something of a client that an ordinary process cannot give: a stock
//! rshd or rlogind accepts a connection only from a reserved source port (512-1023), which on
//! Linux only root can bind. NetGet tries one when it may and otherwise connects from an
//! ordinary port, says so in every event, and lets the server refuse.
pub mod actions;
pub mod rlogin;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::rsh::wire;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::{RexecClientProtocol, RloginClientProtocol, RshClientProtocol};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Connecting, and the server's status byte.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// One command, from connecting to the end of its output.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
/// A handler chain (result → event → command …) stops after this many follow-ups.
pub const MAX_FOLLOWUP_DEPTH: usize = 8;
/// rlogin's defaults.
pub const DEFAULT_TERMINAL: &str = "xterm";
pub const DEFAULT_SPEED: u32 = 38400;
pub const DEFAULT_WINDOW: wire::WindowSize = wire::WindowSize {
    rows: 24,
    cols: 80,
    xpixel: 0,
    ypixel: 0,
};

/// Which one-shot client.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Service {
    Rsh,
    Rexec,
}

impl Service {
    fn name(self) -> &'static str {
        match self {
            Self::Rsh => "RSH",
            Self::Rexec => "REXEC",
        }
    }
    fn protocol(self) -> Arc<dyn Client> {
        match self {
            Self::Rsh => Arc::new(RshClientProtocol),
            Self::Rexec => Arc::new(RexecClientProtocol),
        }
    }
    fn connected(self) -> &'static EventType {
        match self {
            Self::Rsh => &actions::RSH_CONNECTED_EVENT,
            Self::Rexec => &actions::REXEC_CONNECTED_EVENT,
        }
    }
    fn result(self) -> &'static EventType {
        match self {
            Self::Rsh => &actions::RSH_RESULT_EVENT,
            Self::Rexec => &actions::REXEC_RESULT_EVENT,
        }
    }
}

/// The user running NetGet, which is what rsh and rlogin claim by default.
pub fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .ok()
        .filter(|u| !u.is_empty() && !u.contains('\0'))
        .unwrap_or_else(|| "netget".to_string())
}

/// The server's address, resolved once.
pub async fn resolve(remote: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(remote)
        .await
        .with_context(|| format!("resolving {remote}"))?
        .next()
        .with_context(|| format!("{remote} resolves to no address"))
}

/// Whether this process may bind a reserved port at all: the first port that binds says yes,
/// permission denied says no, and a port in use (other connections hold them) says nothing.
pub fn reserved_ports_available() -> bool {
    for port in (wire::RESERVED_LOW..=wire::RESERVED_HIGH).rev() {
        match std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)) {
            Ok(_) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return false,
            Err(_) => continue,
        }
    }
    // Every one is held by another socket, which an unprivileged process could not have done.
    true
}

/// What one command produced.
#[derive(Debug, Default)]
pub struct Outcome {
    pub accepted: bool,
    pub error: Option<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
    pub source_port: u16,
    pub reserved_source_port: bool,
}

/// Read one capped stream to EOF; true when it was cut at the cap.
async fn collect<R: AsyncRead + Unpin>(r: &mut R, into: &mut Vec<u8>) -> bool {
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => {
                let room = crate::server::rsh::MAX_OUTPUT - into.len();
                into.extend_from_slice(&buf[..n.min(room)]);
                if n > room {
                    return true;
                }
            }
        }
    }
}

/// Run one command: connect (from a reserved port when possible), open a listener for the
/// stderr connection when asked, send every field at once, read the status byte, then both
/// streams to their end. `fields` are the two fields between the stderr port and the command:
/// rsh's client and server user, rexec's user and password.
pub async fn run_command(
    target: SocketAddr,
    service: Service,
    fields: [&str; 2],
    command: &str,
    stdin: Option<&str>,
    want_stderr: bool,
) -> Result<Outcome> {
    let (stream, reserved) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        wire::connect_maybe_reserved(target, service == Service::Rsh),
    )
    .await
    .with_context(|| format!("connecting to {target} timed out"))?
    .with_context(|| format!("connecting to {target}"))?;
    let local = stream.local_addr()?;
    let mut outcome = Outcome {
        source_port: local.port(),
        reserved_source_port: reserved,
        ..Default::default()
    };
    let listener = if want_stderr {
        Some(wire::listen_maybe_reserved(local.ip(), service == Service::Rsh).await?)
    } else {
        None
    };
    let port = match &listener {
        Some(l) => l.local_addr()?.port().to_string(),
        None => String::new(),
    };
    let (mut r, mut w) = stream.into_split();
    w.write_all(&wire::encode_fields(&[
        &port, fields[0], fields[1], command,
    ]))
    .await?;

    // The status byte, then (refused) the line after it.
    //
    // inetutils rexecd 2.8, asked for a stderr connection, points its standard error at that
    // connection and *then* writes the status byte to standard error, so the byte arrives on
    // the stderr connection and the main one starts with the command's output (inetutils' own
    // rexec copes by stripping a leading \0 or \1 from whichever stream has it). For rexec
    // with a stderr connection, a main stream that opens with anything else, or ends at
    // once, sends this client to the stderr connection for the status byte.
    let mut status = [0u8; 1];
    let got = tokio::time::timeout(CONNECT_TIMEOUT, r.read(&mut status))
        .await
        .context("the server sent no status byte within 10 s")??;
    let status_on_stderr = service == Service::Rexec && listener.is_some();
    let mut first_stdout: Option<u8> = None;
    match (got, status[0]) {
        (0, _) if status_on_stderr => {}
        (0, _) => bail!("the server closed the connection without answering"),
        (_, wire::STATUS_OK) => outcome.accepted = true,
        (_, wire::STATUS_ERROR) => {
            outcome.error = Some(refusal_from(&mut r).await);
            return Ok(outcome);
        }
        (_, other) if status_on_stderr => first_stdout = Some(other),
        (_, other) => bail!("not an r-service answer: status byte 0x{other:02x}"),
    }

    // The server opened the stderr connection before it answered; accept it, from the
    // server's own address only.
    let mut err_stream: Option<TcpStream> = None;
    if let Some(listener) = listener {
        let accepted = tokio::time::timeout(wire::STDERR_CONNECT_TIMEOUT, async {
            loop {
                let (s, from) = listener.accept().await?;
                // A daemon connects back from INADDR_ANY, so on loopback it leaves from
                // 127.0.0.1 whichever 127/8 address the client dialled.
                let loopback = from.ip().is_loopback() && target.ip().is_loopback();
                if from.ip() == target.ip() || loopback {
                    return Ok::<_, std::io::Error>(s);
                }
            }
        })
        .await;
        match accepted {
            Ok(Ok(s)) => err_stream = Some(s),
            _ => {
                outcome.error = Some("the server never opened the stderr connection".into());
            }
        }
    }
    if !outcome.accepted {
        // The status byte did not come on the main connection: it must open the stderr one.
        let Some(err) = err_stream.as_mut() else {
            bail!("the server sent no status byte and no stderr connection");
        };
        let mut byte = [0u8; 1];
        let got = tokio::time::timeout(CONNECT_TIMEOUT, err.read(&mut byte))
            .await
            .context("the server sent no status byte within 10 s")??;
        match (got, byte[0]) {
            (1, wire::STATUS_OK) => outcome.accepted = true,
            (1, wire::STATUS_ERROR) => {
                outcome.error = Some(refusal_from(err).await);
                return Ok(outcome);
            }
            (0, _) => bail!("the server closed the connection without answering"),
            (_, other) => bail!("not an r-service answer: status byte 0x{other:02x}"),
        }
    }

    if let Some(text) = stdin {
        w.write_all(text.as_bytes()).await?;
    }
    let _ = w.shutdown().await;
    let mut stdout: Vec<u8> = first_stdout.into_iter().collect();
    let mut stderr = Vec::new();
    let read_all = async {
        let out = collect(&mut r, &mut stdout);
        let err = async {
            match err_stream.as_mut() {
                Some(s) => collect(s, &mut stderr).await,
                None => false,
            }
        };
        let (a, b) = tokio::join!(out, err);
        a || b
    };
    match tokio::time::timeout(COMMAND_TIMEOUT, read_all).await {
        Ok(cut) => outcome.truncated = cut,
        Err(_) => {
            outcome.truncated = true;
            outcome.error = Some(format!(
                "the command was still running after {}s; output so far",
                COMMAND_TIMEOUT.as_secs()
            ));
        }
    }
    outcome.stdout = stdout;
    outcome.stderr = stderr;
    Ok(outcome)
}

/// The refusal line after a `\1`: up to a newline, at most [`wire::MAX_ERROR_LINE`] bytes,
/// within [`CONNECT_TIMEOUT`].
async fn refusal_from<R: AsyncRead + Unpin>(r: &mut R) -> String {
    let mut line = Vec::new();
    let read = tokio::time::timeout(CONNECT_TIMEOUT, async {
        let mut buf = [0u8; 256];
        loop {
            if let Some(text) = wire::refusal_line(&line, false) {
                return text;
            }
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => return wire::refusal_line(&line, true).unwrap_or_default(),
                Ok(n) => line.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    read.unwrap_or_else(|_| wire::refusal_line(&line, true).unwrap_or_default())
}

/// An rsh or rexec client: ready at once, then one connection per command.
pub async fn connect_exec(ctx: ConnectContext, service: Service) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let string = |key: &str| -> Result<Option<String>> {
        Ok(params
            .map(|p| p.get_optional_string(key))
            .transpose()?
            .flatten())
    };
    let want_stderr = params
        .map(|p| p.get_optional_bool("stderr"))
        .transpose()?
        .flatten()
        .unwrap_or(true);
    let (first, second, shown_user) = match service {
        Service::Rsh => {
            let local = string("local_user")?.unwrap_or_else(current_user);
            let remote = string("remote_user")?.unwrap_or_else(|| local.clone());
            (local, remote.clone(), remote)
        }
        Service::Rexec => {
            let user = string("user")?.context("the user startup parameter is required")?;
            let password =
                string("password")?.context("the password startup parameter is required")?;
            (user.clone(), password, user)
        }
    };
    wire::check_field(&first, wire::MAX_USER, "the user")?;
    wire::check_field(
        &second,
        wire::MAX_PASSWORD.max(wire::MAX_USER),
        "the second field",
    )?;
    let target = resolve(&ctx.remote_addr).await?;

    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<(Value, usize)>(32);
    let (event_tx, event_rx) = mpsc::channel::<(Event, usize)>(32);
    let connected = match service {
        Service::Rsh => json!({
            "remote_addr": target.to_string(),
            "local_user": first,
            "remote_user": second,
            "reserved_ports": reserved_ports_available(),
        }),
        Service::Rexec => json!({"remote_addr": target.to_string(), "user": first}),
    };
    event_tx.try_send((Event::new(service.connected(), connected), 0))?;
    let dispatcher = spawn_dispatcher(&ctx, service.protocol(), event_rx, internal_tx).await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let session = ExecSession {
            ctx: &session_ctx,
            service,
            target,
            fields: [first, second],
            shown_user,
            want_stderr,
        };
        let result = session.run(external, internal_rx, event_tx).await;
        dispatcher.abort();
        finish_client(&session_ctx, service.name(), result).await;
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    // No connection stays open between commands, so there is no local address to report (the
    // HTTP client's convention).
    Ok(SocketAddr::from(([0, 0, 0, 0], 0)))
}

/// Mark a client's end in its status.
async fn finish_client(ctx: &ConnectContext, name: &str, result: Result<()>) {
    let status = match result {
        Ok(()) => ClientStatus::Disconnected,
        Err(e) => {
            Log::new(Some(&ctx.status_tx)).warn(format!("{name} client ended: {e:#}"));
            ClientStatus::Error(e.to_string())
        }
    };
    ctx.state.update_client_status(ctx.client_id, status).await;
    ctx.state.remove_client_handle(ctx.client_id).await;
    let _ = ctx.status_tx.send("__UPDATE_UI__".into());
}

/// Events in, the model (or a handler) asked, its actions out to the session with the depth
/// they were produced at. A failed call sends nothing: fail closed.
pub(crate) async fn spawn_dispatcher(
    ctx: &ConnectContext,
    protocol: Arc<dyn Client>,
    mut events: mpsc::Receiver<(Event, usize)>,
    actions_tx: mpsc::Sender<(Value, usize)>,
) -> tokio::task::AbortHandle {
    let task = tokio::spawn({
        let ctx = ctx.clone();
        async move {
            while let Some((event, depth)) = events.recv().await {
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
                    protocol.as_ref(),
                    &ctx.status_tx,
                )
                .await
                {
                    Ok(result) => {
                        if let Some(memory) = result.memory_updates {
                            ctx.state.set_memory_for_client(ctx.client_id, memory).await;
                        }
                        for action in result.actions {
                            if actions_tx.send((action, depth + 1)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!(
                        "{} client handler failed (nothing sent): {e}",
                        protocol.protocol_name()
                    )),
                }
            }
        }
    });
    let abort = task.abort_handle();
    ctx.state.register_client_task(ctx.client_id, task).await;
    abort
}

struct ExecSession<'a> {
    ctx: &'a ConnectContext,
    service: Service,
    target: SocketAddr,
    fields: [String; 2],
    shown_user: String,
    want_stderr: bool,
}

impl ExecSession<'_> {
    async fn run(
        &self,
        mut external: mpsc::Receiver<ClientCommand>,
        mut internal: mpsc::Receiver<(Value, usize)>,
        events: mpsc::Sender<(Event, usize)>,
    ) -> Result<()> {
        let log = Log::new(Some(&self.ctx.status_tx));
        let protocol = self.service.protocol();
        let name = self.service.name();
        loop {
            let (action, depth, mut injected) = tokio::select! {
                command = external.recv() => match command {
                    Some(c) => (c.action.clone(), 0, Some(c)),
                    None => return Ok(()),
                },
                action = internal.recv() => match action {
                    Some((a, depth)) => (a, depth, None),
                    None => return Ok(()),
                },
            };
            let reply = |injected: &mut Option<ClientCommand>,
                         outcome: Result<ClientSendOutcome>| {
                if let Some(command) = injected.take() {
                    crate::client::command_support::reply(command, outcome);
                }
            };
            match protocol.execute_action(action.clone()) {
                Ok(ClientActionResult::Disconnect) => {
                    reply(&mut injected, Ok(ClientSendOutcome::Disconnected));
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) => {
                    log.warn(format!("{name} client action refused: {e:#}"));
                    reply(
                        &mut injected,
                        Ok(ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        }),
                    );
                    continue;
                }
            }
            if depth > MAX_FOLLOWUP_DEPTH {
                log.warn(format!(
                    "{name} client: handler chain stopped after {MAX_FOLLOWUP_DEPTH} follow-ups"
                ));
                continue;
            }
            let (command, stdin) = actions::run_fields(&action)?;
            if injected.is_some() {
                self.ctx
                    .state
                    .record_access_log(
                        AccessLogOwner::Client(self.ctx.client_id.as_u32()),
                        name,
                        None,
                        "injected_action",
                        action.clone(),
                        vec![],
                    )
                    .await;
            }
            let outcome = run_command(
                self.target,
                self.service,
                [&self.fields[0], &self.fields[1]],
                &command,
                stdin.as_deref(),
                self.want_stderr,
            )
            .await;
            let data = match outcome {
                Ok(o) => {
                    if !o.reserved_source_port && self.service == Service::Rsh {
                        log.warn(format!(
                            "RSH client connected from ordinary port {}: a stock rshd refuses \
                             any source port outside 512-1023",
                            o.source_port
                        ));
                    }
                    let user_key = if self.service == Service::Rsh {
                        "remote_user"
                    } else {
                        "user"
                    };
                    let mut data = json!({
                        "command": command,
                        "accepted": o.accepted,
                        "stdout": text(&o.stdout),
                        "stderr": text(&o.stderr),
                        "truncated": o.truncated,
                        "source_port": o.source_port,
                        "reserved_source_port": o.reserved_source_port,
                    });
                    data[user_key] = json!(self.shown_user);
                    if let Some(e) = o.error {
                        data["error"] = json!(e);
                    }
                    data
                }
                Err(e) => json!({
                    "command": command,
                    "accepted": false,
                    "error": format!("{e:#}"),
                    "stdout": "",
                    "stderr": "",
                    "truncated": false,
                    "source_port": 0,
                    "reserved_source_port": false,
                }),
            };
            reply(
                &mut injected,
                Ok(ClientSendOutcome::Executed {
                    detail: data.to_string(),
                }),
            );
            anyhow::ensure!(
                events
                    .try_send((Event::new(self.service.result(), data), depth))
                    .is_ok(),
                "{name} event queue full; consumer stalled"
            );
        }
    }
}

/// A stream's text for the model: lossy UTF-8, escape sequences and controls but newline and
/// tab removed.
pub fn text(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes).replace("\r\n", "\n");
    crate::utils::sanitize::multiline(&s)
}

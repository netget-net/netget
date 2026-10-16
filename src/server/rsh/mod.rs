//! The BSD r-services: rsh (514), rexec (512) and rlogin (513, in [`rlogin`]).
//!
//! One module because the three are one protocol family: the same NUL-terminated handshake
//! (`rcmd(3)`'s), the same `\0` / `\1 text\n` status byte, the same optional second connection
//! for standard error that the server opens back to the client, and the same reserved-port
//! trust model. [`wire`] holds all of that once, for both roles; this file holds the accept
//! loop the three servers share and the one-shot command session rsh and rexec share. rlogin's
//! interactive session lives in its own directory because it is the one of the three a person
//! types into, so it alone takes a peer handle.
//!
//! What Rust decides: every byte of the handshake and its bounds, rexec's password (checked
//! against the configured `accounts`, never shown to the model), where the stderr connection
//! goes (the client's own address and nothing else), and the status byte. What the model
//! decides: whether an rsh request is trusted and what the command prints, what an rexec
//! command prints, and whether an rlogin is trusted, needs a password or is refused, then the
//! whole session. A model that fails or says nothing is answered `\1` with a fixed line and the
//! connection closes: nothing runs as though it had been trusted.
//!
//! These protocols send passwords in clear text and trust source addresses and source ports.
//! That is what they are; NetGet implements them so they can be studied and mocked, not as a
//! way to make them safe.
pub mod actions;
pub mod rlogin;
pub mod wire;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::{ActionResult, Server};
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS};
use crate::server::connection::ConnectionId;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use anyhow::Result;
use serde_json::json;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// After the answer, how long the client is given to close its end before the connection is
/// dropped. Closing with unread input queued makes the kernel send a reset, which can destroy
/// output the client has not read yet, so the server half-closes and reads to EOF first.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// What the drain will read (stdin the command never asked for) before giving up.
pub const DRAIN_MAX_BYTES: usize = 256 * 1024;
/// The largest standard output, and separately standard error, one answer may carry.
pub const MAX_OUTPUT: usize = 1024 * 1024;

/// One accepted connection, already recorded on the server.
pub struct Conn {
    pub ctx: SpawnContext,
    pub stream: TcpStream,
    pub remote: SocketAddr,
    pub local: SocketAddr,
    pub id: ConnectionId,
}

/// The accept loop the three servers share: bind (the caller's host and port), admit up to
/// [`DEFAULT_MAX_CONNECTIONS`], record each connection, hand it to `handler`, and mark it
/// closed when the handler returns. Every task is registered, so stopping the server stops
/// every connection with it.
pub async fn serve<H, F>(ctx: SpawnContext, name: &'static str, handler: H) -> Result<SocketAddr>
where
    H: Fn(Conn) -> F + Send + Sync + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    #[allow(deprecated)]
    let listen = ctx.socket_addr().unwrap_or(ctx.legacy_listen_addr());
    let listener = crate::server::socket_helpers::create_reusable_tcp_listener(listen).await?;
    let local = listener.local_addr()?;
    Log::new(Some(&ctx.status_tx)).info(format!("{name} server listening on {local}"));
    let state = ctx.state.clone();
    let server_id = ctx.server_id;
    let handler = Arc::new(handler);
    let accept = tokio::spawn(async move {
        let limiter = ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
        loop {
            // No refusal text: past the cap the peer is closed before its handshake, which an
            // r-service client reports as the connection dropping.
            let (stream, remote, permit) =
                match accept_bounded(&listener, &limiter, b"", name, Some(&ctx.status_tx)).await {
                    Ok(v) => v,
                    Err(e) => {
                        Log::new(Some(&ctx.status_tx)).error(format!("{name} accept failed: {e}"));
                        break;
                    }
                };
            let ctx = ctx.clone();
            let handler = handler.clone();
            let owner = ctx.state.clone();
            owner
                .spawn_server_task(server_id, async move {
                    let _permit = permit;
                    let id = ConnectionId::new(ctx.state.get_next_unified_id().await);
                    let local_conn = stream.local_addr().unwrap_or(local);
                    let now = crate::utils::clock::Instant::now();
                    ctx.state
                        .add_connection_to_server(
                            ctx.server_id,
                            ConnectionState {
                                id,
                                remote_addr: remote,
                                local_addr: local_conn,
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
                    let state = ctx.state.clone();
                    let status_tx = ctx.status_tx.clone();
                    handler(Conn {
                        ctx,
                        stream,
                        remote,
                        local: local_conn,
                        id,
                    })
                    .await;
                    state.remove_peer_handle(server_id, id.as_u32()).await;
                    state.close_connection_on_server(server_id, id).await;
                    let _ = status_tx.send("__UPDATE_UI__".into());
                })
                .await;
        }
    });
    state.register_server_task(server_id, accept).await;
    Ok(local)
}

/// Why reading the handshake stopped.
#[derive(Debug)]
pub enum FieldError {
    /// The peer closed before the field ended.
    Eof,
    /// More bytes than the field's cap, with no NUL.
    TooLong,
    /// [`wire::HANDSHAKE_TIMEOUT`] passed.
    TimedOut,
    Io(std::io::Error),
}

/// Reads the handshake's NUL-terminated fields, each against its own cap. Bytes past the last
/// field (an rlogin client's first keystrokes, say) stay in [`FieldReader::rest`].
#[derive(Default)]
pub struct FieldReader {
    buf: Vec<u8>,
}

impl FieldReader {
    pub async fn next<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        max: usize,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<Vec<u8>, FieldError> {
        loop {
            match wire::split_field(&self.buf, max) {
                wire::FieldScan::Complete(n) => {
                    let field = self.buf[..n].to_vec();
                    self.buf.drain(..=n);
                    return Ok(field);
                }
                wire::FieldScan::TooLong => return Err(FieldError::TooLong),
                wire::FieldScan::NeedMore => {}
            }
            let mut chunk = [0u8; 1024];
            let n = tokio::time::timeout_at(deadline, r.read(&mut chunk))
                .await
                .map_err(|_| FieldError::TimedOut)?
                .map_err(FieldError::Io)?;
            if n == 0 {
                return Err(FieldError::Eof);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// What arrived after the last field read.
    pub fn rest(self) -> Vec<u8> {
        self.buf
    }
}

/// Lossy text of a peer's field, with every control character replaced: a user name or
/// terminal type is one line.
pub fn field_text(field: &[u8]) -> String {
    crate::utils::sanitize::line_field(&String::from_utf8_lossy(field))
}

/// Open the stderr connection back to the client: to the address the main connection came
/// from and the port it named, never anywhere else, from a reserved port when this process may
/// bind one (`rcmd(3)` refuses a stderr connection from any other).
pub async fn connect_stderr(remote: SocketAddr, port: u16) -> std::io::Result<(TcpStream, bool)> {
    let target = SocketAddr::new(remote.ip(), port);
    tokio::time::timeout(
        wire::STDERR_CONNECT_TIMEOUT,
        wire::connect_maybe_reserved(target, true),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "stderr connect timed out"))?
}

/// Write `bytes`, half-close, then read the peer's side to EOF (bounded) so closing never
/// resets a connection whose output the client has not read yet.
pub async fn finish<R, W>(r: &mut R, w: &mut W, bytes: &[u8])
where
    R: AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    if !bytes.is_empty() {
        let _ = w.write_all(bytes).await;
    }
    let _ = w.flush().await;
    let _ = w.shutdown().await;
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, async {
        let mut buf = [0u8; 4096];
        let mut total = 0usize;
        while total < DRAIN_MAX_BYTES {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
    })
    .await;
}

/// Which one-shot service a connection is speaking.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExecService {
    Rsh,
    Rexec,
}

impl ExecService {
    pub fn name(self) -> &'static str {
        match self {
            Self::Rsh => "RSH",
            Self::Rexec => "REXEC",
        }
    }
}

/// One account rexec (and rlogin's password prompt) will accept.
#[derive(Clone)]
pub struct Account {
    pub user: String,
    pub password: String,
}

/// The `accounts` startup parameter: `[{"user": "alice", "password": "…"}]`.
pub fn parse_accounts(ctx: &SpawnContext) -> Result<Arc<Vec<Account>>> {
    let list = ctx
        .startup_params
        .as_ref()
        .map(|p| p.get_optional_array("accounts"))
        .transpose()?
        .flatten();
    let mut accounts = Vec::new();
    if let Some(list) = list {
        for entry in list {
            let user = entry["user"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("each account needs a user (a string)"))?;
            let password = entry["password"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("each account needs a password (a string)"))?;
            wire::check_field(user, wire::MAX_USER, "an account's user")?;
            wire::check_field(password, wire::MAX_PASSWORD, "an account's password")?;
            accounts.push(Account {
                user: user.to_string(),
                password: password.to_string(),
            });
        }
    }
    Ok(Arc::new(accounts))
}

/// Compare without stopping at the first difference, so the time a refusal takes says nothing
/// about how much of the password was right.
fn same(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

/// Whether `user`/`password` is one of `accounts`. Every account is compared, matched or not.
pub fn authenticate(accounts: &[Account], user: &[u8], password: &[u8]) -> bool {
    let mut ok = false;
    for a in accounts {
        ok |= same(a.user.as_bytes(), user) & same(a.password.as_bytes(), password);
    }
    ok
}

/// The model's answer to a command.
enum Answer {
    Output { stdout: String, stderr: String },
    Refuse(String),
}

/// One rsh or rexec connection: handshake, the decision, the answer, close.
pub async fn exec_connection(
    conn: Conn,
    service: ExecService,
    protocol: Arc<dyn Server>,
    accounts: Arc<Vec<Account>>,
) {
    let Conn {
        ctx,
        stream,
        remote,
        id,
        ..
    } = conn;
    let log = Log::new(Some(&ctx.status_tx));
    let name = service.name();
    let subject = format!("{name} request from {remote} (connection {id})");
    let (mut r, mut w) = stream.into_split();
    let deadline = tokio::time::Instant::now() + wire::HANDSHAKE_TIMEOUT;
    let mut fields = FieldReader::default();

    // The stderr port comes first, and the connection back has to be made before the other
    // fields are read: `rcmd(3)` waits in accept() before it sends them.
    let port = match fields.next(&mut r, wire::MAX_PORT_FIELD, deadline).await {
        Ok(f) => wire::parse_port(&f),
        Err(e) => {
            refuse_handshake(&log, &subject, "stderr port", e, &mut r, &mut w, false).await;
            return;
        }
    };
    let port = match port {
        Ok(p) => p,
        Err(why) => {
            log.warn(format!("{subject} decision=refused_bad_handshake: {why}"));
            finish(
                &mut r,
                &mut w,
                &wire::refusal(&format!("netget: {why}"), false),
            )
            .await;
            return;
        }
    };
    let mut stderr = None;
    let mut stderr_reserved = false;
    if let Some(p) = port {
        match connect_stderr(remote, p).await {
            Ok((s, reserved)) => {
                stderr_reserved = reserved;
                stderr = Some(s);
            }
            Err(e) => {
                log.warn(format!(
                    "{subject} decision=refused_stderr_unreachable: {}:{p}: {e}",
                    remote.ip()
                ));
                finish(
                    &mut r,
                    &mut w,
                    &wire::refusal("netget: cannot connect to the stderr port", false),
                )
                .await;
                return;
            }
        }
    }

    let (first_max, first_what, second_max, second_what) = match service {
        ExecService::Rsh => (wire::MAX_USER, "client user", wire::MAX_USER, "server user"),
        ExecService::Rexec => (wire::MAX_USER, "user", wire::MAX_PASSWORD, "password"),
    };
    let mut read = Vec::new();
    for (max, what) in [
        (first_max, first_what),
        (second_max, second_what),
        (wire::MAX_COMMAND, "command"),
    ] {
        match fields.next(&mut r, max, deadline).await {
            Ok(f) => read.push(f),
            Err(e) => {
                refuse_handshake(&log, &subject, what, e, &mut r, &mut w, false).await;
                return;
            }
        }
    }
    let command = crate::utils::sanitize::multiline(&String::from_utf8_lossy(&read[2]));
    ctx.state
        .update_connection_stats(
            ctx.server_id,
            id,
            Some(read.iter().map(|f| f.len() as u64 + 1).sum::<u64>()),
            None,
            Some(1),
            None,
        )
        .await;

    let data = match service {
        ExecService::Rsh => json!({
            "client_user": field_text(&read[0]),
            "server_user": field_text(&read[1]),
            "command": command,
            "client_address": remote.ip().to_string(),
            "client_port": remote.port(),
            "reserved_source_port": wire::is_reserved(remote.port()),
            "stderr_channel": stderr.is_some(),
        }),
        ExecService::Rexec => {
            // Checked here, before anything reaches the model: the password is never part of
            // an event, a log line or the access log.
            if accounts.is_empty() {
                log.warn(format!(
                    "{subject} user={} decision=refused_no_accounts: this server has no \
                     accounts configured, so no password can be right",
                    field_text(&read[0])
                ));
                finish(&mut r, &mut w, &wire::refusal("Login incorrect.", false)).await;
                return;
            }
            if !authenticate(&accounts, &read[0], &read[1]) {
                log.warn(format!(
                    "{subject} user={} decision=refused_bad_password",
                    field_text(&read[0])
                ));
                finish(&mut r, &mut w, &wire::refusal("Login incorrect.", false)).await;
                return;
            }
            json!({
                "user": field_text(&read[0]),
                "command": command,
                "client_address": remote.ip().to_string(),
                "client_port": remote.port(),
                "stderr_channel": stderr.is_some(),
            })
        }
    };
    let event_type = match service {
        ExecService::Rsh => &*actions::RSH_COMMAND_EVENT,
        ExecService::Rexec => &*actions::REXEC_COMMAND_EVENT,
    };
    let event = Event::new(event_type, data);
    let answer = match call_llm(
        &ctx.llm_client,
        &ctx.state,
        ctx.server_id,
        Some(id),
        &event,
        protocol.as_ref(),
    )
    .await
    {
        Ok(result) if !result.failures.is_empty() => {
            log.error(format!(
                "{subject} decision=fail_closed_invalid_reply: {}",
                result.failure_summary().unwrap_or_default()
            ));
            None
        }
        Ok(result) => {
            let found = first_answer(result.protocol_results);
            if found.is_none() {
                log.error(format!(
                    "{subject} decision=model_silent: no answer, so nothing runs and the \
                     request is refused"
                ));
            }
            found
        }
        Err(e) => {
            let decision = match crate::utils::WireFailure::classify(&e) {
                crate::utils::WireFailure::Overloaded => "fail_closed_llm_overloaded",
                crate::utils::WireFailure::Unavailable => "fail_closed_llm_error",
            };
            log.error(format!("{subject} decision={decision}: {e}"));
            None
        }
    };
    match answer {
        None => {
            // Fail closed: a refusal with a fixed line. Nothing runs, and the client is told
            // in the protocol's own way that the request did not succeed.
            finish(
                &mut r,
                &mut w,
                &wire::refusal(
                    crate::utils::WireFailure::Unavailable.prefixed_text(),
                    false,
                ),
            )
            .await;
        }
        Some(Answer::Refuse(message)) => {
            log.info(format!("{subject} decision=model_reject"));
            finish(&mut r, &mut w, &wire::refusal(&message, false)).await;
        }
        Some(Answer::Output {
            stdout,
            stderr: err,
        }) => {
            log.info(format!(
                "{subject} decision=model_answer ({} bytes out, {} bytes err{})",
                stdout.len(),
                err.len(),
                if stderr.is_some() {
                    if stderr_reserved {
                        ", stderr connection from a reserved port"
                    } else {
                        ", stderr connection from an ordinary port"
                    }
                } else {
                    ""
                }
            ));
            let _ = w.write_all(&[wire::STATUS_OK]).await;
            let mut main = stdout.into_bytes();
            match stderr.as_mut() {
                Some(s) => {
                    let _ = s.write_all(err.as_bytes()).await;
                    let _ = s.shutdown().await;
                }
                None => main.extend_from_slice(err.as_bytes()),
            }
            ctx.state
                .update_connection_stats(
                    ctx.server_id,
                    id,
                    None,
                    Some(main.len() as u64 + 1),
                    None,
                    Some(1),
                )
                .await;
            finish(&mut r, &mut w, &main).await;
        }
    }
    drop(stderr);
}

/// The first rsh/rexec answer in what the executor returned.
fn first_answer(results: Vec<ActionResult>) -> Option<Answer> {
    let mut stack: Vec<ActionResult> = results.into_iter().rev().collect();
    while let Some(r) = stack.pop() {
        match r {
            ActionResult::Custom { name, data } if name.ends_with("_output") => {
                return Some(Answer::Output {
                    stdout: data["stdout"].as_str().unwrap_or_default().to_string(),
                    stderr: data["stderr"].as_str().unwrap_or_default().to_string(),
                });
            }
            ActionResult::Custom { name, data } if name.ends_with("_refuse") => {
                return Some(Answer::Refuse(
                    data["message"]
                        .as_str()
                        .unwrap_or("Permission denied.")
                        .to_string(),
                ));
            }
            ActionResult::Multiple(items) => stack.extend(items.into_iter().rev()),
            _ => {}
        }
    }
    None
}

/// Refuse a handshake that could not be read: `\1` and the reason for a field that ran past
/// its cap, a quiet close for a peer that hung up or went silent.
async fn refuse_handshake<R, W>(
    log: &Log<'_>,
    subject: &str,
    what: &str,
    e: FieldError,
    r: &mut R,
    w: &mut W,
    crlf: bool,
) where
    R: AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    match e {
        FieldError::TooLong => {
            log.warn(format!(
                "{subject} decision=refused_field_too_long: the {what} field ran past its cap"
            ));
            finish(
                r,
                w,
                &wire::refusal(&format!("netget: {what} too long"), crlf),
            )
            .await;
        }
        FieldError::TimedOut => {
            log.info(format!(
                "{subject} decision=refused_handshake_timeout: no complete {what} within {}s",
                wire::HANDSHAKE_TIMEOUT.as_secs()
            ));
            finish(r, w, &wire::refusal("netget: handshake timed out", crlf)).await;
        }
        FieldError::Eof => {
            log.debug(format!("{subject} closed during the handshake ({what})"));
        }
        FieldError::Io(e) => log.debug(format!("{subject} read failed ({what}): {e}")),
    }
}

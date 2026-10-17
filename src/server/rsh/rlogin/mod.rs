//! rlogin's interactive session (RFC 1282), on the accept loop the r-services share
//! ([`crate::server::rsh::serve`]).
//!
//! A real rlogind hands the session to `login` on a pty in packet mode. There is no pty here, so
//! NetGet stands in for one: it echoes what the user types, edits the line (DEL, ^U, ^C, ^D),
//! sends the urgent control bytes a packet-mode pty would raise (`TIOCPKT_WINDOW` to ask for
//! the window size once the login is accepted, `TIOCPKT_FLUSHWRITE` on ^C), and strips the
//! client's window-size messages out of the keystrokes. The model sees whole lines.
pub mod actions;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::{ActionResult, Server};
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::rsh::{
    authenticate, field_text, finish, wire, Account, Conn, FieldError, FieldReader,
};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use wire::{LineEditor, LineEvent, RloginInput, WindowSize};

/// How long a session that has typed nothing yet may stay silent — the same 300 s a `manual`
/// rule gives a person to answer, because the other end of rlogin is a person.
pub const FIRST_LINE_TIMEOUT: Duration = Duration::from_secs(300);
/// How long an established session may go between keystrokes (telnet's ten minutes, Cisco's
/// `exec-timeout 10 0`).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// Password attempts before the session is closed, as login(1) gives.
pub const MAX_PASSWORD_ATTEMPTS: usize = 3;
/// The largest banner, line or block of text one action may print.
pub const MAX_BANNER: usize = 64 * 1024;

/// What the model decided about a login.
enum Login {
    Trust {
        banner: String,
        prompt: String,
    },
    Password {
        banner: String,
        prompt: String,
        password_prompt: String,
    },
    Refuse(String),
}

/// What the next line read produced.
enum Next {
    Line(String),
    Interrupt,
    Eof,
    TooLong,
    TimedOut,
    Closed,
}

struct Session {
    ctx: crate::protocol::SpawnContext,
    id: crate::server::connection::ConnectionId,
    r: OwnedReadHalf,
    w: Arc<Mutex<OwnedWriteHalf>>,
    input: RloginInput,
    editor: LineEditor,
    queue: VecDeque<LineEvent>,
    window: Option<WindowSize>,
}

impl Session {
    async fn write(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut w = self.w.lock().await;
        let _ = w.write_all(bytes).await;
        let _ = w.flush().await;
        drop(w);
        self.ctx
            .state
            .update_connection_stats(
                self.ctx.server_id,
                self.id,
                None,
                Some(bytes.len() as u64),
                None,
                Some(1),
            )
            .await;
    }

    /// One urgent byte, as a packet-mode pty would raise it.
    async fn urgent(&self, byte: u8) {
        let w = self.w.lock().await;
        let _ = socket2::SockRef::from(w.as_ref()).send_out_of_band(&[byte]);
    }

    /// Bytes that arrived with the handshake or since: window sizes out, keystrokes edited.
    fn absorb(&mut self, bytes: &[u8]) {
        let (data, sizes) = self.input.feed(bytes);
        if let Some(last) = sizes.last() {
            self.window = Some(*last);
            Log::new(Some(&self.ctx.status_tx)).debug(format!(
                "RLOGIN connection {} window {}x{}",
                self.id, last.cols, last.rows
            ));
        }
        self.queue.extend(self.editor.feed(&data));
    }

    async fn next(&mut self, timeout: Duration) -> Next {
        loop {
            while let Some(event) = self.queue.pop_front() {
                match event {
                    LineEvent::Echo(bytes) => self.write(&bytes).await,
                    LineEvent::Line(line) => return Next::Line(line),
                    LineEvent::Interrupt => {
                        self.urgent(wire::TIOCPKT_FLUSHWRITE).await;
                        return Next::Interrupt;
                    }
                    LineEvent::Eof => return Next::Eof,
                    LineEvent::TooLong => return Next::TooLong,
                }
            }
            let mut buf = [0u8; 4096];
            let n = match tokio::time::timeout(timeout, self.r.read(&mut buf)).await {
                Err(_) => return Next::TimedOut,
                Ok(Ok(0)) | Ok(Err(_)) => return Next::Closed,
                Ok(Ok(n)) => n,
            };
            self.ctx
                .state
                .update_connection_stats(
                    self.ctx.server_id,
                    self.id,
                    Some(n as u64),
                    None,
                    Some(1),
                    None,
                )
                .await;
            self.absorb(&buf[..n]);
        }
    }
}

fn text(data: &Value, key: &str, default: &str) -> String {
    data[key].as_str().unwrap_or(default).to_string()
}

/// The first login decision among the executor's results.
fn login_answer(results: Vec<ActionResult>) -> Option<Login> {
    let mut stack: Vec<ActionResult> = results.into_iter().rev().collect();
    while let Some(r) = stack.pop() {
        match r {
            ActionResult::Custom { name, data } => match name.as_str() {
                actions::TRUST => {
                    return Some(Login::Trust {
                        banner: text(&data, "banner", ""),
                        prompt: text(&data, "prompt", ""),
                    })
                }
                actions::ASK_PASSWORD => {
                    return Some(Login::Password {
                        banner: text(&data, "banner", ""),
                        prompt: text(&data, "prompt", ""),
                        password_prompt: text(&data, "password_prompt", "Password: "),
                    })
                }
                actions::REFUSE => {
                    return Some(Login::Refuse(text(&data, "message", "Permission denied.")))
                }
                _ => {}
            },
            ActionResult::Multiple(items) => stack.extend(items.into_iter().rev()),
            _ => {}
        }
    }
    None
}

/// One rlogin connection, from the handshake to the end of the session.
pub async fn session(conn: Conn, accounts: Arc<Vec<Account>>) {
    let Conn {
        ctx,
        stream,
        remote,
        id,
        ..
    } = conn;
    let log = Log::new(Some(&ctx.status_tx));
    let subject = format!("RLOGIN session from {remote} (connection {id})");
    let (mut r, mut w) = stream.into_split();
    let deadline = tokio::time::Instant::now() + wire::HANDSHAKE_TIMEOUT;
    let mut fields = FieldReader::default();
    let mut read = Vec::new();
    for (max, what) in [
        (wire::MAX_PORT_FIELD, "leading NUL"),
        (wire::MAX_USER, "client user"),
        (wire::MAX_USER, "server user"),
        (wire::MAX_TERMINAL, "terminal"),
    ] {
        match fields.next(&mut r, max, deadline).await {
            Ok(f) => read.push(f),
            Err(e) => {
                handshake_failed(&log, &subject, what, e, &mut r, &mut w).await;
                return;
            }
        }
    }
    // rlogin opens with an empty stderr-port field: the leading NUL.
    if !read[0].is_empty() {
        log.warn(format!(
            "{subject} decision=refused_bad_handshake: a stderr port where rlogin sends none \
             (an rsh client on the rlogin port?)"
        ));
        finish(
            &mut r,
            &mut w,
            &wire::refusal("netget: rlogin takes no stderr port", true),
        )
        .await;
        return;
    }
    let client_user = field_text(&read[1]);
    let server_user = field_text(&read[2]);
    let (terminal, speed) = wire::parse_terminal(&field_text(&read[3]));
    let protocol: Arc<dyn Server> = Arc::new(actions::RloginProtocol);

    let event = Event::new(
        &actions::LOGIN_EVENT,
        json!({
            "client_user": client_user,
            "server_user": server_user,
            "terminal": terminal,
            "speed": speed,
            "client_address": remote.ip().to_string(),
            "client_port": remote.port(),
            "reserved_source_port": wire::is_reserved(remote.port()),
        }),
    );
    let login = match call_llm(
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
            let found = login_answer(result.protocol_results);
            if found.is_none() {
                log.error(format!(
                    "{subject} decision=model_silent: no login decision, so the login is refused"
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
    let (banner, prompt, password_prompt) = match login {
        None => {
            finish(
                &mut r,
                &mut w,
                &wire::refusal(crate::utils::WireFailure::Unavailable.prefixed_text(), true),
            )
            .await;
            return;
        }
        Some(Login::Refuse(message)) => {
            log.info(format!(
                "{subject} user={server_user} decision=model_reject"
            ));
            finish(&mut r, &mut w, &wire::refusal(&message, true)).await;
            return;
        }
        Some(Login::Trust { banner, prompt }) => {
            log.info(format!(
                "{subject} user={server_user} decision=model_answer (trusted)"
            ));
            (banner, prompt, None)
        }
        Some(Login::Password {
            banner,
            prompt,
            password_prompt,
        }) => {
            log.info(format!(
                "{subject} user={server_user} decision=model_answer (password required)"
            ));
            (banner, prompt, Some(password_prompt))
        }
    };

    let _ = w.write_all(&[wire::STATUS_OK]).await;
    let w = Arc::new(Mutex::new(w));
    let mut s = Session {
        ctx: ctx.clone(),
        id,
        r,
        w: w.clone(),
        input: RloginInput::default(),
        editor: LineEditor::default(),
        queue: VecDeque::new(),
        window: None,
    };
    // The packet-mode pty's first word: "tell me your window size".
    s.urgent(wire::TIOCPKT_WINDOW).await;
    let peer_rx =
        crate::server::peer_support::register_peer_channel(&ctx.state, ctx.server_id, id.as_u32())
            .await;
    crate::server::peer_support::spawn_peer_command_task(
        peer_rx,
        protocol.clone(),
        ctx.state.clone(),
        ctx.server_id,
        id.as_u32(),
        w.clone(),
        ctx.status_tx.clone(),
    );
    s.absorb(&fields.rest());

    if let Some(password_prompt) = password_prompt {
        let mut attempts = 0;
        loop {
            s.write(&wire::crlf(&password_prompt)).await;
            s.editor.echo = false;
            let line = match s.next(FIRST_LINE_TIMEOUT).await {
                Next::Line(l) => l,
                Next::Interrupt => continue,
                _ => {
                    log.info(format!("{subject} ended at the password prompt"));
                    return close(&s).await;
                }
            };
            s.editor.echo = true;
            if authenticate(&accounts, server_user.as_bytes(), line.as_bytes()) {
                log.info(format!("{subject} user={server_user} password accepted"));
                break;
            }
            attempts += 1;
            log.warn(format!(
                "{subject} user={server_user} decision=refused_bad_password (attempt {attempts})"
            ));
            s.write(b"Login incorrect\r\n").await;
            if attempts >= MAX_PASSWORD_ATTEMPTS {
                return close(&s).await;
            }
        }
    }
    s.write(&wire::crlf(&banner)).await;
    s.write(&wire::crlf(&prompt)).await;

    let mut answered = false;
    loop {
        let timeout = if answered {
            IDLE_TIMEOUT
        } else {
            FIRST_LINE_TIMEOUT
        };
        let (line, interrupt) = match s.next(timeout).await {
            Next::Line(l) => (l, false),
            Next::Interrupt => (String::new(), true),
            Next::Eof => {
                log.info(format!("{subject} decision=peer_eof (^D on an empty line)"));
                s.write(b"logout\r\n").await;
                break;
            }
            Next::TooLong => {
                log.warn(format!(
                    "{subject} decision=refused_line_too_long: more than {} bytes",
                    wire::MAX_LINE_BYTES
                ));
                s.write(b"\r\n[netget] line too long\r\n").await;
                break;
            }
            Next::TimedOut => {
                log.info(format!(
                    "{subject} idle for {}s; closing",
                    timeout.as_secs()
                ));
                break;
            }
            Next::Closed => break,
        };
        answered = true;
        let window = s.window.map(|w| json!({"rows": w.rows, "cols": w.cols}));
        let event = Event::new(
            &actions::LINE_EVENT,
            json!({
                "line": crate::utils::sanitize::line_field(&line),
                "user": server_user,
                "terminal": terminal,
                "window": window,
                "interrupt": interrupt,
            }),
        );
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
            Ok(result) => {
                let mut wrote = 0;
                let mut closing = false;
                let mut waited = false;
                let failures = result.failure_summary();
                let mut stack: Vec<ActionResult> =
                    result.protocol_results.into_iter().rev().collect();
                while let Some(item) = stack.pop() {
                    match item {
                        ActionResult::Output(bytes) => {
                            wrote += 1;
                            s.write(&bytes).await;
                        }
                        ActionResult::CloseConnection => closing = true,
                        ActionResult::WaitForMore => waited = true,
                        ActionResult::Custom { name, data } if name == actions::SET_ECHO => {
                            s.editor.echo = data["echo"].as_bool().unwrap_or(true);
                        }
                        ActionResult::Multiple(items) => stack.extend(items.into_iter().rev()),
                        _ => {}
                    }
                }
                if wrote > 0 || closing {
                    log.info(format!(
                        "{subject} decision={} ({wrote} write(s){})",
                        if wrote == 0 {
                            "model_reject"
                        } else {
                            "model_answer"
                        },
                        if closing { ", then close" } else { "" }
                    ));
                } else if let Some(f) = failures {
                    log.error(format!("{subject} decision=fail_closed_bad_action: {f}"));
                } else if waited {
                    log.info(format!("{subject} decision=model_wait_for_more"));
                } else {
                    log.warn(format!(
                        "{subject} decision=model_silent: nothing printed for the line"
                    ));
                }
                if closing {
                    break;
                }
            }
            Err(e) => {
                let failure = crate::utils::WireFailure::classify(&e);
                let decision = if failure.is_overloaded() {
                    "fail_closed_llm_overloaded"
                } else {
                    "fail_closed_llm_error"
                };
                log.error(format!("{subject} decision={decision}: {e}"));
                // A notice on its own line: not a prompt and not the command's output.
                s.write(format!("\r\n[netget] {}\r\n", failure.text()).as_bytes())
                    .await;
            }
        }
    }
    close(&s).await;
}

async fn close(s: &Session) {
    let mut w = s.w.lock().await;
    let _ = w.shutdown().await;
}

async fn handshake_failed(
    log: &Log<'_>,
    subject: &str,
    what: &str,
    e: FieldError,
    r: &mut OwnedReadHalf,
    w: &mut OwnedWriteHalf,
) {
    match e {
        FieldError::TooLong => {
            log.warn(format!(
                "{subject} decision=refused_field_too_long: the {what} field ran past its cap"
            ));
            finish(r, w, &wire::refusal(wire::field_too_long(what), true)).await;
        }
        FieldError::TimedOut => {
            log.info(format!(
                "{subject} decision=refused_handshake_timeout ({what})"
            ));
            finish(r, w, &wire::refusal("netget: handshake timed out", true)).await;
        }
        FieldError::Eof | FieldError::Io(_) => {
            log.debug(format!("{subject} closed during the handshake ({what})"))
        }
    }
}

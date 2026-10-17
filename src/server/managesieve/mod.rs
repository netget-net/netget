//! ManageSieve (RFC 5804) server. Rust owns the line and literal grammar, capabilities, SASL
//! PLAIN and name checks; the handler decides logins and answers every script command.
pub mod actions;
pub mod proto;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS};
use crate::server::connection::ConnectionId;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::utils::clock::Instant;
use anyhow::Result;
use base64::Engine;
use proto::Arg;
use serde_json::{json, Value as Json};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const DEFAULT_EXTENSIONS: &str =
    "fileinto reject envelope vacation imap4flags variables body copy";
pub const DEFAULT_IMPLEMENTATION: &str = "NetGet";
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Once a command has started, the rest of it (a literal included) must arrive within this.
pub const COMMAND_DEADLINE: Duration = Duration::from_secs(60);
pub const MAX_AUTH_FAILURES: u32 = 3;

struct Shared {
    ctx: SpawnContext,
    capabilities: Vec<u8>,
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let mut extensions = DEFAULT_EXTENSIONS.to_owned();
    let mut implementation = DEFAULT_IMPLEMENTATION.to_owned();
    if let Some(p) = ctx.startup_params.as_ref() {
        if let Some(e) = p.get_optional_string("sieve_extensions")? {
            anyhow::ensure!(
                e.len() <= 1024 && !e.contains(['"', '\\', '\r', '\n']),
                "sieve_extensions is plain text up to 1024 bytes"
            );
            extensions = e;
        }
        if let Some(i) = p.get_optional_string("implementation")? {
            anyhow::ensure!(
                i.len() <= 256 && !i.contains(['"', '\\', '\r', '\n']),
                "implementation is plain text up to 256 bytes"
            );
            implementation = i;
        }
    }
    let capabilities = format!(
        "\"IMPLEMENTATION\" \"{implementation}\"\r\n\"SASL\" \"PLAIN\"\r\n\"SIEVE\" \"{extensions}\"\r\n\"VERSION\" \"1.0\"\r\n"
    )
    .into_bytes();
    let listener = tokio::net::TcpListener::bind(ctx.legacy_listen_addr()).await?;
    let local = listener.local_addr()?;
    Log::new(Some(&ctx.status_tx)).info(format!("ManageSieve server on {local}"));
    let shared = Arc::new(Shared {
        ctx: ctx.clone(),
        capabilities,
    });
    let server_id = ctx.server_id;
    let accept = tokio::spawn(async move {
        let limiter = ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
        loop {
            let (stream, peer, permit) = match accept_bounded(
                &listener,
                &limiter,
                b"BYE \"Too many connections\"\r\n",
                "ManageSieve",
                Some(&shared.ctx.status_tx),
            )
            .await
            {
                Ok(v) => v,
                Err(_) => break,
            };
            let id = ConnectionId::new(shared.ctx.state.get_next_unified_id().await);
            let now = Instant::now();
            shared
                .ctx
                .state
                .add_connection_to_server(
                    server_id,
                    ConnectionState {
                        id,
                        remote_addr: peer,
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
            let child = shared.clone();
            shared
                .ctx
                .state
                .spawn_server_task(server_id, async move {
                    let _permit = permit;
                    let mut s = Session {
                        shared: &child,
                        id,
                        stream,
                        buf: Vec::new(),
                        user: None,
                        failures: 0,
                    };
                    if let Err(e) = s.run().await {
                        Log::new(Some(&child.ctx.status_tx))
                            .debug(format!("ManageSieve connection {id}: {e:#}"));
                    }
                    child
                        .ctx
                        .state
                        .update_connection_status(server_id, id, ConnectionStatus::Closed)
                        .await;
                    let _ = child.ctx.status_tx.send("__UPDATE_UI__".into());
                })
                .await;
        }
    });
    ctx.state.register_server_task(server_id, accept).await;
    Ok(local)
}

fn outcome(ctx: &SpawnContext, id: ConnectionId, operation: &str, decision: &str) {
    let summary = format!("ManageSieve connection {id} operation={operation} decision={decision}");
    let log = Log::new(Some(&ctx.status_tx));
    if decision.starts_with("fail_closed_") || decision == "model_silent" {
        log.error(summary);
    } else {
        log.info(summary);
    }
}

struct Session<'a> {
    shared: &'a Shared,
    id: ConnectionId,
    stream: TcpStream,
    buf: Vec<u8>,
    user: Option<String>,
    failures: u32,
}

impl Session<'_> {
    async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.stream.write_all(bytes).await?;
        let ctx = &self.shared.ctx;
        ctx.state
            .update_connection_stats(
                ctx.server_id,
                self.id,
                None,
                Some(bytes.len() as u64),
                None,
                Some(1),
            )
            .await;
        Ok(())
    }

    /// The next command line; None when the client closed or went idle.
    async fn line(&mut self) -> Result<Option<Vec<Arg>>> {
        let mut deadline: Option<tokio::time::Instant> = None;
        loop {
            if let Some((args, used)) = proto::parse(&self.buf)? {
                self.buf.drain(..used);
                let ctx = &self.shared.ctx;
                ctx.state
                    .update_connection_stats(
                        ctx.server_id,
                        self.id,
                        Some(used as u64),
                        None,
                        Some(1),
                        None,
                    )
                    .await;
                return Ok(Some(args));
            }
            let limit = *deadline.get_or_insert_with(|| {
                tokio::time::Instant::now()
                    + if self.buf.is_empty() {
                        IDLE_TIMEOUT
                    } else {
                        COMMAND_DEADLINE
                    }
            });
            let mut chunk = [0u8; 16 * 1024];
            let n = match tokio::time::timeout_at(limit, self.stream.read(&mut chunk)).await {
                Ok(r) => r?,
                Err(_) if self.buf.is_empty() => {
                    self.write(&proto::status("BYE", None, "Idle timeout"))
                        .await
                        .ok();
                    return Ok(None);
                }
                Err(_) => anyhow::bail!("a command stalled"),
            };
            if n == 0 {
                return Ok(None);
            }
            if self.buf.is_empty() {
                deadline = Some(tokio::time::Instant::now() + COMMAND_DEADLINE);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn ask(&mut self, event: Event, operation: &str) -> Result<Json, ()> {
        let ctx = &self.shared.ctx;
        let result = match call_llm(
            &ctx.llm_client,
            &ctx.state,
            ctx.server_id,
            Some(self.id),
            &event,
            &actions::ManageSieveProtocol,
        )
        .await
        {
            Ok(r) => r,
            Err(_) => {
                outcome(ctx, self.id, operation, "fail_closed_llm_error");
                return Err(());
            }
        };
        let mut answers = Vec::new();
        let mut pending = result.protocol_results;
        while let Some(r) = pending.pop() {
            match r {
                ActionResult::Custom { data, .. } => answers.push(data),
                ActionResult::Multiple(items) => pending.extend(items),
                _ => {}
            }
        }
        match (result.failures.is_empty(), answers.len()) {
            (true, 1) => Ok(answers.remove(0)),
            (true, 0) => {
                outcome(ctx, self.id, operation, "model_silent");
                Err(())
            }
            _ => {
                outcome(ctx, self.id, operation, "fail_closed_invalid_reply");
                Err(())
            }
        }
    }

    async fn run(&mut self) -> Result<()> {
        let mut greeting = self.shared.capabilities.clone();
        greeting.extend(proto::status("OK", None, "NetGet ManageSieve ready."));
        self.write(&greeting).await?;
        loop {
            let args = match self.line().await {
                Ok(Some(a)) => a,
                Ok(None) => return Ok(()),
                Err(e) => {
                    outcome(&self.shared.ctx, self.id, "parse", "protocol_refusal");
                    self.write(&proto::status("BYE", None, "Protocol error"))
                        .await
                        .ok();
                    return Err(e);
                }
            };
            let Some(Arg::Atom(command)) = args.first() else {
                self.write(&proto::status("NO", None, "Expected a command"))
                    .await?;
                continue;
            };
            let command = command.to_ascii_uppercase();
            let rest = &args[1..];
            match command.as_str() {
                "CAPABILITY" => {
                    let mut out = self.shared.capabilities.clone();
                    out.extend(proto::status("OK", None, "Capability completed."));
                    self.write(&out).await?;
                }
                "NOOP" => {
                    let reply = match rest.first().and_then(Arg::bytes) {
                        Some(tag) => {
                            let mut code = b"TAG ".to_vec();
                            code.extend(proto::string(tag, false));
                            proto::status("OK", Some(&String::from_utf8_lossy(&code)), "Done")
                        }
                        None => proto::status("OK", None, "Done"),
                    };
                    self.write(&reply).await?;
                }
                "LOGOUT" => {
                    self.write(&proto::status("OK", None, "Logout completed."))
                        .await?;
                    return Ok(());
                }
                "STARTTLS" => {
                    self.write(&proto::status("NO", None, "STARTTLS is not available"))
                        .await?
                }
                "AUTHENTICATE" => {
                    if !self.authenticate(rest).await? {
                        return Ok(());
                    }
                }
                "UNAUTHENTICATE" if self.user.is_some() => {
                    self.user = None;
                    self.write(&proto::status("OK", None, "Unauthenticate completed."))
                        .await?;
                }
                "LISTSCRIPTS" | "GETSCRIPT" | "PUTSCRIPT" | "CHECKSCRIPT" | "SETACTIVE"
                | "DELETESCRIPT" | "RENAMESCRIPT" | "HAVESPACE" => match self.user.clone() {
                    None => {
                        self.write(&proto::status("NO", None, "Authenticate first"))
                            .await?
                    }
                    Some(user) => self.script_command(&user, &command, rest).await?,
                },
                _ => {
                    self.write(&proto::status("NO", None, "Unknown command"))
                        .await?
                }
            }
        }
    }

    /// Ok(false) when the connection should close.
    async fn authenticate(&mut self, args: &[Arg]) -> Result<bool> {
        if self.user.is_some() {
            self.write(&proto::status("NO", None, "Already authenticated"))
                .await?;
            return Ok(true);
        }
        let mechanism = args.first().and_then(Arg::text).unwrap_or_default();
        if !mechanism.eq_ignore_ascii_case("PLAIN") {
            self.write(&proto::status("NO", None, "Unsupported SASL mechanism"))
                .await?;
            return Ok(true);
        }
        let response = match args.get(1) {
            Some(r) => r.text(),
            None => {
                self.write(b"\"\"\r\n").await?;
                match self.line().await? {
                    Some(a) => a.first().and_then(Arg::text),
                    None => return Ok(false),
                }
            }
        };
        let Some(response) = response else {
            self.write(&proto::status("NO", None, "Expected a SASL response"))
                .await?;
            return Ok(true);
        };
        if response == "*" {
            self.write(&proto::status("NO", None, "Authentication cancelled"))
                .await?;
            return Ok(true);
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(response.trim())
            .ok();
        let parts: Option<Vec<String>> = decoded.and_then(|d| {
            let p: Vec<&[u8]> = d.split(|b| *b == 0).collect();
            (p.len() == 3).then(|| {
                p.iter()
                    .map(|x| String::from_utf8_lossy(x).into_owned())
                    .collect()
            })
        });
        let Some(parts) = parts.filter(|p| !p[1].is_empty()) else {
            outcome(&self.shared.ctx, self.id, "auth", "protocol_refusal");
            self.write(&proto::status("NO", None, "Malformed SASL PLAIN response"))
                .await?;
            return Ok(true);
        };
        let mut data = json!({"user": parts[1], "password": parts[2]});
        if !parts[0].is_empty() && parts[0] != parts[1] {
            data["authorize_as"] = json!(parts[0]);
        }
        let answer = self
            .ask(Event::new(&actions::AUTH_EVENT, data), "auth")
            .await;
        match answer {
            Ok(a) if a["type"] == "managesieve_ok" => {
                outcome(&self.shared.ctx, self.id, "auth", "model_answer");
                self.user = Some(if parts[0].is_empty() {
                    parts[1].clone()
                } else {
                    parts[0].clone()
                });
                self.write(&proto::status(
                    "OK",
                    None,
                    a["message"].as_str().unwrap_or("Logged in."),
                ))
                .await?;
            }
            other => {
                if other.is_ok() {
                    outcome(&self.shared.ctx, self.id, "auth", "model_reject");
                }
                self.failures += 1;
                if self.failures >= MAX_AUTH_FAILURES {
                    self.write(&proto::status("BYE", None, "Too many failed logins"))
                        .await?;
                    return Ok(false);
                }
                let code = if other.is_err() {
                    Some("TRYLATER")
                } else {
                    None
                };
                self.write(&proto::status("NO", code, "Authentication failed"))
                    .await?;
            }
        }
        Ok(true)
    }

    /// The event data for a script command, or the refusal it gets without asking anyone:
    /// `(reply text, whether the refusal is logged as protocol_refusal)`.
    fn script_event(user: &str, command: &str, args: &[Arg]) -> Result<Json, (String, bool)> {
        let (want, names, script, size): (usize, usize, bool, bool) = match command {
            "LISTSCRIPTS" => (0, 0, false, false),
            "GETSCRIPT" | "DELETESCRIPT" | "SETACTIVE" => (1, 1, false, false),
            "PUTSCRIPT" => (2, 1, true, false),
            "CHECKSCRIPT" => (1, 0, true, false),
            "RENAMESCRIPT" => (2, 2, false, false),
            _ => (2, 1, false, true),
        };
        if args.len() != want || args[..names].iter().any(|a| a.bytes().is_none()) {
            return Err((format!("{command} takes {want} argument(s)"), false));
        }
        let mut data = json!({"user": user, "command": command});
        for (i, key) in ["name", "new_name"].iter().enumerate().take(names) {
            let raw = args[i].bytes().unwrap_or_default();
            let deactivate = command == "SETACTIVE" && raw.is_empty();
            if !deactivate && !proto::valid_name(raw) {
                return Err(("Invalid script name".into(), true));
            }
            data[*key] = json!(String::from_utf8_lossy(raw));
        }
        if script {
            match args
                .last()
                .and_then(Arg::bytes)
                .map(|b| String::from_utf8(b.to_vec()))
            {
                Some(Ok(text)) => data["script"] = json!(text),
                _ => return Err(("The script is not a UTF-8 string".into(), true)),
            }
        }
        if size {
            match args.get(1) {
                Some(Arg::Number(n)) => data["size"] = json!(n),
                _ => return Err(("HAVESPACE takes a name and a number".into(), false)),
            }
        }
        Ok(data)
    }

    /// The reply to a script command the handler answered (or failed to).
    fn script_reply(&self, command: &str, answer: Result<Json, ()>) -> Vec<u8> {
        let ctx = &self.shared.ctx;
        let operation = command.to_ascii_lowercase();
        match answer {
            Err(()) => proto::status("NO", Some("TRYLATER"), "The server cannot answer right now"),
            Ok(a) => match (a["type"].as_str().unwrap_or_default(), command) {
                ("managesieve_no", _) => {
                    outcome(ctx, self.id, &operation, "model_reject");
                    proto::status(
                        "NO",
                        a["code"].as_str(),
                        a["message"].as_str().unwrap_or("Failed"),
                    )
                }
                ("managesieve_scripts", "LISTSCRIPTS") => {
                    outcome(ctx, self.id, &operation, "model_answer");
                    let mut out = Vec::new();
                    for s in a["scripts"].as_array().into_iter().flatten() {
                        out.extend(proto::string(
                            s["name"].as_str().unwrap_or_default().as_bytes(),
                            false,
                        ));
                        if s["active"] == true {
                            out.extend(b" ACTIVE");
                        }
                        out.extend(b"\r\n");
                    }
                    out.extend(proto::status("OK", None, "Listscripts completed."));
                    out
                }
                ("managesieve_script", "GETSCRIPT") => {
                    outcome(ctx, self.id, &operation, "model_answer");
                    let text = a["script"].as_str().unwrap_or_default();
                    let mut out = format!("{{{}}}\r\n", text.len()).into_bytes();
                    out.extend(text.as_bytes());
                    out.extend(b"\r\n");
                    out.extend(proto::status("OK", None, "Getscript completed."));
                    out
                }
                ("managesieve_ok", c) if c != "LISTSCRIPTS" && c != "GETSCRIPT" => {
                    outcome(ctx, self.id, &operation, "model_answer");
                    let code = (a["warnings"] == true).then_some("WARNINGS");
                    let default = format!("{} completed.", c.to_ascii_lowercase());
                    proto::status("OK", code, a["message"].as_str().unwrap_or(&default))
                }
                _ => {
                    outcome(ctx, self.id, &operation, "fail_closed_invalid_reply");
                    proto::status("NO", Some("TRYLATER"), "The server cannot answer right now")
                }
            },
        }
    }

    async fn script_command(&mut self, user: &str, command: &str, args: &[Arg]) -> Result<()> {
        let data = match Self::script_event(user, command, args) {
            Ok(data) => data,
            Err((message, logged)) => {
                if logged {
                    outcome(&self.shared.ctx, self.id, command, "protocol_refusal");
                }
                return self.write(&proto::status("NO", None, &message)).await;
            }
        };
        if batchable(command) {
            let mut batch = vec![(command.to_string(), data)];
            self.collect_batch(user, &mut batch).await?;
            if batch.len() > 1 {
                return self.answer_batch(batch).await;
            }
            let (_, data) = batch.remove(0);
            return self.ask_and_reply(command, data).await;
        }
        self.ask_and_reply(command, data).await
    }

    async fn ask_and_reply(&mut self, command: &str, data: Json) -> Result<()> {
        let operation = command.to_ascii_lowercase();
        let answer = self
            .ask(Event::new(&actions::COMMAND_EVENT, data), &operation)
            .await;
        let reply = self.script_reply(command, answer);
        self.write(&reply).await
    }

    /// Append the script commands already waiting behind `batch`'s first that may be answered
    /// with it in one model call, consuming them. Stops at the first command that is not a
    /// well-formed batchable script command (it is then read normally), and reads only what is
    /// already buffered or readable without waiting.
    async fn collect_batch(&mut self, user: &str, batch: &mut Vec<(String, Json)>) -> Result<()> {
        if !crate::server::command_batch::one_model_call_answers(
            &self.shared.ctx.state,
            self.shared.ctx.server_id,
            &[actions::COMMAND_EVENT.id.as_str()],
        )
        .await
        {
            return Ok(());
        }
        while batch.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
            let parsed = match proto::parse(&self.buf) {
                Ok(Some(parsed)) => Some(parsed),
                Ok(None) => None,
                Err(_) => return Ok(()),
            };
            let Some((args, used)) = parsed else {
                // Nothing whole is buffered: take what the socket already holds, and wait for
                // nothing.
                let mut chunk = [0u8; 16 * 1024];
                match tokio::time::timeout(Duration::ZERO, self.stream.read(&mut chunk)).await {
                    Ok(Ok(n)) if n > 0 => {
                        self.buf.extend_from_slice(&chunk[..n]);
                        continue;
                    }
                    _ => return Ok(()),
                }
            };
            let Some(Arg::Atom(command)) = args.first() else {
                return Ok(());
            };
            let command = command.to_ascii_uppercase();
            if !batchable(&command) {
                return Ok(());
            }
            let Ok(data) = Self::script_event(user, &command, &args[1..]) else {
                return Ok(());
            };
            self.buf.drain(..used);
            let ctx = &self.shared.ctx;
            ctx.state
                .update_connection_stats(
                    ctx.server_id,
                    self.id,
                    Some(used as u64),
                    None,
                    Some(1),
                    None,
                )
                .await;
            batch.push((command, data));
        }
        Ok(())
    }

    /// Answer pipelined script commands with one model call, one answer per command, in
    /// order.
    ///
    /// The answer is used only when every action executed and it holds exactly one answer per
    /// command. Anything else and every command is answered `NO (TRYLATER)`, the reply a
    /// single command gets when its answer is unusable: the client reads one response per
    /// command and stays in step, and no command is answered with another's script list.
    async fn answer_batch(&mut self, batch: Vec<(String, Json)>) -> Result<()> {
        let total = batch.len();
        let events: Vec<Event> = batch
            .iter()
            .enumerate()
            .map(|(i, (_, data))| {
                let mut data = data.clone();
                crate::server::command_batch::mark_pipelined(&mut data, i + 1, total);
                Event::new(&actions::COMMAND_EVENT, data)
            })
            .collect();
        let ctx = &self.shared.ctx;
        let answers: Option<Vec<Json>> = match crate::llm::action_helper::call_llm_batch(
            &ctx.llm_client,
            &ctx.state,
            ctx.server_id,
            Some(self.id),
            &events,
            &actions::ManageSieveProtocol,
        )
        .await
        {
            Err(_) => {
                outcome(ctx, self.id, "batch", "fail_closed_llm_error");
                None
            }
            Ok(result) => {
                fn walk(results: Vec<ActionResult>, out: &mut Vec<Json>) {
                    for r in results {
                        match r {
                            ActionResult::Custom { data, .. } => out.push(data),
                            ActionResult::Multiple(items) => walk(items, out),
                            _ => {}
                        }
                    }
                }
                let failed = !result.failures.is_empty();
                let mut answers = Vec::new();
                walk(result.protocol_results, &mut answers);
                if failed || answers.len() != total {
                    outcome(ctx, self.id, "batch", "fail_closed_batch_mismatch");
                    None
                } else {
                    Some(answers)
                }
            }
        };
        let mut out = Vec::new();
        match answers {
            Some(answers) => {
                for ((command, _), answer) in batch.iter().zip(answers) {
                    out.extend(self.script_reply(command, Ok(answer)));
                }
            }
            None => {
                for _ in &batch {
                    out.extend(proto::status(
                        "NO",
                        Some("TRYLATER"),
                        "The server cannot answer right now",
                    ));
                }
            }
        }
        self.write(&out).await
    }
}

/// Whether a script command may be answered as part of a batch: the ones whose arguments are
/// names and numbers. `PUTSCRIPT` and `CHECKSCRIPT` carry a whole script (a literal) and are
/// answered one at a time, as are AUTHENTICATE, STARTTLS, LOGOUT and everything NetGet answers
/// itself.
fn batchable(command: &str) -> bool {
    matches!(
        command,
        "LISTSCRIPTS" | "GETSCRIPT" | "SETACTIVE" | "DELETESCRIPT" | "RENAMESCRIPT" | "HAVESPACE"
    )
}

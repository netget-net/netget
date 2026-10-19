//! ManageSieve client over the server's line and literal parser.
pub mod actions;
use crate::client::llm_budget::call_llm_for_client_batch;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::managesieve::proto::{self, Arg};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::ManageSieveClientProtocol;
use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use serde_json::{json, Map, Value as Json};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const TIMEOUT: Duration = Duration::from_secs(30);
/// Lines in one response (LISTSCRIPTS entries, capabilities).
const MAX_LINES: usize = 4096;

struct Conn {
    stream: TcpStream,
    buf: Vec<u8>,
}

/// A final response line.
struct Status {
    status: String,
    code: Option<String>,
    message: Option<String>,
}

impl Conn {
    async fn line(&mut self) -> Result<Vec<Arg>> {
        loop {
            if let Some((args, used)) = proto::parse(&self.buf)? {
                self.buf.drain(..used);
                return Ok(args);
            }
            let mut chunk = [0u8; 16 * 1024];
            let n = tokio::time::timeout(TIMEOUT, self.stream.read(&mut chunk))
                .await
                .context("the server stalled")??;
            ensure!(n > 0, "the server closed the connection");
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Lines up to the final OK/NO/BYE.
    async fn response(&mut self) -> Result<(Vec<Vec<Arg>>, Status)> {
        let mut lines = Vec::new();
        loop {
            let args = self.line().await?;
            if let Some(Arg::Atom(a)) = args.first() {
                let up = a.to_ascii_uppercase();
                if matches!(up.as_str(), "OK" | "NO" | "BYE") {
                    let mut i = 1;
                    let mut code = None;
                    if let Some(Arg::Atom(c)) = args
                        .get(1)
                        .filter(|c| matches!(c, Arg::Atom(t) if t.starts_with('(')))
                    {
                        let mut parts = vec![c.clone()];
                        i = 2;
                        while !parts.last().is_some_and(|p| p.ends_with(')')) && i < args.len() {
                            parts.push(args[i].text().unwrap_or_default());
                            i += 1;
                        }
                        code = Some(
                            parts
                                .join(" ")
                                .trim_start_matches('(')
                                .trim_end_matches(')')
                                .to_owned(),
                        );
                    }
                    let message = args.get(i).and_then(Arg::text);
                    return Ok((
                        lines,
                        Status {
                            status: up,
                            code,
                            message,
                        },
                    ));
                }
            }
            lines.push(args);
            ensure!(
                lines.len() <= MAX_LINES,
                "a response of more than {MAX_LINES} lines"
            );
        }
    }

    async fn command(&mut self, parts: &[Vec<u8>]) -> Result<()> {
        let mut out = Vec::new();
        for (i, p) in parts.iter().enumerate() {
            if i > 0 {
                out.push(b' ');
            }
            out.extend(p);
        }
        out.extend(b"\r\n");
        self.stream.write_all(&out).await?;
        Ok(())
    }
}

fn s(text: &str) -> Vec<u8> {
    proto::string(text.as_bytes(), true)
}

async fn act(c: &mut Conn, v: &Json) -> Result<Json> {
    let name = v["name"].as_str().unwrap_or_default();
    let (command, parts): (&str, Vec<Vec<u8>>) = match v["type"].as_str().unwrap_or_default() {
        "managesieve_list" => ("LISTSCRIPTS", vec![]),
        "managesieve_get" => ("GETSCRIPT", vec![s(name)]),
        "managesieve_put" => (
            "PUTSCRIPT",
            vec![s(name), s(v["script"].as_str().unwrap_or_default())],
        ),
        "managesieve_check" => (
            "CHECKSCRIPT",
            vec![s(v["script"].as_str().unwrap_or_default())],
        ),
        "managesieve_set_active" => ("SETACTIVE", vec![s(name)]),
        "managesieve_delete" => ("DELETESCRIPT", vec![s(name)]),
        "managesieve_rename" => (
            "RENAMESCRIPT",
            vec![s(name), s(v["new_name"].as_str().unwrap_or_default())],
        ),
        "managesieve_have_space" => (
            "HAVESPACE",
            vec![
                s(name),
                v["size"].as_u64().unwrap_or(0).to_string().into_bytes(),
            ],
        ),
        other => bail!("{other} is not a ManageSieve command"),
    };
    let mut all = vec![command.as_bytes().to_vec()];
    all.extend(parts);
    c.command(&all).await?;
    let (lines, st) = c.response().await?;
    let mut out =
        json!({"command": command, "status": st.status, "code": st.code, "message": st.message});
    if st.status == "OK" {
        match command {
            "LISTSCRIPTS" => {
                out["scripts"] = json!(lines
                    .iter()
                    .filter_map(|l| Some(json!({"name": l.first()?.text()?, "active": l.get(1).and_then(Arg::text).is_some_and(|a| a.eq_ignore_ascii_case("ACTIVE"))})))
                    .collect::<Vec<_>>())
            }
            "GETSCRIPT" => out["script"] = json!(lines.first().and_then(|l| l.first()).and_then(Arg::text)),
            _ => {}
        }
    }
    Ok(out)
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let p = ctx
        .startup_params
        .as_ref()
        .context("the managesieve client needs user and password")?;
    let user = p.get_optional_string("user")?.context("user is required")?;
    let password = p
        .get_optional_string("password")?
        .context("password is required")?;
    let authz = p.get_optional_string("authorize_as")?.unwrap_or_default();
    let stream = tokio::time::timeout(TIMEOUT, TcpStream::connect(&ctx.remote_addr))
        .await
        .context("ManageSieve connect timed out")??;
    let local = stream.local_addr()?;
    let mut c = Conn {
        stream,
        buf: Vec::new(),
    };
    let (lines, st) = c.response().await?;
    ensure!(
        st.status == "OK",
        "the server greeted with {}: {}",
        st.status,
        st.message.unwrap_or_default()
    );
    let mut caps = Map::new();
    for l in &lines {
        if let Some(k) = l.first().and_then(Arg::text) {
            caps.insert(
                k.to_ascii_uppercase(),
                json!(l.get(1).and_then(Arg::text).unwrap_or_default()),
            );
        }
    }
    ensure!(
        caps.get("SASL").and_then(Json::as_str).is_some_and(|m| m
            .split_whitespace()
            .any(|m| m.eq_ignore_ascii_case("PLAIN"))),
        "the server does not offer SASL PLAIN without TLS"
    );
    let token =
        base64::engine::general_purpose::STANDARD.encode(format!("{authz}\0{user}\0{password}"));
    c.command(&[b"AUTHENTICATE".to_vec(), s("PLAIN"), s(&token)])
        .await?;
    let (_, st) = c.response().await?;
    ensure!(
        st.status == "OK",
        "the server refused the login: {}",
        st.message.unwrap_or_default()
    );
    let extensions: Vec<String> = caps
        .get("SIEVE")
        .and_then(Json::as_str)
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let info = json!({"implementation": caps.get("IMPLEMENTATION"), "sieve_extensions": extensions, "capabilities": caps});

    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<Json>(16);
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(16);
    event_tx.try_send(Event::new(&actions::CONNECTED_EVENT, info))?;
    let events_ctx = ctx.clone();
    let dispatcher = tokio::spawn(async move {
        let protocol = ManageSieveClientProtocol;
        while let Some(first) = event_rx.recv().await {
            // The session keeps running the model's earlier actions (and injected ones) while
            // this call is out, so their results queue here. With batching on, everything
            // already waiting is answered in one call; with it off, one result per call.
            let mut events = vec![first];
            if events_ctx
                .state
                .client_conversation_settings(events_ctx.client_id)
                .await
                .is_some_and(|(_, batching)| batching)
            {
                while events.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                    match event_rx.try_recv() {
                        Ok(event) => events.push(event),
                        Err(_) => break,
                    }
                }
            }
            let instruction = events_ctx
                .state
                .get_instruction_for_client(events_ctx.client_id)
                .await
                .unwrap_or_default();
            let memory = events_ctx
                .state
                .get_memory_for_client(events_ctx.client_id)
                .await
                .unwrap_or_default();
            match call_llm_for_client_batch(
                &events_ctx.llm_client,
                &events_ctx.state,
                events_ctx.client_id.to_string(),
                &instruction,
                &memory,
                &events,
                &protocol,
                &events_ctx.status_tx,
            )
            .await
            {
                Ok(result) => {
                    if let Some(memory) = result.memory_updates {
                        events_ctx
                            .state
                            .set_memory_for_client(events_ctx.client_id, memory)
                            .await;
                    }
                    for action in result.actions {
                        if internal_tx.send(action).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => Log::new(Some(&events_ctx.status_tx))
                    .warn(format!("ManageSieve client handler: {e}")),
            }
        }
    });
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        if let Err(e) = run(&session_ctx, &mut c, external, internal_rx, &event_tx).await {
            Log::new(Some(&session_ctx.status_tx)).warn(format!("ManageSieve client ended: {e:#}"));
        }
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
    Ok(local)
}

async fn run(
    ctx: &ConnectContext,
    c: &mut Conn,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<Json>,
    events: &mpsc::Sender<Event>,
) -> Result<()> {
    loop {
        let (action, command) = tokio::select! {
            m = external.recv() => match m { Some(m) => (m.action.clone(), Some(m)), None => return Ok(()) },
            a = internal.recv() => match a { Some(a) => (a, None), None => return Ok(()) },
        };
        let outcome = match ManageSieveClientProtocol.execute_action(action.clone()) {
            Err(e) => Ok(ClientSendOutcome::Rejected {
                error: e.to_string(),
            }),
            Ok(ClientActionResult::Disconnect) => {
                let _ = c.command(&[b"LOGOUT".to_vec()]).await;
                let _ = tokio::time::timeout(Duration::from_secs(5), c.response()).await;
                if let Some(m) = command {
                    crate::client::command_support::reply(m, Ok(ClientSendOutcome::Disconnected));
                }
                return Ok(());
            }
            Ok(_) => match act(c, &action).await {
                Ok(response) => {
                    let bye = response["status"] == "BYE";
                    events
                        .send(Event::new(&actions::RESPONSE_EVENT, response))
                        .await
                        .ok();
                    if bye {
                        Err(anyhow::anyhow!("the server said BYE"))
                    } else {
                        Ok(ClientSendOutcome::Sent { bytes_sent: 0 })
                    }
                }
                Err(e) => Err(e),
            },
        };
        let failed = outcome.is_err();
        if let Some(m) = command {
            let logged = outcome
                .as_ref()
                .map(|o| serde_json::to_value(o).unwrap_or(Json::Null))
                .unwrap_or_else(|e| json!({"error": e.to_string()}));
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "ManageSieve",
                    None,
                    "injected_action",
                    json!({"type": action["type"]}),
                    vec![logged],
                )
                .await;
            crate::client::command_support::reply(m, outcome);
        }
        if failed {
            bail!("the ManageSieve session ended");
        }
    }
}

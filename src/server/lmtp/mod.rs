//! LMTP (RFC 2033) delivery server. Rust owns the SMTP-style state machine, framing, bounds
//! and the one-reply-per-recipient rule after DATA; handlers decide which recipients exist
//! and what happened to each delivery. Nothing is stored here.
pub mod actions;
pub mod wire;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::connection::ConnectionId;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::{collections::HashMap, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use wire::Line;

/// RFC 5321 4.5.3.2.7 suggests a five-minute server timeout between commands.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const MAX_IDLE_TIMEOUT_SECS: u64 = 3600;
pub const DEFAULT_HOSTNAME: &str = "netget";
/// Consecutive refused commands before the session is closed with 421.
pub const MAX_BAD_COMMANDS: usize = 20;

#[derive(Clone)]
struct Config {
    hostname: String,
    max_message: u64,
    idle: Duration,
}

fn config(ctx: &SpawnContext) -> Result<Config> {
    let params = ctx.startup_params.as_ref();
    let hostname = params
        .map(|p| p.get_optional_string("hostname"))
        .transpose()?
        .flatten()
        .unwrap_or_else(|| DEFAULT_HOSTNAME.to_string());
    anyhow::ensure!(
        !hostname.is_empty()
            && hostname.len() <= 255
            && hostname.chars().all(|c| c.is_ascii_graphic()),
        "hostname must be 1..=255 printable ASCII characters without spaces"
    );
    let max_message = params
        .map(|p| p.get_optional_u64("max_message_bytes"))
        .transpose()?
        .flatten()
        .unwrap_or(wire::DEFAULT_MAX_MESSAGE_BYTES);
    anyhow::ensure!(
        (1..=wire::MAX_MESSAGE_BYTES_LIMIT).contains(&max_message),
        "max_message_bytes must be between 1 and {}",
        wire::MAX_MESSAGE_BYTES_LIMIT
    );
    let idle = params
        .map(|p| p.get_optional_u64("idle_timeout_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(IDLE_TIMEOUT.as_secs());
    anyhow::ensure!(
        (1..=MAX_IDLE_TIMEOUT_SECS).contains(&idle),
        "idle_timeout_secs must be between 1 and {MAX_IDLE_TIMEOUT_SECS}"
    );
    Ok(Config {
        hostname,
        max_message,
        idle: Duration::from_secs(idle),
    })
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let cfg = config(&ctx)?;
    let listener = TcpListener::bind(ctx.legacy_listen_addr()).await?;
    let addr = listener.local_addr()?;
    Log::new(Some(&ctx.status_tx)).info(format!("LMTP listening on {addr}"));
    let state = ctx.state.clone();
    let server_id = ctx.server_id;
    let accept = tokio::spawn(async move {
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(
            crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS,
        );
        loop {
            let (socket, peer, permit) = match crate::server::accept_bounded::accept_bounded(
                &listener,
                &limiter,
                b"421 4.3.2 Too many connections, try again later\r\n",
                "LMTP",
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
            let child = ctx.clone();
            let cfg = cfg.clone();
            ctx.state
                .spawn_server_task(server_id, async move {
                    let _permit = permit;
                    if let Err(e) = session(&child, id, socket, &cfg).await {
                        Log::new(Some(&child.status_tx))
                            .warn(format!("LMTP connection {id} ended: {e}"));
                    }
                    child
                        .state
                        .update_connection_status(server_id, id, ConnectionStatus::Closed)
                        .await;
                    let _ = child.status_tx.send("__UPDATE_UI__".into());
                })
                .await;
        }
    });
    state.register_server_task(server_id, accept).await;
    Ok(addr)
}

async fn write<W: tokio::io::AsyncWrite + Unpin>(
    ctx: &SpawnContext,
    id: ConnectionId,
    w: &mut W,
    reply: &str,
) -> Result<()> {
    tokio::time::timeout(wire::IO_TIMEOUT, w.write_all(reply.as_bytes()))
        .await
        .context("LMTP write deadline")??;
    ctx.state
        .update_connection_stats(
            ctx.server_id,
            id,
            None,
            Some(reply.len() as u64),
            None,
            Some(1),
        )
        .await;
    Ok(())
}

fn outcome(ctx: &SpawnContext, id: ConnectionId, operation: &str, decision: &str) {
    let summary = format!("LMTP connection {id} operation={operation} decision={decision}");
    let log = Log::new(Some(&ctx.status_tx));
    if decision.starts_with("fail_closed_") || decision == "model_silent" {
        log.error(summary);
    } else {
        log.info(summary);
    }
}

/// Ask the handler and return the single expected action, logging how a failure happened.
async fn decision(
    ctx: &SpawnContext,
    id: ConnectionId,
    event: Event,
    expected: &str,
) -> Result<Value> {
    let result = match call_llm(
        &ctx.llm_client,
        &ctx.state,
        ctx.server_id,
        Some(id),
        &event,
        &actions::LmtpProtocol,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            outcome(ctx, id, event.id(), "fail_closed_llm_error");
            return Err(error);
        }
    };
    if !result.failures.is_empty() {
        outcome(ctx, id, event.id(), "fail_closed_invalid_reply");
        anyhow::bail!("LMTP handler supplied an invalid action");
    }
    let mut found = None;
    let mut pending = result.protocol_results;
    while let Some(result) = pending.pop() {
        match result {
            ActionResult::Custom { name, data } if name == expected => {
                if found.is_some() {
                    outcome(ctx, id, event.id(), "fail_closed_invalid_reply");
                    anyhow::bail!("Multiple LMTP answers to one event");
                }
                found = Some(data);
            }
            ActionResult::Multiple(items) => pending.extend(items),
            _ => {}
        }
    }
    if found.is_none() {
        outcome(ctx, id, event.id(), "model_silent");
    }
    found.context("Handler did not answer the LMTP event")
}

/// The reply to one RCPT the handler decided, recording the recipient when it is accepted.
fn recipient_reply(
    ctx: &SpawnContext,
    id: ConnectionId,
    answer: &Value,
    address: String,
    recipients: &mut Vec<String>,
) -> String {
    let reason = answer["reason"].as_str();
    if answer["accept"] == true {
        outcome(ctx, id, "lmtp_recipient", "model_answer");
        let reply = wire::render(
            250,
            "2.1.5",
            reason.unwrap_or(&format!("<{address}> recipient OK")),
        );
        recipients.push(address);
        reply
    } else if answer["temporary"] == true {
        outcome(ctx, id, "lmtp_recipient", "model_reject");
        wire::render(
            450,
            "4.2.1",
            reason.unwrap_or("Mailbox temporarily unavailable"),
        )
    } else {
        outcome(ctx, id, "lmtp_recipient", "model_reject");
        wire::render(550, "5.1.1", reason.unwrap_or("No such user here"))
    }
}

/// The address of a pipelined line that is a well-formed `RCPT TO:<address>` and may join a
/// batch, or `None` for anything else (which ends the batch and is read normally).
fn pipelined_recipient(line: &str) -> Option<String> {
    let line = line.trim_end_matches(['\r', '\n']);
    let (verb, argument) = line.split_once(' ')?;
    if !verb.eq_ignore_ascii_case("RCPT") {
        return None;
    }
    let (address, _) = wire::parse_path(argument.trim(), "TO:")?;
    (!address.is_empty()).then_some(address)
}

/// Decide pipelined RCPTs in one model call: one `lmtp_recipient_reply` per recipient, in
/// RCPT order.
///
/// The answer is used only when it holds exactly one reply per recipient and every action
/// executed. Anything else and every recipient in the batch gets `451 4.3.0`: none is
/// accepted, so an answer one short can never accept the wrong mailbox, and the client — which
/// reads one reply per RCPT — stays in step.
async fn recipient_batch(
    ctx: &SpawnContext,
    id: ConnectionId,
    sender: &str,
    lhlo: &str,
    recipients: &mut Vec<String>,
    batch: Vec<String>,
) -> String {
    let total = batch.len();
    let accepted_so_far = recipients.len();
    let events: Vec<Event> = batch
        .iter()
        .enumerate()
        .map(|(i, address)| {
            let mut data = json!({
                "recipient": address,
                "mail_from": sender,
                "lhlo": lhlo,
                "accepted_so_far": accepted_so_far,
            });
            crate::server::command_batch::mark_pipelined(&mut data, i + 1, total);
            Event::new(&actions::RECIPIENT_EVENT, data)
        })
        .collect();
    let result = match crate::llm::action_helper::call_llm_batch(
        &ctx.llm_client,
        &ctx.state,
        ctx.server_id,
        Some(id),
        &events,
        &actions::LmtpProtocol,
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            outcome(ctx, id, "lmtp_recipient", "fail_closed_llm_error");
            return TEMPORARY_FAILURE.repeat(total);
        }
    };
    let mut answers = Vec::new();
    fn walk(results: Vec<ActionResult>, answers: &mut Vec<Value>) {
        for result in results {
            match result {
                ActionResult::Custom { name, data } if name == "lmtp_recipient_reply" => {
                    answers.push(data)
                }
                ActionResult::Multiple(items) => walk(items, answers),
                _ => {}
            }
        }
    }
    let failed = !result.failures.is_empty();
    walk(result.protocol_results, &mut answers);
    if failed || answers.len() != total {
        outcome(ctx, id, "lmtp_recipient", "fail_closed_batch_mismatch");
        return TEMPORARY_FAILURE.repeat(total);
    }
    batch
        .into_iter()
        .zip(answers)
        .map(|(address, answer)| recipient_reply(ctx, id, &answer, address, recipients))
        .collect()
}

const TEMPORARY_FAILURE: &str = "451 4.3.0 Temporary local failure, try again later\r\n";

/// One reply per accepted recipient, in RCPT order (RFC 2033 4.2).
fn delivery_replies(
    ctx: &SpawnContext,
    id: ConnectionId,
    recipients: &[String],
    answer: &Value,
) -> String {
    let mut listed: HashMap<String, &Value> = HashMap::new();
    if let Some(results) = answer["results"].as_array() {
        for result in results {
            if let Some(recipient) = result["recipient"].as_str() {
                listed
                    .entry(recipient.to_ascii_lowercase())
                    .or_insert(result);
            }
        }
    }
    let mut replies = String::new();
    for recipient in recipients {
        let reply = match listed.get(&recipient.to_ascii_lowercase()) {
            Some(result) => {
                let reason = result["reason"].as_str();
                if result["delivered"] == true {
                    outcome(ctx, id, "lmtp_message", "model_answer");
                    wire::render(
                        250,
                        "2.0.0",
                        reason.unwrap_or(&format!("<{recipient}> delivered")),
                    )
                } else if result["temporary"] == true {
                    outcome(ctx, id, "lmtp_message", "model_reject");
                    wire::render(
                        450,
                        "4.2.0",
                        reason.unwrap_or("Mailbox temporarily unavailable"),
                    )
                } else {
                    outcome(ctx, id, "lmtp_message", "model_reject");
                    wire::render(550, "5.0.0", reason.unwrap_or("Delivery refused"))
                }
            }
            None => match answer["deliver_all"].as_bool() {
                Some(true) => {
                    outcome(ctx, id, "lmtp_message", "model_answer");
                    wire::render(250, "2.0.0", &format!("<{recipient}> delivered"))
                }
                Some(false) => {
                    outcome(ctx, id, "lmtp_message", "model_reject");
                    wire::render(550, "5.0.0", "Delivery refused")
                }
                None => {
                    outcome(ctx, id, "lmtp_message", "fail_closed_incomplete_reply");
                    TEMPORARY_FAILURE.to_string()
                }
            },
        };
        replies.push_str(&reply);
    }
    replies
}

enum Data {
    Message(Vec<u8>),
    TooBig,
    BadLine,
}

/// Read DATA through the terminating dot, keeping at most `max` bytes.
async fn read_data<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    cfg: &Config,
) -> Result<(Data, u64)> {
    let mut message = Vec::new();
    let mut total: u64 = 0;
    let mut too_big = false;
    let mut bad_line = false;
    loop {
        match wire::read_line(reader, cfg.idle).await? {
            Line::Text(line) => {
                if line == "." {
                    break;
                }
                let line = line.strip_prefix('.').unwrap_or(&line);
                total = total.saturating_add(line.len() as u64 + 2);
                if total > cfg.max_message {
                    too_big = true;
                    message = Vec::new();
                } else if !too_big {
                    message.extend_from_slice(line.as_bytes());
                    message.extend_from_slice(b"\r\n");
                }
            }
            Line::TooLong => {
                bad_line = true;
                total = total.saturating_add(wire::MAX_LINE_BYTES as u64);
            }
            Line::Eof => anyhow::bail!("LMTP peer closed the connection during DATA"),
        }
    }
    let data = if bad_line {
        Data::BadLine
    } else if too_big {
        Data::TooBig
    } else {
        Data::Message(message)
    };
    Ok((data, total))
}

async fn session(
    ctx: &SpawnContext,
    id: ConnectionId,
    socket: TcpStream,
    cfg: &Config,
) -> Result<()> {
    let (read, mut out) = tokio::io::split(socket);
    let mut reader = BufReader::new(read);
    write(
        ctx,
        id,
        &mut out,
        &wire::render(220, "", &format!("{} LMTP NetGet ready", cfg.hostname)),
    )
    .await?;
    let mut lhlo: Option<String> = None;
    let mut from: Option<String> = None;
    let mut recipients: Vec<String> = Vec::new();
    let mut bad = 0usize;
    loop {
        let line = match wire::read_line(&mut reader, cfg.idle).await {
            Ok(Line::Text(line)) => line,
            Ok(Line::TooLong) => {
                bad += 1;
                write(
                    ctx,
                    id,
                    &mut out,
                    &wire::render(500, "5.5.2", "Line too long"),
                )
                .await?;
                if bad >= MAX_BAD_COMMANDS {
                    write(
                        ctx,
                        id,
                        &mut out,
                        &wire::render(421, "4.7.0", "Too many errors"),
                    )
                    .await?;
                    return Ok(());
                }
                continue;
            }
            Ok(Line::Eof) => return Ok(()),
            Err(error) => {
                let _ = write(
                    ctx,
                    id,
                    &mut out,
                    &wire::render(421, "4.4.2", "Idle timeout, closing"),
                )
                .await;
                return Err(error);
            }
        };
        ctx.state
            .update_connection_stats(
                ctx.server_id,
                id,
                Some(line.len() as u64 + 2),
                None,
                Some(1),
                None,
            )
            .await;
        let (verb, argument) = match line.split_once(' ') {
            Some((verb, rest)) => (verb.to_ascii_uppercase(), rest.trim().to_string()),
            None => (line.trim().to_ascii_uppercase(), String::new()),
        };
        let reply = match verb.as_str() {
            "LHLO" => {
                if argument.is_empty() || argument.contains(' ') {
                    wire::render(501, "5.5.4", "Syntax: LHLO domain")
                } else {
                    lhlo = Some(argument);
                    from = None;
                    recipients.clear();
                    wire::render_multi(
                        250,
                        &[
                            cfg.hostname.clone(),
                            "PIPELINING".into(),
                            "ENHANCEDSTATUSCODES".into(),
                            "8BITMIME".into(),
                            format!("SIZE {}", cfg.max_message),
                        ],
                    )
                }
            }
            "HELO" | "EHLO" => wire::render(500, "5.5.1", "This is an LMTP server; use LHLO"),
            "MAIL" => {
                if lhlo.is_none() {
                    wire::render(503, "5.5.1", "Send LHLO first")
                } else if from.is_some() {
                    wire::render(503, "5.5.1", "Nested MAIL command")
                } else {
                    match wire::parse_path(&argument, "FROM:") {
                        None => wire::render(501, "5.5.4", "Syntax: MAIL FROM:<address>"),
                        Some((address, params)) => {
                            let mut refusal = None;
                            for param in &params {
                                let (key, value) = param.split_once('=').unwrap_or((param, ""));
                                match key.to_ascii_uppercase().as_str() {
                                    "SIZE" => match value.parse::<u64>() {
                                        Ok(size) if size > cfg.max_message => {
                                            refusal = Some(wire::render(
                                                552,
                                                "5.3.4",
                                                "Message size exceeds fixed limit",
                                            ))
                                        }
                                        Ok(_) => {}
                                        Err(_) => {
                                            refusal = Some(wire::render(
                                                501,
                                                "5.5.4",
                                                "Invalid SIZE parameter",
                                            ))
                                        }
                                    },
                                    "BODY"
                                        if matches!(
                                            value.to_ascii_uppercase().as_str(),
                                            "7BIT" | "8BITMIME"
                                        ) => {}
                                    _ => {
                                        refusal = Some(wire::render(
                                            555,
                                            "5.5.4",
                                            "MAIL parameter not recognized",
                                        ))
                                    }
                                }
                            }
                            match refusal {
                                Some(refusal) => refusal,
                                None => {
                                    from = Some(address);
                                    wire::render(250, "2.1.0", "Sender OK")
                                }
                            }
                        }
                    }
                }
            }
            "RCPT" => match (&from, wire::parse_path(&argument, "TO:")) {
                (None, _) => wire::render(503, "5.5.1", "Need MAIL before RCPT"),
                (_, None) => wire::render(501, "5.5.4", "Syntax: RCPT TO:<address>"),
                (Some(_), Some((address, _))) if address.is_empty() => {
                    wire::render(501, "5.1.3", "Empty recipient address")
                }
                (Some(_), Some(_)) if recipients.len() >= wire::MAX_RECIPIENTS => {
                    wire::render(452, "4.5.3", "Too many recipients")
                }
                (Some(sender), Some((address, _))) => {
                    // RFC 2033 requires PIPELINING, and a client delivering to several
                    // mailboxes sends its RCPT lines together. Those already waiting behind
                    // this one are decided with it in one model call when the instance
                    // batches; anything other than another well-formed RCPT ends the run and
                    // is read normally.
                    let mut batch = vec![address];
                    if crate::server::command_batch::one_model_call_answers(
                        &ctx.state,
                        ctx.server_id,
                        &[actions::RECIPIENT_EVENT.id.as_str()],
                    )
                    .await
                    {
                        use tokio::io::AsyncBufReadExt;
                        while batch.len() < crate::protocol::metadata::MAX_BATCH_EVENTS
                            && recipients.len() + batch.len() < wire::MAX_RECIPIENTS
                        {
                            let Some((next, len)) = crate::server::command_batch::peek_ready_line(
                                &mut reader,
                                wire::MAX_LINE_BYTES,
                            )
                            .await
                            else {
                                break;
                            };
                            let Some(next) = pipelined_recipient(&next) else {
                                break;
                            };
                            reader.consume(len);
                            ctx.state
                                .update_connection_stats(
                                    ctx.server_id,
                                    id,
                                    Some(len as u64),
                                    None,
                                    Some(1),
                                    None,
                                )
                                .await;
                            batch.push(next);
                        }
                    }
                    let lhlo_domain = lhlo.clone().unwrap_or_default();
                    if batch.len() > 1 {
                        recipient_batch(ctx, id, sender, &lhlo_domain, &mut recipients, batch).await
                    } else {
                        let address = batch.remove(0);
                        let event = Event::new(
                            &actions::RECIPIENT_EVENT,
                            json!({
                                "recipient": address,
                                "mail_from": sender,
                                "lhlo": lhlo_domain,
                                "accepted_so_far": recipients.len(),
                            }),
                        );
                        match decision(ctx, id, event, "lmtp_recipient_reply").await {
                            Ok(answer) => {
                                recipient_reply(ctx, id, &answer, address, &mut recipients)
                            }
                            Err(_) => TEMPORARY_FAILURE.to_string(),
                        }
                    }
                }
            },
            "DATA" => {
                if !argument.is_empty() {
                    wire::render(501, "5.5.4", "DATA takes no argument")
                } else if from.is_none() {
                    wire::render(503, "5.5.1", "Need MAIL before DATA")
                } else if recipients.is_empty() {
                    wire::render(503, "5.5.1", "No valid recipients")
                } else {
                    write(
                        ctx,
                        id,
                        &mut out,
                        &wire::render(354, "", "End data with <CR><LF>.<CR><LF>"),
                    )
                    .await?;
                    let (data, size) = read_data(&mut reader, cfg).await?;
                    ctx.state
                        .update_connection_stats(ctx.server_id, id, Some(size), None, Some(1), None)
                        .await;
                    let replies = match data {
                        Data::TooBig => wire::render(552, "5.3.4", "Message too big for system")
                            .repeat(recipients.len()),
                        Data::BadLine => wire::render(500, "5.5.2", "Line too long in message")
                            .repeat(recipients.len()),
                        Data::Message(message) => {
                            let (headers, body, truncated) = wire::summarize(&message);
                            let subject = headers.get("subject").cloned().unwrap_or(Value::Null);
                            let event = Event::new(
                                &actions::MESSAGE_EVENT,
                                json!({
                                    "mail_from": from.clone().unwrap_or_default(),
                                    "recipients": recipients,
                                    "size": message.len(),
                                    "headers": headers,
                                    "subject": subject,
                                    "body": body,
                                    "body_truncated": truncated,
                                }),
                            );
                            match decision(ctx, id, event, "lmtp_delivery").await {
                                Ok(answer) => delivery_replies(ctx, id, &recipients, &answer),
                                Err(_) => TEMPORARY_FAILURE.repeat(recipients.len()),
                            }
                        }
                    };
                    from = None;
                    recipients.clear();
                    replies
                }
            }
            "RSET" => {
                from = None;
                recipients.clear();
                wire::render(250, "2.0.0", "Flushed")
            }
            "NOOP" => wire::render(250, "2.0.0", "OK"),
            "VRFY" => wire::render(
                252,
                "2.5.0",
                "Cannot VRFY user, but will accept message and attempt delivery",
            ),
            "HELP" => wire::render(
                214,
                "2.0.0",
                "Commands: LHLO MAIL RCPT DATA RSET NOOP VRFY HELP QUIT",
            ),
            "QUIT" => {
                write(
                    ctx,
                    id,
                    &mut out,
                    &wire::render(
                        221,
                        "2.0.0",
                        &format!("{} closing connection", cfg.hostname),
                    ),
                )
                .await?;
                let _ = out.shutdown().await;
                return Ok(());
            }
            "STARTTLS" | "AUTH" | "BDAT" | "ETRN" | "EXPN" | "TURN" => {
                wire::render(502, "5.5.1", "Command not implemented")
            }
            _ => wire::render(500, "5.5.2", "Command unrecognized"),
        };
        let refused = matches!(reply.get(..3), Some("500" | "501" | "502" | "503" | "555"));
        bad = if refused { bad + 1 } else { 0 };
        write(ctx, id, &mut out, &reply).await?;
        if bad >= MAX_BAD_COMMANDS {
            write(
                ctx,
                id,
                &mut out,
                &wire::render(421, "4.7.0", "Too many errors, closing"),
            )
            .await?;
            let _ = out.shutdown().await;
            return Ok(());
        }
    }
}

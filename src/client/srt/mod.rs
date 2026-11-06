//! SRT caller over srt-tokio.
pub mod actions;
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
use crate::utils::clock::Instant;
pub use actions::SrtClientProtocol;
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use srt_tokio::{SocketStatistics, SrtSocket};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_TEXTS: usize = 20;
const TS: usize = 188;
const MESSAGE: usize = 7 * TS;

/// Model-originated actions that may follow one another: an answer to the report at this depth
/// is not carried out, so a model that answers every report with another send stops here.
pub const MAX_FOLLOWUPS: u8 = 4;

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let p = ctx.startup_params.as_ref();
    let stream_id = p
        .map(|p| p.get_optional_string("stream_id"))
        .transpose()?
        .flatten();
    if let Some(s) = &stream_id {
        ensure!(
            s.len() <= 512 && !crate::utils::sanitize::has_controls(&s),
            "stream_id is up to 512 printable characters"
        );
    }
    let latency = p
        .map(|p| p.get_optional_u64("latency_ms"))
        .transpose()?
        .flatten()
        .unwrap_or(crate::server::srt::DEFAULT_LATENCY.as_millis() as u64);
    ensure!(
        (20..=8000).contains(&latency),
        "latency_ms must be 20..=8000"
    );
    let passphrase = p
        .map(|p| p.get_optional_string("passphrase"))
        .transpose()?
        .flatten();
    let media_root = crate::client::media_root::MediaRoot::new(
        p.map(|p| p.get_optional_string(crate::client::media_root::MEDIA_ROOT_PARAM))
            .transpose()?
            .flatten()
            .as_deref(),
    )?;
    let remote: SocketAddr = tokio::net::lookup_host(&ctx.remote_addr)
        .await?
        .next()
        .context("remote_addr does not resolve")?;
    let udp = tokio::net::UdpSocket::bind(if remote.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })
    .await?;
    let local = udp.local_addr()?;
    let mut builder = SrtSocket::builder()
        .latency(Duration::from_millis(latency))
        .set(crate::server::srt::announce_mss)
        .socket(udp);
    if let Some(pw) = passphrase {
        ensure!(
            (10..=79).contains(&pw.len()),
            "passphrase must be 10 to 79 characters"
        );
        builder = builder.encryption(16, pw);
    }
    let mut socket =
        tokio::time::timeout(CONNECT_TIMEOUT, builder.call(remote, stream_id.as_deref()))
            .await
            .context("SRT connect timed out")?
            .context("the listener refused or did not answer the SRT handshake")?;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<(Value, u8)>(16);
    let (event_tx, mut event_rx) = mpsc::channel::<(Event, u8)>(16);
    let negotiated = socket.settings().recv_tsbpd_latency.as_millis() as u64;
    event_tx.try_send((
        Event::new(
            &actions::CONNECTED_EVENT,
            json!({"stream_id": stream_id.unwrap_or_default(), "latency_ms": negotiated}),
        ),
        0,
    ))?;
    let events_ctx = ctx.clone();
    let dispatcher = tokio::spawn(async move {
        let protocol = SrtClientProtocol;
        while let Some((event, depth)) = event_rx.recv().await {
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
            match call_llm_for_client(
                &events_ctx.llm_client,
                &events_ctx.state,
                events_ctx.client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
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
                        if depth >= MAX_FOLLOWUPS && action["type"] != "disconnect" {
                            Log::new(Some(&events_ctx.status_tx)).warn(format!(
                                "SRT client: follow-up limit ({MAX_FOLLOWUPS}) reached; {} not sent",
                                action["type"]
                            ));
                            continue;
                        }
                        if internal_tx.send((action, depth + 1)).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    Log::new(Some(&events_ctx.status_tx)).warn(format!("SRT client handler: {e}"))
                }
            }
        }
    });
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        if let Err(e) = run(
            &session_ctx,
            &media_root,
            &mut socket,
            external,
            internal_rx,
            &event_tx,
        )
        .await
        {
            Log::new(Some(&session_ctx.status_tx)).warn(format!("SRT client ended: {e:#}"));
        }
        let _ = socket.close().await;
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

fn stats(s: Option<&SocketStatistics>) -> Value {
    s.map(|s| {
        json!({"rx_packets": s.rx_data, "rx_bytes": s.rx_bytes, "rx_lost_packets": s.rx_loss_data, "rx_retransmitted_packets": s.rx_retransmit_data, "rx_dropped_packets": s.rx_dropped_data,
               "tx_packets": s.tx_data, "tx_bytes": s.tx_bytes, "tx_retransmitted_packets": s.tx_retransmit_data, "tx_lost_packets": s.tx_loss_data, "rtt_ms": s.tx_average_rtt.as_millis() as u64})
    })
    .unwrap_or(Value::Null)
}

async fn run(
    ctx: &ConnectContext,
    media_root: &crate::client::media_root::MediaRoot,
    socket: &mut SrtSocket,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, u8)>,
    events: &mpsc::Sender<(Event, u8)>,
) -> Result<()> {
    let mut stats_stream = socket.statistics().clone();
    let mut latest: Option<SocketStatistics> = None;
    loop {
        enum Wake {
            Action(Value, u8, Option<ClientCommand>),
            Closed,
            Stats(Option<SocketStatistics>),
            Idle,
        }
        let wake = tokio::select! {
            c = external.recv() => match c { Some(c) => Wake::Action(c.action.clone(), 0, Some(c)), None => Wake::Closed },
            a = internal.recv() => match a { Some((a, d)) => Wake::Action(a, d, None), None => Wake::Closed },
            s = stats_stream.next() => Wake::Stats(s),
            // Between operations, anything the listener sends is read and set aside.
            d = socket.next() => match d { None | Some(Err(_)) => Wake::Closed, Some(Ok(_)) => Wake::Idle },
        };
        let (action, depth, command) = match wake {
            Wake::Closed => return Ok(()),
            Wake::Idle => continue,
            Wake::Stats(s) => {
                latest = s.or(latest);
                continue;
            }
            Wake::Action(a, d, c) => (a, d, c),
        };
        let outcome = match SrtClientProtocol.execute_action(action.clone()) {
            Err(e) => Ok(ClientSendOutcome::Rejected {
                error: e.to_string(),
            }),
            Ok(ClientActionResult::Disconnect) => {
                if let Some(c) = command {
                    crate::client::command_support::reply(c, Ok(ClientSendOutcome::Disconnected));
                }
                return Ok(());
            }
            Ok(_) => {
                let report = match action["type"].as_str() {
                    Some("srt_receive") => {
                        receive(
                            socket,
                            &mut stats_stream,
                            &mut latest,
                            action["seconds"].as_f64().unwrap_or(5.0),
                        )
                        .await
                    }
                    Some("srt_send_file") => {
                        send_file(media_root, socket, &mut stats_stream, &mut latest, &action).await
                    }
                    _ => {
                        let text =
                            Bytes::from(action["text"].as_str().unwrap_or_default().to_owned());
                        let n = text.len();
                        socket.send((std::time::Instant::now(), text)).await.map_err(anyhow::Error::from).map(|()| json!({"operation": "send_text", "messages": 1, "bytes": n, "statistics": stats(latest.as_ref())}))
                    }
                };
                match report {
                    Ok(r) => {
                        events
                            .send((Event::new(&actions::REPORT_EVENT, r), depth))
                            .await
                            .ok();
                        Ok(ClientSendOutcome::Sent { bytes_sent: 0 })
                    }
                    Err(e) => Err(e),
                }
            }
        };
        if let Some(c) = command {
            let logged = outcome
                .as_ref()
                .map(|o| serde_json::to_value(o).unwrap_or(Value::Null))
                .unwrap_or_else(|e| json!({"error": e.to_string()}));
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "SRT",
                    None,
                    "injected_action",
                    json!({"type": action["type"]}),
                    vec![logged],
                )
                .await;
            crate::client::command_support::reply(c, outcome);
        } else if let Err(e) = outcome {
            Log::new(Some(&ctx.status_tx)).warn(format!("SRT action failed: {e:#}"));
        }
    }
}

/// MPEG-TS bookkeeping: PIDs, the PMT PIDs the PAT names, and the stream types the PMTs list.
#[derive(Default)]
struct TsTally {
    packets: u64,
    pids: BTreeSet<u16>,
    pmt_pids: BTreeSet<u16>,
    stream_types: BTreeSet<String>,
}

impl TsTally {
    fn feed(&mut self, data: &[u8]) -> bool {
        if data.is_empty() || data.len() % TS != 0 || data.chunks(TS).any(|p| p[0] != 0x47) {
            return false;
        }
        for p in data.chunks(TS) {
            self.packets += 1;
            let pid = (u16::from(p[1] & 0x1f) << 8) | u16::from(p[2]);
            self.pids.insert(pid);
            let start = p[1] & 0x40 != 0;
            let has_payload = p[3] & 0x10 != 0;
            if !start || !has_payload {
                continue;
            }
            let mut i = 4;
            if p[3] & 0x20 != 0 {
                i += 1 + p[4] as usize;
            }
            let Some(&pointer) = p.get(i) else { continue };
            let s = i + 1 + pointer as usize;
            let Some(section) = p.get(s..) else { continue };
            if section.len() < 12 {
                continue;
            }
            let length = (((section[1] & 0x0f) as usize) << 8) | section[2] as usize;
            let end = (3 + length).min(section.len()).saturating_sub(4);
            if pid == 0 && section[0] == 0x00 {
                let mut j = 8;
                while j + 4 <= end {
                    let program = u16::from_be_bytes([section[j], section[j + 1]]);
                    let pmt = (u16::from(section[j + 2] & 0x1f) << 8) | u16::from(section[j + 3]);
                    if program != 0 {
                        self.pmt_pids.insert(pmt);
                    }
                    j += 4;
                }
            } else if self.pmt_pids.contains(&pid) && section[0] == 0x02 {
                let info = (((section[10] & 0x0f) as usize) << 8) | section[11] as usize;
                let mut j = 12 + info;
                while j + 5 <= end {
                    let kind = section[j];
                    self.stream_types.insert(match kind {
                        0x1b => "h264".into(),
                        0x24 => "hevc".into(),
                        0x0f => "aac".into(),
                        0x03 | 0x04 => "mp3".into(),
                        other => format!("0x{other:02x}"),
                    });
                    let es_info =
                        (((section[j + 3] & 0x0f) as usize) << 8) | section[j + 4] as usize;
                    j += 5 + es_info;
                }
            }
        }
        true
    }
}

async fn receive(
    socket: &mut SrtSocket,
    stats_stream: &mut (impl futures::Stream<Item = SocketStatistics> + Unpin),
    latest: &mut Option<SocketStatistics>,
    seconds: f64,
) -> Result<Value> {
    let until = Instant::now() + Duration::from_secs_f64(seconds);
    let (mut messages, mut bytes) = (0u64, 0u64);
    let mut ts = TsTally::default();
    let mut texts: Vec<String> = Vec::new();
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep(left) => break,
            s = stats_stream.next() => *latest = s.or(latest.take()),
            d = socket.next() => match d {
                None | Some(Err(_)) => break,
                Some(Ok((_, data))) => {
                    messages += 1;
                    bytes += data.len() as u64;
                    if !ts.feed(&data) && texts.len() < MAX_TEXTS {
                        if let Ok(t) = std::str::from_utf8(&data) {
                            texts.push(t.to_owned());
                        }
                    }
                }
            },
        }
    }
    Ok(
        json!({"operation": "receive", "messages": messages, "bytes": bytes, "ts_packets": ts.packets, "pids": ts.pids, "stream_types": ts.stream_types, "texts": texts, "statistics": stats(latest.as_ref())}),
    )
}

async fn send_file(
    media_root: &crate::client::media_root::MediaRoot,
    socket: &mut SrtSocket,
    stats_stream: &mut (impl futures::Stream<Item = SocketStatistics> + Unpin),
    latest: &mut Option<SocketStatistics>,
    a: &Value,
) -> Result<Value> {
    let path = a["path"].as_str().unwrap_or_default();
    // The peer this file goes to is the peer whose responses the model reads: confined
    // to `media_root`, or it is a file-exfiltration primitive. See `client::media_root`.
    let path = media_root.resolve(path, "the srt_send_file 'path'")?;
    let meta = tokio::fs::metadata(&path)
        .await
        .with_context(|| format!("reading {}", path.display()))?;
    ensure!(meta.len() <= MAX_FILE, "{} is over 64 MiB", path.display());
    let file = tokio::fs::read(&path).await?;
    ensure!(
        file.len() >= TS && file[0] == 0x47,
        "{} is not an MPEG-TS file",
        path.display()
    );
    let kbps = a["bitrate_kbps"].as_f64().unwrap_or(2000.0);
    let per_message = Duration::from_secs_f64(MESSAGE as f64 * 8.0 / (kbps * 1000.0));
    let started = Instant::now();
    let (mut messages, mut bytes) = (0u64, 0u64);
    let mut ts = TsTally::default();
    for chunk in file.chunks(MESSAGE) {
        let due = per_message * messages as u32;
        let elapsed = started.elapsed();
        if due > elapsed {
            tokio::time::sleep(due - elapsed).await;
        }
        ts.feed(chunk);
        socket
            .send((std::time::Instant::now(), Bytes::copy_from_slice(chunk)))
            .await?;
        messages += 1;
        bytes += chunk.len() as u64;
        while let Some(Some(s)) = futures::FutureExt::now_or_never(stats_stream.next()) {
            *latest = Some(s);
        }
    }
    // Let the last packets be acknowledged (and retransmitted if lost) before reporting.
    let drain = Instant::now() + Duration::from_secs(1);
    while let Ok(Some(s)) = tokio::time::timeout(
        drain.saturating_duration_since(Instant::now()),
        stats_stream.next(),
    )
    .await
    {
        *latest = Some(s);
    }
    Ok(
        json!({"operation": "send_file", "messages": messages, "bytes": bytes, "ts_packets": ts.packets, "pids": ts.pids, "stream_types": ts.stream_types, "statistics": stats(latest.as_ref())}),
    )
}

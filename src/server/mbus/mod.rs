//! M-Bus slave — NetGet is an M-Bus/IP gateway with one or more meters behind it.
//!
//! An M-Bus/IP gateway is a transparent bridge between TCP and the two-wire bus: a master
//! (libmbus's `mbus-tcp-*` tools, a SCADA system) writes EN 13757-2 telegrams to the socket and
//! reads the meters' answers back from it, byte for byte. NetGet plays the gateway and every
//! meter on its bus. Rust runs the link layer — framing, checksums, addressing, selection, the
//! FCB rule, multi-telegram readouts — and encodes the application layer; the model decides
//! each meter's readings and whether it accepts a write or a reset.
//!
//! ## One telegram at a time
//!
//! M-Bus is half duplex and master driven: a master sends one telegram and waits for the
//! answer (or a timeout) before it sends the next. The connection loop does the same — read a
//! telegram, answer it (asking the model if it must), read the next — so a meter never answers
//! two requests at once, and the read deadline never runs while the model is thinking (see
//! [`IdleTimeoutReader`](crate::server::accept_bounded::IdleTimeoutReader)).
//!
//! ## What the model is asked, and what it is not
//!
//! - **REQ_UD2** for a fresh readout raises `mbus_request_data`. A repeated FCB (the master did
//!   not get the last answer) resends the previous telegram, and the telegrams after the first
//!   of a multi-telegram readout are sent from the readout the model already gave — neither
//!   reaches the model.
//! - **SND_UD** with data records (CI 0x51) raises `mbus_write_data`; with an application reset
//!   (CI 0x50) `mbus_application_reset`.
//! - **SND_NKE**, **REQ_UD1**, **selection** (CI 0x52) and **baud rate** changes are link
//!   layer: Rust answers E5 for each addressed meter and the model is not asked.
//!
//! ## Collisions
//!
//! Several meters can answer one telegram: two meters at one primary address, a selection mask
//! matching two, a REQ_UD2 to 254. On a real bus their answers overlap and garble; through a
//! gateway the master reads more bytes than one answer. NetGet writes each meter's answer back
//! to back, which is what masters test for (libmbus reads on after an answer and reports a
//! collision if anything else arrives). It does not fabricate line noise.
//!
//! ## Failing closed
//!
//! A readout the model cannot answer — an LLM error, an answer NetGet cannot encode — is
//! answered with a RSP_UD holding the meter's identity, **no records** and the status byte's
//! application bits (busy when the model is overloaded, error otherwise): the master learns
//! the meter is present and has nothing to report, and no reading is invented. A write or
//! application reset the model cannot answer is **not** acknowledged — E5 would accept a
//! change nobody approved — so the master times out, which is how M-Bus refuses. Every event
//! logs one `decision=`: `model_answer`, `model_reject`, `model_silent`,
//! `fail_closed_bad_action`, `fail_closed_llm_error`, `fail_closed_llm_overloaded`.
pub mod actions;
pub mod frame;
pub mod records;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::state::ServerId;
use actions::{MbusProtocol, MeterConfig};
use anyhow::Result;
use frame::{addr, c, ci, Frame, Parsed};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Concurrent master connections.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;
/// The read deadline before a new connection's first byte.
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(60);

pub struct MbusServer;

/// What every connection shares: the meters on the bus. Their identity is configuration, but a
/// write can move a meter to a new primary address, and the access number counts every fresh
/// telegram whichever master asked.
struct Shared {
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: ServerId,
    meters: std::sync::Mutex<Vec<MeterState>>,
}

#[derive(Clone, Copy)]
struct MeterState {
    config: MeterConfig,
    access: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Request,
    Send,
}

/// The previous FCB-counted transaction with one meter, kept to resend on a repeated FCB.
#[derive(Clone)]
struct Last {
    fcb: bool,
    kind: Kind,
    response: Vec<u8>,
}

/// Link-layer state between one master connection and one meter.
#[derive(Clone, Default)]
struct Link {
    selected: bool,
    last: Option<Last>,
    /// Telegrams of the current readout not yet sent (each already framed).
    pending: VecDeque<Vec<u8>>,
}

struct Conn {
    shared: Arc<Shared>,
    connection_id: ConnectionId,
    links: Vec<Link>,
}

impl Conn {
    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.shared.status_tx))
    }

    fn meters(&self) -> Vec<MeterState> {
        self.shared
            .meters
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default()
    }

    /// Which meters a primary address reaches, and whether they answer.
    fn targets(&self, a: u8) -> (Vec<usize>, &'static str, bool) {
        let meters = self.meters();
        match a {
            addr::NETWORK_LAYER => (
                (0..meters.len())
                    .filter(|i| self.links[*i].selected)
                    .collect(),
                "secondary",
                true,
            ),
            addr::BROADCAST_REPLY => ((0..meters.len()).collect(), "broadcast", true),
            addr::BROADCAST_NO_REPLY => ((0..meters.len()).collect(), "broadcast", false),
            a => (
                (0..meters.len())
                    .filter(|i| meters[*i].config.primary_address == a)
                    .collect(),
                "primary",
                true,
            ),
        }
    }
}

impl MbusServer {
    pub async fn spawn(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        meters: Vec<MeterConfig>,
        idle: Duration,
    ) -> Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        let summary = meters
            .iter()
            .map(|m| format!("{}@{}", m.address.to_hex(), m.primary_address))
            .collect::<Vec<_>>()
            .join(", ");
        // The E2E harness parses the port out of everything after the last "on ".
        Log::new(Some(&status_tx)).info(format!(
            "M-Bus gateway with {} meter(s) [{summary}] listening on {local_addr}",
            meters.len()
        ));
        let shared = Arc::new(Shared {
            app_state: app_state.clone(),
            llm_client,
            status_tx: status_tx.clone(),
            server_id,
            meters: std::sync::Mutex::new(
                meters
                    .into_iter()
                    .map(|config| MeterState { config, access: 0 })
                    .collect(),
            ),
        });
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let registrar = app_state.clone();
        let accept = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    // A gateway has no way to say "busy" in M-Bus: the refused master is closed.
                    b"",
                    "M-Bus",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote, permit)) => {
                        let shared = shared.clone();
                        let local = stream.local_addr().unwrap_or(local_addr);
                        let owner = app_state.clone();
                        owner
                            .spawn_server_task(server_id, async move {
                                let _permit = permit;
                                if let Err(e) =
                                    handle_connection(shared.clone(), stream, remote, local, idle)
                                        .await
                                {
                                    Log::new(Some(&shared.status_tx)).debug(format!(
                                        "M-Bus connection from {remote} ended: {e:#}"
                                    ));
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("M-Bus accept failed, stopping loop: {e}"));
                        break;
                    }
                }
            }
        });
        registrar.register_server_task(server_id, accept).await;
        Ok(local_addr)
    }
}

async fn handle_connection(
    shared: Arc<Shared>,
    stream: TcpStream,
    remote: SocketAddr,
    local: SocketAddr,
    idle: Duration,
) -> Result<()> {
    let app_state = shared.app_state.clone();
    let server_id = shared.server_id;
    let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);
    let _ = stream.set_nodelay(true);
    let (read_half, mut write_half) = tokio::io::split(stream);
    let now = crate::utils::clock::Instant::now();
    app_state
        .add_connection_to_server(
            server_id,
            ConnectionState {
                id: connection_id,
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
    let _ = shared.status_tx.send("__UPDATE_UI__".to_string());
    let n_meters = shared.meters.lock().map(|m| m.len()).unwrap_or(0);
    let mut conn = Conn {
        shared: shared.clone(),
        connection_id,
        links: vec![Link::default(); n_meters],
    };
    let mut reader = crate::server::accept_bounded::IdleTimeoutReader::with_first(
        read_half,
        FIRST_BYTE_TIMEOUT.min(idle),
        idle,
    );
    // Never more than one telegram's bytes plus one read: `parse` consumes or skips whatever
    // a whole telegram (or a broken one) occupies.
    let mut buf: Vec<u8> = Vec::with_capacity(frame::MAX_FRAME_LEN * 2);
    let mut chunk = [0u8; frame::MAX_FRAME_LEN];
    // Bytes discarded since the last whole telegram. Line noise on a bus is a few bytes; more
    // than a whole telegram's worth that is not M-Bus is a peer that does not speak it, and
    // the gateway hangs up rather than reading on for ever.
    let mut junk = 0usize;
    let result: Result<()> = async {
        loop {
            let frame = loop {
                match frame::parse(&buf) {
                    Parsed::Frame(f, used) => {
                        buf.drain(..used);
                        junk = 0;
                        break f;
                    }
                    Parsed::Invalid { skip, reason } => {
                        let skip = skip.min(buf.len());
                        buf.drain(..skip);
                        junk += skip;
                        if junk > frame::MAX_FRAME_LEN {
                            conn.log().warn(format!(
                                "M-Bus {remote}: {junk} bytes without a valid telegram (more \
                                 than the {}-byte longest one); closing \
                                 decision=protocol_error",
                                frame::MAX_FRAME_LEN
                            ));
                            return Ok(());
                        }
                        conn.log().warn(format!(
                            "M-Bus {remote}: discarded {skip} byte(s), {reason}; no meter \
                             answers a garbled telegram decision=protocol_error"
                        ));
                        continue;
                    }
                    Parsed::Incomplete(_) => {}
                }
                let n = match reader.read(&mut chunk).await {
                    Ok(0) => return Ok(()),
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        conn.log().info(format!(
                            "M-Bus master {remote} silent for {idle:?}; closing \
                             decision=protocol_timeout"
                        ));
                        return Ok(());
                    }
                    Err(e) => return Err(e.into()),
                };
                buf.extend_from_slice(&chunk[..n]);
                app_state
                    .update_connection_stats(
                        server_id,
                        connection_id,
                        Some(n as u64),
                        None,
                        Some(1),
                        None,
                    )
                    .await;
            };
            let reply = answer(&mut conn, &frame).await;
            if !reply.is_empty() {
                write_half.write_all(&reply).await?;
                write_half.flush().await?;
                app_state
                    .update_connection_stats(
                        server_id,
                        connection_id,
                        None,
                        Some(reply.len() as u64),
                        None,
                        Some(1),
                    )
                    .await;
            }
        }
    }
    .await;
    let _ = write_half.shutdown().await;
    app_state
        .remove_connection_from_server(server_id, connection_id)
        .await;
    let _ = shared.status_tx.send("__UPDATE_UI__".to_string());
    result
}

/// What the meters say to one telegram, every answering meter's bytes back to back.
async fn answer(conn: &mut Conn, f: &Frame) -> Vec<u8> {
    let log = conn.log();
    let (c, a) = match f {
        Frame::Ack => {
            log.debug("M-Bus E5 from the master ignored (only slaves acknowledge)");
            return Vec::new();
        }
        Frame::Short { c, a } | Frame::Control { c, a, .. } | Frame::Long { c, a, .. } => (*c, *a),
    };
    if c & c::DIR_M2S == 0 {
        log.debug(format!(
            "M-Bus {} is slave-to-master traffic; ignored",
            f.describe()
        ));
        return Vec::new();
    }
    let function = c::function(c);
    match f {
        Frame::Short { .. } if function == c::function(c::SND_NKE) => snd_nke(conn, a),
        Frame::Short { .. } if function == c::function(c::REQ_UD2) => req_ud2(conn, c, a).await,
        Frame::Short { .. } if function == c::function(c::REQ_UD1) => {
            // No meter here raises alarms: class 1 data is "nothing", which is E5.
            let (targets, _, reply) = conn.targets(a);
            if reply {
                vec![frame::ACK; targets.len()]
            } else {
                Vec::new()
            }
        }
        Frame::Control { ci, .. } | Frame::Long { ci, .. }
            if function == c::function(c::SND_UD) =>
        {
            snd_ud(conn, c, a, *ci, f.data()).await
        }
        _ => {
            log.info(format!(
                "M-Bus {} to address {a} is not something a meter answers; ignored",
                f.describe()
            ));
            Vec::new()
        }
    }
}

/// SND_NKE: every addressed meter resets its link (FCB, a readout in progress) and answers E5.
/// At 253 it also ends the selection.
fn snd_nke(conn: &mut Conn, a: u8) -> Vec<u8> {
    let (targets, _, reply) = conn.targets(a);
    for i in &targets {
        let link = &mut conn.links[*i];
        link.last = None;
        link.pending.clear();
        if a == addr::NETWORK_LAYER {
            link.selected = false;
        }
    }
    if reply {
        vec![frame::ACK; targets.len()]
    } else {
        Vec::new()
    }
}

fn fcb_of(c: u8) -> Option<bool> {
    (c & c::FCV != 0).then_some(c & c::FCB != 0)
}

async fn req_ud2(conn: &mut Conn, c: u8, a: u8) -> Vec<u8> {
    let (targets, addressed_by, reply) = conn.targets(a);
    let fcb = fcb_of(c);
    let status_tx = conn.shared.status_tx.clone();
    let log = Log::new(Some(&status_tx));
    let mut out = Vec::new();
    for i in targets {
        let meters = conn.meters();
        let Some(meter) = meters.get(i).copied() else {
            continue;
        };
        let label = meter.config.address.to_hex();
        let link = &mut conn.links[i];
        // The master did not get our last answer: the same FCB again means "repeat".
        if let (Some(fcb), Some(last)) = (fcb, &link.last) {
            if last.fcb == fcb && last.kind == Kind::Request {
                log.info(format!(
                    "M-Bus REQ_UD2 for meter {label} repeats FCB {}; resending the last \
                     telegram",
                    u8::from(fcb)
                ));
                out.extend_from_slice(&last.response.clone());
                continue;
            }
            // A toggled FCB with telegrams left: the next one of the readout.
            if last.kind == Kind::Request && !link.pending.is_empty() {
                if let Some(next) = link.pending.pop_front() {
                    log.info(format!(
                        "M-Bus REQ_UD2 for meter {label}: next telegram of the readout ({} \
                         left after it)",
                        link.pending.len()
                    ));
                    link.last = Some(Last {
                        fcb,
                        kind: Kind::Request,
                        response: next.clone(),
                    });
                    out.extend(next);
                    continue;
                }
            }
        }
        link.pending.clear();
        let mut telegrams = readout(conn, i, meter, addressed_by, fcb).await;
        if telegrams.is_empty() {
            conn.links[i].last = None;
            continue;
        }
        let first = telegrams.remove(0);
        let link = &mut conn.links[i];
        link.pending = telegrams.into_iter().collect();
        link.last = fcb.map(|fcb| Last {
            fcb,
            kind: Kind::Request,
            response: first.clone(),
        });
        out.extend(first);
    }
    if reply {
        out
    } else {
        Vec::new()
    }
}

/// Reserve `n` access numbers on a meter; the first one.
fn take_access(conn: &Conn, i: usize, n: usize) -> u8 {
    let Ok(mut meters) = conn.shared.meters.lock() else {
        return 0;
    };
    let Some(m) = meters.get_mut(i) else {
        return 0;
    };
    let first = m.access;
    m.access = m.access.wrapping_add(n as u8);
    first
}

fn frame_telegrams(primary: u8, telegrams: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    telegrams
        .into_iter()
        .filter_map(|data| {
            Frame::long(c::RSP_UD, primary, ci::RSP_VARIABLE, data)
                .encode()
                .ok()
        })
        .collect()
}

/// A RSP_UD with the meter's identity, no records and the status's application bits.
fn failure_telegram(conn: &Conn, i: usize, meter: MeterState, status_bits: u8) -> Vec<Vec<u8>> {
    let access = take_access(conn, i, 1);
    match records::pack_telegrams(meter.config.address, access, status_bits, &[]) {
        Ok(t) => frame_telegrams(meter.config.primary_address, t),
        Err(_) => Vec::new(),
    }
}

/// Ask the model for a fresh readout and frame it: one telegram, or several when the records
/// do not fit one. Empty when the meter stays silent.
async fn readout(
    conn: &Conn,
    i: usize,
    meter: MeterState,
    addressed_by: &str,
    fcb: Option<bool>,
) -> Vec<Vec<u8>> {
    let label = meter.config.address.to_hex();
    let log = conn.log();
    let event = Event::new(
        &actions::REQUEST_DATA_EVENT,
        json!({
            "meter": meter.config.json(),
            "addressed_by": addressed_by,
            "fcb": fcb,
        }),
    );
    let (chosen, refused) = match ask(conn, &event, &label).await {
        Ok(answered) => answered,
        Err((bits, tag)) => {
            log.error(format!(
                "M-Bus REQ_UD2 for meter {label} not answered by the model; RSP_UD with no \
                 records and {} status decision={tag}",
                if bits == records::status::APPLICATION_BUSY {
                    "application_busy"
                } else {
                    "application_error"
                }
            ));
            return failure_telegram(conn, i, meter, bits);
        }
    };
    match chosen {
        Some((name, data)) if name == actions::RESULT_RESPOND => {
            let packed = actions::respond_from_json(&data).and_then(|(encoded, status)| {
                // Pack with a placeholder access number to learn how many telegrams it takes,
                // then reserve exactly that many.
                let n = records::pack_telegrams(meter.config.address, 0, status, &encoded)?.len();
                let access = take_access(conn, i, n);
                records::pack_telegrams(meter.config.address, access, status, &encoded)
            });
            match packed {
                Ok(t) => {
                    let n_records = data["records"].as_array().map(Vec::len).unwrap_or(0);
                    log.info(format!(
                        "M-Bus REQ_UD2 for meter {label} decision=model_answer: {n_records} \
                         record(s) in {} telegram(s)",
                        t.len()
                    ));
                    frame_telegrams(meter.config.primary_address, t)
                }
                Err(e) => {
                    log.error(format!(
                        "M-Bus REQ_UD2 for meter {label}: the model's records cannot be sent \
                         ({e:#}); answering with no records and application_error status \
                         decision=fail_closed_bad_action"
                    ));
                    failure_telegram(conn, i, meter, records::status::APPLICATION_ERROR)
                }
            }
        }
        Some((name, data)) if name == actions::RESULT_SILENT => {
            log.info(format!(
                "M-Bus REQ_UD2 for meter {label} decision=model_reject: the meter stays silent \
                 ({})",
                data["reason"].as_str().unwrap_or("no reason given")
            ));
            Vec::new()
        }
        _ if !refused.is_empty() => {
            log.error(format!(
                "M-Bus REQ_UD2 for meter {label} produced no usable action ({refused}); \
                 answering with no records and application_error status \
                 decision=fail_closed_bad_action"
            ));
            failure_telegram(conn, i, meter, records::status::APPLICATION_ERROR)
        }
        _ => {
            log.warn(format!(
                "M-Bus REQ_UD2 for meter {label} produced no action; the meter stays silent \
                 decision=model_silent"
            ));
            Vec::new()
        }
    }
}

/// What the model answered: the first result naming a reply, and the refusals of anything the
/// executor rejected.
type Answered = (Option<(String, Value)>, String);

/// Call the model. `Err` carries the status bits and decision tag of a failed call (the caller
/// logs it): busy when the model is overloaded, error otherwise.
async fn ask(
    conn: &Conn,
    event: &Event,
    label: &str,
) -> std::result::Result<Answered, (u8, &'static str)> {
    match call_llm(
        &conn.shared.llm_client,
        &conn.shared.app_state,
        conn.shared.server_id,
        Some(conn.connection_id),
        event,
        &MbusProtocol::new(),
    )
    .await
    {
        Ok(x) => {
            for m in x.messages {
                let _ = conn.shared.status_tx.send(m);
            }
            let mut results = Vec::new();
            flatten(x.protocol_results, &mut results);
            let chosen = results.into_iter().find_map(|r| match r {
                ActionResult::Custom { name, data } => Some((name, data)),
                _ => None,
            });
            let refused = x
                .failures
                .iter()
                .map(|f| format!("{}: {}", f.action, f.error))
                .collect::<Vec<_>>()
                .join("; ");
            Ok((chosen, refused))
        }
        Err(e) => {
            let (bits, tag) = match crate::utils::wire_failure::WireFailure::classify(&e) {
                crate::utils::wire_failure::WireFailure::Overloaded => (
                    records::status::APPLICATION_BUSY,
                    "fail_closed_llm_overloaded",
                ),
                crate::utils::wire_failure::WireFailure::Unavailable => {
                    (records::status::APPLICATION_ERROR, "fail_closed_llm_error")
                }
            };
            conn.log().debug(format!(
                "M-Bus {} for meter {label}: model call failed: {e:#}",
                event.event_type.id
            ));
            Err((bits, tag))
        }
    }
}

fn flatten(results: Vec<ActionResult>, out: &mut Vec<ActionResult>) {
    for r in results {
        match r {
            ActionResult::Multiple(inner) => flatten(inner, out),
            other => out.push(other),
        }
    }
}

async fn snd_ud(conn: &mut Conn, c: u8, a: u8, ci_byte: u8, data: &[u8]) -> Vec<u8> {
    match ci_byte {
        ci::SELECT => select(conn, a, data),
        ci::SELECT_MODE2 => {
            conn.log().info(
                "M-Bus mode-2 selection (CI 0x56, big-endian identification) is not \
                 supported; no meter answers"
                    .to_string(),
            );
            Vec::new()
        }
        ci::BAUD_FIRST..=ci::BAUD_LAST => {
            // The gateway's TCP side has no baud rate; each addressed meter acknowledges.
            let (targets, _, reply) = conn.targets(a);
            if reply {
                vec![frame::ACK; targets.len()]
            } else {
                Vec::new()
            }
        }
        ci::DATA_SEND | ci::APPLICATION_RESET => write(conn, c, a, ci_byte, data).await,
        other => {
            conn.log().info(format!(
                "M-Bus SND_UD with CI {other:#04x} is not supported; no meter answers"
            ));
            Vec::new()
        }
    }
}

/// Secondary selection (CI 0x52 at 253): every meter whose secondary address the mask matches
/// is selected and answers E5; every other meter is deselected.
fn select(conn: &mut Conn, a: u8, data: &[u8]) -> Vec<u8> {
    if a != addr::NETWORK_LAYER {
        conn.log().info(format!(
            "M-Bus selection sent to address {a}, not 253; no meter answers"
        ));
        return Vec::new();
    }
    if data.len() != 8 {
        conn.log().info(format!(
            "M-Bus selection with {} bytes (extended selection by fabrication number is not \
             supported); no meter answers",
            data.len()
        ));
        return Vec::new();
    }
    let mut mask = [0u8; 8];
    mask.copy_from_slice(data);
    let meters = conn.meters();
    let mut matched = 0usize;
    for (i, m) in meters.iter().enumerate() {
        let hit = m.config.address.matches(&mask);
        conn.links[i].selected = hit;
        if hit {
            matched += 1;
        }
    }
    conn.log().debug(format!(
        "M-Bus selection {} matches {matched} meter(s)",
        frame::mask_to_hex(&mask)
    ));
    vec![frame::ACK; matched]
}

/// SND_UD carrying data (CI 0x51) or an application reset (CI 0x50).
async fn write(conn: &mut Conn, c: u8, a: u8, ci_byte: u8, data: &[u8]) -> Vec<u8> {
    let (targets, addressed_by, reply) = conn.targets(a);
    let fcb = fcb_of(c);
    let decoded = if ci_byte == ci::DATA_SEND {
        match records::decode_records(data) {
            Ok(d) => Some(d),
            Err(e) => {
                conn.log().warn(format!(
                    "M-Bus SND_UD data to address {a} cannot be decoded ({e:#}); no meter \
                     answers decision=protocol_error"
                ));
                return Vec::new();
            }
        }
    } else {
        None
    };
    let mut out = Vec::new();
    for i in targets {
        let meters = conn.meters();
        let Some(meter) = meters.get(i).copied() else {
            continue;
        };
        let label = meter.config.address.to_hex();
        if let (Some(fcb), Some(last)) = (fcb, &conn.links[i].last) {
            if last.fcb == fcb && last.kind == Kind::Send {
                conn.log().info(format!(
                    "M-Bus SND_UD for meter {label} repeats FCB {}; acknowledging again without \
                     applying it twice",
                    u8::from(fcb)
                ));
                out.extend_from_slice(&last.response.clone());
                continue;
            }
        }
        let (event, what) = match &decoded {
            Some(d) => (
                Event::new(
                    &actions::WRITE_DATA_EVENT,
                    json!({
                        "meter": meter.config.json(),
                        "addressed_by": addressed_by,
                        "records": d.records,
                        "global_readout": d.global_readout,
                    }),
                ),
                "SND_UD data",
            ),
            None => (
                Event::new(
                    &actions::APPLICATION_RESET_EVENT,
                    json!({
                        "meter": meter.config.json(),
                        "addressed_by": addressed_by,
                        "subcode": data.first(),
                    }),
                ),
                "application reset",
            ),
        };
        let accepted = match ask(conn, &event, &label).await {
            Err((_, tag)) => {
                conn.log().error(format!(
                    "M-Bus {what} for meter {label} not answered by the model; not \
                     acknowledged decision={tag}"
                ));
                false
            }
            Ok((Some((name, _)), _)) if name == actions::RESULT_ACK => {
                conn.log().info(format!(
                    "M-Bus {what} for meter {label} decision=model_answer: acknowledged"
                ));
                true
            }
            Ok((Some((name, data)), _)) if name == actions::RESULT_SILENT => {
                conn.log().info(format!(
                    "M-Bus {what} for meter {label} decision=model_reject: not acknowledged \
                     ({})",
                    data["reason"].as_str().unwrap_or("no reason given")
                ));
                false
            }
            Ok((other, refused)) => {
                if other.is_some() || !refused.is_empty() {
                    conn.log().error(format!(
                        "M-Bus {what} for meter {label} produced no usable answer ({}); not \
                         acknowledged decision=fail_closed_bad_action",
                        if refused.is_empty() {
                            "mbus_respond_data does not answer a write".to_string()
                        } else {
                            refused
                        }
                    ));
                } else {
                    conn.log().warn(format!(
                        "M-Bus {what} for meter {label} produced no action; not acknowledged \
                         decision=model_silent"
                    ));
                }
                false
            }
        };
        if !accepted {
            continue;
        }
        let link = &mut conn.links[i];
        if decoded.is_none() {
            // An application reset abandons the readout in progress.
            link.pending.clear();
        }
        link.last = fcb.map(|fcb| Last {
            fcb,
            kind: Kind::Send,
            response: vec![frame::ACK],
        });
        if let Some(d) = &decoded {
            apply_bus_address(conn, i, d, &label);
        }
        out.push(frame::ACK);
    }
    if reply {
        out
    } else {
        Vec::new()
    }
}

/// An acknowledged write carrying a bus_address record moves the meter to that primary address.
fn apply_bus_address(conn: &Conn, i: usize, d: &records::Decoded, label: &str) {
    let Some(new) = d
        .records
        .iter()
        .filter(|r| r["quantity"] == "bus_address")
        .find_map(|r| r["value"].as_u64())
    else {
        return;
    };
    if new > addr::MAX_PRIMARY as u64 {
        conn.log().warn(format!(
            "M-Bus meter {label}: bus_address {new} is above 250; primary address unchanged"
        ));
        return;
    }
    if let Ok(mut meters) = conn.shared.meters.lock() {
        if let Some(m) = meters.get_mut(i) {
            let old = m.config.primary_address;
            m.config.primary_address = new as u8;
            conn.log().info(format!(
                "M-Bus meter {label} moved from primary address {old} to {new}"
            ));
        }
    }
}

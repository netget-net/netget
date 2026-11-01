//! RTP server (RFC 3550).
//!
//! Binds a UDP socket and speaks Real-time Transport Protocol. When a datagram arrives it is
//! parsed as RTP (or RTCP) and turned into an event; the model answers by *describing* what the
//! stream should carry (a tone, DTMF, silence) and this server synthesizes G.711 and frames it
//! into correct RTP packets sent back to the peer. See `media.rs` for the VNC-style text-to-media
//! engine, shared with the `rtsp` control server.
//!
//! # RTP is high-rate, so the model is behind a budget
//!
//! A single G.711 stream is 50 packets per second, and the model does not belong on that path:
//! one LLM call per inbound datagram would exhaust the budget in seconds, and every consultation
//! that does happen can authorize up to 30 seconds of outbound media — so an attacker spoofing
//! a source address gets an amplifier as well. Two gates stand in front of `call_llm`, in the
//! shape `src/server/tuntap/` established:
//!
//! ```text
//!   datagram ─▶ GATE 1  run the handler; did it ANSWER?  ── yes ──▶ no model call, always runs
//!              │        (script / static / manual rule)
//!              └─▶ GATE 2  a rolling per-minute budget   ── over ──▶ dropped,
//!                          (`llm_max_per_minute`, 30)                decision=fail_closed_rate_limited
//! ```
//!
//! Gate 1 is why the budget is safe to set low: script and static handlers are the intended way
//! to run RTP at rate and are never charged. **The exemption is decided by the handler's answer,
//! not by its presence in the routing table** — a `Script` rule whose language is unknown, whose
//! interpreter is missing, or whose code throws answers `FallbackToLlm`, and such a datagram is
//! charged like any unclaimed one. Deciding this from configuration was a live defect in this
//! file: `call_llm` dispatches the handler itself, so a declining script reached the model with
//! the budget already skipped, at wire rate, with `llm_max_per_minute` inert. See
//! `tests/handler_result_decides_the_bound_test.rs` and
//! `tests/server/rtp/script_fallback_budget_test.rs`.
//!
//! Gate 2 is a *ceiling*, not a smoothing filter — a sliding window rather than a leaky bucket,
//! so "never more than N in any minute" is literally true. Setting `llm_max_per_minute` to 0
//! forbids model consultation outright, which is the right configuration for a server driven
//! entirely by handlers.

pub mod actions;
pub mod media;

use crate::server::connection::ConnectionId;
use crate::utils::clock::Instant;
use anyhow::Result;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{error, trace};

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::event_handler_executor::EventHandlerResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::{Event, StartupParams};
use crate::scripting::EventHandlerType;
use crate::server::RtpProtocol;
use crate::state::app_state::AppState;
use actions::{RTCP_RECEIVED_EVENT, RTP_RECEIVED_EVENT};
use media::{AudioCodec, RtpPacketizer};

/// Default ceiling on model consultations per rolling minute.
///
/// Deliberately far below a real stream's 50 packets per second: the model is for deciding what
/// a stream carries, not for being asked about every frame of it.
pub const DEFAULT_LLM_MAX_PER_MINUTE: u32 = 30;

/// A rolling one-minute ceiling on model consultations.
///
/// A sliding window rather than a token bucket, for the same reason `tuntap::EscalationBudget`
/// is: the guarantee the parameter promises is the literal one — never more than N in any
/// minute. A leaky bucket refilling continuously permits exactly the short bursts this exists
/// to prevent.
#[derive(Debug)]
pub struct RtpLlmBudget {
    max_per_minute: u32,
    window: Duration,
    hits: VecDeque<Instant>,
    /// Consultations refused since the last time a refusal was reported to the operator. The
    /// status channel is unbounded and RTP is high-rate, so one line per dropped packet would
    /// itself be the denial of service; the count is folded into the next report instead.
    suppressed: u64,
}

impl RtpLlmBudget {
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_minute,
            window: Duration::from_secs(60),
            hits: VecDeque::new(),
            suppressed: 0,
        }
    }

    pub fn max_per_minute(&self) -> u32 {
        self.max_per_minute
    }

    /// Take one consultation if the window has room. Returns false when it does not.
    pub fn try_take(&mut self) -> bool {
        self.try_take_at(Instant::now())
    }

    /// [`Self::try_take`] against a caller-supplied clock, so the window is testable without
    /// sleeping for a minute.
    pub fn try_take_at(&mut self, now: Instant) -> bool {
        if self.max_per_minute == 0 {
            return false;
        }
        while let Some(front) = self.hits.front() {
            if now.duration_since(*front) >= self.window {
                self.hits.pop_front();
            } else {
                break;
            }
        }
        if self.hits.len() as u32 >= self.max_per_minute {
            return false;
        }
        self.hits.push_back(now);
        true
    }

    /// Record a refusal and say whether it should be reported loudly.
    ///
    /// The first refusal after a period of admissions is reported with however many were
    /// suppressed before it; the rest go to the file log only.
    pub fn note_refusal(&mut self) -> Option<u64> {
        self.suppressed += 1;
        if self.suppressed == 1 {
            Some(0)
        } else {
            None
        }
    }

    /// Clear the suppression counter, returning how many refusals went unreported.
    pub fn take_suppressed(&mut self) -> u64 {
        std::mem::take(&mut self.suppressed)
    }
}

/// Startup configuration read from declared parameters.
#[derive(Debug, Clone)]
pub struct RtpConfig {
    /// Ceiling on model consultations per rolling minute. Zero forbids them entirely.
    pub llm_max_per_minute: u32,
}

impl Default for RtpConfig {
    fn default() -> Self {
        Self {
            llm_max_per_minute: DEFAULT_LLM_MAX_PER_MINUTE,
        }
    }
}

impl RtpConfig {
    /// Read the declared startup parameters. Propagates the parameter error with `?` rather
    /// than unwrapping it, so a bad value names itself instead of killing the spawn task.
    pub fn from_params(params: &Option<StartupParams>) -> Result<Self> {
        let mut cfg = Self::default();
        let Some(params) = params else {
            return Ok(cfg);
        };
        if let Some(v) = params.get_optional_u64("llm_max_per_minute")? {
            if v > u32::MAX as u64 {
                anyhow::bail!("llm_max_per_minute {v} is out of range");
            }
            cfg.llm_max_per_minute = v as u32;
        }
        Ok(cfg)
    }
}

/// RTP server that generates/answers media streams under LLM control.
pub struct RtpServer;

impl RtpServer {
    /// Spawn the RTP server. Awaits the socket bind so a failure is reported to
    /// `server_startup` as `Err`, and registers the accept loop so `stop_server` can abort it.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        cfg: RtpConfig,
    ) -> Result<SocketAddr> {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        let local_addr = socket.local_addr()?;
        Log::new(Some(&status_tx)).info(format!(
            "RTP server listening on {} (llm_max_per_minute={})",
            local_addr, cfg.llm_max_per_minute
        ));

        let protocol = Arc::new(RtpProtocol::new());
        let task_registrar = app_state.clone();
        let budget = Arc::new(Mutex::new(RtpLlmBudget::new(cfg.llm_max_per_minute)));

        let accept_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65535];
            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((n, peer_addr)) => {
                        let data = buffer[..n].to_vec();
                        // One connection entry per *peer*, not per datagram. Adding one for
                        // every packet made a 50 pps stream push 50 rows and 50
                        // `__UPDATE_UI__` messages a second onto the unbounded status channel,
                        // and left `send_rtp_audio`'s remote-address lookup picking the first
                        // of a hundred identical entries.
                        let connection_id =
                            Self::track_peer(&app_state, server_id, peer_addr, local_addr, n).await;
                        if connection_id.is_none() {
                            trace!("RTP datagram for a server that is no longer registered");
                            continue;
                        }
                        let connection_id = connection_id.expect("checked is_none above");

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let socket_clone = socket.clone();
                        let protocol_clone = protocol.clone();
                        let budget_clone = budget.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                Self::handle_datagram(
                                    &data,
                                    peer_addr,
                                    local_addr,
                                    connection_id,
                                    server_id,
                                    &llm_clone,
                                    &state_clone,
                                    &status_clone,
                                    &socket_clone,
                                    protocol_clone.as_ref(),
                                    &budget_clone,
                                )
                                .await;
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx)).error(format!("RTP recv error: {}", e));
                    }
                }
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;
        Ok(local_addr)
    }

    /// Attribute an inbound datagram to a connection entry for `peer_addr`, creating one only
    /// if this peer has no live entry.
    ///
    /// Returns `None` when the server is gone from state, which is the one case where there is
    /// nothing to attribute the packet to. RTP declares `.connectionless()`, so the 10-second
    /// idle sweep reclaims entries for peers that have stopped sending; a peer that resumes
    /// simply gets a fresh one.
    async fn track_peer(
        state: &AppState,
        server_id: crate::state::ServerId,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        bytes: usize,
    ) -> Option<ConnectionId> {
        let existing = state
            .with_server_mut(server_id, |s| {
                s.connections
                    .values_mut()
                    .find(|c| c.remote_addr == peer_addr)
                    .map(|c| {
                        c.bytes_received += bytes as u64;
                        c.packets_received += 1;
                        c.last_activity = crate::utils::clock::Instant::now();
                        c.id
                    })
            })
            .await;

        match existing {
            // Server not registered any more.
            None => None,
            // Registered, and this peer already has an entry that has just been updated.
            Some(Some(id)) => Some(id),
            // Registered, first datagram from this peer: add an entry and repaint once.
            Some(None) => {
                use crate::state::server::{
                    ConnectionState as ServerConnectionState, ConnectionStatus,
                    ProtocolConnectionInfo,
                };
                let id = ConnectionId::new(state.get_next_unified_id().await);
                let now = crate::utils::clock::Instant::now();
                state
                    .add_connection_to_server(
                        server_id,
                        ServerConnectionState {
                            id,
                            remote_addr: peer_addr,
                            local_addr,
                            bytes_sent: 0,
                            bytes_received: bytes as u64,
                            packets_sent: 0,
                            packets_received: 1,
                            last_activity: now,
                            status: ConnectionStatus::Active,
                            status_changed_at: now,
                            protocol_info: ProtocolConnectionInfo::empty(),
                        },
                    )
                    .await;
                Some(id)
            }
        }
    }

    /// What the *configuration* says would answer this event. **Diagnostics only.**
    ///
    /// This must never decide whether the budget applies, and it used to. A `Script` rule
    /// reads as "answers in-process, costs no model call" right up until
    /// `execute_script_handler` returns `FallbackToLlm` — `python3` not installed, an unknown
    /// language name, or a script that threw — and by then the gate had been skipped on the
    /// strength of the rule merely *existing*. `call_llm` then dispatched the same handler
    /// itself, watched it decline, and consulted the model uncharged. On a 50 pps stream that
    /// is 50 uncounted consultations a second with `llm_max_per_minute` inert, and each one
    /// can authorize up to 30 seconds of outbound media.
    ///
    /// [`Self::handle_datagram`] therefore runs the handler and branches on its **answer**,
    /// the way `tuntap::handle_frame` does. What is left for this function is the one thing
    /// the answer cannot express: that a rule was configured and did *not* answer, which in
    /// the log is otherwise indistinguishable from no rule at all.
    pub async fn configured_handler_kind(
        state: &AppState,
        server_id: crate::state::ServerId,
        event_type_id: &str,
    ) -> Option<&'static str> {
        let config = state.get_event_handler_config(server_id).await?;
        match config.find_handler(event_type_id)? {
            EventHandlerType::Script { .. } => Some("script"),
            EventHandlerType::Static { .. } => Some("static"),
            EventHandlerType::Manual { .. } => Some("manual"),
            EventHandlerType::Llm { .. } => Some("llm"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_datagram(
        data: &[u8],
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        llm: &OllamaClient,
        state: &AppState,
        status_tx: &mpsc::UnboundedSender<String>,
        socket: &UdpSocket,
        protocol: &RtpProtocol,
        budget: &Mutex<RtpLlmBudget>,
    ) {
        let is_rtcp = media::is_rtcp(data);
        let base = serde_json::json!({
            "peer_addr": peer_addr.to_string(),
            "local_addr": local_addr.to_string(),
            "connection_id": connection_id.to_string(),
        });

        let event = if is_rtcp {
            let mut d = base;
            d["packet_type"] = serde_json::json!(data.get(1).copied().unwrap_or(0));
            d["length"] = serde_json::json!(data.len());
            Event {
                event_type: &RTCP_RECEIVED_EVENT,
                data: d,
            }
        } else {
            let parsed = match media::parse_rtp(data) {
                Some(p) => p,
                None => {
                    Log::new(Some(status_tx)).warn(format!(
                        "RTP unparseable datagram from {} ({} bytes)",
                        peer_addr,
                        data.len()
                    ));
                    return;
                }
            };
            Log::new(Some(status_tx)).trace(format!(
                "RTP in: pt={} seq={} ts={} ssrc={:08x} len={}",
                parsed.payload_type,
                parsed.sequence,
                parsed.timestamp,
                parsed.ssrc,
                parsed.payload_len
            ));
            let mut d = base;
            d["payload_type"] = serde_json::json!(parsed.payload_type);
            d["sequence"] = serde_json::json!(parsed.sequence);
            d["timestamp"] = serde_json::json!(parsed.timestamp);
            d["ssrc"] = serde_json::json!(parsed.ssrc);
            d["marker"] = serde_json::json!(parsed.marker);
            d["payload_len"] = serde_json::json!(parsed.payload_len);
            Event {
                event_type: &RTP_RECEIVED_EVENT,
                data: d,
            }
        };

        let event_id = event.event_type.id.clone();

        // Gate 1: a deterministic rule answers in-process and is never charged — but the
        // exemption belongs to a rule that *answered*, not to one that was merely configured.
        // Inspecting `find_handler` and skipping gate 2 on a `Script` match was the hole:
        // `execute_script_handler` returns `FallbackToLlm` when the language name is unknown,
        // when the interpreter is missing, or when the script throws, and `call_llm` — which
        // dispatches the handler again itself — then reached the model with the budget already
        // bypassed. So the handler runs here and its answer decides.
        //
        // Gate 2: everything the handler did not answer is charged to the rolling per-minute
        // budget. Without it a 50 pps stream is 50 LLM calls a second, and each consultation
        // can authorize up to 30 seconds of outbound media, so a spoofed source address turns
        // the server into an amplifier. Over budget the datagram is dropped and nothing goes on
        // the wire, which is the same silence every other RTP failure produces — hence the
        // `decision=` tag.
        let handler_outcome = crate::llm::event_handler_executor::try_execute_event_handler(
            state,
            server_id,
            Some(connection_id),
            &event_id,
            &event.event_type.description,
            Some(event.data.clone()),
            Some(protocol),
        )
        .await;

        let (result, answered_by) = match handler_outcome {
            Ok(EventHandlerResult::Handled(r)) => {
                // `call_llm` is not reached on this path, so the two things it does for every
                // event regardless of who answers are done here: the pipe tap, which must fire
                // even when a handler answers, and the access-log entry the dashboard's request
                // pane reads. Skipping them would make a handler-answered datagram invisible.
                crate::pipe::dispatch_pipes(state, server_id, &event).await;
                state
                    .record_access_log(
                        crate::state::AccessLogOwner::Server(server_id.as_u32()),
                        protocol.protocol_name(),
                        Some(connection_id.as_u32()),
                        &event_id,
                        event.data.clone(),
                        r.access_log_actions(),
                    )
                    .await;
                (r, "handler")
            }
            Err(e) => {
                // A manual rule that timed out or was dismissed, or a handler that failed
                // hard. RTP has no error frame, so this is the same silence as a backend
                // failure and is separated from it only by its tag.
                Log::new(Some(status_tx)).error(format!(
                    "RTP {} from {} decision=fail_closed_handler_error; no media sent: {}",
                    event_id, peer_addr, e
                ));
                return;
            }
            Ok(EventHandlerResult::FallbackToLlm { .. }) => {
                let refused = {
                    let mut b = budget.lock().expect("RTP budget mutex poisoned");
                    if b.try_take() {
                        None
                    } else {
                        let report_now = b.note_refusal().is_some();
                        Some((b.max_per_minute(), report_now))
                    }
                };
                if let Some((max, report_now)) = refused {
                    // A configured rule that declined is the case an operator will otherwise
                    // misread: the routing table says "a handler answers this" and the charge
                    // says otherwise. Name it.
                    let why = match Self::configured_handler_kind(state, server_id, &event_id).await
                    {
                        Some(kind @ ("script" | "static" | "manual")) => format!(
                            " (the {kind} rule for this event did not answer — an unknown \
                                 language, a missing interpreter or a failing script falls \
                                 through to the model, which is charged)"
                        ),
                        _ => String::new(),
                    };
                    let line = format!(
                        "RTP {} from {} decision=fail_closed_rate_limited; no media sent \
                         (already used the {} model consultation(s) this minute allows — raise \
                         llm_max_per_minute, or answer this event with a script/static handler, \
                         which is never charged){}",
                        event_id, peer_addr, max, why
                    );
                    if report_now {
                        Log::new(Some(status_tx)).warn(line);
                    } else {
                        trace!("{line}");
                    }
                    return;
                }
                // Admitted: report anything that was dropped while the window was full, so the
                // count is not lost just because the flood stopped.
                let suppressed = {
                    let mut b = budget.lock().expect("RTP budget mutex poisoned");
                    b.take_suppressed()
                };
                if suppressed > 1 {
                    Log::new(Some(status_tx)).warn(format!(
                        "RTP dropped {} further datagram(s) over the model budget before this one",
                        suppressed - 1
                    ));
                }

                // `call_llm` dispatches the handlers again before reaching the model. For a
                // handler that has just said it cannot answer that is a second no-op (an
                // unknown or missing language) or a second failing script run — wasteful, not
                // harmful, and the alternative is a second entry point into `src/llm/` whose
                // two copies would drift. The *answering* path never gets here, so nothing that
                // answered is ever run twice: no script that produced actions runs again, and
                // no manual rule parks twice.
                match call_llm(llm, state, server_id, Some(connection_id), &event, protocol).await {
                    Ok(r) => (r, "model"),
                    Err(e) => {
                        // Fail closed: RTP is a one-way media transport with no error frame and
                        // no request/response turn, so we emit nothing on the wire rather than
                        // falling through to some default stream (which would fabricate media
                        // the model never authorized) or inventing an RTCP BYE for a session we
                        // never joined. The peer is not blocked on us; the operator is the one
                        // who needs to know, so the whole error goes to the log and the status
                        // stream and nothing goes to the socket.
                        //
                        // `decision=` mirrors `src/server/radius/`: an operator greps
                        // `fail_closed_` to find every datagram the model did not actually
                        // answer, and the overloaded / errored split is kept even though RTP
                        // has no way to express it on the wire. There is no `model_reject`
                        // counterpart — RTP has no accept/deny semantics, so a model declining
                        // to stream is exactly the `*_sent_nothing` case below.
                        let decision = if crate::utils::WireFailure::classify(&e).is_overloaded() {
                            "fail_closed_backend_overloaded"
                        } else {
                            "fail_closed_backend_error"
                        };
                        Log::new(Some(status_tx)).error(format!(
                            "RTP {} from {} decision={}; no media sent: {}",
                            event_id, peer_addr, decision, e
                        ));
                        return;
                    }
                }
            }
        };

        if result.raw_actions.is_empty() {
            // Whoever answered, answered "stream nothing". For RTP that is legitimate — a
            // receiver owes its sender no media — but on the wire it is byte-identical to a
            // backend outage, so the two must be separable here.
            Log::new(Some(status_tx)).info(format!(
                "RTP {} from {} decision={}_sent_nothing (no media requested)",
                event_id, peer_addr, answered_by
            ));
        }
        for action in &result.raw_actions {
            Self::execute_send_action(action, peer_addr, socket, status_tx, state, server_id).await;
        }
    }

    /// Interpret one model action and, if it is a media-send, synthesize and transmit RTP.
    async fn execute_send_action(
        action: &serde_json::Value,
        peer_addr: SocketAddr,
        socket: &UdpSocket,
        status_tx: &mpsc::UnboundedSender<String>,
        state: &AppState,
        server_id: crate::state::ServerId,
    ) {
        let action_type = action.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match action_type {
            "send_rtp_audio" => {
                Self::send_rtp_audio(action, peer_addr, socket, status_tx, state, server_id).await;
            }
            "send_rtcp_sender_report" => {
                Self::send_rtcp(action, peer_addr, socket, status_tx).await;
            }
            // Common/no-op actions (set_memory, notify_operator, …) are executed by the shared
            // executor already; nothing to put on the wire here.
            "" => {
                Log::new(Some(status_tx)).warn(format!(
                    "RTP action with no \"type\" field, ignored: {}",
                    action
                ));
            }
            other => {
                // Not on the wire, but not silent either: a misspelled media action is
                // otherwise indistinguishable from the model deciding to stream nothing.
                Log::new(Some(status_tx)).debug(format!(
                    "RTP no wire output for action type \"{}\" (handled by the shared executor \
                     if it is a common action)",
                    other
                ));
            }
        }
    }

    async fn send_rtp_audio(
        action: &serde_json::Value,
        peer_addr: SocketAddr,
        socket: &UdpSocket,
        status_tx: &mpsc::UnboundedSender<String>,
        state: &AppState,
        server_id: crate::state::ServerId,
    ) {
        let codec = match action
            .get("payload_type")
            .and_then(|v| v.as_str())
            .map(AudioCodec::parse)
            .unwrap_or(Ok(AudioCodec::Pcmu))
        {
            Ok(c) => c,
            Err(e) => {
                Log::new(Some(status_tx)).warn(format!("RTP send_rtp_audio: {}", e));
                return;
            }
        };
        let content = match media::parse_audio_content(action) {
            Ok(c) => c,
            Err(e) => {
                Log::new(Some(status_tx)).warn(format!("RTP send_rtp_audio content: {}", e));
                return;
            }
        };
        let duration_ms = action
            .get("duration_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000);
        let payload = match media::synthesize(codec, &content, duration_ms) {
            Ok(p) => p,
            Err(e) => {
                Log::new(Some(status_tx)).warn(format!("RTP synthesis: {}", e));
                return;
            }
        };

        let ssrc = action
            .get("ssrc")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or_else(|| rand::random());
        let seq = action
            .get("start_sequence")
            .and_then(|v| v.as_u64())
            .map(|v| v as u16);
        let ts = action
            .get("start_timestamp")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let mut packetizer = RtpPacketizer::new(ssrc, codec.payload_type(), seq, ts);
        let packets = packetizer.packetize(&payload, media::G711_SAMPLES_PER_FRAME);

        let mut sent = 0u64;
        let mut bytes = 0u64;
        for pkt in &packets {
            match socket.send_to(pkt, peer_addr).await {
                Ok(w) => {
                    sent += 1;
                    bytes += w as u64;
                }
                Err(e) => {
                    error!("RTP send failed to {}: {}", peer_addr, e);
                    break;
                }
            }
            // Pace at the frame interval (20 ms) so this is a real-time stream, not a burst.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        state
            .with_server_mut(server_id, |s| {
                if let Some(c) = s
                    .connections
                    .values_mut()
                    .find(|c| c.remote_addr == peer_addr)
                {
                    c.bytes_sent += bytes;
                    c.packets_sent += sent;
                }
            })
            .await;
        // FileOnly: the send_rtp_audio action's own log_template already reports
        // "-> RTP {content} {payload_type} {duration_ms}ms" to the TUI at INFO.
        Log::new(Some(status_tx)).debug(format!(
            "RTP sent {} {} packet(s) ({} bytes) to {}",
            sent,
            codec.rtpmap_name(),
            bytes,
            peer_addr
        ));
    }

    async fn send_rtcp(
        action: &serde_json::Value,
        peer_addr: SocketAddr,
        socket: &UdpSocket,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        let ssrc = action
            .get("ssrc")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or_else(rand::random);
        let rtp_ts = action
            .get("rtp_timestamp")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let packet_count = action
            .get("packet_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let octet_count = action
            .get("octet_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let sr = media::build_rtcp_sender_report(ssrc, rtp_ts, packet_count, octet_count);
        match socket.send_to(&sr, peer_addr).await {
            Ok(w) => {
                // FileOnly: the send_rtcp_sender_report action's own log_template already
                // reports "-> RTCP SR" to the TUI at INFO.
                Log::new(Some(status_tx)).debug(format!("RTCP SR to {} ({} bytes)", peer_addr, w));
            }
            Err(e) => {
                Log::new(Some(status_tx)).error(format!("RTCP send failed: {}", e));
            }
        }
    }
}

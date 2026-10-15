//! BGP-4 server (RFC 4271).
//!
//! # Division of labour
//!
//! Rust owns the *session*: TCP framing, OPEN validation, capability and hold-time
//! negotiation, the KEEPALIVE cadence, hold-timer expiry, and NOTIFICATION on error. None of
//! that requires reasoning and all of it has to be right on a millisecond budget, so none of it
//! is delegated to the model.
//!
//! The LLM owns the *content*: whether to peer with this neighbour at all, and which routes to
//! announce or withdraw. That is why there is no RIB here and why one is not planned — the root
//! CLAUDE.md forbids protocols from implementing storage, and a RIB is storage. Route state, if
//! a deployment wants any, belongs in the generic SQLite facility or in server memory, reached
//! through actions.
//!
//! # Session flow
//!
//! ```text
//! TCP accept                        -> Connect
//! peer OPEN, validated + negotiated -> bgp_open event -> our OPEN + KEEPALIVE -> OpenConfirm
//! peer KEEPALIVE                    -> Established -> bgp_established event
//! peer UPDATE                       -> bgp_update event
//! hold timer expires                -> NOTIFICATION 4/0, close
//! ```
//!
//! Sending a KEEPALIVE immediately after our OPEN is the step RFC 4271 section 8.2.2 requires
//! to reach OpenConfirm, and it was missing: the old implementation only ever sent a KEEPALIVE
//! in reply to one, so a peer that waits for ours before sending its own would deadlock.
//!
//! # Concurrency
//!
//! The write half is owned by a dedicated task fed by an unbounded channel, so the keepalive
//! ticker keeps the session alive while the read loop is blocked in an LLM call. Sharing a
//! `TcpStream` behind a lock would have meant holding that lock across the LLM await.

pub mod actions;
pub mod wire;

use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};
use tracing::{debug, error, info, trace, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::BgpProtocol;
use crate::state::app_state::AppState;
use crate::state::server::BgpSessionState;
use crate::utils::WireFailure;
use actions::{
    BGP_ESTABLISHED_EVENT, BGP_MESSAGE_INTENT, BGP_NOTIFICATION_EVENT, BGP_OPEN_EVENT,
    BGP_UPDATE_EVENT,
};
use netgauze_bgp_pkt::{capabilities::BgpCapability, BgpMessage};

/// Hold time used unless the peer proposes something shorter, or startup overrides it.
/// RFC 4271 section 4.2 suggests 90; 180 is the near-universal vendor default.
const DEFAULT_HOLD_TIME: u16 = 180;

/// Below this the hold time is unusable (RFC 4271 section 6.2: 1 and 2 are rejected outright).
const MIN_HOLD_TIME: u16 = 3;

/// RFC 4271 section 8.2.2: on entering OpenSent the speaker sets its Hold Timer to "a large
/// value", for which the RFC suggests 4 minutes. It exists precisely because the *negotiated*
/// hold timer cannot start until an OPEN has been exchanged, so until then nothing bounds how
/// long a peer may stay silent.
///
/// Without it a peer that completed the TCP handshake and then sent nothing — or sent a valid
/// header and then stopped — parked `read_exact` forever, holding the connection, its task and
/// its state entry for the life of the process. The negotiated timers were already enforced;
/// this is the window before them.
const OPEN_HOLD_TIME: std::time::Duration = std::time::Duration::from_secs(240);

/// Concurrent sessions this speaker admits before it starts refusing.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. [`OPEN_HOLD_TIME`] bounds how
/// long *one* silent peer holds a slot and it is four minutes by RFC 4271 §8.2.2's own
/// recommendation, so without a cap a stranger connecting once a second pins two hundred and
/// forty sockets before the first becomes eligible to close — and every one of those costs a
/// session task, a writer task, a keepalive timer and an `AppState` row, all of it before a
/// single OPEN has been validated.
///
/// The house default is *generous* for BGP rather than tight, and that is deliberate. A real
/// speaker peers with tens of neighbours, not hundreds, so a number like 64 would fit the
/// traffic — and would hand an attacker a cheap way to lock the configured neighbours out by
/// filling the table with half-open connections. A cap's job is to bound what a stranger can
/// pin, not to be the smallest number that works, so it sits far above any plausible neighbour
/// count while still being finite.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes: NOTIFICATION
/// 6/8, Cease / **Out of Resources**.
///
/// **BGP is the rare protocol here whose refusal needs nothing from the peer.** A NOTIFICATION
/// is a complete message on its own — marker, length, type, error code, subcode — with no
/// field echoing anything the sender has received, so unlike `ipp`'s `server-error-busy` or a
/// MongoDB reply there is nothing to fabricate. RFC 4271 §6 also allows it in *any* state: a
/// speaker in Connect or Active that decides not to proceed sends one and closes, which is
/// precisely this moment. So there is no reason to fall back to silence here.
///
/// **6/8 rather than 6/5, and the difference is what the peer does next.** RFC 4486 §4's
/// `Connection Rejected` reads as the closer match — it is written about a speaker that
/// disallows a connection *after* accepting the transport connection — but it means a
/// permanent, policy refusal ("the peer is not configured locally"), and a conforming
/// implementation treats it as such. A full connection table is transient, and §8's
/// `Out of Resources` is the subcode whose defined handling is damping and retry. It is also
/// what this session already sends when the model backend is saturated
/// ([`SendOutcome::cease_subcode`] maps `WireFailure::Overloaded` to it), so a resource
/// condition speaks with one voice whichever end of the connection it is discovered at.
///
/// Encoded through [`wire::encode_notification`] rather than written as 21 literal bytes, so
/// the marker, length and type cannot drift from what the decoder on the other side of this
/// module expects.
static CONNECTION_CAP_REFUSAL: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
    wire::encode_notification(wire::ERR_CEASE, wire::SUB_CEASE_OUT_OF_RESOURCES, &[])
        .expect("a NOTIFICATION with no data is 21 bytes and cannot exceed the BGP maximum")
});

/// BGP server that handles routing protocol sessions under LLM policy control.
pub struct BgpServer;

impl BgpServer {
    /// Spawn the BGP listener.
    ///
    /// Returns once the socket is bound, so `server_startup` can report a real failure rather
    /// than parking the server in `Running` having bound nothing.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        let config = BgpConfig::from_params(startup_params.as_ref())?;
        Log::new(Some(&status_tx)).info(format!(
            "BGP server listening on {} as AS{} router-id {} hold {}s",
            local_addr, config.local_as, config.router_id, config.hold_time
        ));

        let protocol = Arc::new(BgpProtocol::new());

        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    &CONNECTION_CAP_REFUSAL,
                    "BGP",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id = crate::server::connection::ConnectionId::new(
                            app_state.get_next_unified_id().await,
                        );
                        Log::new(Some(&status_tx)).info(format!(
                            "BGP connection {} from {}",
                            connection_id, remote_addr
                        ));

                        register_connection(&app_state, server_id, connection_id, remote_addr)
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let protocol_clone = protocol.clone();
                        let config_clone = config.clone();

                        let session_registrar = app_state.clone();
                        let session_handle = tokio::spawn(async move {
                            // Released when this task ends, and this task is the whole of the
                            // session even though `run_session` spawns a writer and a
                            // keepalive timer: its only exit path aborts the timer, drops the
                            // last sender and then `.await`s the writer, so nothing outlives
                            // this future and `MAX_CONNECTIONS` caps live sessions rather than
                            // accepts.
                            let _permit = permit;
                            if let Err(e) = run_session(
                                stream,
                                connection_id,
                                server_id,
                                remote_addr,
                                llm_clone,
                                state_clone.clone(),
                                status_clone.clone(),
                                protocol_clone,
                                config_clone,
                            )
                            .await
                            {
                                Log::new(Some(&status_clone))
                                    .error(format!("BGP session error: {}", e));
                            }

                            state_clone
                                .close_connection_on_server(server_id, connection_id)
                                .await;
                            Log::new(Some(&status_clone))
                                .info(format!("BGP connection {} closed", connection_id));
                            let _ = status_clone.send("__UPDATE_UI__".to_string());
                        });
                        // Aborting the accept loop closes the listener but does nothing to
                        // sessions already running: each owns its own socket and keeps sending
                        // keepalives (and spending LLM budget) after `stop_server` reported the
                        // server gone. Registering the session handle is what makes the stop
                        // actually stop. `register_server_task` prunes finished handles on every
                        // call, so a long-lived listener does not accumulate them.
                        session_registrar
                            .register_server_task(server_id, session_handle)
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("Failed to accept BGP connection: {}", e));
                        break;
                    }
                }
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }
}

/// Operator-supplied identity for this speaker.
#[derive(Debug, Clone)]
pub struct BgpConfig {
    pub local_as: u32,
    pub router_id: Ipv4Addr,
    pub hold_time: u16,
}

impl BgpConfig {
    /// Validate startup parameters up front.
    ///
    /// Every value here ends up on the wire, so a bad one is rejected at startup with a message
    /// naming the parameter rather than silently becoming a different, valid-looking value. The
    /// previous code accepted any `as_number` and then truncated it to 16 bits when writing the
    /// OPEN, so AS 4200000000 became AS 60416 with no diagnostic.
    fn from_params(params: Option<&crate::protocol::StartupParams>) -> Result<Self> {
        let Some(params) = params else {
            return Ok(Self {
                local_as: 65000,
                router_id: Ipv4Addr::new(192, 168, 1, 1),
                hold_time: DEFAULT_HOLD_TIME,
            });
        };

        let local_as = params.get_optional_u32("as_number")?.unwrap_or(65000);
        if local_as == 0 {
            return Err(anyhow!("as_number must be between 1 and 4294967295"));
        }

        let router_id = match params.get_optional_string("router_id")? {
            Some(s) => s.parse::<Ipv4Addr>().map_err(|_| {
                anyhow!("router_id must be an IPv4 address in dotted-quad form, got {s:?}")
            })?,
            None => Ipv4Addr::new(192, 168, 1, 1),
        };
        if router_id.is_unspecified() {
            return Err(anyhow!(
                "router_id must not be 0.0.0.0 (RFC 4271 requires a valid BGP Identifier)"
            ));
        }

        let hold_time = match params.get_optional_u64("hold_time")? {
            Some(v) => {
                let v = u16::try_from(v)
                    .map_err(|_| anyhow!("hold_time must be between 0 and 65535, got {v}"))?;
                if v != 0 && v < MIN_HOLD_TIME {
                    return Err(anyhow!(
                        "hold_time must be 0 (timers disabled) or at least {MIN_HOLD_TIME} seconds"
                    ));
                }
                v
            }
            None => DEFAULT_HOLD_TIME,
        };

        Ok(Self {
            local_as,
            router_id,
            hold_time,
        })
    }
}

async fn register_connection(
    app_state: &AppState,
    server_id: crate::state::ServerId,
    connection_id: crate::server::connection::ConnectionId,
    remote_addr: SocketAddr,
) {
    use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
    let now = crate::utils::clock::Instant::now();
    app_state
        .add_connection_to_server(
            server_id,
            ConnectionState {
                id: connection_id,
                remote_addr,
                local_addr: remote_addr,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                last_activity: now,
                status: ConnectionStatus::Active,
                status_changed_at: now,
                protocol_info: ProtocolConnectionInfo::new(serde_json::json!({
                    "bgp_state": "Connect",
                })),
            },
        )
        .await;
}

/// One BGP peering session.
struct BgpSession {
    connection_id: crate::server::connection::ConnectionId,
    server_id: crate::state::ServerId,
    remote_addr: SocketAddr,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<BgpProtocol>,
    config: BgpConfig,

    state: BgpSessionState,
    /// The peer's real ASN: its four-octet-AS capability if it sent one, else the OPEN field.
    peer_as: Option<u32>,
    peer_router_id: Option<Ipv4Addr>,
    /// Whether four-octet AS was negotiated. Decides how inbound AS_PATH is read and how
    /// outbound AS_PATH must be written.
    peer_asn4: bool,
    /// Negotiated hold time: min(ours, theirs). Zero disables both timers.
    hold_time: u16,

    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// `peer_asn4`, mirrored for the peer command task so an injected UPDATE is encoded at the
    /// width this session negotiated.
    peer_asn4_shared: Arc<AtomicBool>,
    /// Seconds since session start at which the last message arrived, for hold-timer expiry.
    last_received: Arc<AtomicU64>,
    started: crate::utils::clock::Instant,
}

/// Outcome of reading one framed message off the wire.
enum Incoming {
    Message(BgpMessage),
    /// Header was structurally invalid; the session must send this NOTIFICATION and close.
    HeaderError(wire::HeaderError),
    /// Body did not parse. The header's type octet travels with it because RFC 4271 forbids
    /// answering a NOTIFICATION with another NOTIFICATION, even a malformed one.
    DecodeError(wire::DecodeError, u8),
    Eof,
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    stream: tokio::net::TcpStream,
    connection_id: crate::server::connection::ConnectionId,
    server_id: crate::state::ServerId,
    remote_addr: SocketAddr,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<BgpProtocol>,
    config: BgpConfig,
) -> Result<()> {
    // Never clone a TcpStream: split it, give the write half to one task, and let everything
    // that needs to send push bytes through a channel.
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Every byte that reaches the wire passes through here, so this is the one place the
    // outbound counters (and `last_activity`) are kept — keepalives, NOTIFICATIONs and injected
    // messages included.
    let stats_state = app_state.clone();
    let writer_task = tokio::spawn(async move {
        while let Some(bytes) = out_rx.recv().await {
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
            stats_state
                .update_connection_stats(
                    server_id,
                    connection_id,
                    None,
                    Some(bytes.len() as u64),
                    None,
                    Some(1),
                )
                .await;
        }
        let _ = writer.shutdown().await;
    });

    let shutdown = Arc::new(Shutdown::default());
    let peer_asn4_shared = Arc::new(AtomicBool::new(false));

    // Dashboard injection ("message this peer" / "disconnect this peer"). Registered before
    // the first read so the operator can reach the session even while a manual rule parks the
    // `bgp_open` event. BGP's wire verbs yield `ActionResult::Custom` intents rather than
    // bytes, so the generic `peer_support::spawn_peer_command_task` cannot encode them; this
    // task runs the same central executor and then the same `wire::encode_intent` the session
    // uses, with the negotiated AS width, and pushes the result down the same write channel.
    let peer_rx = crate::server::peer_support::register_peer_channel(
        &app_state,
        server_id,
        connection_id.as_u32(),
    )
    .await;
    let peer_task = spawn_peer_command_task(
        peer_rx,
        protocol.clone(),
        app_state.clone(),
        server_id,
        connection_id,
        out_tx.clone(),
        peer_asn4_shared.clone(),
        shutdown.clone(),
        status_tx.clone(),
    )
    .await;

    let mut session = BgpSession {
        connection_id,
        server_id,
        remote_addr,
        llm_client,
        app_state,
        status_tx,
        protocol,
        config,
        state: BgpSessionState::Connect,
        peer_as: None,
        peer_router_id: None,
        peer_asn4: false,
        hold_time: 0,
        out_tx,
        peer_asn4_shared,
        last_received: Arc::new(AtomicU64::new(0)),
        started: crate::utils::clock::Instant::now(),
    };

    let mut timer_task: Option<tokio::task::AbortHandle> = None;
    let result = session.run(&mut reader, &shutdown, &mut timer_task).await;

    // Every exit path of the session passes through here, so the peer handle is removed exactly
    // once. The peer task holds a write-channel sender, so it must go before the writer task is
    // awaited below.
    session
        .app_state
        .remove_peer_handle(server_id, connection_id.as_u32())
        .await;
    peer_task.abort();

    // Drop the session (and with it the last non-timer sender) so the writer task drains what
    // is queued — in particular a final NOTIFICATION — and then closes the socket.
    if let Some(handle) = timer_task {
        handle.abort();
    }
    drop(session);
    let _ = writer_task.await;

    result
}

impl BgpSession {
    async fn run(
        &mut self,
        reader: &mut tokio::io::ReadHalf<tokio::net::TcpStream>,
        shutdown: &Arc<Shutdown>,
        timer_task: &mut Option<tokio::task::AbortHandle>,
    ) -> Result<()> {
        debug!("BGP session {} in Connect state", self.connection_id);

        loop {
            if shutdown.is_set() {
                break;
            }
            // Before the OPEN exchange there is no negotiated hold timer, so this deadline is
            // the only thing bounding a silent peer (RFC 4271 section 8.2.2). Afterwards
            // `spawn_timers` owns the schedule and signals expiry through `shutdown`, which the
            // first select arm turns into an exit even from inside a parked read.
            let open_deadline =
                matches!(self.state, BgpSessionState::Connect).then_some(OPEN_HOLD_TIME);

            let (incoming, bytes_in) = tokio::select! {
                biased;
                _ = shutdown.notify.notified() => break,
                result = with_deadline(open_deadline, read_message(reader, self.peer_asn4)) => {
                    match result {
                        Ok(incoming) => incoming,
                        Err(DeadlineExpired) => {
                            Log::new(Some(&self.status_tx)).warn(format!(
                                "BGP peer {} sent no OPEN within {}s, closing (RFC 4271 8.2.2)",
                                self.remote_addr,
                                OPEN_HOLD_TIME.as_secs()
                            ));
                            self.notify(wire::ERR_HOLD_TIMER_EXPIRED, 0, &[]);
                            break;
                        }
                    }
                }
            };
            if bytes_in > 0 {
                self.app_state
                    .update_connection_stats(
                        self.server_id,
                        self.connection_id,
                        Some(bytes_in as u64),
                        None,
                        Some(1),
                        None,
                    )
                    .await;
            }

            match incoming {
                Incoming::Eof => {
                    debug!("BGP connection {} closed by peer", self.connection_id);
                    break;
                }
                Incoming::HeaderError(e) => {
                    Log::new(Some(&self.status_tx)).warn(format!(
                        "BGP header rejected from {}: {:?}",
                        self.remote_addr, e
                    ));
                    let (code, sub) = e.notify_code();
                    self.notify(code, sub, &e.notify_data());
                    break;
                }
                Incoming::DecodeError(e, msg_type) => {
                    Log::new(Some(&self.status_tx)).warn(format!(
                        "BGP message from {} failed to parse: {}",
                        self.remote_addr, e
                    ));
                    if msg_type != wire::MSG_NOTIFICATION {
                        let (code, sub) = e.notify;
                        self.notify(code, sub, &[]);
                    }
                    break;
                }
                Incoming::Message(msg) => {
                    self.last_received
                        .store(self.started.elapsed().as_secs(), Ordering::Relaxed);
                    if !self.dispatch(msg, shutdown, timer_task).await? {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle one decoded message. Returns `false` when the session must close.
    async fn dispatch(
        &mut self,
        msg: BgpMessage,
        shutdown: &Arc<Shutdown>,
        timer_task: &mut Option<tokio::task::AbortHandle>,
    ) -> Result<bool> {
        match (self.state.clone(), msg) {
            (BgpSessionState::Connect, BgpMessage::Open(open)) => {
                self.on_open(open, shutdown, timer_task).await
            }
            // A NOTIFICATION is never answered, in any state (RFC 4271 section 4.5).
            (BgpSessionState::Connect, BgpMessage::Notification(n)) => {
                self.on_notification(n).await;
                Ok(false)
            }
            // RFC 4271 section 6.6: anything else while waiting for an OPEN is an FSM error.
            // Closing silently, as the old code did for unknown types, leaves the peer guessing.
            (BgpSessionState::Connect, _) => {
                self.notify(wire::ERR_FSM, wire::SUB_FSM_OPENSENT, &[]);
                Ok(false)
            }

            (BgpSessionState::OpenConfirm, BgpMessage::KeepAlive) => {
                self.on_established().await?;
                Ok(true)
            }
            (BgpSessionState::OpenConfirm, BgpMessage::Notification(n)) => {
                self.on_notification(n).await;
                Ok(false)
            }
            (BgpSessionState::OpenConfirm, _) => {
                self.notify(wire::ERR_FSM, wire::SUB_FSM_OPENCONFIRM, &[]);
                Ok(false)
            }

            (BgpSessionState::Established, BgpMessage::KeepAlive) => {
                // Deliberately no LLM call. A keepalive arrives every hold/3 seconds for the
                // life of the session; consulting a model each time would spend a request every
                // minute per peer to decide nothing. The hold timer has already been reset by
                // the caller, which is the entire semantics of a KEEPALIVE.
                trace!("BGP KEEPALIVE from {}", self.remote_addr);
                Ok(true)
            }
            (BgpSessionState::Established, BgpMessage::Update(update)) => {
                self.on_update(update).await?;
                Ok(true)
            }
            (BgpSessionState::Established, BgpMessage::Notification(n)) => {
                self.on_notification(n).await;
                Ok(false)
            }
            (BgpSessionState::Established, BgpMessage::RouteRefresh(_)) => {
                // NetGet does not advertise the route-refresh capability, so a conforming peer
                // will not send this. If one does anyway, ignoring it is correct: there is no
                // RIB to re-advertise from. Answering with a Bad Message Type NOTIFICATION, as
                // the old code did for every type it did not recognise, would tear down a
                // perfectly healthy session.
                warn!(
                    "BGP ROUTE-REFRESH from {} ignored: no RIB to re-advertise",
                    self.remote_addr
                );
                Ok(true)
            }
            (BgpSessionState::Established, BgpMessage::Open(_)) => {
                self.notify(wire::ERR_FSM, wire::SUB_FSM_ESTABLISHED, &[]);
                Ok(false)
            }

            (_, BgpMessage::Notification(n)) => {
                self.on_notification(n).await;
                Ok(false)
            }
            (state, msg) => {
                warn!(
                    "BGP {:?} message in unexpected state {:?}",
                    msg.get_type(),
                    state
                );
                self.notify(wire::ERR_FSM, 0, &[]);
                Ok(false)
            }
        }
    }

    /// Validate the peer's OPEN, negotiate, ask the model for a peering decision, reply.
    async fn on_open(
        &mut self,
        open: netgauze_bgp_pkt::open::BgpOpenMessage,
        shutdown: &Arc<Shutdown>,
        timer_task: &mut Option<tokio::task::AbortHandle>,
    ) -> Result<bool> {
        // Version, hold time bounds and BGP Identifier validity are checked by the decoder;
        // reaching here means they passed. What is left is what only we can judge.
        let peer_as = open.my_asn4();
        if peer_as == 0 {
            Log::new(Some(&self.status_tx)).warn("BGP peer advertised AS 0, rejecting");
            self.notify(wire::ERR_OPEN, wire::SUB_BAD_PEER_AS, &[]);
            return Ok(false);
        }
        let peer_hold = open.hold_time();
        if peer_hold != 0 && peer_hold < MIN_HOLD_TIME {
            self.notify(wire::ERR_OPEN, wire::SUB_UNACCEPTABLE_HOLD_TIME, &[]);
            return Ok(false);
        }

        self.peer_as = Some(peer_as);
        self.peer_router_id = Some(open.bgp_id());
        self.peer_asn4 = open
            .capabilities()
            .into_iter()
            .any(|c| matches!(c, BgpCapability::FourOctetAs(_)));
        self.peer_asn4_shared
            .store(self.peer_asn4, Ordering::Relaxed);

        // Provisional negotiation against our configured proposal, so the model can see what
        // the session would settle on. It is recomputed below from the hold time actually put
        // in our OPEN, which a handler is free to override.
        self.hold_time = negotiate_hold(self.config.hold_time, peer_hold);

        Log::new(Some(&self.status_tx)).info(format!(
            "BGP OPEN from AS{} router-id {} hold {}s (asn4={}), negotiated hold {}s",
            peer_as,
            open.bgp_id(),
            peer_hold,
            self.peer_asn4,
            self.hold_time
        ));

        let event = Event {
            event_type: &BGP_OPEN_EVENT,
            data: serde_json::json!({
                "connection_id": self.connection_id.to_string(),
                "peer_as": peer_as,
                "peer_router_id": open.bgp_id().to_string(),
                "peer_hold_time": peer_hold,
                "peer_supports_four_octet_as": self.peer_asn4,
                "peer_capabilities": wire::capabilities_to_json(&open),
                "negotiated_hold_time": self.hold_time,
                "local_as": self.config.local_as,
                "local_router_id": self.config.router_id.to_string(),
                "remote_addr": self.remote_addr.to_string(),
            }),
        };

        let outcome = self.call_llm_and_send(&event).await;

        match outcome {
            // The model explicitly refused. RFC 4271 wants a NOTIFICATION, which it already
            // sent, and the session ends. This path is structurally distinct from "the model
            // said nothing" on purpose: silence must not be readable as refusal, and refusal
            // must not be readable as silence.
            SendOutcome::Refused => {
                info!(
                    "BGP bgp_open decision=model_reject peer={} AS{}",
                    self.remote_addr, peer_as
                );
                Ok(false)
            }
            // The operator opted into a dynamic peering policy (that is the only way an LLM call
            // happens here at all) and it could not be evaluated. Sending the configured OPEN
            // would admit a neighbour the policy might have refused, which is the fail-open
            // pattern the root CLAUDE.md calls the most dangerous in this codebase: a backend
            // outage would silently become "peer with anyone". So refuse — and refuse with the
            // subcode that tells the peer whether to come back.
            SendOutcome::Failed(failure) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "BGP refusing to peer with {} AS{}: peering policy could not be evaluated \
                     (decision=fail_closed_llm_error, {})",
                    self.remote_addr,
                    peer_as,
                    if failure.is_overloaded() {
                        "resource"
                    } else {
                        "unavailable"
                    }
                ));
                self.notify(wire::ERR_CEASE, SendOutcome::cease_subcode(failure), &[]);
                Ok(false)
            }
            SendOutcome::SentOpen { hold_time } => {
                // RFC 4271 section 4.2: the negotiated hold time is the smaller of the two
                // *proposals*. Ours is whatever went into the OPEN we just sent, which is the
                // handler's value and not necessarily the configured one — deriving the timers
                // from the config instead would make NetGet keep a schedule its peer never
                // agreed to.
                self.hold_time = negotiate_hold(hold_time, peer_hold);
                self.after_open_sent(shutdown, timer_task).await;
                Ok(true)
            }
            SendOutcome::Nothing => {
                // The policy ran and produced no OPEN — a `wait_for_more`, or a handler that
                // returned nothing. This is *not* the backend-failure case, which is handled
                // above; the distinction matters because peering is not an authorisation
                // decision when the policy was actually consulted: the operator
                // opened this port with this ASN, and a peer that already completed a TCP
                // handshake gets the configured OPEN. Refusing here would mean an LLM outage
                // silently drops every session it did not explicitly bless.
                Log::new(Some(&self.status_tx)).warn(format!(
                    "BGP no OPEN from handler for {} (decision=model_silent), sending \
                     configured OPEN AS{}",
                    self.remote_addr, self.config.local_as
                ));
                let bytes = wire::encode(wire::build_open(
                    self.config.local_as,
                    self.config.hold_time,
                    self.config.router_id,
                ))?;
                self.send(bytes);
                self.hold_time = negotiate_hold(self.config.hold_time, peer_hold);
                self.after_open_sent(shutdown, timer_task).await;
                Ok(true)
            }
        }
    }

    /// RFC 4271 section 8.2.2: having sent OPEN and received the peer's, send a KEEPALIVE and
    /// enter OpenConfirm. Start the timers here, because from this point the peer is entitled
    /// to expect keepalives at the negotiated cadence.
    async fn after_open_sent(
        &mut self,
        shutdown: &Arc<Shutdown>,
        timer_task: &mut Option<tokio::task::AbortHandle>,
    ) {
        self.send(wire::encode_keepalive());
        self.state = BgpSessionState::OpenConfirm;
        debug!("BGP session {} -> OpenConfirm", self.connection_id);

        if self.hold_time > 0 && timer_task.is_none() {
            *timer_task = Some(
                spawn_timers(
                    self.hold_time,
                    self.out_tx.clone(),
                    self.last_received.clone(),
                    self.started,
                    shutdown.clone(),
                    self.status_tx.clone(),
                    self.connection_id,
                    self.app_state.clone(),
                    self.server_id,
                )
                .await,
            );
        }
    }

    async fn on_established(&mut self) -> Result<()> {
        self.state = BgpSessionState::Established;
        let peer_as = self.peer_as.unwrap_or(0);
        Log::new(Some(&self.status_tx)).info(format!(
            "BGP session {} established with AS{}",
            self.connection_id, peer_as
        ));
        self.set_connection_state("Established").await;

        // The one moment worth a model call on the session path: the peer is up and will accept
        // UPDATEs. Everything the model needs to answer with `send_bgp_update` is here.
        let event = Event {
            event_type: &BGP_ESTABLISHED_EVENT,
            data: serde_json::json!({
                "connection_id": self.connection_id.to_string(),
                "peer_as": peer_as,
                "peer_router_id": self.peer_router_id.map(|r| r.to_string()),
                "peer_supports_four_octet_as": self.peer_asn4,
                "negotiated_hold_time": self.hold_time,
                "local_as": self.config.local_as,
                "local_router_id": self.config.router_id.to_string(),
                "remote_addr": self.remote_addr.to_string(),
            }),
        };
        let outcome = self.call_llm_and_send(&event).await;
        self.log_advertisement_outcome("bgp_established", outcome);
        Ok(())
    }

    /// Log what an advertisement-shaped event decided, keeping the three cases apart.
    ///
    /// Nothing is written to the peer on any of them, and that is protocol-correct: RFC 4271
    /// defines no reply to a session coming up or to an inbound UPDATE, and advertising *no*
    /// routes already is the fail-closed answer — a backend outage must not leak a route, and
    /// tearing an Established session down with a NOTIFICATION because one model call hiccuped
    /// would be a worse answer than advertising nothing. The keepalive ticker runs in its own
    /// task, so the peer is not left hanging either way. What must not happen is the three
    /// cases becoming indistinguishable to the operator, so they are tagged here.
    fn log_advertisement_outcome(&self, event_id: &str, outcome: SendOutcome) {
        match outcome {
            SendOutcome::Failed(failure) => {
                // The error itself was already logged in full by `call_llm_and_send`.
                Log::new(Some(&self.status_tx)).warn(format!(
                    "BGP {} advertised nothing to {} (decision=fail_closed_llm_error, {})",
                    event_id,
                    self.remote_addr,
                    if failure.is_overloaded() {
                        "resource"
                    } else {
                        "unavailable"
                    }
                ));
            }
            SendOutcome::Nothing => debug!(
                "BGP {} decision=model_silent peer={}: nothing advertised",
                event_id, self.remote_addr
            ),
            SendOutcome::Refused => info!(
                "BGP {} decision=model_reject peer={}: NOTIFICATION sent",
                event_id, self.remote_addr
            ),
            SendOutcome::SentOpen { .. } => debug!(
                "BGP {} peer={}: handler answered",
                event_id, self.remote_addr
            ),
        }
    }

    async fn on_update(
        &mut self,
        update: netgauze_bgp_pkt::update::BgpUpdateMessage,
    ) -> Result<()> {
        let parsed = wire::update_to_json(&update);
        info!(
            "BGP UPDATE from AS{:?}: {} withdrawn, {} announced",
            self.peer_as,
            update.withdraw_routes().len(),
            update.nlri().len()
        );

        let mut data = parsed;
        data["connection_id"] = serde_json::json!(self.connection_id.to_string());
        data["peer_as"] = serde_json::json!(self.peer_as);

        let event = Event {
            event_type: &BGP_UPDATE_EVENT,
            data,
        };
        let outcome = self.call_llm_and_send(&event).await;
        self.log_advertisement_outcome("bgp_update", outcome);
        Ok(())
    }

    async fn on_notification(&mut self, n: netgauze_bgp_pkt::notification::BgpNotificationMessage) {
        let (code, subcode) = notification_codes(&n);
        Log::new(Some(&self.status_tx)).warn(format!(
            "BGP NOTIFICATION from {}: {} / {}",
            self.remote_addr,
            wire::error_name(code),
            wire::error_subcode_name(code, subcode)
        ));

        let event = Event {
            event_type: &BGP_NOTIFICATION_EVENT,
            data: serde_json::json!({
                "connection_id": self.connection_id.to_string(),
                "peer_as": self.peer_as,
                "error_code": code,
                "error_name": wire::error_name(code),
                "error_subcode": subcode,
                "error_subcode_name": wire::error_subcode_name(code, subcode),
            }),
        };
        // RFC 4271: a NOTIFICATION is never answered with another message, so anything the model
        // returns here is informational only and is not written to the socket. That makes the
        // call pure observation, so skip it entirely unless the operator opted into LLM handling
        // (a server instruction or a per-event handler) — otherwise it is a wasted round-trip
        // that can change nothing.
        if operator_wants_dynamic(&self.app_state, self.server_id, &event.event_type.id).await {
            // Purely observational: the session is already over and RFC 4271 forbids answering a
            // NOTIFICATION, so a backend failure here changes nothing on the wire. It is still
            // logged with the same tag so an operator sees the outage in one grep.
            if let Err(e) = call_llm(
                &self.llm_client,
                &self.app_state,
                self.server_id,
                Some(self.connection_id),
                &event,
                &*self.protocol,
            )
            .await
            {
                error!(
                    "BGP bgp_notification decision=fail_closed_llm_error category={:?} peer={}: \
                     {:#}",
                    WireFailure::classify(&e),
                    self.remote_addr,
                    e
                );
            }
        }
    }

    /// Run the handler for `event` and write whatever BGP messages it produced.
    async fn call_llm_and_send(&mut self, event: &Event) -> SendOutcome {
        // The BGP OPEN handshake is mechanical: given the configured ASN/router-id/hold-time and
        // a peer that passed validation, the OPEN we send is fully determined — which is exactly
        // why the SendOutcome::Nothing path below already answers a silent handler with the
        // configured OPEN. Advertising routes (established/update) is by contrast a policy
        // decision. So with no operator policy — no server instruction and no per-event handler —
        // we return Nothing WITHOUT an LLM round-trip: bgp_open falls through to the configured
        // OPEN (the correct static handshake), and established/update advertise nothing (correct,
        // there is no policy to apply). The model is consulted only when the operator opts in.
        if !operator_wants_dynamic(&self.app_state, self.server_id, &event.event_type.id).await {
            debug!(
                "BGP {} handled statically (no operator policy configured): no LLM call",
                event.event_type.id
            );
            return SendOutcome::Nothing;
        }

        let result = match call_llm(
            &self.llm_client,
            &self.app_state,
            self.server_id,
            Some(self.connection_id),
            event,
            &*self.protocol,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                // The full error goes to the log and the operator's status stream. Nothing
                // derived from it reaches the peer — a BGP NOTIFICATION has no free-text field
                // at all, so the category is carried by the Cease subcode and nothing else.
                let failure = WireFailure::classify(&e);
                error!(
                    "BGP {} decision=fail_closed_llm_error category={:?} peer={}: {:#}",
                    event.event_type.id, failure, self.remote_addr, e
                );
                Log::new(Some(&self.status_tx)).warn(format!(
                    "BGP handler for {} could not be run (decision=fail_closed_llm_error): {}",
                    event.event_type.id, e
                ));
                return SendOutcome::Failed(failure);
            }
        };

        let mut outcome = SendOutcome::Nothing;
        let mut queue: Vec<ActionResult> = result.protocol_results;
        while let Some(item) = queue.pop() {
            match item {
                ActionResult::Multiple(inner) => queue.extend(inner),
                ActionResult::Custom { name, data } if name == BGP_MESSAGE_INTENT => {
                    let kind = data.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                    match wire::encode_intent(&data, self.peer_asn4) {
                        Ok(bytes) => {
                            self.send(bytes);
                            outcome = match kind {
                                "open" => SendOutcome::SentOpen {
                                    hold_time: data
                                        .get("hold_time")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0)
                                        as u16,
                                },
                                "notification" => SendOutcome::Refused,
                                _ => match outcome {
                                    SendOutcome::Nothing => SendOutcome::Nothing,
                                    other => other,
                                },
                            };
                        }
                        Err(e) => {
                            // Encoding failed, so nothing goes on the wire. Emitting a
                            // half-formed message would be worse than emitting none.
                            Log::new(Some(&self.status_tx))
                                .warn(format!("BGP refused to encode {} action: {}", kind, e));
                        }
                    }
                }
                // Raw bytes are still honoured for any handler that produces them, but no BGP
                // action returns Output any more.
                ActionResult::Output(bytes) => self.send(bytes),
                _ => {}
            }
        }
        outcome
    }

    fn send(&self, bytes: Vec<u8>) {
        if self.out_tx.send(bytes).is_err() {
            debug!("BGP write channel closed on {}", self.connection_id);
        }
    }

    fn notify(&self, code: u8, subcode: u8, data: &[u8]) {
        match wire::encode_notification(code, subcode, data) {
            Ok(bytes) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "BGP NOTIFICATION {} / {} to {}",
                    wire::error_name(code),
                    wire::error_subcode_name(code, subcode),
                    self.remote_addr
                ));
                self.send(bytes);
            }
            Err(e) => error!("BGP could not encode NOTIFICATION {code}/{subcode}: {e}"),
        }
    }

    async fn set_connection_state(&self, state: &str) {
        let server_id = self.server_id;
        let conn_id = self.connection_id;
        let value = serde_json::json!({ "bgp_state": state });
        self.app_state
            .with_server_mut(server_id, |server| {
                if let Some(conn) = server.connections.get_mut(&conn_id) {
                    conn.protocol_info =
                        crate::state::server::ProtocolConnectionInfo::new(value.clone());
                }
            })
            .await;
    }
}

/// Session shutdown signal.
///
/// The flag is the source of truth and the `Notify` only interrupts a parked read. `Notify`
/// alone is not enough: `notify_waiters` wakes tasks that are *already* waiting, so a signal
/// raised while the read loop is inside an LLM call would be dropped and the session would hang
/// until the peer closed the socket.
#[derive(Default)]
struct Shutdown {
    flag: AtomicBool,
    notify: Notify,
}

impl Shutdown {
    fn set(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn is_set(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// Returns true if the operator opted into dynamic (LLM- or handler-driven) responses for this
/// server: either a non-empty server instruction was given, or an event handler is configured
/// for `event_id`. When false the session applies its static default and never consults the
/// model — for BGP that means the configured OPEN on the handshake and no route advertisement.
async fn operator_wants_dynamic(
    state: &AppState,
    server_id: crate::state::ServerId,
    event_id: &str,
) -> bool {
    state
        .with_server_mut(server_id, |server| {
            let has_instruction = !server.instruction.trim().is_empty();
            let has_handler = server
                .event_handler_config
                .as_ref()
                .map(|c| c.find_handler(event_id).is_some())
                .unwrap_or(false);
            has_instruction || has_handler
        })
        .await
        .unwrap_or(false)
}

/// RFC 4271 section 4.2: the session runs on the smaller of the two proposed hold times, and a
/// zero from either side turns the timers off entirely.
fn negotiate_hold(ours: u16, theirs: u16) -> u16 {
    if ours == 0 || theirs == 0 {
        0
    } else {
        ours.min(theirs)
    }
}

/// What a handler's actions amounted to on the OPEN path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendOutcome {
    /// An OPEN was written, proposing this hold time; carry on to OpenConfirm.
    SentOpen { hold_time: u16 },
    /// A NOTIFICATION was written; the model refused to peer.
    Refused,
    /// Nothing usable was produced: `wait_for_more`, an empty handler, or a model that answered
    /// with no BGP action. The operator's policy was *evaluated* and simply said nothing.
    Nothing,
    /// The handler could not be run at all — the backend errored, timed out, or was saturated.
    /// Distinct from [`SendOutcome::Nothing`] on purpose: the policy was never evaluated, so a
    /// caller that treats silence as consent must not treat this the same way.
    Failed(WireFailure),
}

impl SendOutcome {
    /// The Cease subcode a failed handler earns. RFC 4486 separates a resource condition, which
    /// a peer damps and retries, from an outright rejection, which it does not — so a saturated
    /// backend must not be reported as a permanent refusal to peer.
    fn cease_subcode(failure: WireFailure) -> u8 {
        match failure {
            WireFailure::Overloaded => wire::SUB_CEASE_OUT_OF_RESOURCES,
            WireFailure::Unavailable => wire::SUB_CEASE_CONNECTION_REJECTED,
        }
    }
}

/// Keepalive cadence and hold-timer enforcement.
///
/// Runs in its own task so keepalives continue while the read loop is inside an LLM call. Both
/// were previously absent: nothing was sent unless the peer spoke first, and a peer that went
/// silent held the socket forever.
#[allow(clippy::too_many_arguments)]
async fn spawn_timers(
    hold_time: u16,
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    last_received: Arc<AtomicU64>,
    started: crate::utils::clock::Instant,
    shutdown: Arc<Shutdown>,
    status_tx: mpsc::UnboundedSender<String>,
    connection_id: crate::server::connection::ConnectionId,
    app_state: Arc<AppState>,
    server_id: crate::state::ServerId,
) -> tokio::task::AbortHandle {
    // RFC 4271 section 10: KeepaliveTime is a third of the negotiated HoldTime.
    let interval = std::time::Duration::from_secs(u64::from(hold_time).div_ceil(3).max(1));
    // Tracked, not detached. `CLAUDE.md` records this exact task as the reason
    // "register every task you spawn, not just the top one" is a rule: aborting the read
    // loop does not abort what it spawned, so the keepalive timer kept writing to the
    // socket — and kept it open — after the server was stopped.
    let task_owner = app_state.clone();
    task_owner
        .spawn_server_task(server_id, async move {
            let keepalive = wire::encode_keepalive();
            loop {
                tokio::time::sleep(interval).await;

                let elapsed = started.elapsed().as_secs();
                let last = last_received.load(Ordering::Relaxed);
                if elapsed.saturating_sub(last) >= u64::from(hold_time) {
                    Log::new(Some(&status_tx)).warn(format!(
                        "BGP hold timer expired on {} after {}s of silence",
                        connection_id,
                        elapsed.saturating_sub(last)
                    ));
                    if let Ok(bytes) =
                        wire::encode_notification(wire::ERR_HOLD_TIMER_EXPIRED, 0, &[])
                    {
                        let _ = out_tx.send(bytes);
                    }
                    shutdown.set();
                    return;
                }

                if out_tx.send(keepalive.clone()).is_err() {
                    return;
                }
                trace!("BGP KEEPALIVE sent on {}", connection_id);
            }
        })
        .await
}

/// `with_deadline` gave up before `fut` finished.
struct DeadlineExpired;

/// Await `fut`, abandoning it after `limit` when one is given.
///
/// A plain `tokio::time::timeout` cannot express "no limit", and the two cases differ per
/// message here: only the pre-OPEN read is bounded from this loop, because after that the
/// negotiated hold timer runs in its own task.
async fn with_deadline<F: std::future::Future>(
    limit: Option<std::time::Duration>,
    fut: F,
) -> std::result::Result<F::Output, DeadlineExpired> {
    match limit {
        Some(limit) => tokio::time::timeout(limit, fut)
            .await
            .map_err(|_| DeadlineExpired),
        None => Ok(fut.await),
    }
}

/// Read one BGP message: 19-byte header, bounds check, then exactly the declared body.
///
/// Nothing is allocated before the length has been validated against \[19, 4096\], so a peer
/// cannot make the server reserve an arbitrary buffer, and `len - 19` cannot underflow.
///
/// The second element is the number of octets consumed, for the connection's inbound counters.
async fn read_message(
    reader: &mut tokio::io::ReadHalf<tokio::net::TcpStream>,
    asn4: bool,
) -> (Incoming, usize) {
    let mut header = [0u8; wire::BGP_HEADER_LEN];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return (Incoming::Eof, 0),
        Err(e) => {
            debug!("BGP read error: {e}");
            return (Incoming::Eof, 0);
        }
    }

    let (len, msg_type) = match wire::parse_header(&header) {
        Ok(v) => v,
        Err(e) => return (Incoming::HeaderError(e), wire::BGP_HEADER_LEN),
    };

    let mut full = vec![0u8; len];
    full[..wire::BGP_HEADER_LEN].copy_from_slice(&header);
    if len > wire::BGP_HEADER_LEN {
        if let Err(e) = reader.read_exact(&mut full[wire::BGP_HEADER_LEN..]).await {
            debug!("BGP truncated message body: {e}");
            return (Incoming::Eof, wire::BGP_HEADER_LEN);
        }
    }

    let incoming = match wire::decode(&full, asn4) {
        Ok(msg) => Incoming::Message(msg),
        Err(e) => Incoming::DecodeError(e, msg_type),
    };
    (incoming, len)
}

/// Drive one connection's injected-action channel (the dashboard's "message this peer" and
/// "disconnect this peer") until the handle is removed or the session ends.
///
/// Mirrors `peer_support::handle_peer_command` — same central executor, same access-log entry,
/// same reply — but encodes BGP's `Custom` message intents through `wire::encode_intent` at the
/// negotiated AS width and pushes bytes down the session's write channel, so nothing is written
/// that the model's own actions could not have produced. `close_connection` (not offered to the
/// model) executes to `ActionResult::CloseConnection`, which here means what RFC 4271 says a
/// deliberate teardown means: NOTIFICATION 6/2 (Cease / Administrative Shutdown) followed by the
/// close, raised through the session's `Shutdown` so the read loop exits even if the peer never
/// speaks again.
#[allow(clippy::too_many_arguments)]
async fn spawn_peer_command_task(
    mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
    protocol: Arc<BgpProtocol>,
    app_state: Arc<AppState>,
    server_id: crate::state::ServerId,
    connection_id: crate::server::connection::ConnectionId,
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    peer_asn4: Arc<AtomicBool>,
    shutdown: Arc<Shutdown>,
    status_tx: mpsc::UnboundedSender<String>,
) -> tokio::task::AbortHandle {
    use crate::llm::actions::protocol_trait::Protocol;
    use crate::state::client_handles::ClientSendOutcome;
    use crate::state::AccessLogOwner;

    // Tracked, not detached: stop_server must abort this task too.
    let task_owner = app_state.clone();
    task_owner
        .spawn_server_task(server_id, async move {
            while let Some(command) = command_rx.recv().await {
                let action = command.action.clone();
                let outcome = execute_injected_action(
                    &action,
                    protocol.as_ref(),
                    &app_state,
                    server_id,
                    &out_tx,
                    peer_asn4.load(Ordering::Relaxed),
                    &shutdown,
                )
                .await;

                let outcome_json = match &outcome {
                    Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
                    Err(e) => serde_json::json!({"error": e.to_string()}),
                };
                app_state
                    .record_access_log(
                        AccessLogOwner::Server(server_id.as_u32()),
                        protocol.protocol_name(),
                        Some(connection_id.as_u32()),
                        "injected_action",
                        action,
                        vec![outcome_json],
                    )
                    .await;

                match &outcome {
                    Err(e) => warn!(
                        "BGP injected action on server #{} connection {} failed: {}",
                        server_id.as_u32(),
                        connection_id,
                        e
                    ),
                    Ok(ClientSendOutcome::Disconnected) => {
                        app_state
                            .remove_peer_handle(server_id, connection_id.as_u32())
                            .await;
                        app_state
                            .close_connection_on_server(server_id, connection_id)
                            .await;
                    }
                    Ok(_) => {}
                }
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                let _ = command.reply_tx.send(outcome);
            }
            debug!(
                "BGP peer command task for server #{} connection {} ended",
                server_id.as_u32(),
                connection_id
            );
        })
        .await
}

/// Execute one injected action and queue whatever it encodes to.
async fn execute_injected_action(
    action: &serde_json::Value,
    protocol: &BgpProtocol,
    app_state: &AppState,
    server_id: crate::state::ServerId,
    out_tx: &mpsc::UnboundedSender<Vec<u8>>,
    peer_asn4: bool,
    shutdown: &Arc<Shutdown>,
) -> Result<crate::state::client_handles::ClientSendOutcome> {
    use crate::state::client_handles::ClientSendOutcome;

    let cease = |out_tx: &mpsc::UnboundedSender<Vec<u8>>| -> Result<()> {
        let bytes =
            wire::encode_notification(wire::ERR_CEASE, wire::SUB_CEASE_ADMIN_SHUTDOWN, &[])?;
        out_tx
            .send(bytes)
            .map_err(|_| anyhow!("BGP session already closed"))?;
        shutdown.set();
        Ok(())
    };

    let result = crate::llm::actions::executor::execute_actions(
        vec![action.clone()],
        app_state,
        Some(protocol),
        Some(server_id),
        None,
    )
    .await?;

    // The executor records a protocol rejection (unknown verb, bad prefix, AS 0 ...) as a
    // failure and carries on; surface it as such instead of "executed (nothing to write)".
    if let Some(failure) = result.failures.first() {
        return Ok(ClientSendOutcome::Rejected {
            error: failure.error.clone(),
        });
    }

    let mut bytes_sent = 0usize;
    let mut closed = false;
    let mut details: Vec<String> = Vec::new();
    let mut queue: Vec<ActionResult> = result.protocol_results;
    queue.reverse();
    while let Some(item) = queue.pop() {
        match item {
            ActionResult::Multiple(inner) => {
                for item in inner.into_iter().rev() {
                    queue.push(item);
                }
            }
            ActionResult::Custom { name, data } if name == BGP_MESSAGE_INTENT => {
                let bytes = wire::encode_intent(&data, peer_asn4)?;
                bytes_sent += bytes.len();
                out_tx
                    .send(bytes)
                    .map_err(|_| anyhow!("BGP session already closed"))?;
            }
            ActionResult::Output(bytes) => {
                bytes_sent += bytes.len();
                out_tx
                    .send(bytes)
                    .map_err(|_| anyhow!("BGP session already closed"))?;
            }
            ActionResult::CloseConnection => {
                cease(out_tx)?;
                closed = true;
            }
            ActionResult::WaitForMore | ActionResult::NoAction => {}
            other => details.push(format!("{other:?}")),
        }
    }

    Ok(if closed {
        ClientSendOutcome::Disconnected
    } else if bytes_sent > 0 {
        ClientSendOutcome::Sent { bytes_sent }
    } else if details.is_empty() {
        ClientSendOutcome::Executed {
            detail: "executed (nothing to write)".to_string(),
        }
    } else {
        ClientSendOutcome::Executed {
            detail: crate::utils::truncate_for_log(&details.join("; "), 160),
        }
    })
}

/// Recover the (code, subcode) pair from netgauze's typed NOTIFICATION so it can be reported
/// numerically, the way RFC 4271 section 6 names it.
fn notification_codes(n: &netgauze_bgp_pkt::notification::BgpNotificationMessage) -> (u8, u8) {
    use netgauze_bgp_pkt::notification::*;
    match n {
        BgpNotificationMessage::MessageHeaderError(e) => (
            wire::ERR_HEADER,
            match e {
                MessageHeaderError::Unspecific { .. } => 0,
                MessageHeaderError::ConnectionNotSynchronized { .. } => 1,
                MessageHeaderError::BadMessageLength { .. } => 2,
                MessageHeaderError::BadMessageType { .. } => 3,
            },
        ),
        BgpNotificationMessage::OpenMessageError(e) => (
            wire::ERR_OPEN,
            match e {
                OpenMessageError::Unspecific { .. } => 0,
                OpenMessageError::UnsupportedVersionNumber { .. } => 1,
                OpenMessageError::BadPeerAs { .. } => 2,
                OpenMessageError::BadBgpIdentifier { .. } => 3,
                OpenMessageError::UnsupportedOptionalParameter { .. } => 4,
                OpenMessageError::UnacceptableHoldTime { .. } => 6,
                OpenMessageError::UnsupportedCapability { .. } => 7,
                OpenMessageError::RoleMismatch { .. } => 11,
            },
        ),
        BgpNotificationMessage::UpdateMessageError(e) => (
            wire::ERR_UPDATE,
            match e {
                UpdateMessageError::Unspecific { .. } => 0,
                UpdateMessageError::MalformedAttributeList { .. } => 1,
                UpdateMessageError::UnrecognizedWellKnownAttribute { .. } => 2,
                UpdateMessageError::MissingWellKnownAttribute { .. } => 3,
                UpdateMessageError::AttributeFlagsError { .. } => 4,
                UpdateMessageError::AttributeLengthError { .. } => 5,
                UpdateMessageError::InvalidOriginAttribute { .. } => 6,
                UpdateMessageError::InvalidNextHopAttribute { .. } => 8,
                UpdateMessageError::OptionalAttributeError { .. } => 9,
                UpdateMessageError::InvalidNetworkField { .. } => 10,
                UpdateMessageError::MalformedAsPath { .. } => 11,
            },
        ),
        BgpNotificationMessage::HoldTimerExpiredError(e) => (
            wire::ERR_HOLD_TIMER_EXPIRED,
            match e {
                HoldTimerExpiredError::Unspecific { sub_code, .. } => *sub_code,
            },
        ),
        BgpNotificationMessage::FiniteStateMachineError(e) => (
            wire::ERR_FSM,
            match e {
                FiniteStateMachineError::Unspecific { .. } => 0,
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenSentState { .. } => 1,
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenConfirmState { .. } => 2,
                FiniteStateMachineError::ReceiveUnexpectedMessageInEstablishedState { .. } => 3,
            },
        ),
        BgpNotificationMessage::CeaseError(e) => (
            wire::ERR_CEASE,
            match e {
                CeaseError::MaximumNumberOfPrefixesReached { .. } => 1,
                CeaseError::AdministrativeShutdown { .. } => 2,
                CeaseError::PeerDeConfigured { .. } => 3,
                CeaseError::AdministrativeReset { .. } => 4,
                CeaseError::ConnectionRejected { .. } => 5,
                CeaseError::OtherConfigurationChange { .. } => 6,
                CeaseError::ConnectionCollisionResolution { .. } => 7,
                CeaseError::OutOfResources { .. } => 8,
                CeaseError::HardReset { .. } => 9,
                CeaseError::BfdDown { .. } => 10,
            },
        ),
        BgpNotificationMessage::RouteRefreshError(e) => (
            7,
            match e {
                RouteRefreshError::InvalidMessageLength { .. } => 1,
            },
        ),
    }
}

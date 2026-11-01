//! SSDP / UPnP discovery server (UPnP Device Architecture 1.1, §1).
//!
//! HTTPU — HTTP/1.1 syntax in a single UDP datagram — on port 1900, plus the
//! `239.255.255.250` / `FF02::C` multicast groups. This file owns the socket, the multicast
//! join, the MX response jitter and, most importantly, **the rule that a failure produces no
//! datagram at all**.
//!
//! See `src/server/ssdp/CLAUDE.md` for the design rationale, the multicast-on-loopback
//! situation, and the list of things this server deliberately does not implement.

pub mod actions;
pub mod message;

pub use actions::SsdpProtocol;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use actions::{RequestContext, SSDP_MSEARCH_EVENT, SSDP_NOTIFY_EVENT};
use message::{HttpuMessage, SSDP_GROUP_V4, SSDP_GROUP_V6, SSDP_PORT};

/// Default ceiling on the MX jitter. A faithful 5-second wait is correct SSDP and makes
/// every exchange that touches this protocol unusably slow, so the ceiling is an operator
/// knob (`max_response_delay_ms`) with a value that still produces visible jitter.
const DEFAULT_MAX_RESPONSE_DELAY_MS: u64 = 1000;

/// How the datagram was disposed of.
///
/// SSDP cannot express any of these on the wire — a device that answers and a device that is
/// broken are equally silent to a control point — so the log is the *only* place the
/// distinction can live. That is the `radius` discipline applied to a protocol whose safe
/// default is silence rather than denial: `model_reject` (the device does not match, and the
/// model said so) must never be confused with `model_silent` (the model produced nothing) or
/// with `fail_closed_llm_error` (the backend fell over).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The model answered with `send_ssdp_response`; a 200 OK went to the searcher.
    ModelResponse,
    /// The model answered with `send_ssdp_notify`; an announcement went to the group.
    ModelNotify,
    /// The model answered with `no_response`: an explicit, correct refusal to advertise.
    ModelReject,
    /// The model returned no protocol action at all. Nothing is sent.
    ModelSilent,
    /// The model's action could not be rendered. Nothing is sent.
    FailClosedActionError,
    /// The LLM call itself failed. Nothing is sent.
    FailClosedLlmError,
}

impl Decision {
    /// Stable, grep-able token. `decision=fail_closed_` finds every datagram the model did
    /// not actually answer.
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::ModelResponse => "model_response",
            Decision::ModelNotify => "model_notify",
            Decision::ModelReject => "model_reject",
            Decision::ModelSilent => "model_silent",
            Decision::FailClosedActionError => "fail_closed_action_error",
            Decision::FailClosedLlmError => "fail_closed_llm_error",
        }
    }

    /// True when the server, not the model, is the reason nothing was sent.
    pub fn is_fail_closed(&self) -> bool {
        matches!(
            self,
            Decision::FailClosedActionError | Decision::FailClosedLlmError
        )
    }
}

/// What the model asked to be put on the wire, if anything.
enum Reply {
    /// Unicast back to the sender (an M-SEARCH response).
    Unicast(Vec<u8>),
    /// To the multicast group, or to `notify_target` when the operator overrode it.
    Announcement(Vec<u8>),
}

/// Settings resolved once at startup and shared by every datagram.
#[derive(Clone, Debug)]
struct SsdpConfig {
    max_response_delay_ms: u64,
    server_header: String,
    /// `HOST` header value for an outbound NOTIFY — the *protocol's* group, always, because
    /// that is what the header means regardless of where the datagram is actually sent.
    notify_host: String,
    /// Where an outbound NOTIFY is actually sent.
    notify_target: SocketAddr,
}

pub struct SsdpServer;

impl SsdpServer {
    /// Bind the socket, join the multicast group if asked, and start serving.
    ///
    /// Returns `Err` — so `server_startup` sets `ServerStatus::Error` — when the socket
    /// cannot be bound or a startup parameter is unusable. It does **not** return `Err` when
    /// the multicast join fails: see `join_group`.
    pub async fn spawn_with_llm_actions(ctx: SpawnContext) -> Result<SocketAddr> {
        let listen_addr = ctx.legacy_listen_addr();
        let SpawnContext {
            llm_client,
            state,
            status_tx,
            server_id,
            startup_params,
            ..
        } = ctx;

        // Every parameter is read here, and every read one is declared. Errors propagate
        // with `?` so an undeclared key or a wrong type names itself instead of panicking
        // the task that is starting the server.
        let (
            max_response_delay_ms,
            server_header,
            join_multicast,
            multicast_interface,
            notify_override,
        ) = match &startup_params {
            Some(p) => (
                p.get_optional_u64("max_response_delay_ms")?
                    .unwrap_or(DEFAULT_MAX_RESPONSE_DELAY_MS),
                p.get_optional_string("server_header")?,
                p.get_optional_bool("join_multicast")?.unwrap_or(true),
                p.get_optional_string("multicast_interface")?,
                p.get_optional_string("notify_target")?,
            ),
            None => (DEFAULT_MAX_RESPONSE_DELAY_MS, None, true, None, None),
        };

        let socket = Arc::new(
            UdpSocket::bind(listen_addr)
                .await
                .with_context(|| format!("SSDP failed to bind {listen_addr}"))?,
        );
        let local_addr = socket.local_addr()?;

        // The group depends on the family we actually bound, not on what was asked for.
        let (notify_host, default_notify_target) = match local_addr.ip() {
            IpAddr::V4(_) => (
                format!("{SSDP_GROUP_V4}:{SSDP_PORT}"),
                SocketAddr::from((SSDP_GROUP_V4, SSDP_PORT)),
            ),
            IpAddr::V6(_) => (
                format!("[{SSDP_GROUP_V6}]:{SSDP_PORT}"),
                SocketAddr::from((SSDP_GROUP_V6, SSDP_PORT)),
            ),
        };

        let notify_target = match notify_override {
            Some(raw) => raw.parse::<SocketAddr>().with_context(|| {
                format!("SSDP notify_target {raw:?} is not a valid ip:port address")
            })?,
            None => default_notify_target,
        };

        let config = SsdpConfig {
            max_response_delay_ms,
            server_header: server_header
                .unwrap_or_else(|| actions::DEFAULT_SERVER_HEADER.to_string()),
            notify_host,
            notify_target,
        };

        if join_multicast {
            join_group(
                &socket,
                local_addr,
                multicast_interface.as_deref(),
                &status_tx,
            );
        } else {
            info!("SSDP multicast join skipped: join_multicast=false");
            Log::new(Some(&status_tx)).debug(
                "SSDP not joining the multicast group (join_multicast=false); unicast \
                 M-SEARCH still works",
            );
        }

        info!(
            "SSDP server listening on {} (announcements to {})",
            local_addr, config.notify_target
        );
        Log::new(Some(&status_tx)).info(format!("SSDP server listening on {local_addr}"));

        let task_registrar = state.clone();
        let accept_handle = tokio::spawn(async move {
            // 65535 is the largest a UDP datagram can be; `message::parse` refuses anything
            // over MAX_MESSAGE_LEN, so an over-long datagram is reported rather than
            // silently truncated into plausible-looking headers.
            let mut buffer = vec![0u8; 65535];

            loop {
                let (n, peer_addr) = match socket.recv_from(&mut buffer).await {
                    Ok(pair) => pair,
                    Err(e) => {
                        Log::new(Some(&status_tx)).error(format!("SSDP receive error: {e}"));
                        break;
                    }
                };

                let data = buffer[..n].to_vec();
                trace!(
                    "SSDP {} bytes from {}: {:?}",
                    n,
                    peer_addr,
                    String::from_utf8_lossy(&data)
                );

                let parsed = match message::parse(&data) {
                    Ok(m) => m,
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .warn(format!("SSDP dropped datagram from {peer_addr}: {e}"));
                        continue;
                    }
                };

                // A status line is a *response* — another device answering somebody else's
                // search, which lands here whenever we are joined to the group. Answering a
                // response would be a discovery loop.
                let Some(method) = parsed.method.clone() else {
                    debug!(
                        "SSDP ignoring a response ({}) from {}: not a request",
                        parsed.start_line, peer_addr
                    );
                    continue;
                };

                let connection_id =
                    Self::record_connection(&state, server_id, local_addr, peer_addr, n).await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());

                let llm = llm_client.clone();
                let st = state.clone();
                let tx = status_tx.clone();
                let sock = socket.clone();
                let cfg = config.clone();

                let handle = tokio::spawn(async move {
                    Self::handle_request(
                        parsed,
                        method,
                        peer_addr,
                        connection_id,
                        sock,
                        llm,
                        st,
                        tx,
                        server_id,
                        cfg,
                    )
                    .await;
                });

                // Registered, not detached. An M-SEARCH answer can be held back for up to
                // `max_response_delay_ms`, so a task spawned here routinely outlives the
                // datagram that created it, and `stop_server` must be able to cancel it —
                // otherwise a stopped server can still emit an advertisement. (BGP's
                // keepalive timer is the precedent: aborting a loop does not abort what the
                // loop spawned.) `register_server_task` prunes finished handles on every
                // call, so this does not accumulate.
                state.register_server_task(server_id, handle).await;
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    async fn record_connection(
        state: &Arc<AppState>,
        server_id: ServerId,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        bytes: usize,
    ) -> ConnectionId {
        use crate::state::server::{
            ConnectionState as ServerConnectionState, ConnectionStatus, ProtocolConnectionInfo,
        };
        let connection_id = ConnectionId::new(state.get_next_unified_id().await);
        let now = crate::utils::clock::Instant::now();
        let conn_state = ServerConnectionState {
            id: connection_id,
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
        };
        state.add_connection_to_server(server_id, conn_state).await;
        connection_id
    }

    /// Ask the model, apply the MX jitter, then send what it asked for — or nothing.
    #[allow(clippy::too_many_arguments)]
    async fn handle_request(
        request: HttpuMessage,
        method: String,
        peer_addr: SocketAddr,
        connection_id: ConnectionId,
        socket: Arc<UdpSocket>,
        llm_client: crate::llm::ollama_client::OllamaClient,
        state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        config: SsdpConfig,
    ) {
        let search_target = request.header("ST").map(str::to_string);

        let (event, kind) = match method.as_str() {
            "M-SEARCH" => (
                Event::new(&SSDP_MSEARCH_EVENT, Self::msearch_data(&request, peer_addr)),
                "M-SEARCH",
            ),
            "NOTIFY" => (
                Event::new(&SSDP_NOTIFY_EVENT, Self::notify_data(&request, peer_addr)),
                "NOTIFY",
            ),
            other => {
                // SUBSCRIBE/UNSUBSCRIBE are GENA and travel over TCP; anything else is not
                // SSDP at all. Dropped, and said out loud so it is not mistaken for the
                // deliberate silence below.
                warn!(
                    "SSDP ignoring {} from {}: not a message this server serves (only \
                     M-SEARCH and NOTIFY)",
                    other, peer_addr
                );
                return;
            }
        };

        // A real device waits a random interval before answering so a whole network's
        // replies do not arrive at once. Computing the deadline *before* the LLM call and
        // sleeping to it afterwards means the model's own latency counts towards the wait
        // instead of being added to it — so the jitter is a floor on the response time
        // rather than a tax on top of it.
        let delay_ms = message::response_delay_ms(request.mx(), config.max_response_delay_ms);
        let send_at = tokio::time::Instant::now() + std::time::Duration::from_millis(delay_ms);

        let protocol = SsdpProtocol::for_request(RequestContext {
            search_target: search_target.clone(),
            server_header: config.server_header.clone(),
            notify_host: config.notify_host.clone(),
        });

        let llm_outcome = call_llm(&llm_client, &state, server_id, None, &event, &protocol).await;
        let (decision, reply, reason) = Self::decide(llm_outcome, &status_tx, peer_addr);

        // Log the decision before acting on it. Because nothing distinguishes these cases on
        // the wire, this line is the only record that exists.
        let summary = format!(
            "SSDP {} from {} st={} decision={}{}",
            kind,
            peer_addr,
            search_target.as_deref().unwrap_or("-"),
            decision.as_str(),
            reason
                .as_deref()
                .map(|r| format!(" reason={r:?}"))
                .unwrap_or_default(),
        );
        let log = Log::new(Some(&status_tx));
        if decision.is_fail_closed() {
            log.error(format!(
                "{summary} (nothing sent: SSDP has no error message, and every reply it \
                 defines asserts that a device exists)"
            ));
        } else {
            log.info(&summary);
        }

        let Some(reply) = reply else {
            debug!(
                "SSDP sending nothing to {} ({})",
                peer_addr,
                decision.as_str()
            );
            return;
        };

        let (bytes, destination) = match reply {
            Reply::Unicast(bytes) => (bytes, peer_addr),
            Reply::Announcement(bytes) => (bytes, config.notify_target),
        };

        if delay_ms > 0 {
            debug!(
                "SSDP holding the answer to {} for {}ms (MX jitter)",
                peer_addr, delay_ms
            );
            tokio::time::sleep_until(send_at).await;
        }

        match socket.send_to(&bytes, destination).await {
            Ok(sent) => {
                trace!(
                    "SSDP sent {} bytes to {}: {:?}",
                    sent,
                    destination,
                    String::from_utf8_lossy(&bytes)
                );
                state
                    .update_connection_stats(
                        server_id,
                        connection_id,
                        None,
                        Some(sent as u64),
                        None,
                        Some(1),
                    )
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
            }
            Err(e) => {
                // A send to the multicast group commonly fails on a loopback-bound socket
                // (ENETUNREACH / EHOSTUNREACH). That is an environment limitation, not a
                // protocol error, and it must be visible rather than swallowed.
                Log::new(Some(&status_tx)).error(format!(
                    "SSDP failed to send to {destination}: {e}. A send to the multicast \
                     group from a socket bound to 127.0.0.1 fails this way \
                     (EADDRNOTAVAIL): the loopback interface has no multicast route. Bind \
                     0.0.0.0, or set the notify_target startup parameter to a reachable \
                     address."
                ));
            }
        }
    }

    /// **The silence rule.**
    ///
    /// Returns the decision, the bytes to send (if any) and an optional human reason for the
    /// log. Nothing in here can invent a reply: every `Some` came from an action the model
    /// named.
    fn decide(
        llm_outcome: Result<crate::llm::ExecutionResult>,
        status_tx: &mpsc::UnboundedSender<String>,
        peer_addr: SocketAddr,
    ) -> (Decision, Option<Reply>, Option<String>) {
        let log = Log::new(Some(status_tx));

        let execution = match llm_outcome {
            Ok(result) => {
                for message in &result.messages {
                    log.info(message);
                }
                result
            }
            Err(e) => {
                // The category is kept because an overloaded backend and a dead one are
                // worth telling apart after the fact — but neither reaches the wire. There
                // is no header in an SSDP message that could carry it, and inventing one
                // would still be a well-formed advertisement for a device that does not
                // exist.
                let category = match crate::utils::wire_failure::WireFailure::classify(&e) {
                    crate::utils::wire_failure::WireFailure::Overloaded => "overloaded",
                    crate::utils::wire_failure::WireFailure::Unavailable => "unavailable",
                };
                log.error(format!(
                    "SSDP LLM call failed for {peer_addr} (category={category}): {e}"
                ));
                return (Decision::FailClosedLlmError, None, None);
            }
        };

        // Take the first result that says something. Extra results are a model error, not a
        // licence to advertise several devices from one datagram — a control point would
        // record every one of them.
        let mut chosen: Option<(Decision, Option<Reply>, Option<String>)> = None;
        let mut extra = 0usize;

        for result in &execution.protocol_results {
            let candidate = match result {
                ActionResult::Output(bytes) => Some((
                    Decision::ModelResponse,
                    Some(Reply::Unicast(bytes.clone())),
                    None,
                )),
                ActionResult::Custom { name, data } if name == "ssdp_notify" => {
                    data.get("message").and_then(|v| v.as_str()).map(|m| {
                        (
                            Decision::ModelNotify,
                            Some(Reply::Announcement(m.as_bytes().to_vec())),
                            data.get("nts").and_then(|v| v.as_str()).map(str::to_string),
                        )
                    })
                }
                ActionResult::Custom { name, data } if name == "ssdp_no_response" => Some((
                    Decision::ModelReject,
                    None,
                    data.get("reason")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                )),
                // NoAction covers notify_operator / set_memory and friends: bookkeeping, not
                // an answer. It must not be read as a decision either way.
                _ => None,
            };

            match candidate {
                Some(c) if chosen.is_none() => chosen = Some(c),
                Some(_) => extra += 1,
                None => {}
            }
        }

        if extra > 0 {
            warn!(
                "SSDP ignored {} extra protocol result(s) for {}; one datagram gets one \
                 answer",
                extra, peer_addr
            );
        }

        if let Some(chosen) = chosen {
            return chosen;
        }

        // Nothing usable came back. If the model produced actions that failed to render,
        // that is the server's problem to report; if it produced none at all, it simply said
        // nothing. Neither is `model_reject`: an explicit refusal is an action, and
        // conflating them is the OAuth2 mistake in its silence-shaped form.
        if !execution.failures.is_empty() {
            for failure in &execution.failures {
                log.error(format!(
                    "SSDP could not render the model's action for {peer_addr}: {failure:?}"
                ));
            }
            return (Decision::FailClosedActionError, None, None);
        }
        (Decision::ModelSilent, None, None)
    }

    /// Structured payload for `ssdp_msearch`. Headers as a map, never a rendered blob.
    fn msearch_data(request: &HttpuMessage, peer_addr: SocketAddr) -> serde_json::Value {
        serde_json::json!({
            "st": request.header("ST"),
            "mx": request.mx(),
            "man": request.header("MAN"),
            "host": request.header("HOST"),
            "source_address": peer_addr.to_string(),
            "user_agent": request.header("USER-AGENT"),
            "headers": request.headers_json(),
        })
    }

    /// Structured payload for `ssdp_notify`.
    fn notify_data(request: &HttpuMessage, peer_addr: SocketAddr) -> serde_json::Value {
        serde_json::json!({
            "nt": request.header("NT"),
            "nts": request.header("NTS"),
            "usn": request.header("USN"),
            "location": request.header("LOCATION"),
            "server": request.header("SERVER"),
            "cache_control_max_age": max_age_of(request),
            "host": request.header("HOST"),
            "source_address": peer_addr.to_string(),
            "headers": request.headers_json(),
        })
    }
}

/// `max-age` out of a `CACHE-CONTROL` header, as a number the model can compare.
///
/// Handed over as a number rather than the raw `"max-age=1800"` string because a model asked
/// "is this announcement still fresh?" should not have to parse a header directive first.
fn max_age_of(request: &HttpuMessage) -> Option<u64> {
    let value = request.header("CACHE-CONTROL")?;
    value.split(',').find_map(|directive| {
        let (name, v) = directive.split_once('=')?;
        if name.trim().eq_ignore_ascii_case("max-age") {
            v.trim().parse::<u64>().ok()
        } else {
            None
        }
    })
}

/// Join the SSDP multicast group. **Best effort, and deliberately so.**
///
/// A join depends on the interface, the routing table and, on Linux, `CAP_NET_ADMIN`-adjacent
/// policy — none of which this protocol declares a `PrivilegeRequirement` for, because it does
/// not need one to be useful. A server that refused to start when the join failed would be
/// unusable for exactly the local testing this protocol is most often used for: **a unicast
/// M-SEARCH sent straight to the port is answered whether or not the join succeeded**, and
/// that is the whole functional surface minus the ability to overhear the group.
///
/// So a failed join is a warning on both channels, not an `Err`. It is *logged* rather than
/// passed over because a silent failure here presents as "the server is up but never sees any
/// searches", which is indistinguishable from the server being broken.
///
/// **Measured on macOS 27 (Darwin), and not what was expected**: the join succeeds from a
/// socket bound to `127.0.0.1` as well as from `0.0.0.0`, on both `127.0.0.1` and `0.0.0.0`
/// as the interface argument. What fails on a loopback bind is *sending* to the group —
/// `sendto(239.255.255.250:1900)` returns `EADDRNOTAVAIL`, because loopback carries no
/// multicast route. That asymmetry is why `notify_target` exists and why the join is not the
/// thing standing between this server and a local test.
fn join_group(
    socket: &UdpSocket,
    local_addr: SocketAddr,
    multicast_interface: Option<&str>,
    status_tx: &mpsc::UnboundedSender<String>,
) {
    let log = Log::new(Some(status_tx));

    let result = match local_addr.ip() {
        IpAddr::V4(_) => {
            let iface = match multicast_interface {
                Some(raw) => match raw.parse::<Ipv4Addr>() {
                    Ok(ip) => ip,
                    Err(e) => {
                        log.warn(format!(
                            "SSDP multicast_interface {raw:?} is not an IPv4 address ({e}); \
                             falling back to 0.0.0.0"
                        ));
                        Ipv4Addr::UNSPECIFIED
                    }
                },
                None => Ipv4Addr::UNSPECIFIED,
            };
            socket
                .join_multicast_v4(SSDP_GROUP_V4, iface)
                .map(|_| format!("{SSDP_GROUP_V4} on interface {iface}"))
        }
        IpAddr::V6(_) => socket
            .join_multicast_v6(&SSDP_GROUP_V6, 0)
            .map(|_| format!("{SSDP_GROUP_V6} on interface index 0")),
    };

    match result {
        Ok(what) => {
            info!("SSDP joined multicast group {}", what);
            log.info(format!("SSDP joined multicast group {what}"));
        }
        Err(e) => {
            warn!("SSDP multicast join failed: {}", e);
            log.warn(format!(
                "SSDP could not join the multicast group ({e}); the server is running and \
                 still answers unicast M-SEARCH sent to {local_addr}, but it will not \
                 overhear multicast searches. Check the multicast_interface parameter, or \
                 pass join_multicast: false if unicast is all you need."
            ));
        }
    }
}

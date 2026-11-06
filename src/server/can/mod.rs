//! CAN bus (SocketCAN) server — NetGet as an ECU on somebody's vehicle bus.
//!
//! CAN is a broadcast bus, not a network. There is no addressing, no routing, no session and no
//! authentication: every frame reaches every node, and each node decides for itself whether the
//! 11- or 29-bit identifier is one it answers. Arbitration is by identifier — the numerically
//! lowest wins the bus — which is a priority scheme, not a security one.
//!
//! **That is what makes an LLM-driven ECU simulator worth building, and it is the same property
//! that makes it dangerous.** A NetGet instance on a real vehicle bus can claim any identifier
//! and impersonate any controller, and nothing on the bus can tell. See `CLAUDE.md`.
//!
//! # Two transports, one codec
//!
//! The frame format lives in [`frame`] and is pure. This module is the thin layer that moves
//! those bytes, and [`transport`] is the thinner one that touches the OS:
//!
//! * **`transport: "socketcan"`** (the default) — a real `AF_CAN` socket, which exists **only in
//!   the Linux kernel**. On macOS and Windows `spawn()` returns an error naming the reason
//!   rather than reporting a server that is up and hearing nothing. This code has never been
//!   compiled or run; see `CLAUDE.md`.
//! * **`transport: "udp"`** — a testing transport carrying the same `struct can_frame` /
//!   `struct canfd_frame` octets as UDP datagram payloads, so the whole event → handler/LLM →
//!   action → frame path runs unprivileged. No real CAN node speaks it.
//!
//! # LLM failure → silence, and there is no alternative
//!
//! CAN has no error *reply*. The thing called an error frame is not a message: it is six
//! dominant bits transmitted **on top of** a frame in flight, destroying it for every node on the
//! bus, after which the transmitting controller increments an error counter. Enough of them make
//! it error-passive and then bus-off, at which point it has disconnected itself. Emitting one to
//! signal "the backend is down" would corrupt other nodes' traffic and could take this node — or
//! with enough repetition, another — off the bus entirely.
//!
//! So a failure transmits **nothing**, and nothing derived from the error ever reaches the wire.
//! Silence is also completely ordinary on CAN: almost every node ignores almost every frame. The
//! distinction therefore survives only in the log, tagged `decision=` the way
//! `src/server/radius/` tags its own:
//!
//! | Tag | Meaning |
//! |---|---|
//! | `decision=no_policy` | No instruction and no handler — nothing is transmitted and **no LLM call is made** |
//! | `decision=model_reject` | The model answered `no_response` — a real decision |
//! | `decision=model_silent` | The model returned nothing usable |
//! | `decision=fail_closed_overloaded` | The call failed and the backend is saturated (retryable) |
//! | `decision=fail_closed_llm_error` | The call failed otherwise |

pub mod actions;
pub mod frame;
pub mod transport;

use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::{console_debug, console_error, console_info};
use actions::{
    CanProtocol, CAN_BUS_STATE_CHANGED_EVENT, CAN_ERROR_FRAME_EVENT, CAN_FRAME_RECEIVED_EVENT,
    DEFAULT_INTERFACE, NO_RESPONSE_ACTION,
};
use frame::{BusState, CanFrame};
use transport::{FrameSink, TransportKind};

/// How long the blocking `AF_CAN` read parks before checking whether it has been asked to stop.
#[cfg(target_os = "linux")]
const CAN_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// Everything the startup parameters configure. Every field here is read.
#[derive(Debug, Clone)]
struct CanConfig {
    transport: TransportKind,
    interface: String,
    udp_peer: Option<SocketAddr>,
}

impl CanConfig {
    /// Parse and cross-check the startup parameters.
    ///
    /// Errors propagate with `?` — never `unwrap()`. An undeclared key or a wrong-typed value has
    /// to name itself and leave no half-registered server behind, which is why this runs before
    /// anything is opened or bound.
    fn from_params(
        params: Option<&crate::protocol::StartupParams>,
        ctx_interface: Option<String>,
    ) -> Result<Self> {
        let Some(params) = params else {
            return Ok(Self {
                transport: TransportKind::SocketCan,
                interface: ctx_interface.unwrap_or_else(|| DEFAULT_INTERFACE.to_string()),
                udp_peer: None,
            });
        };

        let transport = TransportKind::parse(params.get_optional_string("transport")?.as_deref())?;

        // The startup parameter wins over `SpawnContext::interface`, which MCP cannot set at all.
        let interface = params
            .get_optional_string("interface")?
            .or(ctx_interface)
            .unwrap_or_else(|| DEFAULT_INTERFACE.to_string());

        if interface.trim().is_empty() {
            bail!("interface must be a CAN interface name such as 'can0' or 'vcan0', not empty");
        }

        let udp_peer = match params.get_optional_string("udp_peer")? {
            None => None,
            Some(text) => {
                if transport != TransportKind::Udp {
                    bail!(
                        "udp_peer was given but transport is \"socketcan\", where it would do \
                         nothing. Set transport to \"udp\" or drop udp_peer."
                    );
                }
                Some(text.parse::<SocketAddr>().with_context(|| {
                    format!("udp_peer must be HOST:PORT (e.g. 127.0.0.1:34567), got '{text}'")
                })?)
            }
        };

        Ok(Self {
            transport,
            interface,
            udp_peer,
        })
    }
}

/// The parts of the running server every per-frame task needs.
struct CanContext {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<CanProtocol>,
    server_id: crate::state::ServerId,
    /// What to call the bus in events and in the log: the interface name on SocketCAN, or
    /// `udp:HOST:PORT` on the test transport, so nothing can mistake one for the other.
    interface_label: String,
    /// The controller's last known error-confinement state.
    ///
    /// A plain `std::sync::Mutex` holding a `Copy` value: it is read, compared and written inside
    /// one short critical section with no `.await` anywhere near it.
    bus_state: Mutex<BusState>,
}

/// CAN bus server.
pub struct CanServer;

impl CanServer {
    /// Start a CAN server.
    ///
    /// Returns `Err` — never a server left sitting in `Running` — when the platform has no
    /// `AF_CAN`, when the interface does not exist or is down, when the UDP socket cannot be
    /// bound, or when a startup parameter is unusable. Every one of those is detected before this
    /// function returns, so `server_startup.rs` records `ServerStatus::Error` with the reason.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        ctx_interface: Option<String>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Parameters first: an unusable one must fail before anything is opened or bound.
        let config = CanConfig::from_params(startup_params.as_ref(), ctx_interface)?;

        match config.transport {
            TransportKind::Udp => {
                Self::spawn_udp(
                    listen_addr,
                    config,
                    llm_client,
                    app_state,
                    status_tx,
                    server_id,
                )
                .await
            }
            TransportKind::SocketCan => {
                Self::spawn_socketcan(config, llm_client, app_state, status_tx, server_id).await
            }
        }
    }

    /// The testing transport: SocketCAN frame structs carried in UDP datagrams.
    async fn spawn_udp(
        listen_addr: SocketAddr,
        config: CanConfig,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        // Awaited, so a bind failure comes back as `Err` rather than being logged from a detached
        // task while the server sits in `Running`.
        let socket = Arc::new(UdpSocket::bind(listen_addr).await.with_context(|| {
            format!("failed to bind the CAN UDP test transport to {listen_addr}")
        })?);
        let local_addr = socket.local_addr()?;

        console_info!(
            status_tx,
            "CAN listening on {} (transport=udp — a TEST transport carrying SocketCAN frame \
             structs in datagrams; no real CAN node speaks it)",
            local_addr
        );

        let ctx = Arc::new(CanContext {
            llm_client,
            app_state: app_state.clone(),
            status_tx: status_tx.clone(),
            protocol: Arc::new(CanProtocol::new()),
            server_id,
            interface_label: format!("udp:{local_addr}"),
            bus_state: Mutex::new(BusState::ErrorActive),
        });

        let sink = FrameSink::Udp {
            socket: socket.clone(),
            configured_peer: config.udp_peer,
            last_peer: Arc::new(Mutex::new(None)),
        };

        let receive_ctx = ctx.clone();
        let receive_sink = sink.clone();
        let loop_state = app_state.clone();
        let receive_handle = tokio::spawn(async move {
            // 72 octets is the largest SocketCAN frame struct; the buffer is generous so an
            // oversized datagram is *seen* and rejected by the codec rather than silently cut to
            // a length that happens to decode.
            let mut buffer = vec![0u8; 4096];
            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((n, peer)) => {
                        if let FrameSink::Udp { last_peer, .. } = &receive_sink {
                            *last_peer.lock().expect("can peer mutex poisoned") = Some(peer);
                        }
                        let frame = match CanFrame::from_wire_bytes(&buffer[..n]) {
                            Ok(frame) => frame,
                            Err(e) => {
                                // Anyone can send anything to a UDP port; this is not an
                                // operator's problem.
                                debug!("CAN ignoring an undecodable datagram ({n} bytes): {e}");
                                continue;
                            }
                        };
                        let ctx = receive_ctx.clone();
                        let sink = receive_sink.clone();
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = loop_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                Self::handle_frame(frame, Some(peer), local_addr, ctx, sink).await;
                            })
                            .await;
                    }
                    Err(e) => {
                        console_error!(receive_ctx.status_tx, "CAN UDP receive error: {}", e);
                        break;
                    }
                }
            }
        });

        app_state
            .register_server_task(server_id, receive_handle)
            .await;

        Ok(local_addr)
    }

    /// The real transport: an `AF_CAN` socket on a Linux CAN interface.
    ///
    /// **Never compiled, never executed.** `AF_CAN` is a Linux kernel address family; there is no
    /// macOS or Windows equivalent to port to. Everything below the codec is therefore bring-up
    /// code, and `metadata().notes` says so rather than implying otherwise.
    #[cfg(target_os = "linux")]
    async fn spawn_socketcan(
        config: CanConfig,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        use socketcan::{ShouldRetry, Socket};

        console_info!(
            status_tx,
            "CAN opening AF_CAN socket on interface {}",
            config.interface
        );

        let ctx = Arc::new(CanContext {
            llm_client,
            app_state: app_state.clone(),
            status_tx: status_tx.clone(),
            protocol: Arc::new(CanProtocol::new()),
            server_id,
            interface_label: config.interface.clone(),
            bus_state: Mutex::new(BusState::ErrorActive),
        });

        // Opening the socket is the step that can fail for reasons the operator must see (no such
        // interface, interface down), so it must not be fire-and-forget: the outcome comes back
        // over a oneshot and this function returns `Ok` only once the socket is genuinely open.
        // ARP, DataLink and ICMP each shipped the fire-and-forget version of this and were each
        // fixed separately.
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<()>>();

        // `JoinHandle::abort()` cannot interrupt a thread parked in a blocking read, so the loop
        // is stopped cooperatively and the read has a timeout that bounds how long that takes.
        let stop = crate::utils::StopSignal::new();
        let stop_in_loop = stop.clone();

        let (frame_tx, frame_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let sink = FrameSink::SocketCan(frame_tx.clone());

        let loop_interface = config.interface.clone();
        let loop_ctx = ctx.clone();
        let loop_sink = sink.clone();

        tokio::task::spawn_blocking(move || {
            // Two sockets on the same interface rather than one shared between threads: a
            // transmit blocked behind a busy bus must not stall the receive loop, and `recv_own_msgs`
            // is off so the reader never sees what the writer sent. `lldp` opens two pcap handles
            // for the same reason.
            let open = || -> Result<(socketcan::CanFdSocket, socketcan::CanFdSocket)> {
                let rx = transport::linux::open(&loop_interface)?;
                rx.set_read_timeout(CAN_READ_TIMEOUT).with_context(|| {
                    format!("failed to set a read timeout on '{loop_interface}'")
                })?;
                let tx = transport::linux::open(&loop_interface)?;
                Ok((rx, tx))
            };

            let (rx_socket, tx_socket) = match open() {
                Ok(sockets) => {
                    let _ = ready_tx.send(Ok(()));
                    sockets
                }
                Err(e) => {
                    console_error!(loop_ctx.status_tx, "CAN startup failed: {:#}", e);
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };

            // Transmission runs on its own thread: `write_frame` blocks while the controller
            // arbitrates for the bus, and the receive loop must not stall behind it.
            std::thread::spawn(move || {
                while let Ok(bytes) = frame_rx.recv() {
                    let outgoing = match CanFrame::from_wire_bytes(&bytes)
                        .and_then(|frame| transport::linux::to_socketcan(&frame))
                    {
                        Ok(outgoing) => outgoing,
                        Err(e) => {
                            error!("CAN cannot build the frame to transmit: {e:#}");
                            continue;
                        }
                    };
                    if let Err(e) = tx_socket.write_frame(&outgoing) {
                        error!("CAN failed to transmit frame: {e}");
                    }
                }
            });

            let runtime = tokio::runtime::Handle::current();
            let nowhere: SocketAddr = "0.0.0.0:0"
                .parse()
                .expect("0.0.0.0:0 is a valid socket address");

            loop {
                if stop_in_loop.is_stopped() {
                    console_info!(
                        loop_ctx.status_tx,
                        "CAN socket on {} stopping",
                        loop_interface
                    );
                    break;
                }
                match rx_socket.read_frame() {
                    Ok(any) => {
                        let frame = transport::linux::from_socketcan(&any);
                        let ctx = loop_ctx.clone();
                        let sink = loop_sink.clone();
                        runtime.spawn(async move {
                            Self::handle_frame(frame, None, nowhere, ctx, sink).await;
                        });
                    }
                    // The read timeout is what bounds how long a stop takes to notice on a
                    // silent bus.
                    Err(e) if e.should_retry() => continue,
                    Err(e) => {
                        console_error!(loop_ctx.status_tx, "CAN receive error: {}", e);
                        break;
                    }
                }
            }

            // Dropping the last sender ends the transmit thread, closing its socket with it.
            drop(frame_tx);
            drop(rx_socket);
        });

        match ready_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "the CAN receive task on '{}' exited before signalling readiness",
                    config.interface
                ))
            }
        }

        app_state
            .register_server_task(server_id, stop.park_task())
            .await;

        console_info!(status_tx, "CAN active on {}", config.interface);

        // A CAN interface has no address and no port. `server_startup` records this and the
        // dashboard shows the interface instead.
        Ok("0.0.0.0:0"
            .parse()
            .expect("0.0.0.0:0 is a valid socket address"))
    }

    /// Every platform without `AF_CAN`: refuse, with the reason.
    ///
    /// Refusing is not the same as hiding. The protocol stays registered and stays visible to the
    /// model, so an operator on macOS gets `ServerStatus::Error` explaining that `AF_CAN` is a
    /// Linux kernel address family and pointing at `vcan` and at the UDP test transport — rather
    /// than a protocol that is mysteriously absent, or worse, one sitting in `Running` having
    /// heard nothing.
    #[cfg(not(target_os = "linux"))]
    async fn spawn_socketcan(
        config: CanConfig,
        _llm_client: OllamaClient,
        _app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        _server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        console_error!(
            status_tx,
            "CAN cannot start on interface {}: {}",
            config.interface,
            transport::UNSUPPORTED_PLATFORM_MESSAGE
        );
        transport::socketcan_unavailable()
    }

    /// Turn one received frame into the right event, and hand it to the policy.
    async fn handle_frame(
        frame: CanFrame,
        peer: Option<SocketAddr>,
        local_addr: SocketAddr,
        ctx: Arc<CanContext>,
        sink: FrameSink,
    ) {
        console_debug!(
            ctx.status_tx,
            "CAN {} rx {}",
            ctx.interface_label,
            frame.describe()
        );
        trace!("CAN rx raw: {:?}", frame);

        // Connectionless bookkeeping: one entry per frame heard, which the 10-second idle sweep
        // reaps because `metadata()` declares `.connectionless()`. A CAN bus has no connections
        // at all; these exist so the dashboard's ↓/↑ counters have something to count.
        let connection_id = ConnectionId::new(ctx.app_state.get_next_unified_id().await);
        {
            use crate::state::server::{
                ConnectionState as ServerConnectionState, ConnectionStatus, ProtocolConnectionInfo,
            };
            let now = crate::utils::clock::Instant::now();
            let nowhere: SocketAddr = "0.0.0.0:0"
                .parse()
                .expect("0.0.0.0:0 is a valid socket address");
            let conn = ServerConnectionState {
                id: connection_id,
                remote_addr: peer.unwrap_or(nowhere),
                local_addr,
                bytes_sent: 0,
                bytes_received: frame.data.len() as u64,
                packets_sent: 0,
                packets_received: 1,
                last_activity: now,
                status: ConnectionStatus::Active,
                status_changed_at: now,
                protocol_info: ProtocolConnectionInfo::empty(),
            };
            ctx.app_state
                .add_connection_to_server(ctx.server_id, conn)
                .await;
            let _ = ctx.status_tx.send("__UPDATE_UI__".to_string());
        }

        let mut data = frame.to_event_data();
        data.insert(
            "interface".into(),
            serde_json::json!(ctx.interface_label.clone()),
        );
        data.insert(
            "connection_id".into(),
            serde_json::json!(connection_id.to_string()),
        );

        if frame.error {
            // A state change is reported *in addition to* the error frame that carried it: the
            // two answer different questions, and an operator's handler may reasonably key on
            // either. The transition is computed under a short non-async critical section.
            let transition = frame.bus_state().and_then(|observed| {
                let mut state = ctx.bus_state.lock().expect("can bus state mutex poisoned");
                let previous = *state;
                if previous == observed {
                    None
                } else {
                    *state = observed;
                    Some((previous, observed))
                }
            });

            let error_event = Event::new(
                &CAN_ERROR_FRAME_EVENT,
                serde_json::Value::Object(data.clone()),
            );
            Self::dispatch_event(error_event, Some(connection_id), ctx.clone(), sink.clone()).await;

            if let Some((previous, observed)) = transition {
                console_info!(
                    ctx.status_tx,
                    "CAN {} bus state {} -> {}",
                    ctx.interface_label,
                    previous.as_str(),
                    observed.as_str()
                );
                let mut state_data = data;
                state_data.insert("bus_state".into(), serde_json::json!(observed.as_str()));
                state_data.insert(
                    "previous_state".into(),
                    serde_json::json!(previous.as_str()),
                );
                let state_event = Event::new(
                    &CAN_BUS_STATE_CHANGED_EVENT,
                    serde_json::Value::Object(state_data),
                );
                Self::dispatch_event(state_event, Some(connection_id), ctx, sink).await;
            }
            return;
        }

        let event = Event::new(&CAN_FRAME_RECEIVED_EVENT, serde_json::Value::Object(data));
        Self::dispatch_event(event, Some(connection_id), ctx, sink).await;
    }

    /// Ask the operator's policy (handler, script or model) what to transmit, and transmit it —
    /// or nothing, which is a complete and ordinary answer on a CAN bus.
    async fn dispatch_event(
        event: Event,
        connection_id: Option<ConnectionId>,
        ctx: Arc<CanContext>,
        sink: FrameSink,
    ) {
        let event_id = event.event_type.id.clone();

        // With no operator policy there is no ECU to simulate, so there is nothing to answer
        // with — and a real CAN bus carries thousands of frames a second, so a model round-trip
        // per frame would be ruinous as well as pointless. `lldp`, `arp` and `ospf` gate on the
        // same condition for the same reason.
        if !operator_wants_dynamic(&ctx.app_state, ctx.server_id, &event_id).await {
            debug!(
                "CAN {event_id} decision=no_policy: no instruction and no handler, nothing \
                 transmitted and no LLM call"
            );
            let _ = ctx.status_tx.send(format!(
                "CAN {event_id} decision=no_policy: listening only (no instruction or handler)"
            ));
            return;
        }

        match call_llm(
            &ctx.llm_client,
            &ctx.app_state,
            ctx.server_id,
            connection_id,
            &event,
            ctx.protocol.as_ref(),
        )
        .await
        {
            Ok(result) => {
                for message in &result.messages {
                    Log::to(&ctx.status_tx).info(message);
                }

                let mut sent = 0usize;
                for protocol_result in &result.protocol_results {
                    for bytes in protocol_result.get_all_output() {
                        // Decoded back into a frame so the log says what went out in CAN terms
                        // and not as a hex blob, and so a malformed struct is caught before it
                        // reaches the bus rather than after.
                        let frame = match CanFrame::from_wire_bytes(&bytes) {
                            Ok(frame) => frame,
                            Err(e) => {
                                console_error!(
                                    ctx.status_tx,
                                    "CAN cannot transmit a malformed frame: {:#}",
                                    e
                                );
                                continue;
                            }
                        };
                        match sink.send(&frame).await {
                            Ok(_) => {
                                sent += 1;
                                console_debug!(
                                    ctx.status_tx,
                                    "CAN {} tx {}",
                                    ctx.interface_label,
                                    frame.describe()
                                );
                            }
                            Err(e) => {
                                console_error!(ctx.status_tx, "CAN transmit failed: {:#}", e);
                            }
                        }
                    }
                }

                if sent == 0 {
                    // Nothing went out. On the bus that is indistinguishable from a node that
                    // simply does not own this identifier — which is the overwhelmingly common
                    // case — so the tag is the only place the difference survives.
                    let rejected = result.raw_actions.iter().any(|a| {
                        a.get("type").and_then(|t| t.as_str()) == Some(NO_RESPONSE_ACTION)
                    });
                    let decision = if rejected {
                        "model_reject"
                    } else {
                        "model_silent"
                    };
                    info!(
                        "CAN {event_id} decision={decision}: nothing transmitted (silence is \
                         normal on a CAN bus)"
                    );
                    let _ = ctx.status_tx.send(format!(
                        "CAN {event_id} decision={decision}: nothing transmitted"
                    ));
                }
            }
            Err(e) => {
                // Fail closed, and closed for CAN means silence. There is no error reply to
                // send: a CAN error frame is six dominant bits transmitted on top of a frame in
                // flight, which destroys that frame for every node and, repeated, drives
                // controllers error-passive and then bus-off. Signalling a NetGet outage that way
                // would corrupt other nodes' traffic. Nothing derived from `e` reaches the bus —
                // only this log line and the status stream, both local.
                let category = crate::utils::WireFailure::classify(&e);
                let decision = if category.is_overloaded() {
                    "fail_closed_overloaded"
                } else {
                    "fail_closed_llm_error"
                };
                error!(
                    "CAN {event_id} decision={decision}: nothing transmitted, CAN has no error \
                     reply and an error frame would corrupt traffic in flight ({}): {}",
                    category.text(),
                    e
                );
                let _ = ctx.status_tx.send(format!(
                    "✗ CAN {event_id} decision={decision}: nothing transmitted ({}): {}",
                    category.text(),
                    e
                ));
            }
        }
    }
}

/// True when the operator opted into dynamic behaviour: a non-empty server instruction, or an
/// event handler configured for this event.
///
/// False means listen and say nothing — for CAN, because with no configured ECU there is no
/// identifier this node owns and nothing honest to transmit.
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

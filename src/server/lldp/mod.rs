//! LLDP (IEEE 802.1AB) server — NetGet as a switch on somebody else's link.
//!
//! LLDP is a one-way announcement protocol: every agent periodically transmits a description of
//! itself to the nearest-bridge group address `01:80:C2:00:00:0E` under EtherType `0x88CC`, and
//! every agent records what it hears in a table an operator reads. There is no request, no
//! response and no acknowledgement. What makes it worth driving from a model is that **the
//! identity is authored, not derived**: chassis ID, system description and capability set are
//! choices, and they are exactly what network reconnaissance reads off a link.
//!
//! # Two transports, one codec
//!
//! The frame format lives in [`codec`] and is a pure function over plain values. This module is
//! the thin layer that moves those bytes:
//!
//! * **`transport: "raw"`** (the default) — libpcap capture and injection on a real interface,
//!   filtered to `ether proto 0x88cc`. Needs root, `/dev/bpf*` access on macOS/BSD, or
//!   `CAP_NET_RAW` on Linux. **This code has never been executed**; see `CLAUDE.md`.
//! * **`transport: "udp"`** — a testing transport that carries complete Ethernet frames as UDP
//!   datagram payloads, so the whole event → handler/LLM → frame path runs unprivileged. No
//!   real neighbour speaks it. This is the same accommodation `ospf` makes for its raw socket,
//!   made explicit as a declared parameter rather than left to the test file.
//!
//! # Failure is silence, and the log is where the difference lives
//!
//! LLDP is in the deliberately-silent class the root `CLAUDE.md` describes. Every frame the
//! protocol defines is a *positive assertion* that a device with a given identity exists on this
//! link, and a neighbour writes it straight into its topology table. There is no error frame to
//! send, and fabricating an advertisement to signal "netget is broken" would put a device on the
//! network map that does not exist. So an LLM failure transmits **nothing**, and no `WireFailure`
//! text ever reaches the wire.
//!
//! On the wire all four outcomes are identical, so they are separated in the log by a
//! `decision=` tag, the way `src/server/radius/` separates its cases:
//!
//! | Tag | Meaning |
//! |---|---|
//! | `decision=no_policy` | No instruction and no handler — nothing is advertised and no LLM call is made |
//! | `decision=model_reject` | The model answered `no_advertisement` — a real decision |
//! | `decision=model_silent` | The model returned nothing usable |
//! | `decision=fail_closed_overloaded` | The call failed and the backend is saturated (retryable) |
//! | `decision=fail_closed_llm_error` | The call failed otherwise |

pub mod actions;
pub mod codec;

use anyhow::{anyhow, bail, Context, Result};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::{console_debug, console_error, console_info, console_trace};
use actions::{
    LldpProtocol, LLDP_ADVERTISEMENT_RESULT, LLDP_ADVERTISE_DUE_EVENT,
    LLDP_NEIGHBOR_ADVERTISEMENT_EVENT, NO_ADVERTISEMENT_ACTION,
};

/// BPF expression restricting capture to LLDP. Anything wider hands every frame on the segment
/// to the model, so a failure to compile it has to refuse the start rather than fall through.
const LLDP_BPF_FILTER: &str = "ether proto 0x88cc";

/// Which way frames travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportKind {
    /// Real Ethernet through libpcap. Privileged, and never executed in this repository.
    Raw,
    /// Whole Ethernet frames inside UDP datagrams. Testing only.
    Udp,
}

/// Everything the startup parameters configure. Every field here is read.
#[derive(Debug, Clone)]
struct LldpConfig {
    transport: TransportKind,
    udp_peer: Option<SocketAddr>,
    advertise_interval_secs: u64,
    source_mac: Option<[u8; 6]>,
}

impl LldpConfig {
    fn from_params(params: Option<&crate::protocol::StartupParams>) -> Result<Self> {
        let Some(params) = params else {
            return Ok(Self {
                transport: TransportKind::Raw,
                udp_peer: None,
                advertise_interval_secs: 0,
                source_mac: None,
            });
        };

        let transport = match params.get_optional_string("transport")?.as_deref() {
            None | Some("raw") => TransportKind::Raw,
            Some("udp") => TransportKind::Udp,
            Some(other) => bail!(
                "transport must be \"raw\" (real Ethernet via libpcap) or \"udp\" (testing \
                 transport carrying Ethernet frames in datagrams), got '{other}'"
            ),
        };

        let udp_peer = match params.get_optional_string("udp_peer")? {
            None => None,
            Some(text) => {
                if transport != TransportKind::Udp {
                    bail!(
                        "udp_peer was given but transport is \"raw\", where it would do nothing. \
                         Set transport to \"udp\" or drop udp_peer."
                    );
                }
                Some(text.parse::<SocketAddr>().with_context(|| {
                    format!("udp_peer must be HOST:PORT (e.g. 127.0.0.1:34567), got '{text}'")
                })?)
            }
        };

        let advertise_interval_secs = match params.get_optional_i64("advertise_interval_secs")? {
            None => 0,
            Some(v) if (0..=86_400).contains(&v) => v as u64,
            Some(v) => bail!(
                "advertise_interval_secs must be between 0 (timer disabled) and 86400, got {v}"
            ),
        };

        let source_mac = match params.get_optional_string("source_mac")? {
            None => None,
            Some(text) => Some(codec::parse_mac(&text)?),
        };

        Ok(Self {
            transport,
            udp_peer,
            advertise_interval_secs,
            source_mac,
        })
    }
}

/// Where a built frame goes.
///
/// Cloned into each per-frame task rather than shared behind an `Arc`: `std::sync::mpsc::Sender`
/// is `Send` but its `Sync`ness is not something to rely on, and cloning a channel handle costs
/// nothing.
#[derive(Clone)]
enum FrameSink {
    /// Hand the frame to the blocking pcap injection thread.
    Pcap(std::sync::mpsc::Sender<Vec<u8>>),
    /// Send the frame as a UDP datagram, to the configured peer or to whoever spoke last.
    Udp {
        socket: Arc<UdpSocket>,
        configured_peer: Option<SocketAddr>,
        last_peer: Arc<Mutex<Option<SocketAddr>>>,
    },
}

impl FrameSink {
    async fn send(&self, frame: Vec<u8>) -> Result<usize> {
        match self {
            FrameSink::Pcap(tx) => {
                let len = frame.len();
                tx.send(frame)
                    .map_err(|_| anyhow!("pcap injection thread has gone away"))?;
                Ok(len)
            }
            FrameSink::Udp {
                socket,
                configured_peer,
                last_peer,
            } => {
                // The guard is dropped before the await: never hold a lock across I/O.
                let peer = match configured_peer {
                    Some(p) => Some(*p),
                    None => *last_peer.lock().expect("lldp peer mutex poisoned"),
                };
                let peer = peer.ok_or_else(|| {
                    anyhow!(
                        "no UDP peer to transmit to: nothing has been received yet and no \
                         udp_peer startup parameter was given"
                    )
                })?;
                Ok(socket.send_to(&frame, peer).await?)
            }
        }
    }
}

/// The parts of the running server every per-frame task needs.
struct LldpContext {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<LldpProtocol>,
    server_id: crate::state::ServerId,
    /// Ethernet source address used when an action names none. Also the address whose own
    /// frames are ignored on receive, so an injected advertisement captured back off the wire
    /// cannot trigger another one.
    source_mac: [u8; 6],
    interface: Option<String>,
}

pub struct LldpServer;

impl LldpServer {
    /// Start an LLDP agent.
    ///
    /// Returns `Err` — never a server left sitting in `Running` — when the capture handle cannot
    /// be opened, the BPF filter cannot be compiled, the UDP socket cannot be bound, or a
    /// startup parameter is unusable. ARP, DataLink and ICMP each shipped the fire-and-forget
    /// version of this and were each fixed separately; IS-IS was missed three times.
    pub async fn spawn_with_llm_actions(
        interface: Option<String>,
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Parameters first: an unusable one must fail before anything is bound or opened.
        let config = LldpConfig::from_params(startup_params.as_ref())?;

        match config.transport {
            TransportKind::Raw => {
                let interface = interface.ok_or_else(|| {
                    anyhow!(
                        "LLDP transport \"raw\" needs an interface to capture on (pass \
                         `interface`), or use transport \"udp\" for an unprivileged test run"
                    )
                })?;
                let source_mac = config
                    .source_mac
                    .or_else(|| interface_mac(&interface))
                    .unwrap_or_else(|| {
                        codec::parse_mac(actions::DEFAULT_SOURCE_MAC)
                            .expect("DEFAULT_SOURCE_MAC is a literal MAC address")
                    });
                Self::spawn_raw(
                    interface, config, source_mac, llm_client, app_state, status_tx, server_id,
                )
                .await
            }
            TransportKind::Udp => {
                // No interface exists, so there is no address to inherit: the configured value
                // or the locally-administered default is all there is.
                let source_mac = config.source_mac.unwrap_or_else(|| {
                    codec::parse_mac(actions::DEFAULT_SOURCE_MAC)
                        .expect("DEFAULT_SOURCE_MAC is a literal MAC address")
                });
                Self::spawn_udp(
                    listen_addr,
                    interface,
                    config,
                    source_mac,
                    llm_client,
                    app_state,
                    status_tx,
                    server_id,
                )
                .await
            }
        }
    }

    /// The testing transport: whole Ethernet frames carried in UDP datagrams.
    #[allow(clippy::too_many_arguments)]
    async fn spawn_udp(
        listen_addr: SocketAddr,
        interface: Option<String>,
        config: LldpConfig,
        source_mac: [u8; 6],
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        // Awaited, so a bind failure is returned rather than logged from a detached task.
        let socket = Arc::new(UdpSocket::bind(listen_addr).await.with_context(|| {
            format!("failed to bind the LLDP UDP test transport to {listen_addr}")
        })?);
        let local_addr = socket.local_addr()?;

        console_info!(
            status_tx,
            "LLDP listening on {} (transport=udp — a TEST transport carrying Ethernet frames in \
             datagrams; no real LLDP neighbour speaks it)",
            local_addr
        );

        let ctx = Arc::new(LldpContext {
            llm_client,
            app_state: app_state.clone(),
            status_tx: status_tx.clone(),
            protocol: Arc::new(LldpProtocol::new()),
            server_id,
            source_mac,
            interface,
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
            let mut buffer = vec![0u8; 65535];
            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((n, peer)) => {
                        if let FrameSink::Udp { last_peer, .. } = &receive_sink {
                            *last_peer.lock().expect("lldp peer mutex poisoned") = Some(peer);
                        }
                        let frame = buffer[..n].to_vec();
                        let ctx = receive_ctx.clone();
                        let sink = receive_sink.clone();
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = loop_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                Self::handle_frame(&frame, Some(peer), local_addr, ctx, sink).await;
                            })
                            .await;
                    }
                    Err(e) => {
                        console_error!(receive_ctx.status_tx, "LLDP UDP receive error: {}", e);
                        break;
                    }
                }
            }
        });

        app_state
            .register_server_task(server_id, receive_handle)
            .await;

        Self::spawn_advertise_timer(&config, ctx, sink, app_state, server_id).await;

        Ok(local_addr)
    }

    /// The real transport: libpcap capture and injection on an Ethernet interface.
    ///
    /// **Never executed anywhere.** It compiles, and it is written to the same shape as `arp`
    /// and `isis`, but no test in this repository has the privilege to open a capture handle.
    #[allow(clippy::too_many_arguments)]
    async fn spawn_raw(
        interface: String,
        config: LldpConfig,
        source_mac: [u8; 6],
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        use pcap::{Capture, Device};

        console_info!(
            status_tx,
            "LLDP starting capture on interface {} (source MAC {})",
            interface,
            codec::format_mac(&source_mac)
        );

        let ctx = Arc::new(LldpContext {
            llm_client,
            app_state: app_state.clone(),
            status_tx: status_tx.clone(),
            protocol: Arc::new(LldpProtocol::new()),
            server_id,
            source_mac,
            interface: Some(interface.clone()),
        });

        // Opening the capture is the privileged step, so it must not be fire-and-forget: the
        // outcome comes back over a oneshot and this function only returns Ok once the handle
        // is genuinely open. A server reporting Running while capturing nothing is worse than
        // one that refuses to start.
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<()>>();

        // `JoinHandle::abort()` cannot interrupt a thread parked in `next_packet()`, so the
        // capture loop is stopped cooperatively.
        let stop = crate::utils::StopSignal::new();
        let stop_in_loop = stop.clone();

        let (packet_tx, packet_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let sink = FrameSink::Pcap(packet_tx.clone());

        let loop_interface = interface.clone();
        let loop_ctx = ctx.clone();
        let loop_sink = sink.clone();
        tokio::task::spawn_blocking(move || {
            let open = || -> Result<(Capture<pcap::Active>, Capture<pcap::Active>)> {
                let device = Device::list()
                    .context("failed to list network devices")?
                    .into_iter()
                    .find(|d| d.name == loop_interface)
                    .ok_or_else(|| anyhow!("no such capture device '{}'", loop_interface))?;

                let mut cap_rx = Capture::from_device(device.clone())
                    .map(|c| c.promisc(true).snaplen(65535).timeout(1000))
                    .and_then(|c| c.open())
                    .with_context(|| {
                        format!(
                            "failed to open pcap capture on '{}' (needs root, or read access to \
                             /dev/bpf* on macOS/BSD, or CAP_NET_RAW on Linux)",
                            loop_interface
                        )
                    })?;

                // `ether proto` is an Ethernet-only keyword. On a link type with no Ethernet
                // header — loopback (DLT_NULL/DLT_LOOP), tunnels, raw-IP devices — libpcap
                // compiles it to "expression rejects all packets" and errors. That refusal is
                // correct: LLDP cannot exist there. The message has to say so, because
                // libpcap's own names the optimiser rather than the problem. Same trap `arp`
                // documents.
                cap_rx.filter(LLDP_BPF_FILTER, true).with_context(|| {
                    format!(
                        "failed to apply the '{LLDP_BPF_FILTER}' BPF filter on '{}'. LLDP is an \
                         Ethernet-only protocol, so this fails on any interface with no Ethernet \
                         link layer — loopback (lo/lo0), tunnels and raw-IP devices carry no LLDP \
                         and libpcap rejects the filter outright. Point this server at a real \
                         Ethernet interface, or use transport \"udp\" for an unprivileged test.",
                        loop_interface
                    )
                })?;

                let cap_tx = Capture::from_device(device)
                    .map(|c| c.promisc(true).snaplen(65535).timeout(1000))
                    .and_then(|c| c.open())
                    .with_context(|| {
                        format!(
                            "failed to open pcap injection handle on '{}'",
                            loop_interface
                        )
                    })?;

                Ok((cap_rx, cap_tx))
            };

            let (mut cap_rx, mut cap_tx) = match open() {
                Ok(handles) => {
                    let _ = ready_tx.send(Ok(()));
                    handles
                }
                Err(e) => {
                    console_error!(loop_ctx.status_tx, "LLDP capture startup failed: {:#}", e);
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };

            // Injection runs on its own thread: `sendpacket` blocks, and the capture loop must
            // not stall behind it.
            std::thread::spawn(move || {
                while let Ok(frame) = packet_rx.recv() {
                    if let Err(e) = cap_tx.sendpacket(frame) {
                        error!("LLDP failed to inject frame: {}", e);
                    }
                }
            });

            let runtime = tokio::runtime::Handle::current();

            loop {
                if stop_in_loop.is_stopped() {
                    console_info!(
                        loop_ctx.status_tx,
                        "LLDP capture on {} stopping",
                        loop_interface
                    );
                    break;
                }
                match cap_rx.next_packet() {
                    Ok(packet) => {
                        let frame = packet.data.to_vec();
                        let ctx = loop_ctx.clone();
                        let sink = loop_sink.clone();
                        runtime.spawn(async move {
                            let nowhere: SocketAddr = "0.0.0.0:0"
                                .parse()
                                .expect("0.0.0.0:0 is a valid socket address");
                            Self::handle_frame(&frame, None, nowhere, ctx, sink).await;
                        });
                    }
                    // The 1000ms read timeout is what bounds how long a stop takes to notice
                    // on an idle interface.
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(e) => {
                        console_error!(loop_ctx.status_tx, "LLDP capture error: {}", e);
                        break;
                    }
                }
            }

            // Dropping the last sender ends the injection thread, closing its handle with it.
            drop(packet_tx);
            drop(cap_rx);
        });

        match ready_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(anyhow!(
                    "LLDP capture task on '{}' exited before signalling readiness",
                    interface
                ))
            }
        }

        app_state
            .register_server_task(server_id, stop.park_task())
            .await;

        console_info!(status_tx, "LLDP capture active on {}", interface);

        Self::spawn_advertise_timer(&config, ctx, sink, app_state, server_id).await;

        // Nothing is bound to an address: LLDP has no port. `server_startup` records this and
        // the dashboard shows the interface instead.
        Ok("0.0.0.0:0"
            .parse()
            .expect("0.0.0.0:0 is a valid socket address"))
    }

    /// Start the periodic `lldp_advertise_due` timer, if one was configured.
    ///
    /// Registered like every other task: a timer that outlives `stop_server` keeps advertising
    /// an identity for a server the operator has closed. (BGP's keepalive did exactly that.)
    async fn spawn_advertise_timer(
        config: &LldpConfig,
        ctx: Arc<LldpContext>,
        sink: FrameSink,
        app_state: Arc<AppState>,
        server_id: crate::state::ServerId,
    ) {
        if config.advertise_interval_secs == 0 {
            debug!("LLDP advertise timer disabled (advertise_interval_secs = 0)");
            return;
        }

        let interval_secs = config.advertise_interval_secs;
        let handle = tokio::spawn(async move {
            let mut sequence: u64 = 0;
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            // The first tick is immediate; consume it so the first advertisement happens one
            // interval in rather than racing the server's own startup log.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                sequence += 1;
                let n = sequence;
                let event = Event::new(
                    &LLDP_ADVERTISE_DUE_EVENT,
                    serde_json::json!({
                        "interval_secs": interval_secs,
                        "sequence": n,
                        "interface": ctx.interface,
                    }),
                );
                Self::dispatch_event(event, None, ctx.clone(), sink.clone()).await;
            }
        });

        app_state.register_server_task(server_id, handle).await;
    }

    /// Decode one received frame and hand the neighbour to the model.
    async fn handle_frame(
        frame: &[u8],
        peer: Option<SocketAddr>,
        local_addr: SocketAddr,
        ctx: Arc<LldpContext>,
        sink: FrameSink,
    ) {
        let decoded = match codec::decode_frame(frame) {
            Ok(decoded) => decoded,
            Err(e) => {
                // Not an error worth an operator's attention: on a real segment the capture
                // filter already restricts this to 0x88CC, and on the UDP transport anyone can
                // send anything.
                debug!(
                    "LLDP ignoring an undecodable frame ({} bytes): {}",
                    frame.len(),
                    e
                );
                return;
            }
        };

        // Our own advertisement, captured back off the wire. Answering it would advertise
        // again, and again.
        if decoded.source_mac == ctx.source_mac {
            trace!(
                "LLDP ignoring our own frame from {}",
                codec::format_mac(&decoded.source_mac)
            );
            return;
        }

        let source_mac = codec::format_mac(&decoded.source_mac);
        let destination_mac = codec::format_mac(&decoded.destination_mac);

        console_debug!(
            ctx.status_tx,
            "LLDP advertisement from {} ({} bytes)",
            source_mac,
            frame.len()
        );
        console_trace!(
            ctx.status_tx,
            "LLDP neighbour {}: chassis={} port={} ttl={}",
            source_mac,
            decoded.lldpdu.chassis_id,
            decoded.lldpdu.port_id,
            decoded.lldpdu.ttl
        );

        // Connectionless bookkeeping: one entry per neighbour heard from, which the 10-second
        // idle sweep reaps (metadata declares `.connectionless()`).
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
                bytes_received: frame.len() as u64,
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

        let mut data = decoded.lldpdu.to_event_data();
        data.insert("source_mac".into(), serde_json::json!(source_mac));
        data.insert("destination_mac".into(), serde_json::json!(destination_mac));
        data.insert(
            "connection_id".into(),
            serde_json::json!(connection_id.to_string()),
        );

        let event = Event::new(
            &LLDP_NEIGHBOR_ADVERTISEMENT_EVENT,
            serde_json::Value::Object(data),
        );

        Self::dispatch_event(event, Some(connection_id), ctx, sink).await;
    }

    /// Ask the operator's policy (handler, script or model) what to advertise, and transmit
    /// whatever it chooses — or nothing, which is a complete answer here.
    async fn dispatch_event(
        event: Event,
        connection_id: Option<ConnectionId>,
        ctx: Arc<LldpContext>,
        sink: FrameSink,
    ) {
        let event_id = event.event_type.id.clone();

        // What to advertise is *policy*, and there is no advertisement that can be derived from
        // a received one — an identity is invented, not computed. With no operator policy the
        // spec-safe answer is to listen and say nothing, and to do that WITHOUT an LLM
        // round-trip per captured frame. `arp` and `ospf` gate on the same condition for the
        // same reason.
        if !operator_wants_dynamic(&ctx.app_state, ctx.server_id, &event_id).await {
            debug!(
                "LLDP {} decision=no_policy: no instruction and no handler, nothing advertised \
                 and no LLM call",
                event_id
            );
            let _ = ctx.status_tx.send(format!(
                "LLDP {} decision=no_policy: listening only (no instruction or handler)",
                event_id
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
                    let crate::llm::actions::protocol_trait::ActionResult::Custom { name, data } =
                        protocol_result
                    else {
                        continue;
                    };
                    if name != LLDP_ADVERTISEMENT_RESULT {
                        continue;
                    }

                    let Some(action) = data.get("action") else {
                        warn!("LLDP advertisement result carried no action payload");
                        continue;
                    };

                    // Re-parsed here rather than carried as bytes because the *server* owns the
                    // source address: the model names an identity, not a frame.
                    let request = match codec::AdvertisementRequest::from_action(action) {
                        Ok(request) => request,
                        Err(e) => {
                            console_error!(
                                ctx.status_tx,
                                "LLDP cannot build advertisement: {:#}",
                                e
                            );
                            continue;
                        }
                    };
                    let frame = match request.to_frame(ctx.source_mac) {
                        Ok(frame) => frame,
                        Err(e) => {
                            console_error!(
                                ctx.status_tx,
                                "LLDP cannot encode advertisement: {:#}",
                                e
                            );
                            continue;
                        }
                    };

                    match sink.send(frame).await {
                        Ok(n) => {
                            sent += 1;
                            console_debug!(
                                ctx.status_tx,
                                "LLDP advertised {} ({} on port {}, {} bytes)",
                                request
                                    .lldpdu
                                    .system_name
                                    .clone()
                                    .unwrap_or_else(|| "unnamed".to_string()),
                                request.lldpdu.chassis_id,
                                request.lldpdu.port_id,
                                n
                            );
                        }
                        Err(e) => {
                            console_error!(ctx.status_tx, "LLDP transmit failed: {:#}", e);
                        }
                    }
                }

                if sent == 0 {
                    // Nothing went out. On the wire that is indistinguishable from a passive
                    // listener, so the tag is the only place the difference survives.
                    let rejected = result.raw_actions.iter().any(|a| {
                        a.get("type").and_then(|t| t.as_str()) == Some(NO_ADVERTISEMENT_ACTION)
                    });
                    let decision = if rejected {
                        "model_reject"
                    } else {
                        "model_silent"
                    };
                    info!(
                        "LLDP {} decision={}: nothing advertised (LLDP has no error frame; \
                         silence is the protocol-correct answer)",
                        event_id, decision
                    );
                    let _ = ctx.status_tx.send(format!(
                        "LLDP {} decision={}: nothing advertised",
                        event_id, decision
                    ));
                }
            }
            Err(e) => {
                // Fail closed, and closed for LLDP means silence. The only frame this server
                // can emit asserts that a device with a given identity exists on this link, and
                // that identity is exactly what the failed call was supposed to decide.
                // Fabricating one writes a device that does not exist into a neighbour's
                // topology table — far worse than the neighbour simply not hearing from us,
                // which its own TTL already handles. Nothing derived from `e` reaches the wire.
                let category = crate::utils::WireFailure::classify(&e);
                let decision = if category.is_overloaded() {
                    "fail_closed_overloaded"
                } else {
                    "fail_closed_llm_error"
                };
                error!(
                    "LLDP {} decision={}: nothing advertised, LLDP has no failure frame ({}): {}",
                    event_id,
                    decision,
                    category.text(),
                    e
                );
                let _ = ctx.status_tx.send(format!(
                    "✗ LLDP {} decision={}: nothing advertised ({}): {}",
                    event_id,
                    decision,
                    category.text(),
                    e
                ));
            }
        }
    }
}

/// The interface's own hardware address, where the platform will tell us.
///
/// `pnet::datalink` reads this the same way on every OS it supports, which is why it is used
/// here rather than `/sys/class/net/<if>/address` — that is Linux-only and is why `isis` sends
/// from a locally-administered placeholder everywhere else.
fn interface_mac(interface: &str) -> Option<[u8; 6]> {
    pnet::datalink::interfaces()
        .into_iter()
        .find(|i| i.name == interface)
        .and_then(|i| i.mac)
        .map(|mac| [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5])
}

/// True when the operator opted into dynamic behaviour: a non-empty server instruction, or an
/// event handler configured for this event. False means the static default applies — for LLDP,
/// advertise nothing, because with no configured identity there is nothing honest to claim.
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

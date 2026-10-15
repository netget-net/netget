//! CDP (Cisco Discovery Protocol) server — NetGet impersonating a Cisco device to its neighbours.
//!
//! CDP is the classic Layer-2 reconnaissance leak: a switch announces its hostname, hardware
//! model, IOS version, port name and **native VLAN** to anyone on the wire, unsolicited, every
//! 60 seconds. Here the *model* authors all of it, so what a neighbour records about "the switch
//! it is plugged into" is whatever the LLM decides to claim.
//!
//! # Structure
//!
//! * [`codec`] is a **pure** module: TLVs, the 802.3 + LLC/SNAP header and the CDP checksum, with
//!   no I/O of any kind. That is where the protocol can actually be wrong, and it is
//!   exhaustively tested against literal specification bytes and real captures.
//! * This file is the transport, and it is deliberately thin. It has two implementations:
//!   - **raw** — libpcap capture and injection on a named interface. Needs packet-capture
//!     privilege (root, `/dev/bpf*` access on macOS/BSD, or `CAP_NET_RAW` on Linux). **Never
//!     executed by any test.**
//!   - **udp** — one complete 802.3 frame per datagram, replying to the datagram's sender.
//!     Needs no privilege, and exists so the whole event → LLM → action → frame path runs in the
//!     test suite. Selected with the `transport` startup parameter, the same way `ospf` is
//!     driven over UDP in tests.
//!
//! # Silence on failure
//!
//! CDP is in the **deliberately-silent** class (root `CLAUDE.md`). Every frame the protocol
//! defines is a positive assertion — "a device with this identity exists on this link" — which
//! the neighbour caches and an operator reads back. There is no CDP error or NAK frame, so on an
//! LLM failure a fabricated advertisement would be strictly worse than nothing: it poisons a
//! neighbour table with a device that does not exist. The wire therefore carries nothing, no
//! `WireFailure` text is ever interpolated into a frame, and the distinction survives only in the
//! log, in the same shape `src/server/radius/` uses. The six tokens this file actually emits,
//! and the whole set — grep them, do not guess, because a token that does not exist is worse
//! than none:
//!
//! `decision=passive_no_policy` · `model_reject` · `model_silent` · `model_invalid_action` ·
//! `fail_closed_llm_error_overloaded` · `fail_closed_llm_error_unavailable`
//!
//! Note the last two: there is no bare `fail_closed_llm_error`. The `WireFailure` category is
//! folded into the token so that "the backend is saturated, retry" and "the backend is broken"
//! stay greppable apart, which is the one thing an operator wants from a log line that says
//! nothing went on the wire.

pub mod actions;
pub mod codec;

use anyhow::{anyhow, Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;

use actions::{CdpProtocol, CdpTransport, CDP_ACTION_RESULT, CDP_NEIGHBOR_ADVERTISEMENT_EVENT};
use codec::{CdpAdvertisement, FrameHeader};

/// The source MAC used by the UDP test transport when none is configured.
///
/// Locally administered (bit 1 of the first octet set) so it can never collide with a real
/// Cisco OUI, while still being obviously CDP-ish to anyone reading a capture.
const DEFAULT_UDP_SOURCE_MAC: [u8; 6] = [0x02, 0x00, 0x0c, 0xcc, 0xcc, 0x01];

/// BPF filter for CDP: multicast destination, SNAP encapsulation, Cisco OUI, protocol 0x2000.
///
/// Offsets are into the frame: `[14:2]` is DSAP+SSAP, `[16:1]` the LLC control byte, `[17:3]`
/// cannot be expressed in one term so the OUI is split, and `[20:2]` is the SNAP protocol id.
/// Without a filter the capture hands *every* frame on the segment to the LLM, so a compile
/// failure here has to refuse the start rather than fall through — the same reasoning
/// `src/server/arp/mod.rs` records.
const CDP_BPF_FILTER: &str = "ether dst 01:00:0c:cc:cc:cc and ether[14:2] = 0xaaaa \
                              and ether[16:1] = 0x03 and ether[17:2] = 0x0000 \
                              and ether[19:1] = 0x0c and ether[20:2] = 0x2000";

/// Where an outgoing frame goes.
#[derive(Clone)]
enum CdpSink {
    /// A live pcap handle, shared with the capture loop.
    #[cfg(all(unix, feature = "libpcap"))]
    Raw(Arc<std::sync::Mutex<pcap::Capture<pcap::Active>>>),
    /// The bound UDP socket, plus the peer this frame is answering.
    Udp(Arc<UdpSocket>, SocketAddr),
}

impl CdpSink {
    async fn send(&self, frame: &[u8]) -> Result<()> {
        match self {
            #[cfg(all(unix, feature = "libpcap"))]
            CdpSink::Raw(cap) => {
                let mut guard = cap.lock().unwrap_or_else(|e| e.into_inner());
                guard
                    .sendpacket(frame)
                    .context("pcap injection of a CDP frame failed")
            }
            CdpSink::Udp(socket, peer) => {
                socket
                    .send_to(frame, peer)
                    .await
                    .with_context(|| format!("sending a CDP frame to {} failed", peer))?;
                Ok(())
            }
        }
    }

    fn describe(&self) -> String {
        match self {
            #[cfg(all(unix, feature = "libpcap"))]
            CdpSink::Raw(_) => "pcap".to_string(),
            CdpSink::Udp(_, peer) => format!("udp:{}", peer),
        }
    }
}

/// Everything the frame handler needs, so the two transports share one code path.
struct CdpContext {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<CdpProtocol>,
    server_id: crate::state::ServerId,
    source_mac: [u8; 6],
}

pub struct CdpServer;

impl CdpServer {
    /// Start a CDP server.
    ///
    /// Returns the bound UDP address on the `udp` transport, and an unbound placeholder on the
    /// `raw` transport (which owns no socket). Either way this only returns `Ok` once the
    /// transport is genuinely live: the pcap handle is opened on a blocking thread and its
    /// outcome is handed back over a oneshot, so a failure surfaces as `ServerStatus::Error`
    /// rather than as a server that reports `Running` while capturing nothing — the defect root
    /// `CLAUDE.md` records for ARP, DataLink and ICMP.
    pub async fn spawn_with_llm_actions(ctx: crate::protocol::SpawnContext) -> Result<SocketAddr> {
        let crate::protocol::SpawnContext {
            interface,
            host,
            port,
            mac_address,
            llm_client,
            state: app_state,
            status_tx,
            server_id,
            startup_params,
            ..
        } = ctx;

        // --- startup parameters -------------------------------------------------------------
        //
        // Both declared parameters are read here. `?` propagates a `StartupParamError` so an
        // undeclared key or a wrong-typed value becomes a clean error naming the key; it must
        // never be unwrapped (root CLAUDE.md, "Startup parameters").
        let mut transport = CdpTransport::Raw;
        let mut configured_mac: Option<[u8; 6]> = None;

        if let Some(ref params) = startup_params {
            if let Some(value) = params.get_optional_string("transport")? {
                transport = CdpTransport::parse(&value)?;
            }
            if let Some(value) = params.get_optional_string("source_mac")? {
                configured_mac = Some(codec::parse_mac(&value)?);
            }
        }
        // The flexible-binding `mac_address` field means the same thing; an explicit
        // `source_mac` startup parameter wins because it is the more specific request.
        if configured_mac.is_none() {
            if let Some(ref value) = mac_address {
                configured_mac = Some(codec::parse_mac(value)?);
            }
        }

        let protocol = Arc::new(CdpProtocol::new());

        match transport {
            CdpTransport::Udp => {
                Self::spawn_udp(
                    host.unwrap_or_else(|| "127.0.0.1".to_string()),
                    port.unwrap_or(0),
                    configured_mac.unwrap_or(DEFAULT_UDP_SOURCE_MAC),
                    llm_client,
                    app_state,
                    status_tx,
                    server_id,
                    protocol,
                )
                .await
            }
            CdpTransport::Raw => {
                let interface = interface.context(
                    "CDP requires a network interface: pass `interface` (e.g. \"en0\"), or use \
                     the `transport: \"udp\"` startup parameter for the unprivileged test \
                     transport",
                )?;
                Self::spawn_raw(
                    interface,
                    configured_mac,
                    llm_client,
                    app_state,
                    status_tx,
                    server_id,
                    protocol,
                )
                .await
            }
        }
    }

    // =============================================================================================
    // UDP test transport
    // =============================================================================================

    /// One complete 802.3 CDP frame per datagram; replies go back to the sender.
    ///
    /// This is not a wire-compatible CDP transport and does not pretend to be — real CDP has no
    /// UDP encapsulation. It exists because the raw transport cannot run without packet-capture
    /// privilege, and everything above the framing (the event, the routing table, the LLM call,
    /// the action executor, the codec) is transport-independent and worth testing. `ospf`
    /// establishes the precedent of driving a privileged protocol over UDP in tests; this makes
    /// it an explicit, declared mode rather than a test that quietly runs a different protocol.
    #[allow(clippy::too_many_arguments)]
    async fn spawn_udp(
        host: String,
        port: u16,
        source_mac: [u8; 6],
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        protocol: Arc<CdpProtocol>,
    ) -> Result<SocketAddr> {
        let bind_addr = format!("{}:{}", host, port);
        let socket = UdpSocket::bind(&bind_addr)
            .await
            .with_context(|| format!("CDP (udp transport) could not bind {}", bind_addr))?;
        let local_addr = socket
            .local_addr()
            .context("CDP (udp transport) bound socket has no local address")?;
        let socket = Arc::new(socket);

        Log::new(Some(&status_tx)).info(format!(
            "CDP listening on {} (udp test transport, source MAC {})",
            local_addr,
            codec::mac_to_string(&source_mac)
        ));

        let cdp_ctx = Arc::new(CdpContext {
            llm_client,
            app_state: app_state.clone(),
            status_tx: status_tx.clone(),
            protocol,
            server_id,
            source_mac,
        });

        let recv_socket = socket.clone();
        let loop_state = app_state.clone();
        let handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65535];
            loop {
                match recv_socket.recv_from(&mut buffer).await {
                    Ok((n, peer)) => {
                        let frame = buffer[..n].to_vec();
                        let sink = CdpSink::Udp(recv_socket.clone(), peer);
                        let cdp_ctx = cdp_ctx.clone();
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = loop_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                if let Err(e) = Self::handle_frame(&frame, sink, cdp_ctx).await {
                                    debug!("CDP frame from {} ignored: {:#}", peer, e);
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        error!("CDP (udp transport) receive error: {}", e);
                        break;
                    }
                }
            }
            warn!("CDP (udp transport) receive loop terminated");
        });

        // Required for `stop_server` to actually release the socket.
        app_state.register_server_task(server_id, handle).await;

        Ok(local_addr)
    }

    // =============================================================================================
    // Raw 802.3 transport
    // =============================================================================================

    /// libpcap capture and injection on a real interface. **Never executed by any test.**
    #[allow(clippy::too_many_arguments)]
    async fn spawn_raw(
        interface: String,
        configured_mac: Option<[u8; 6]>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        protocol: Arc<CdpProtocol>,
    ) -> Result<SocketAddr> {
        Log::new(Some(&status_tx)).info(format!("CDP capture starting on interface {}", interface));

        // Opening the pcap handle is the step that needs privilege, so it must not be
        // fire-and-forget: the outcome comes back over this oneshot and `spawn` only returns Ok
        // once the capture is genuinely live.
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<()>>();

        // `JoinHandle::abort()` cannot interrupt a thread parked in `next_packet()`, so the
        // capture loop is stopped cooperatively through a flag the registered task trips when
        // it is aborted. Same mechanism as `arp` and `isis`.
        let stop = crate::utils::StopSignal::new();
        let stop_in_loop = stop.clone();

        let status_tx_ready = status_tx.clone();
        let app_state_reg = app_state.clone();
        let interface_for_thread = interface.clone();

        tokio::task::spawn_blocking(move || {
            let open = || -> Result<(pcap::Capture<pcap::Active>, [u8; 6])> {
                let device = pcap::Device::list()
                    .context("failed to list capture devices")?
                    .into_iter()
                    .find(|d| d.name == interface_for_thread)
                    .ok_or_else(|| anyhow!("no such capture device '{}'", interface_for_thread))?;

                let local_mac = match configured_mac {
                    Some(mac) => mac,
                    None => Self::interface_mac(&interface_for_thread).unwrap_or_else(|| {
                        warn!(
                            "CDP could not determine the MAC of '{}'; using {}",
                            interface_for_thread,
                            codec::mac_to_string(&DEFAULT_UDP_SOURCE_MAC)
                        );
                        DEFAULT_UDP_SOURCE_MAC
                    }),
                };

                let mut cap = pcap::Capture::from_device(device)
                    .map(|c| c.promisc(true).snaplen(65535).timeout(1000))
                    .and_then(|c| c.open())
                    .with_context(|| {
                        format!(
                            "failed to open pcap capture on '{}' (needs root, or read access to \
                             /dev/bpf* on macOS/BSD, or CAP_NET_RAW on Linux)",
                            interface_for_thread
                        )
                    })?;

                cap.filter(CDP_BPF_FILTER, true).with_context(|| {
                    format!(
                        "failed to apply the CDP BPF filter on '{}'. CDP rides 802.3 with an \
                         LLC/SNAP header, so this filter cannot compile on an interface with no \
                         Ethernet link layer — loopback (lo/lo0), tunnels and raw-IP devices \
                         carry no CDP. Point this server at a real Ethernet or Wi-Fi interface.",
                        interface_for_thread
                    )
                })?;

                Ok((cap, local_mac))
            };

            let (cap, local_mac) = match open() {
                Ok(v) => {
                    let _ = ready_tx.send(Ok(()));
                    v
                }
                Err(e) => {
                    Log::new(Some(&status_tx))
                        .error(format!("CDP capture startup failed: {:#}", e));
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };

            info!(
                "CDP capture live on {} as {}",
                interface_for_thread,
                codec::mac_to_string(&local_mac)
            );

            let cdp_ctx = Arc::new(CdpContext {
                llm_client,
                app_state,
                status_tx: status_tx.clone(),
                protocol,
                server_id,
                source_mac: local_mac,
            });

            let runtime = tokio::runtime::Handle::current();
            let cap = Arc::new(std::sync::Mutex::new(cap));

            loop {
                if stop_in_loop.is_stopped() {
                    Log::new(Some(&status_tx))
                        .info(format!("CDP capture on {} stopping", interface_for_thread));
                    break;
                }
                let mut guard = cap.lock().unwrap_or_else(|e| e.into_inner());
                match guard.next_packet() {
                    Ok(packet) => {
                        let frame = packet.data.to_vec();
                        drop(guard);

                        let sink = CdpSink::Raw(cap.clone());
                        let cdp_ctx = cdp_ctx.clone();
                        runtime.spawn(async move {
                            if let Err(e) = Self::handle_frame(&frame, sink, cdp_ctx).await {
                                debug!("CDP frame ignored: {:#}", e);
                            }
                        });
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        drop(guard);
                        continue;
                    }
                    Err(e) => {
                        drop(guard);
                        Log::new(Some(&status_tx)).error(format!("CDP capture error: {}", e));
                        break;
                    }
                }
            }

            // Shared with in-flight injection tasks; the handle closes with the last of them.
            drop(cap);
        });

        match ready_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(anyhow!(
                    "CDP capture task on '{}' exited before signalling readiness",
                    interface
                ))
            }
        }

        // Only now that the capture is live: `stop_server` aborts this parked task, which trips
        // `stop` and ends the blocking loop above.
        app_state_reg
            .register_server_task(server_id, stop.park_task())
            .await;

        Log::new(Some(&status_tx_ready)).info(format!("CDP capture active on {}", interface));

        // No socket is bound. `is_bound_addr` treats this as "no listening socket".
        Ok("0.0.0.0:0".parse().expect("literal address parses"))
    }

    /// This interface's own MAC, via pnet's cross-platform interface list.
    ///
    /// `pnet` is already a dependency of this feature, and using it avoids the Linux-only
    /// `/sys/class/net` read `isis` falls back on (which returns an error on macOS, the platform
    /// this protocol was written on).
    fn interface_mac(name: &str) -> Option<[u8; 6]> {
        pnet::datalink::interfaces()
            .into_iter()
            .find(|i| i.name == name)
            .and_then(|i| i.mac)
            .map(|m| [m.0, m.1, m.2, m.3, m.4, m.5])
    }

    // =============================================================================================
    // Shared frame handling
    // =============================================================================================

    /// Decode one frame, raise the event, and put whatever the model decides on the wire.
    async fn handle_frame(frame: &[u8], sink: CdpSink, ctx: Arc<CdpContext>) -> Result<()> {
        let (header, payload) = codec::decode_frame(frame)?;
        let decoded = codec::decode_payload(payload)?;

        // Never advertise at our own reflection: the UDP transport echoes to a peer that may be
        // another netget, and on a real segment our own injected frame can come back through the
        // capture handle. Either way, answering it is an infinite loop.
        if header.source_mac == ctx.source_mac {
            trace!("CDP ignoring a frame from our own source MAC");
            return Ok(());
        }

        let connection_id = ConnectionId::new(ctx.app_state.get_next_unified_id().await);

        Self::register_connection(&ctx, connection_id, &header, frame.len()).await;

        let ad = &decoded.advertisement;
        Log::new(Some(&ctx.status_tx)).info(format!(
            "CDP advertisement from {} ({}) via {}",
            ad.device_id.as_deref().unwrap_or("<no device id>"),
            ad.platform.as_deref().unwrap_or("unknown platform"),
            codec::mac_to_string(&header.source_mac),
        ));
        if !decoded.checksum_valid() {
            Log::new(Some(&ctx.status_tx)).warn(format!(
                "CDP advertisement from {} carries checksum 0x{:04x} but computes 0x{:04x}",
                codec::mac_to_string(&header.source_mac),
                decoded.declared_checksum,
                decoded.computed_checksum
            ));
        }

        let event = Event::new(
            &CDP_NEIGHBOR_ADVERTISEMENT_EVENT,
            decoded.to_event_data(&header, &connection_id.to_string()),
        );

        // Whether to announce ourselves to a neighbour at all is a policy decision, not
        // something the received frame determines — and a busy segment produces one
        // advertisement per neighbour per 60s, so consulting the model with no policy
        // configured would burn a round-trip per frame to decide nothing. With no operator
        // instruction and no handler for this event, observe passively. Same gate as `isis` and
        // `ospf`, and the same reasoning.
        if !operator_wants_dynamic(&ctx.app_state, ctx.server_id, &event.event_type.id).await {
            debug!(
                "CDP {} from {} decision=passive_no_policy (no instruction and no handler; no \
                 advertisement and no LLM call)",
                event.event_type.id,
                codec::mac_to_string(&header.source_mac)
            );
            Log::new(Some(&ctx.status_tx)).debug(
                "CDP advertisement observed passively: no operator policy configured, no reply"
                    .to_string(),
            );
            return Ok(());
        }

        Self::dispatch(event, connection_id, sink, header, ctx).await
    }

    /// Record the neighbour as a connection so the dashboard rail shows it.
    async fn register_connection(
        ctx: &CdpContext,
        connection_id: ConnectionId,
        header: &FrameHeader,
        bytes: usize,
    ) {
        use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};

        let now = crate::utils::clock::Instant::now();
        // A MAC is not a socket address and `ConnectionState` has nowhere else to put one, so
        // the readable form goes in `protocol_info` and the address field is the unspecified
        // one. `isis` stuffs a fabricated address into the field and it renders as nonsense.
        let conn = ConnectionState {
            id: connection_id,
            remote_addr: "0.0.0.0:0".parse().expect("literal address parses"),
            local_addr: "0.0.0.0:0".parse().expect("literal address parses"),
            bytes_sent: 0,
            bytes_received: bytes as u64,
            packets_sent: 0,
            packets_received: 1,
            last_activity: now,
            status: ConnectionStatus::Active,
            status_changed_at: now,
            protocol_info: ProtocolConnectionInfo::new(serde_json::json!({
                "source_mac": codec::mac_to_string(&header.source_mac),
                "destination_mac": codec::mac_to_string(&header.destination_mac),
            })),
        };
        ctx.app_state
            .add_connection_to_server(ctx.server_id, conn)
            .await;
        let _ = ctx.status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Ask the model what to say back, and say exactly that or nothing at all.
    async fn dispatch(
        event: Event,
        connection_id: ConnectionId,
        sink: CdpSink,
        header: FrameHeader,
        ctx: Arc<CdpContext>,
    ) -> Result<()> {
        let event_id = event.event_type.id.clone();
        let peer = codec::mac_to_string(&header.source_mac);

        let result = call_llm(
            &ctx.llm_client,
            &ctx.app_state,
            ctx.server_id,
            Some(connection_id),
            &event,
            ctx.protocol.as_ref(),
        )
        .await;

        let execution = match result {
            Ok(execution) => execution,
            Err(e) => {
                // Nothing goes on the wire. CDP has no error frame, and its only frame type
                // asserts that a device exists — so answering a backend outage with an
                // advertisement would turn "netget is broken" into "this switch is real",
                // written into the neighbour's table for `ttl` seconds. The peer simply ages us
                // out, which is the correct outcome. Nothing derived from `e` is ever
                // interpolated into a frame; the operator gets the whole error here.
                let category = crate::utils::WireFailure::classify(&e);
                let decision = if category.is_overloaded() {
                    "fail_closed_llm_error_overloaded"
                } else {
                    "fail_closed_llm_error_unavailable"
                };
                error!(
                    "CDP {} from {} decision={} ({}) — no advertisement emitted; CDP has no \
                     error frame and a fabricated one would poison the neighbour's table. \
                     LLM error: {}",
                    event_id,
                    peer,
                    decision,
                    category.text(),
                    e
                );
                Log::new(Some(&ctx.status_tx)).error(format!(
                    "✗ CDP LLM error (decision={}, no advertisement emitted): {}",
                    decision, e
                ));
                return Ok(());
            }
        };

        for message in &execution.messages {
            Log::new(Some(&ctx.status_tx)).info(message.to_string());
        }

        let mut frames_sent = 0usize;
        let mut explicit_refusal: Option<String> = None;

        for protocol_result in &execution.protocol_results {
            let crate::llm::actions::protocol_trait::ActionResult::Custom { name, data } =
                protocol_result
            else {
                continue;
            };
            if name != CDP_ACTION_RESULT {
                continue;
            }

            match data.get("type").and_then(|v| v.as_str()) {
                Some("no_advertisement") => {
                    explicit_refusal = Some(
                        data.get("reason")
                            .and_then(|v| v.as_str())
                            .unwrap_or("no reason given")
                            .to_string(),
                    );
                }
                Some("send_cdp_advertisement") => {
                    let advertisement = match CdpAdvertisement::from_action(data) {
                        Ok(ad) => ad,
                        Err(e) => {
                            // A malformed answer is a failure to answer, not a licence to
                            // invent a device. Silent on the wire, loud in the log.
                            error!(
                                "CDP {} from {} decision=model_invalid_action — no \
                                 advertisement emitted: {:#}",
                                event_id, peer, e
                            );
                            Log::new(Some(&ctx.status_tx))
                                .error(format!("✗ CDP advertisement rejected: {:#}", e));
                            continue;
                        }
                    };

                    let payload = match codec::encode_payload(&advertisement) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("CDP payload encode failed: {:#}", e);
                            continue;
                        }
                    };
                    let frame = match codec::encode_frame(ctx.source_mac, &payload) {
                        Ok(f) => f,
                        Err(e) => {
                            error!("CDP frame encode failed: {:#}", e);
                            continue;
                        }
                    };

                    match sink.send(&frame).await {
                        Ok(()) => {
                            frames_sent += 1;
                            ctx.app_state
                                .update_connection_stats(
                                    ctx.server_id,
                                    connection_id,
                                    None,
                                    Some(frame.len() as u64),
                                    None,
                                    Some(1),
                                )
                                .await;
                            Log::new(Some(&ctx.status_tx)).info(format!(
                                "→ CDP advertisement sent via {} ({} bytes): {}",
                                sink.describe(),
                                frame.len(),
                                advertisement.summary()
                            ));
                            trace!("CDP sent (hex): {}", hex::encode(&frame));
                        }
                        Err(e) => {
                            Log::new(Some(&ctx.status_tx))
                                .error(format!("CDP send failed: {:#}", e));
                        }
                    }
                }
                other => {
                    warn!("CDP ignoring unexpected action type {:?}", other);
                }
            }
        }

        if frames_sent == 0 {
            // The wire looks identical in all three cases — CDP has no way to express any of
            // them — so the decision tag in the log is the only place the difference survives.
            // Exactly the discipline `src/server/radius/` uses for its fail-closed path.
            let decision = match &explicit_refusal {
                Some(_) => "model_reject",
                None => "model_silent",
            };
            info!(
                "CDP {} from {} decision={} — no advertisement emitted{}",
                event_id,
                peer,
                decision,
                explicit_refusal
                    .as_ref()
                    .map(|r| format!(" (reason: {})", r))
                    .unwrap_or_default()
            );
            Log::new(Some(&ctx.status_tx)).info(format!(
                "CDP answered with no advertisement: decision={}",
                decision
            ));
        }

        Ok(())
    }
}

/// True when the operator opted into dynamic behaviour: a non-empty server instruction, or an
/// event handler configured for this event.
///
/// With neither, the server is a passive listener and never consults the model — see the
/// reasoning at the call site.
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

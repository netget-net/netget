//! VRRP (v2/v3) and CARP server — IP protocol 112, multicast `224.0.0.18`.
//!
//! NetGet owns the wire; the model owns the election. An advertisement arrives, it is decoded
//! into structured fields, an event is raised, and whatever the operator's handler or the
//! model answers is encoded and sent. That is the whole server.
//!
//! # There is deliberately no election state machine
//!
//! Nothing here runs a master-down timer, tracks a state, or transmits on its own. A VRRP
//! implementation that elected itself master and then kept advertising would keep asserting
//! gateway ownership after the model stopped answering — an automatic master NetGet cannot
//! back, which is precisely the fail-open shape the root `CLAUDE.md` forbids. NetGet supplies
//! the wire; the model supplies the decisions, one advertisement at a time.
//!
//! # Two transports
//!
//! * [`VrrpTransport::Raw`] — a real `SOCK_RAW` socket on IP protocol 112 joined to
//!   `224.0.0.18`. Needs `CAP_NET_RAW` (Linux) or root. **This path has never been executed**;
//!   nothing in this tree runs privileged. See `src/server/vrrp/CLAUDE.md`.
//! * [`VrrpTransport::Udp`] — one complete VRRP or CARP message per UDP datagram, byte-identical
//!   to what the raw transport would emit. The codec, the event, the handler/LLM dispatch and
//!   the response encoding are all the real ones; only the IP layer is simulated. This is what
//!   makes the decision path testable without root, the compromise `ospf` documents.
//!
//! # On failure, silence
//!
//! VRRP is in the deliberately-silent class. Every message it can emit is a *positive
//! assertion of gateway ownership*, there is no error or NAK message to send instead, and a
//! fabricated advertisement does not merely mislead a peer: winning the election makes every
//! host on the segment send its off-link traffic to a router that will not forward it. So when
//! the LLM call fails, **nothing goes on the wire** and the failure is recorded in the log with
//! a `decision=` tag, the way `src/server/radius/` separates its cases. Nothing derived from
//! the error ever reaches a packet.

pub mod actions;
pub mod codec;

use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use crate::{console_debug, console_error, console_info, console_trace};

use crate::logging::emit::Log;
use actions::{
    VrrpGroupConfig, VrrpProtocol, VrrpTransport, VRRP_ADVERTISEMENT_RECEIVED_EVENT,
    VRRP_MASTER_RESIGNED_EVENT,
};
use codec::{Advertisement, PseudoHeader, Variant, VRRP_MULTICAST_IPV4};

/// The minimum IPv4 header, used to skip past it on the raw transport.
const IPV4_HEADER_MIN_LEN: usize = 20;

/// Where a reply goes, and what pseudo-header its checksum is built from.
#[derive(Clone)]
enum Responder {
    Udp {
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        /// The bound address, used as the pseudo-header source for VRRPv3.
        local: Ipv4Addr,
    },
    /// Raw IP-protocol-112 socket. The fd is owned by the receive loop's `AsyncFd`, which
    /// outlives every task holding this, because the loop is what spawns them.
    Raw {
        fd: i32,
        /// The interface address, used as the pseudo-header source for VRRPv3.
        source: Ipv4Addr,
    },
}

impl Responder {
    fn source_address(&self) -> Ipv4Addr {
        match self {
            Responder::Udp { local, .. } => *local,
            Responder::Raw { source, .. } => *source,
        }
    }

    async fn send(&self, packet: &[u8], destination: Ipv4Addr) -> Result<()> {
        match self {
            Responder::Udp { socket, peer, .. } => {
                // The datagram goes back to whoever sent one; `destination` has already done
                // its real work by entering the VRRPv3 checksum through the pseudo-header.
                socket
                    .send_to(packet, peer)
                    .await
                    .with_context(|| format!("failed to send VRRP packet to {peer}"))?;
                Ok(())
            }
            Responder::Raw { fd, .. } => send_raw(*fd, destination, packet),
        }
    }

    fn describe(&self, destination: Ipv4Addr) -> String {
        match self {
            Responder::Udp { peer, .. } => {
                format!("{peer} (udp transport, addressed to {destination})")
            }
            Responder::Raw { .. } => destination.to_string(),
        }
    }
}

/// VRRP / CARP server.
pub struct VrrpServer;

impl VrrpServer {
    /// Start on whichever transport the configuration selects.
    ///
    /// Returns only once the transport is genuinely up — the UDP socket bound, or the raw
    /// socket created, joined and non-blocking — so a failure lands in `ServerStatus::Error`
    /// rather than leaving a server in `Running` that has received nothing. That is the
    /// ARP/DataLink/ICMP fire-and-forget defect the root `CLAUDE.md` records.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        config: VrrpGroupConfig,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
    ) -> Result<SocketAddr> {
        match config.transport {
            VrrpTransport::Udp => {
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
            VrrpTransport::Raw => {
                Self::spawn_raw(
                    listen_addr,
                    config,
                    llm_client,
                    app_state,
                    status_tx,
                    server_id,
                )
                .await
            }
        }
    }

    // -----------------------------------------------------------------------
    // UDP test transport
    // -----------------------------------------------------------------------

    async fn spawn_udp(
        listen_addr: SocketAddr,
        config: VrrpGroupConfig,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
    ) -> Result<SocketAddr> {
        let socket = Arc::new(
            UdpSocket::bind(listen_addr)
                .await
                .with_context(|| format!("failed to bind VRRP UDP transport to {listen_addr}"))?,
        );
        let local_addr = socket.local_addr()?;
        let local_v4 = match local_addr.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                return Err(anyhow!(
                    "VRRP carries IPv4 virtual addresses only; the UDP transport must bind an \
                     IPv4 address, got {local_addr}"
                ))
            }
        };

        console_info!(
            status_tx,
            "VRRP server listening on {} (UDP transport: one complete {} message per datagram, \
             vrid {}, priority {})",
            local_addr,
            config.variant.as_str(),
            config.vrid,
            config.priority
        );

        let protocol = Arc::new(VrrpProtocol::new());
        let config = Arc::new(config);
        let task_registrar = app_state.clone();
        let recv_socket = socket.clone();

        let accept_handle = tokio::spawn(async move {
            // A VRRP advertisement with 255 addresses is 1036 octets; read an MTU so anything
            // longer is refused by the decoder with a real message rather than truncated into
            // something that happens to parse.
            let mut buffer = vec![0u8; 2048];
            loop {
                match recv_socket.recv_from(&mut buffer).await {
                    Ok((n, peer)) => {
                        let packet = buffer[..n].to_vec();
                        console_debug!(status_tx, "VRRP received {} byte message from {}", n, peer);
                        console_trace!(status_tx, "VRRP message (hex): {}", hex::encode(&packet));

                        let peer_v4 = match peer.ip() {
                            IpAddr::V4(ip) => ip,
                            IpAddr::V6(_) => {
                                console_debug!(
                                    status_tx,
                                    "VRRP ignoring datagram from IPv6 peer {}: no IPv6 transport",
                                    peer
                                );
                                continue;
                            }
                        };

                        let responder = Responder::Udp {
                            socket: socket.clone(),
                            peer,
                            local: local_v4,
                        };
                        // Over UDP there is no IP header, so the pseudo-header a VRRPv3 sender
                        // would have used is reconstructed by convention: its own address, and
                        // the VRRP multicast group. Documented in `src/server/vrrp/CLAUDE.md`.
                        let inbound_pseudo = PseudoHeader::new(peer_v4, VRRP_MULTICAST_IPV4);

                        Self::spawn_handler(
                            packet,
                            peer_v4,
                            inbound_pseudo,
                            n,
                            responder,
                            &llm_client,
                            &app_state,
                            &status_tx,
                            &protocol,
                            &config,
                            server_id,
                            local_addr,
                            peer,
                        )
                        .await;
                    }
                    Err(e) => {
                        console_error!(status_tx, "VRRP UDP receive error: {}", e);
                        break;
                    }
                }
            }
            warn!("VRRP UDP receive loop terminated");
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    // -----------------------------------------------------------------------
    // Raw IP protocol 112 transport
    // -----------------------------------------------------------------------

    /// NEVER EXECUTED in this tree — needs `CAP_NET_RAW` or root. Written to the same shape as
    /// `ospf`, including reporting the failure rather than starting a server that receives
    /// nothing.
    async fn spawn_raw(
        listen_addr: SocketAddr,
        config: VrrpGroupConfig,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
    ) -> Result<SocketAddr> {
        let interface_ip = match listen_addr.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                return Err(anyhow!(
                    "VRRP over IPv6 (FF02::12) is not implemented; bind an IPv4 interface \
                     address instead of {listen_addr}"
                ))
            }
        };

        // Creating the socket IS the privileged step and it is synchronous, so the refusal
        // reaches the caller directly. Nothing is spawned before this succeeds.
        let raw_socket = create_vrrp_raw_socket(interface_ip).with_context(|| {
            format!(
                "failed to open a raw IP-protocol-112 socket on {interface_ip}. VRRP and CARP \
                 ride directly on IP, so this needs CAP_NET_RAW on Linux or root elsewhere. Use \
                 startup_params.transport = \"udp\" to exercise the protocol without privilege."
            )
        })?;
        let socket_fd = raw_socket.as_raw_fd();

        console_info!(
            status_tx,
            "VRRP server on {} (raw IP protocol 112, joined {}, variant {}, vrid {})",
            interface_ip,
            VRRP_MULTICAST_IPV4,
            config.variant.as_str(),
            config.vrid
        );

        let async_socket = tokio::io::unix::AsyncFd::new(raw_socket)
            .context("failed to register the VRRP raw socket with the tokio reactor")?;

        let protocol = Arc::new(VrrpProtocol::new());
        let config = Arc::new(config);
        let task_registrar = app_state.clone();

        let accept_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65535];
            loop {
                let mut guard = match async_socket.readable().await {
                    Ok(guard) => guard,
                    Err(e) => {
                        console_error!(status_tx, "VRRP raw socket error: {}", e);
                        break;
                    }
                };

                let read = guard.try_io(|inner| {
                    let fd = inner.as_raw_fd();
                    // SAFETY: `fd` is owned by `async_socket` for the whole loop and `buffer`
                    // is a live allocation of the length passed.
                    let n = unsafe {
                        libc::recv(
                            fd,
                            buffer.as_mut_ptr() as *mut libc::c_void,
                            buffer.len(),
                            0,
                        )
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                });

                let n = match read {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => {
                        console_error!(status_tx, "VRRP raw receive error: {}", e);
                        continue;
                    }
                    Err(_would_block) => continue,
                };

                // A raw IPv4 socket delivers the IP header too.
                if n < IPV4_HEADER_MIN_LEN {
                    continue;
                }
                let header_len = ((buffer[0] & 0x0f) as usize) * 4;
                if header_len < IPV4_HEADER_MIN_LEN || n <= header_len {
                    continue;
                }
                let source = Ipv4Addr::new(buffer[12], buffer[13], buffer[14], buffer[15]);
                let destination = Ipv4Addr::new(buffer[16], buffer[17], buffer[18], buffer[19]);
                let packet = buffer[header_len..n].to_vec();
                let payload_len = packet.len();

                console_debug!(
                    status_tx,
                    "VRRP received {} byte message from {} to {}",
                    payload_len,
                    source,
                    destination
                );
                console_trace!(status_tx, "VRRP message (hex): {}", hex::encode(&packet));

                let responder = Responder::Raw {
                    fd: socket_fd,
                    source: interface_ip,
                };
                let inbound_pseudo = PseudoHeader::new(source, destination);

                Self::spawn_handler(
                    packet,
                    source,
                    inbound_pseudo,
                    payload_len,
                    responder,
                    &llm_client,
                    &app_state,
                    &status_tx,
                    &protocol,
                    &config,
                    server_id,
                    SocketAddr::new(IpAddr::V4(interface_ip), 0),
                    SocketAddr::new(IpAddr::V4(source), 0),
                )
                .await;
            }
            warn!("VRRP raw receive loop terminated");
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(SocketAddr::new(IpAddr::V4(interface_ip), 0))
    }

    // -----------------------------------------------------------------------
    // Message -> event
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn spawn_handler(
        packet: Vec<u8>,
        source: Ipv4Addr,
        inbound_pseudo: PseudoHeader,
        bytes: usize,
        responder: Responder,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &Arc<VrrpProtocol>,
        config: &Arc<VrrpGroupConfig>,
        server_id: ServerId,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    ) {
        let llm = llm_client.clone();
        let state = app_state.clone();
        let status = status_tx.clone();
        let proto = protocol.clone();
        let cfg = config.clone();
        // Tracked, not detached: stop_server must abort this task too.
        let task_owner = app_state.clone();
        task_owner
            .spawn_server_task(server_id, async move {
                Self::record_connection(&state, server_id, local_addr, peer_addr, bytes).await;
                Self::handle_packet(
                    packet,
                    source,
                    inbound_pseudo,
                    responder,
                    llm,
                    state,
                    status,
                    proto,
                    cfg,
                    server_id,
                )
                .await;
            })
            .await;
    }

    /// Per-remote-address bookkeeping so the dashboard shows who is advertising.
    ///
    /// These entries have no lifecycle of their own — nothing ever "closes" a VRRP speaker —
    /// which is exactly the case `ProtocolMetadataV2::connectionless` exists for, and why this
    /// protocol declares it: the runtime reaps them once `last_activity` goes stale.
    async fn record_connection(
        state: &Arc<AppState>,
        server_id: ServerId,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        bytes: usize,
    ) {
        use crate::state::server::{
            ConnectionState as ServerConnectionState, ConnectionStatus, ProtocolConnectionInfo,
        };
        let connection_id = ConnectionId::new(state.get_next_unified_id().await);
        let now = crate::utils::clock::Instant::now();
        state
            .add_connection_to_server(
                server_id,
                ServerConnectionState {
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
                },
            )
            .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_packet(
        packet: Vec<u8>,
        source: Ipv4Addr,
        inbound_pseudo: PseudoHeader,
        responder: Responder,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<VrrpProtocol>,
        config: Arc<VrrpGroupConfig>,
        server_id: ServerId,
    ) {
        let decoded = match Advertisement::decode(config.variant, &packet) {
            Ok(decoded) => decoded,
            Err(e) => {
                console_debug!(status_tx, "VRRP ignoring message from {}: {:#}", source, e);
                return;
            }
        };

        let (event_type, data) = match &decoded {
            Advertisement::Vrrp(advertisement) => {
                let scope = advertisement.checksum_scope();
                let checksum_valid = match scope {
                    codec::ChecksumScope::Message => codec::checksum_is_valid(&packet, None),
                    codec::ChecksumScope::PseudoHeaderAndMessage => {
                        codec::checksum_is_valid(&packet, Some(&inbound_pseudo))
                    }
                };
                let mut data = serde_json::json!({
                    "variant": Variant::Vrrp.as_str(),
                    "version": advertisement.version,
                    "vrid": advertisement.vrid,
                    "priority": advertisement.priority,
                    "advert_interval": advertisement.advert_interval_seconds,
                    "addresses": advertisement.addresses.iter().map(|a| a.to_string())
                        .collect::<Vec<_>>(),
                    "address_count": advertisement.addresses.len(),
                    "source_address": source.to_string(),
                    "checksum_valid": checksum_valid,
                    "checksum_scope": scope.as_str(),
                    "auth_type": advertisement.auth_type,
                    "is_address_owner": advertisement.is_address_owner(),
                    "is_resignation": advertisement.is_resignation(),
                });
                merge(&mut data, config.local_summary());
                if advertisement.is_resignation() {
                    (&*VRRP_MASTER_RESIGNED_EVENT, data)
                } else {
                    (&*VRRP_ADVERTISEMENT_RECEIVED_EVENT, data)
                }
            }
            Advertisement::Carp(advertisement) => {
                // CARP's checksum covers the message alone; there is no pseudo-header.
                let checksum_valid = codec::checksum_is_valid(&packet, None);
                // With no configured passphrase there is no key to check against, and
                // reporting `true` would be the fail-open shape this codebase forbids: the
                // model must be able to tell "verified" from "not checked".
                let hmac_valid = if config.carp_passphrase.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::Bool(
                        codec::carp_hmac(
                            config.carp_passphrase.as_bytes(),
                            advertisement.vhid,
                            &config.addresses,
                            advertisement.counter,
                        ) == advertisement.hmac,
                    )
                };
                let mut data = serde_json::json!({
                    "variant": Variant::Carp.as_str(),
                    "version": advertisement.version,
                    "vrid": advertisement.vhid,
                    "advert_interval": advertisement.interval_seconds(),
                    "advskew": advertisement.advskew,
                    "advbase": advertisement.advbase,
                    "demote": advertisement.demote,
                    "counter": advertisement.counter,
                    "source_address": source.to_string(),
                    "checksum_valid": checksum_valid,
                    "checksum_scope": codec::ChecksumScope::Message.as_str(),
                    "hmac_valid": hmac_valid,
                });
                merge(&mut data, config.local_summary());
                (&*VRRP_ADVERTISEMENT_RECEIVED_EVENT, data)
            }
        };

        info!(
            "VRRP {} from {}: vrid={} priority={:?}",
            data.get("variant").and_then(|v| v.as_str()).unwrap_or("?"),
            source,
            data.get("vrid").and_then(|v| v.as_u64()).unwrap_or(0),
            data.get("priority").and_then(|v| v.as_u64()),
        );

        let event = Event::new(event_type, data);
        Self::dispatch_event(
            event, responder, llm_client, app_state, status_tx, protocol, config, server_id,
        )
        .await;
    }

    /// Ask the operator's handler or the model what to answer, and put exactly that — or
    /// nothing — on the wire.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_event(
        event: Event,
        responder: Responder,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<VrrpProtocol>,
        config: Arc<VrrpGroupConfig>,
        server_id: ServerId,
    ) {
        let event_id = event.event_type.id.clone();

        // Whether to take part in an election at all — and at what priority — is policy, not
        // something the received advertisement determines. With no operator policy (no
        // instruction and no handler) the safe answer is to observe and say nothing, and to do
        // that *without* an LLM round-trip: a VRRP group advertises once a second by default,
        // so consulting the model per packet would cost one call per second forever.
        if !operator_wants_dynamic(&app_state, server_id, &event_id).await {
            debug!(
                "VRRP decision=no_policy: {} observed, no operator policy configured (no \
                 instruction and no handler), nothing transmitted and no LLM call",
                event_id
            );
            let _ = status_tx.send(format!(
                "VRRP decision=no_policy: {} observed passively (no policy configured, no LLM)",
                event_id
            ));
            return;
        }

        match call_llm(
            &llm_client,
            &app_state,
            server_id,
            None,
            &event,
            protocol.as_ref(),
        )
        .await
        {
            Ok(execution_result) => {
                for message in &execution_result.messages {
                    Log::to(&status_tx).info(message);
                }

                let mut sent = 0usize;
                for result in execution_result.protocol_results {
                    let crate::llm::actions::protocol_trait::ActionResult::Custom { name, data } =
                        &result
                    else {
                        continue;
                    };
                    if name.as_str() != "vrrp_action" {
                        continue;
                    }

                    match Self::packet_from_action(&config, data, responder.source_address()) {
                        Ok((packet, destination)) => {
                            match responder.send(&packet, destination).await {
                                Ok(()) => {
                                    sent += 1;
                                    debug!(
                                        "VRRP sent {} byte advertisement to {}",
                                        packet.len(),
                                        responder.describe(destination)
                                    );
                                    trace!("VRRP sent (hex): {}", hex::encode(&packet));
                                    let _ = status_tx.send(format!(
                                        "[DEBUG] VRRP sent {} byte advertisement to {}",
                                        packet.len(),
                                        responder.describe(destination)
                                    ));
                                }
                                Err(e) => {
                                    error!("VRRP transmit failed: {:#}", e);
                                    let _ =
                                        status_tx.send(format!("✗ VRRP transmit failed: {:#}", e));
                                }
                            }
                        }
                        Err(e) => {
                            // An advertisement we cannot build is one we must not approximate.
                            error!("VRRP could not build the requested advertisement: {:#}", e);
                            let _ = status_tx.send(format!(
                                "✗ VRRP decision=model_invalid: could not build the requested \
                                 advertisement, nothing transmitted: {:#}",
                                e
                            ));
                        }
                    }
                }

                if sent == 0 {
                    // Nothing went out. VRRP has no error or NAK message, so an explicit
                    // refusal, an empty answer and a build failure are identical on the wire;
                    // the decision tag is the only place the difference survives.
                    let model_rejected = execution_result.raw_actions.iter().any(|a| {
                        a.get("type").and_then(|t| t.as_str()) == Some("no_advertisement")
                    });
                    let decision = if model_rejected {
                        "model_reject"
                    } else {
                        "model_silent"
                    };
                    info!(
                        "VRRP {} answered with no advertisement: decision={} (VRRP has no error \
                         message; staying silent is the protocol-correct response)",
                        event_id, decision
                    );
                    let _ = status_tx.send(format!(
                        "VRRP decision={}: {} answered with no advertisement",
                        decision, event_id
                    ));
                }
            }
            Err(e) => {
                // FAIL CLOSED, AND CLOSED MEANS SILENT. An advertisement is a positive claim
                // to own the virtual gateway address. Emitting one to signal "netget is
                // broken" would, if its priority happened to win, make every host on the
                // segment route through a router that does not forward — a black hole, which
                // is strictly worse for the network than silence. A peer already handles our
                // silence correctly: its master-down interval expires and it takes over,
                // which is the spec-defined outcome for a router that stops speaking.
                //
                // Nothing derived from `e` goes anywhere near a packet; it is classified only
                // to keep an overloaded backend distinguishable from a broken one in the log.
                let category = crate::utils::WireFailure::classify(&e);
                let decision = if category.is_overloaded() {
                    "fail_closed_overloaded"
                } else {
                    "fail_closed_llm_error"
                };
                error!(
                    "VRRP decision={}: LLM call failed for {}, nothing transmitted (VRRP has no \
                     failure message and a fabricated advertisement can black-hole the \
                     segment): {}",
                    decision, event_id, e
                );
                let _ = status_tx.send(format!(
                    "✗ VRRP decision={}: {} unanswered ({}), nothing transmitted: {}",
                    decision,
                    event_id,
                    category.text(),
                    e
                ));
            }
        }
    }

    /// Turn one validated action into wire octets plus the address they are addressed to.
    ///
    /// The operator's configured group is layered in first, so a model that names only
    /// `priority` still emits an advertisement carrying this server's VRID, interval and
    /// virtual addresses.
    fn packet_from_action(
        config: &VrrpGroupConfig,
        data: &serde_json::Value,
        source: Ipv4Addr,
    ) -> Result<(Vec<u8>, Ipv4Addr)> {
        let action_type = data
            .get("type")
            .and_then(|v| v.as_str())
            .context("VRRP action has no 'type'")?;
        if action_type != "send_vrrp_advertisement" {
            return Err(anyhow!("unknown VRRP action '{action_type}'"));
        }

        let mut data = data.clone();
        config.apply_defaults(&mut data);
        let destination = VrrpProtocol::destination_from_action(&data)?;
        let advertisement = VrrpProtocol::advertisement_from_action(&data, config)?;
        // VRRPv3 folds the source and destination into its checksum (RFC 5798 §5.2.8), so the
        // same body addressed elsewhere is different octets. v2 and CARP ignore this.
        let pseudo = PseudoHeader::new(source, destination);
        let packet = advertisement.encode(Some(&pseudo))?;
        Ok((packet, destination))
    }
}

/// Copy every key of `extra` into `target`.
fn merge(target: &mut serde_json::Value, extra: serde_json::Value) {
    if let (Some(target), Some(extra)) = (target.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
}

/// True when the operator opted into dynamic (handler- or LLM-driven) responses for this
/// server: a non-empty instruction, or an event handler matching `event_id`.
///
/// When false the server observes and never consults the model. Advertising is a policy
/// decision with real consequences for somebody's network, and there is no policy to apply.
async fn operator_wants_dynamic(state: &AppState, server_id: ServerId, event_id: &str) -> bool {
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

// ---------------------------------------------------------------------------
// Raw socket
// ---------------------------------------------------------------------------

/// Create the raw IP-protocol-112 socket, joined to `224.0.0.18` on `interface_addr`.
///
/// NEVER EXECUTED in this tree: `SOCK_RAW` needs `CAP_NET_RAW` on Linux and root elsewhere,
/// and nothing here runs privileged. Shaped after `create_ospf_raw_socket`.
///
/// The multicast TTL is **255, not 1** — RFC 5798 §5.1.1.3 requires a VRRP sender to use 255
/// and a receiver to discard anything else, which is what keeps an advertisement from being
/// accepted off-link: a router more than one hop away could not have sent it with 255 intact.
/// A TTL of 1 would be the obvious way to say "link-local" and is precisely wrong here; every
/// conformant peer would drop the packet. See the call to `set_multicast_ttl_v4` below.
fn create_vrrp_raw_socket(interface_addr: Ipv4Addr) -> Result<socket2::Socket> {
    use std::os::unix::io::FromRawFd;

    // SAFETY: the fd is checked for validity before being adopted, and `Socket` takes
    // ownership of it exactly once.
    let socket = unsafe {
        let fd = libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW,
            codec::IP_PROTOCOL_VRRP as libc::c_int,
        );
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        socket2::Socket::from_raw_fd(fd)
    };

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.join_multicast_v4(&VRRP_MULTICAST_IPV4, &interface_addr)?;
    // RFC 5798 §5.1.1.3: VRRP packets are sent with TTL 255 and a receiver discards anything
    // else, but the *multicast* TTL below is the hop limit for our own transmissions; VRRP
    // never leaves the link.
    socket.set_multicast_ttl_v4(255)?;
    socket.set_multicast_if_v4(&interface_addr)?;
    Ok(socket)
}

/// `sendto` on the raw socket. Raw IP has no port, so `sin_port` is 0.
fn send_raw(fd: i32, destination: Ipv4Addr, packet: &[u8]) -> Result<()> {
    // SAFETY: `fd` is owned by the receive loop's `AsyncFd` for as long as any task holding a
    // `Responder::Raw` can run, and `packet` is a live slice of the length passed.
    unsafe {
        let mut addr = std::mem::zeroed::<libc::sockaddr_in>();
        #[cfg(target_os = "macos")]
        {
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        #[cfg(not(target_os = "macos"))]
        {
            addr.sin_family = libc::AF_INET as u16;
        }
        addr.sin_port = 0;
        addr.sin_addr.s_addr = u32::from(destination).to_be();

        let sent = libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        if sent < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

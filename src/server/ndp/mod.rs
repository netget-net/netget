//! IPv6 Neighbour Discovery (RFC 4861) server — NetGet as a router, or as a neighbour, on
//! somebody else's link.
//!
//! NDP is what IPv6 replaced ARP, ICMP Router Discovery and ICMP Redirect with. Five ICMPv6
//! messages carry the whole thing: hosts ask for routers (133) and routers answer (134), nodes
//! ask where an address lives (135) and answer (136), and a router can move a destination to a
//! different first hop (137).
//!
//! **The Router Advertisement is the reason this protocol is here.** One of them hands a link its
//! prefix, its default route and — through RDNSS (RFC 8106) — its DNS resolvers, and every host
//! on the segment accepts it from anybody, unauthenticated. That is what `mitm6` exploits, and
//! having a model author one is the point of the protocol.
//!
//! # Two transports, one codec
//!
//! The packet format lives in [`codec`] and is a pure function over plain values. This module is
//! the thin layer that moves those bytes:
//!
//! * **`transport: "raw"`** (the default) — a raw ICMPv6 socket. Needs root or `CAP_NET_RAW`.
//!   **This code has never been executed**; see `CLAUDE.md`.
//! * **`transport: "udp"`** — a testing transport whose datagrams carry
//!   `source(16) || destination(16) || ICMPv6 message`, so the whole event → handler/LLM →
//!   message path runs unprivileged *including the pseudo-header checksum*, which needs both
//!   addresses and is therefore the one part a naive test transport would quietly skip. No real
//!   IPv6 stack speaks it. This is the same accommodation `ospf` makes for its raw socket, made
//!   explicit as a declared parameter rather than left to the test file.
//!
//! # No timer, deliberately
//!
//! A real router advertises unprompted every few minutes. This server does not, and will not: an
//! unsolicited Router Advertisement reconfigures every host that hears it, and a NetGet instance
//! left running would keep doing so. Every advertisement here comes from an explicit model
//! action in response to something received.
//!
//! # Failure is silence, and the log is where the difference lives
//!
//! NDP is in the deliberately-silent class the root `CLAUDE.md` describes, and its case is among
//! the strongest in the repository. Every message the protocol defines is a *positive assertion*
//! about addressing on this link: an answer writes a binding into the peer's neighbour cache, and
//! a Router Advertisement rewrites its entire routing and DNS configuration. There is no error
//! message to send. Fabricating one on an LLM failure is cache poisoning at best and a full
//! traffic redirect at worst, so this server emits **nothing**, and no `WireFailure` text ever
//! reaches the wire.
//!
//! On the wire all the outcomes are identical, so they are separated in the log by a `decision=`
//! tag, the way `src/server/radius/` separates its cases:
//!
//! | Tag | Meaning |
//! |---|---|
//! | `decision=no_policy` | No instruction and no handler — nothing sent and no LLM call is made |
//! | `decision=model_reject` | The model answered `no_response` — a real decision |
//! | `decision=model_silent` | The model returned nothing usable |
//! | `decision=fail_closed_overloaded` | The call failed and the backend is saturated (retryable) |
//! | `decision=fail_closed_llm_error` | The call failed otherwise |

pub mod actions;
pub mod codec;

use anyhow::{anyhow, bail, Context, Result};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
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
    NdpProtocol, DEFAULT_LINK_LAYER_ADDRESS, DEFAULT_LINK_LOCAL, NDP_MESSAGE_RESULT,
    NDP_NEIGHBOR_ADVERTISEMENT_EVENT, NDP_NEIGHBOR_SOLICITATION_EVENT, NDP_REDIRECT_RECEIVED_EVENT,
    NDP_ROUTER_ADVERTISEMENT_RECEIVED_EVENT, NDP_ROUTER_SOLICITATION_EVENT, NO_RESPONSE_ACTION,
};
use codec::NdpMessage;

/// Which way messages travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportKind {
    /// A real raw ICMPv6 socket. Privileged, and never executed in this repository.
    Raw,
    /// Addressed ICMPv6 messages inside UDP datagrams. Testing only.
    Udp,
}

/// Everything the startup parameters configure. Every field here is read.
#[derive(Debug, Clone)]
struct NdpConfig {
    transport: TransportKind,
    udp_peer: Option<SocketAddr>,
    /// Our own IPv6 address: the source of everything we send, and therefore half of the
    /// pseudo-header every checksum is computed over.
    link_local_address: Ipv6Addr,
    /// Our own link-layer address, when the operator named one.
    link_layer_address: Option<[u8; 6]>,
}

impl NdpConfig {
    fn from_params(params: Option<&crate::protocol::StartupParams>) -> Result<Self> {
        let default_link_local = DEFAULT_LINK_LOCAL
            .parse::<Ipv6Addr>()
            .expect("DEFAULT_LINK_LOCAL is a literal IPv6 address");

        let Some(params) = params else {
            return Ok(Self {
                transport: TransportKind::Raw,
                udp_peer: None,
                link_local_address: default_link_local,
                link_layer_address: None,
            });
        };

        let transport = match params.get_optional_string("transport")?.as_deref() {
            None | Some("raw") => TransportKind::Raw,
            Some("udp") => TransportKind::Udp,
            Some(other) => bail!(
                "transport must be \"raw\" (a real ICMPv6 raw socket) or \"udp\" (testing \
                 transport carrying addressed ICMPv6 messages in datagrams), got '{other}'"
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

        let link_local_address = match params.get_optional_string("link_local_address")? {
            None => default_link_local,
            Some(text) => text.trim().parse::<Ipv6Addr>().with_context(|| {
                format!("link_local_address must be an IPv6 address, got '{text}'")
            })?,
        };

        let link_layer_address = match params.get_optional_string("link_layer_address")? {
            None => None,
            Some(text) => Some(codec::parse_mac(&text)?),
        };

        Ok(Self {
            transport,
            udp_peer,
            link_local_address,
            link_layer_address,
        })
    }
}

/// Where a built message goes.
#[derive(Clone)]
enum MessageSink {
    /// A raw ICMPv6 socket. `scope_id` is the interface index link-local and multicast
    /// destinations need — without it `ff02::1` has no route and the send fails outright.
    Raw {
        socket: Arc<socket2::Socket>,
        scope_id: u32,
    },
    /// Wrap the message with its two addresses and send it as a UDP datagram, to the configured
    /// peer or to whoever spoke last.
    Udp {
        socket: Arc<UdpSocket>,
        configured_peer: Option<SocketAddr>,
        last_peer: Arc<Mutex<Option<SocketAddr>>>,
    },
}

impl MessageSink {
    async fn send(&self, source: Ipv6Addr, destination: Ipv6Addr, message: &[u8]) -> Result<usize> {
        match self {
            MessageSink::Raw { socket, scope_id } => {
                let target = SocketAddrV6::new(destination, 0, 0, *scope_id);
                Ok(socket.send_to(message, &socket2::SockAddr::from(target))?)
            }
            MessageSink::Udp {
                socket,
                configured_peer,
                last_peer,
            } => {
                // The guard is dropped before the await: never hold a lock across I/O.
                let peer = match configured_peer {
                    Some(p) => Some(*p),
                    None => *last_peer.lock().expect("ndp peer mutex poisoned"),
                };
                let peer = peer.ok_or_else(|| {
                    anyhow!(
                        "no UDP peer to transmit to: nothing has been received yet and no \
                         udp_peer startup parameter was given"
                    )
                })?;
                let datagram = codec::encode_addressed(source, destination, message);
                Ok(socket.send_to(&datagram, peer).await?)
            }
        }
    }
}

/// The parts of the running server every per-message task needs.
struct NdpContext {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    protocol: Arc<NdpProtocol>,
    server_id: crate::state::ServerId,
    /// Our own IPv6 address, used as the source when an action names none.
    link_local_address: Ipv6Addr,
    /// Our own link-layer address, filled into Source/Target Link-Layer Address options when an
    /// action names none.
    link_layer_address: [u8; 6],
}

pub struct NdpServer;

impl NdpServer {
    /// Start a Neighbour Discovery server.
    ///
    /// Returns `Err` — never a server left sitting in `Running` — when the raw socket cannot be
    /// opened, the interface cannot be resolved, the UDP socket cannot be bound, or a startup
    /// parameter is unusable. ARP, DataLink and ICMP each shipped the fire-and-forget version of
    /// this and were each fixed separately.
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
        let config = NdpConfig::from_params(startup_params.as_ref())?;

        match config.transport {
            TransportKind::Raw => {
                let interface = interface.ok_or_else(|| {
                    anyhow!(
                        "NDP transport \"raw\" needs an interface to send link-local and \
                         multicast messages on (pass `interface`), or use transport \"udp\" for \
                         an unprivileged test run"
                    )
                })?;
                Self::spawn_raw(
                    interface, config, llm_client, app_state, status_tx, server_id,
                )
                .await
            }
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
        }
    }

    fn build_context(
        config: &NdpConfig,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        interface_mac: Option<[u8; 6]>,
    ) -> Arc<NdpContext> {
        let link_layer_address = config
            .link_layer_address
            .or(interface_mac)
            .unwrap_or_else(|| {
                codec::parse_mac(DEFAULT_LINK_LAYER_ADDRESS)
                    .expect("DEFAULT_LINK_LAYER_ADDRESS is a literal link-layer address")
            });

        Arc::new(NdpContext {
            llm_client,
            app_state,
            status_tx,
            protocol: Arc::new(NdpProtocol::new()),
            server_id,
            link_local_address: config.link_local_address,
            link_layer_address,
        })
    }

    /// The testing transport: `source(16) || destination(16) || ICMPv6 message` in a datagram.
    async fn spawn_udp(
        listen_addr: SocketAddr,
        config: NdpConfig,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        // Awaited, so a bind failure is returned rather than logged from a detached task.
        let socket = Arc::new(UdpSocket::bind(listen_addr).await.with_context(|| {
            format!("failed to bind the NDP UDP test transport to {listen_addr}")
        })?);
        let local_addr = socket.local_addr()?;

        console_info!(
            status_tx,
            "NDP listening on {} as {} (transport=udp — a TEST transport carrying addressed \
             ICMPv6 messages in datagrams; no real IPv6 stack speaks it)",
            local_addr,
            config.link_local_address
        );

        let ctx = Self::build_context(
            &config,
            llm_client,
            app_state.clone(),
            status_tx.clone(),
            server_id,
            None,
        );

        let sink = MessageSink::Udp {
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
                        if let MessageSink::Udp { last_peer, .. } = &receive_sink {
                            *last_peer.lock().expect("ndp peer mutex poisoned") = Some(peer);
                        }
                        let datagram = buffer[..n].to_vec();
                        let ctx = receive_ctx.clone();
                        let sink = receive_sink.clone();
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = loop_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                Self::handle_datagram(&datagram, peer, local_addr, ctx, sink).await;
                            })
                            .await;
                    }
                    Err(e) => {
                        console_error!(receive_ctx.status_tx, "NDP UDP receive error: {}", e);
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

    /// The real transport: a raw ICMPv6 socket.
    ///
    /// **Never executed anywhere.** It compiles, and it is written to the same shape as `icmp`
    /// and `lldp`, including the parts those learned the hard way — but nothing in this
    /// repository has the privilege to open the socket.
    async fn spawn_raw(
        interface: String,
        config: NdpConfig,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        use socket2::{Domain, Protocol, Socket, Type};

        // Resolving the interface is unprivileged and must happen before the socket: a raw
        // ICMPv6 socket with no scope id cannot send to ff02::1 at all, so opening one first
        // would produce a server that starts and can never transmit.
        let (scope_id, interface_mac) = interface_details(&interface).ok_or_else(|| {
            anyhow!(
                "no interface named '{interface}' on this host. NDP is a link-local protocol: \
                 link-local and multicast destinations need the interface's scope id, so there \
                 is no useful default. Use transport \"udp\" for an unprivileged test run."
            )
        })?;

        console_info!(
            status_tx,
            "NDP opening a raw ICMPv6 socket on interface {} (index {}) as {}",
            interface,
            scope_id,
            config.link_local_address
        );

        let ctx = Self::build_context(
            &config,
            llm_client,
            app_state.clone(),
            status_tx.clone(),
            server_id,
            interface_mac,
        );

        // Opening the socket is the privileged step, so it must not be fire-and-forget: the
        // outcome comes back over a oneshot and this function only returns Ok once the socket is
        // genuinely open. A server in Running that has received nothing is worse than one that
        // refuses to start.
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<()>>();

        // `JoinHandle::abort()` cannot interrupt a thread parked in a blocking receive, so the
        // loop is stopped cooperatively. The socket is non-blocking and the loop sleeps 10ms on
        // `WouldBlock`, so a stop is noticed within ~10ms.
        let stop = crate::utils::StopSignal::new();
        let stop_in_loop = stop.clone();

        let loop_interface = interface.clone();
        let loop_ctx = ctx.clone();
        let (sink_tx, sink_rx) = tokio::sync::oneshot::channel::<MessageSink>();

        tokio::task::spawn_blocking(move || {
            let open = || -> Result<Socket> {
                let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).context(
                    "failed to create a raw ICMPv6 socket (needs root, or CAP_NET_RAW on \
                         Linux). Use transport \"udp\" for an unprivileged test run.",
                )?;
                socket
                    .set_nonblocking(true)
                    .context("failed to put the raw ICMPv6 socket in non-blocking mode")?;
                // RFC 4861 §11.2: every NDP message is sent with a Hop Limit of 255 and a
                // receiver discards one that arrives with less. That is the protocol's entire
                // defence against an off-link attacker, and getting it wrong produces a server
                // whose messages are silently dropped by every conforming host.
                socket
                    .set_unicast_hops_v6(codec::NDP_HOP_LIMIT)
                    .context("failed to set the IPv6 unicast hop limit to 255")?;
                socket
                    .set_multicast_hops_v6(codec::NDP_HOP_LIMIT)
                    .context("failed to set the IPv6 multicast hop limit to 255")?;
                socket.set_multicast_if_v6(scope_id).with_context(|| {
                    format!("failed to send IPv6 multicast out of interface '{loop_interface}'")
                })?;
                Ok(socket)
            };

            let socket = match open() {
                Ok(socket) => {
                    let _ = ready_tx.send(Ok(()));
                    Arc::new(socket)
                }
                Err(e) => {
                    console_error!(loop_ctx.status_tx, "NDP raw socket startup failed: {:#}", e);
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };

            let loop_sink = MessageSink::Raw {
                socket: socket.clone(),
                scope_id,
            };
            let _ = sink_tx.send(loop_sink.clone());

            let runtime = tokio::runtime::Handle::current();
            let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 65535];

            loop {
                if stop_in_loop.is_stopped() {
                    console_info!(
                        loop_ctx.status_tx,
                        "NDP receive loop on {} stopping",
                        loop_interface
                    );
                    break;
                }
                match socket.recv_from(&mut buffer) {
                    Ok((n, from)) => {
                        // A raw IPv6 socket never includes the IPv6 header (RFC 3542 §3), so
                        // what arrives is the ICMPv6 message itself.
                        let message =
                            unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u8, n) }
                                .to_vec();
                        let Some(source) = from.as_socket_ipv6().map(|a| *a.ip()) else {
                            debug!("NDP ignoring a packet from a non-IPv6 source address");
                            continue;
                        };
                        let ctx = loop_ctx.clone();
                        let sink = loop_sink.clone();
                        runtime.spawn(async move {
                            // The destination address is not reported without
                            // `IPV6_RECVPKTINFO`, so it is unknown here — and the kernel has
                            // already verified the checksum for an ICMPv6 raw socket
                            // (RFC 3542 §3.1), so nothing is lost by not re-checking it.
                            let nowhere: SocketAddr =
                                "[::]:0".parse().expect("[::]:0 is a valid socket address");
                            Self::handle_message(&message, source, None, None, nowhere, ctx, sink)
                                .await;
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => {
                        console_error!(loop_ctx.status_tx, "NDP raw receive error: {}", e);
                        break;
                    }
                }
            }
        });

        match ready_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(anyhow!(
                    "NDP raw socket task on '{interface}' exited before signalling readiness"
                ))
            }
        }
        // The sink is only produced once the socket is open; awaiting it keeps the two in step.
        let _sink = sink_rx.await.map_err(|_| {
            anyhow!("NDP raw socket task on '{interface}' never produced a transmit handle")
        })?;

        app_state
            .register_server_task(server_id, stop.park_task())
            .await;

        console_info!(status_tx, "NDP raw ICMPv6 active on {}", interface);

        // Nothing is bound to an address: NDP has no port. `server_startup` records this and the
        // dashboard shows the interface instead.
        Ok("[::]:0".parse().expect("[::]:0 is a valid socket address"))
    }

    /// A datagram on the UDP test transport: unwrap the addresses, verify the checksum they were
    /// computed over, and hand the message on.
    async fn handle_datagram(
        datagram: &[u8],
        peer: SocketAddr,
        local_addr: SocketAddr,
        ctx: Arc<NdpContext>,
        sink: MessageSink,
    ) {
        let (source, destination, message) = match codec::decode_addressed(datagram) {
            Ok(parts) => parts,
            Err(e) => {
                debug!(
                    "NDP ignoring an undecodable datagram ({} octets) from {}: {}",
                    datagram.len(),
                    peer,
                    e
                );
                return;
            }
        };

        // The one thing the UDP transport can check that the raw one cannot: on a raw ICMPv6
        // socket the kernel has already verified this, so this is the only place in the running
        // server where the pseudo-header calculation is actually exercised on received bytes.
        if let Err(e) = codec::verify_checksum(message, source, destination) {
            console_debug!(ctx.status_tx, "NDP dropping a message: {}", e);
            return;
        }

        Self::handle_message(
            message,
            source,
            Some(destination),
            Some(peer),
            local_addr,
            ctx,
            sink,
        )
        .await;
    }

    /// Decode one ICMPv6 message and hand it to the operator's policy.
    #[allow(clippy::too_many_arguments)]
    async fn handle_message(
        message: &[u8],
        source: Ipv6Addr,
        destination: Option<Ipv6Addr>,
        peer: Option<SocketAddr>,
        local_addr: SocketAddr,
        ctx: Arc<NdpContext>,
        sink: MessageSink,
    ) {
        let decoded = match NdpMessage::decode(message) {
            Ok(decoded) => decoded,
            Err(e) => {
                // Not worth an operator's attention: a raw ICMPv6 socket delivers every ICMPv6
                // message on the host, most of which are echo replies and none of which are ours.
                trace!(
                    "NDP ignoring a {}-octet ICMPv6 message from {}: {}",
                    message.len(),
                    source,
                    e
                );
                return;
            }
        };

        console_debug!(
            ctx.status_tx,
            "NDP {} from {} ({} octets)",
            decoded.type_name(),
            source,
            message.len()
        );
        console_trace!(
            ctx.status_tx,
            "NDP {} from {}: {} option(s)",
            decoded.type_name(),
            source,
            decoded.options().len()
        );

        // Connectionless bookkeeping: one entry per peer heard from, which the 10-second idle
        // sweep reaps (metadata declares `.connectionless()`).
        let connection_id = ConnectionId::new(ctx.app_state.get_next_unified_id().await);
        {
            use crate::state::server::{
                ConnectionState as ServerConnectionState, ConnectionStatus, ProtocolConnectionInfo,
            };
            let now = crate::utils::clock::Instant::now();
            let nowhere: SocketAddr = "[::]:0".parse().expect("[::]:0 is a valid socket address");
            let conn = ServerConnectionState {
                id: connection_id,
                remote_addr: peer.unwrap_or(SocketAddr::V6(SocketAddrV6::new(source, 0, 0, 0))),
                local_addr: if local_addr.port() == 0 {
                    nowhere
                } else {
                    local_addr
                },
                bytes_sent: 0,
                bytes_received: message.len() as u64,
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

        let mut data = decoded.to_event_data();
        data.insert(
            "source_address".into(),
            serde_json::json!(source.to_string()),
        );
        if let Some(destination) = destination {
            data.insert(
                "destination_address".into(),
                serde_json::json!(destination.to_string()),
            );
        }
        data.insert(
            "connection_id".into(),
            serde_json::json!(connection_id.to_string()),
        );

        let event_type = match &decoded {
            NdpMessage::RouterSolicitation { .. } => &*NDP_ROUTER_SOLICITATION_EVENT,
            NdpMessage::RouterAdvertisement(_) => &*NDP_ROUTER_ADVERTISEMENT_RECEIVED_EVENT,
            NdpMessage::NeighborSolicitation { .. } => &*NDP_NEIGHBOR_SOLICITATION_EVENT,
            NdpMessage::NeighborAdvertisement { .. } => &*NDP_NEIGHBOR_ADVERTISEMENT_EVENT,
            NdpMessage::Redirect { .. } => &*NDP_REDIRECT_RECEIVED_EVENT,
        };

        let event = Event::new(event_type, serde_json::Value::Object(data));
        Self::dispatch_event(event, Some(connection_id), Some(source), ctx, sink).await;
    }

    /// Ask the operator's policy (handler, script or model) what to send, and send whatever it
    /// chooses — or nothing, which is a complete answer here.
    async fn dispatch_event(
        event: Event,
        connection_id: Option<ConnectionId>,
        peer_address: Option<Ipv6Addr>,
        ctx: Arc<NdpContext>,
        sink: MessageSink,
    ) {
        let event_id = event.event_type.id.clone();

        // Whether to answer is *policy*, and there is no answer derivable from the question — an
        // address is claimed, not computed. With no operator policy the spec-safe answer is to
        // observe and say nothing, and to do that WITHOUT an LLM round-trip per received packet;
        // on a busy link a raw ICMPv6 socket sees a great many. `arp`, `lldp` and `ospf` gate on
        // the same condition for the same reason.
        if !operator_wants_dynamic(&ctx.app_state, ctx.server_id, &event_id).await {
            debug!(
                "NDP {} decision=no_policy: no instruction and no handler, nothing sent and no \
                 LLM call",
                event_id
            );
            let _ = ctx.status_tx.send(format!(
                "NDP {} decision=no_policy: observing only (no instruction or handler)",
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
                // Failures on netget's side of the answer: an unbuildable request, an encoder
                // error, a failed transmit. Counted separately from `sent` so the decision tag
                // below can tell "the model said nothing" from "the model answered and we
                // could not deliver it".
                let mut netget_failures = 0usize;
                for protocol_result in &result.protocol_results {
                    let crate::llm::actions::protocol_trait::ActionResult::Custom { name, data } =
                        protocol_result
                    else {
                        continue;
                    };
                    if name != NDP_MESSAGE_RESULT {
                        continue;
                    }

                    let Some(action) = data.get("action") else {
                        warn!("NDP message result carried no action payload");
                        continue;
                    };

                    // Re-parsed here rather than carried as bytes because the *server* owns the
                    // addresses: the model names a message, not a packet.
                    let request = match codec::SendRequest::from_action(action) {
                        Ok(request) => request.with_default_link_layer(ctx.link_layer_address),
                        Err(e) => {
                            netget_failures += 1;
                            console_error!(ctx.status_tx, "NDP cannot build message: {:#}", e);
                            continue;
                        }
                    };

                    let source = request.source.unwrap_or(ctx.link_local_address);
                    let destination = request
                        .destination
                        .unwrap_or_else(|| request.default_destination(peer_address));

                    let bytes = match request.message.encode(source, destination) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            netget_failures += 1;
                            console_error!(ctx.status_tx, "NDP cannot encode message: {:#}", e);
                            continue;
                        }
                    };

                    match sink.send(source, destination, &bytes).await {
                        Ok(n) => {
                            sent += 1;
                            // Without this the rail's `up` counter for every NDP peer stays at
                            // zero for the life of the server, whatever it advertises.
                            if let Some(connection_id) = connection_id {
                                ctx.app_state
                                    .update_connection_stats(
                                        ctx.server_id,
                                        connection_id,
                                        None,
                                        Some(n as u64),
                                        None,
                                        Some(1),
                                    )
                                    .await;
                            }
                            console_debug!(
                                ctx.status_tx,
                                "NDP sent {} to {} ({} octets on the wire)",
                                request.message.type_name(),
                                destination,
                                n
                            );
                        }
                        Err(e) => {
                            netget_failures += 1;
                            console_error!(ctx.status_tx, "NDP transmit failed: {:#}", e);
                        }
                    }
                }

                if sent == 0 {
                    // Nothing went out. On the wire that is indistinguishable from a passive
                    // observer, so the tag is the only place the difference survives — which
                    // makes attributing it correctly the whole job.
                    //
                    // `model_silent` used to cover netget's own failures too: an unbuildable
                    // request, an encoder error or a failed transmit all left `sent` at 0 and
                    // were logged as the model having said nothing. It is the opposite — the
                    // model answered and netget could not deliver it — and an operator
                    // grepping `decision=fail_closed_` saw nothing at all. `src/server/rawip/`,
                    // written to the same rubric, gets this right by consulting its own
                    // failure counts; this now does the same.
                    let rejected = result.raw_actions.iter().any(|a| {
                        a.get("type").and_then(|t| t.as_str()) == Some(NO_RESPONSE_ACTION)
                    });
                    let decision = if rejected {
                        "model_reject"
                    } else if netget_failures > 0 {
                        "fail_closed_send_error"
                    } else if !result.failures.is_empty() {
                        "fail_closed_action_error"
                    } else {
                        "model_silent"
                    };
                    info!(
                        "NDP {} decision={}: nothing sent (NDP has no error message; silence is \
                         the protocol-correct answer)",
                        event_id, decision
                    );
                    let _ = ctx.status_tx.send(format!(
                        "NDP {} decision={}: nothing sent",
                        event_id, decision
                    ));
                }
            }
            Err(e) => {
                // Fail closed, and closed for NDP means silence. Every message this server can
                // emit writes something into the peer's stack — a neighbour cache entry, a
                // default route, a resolver list — and what to write is exactly what the failed
                // call was supposed to decide. Fabricating one is cache poisoning at best and a
                // full traffic redirect at worst, and it is strictly worse than the peer simply
                // not hearing from us, which its own retransmission already handles. Nothing
                // derived from `e` reaches the wire.
                let category = crate::utils::WireFailure::classify(&e);
                let decision = if category.is_overloaded() {
                    "fail_closed_overloaded"
                } else {
                    "fail_closed_llm_error"
                };
                error!(
                    "NDP {} decision={}: nothing sent, NDP has no failure message ({}): {}",
                    event_id,
                    decision,
                    category.text(),
                    e
                );
                let _ = ctx.status_tx.send(format!(
                    "✗ NDP {} decision={}: nothing sent ({}): {}",
                    event_id,
                    decision,
                    category.text(),
                    e
                ));
            }
        }
    }
}

/// The interface's index (its IPv6 scope id) and hardware address, where the platform will tell
/// us.
///
/// `pnet::datalink` reads both the same way on every OS it supports, which is why it is used here
/// rather than `if_nametoindex` plus a platform-specific MAC lookup.
fn interface_details(interface: &str) -> Option<(u32, Option<[u8; 6]>)> {
    pnet::datalink::interfaces()
        .into_iter()
        .find(|i| i.name == interface)
        .map(|i| {
            (
                i.index,
                i.mac.map(|mac| [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]),
            )
        })
}

/// True when the operator opted into dynamic behaviour: a non-empty server instruction, or an
/// event handler configured for this event. False means the static default applies — for NDP,
/// answer nothing, because with no configured policy there is no address we can honestly claim.
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

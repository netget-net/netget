//! GRE tunnel endpoint on IP protocol 47 (RFC 2784, with RFC 2890's key and sequence number):
//! decapsulates what other tunnel endpoints send through a raw socket, and the model plays the
//! hosts behind the tunnel — ARP (gretap), ping and UDP — with replies built in Rust and sent
//! back through the tunnel. Cisco-style keepalives are reflected without the model.
//! **Deliberately silent**: an IP with no host never answers, and a backend failure reads the
//! same way.
pub mod actions;
pub mod raw;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::connection::ConnectionId;
use crate::server::vxlan::frame::{self, Frame, Mac, Payload};
use crate::utils::gre;
use actions::{GreProtocol, PacketContext, Tunnel};
use anyhow::{Context, Result};
use raw::RawGre;
use serde_json::json;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use tokio::time::Instant;

#[derive(Clone)]
struct Config {
    default_mac: Mac,
    macs: Arc<Mutex<HashMap<Ipv4Addr, Mac>>>,
    /// The next sequence number for replies to peers that send them. Given as each reply
    /// leaves, under this lock, so concurrent answers cannot go out of order.
    sequence: Arc<Mutex<u32>>,
}

/// The local address a server binds: its host, which must be an IPv4 address of this machine.
pub fn local_address(host: Option<&str>) -> Result<Ipv4Addr> {
    match host.unwrap_or("127.0.0.1") {
        "localhost" => Ok(Ipv4Addr::LOCALHOST),
        h => h.parse().with_context(|| {
            format!("GRE binds an IPv4 address of this host, and {h:?} is not one")
        }),
    }
}

/// Packets a second, with a burst of one second's worth.
struct RateLimit {
    per_second: f64,
    tokens: f64,
    last: Instant,
    /// When the last "dropping" warning was logged, so a flood logs once a second.
    warned: Option<Instant>,
}

impl RateLimit {
    fn new(per_second: u64) -> Self {
        Self {
            per_second: per_second as f64,
            tokens: per_second as f64,
            last: Instant::now(),
            warned: None,
        }
    }
    fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.per_second).min(self.per_second);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
    fn should_warn(&mut self) -> bool {
        let now = Instant::now();
        if self
            .warned
            .is_some_and(|w| now.duration_since(w).as_secs() < 1)
        {
            return false;
        }
        self.warned = Some(now);
        true
    }
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let peers = actions::parse_peers(
        params
            .map(|p| p.get_optional_array("peers"))
            .transpose()?
            .flatten(),
    )?;
    let only_key = params
        .map(|p| p.get_optional_u64("key"))
        .transpose()?
        .flatten()
        .map(|k| u32::try_from(k).context("key is a 32-bit GRE key (0-4294967295)"))
        .transpose()?;
    let rate = params
        .map(|p| p.get_optional_u64("max_packets_per_second"))
        .transpose()?
        .flatten()
        .unwrap_or(actions::DEFAULT_MAX_PACKETS_PER_SECOND);
    anyhow::ensure!(
        (1..=actions::MAX_PACKETS_PER_SECOND_LIMIT).contains(&rate),
        "max_packets_per_second is 1-{}",
        actions::MAX_PACKETS_PER_SECOND_LIMIT
    );
    let default_mac = frame::parse_mac(
        &params
            .map(|p| p.get_optional_string("overlay_mac"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| frame::DEFAULT_MAC.into()),
    )?;
    let local = local_address(ctx.host.as_deref())?;
    let socket = Arc::new(RawGre::bind(local)?);
    let local_addr = socket.local_addr();
    Log::new(Some(&ctx.status_tx)).info(format!(
        "GRE endpoint on {local} (IP protocol 47){}{}, at most {rate} packets/s",
        only_key
            .map(|k| format!(", {} only", actions::key_str(Some(k))))
            .unwrap_or_default(),
        peers
            .as_ref()
            .map(|p| format!(
                ", for {}",
                p.iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .unwrap_or_default()
    ));
    let config = Config {
        default_mac,
        macs: Default::default(),
        sequence: Default::default(),
    };
    let state = ctx.state.clone();
    let server_id = ctx.server_id;
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; raw::MAX_IP_PACKET];
        let mut limit = RateLimit::new(rate);
        let in_flight = Arc::new(Semaphore::new(actions::MAX_IN_FLIGHT));
        loop {
            let r = match socket.recv(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    Log::new(Some(&ctx.status_tx)).error(format!("GRE receive error: {e}"));
                    break;
                }
            };
            let peer = r.src;
            if peers.as_ref().is_some_and(|p| !p.contains(&peer)) {
                tracing::debug!("GRE dropped a packet from {peer}: not one of the peers");
                continue;
            }
            let packet = &buf[r.start..r.end];
            let (header, payload) = match gre::decode(packet) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("GRE dropped a packet from {peer}: {e:#}");
                    continue;
                }
            };
            if only_key.is_some_and(|k| header.key != Some(k)) {
                tracing::debug!(
                    "GRE dropped a packet from {peer} with {}",
                    actions::key_str(header.key)
                );
                continue;
            }
            if payload.len() > actions::MAX_INNER_BYTES {
                tracing::warn!(
                    "GRE dropped a packet from {peer}: {} bytes of payload, more than {}",
                    payload.len(),
                    actions::MAX_INNER_BYTES
                );
                continue;
            }
            let classified = match header.protocol {
                gre::PROTO_TEB => frame::parse_frame(payload).map(|f| (Tunnel::Gretap, f)),
                gre::PROTO_IPV4 => {
                    if let Some((to, inner)) = keepalive(payload, peer, local) {
                        if !limit.take() {
                            rate_limited(&ctx, &mut limit, peer);
                            continue;
                        }
                        match socket.send_to(inner, to).await {
                            Ok(_) => tracing::debug!("GRE reflected a keepalive to {to}"),
                            Err(e) => tracing::warn!("GRE keepalive to {to} failed: {e}"),
                        }
                        continue;
                    }
                    frame::parse_ipv4_packet(payload).map(|f| (Tunnel::Gre, f))
                }
                other => {
                    tracing::debug!(
                        "GRE from {peer}: protocol type {other:#06x}, not gretap or IPv4"
                    );
                    continue;
                }
            };
            let (tunnel, frame) = match classified {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("GRE dropped a malformed packet from {peer}: {e:#}");
                    continue;
                }
            };
            let Some(event) = event_for(&frame, tunnel, header.key, peer) else {
                if let Payload::Other { what } = &frame.payload {
                    tracing::debug!("GRE from {peer}: {what}, not answered");
                }
                continue;
            };
            if !limit.take() {
                rate_limited(&ctx, &mut limit, peer);
                continue;
            }
            let Ok(permit) = in_flight.clone().try_acquire_owned() else {
                tracing::warn!(
                    "GRE dropped a packet from {peer}: {} answers already in flight",
                    actions::MAX_IN_FLIGHT
                );
                continue;
            };
            let id = ConnectionId::new(ctx.state.get_next_unified_id().await);
            record(&ctx, id, local_addr, peer, packet.len()).await;
            let (child, socket, config) = (ctx.clone(), socket.clone(), config.clone());
            let packet = PacketContext {
                tunnel,
                header,
                frame,
                default_mac: config.default_mac,
                macs: config.macs.clone(),
            };
            let handle = tokio::spawn(async move {
                answer(child, socket, config, packet, event, peer, id).await;
                drop(permit);
            });
            ctx.state.register_server_task(ctx.server_id, handle).await;
        }
    });
    state.register_server_task(server_id, task).await;
    Ok(local_addr)
}

fn rate_limited(ctx: &SpawnContext, limit: &mut RateLimit, peer: Ipv4Addr) {
    if limit.should_warn() {
        Log::new(Some(&ctx.status_tx)).warn(format!(
            "GRE dropping packets from {peer} and others: over {} packets/s decision=rate_limited",
            limit.per_second
        ));
    }
}

/// A Cisco-style keepalive: an IPv4 packet carrying GRE, from us back to the peer that sent
/// it. A tunnel endpoint answers by forwarding it, so the peer receives a GRE packet from us.
/// Only a packet addressed to the sending peer and from our own address is reflected, so the
/// endpoint cannot be used to send GRE anywhere else. Returns where to send it, and the GRE
/// packet to send (our kernel writes the IP header, from our address).
pub fn keepalive(inner: &[u8], peer: Ipv4Addr, local: Ipv4Addr) -> Option<(Ipv4Addr, &[u8])> {
    if inner.len() < 20 || inner[0] >> 4 != 4 || inner[9] != gre::IP_PROTOCOL {
        return None;
    }
    let ihl = usize::from(inner[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([inner[2], inner[3]]));
    if ihl < 20 || total < ihl || total > inner.len() || frame::checksum(&[&inner[..ihl]]) != 0 {
        return None;
    }
    let src = Ipv4Addr::new(inner[12], inner[13], inner[14], inner[15]);
    let dst = Ipv4Addr::new(inner[16], inner[17], inner[18], inner[19]);
    let reflected = &inner[ihl..total];
    (dst == peer && src == local && gre::decode(reflected).is_ok()).then_some((dst, reflected))
}

fn event_for(f: &Frame, tunnel: Tunnel, key: Option<u32>, peer: Ipv4Addr) -> Option<Event> {
    let mut data = json!({
        "tunnel": tunnel.name(),
        "key": key,
        "peer": peer.to_string(),
        "src_mac": (tunnel == Tunnel::Gretap).then(|| frame::mac_str(&f.src_mac)),
    });
    let ip = |a: Option<Ipv4Addr>| a.map(|a| a.to_string());
    let t = match &f.payload {
        Payload::Arp(arp) if arp.request => {
            data["sender_ip"] = json!(arp.sender_ip.to_string());
            data["target_ip"] = json!(arp.target_ip.to_string());
            &*actions::ARP_EVENT
        }
        Payload::Echo {
            request: true,
            identifier,
            sequence,
            data: payload,
        } => {
            let (text, encoding) = frame::data_json(payload);
            data["src_ip"] = json!(ip(f.src_ip));
            data["dst_ip"] = json!(ip(f.dst_ip));
            data["identifier"] = json!(identifier);
            data["sequence"] = json!(sequence);
            data["data"] = json!(text);
            data["encoding"] = json!(encoding);
            &*actions::ECHO_EVENT
        }
        Payload::Udp {
            src_port,
            dst_port,
            data: payload,
        } => {
            let (text, encoding) = frame::data_json(payload);
            data["src_ip"] = json!(ip(f.src_ip));
            data["src_port"] = json!(src_port);
            data["dst_ip"] = json!(ip(f.dst_ip));
            data["dst_port"] = json!(dst_port);
            data["data"] = json!(text);
            data["encoding"] = json!(encoding);
            &*actions::UDP_EVENT
        }
        _ => return None,
    };
    Some(Event::new(t, data))
}

async fn record(ctx: &SpawnContext, id: ConnectionId, local: SocketAddr, peer: Ipv4Addr, n: usize) {
    use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
    let now = crate::utils::clock::Instant::now();
    ctx.state
        .add_connection_to_server(
            ctx.server_id,
            ConnectionState {
                id,
                remote_addr: SocketAddr::new(peer.into(), 0),
                local_addr: local,
                bytes_sent: 0,
                bytes_received: n as u64,
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

async fn answer(
    ctx: SpawnContext,
    socket: Arc<RawGre>,
    config: Config,
    packet: PacketContext,
    event: Event,
    peer: Ipv4Addr,
    id: ConnectionId,
) {
    let summary = format!(
        "GRE {} {} from {peer} {}",
        packet.tunnel.name(),
        event.id(),
        actions::key_str(packet.header.key)
    );
    let protocol = GreProtocol::for_packet(packet);
    let log = Log::new(Some(&ctx.status_tx));
    let execution = match call_llm(
        &ctx.llm_client,
        &ctx.state,
        ctx.server_id,
        Some(id),
        &event,
        &protocol,
    )
    .await
    {
        Ok(e) => e,
        Err(e) => {
            log.error(format!(
                "{summary} decision=fail_closed_llm_error (nothing sent: no host answers): {e}"
            ));
            return;
        }
    };
    let mut sent = 0;
    for result in &execution.protocol_results {
        let items = match result {
            ActionResult::Multiple(all) => all.iter().collect::<Vec<_>>(),
            other => vec![other],
        };
        for item in items {
            if let ActionResult::Output(bytes) = item {
                match send(&socket, &config, bytes.clone(), peer).await {
                    Ok(n) => {
                        sent += 1;
                        ctx.state
                            .update_connection_stats(
                                ctx.server_id,
                                id,
                                None,
                                Some(n as u64),
                                None,
                                Some(1),
                            )
                            .await;
                    }
                    Err(e) => log.warn(format!("{summary}: sending to {peer} failed: {e}")),
                }
            }
        }
    }
    let decision = match (sent, execution.failures.is_empty()) {
        (0, true) => "model_silent",
        (0, false) => "fail_closed_action_error",
        _ => "model_answered",
    };
    log.info(format!("{summary} decision={decision}"));
}

/// Send one reply. A reply that carries a sequence number gets the next one as it leaves: the
/// number is written and the packet handed to the socket under one lock, which is never held
/// across an await (a full send buffer releases it, waits, and takes the next number).
async fn send(
    socket: &RawGre,
    config: &Config,
    mut packet: Vec<u8>,
    to: Ipv4Addr,
) -> std::io::Result<usize> {
    loop {
        {
            let mut next = config.sequence.lock().unwrap_or_else(|e| e.into_inner());
            let numbered = gre::stamp_sequence(&mut packet, *next);
            match socket.try_send_to(&packet, to) {
                Ok(n) => {
                    if numbered {
                        *next = next.wrapping_add(1);
                    }
                    return Ok(n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        socket.writable().await?;
    }
}

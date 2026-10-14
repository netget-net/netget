//! VXLAN / Geneve / GRE (gretap, in UDP) tunnel endpoint: decapsulates what other tunnel
//! endpoints send, and the model plays the hosts on the overlay — ARP, ping and UDP — with
//! replies built in Rust and sent back through the tunnel. **Deliberately silent**: an overlay
//! IP with no host never answers, and a backend failure reads the same way.
pub mod actions;
pub mod frame;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::connection::ConnectionId;
use actions::{FrameContext, VxlanProtocol};
use anyhow::{Context, Result};
use frame::{Encap, Frame, Header, Mac, Payload};
use serde_json::json;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;

#[derive(Clone)]
struct Config {
    encap: Encap,
    default_mac: Mac,
    macs: Arc<Mutex<HashMap<Ipv4Addr, Mac>>>,
    /// GRE: the next sequence number for replies to peers that send them. Given as each reply
    /// leaves, under this lock, so concurrent answers cannot go out of order.
    sequence: Arc<Mutex<u32>>,
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let encap = Encap::parse(
        &params
            .map(|p| p.get_optional_string("encapsulation"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| actions::DEFAULT_ENCAPSULATION.into()),
    )?;
    let only_vni = params
        .map(|p| p.get_optional_u64("vni"))
        .transpose()?
        .flatten();
    if let Some(v) = only_vni {
        anyhow::ensure!(
            v <= encap.max_vni() as u64,
            "vni must be at most {} for {}",
            encap.max_vni(),
            encap.name()
        );
    }
    let default_mac = frame::parse_mac(
        &params
            .map(|p| p.get_optional_string("overlay_mac"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| frame::DEFAULT_MAC.into()),
    )?;
    let port = ctx.port.unwrap_or_else(|| ctx.legacy_listen_addr().port());
    let host = ctx.host.clone().unwrap_or_else(|| "127.0.0.1".into());
    let bind = tokio::net::lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("cannot resolve host {host}"))?
        .next()
        .with_context(|| format!("host {host} resolved to no address"))?;
    let socket = Arc::new(
        UdpSocket::bind(bind)
            .await
            .with_context(|| format!("{} failed to bind {bind}", encap.name()))?,
    );
    let local = socket.local_addr()?;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "{} endpoint listening on {local}{}",
        encap.name().to_uppercase(),
        only_vni
            .map(|v| format!(", {} only", frame::vni_str(encap, Some(v as u32))))
            .unwrap_or_default()
    ));
    let config = Config {
        encap,
        default_mac,
        macs: Default::default(),
        sequence: Default::default(),
    };
    let state = ctx.state.clone();
    let server_id = ctx.server_id;
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        loop {
            let (n, from) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    Log::new(Some(&ctx.status_tx))
                        .error(format!("{} receive error: {e}", encap.name()));
                    break;
                }
            };
            let parsed = frame::decap(encap, &buf[..n])
                .and_then(|(header, inner)| Ok((header, frame::parse_frame(inner)?)));
            let (header, frame) = match parsed {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("{} dropped a datagram from {from}: {e:#}", encap.name());
                    continue;
                }
            };
            let vni = frame::vni_str(encap, header.vni);
            // A GRE frame with no key carries no VNI, so it is not on a filtered overlay.
            if only_vni.is_some_and(|v| header.vni.map(u64::from) != Some(v)) {
                tracing::debug!("{} dropped a frame for {vni} from {from}", encap.name());
                continue;
            }
            let Some(event) = event_for(&frame, header.vni, from) else {
                if let Payload::Other { what } = &frame.payload {
                    tracing::debug!("{} from {from} {vni}: {what}, not answered", encap.name());
                }
                continue;
            };
            let id = ConnectionId::new(ctx.state.get_next_unified_id().await);
            record(&ctx, id, local, from, n).await;
            let (child, socket, config) = (ctx.clone(), socket.clone(), config.clone());
            // Replies go to the sending VTEP at the tunnel port: VTEPs listen on the port
            // they send to, not on the source port they send from.
            let reply_to = SocketAddr::new(from.ip(), local.port());
            let handle = tokio::spawn(async move {
                answer(child, socket, config, header, frame, event, reply_to, id).await
            });
            ctx.state.register_server_task(ctx.server_id, handle).await;
        }
    });
    state.register_server_task(server_id, task).await;
    Ok(local)
}

fn event_for(f: &Frame, vni: Option<u32>, from: SocketAddr) -> Option<Event> {
    let mut data = json!({
        "vni": vni,
        "vtep": from.to_string(),
        "src_mac": frame::mac_str(&f.src_mac),
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

async fn record(
    ctx: &SpawnContext,
    id: ConnectionId,
    local: SocketAddr,
    from: SocketAddr,
    n: usize,
) {
    use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
    let now = crate::utils::clock::Instant::now();
    ctx.state
        .add_connection_to_server(
            ctx.server_id,
            ConnectionState {
                id,
                remote_addr: from,
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

#[allow(clippy::too_many_arguments)]
async fn answer(
    ctx: SpawnContext,
    socket: Arc<UdpSocket>,
    config: Config,
    header: Header,
    frame: Frame,
    event: Event,
    reply_to: SocketAddr,
    id: ConnectionId,
) {
    let summary = format!(
        "{} {} from {reply_to} {}",
        config.encap.name(),
        event.id(),
        frame::vni_str(config.encap, header.vni)
    );
    let protocol = VxlanProtocol::for_frame(FrameContext {
        encap: config.encap,
        header,
        frame,
        default_mac: config.default_mac,
        macs: config.macs.clone(),
    });
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
                match send(&socket, &config, bytes.clone(), reply_to).await {
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
                    Err(e) => log.warn(format!("{summary}: sending to {reply_to} failed: {e}")),
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

/// Send one reply. A GRE reply that carries a sequence number gets the next one as it leaves:
/// the number is written and the datagram handed to the socket under one lock, which is never
/// held across an await (a full send buffer releases it, waits, and takes the next number).
async fn send(
    socket: &UdpSocket,
    config: &Config,
    mut datagram: Vec<u8>,
    to: SocketAddr,
) -> std::io::Result<usize> {
    loop {
        {
            let mut next = config.sequence.lock().unwrap_or_else(|e| e.into_inner());
            let numbered = frame::stamp_sequence(config.encap, &mut datagram, *next);
            match socket.try_send_to(&datagram, to) {
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

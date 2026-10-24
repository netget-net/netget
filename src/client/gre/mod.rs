//! GRE client (IP protocol 47): one host behind a gre (IPv4) or gretap (Ethernet) tunnel to
//! one remote tunnel endpoint. ARP (gretap) and echo requests for its own IP are answered in
//! Rust, as any host's stack would; what the model asks for (resolve, ping, UDP, Ethernet
//! frames, keepalives) goes out through the tunnel, on gretap waiting on ARP when the MAC is
//! not yet known, and what comes back is reported as events.
pub mod actions;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::gre::actions::{key_str, Tunnel};
use crate::server::gre::raw::{self, RawGre};
use crate::server::vxlan::frame::{self, Mac, Payload};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
use crate::utils::gre;
pub use actions::GreClientProtocol;
use actions::Request;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// How long a send waits for ARP before it is reported unreachable (gretap).
pub const ARP_TIMEOUT: Duration = Duration::from_secs(2);
/// Sends waiting on ARP at once; the next is refused.
pub const MAX_PENDING: usize = 32;
/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// Pings and keepalives remembered for their round-trip time.
pub const MAX_OUTSTANDING: usize = 256;
pub const DEFAULT_SOURCE_PORT: u16 = 40000;
const TURNS: usize = 64;

struct Waiting {
    ip: Ipv4Addr,
    action: Value,
    depth: u32,
    deadline: Instant,
    command: Option<ClientCommand>,
}

struct Host {
    socket: RawGre,
    remote: Ipv4Addr,
    tunnel: Tunnel,
    /// What every packet is sent with: the key, and the checksum and sequence flags. Packets
    /// that come back must carry the same key (or, keyless, none).
    header: gre::Header,
    /// The next sequence number, when `header.sequence` is on.
    next_sequence: u32,
    ip: Ipv4Addr,
    mac: Mac,
    arp: HashMap<Ipv4Addr, Mac>,
    waiting: Vec<Waiting>,
    /// Pings sent: (identifier, sequence) → when.
    pings: HashMap<(u16, u16), Instant>,
    /// Keepalives sent and not yet reflected, oldest first.
    keepalives: VecDeque<Instant>,
    identifier: u16,
    sequence: u16,
    ip_id: u16,
    events: mpsc::Sender<(Event, u32)>,
    client: crate::state::ClientId,
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let get = |k: &str| -> Result<Option<String>> {
        Ok(params
            .map(|p| p.get_optional_string(k))
            .transpose()?
            .flatten())
    };
    let flag = |k: &str, default: bool| -> Result<bool> {
        Ok(params
            .map(|p| p.get_optional_bool(k))
            .transpose()?
            .flatten()
            .unwrap_or(default))
    };
    let tunnel = Tunnel::parse(&get("tunnel")?.unwrap_or_else(|| actions::DEFAULT_TUNNEL.into()))?;
    let ip: Ipv4Addr = get("overlay_ip")?
        .context("overlay_ip is required: this host's IPv4 address inside the tunnel")?
        .parse()
        .context("overlay_ip is an IPv4 address")?;
    let mac = frame::parse_mac(&get("overlay_mac")?.unwrap_or_else(|| frame::DEFAULT_MAC.into()))?;
    let key = params
        .map(|p| p.get_optional_u64("key"))
        .transpose()?
        .flatten()
        .map(|k| u32::try_from(k).context("key is a 32-bit GRE key (0-4294967295)"))
        .transpose()?;
    let header = gre::Header {
        protocol: tunnel.protocol(),
        key,
        checksum: flag("gre_checksum", actions::DEFAULT_GRE_CHECKSUM)?,
        sequence: flag("gre_sequence", actions::DEFAULT_GRE_SEQUENCE)?.then_some(0),
    };
    let remote = parse_remote(&ctx.remote_addr).await?;
    let local = match get("local_address")? {
        Some(raw) => raw
            .parse::<Ipv4Addr>()
            .with_context(|| format!("local_address {raw:?} is not an IPv4 address"))?,
        None => route_source(remote).await?,
    };
    let socket = RawGre::bind(local)?;
    let local_addr = socket.local_addr();
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "GRE client {} is {ip}{} behind a {} tunnel with {} from {local} to {remote}",
        ctx.client_id,
        (tunnel == Tunnel::Gretap)
            .then(|| format!(" ({})", frame::mac_str(&mac)))
            .unwrap_or_default(),
        tunnel.name(),
        key_str(key),
    ));
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURNS);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(64);
    let _ = event_tx.try_send((
        Event::new(
            &actions::READY_EVENT,
            json!({"overlay_ip": ip.to_string(),
                   "overlay_mac": (tunnel == Tunnel::Gretap).then(|| frame::mac_str(&mac)),
                   "remote": remote.to_string(), "local": local.to_string(),
                   "key": key, "tunnel": tunnel.name()}),
        ),
        0,
    ));
    let dispatcher = tokio::spawn(run_turns(ctx.clone(), event_rx, internal_tx));
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let mut host = Host {
        socket,
        remote,
        tunnel,
        header,
        next_sequence: 0,
        ip,
        mac,
        arp: HashMap::new(),
        waiting: vec![],
        pings: HashMap::new(),
        keepalives: VecDeque::new(),
        identifier: rand::random(),
        sequence: 0,
        ip_id: rand::random(),
        events: event_tx,
        client: ctx.client_id,
    };
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let result = host.run(&session_ctx, external, internal).await;
        dispatcher_abort.abort();
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx)).warn(format!("GRE client ended: {e:#}"));
                ClientStatus::Error(e.to_string())
            }
        };
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, status)
            .await;
        session_ctx
            .state
            .remove_client_handle(session_ctx.client_id)
            .await;
        let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    Ok(local_addr)
}

/// The remote endpoint: an IPv4 address or a name, with any port ignored (GRE has none).
async fn parse_remote(raw: &str) -> Result<Ipv4Addr> {
    let raw = raw.trim();
    anyhow::ensure!(
        !raw.is_empty(),
        "remote_addr is the remote tunnel endpoint's IPv4 address"
    );
    if let Ok(ip) = raw.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    if let Ok(SocketAddr::V4(a)) = raw.parse::<SocketAddr>() {
        return Ok(*a.ip());
    }
    let host = raw.rsplit_once(':').map_or(raw, |(h, _)| h);
    tokio::net::lookup_host((host, 0))
        .await
        .with_context(|| format!("cannot resolve {raw}"))?
        .find_map(|a| match a.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .with_context(|| format!("{raw} has no IPv4 address; GRE here is IPv4 only"))
}

async fn route_source(remote: Ipv4Addr) -> Result<Ipv4Addr> {
    let probe = UdpSocket::bind("0.0.0.0:0").await?;
    probe
        .connect((remote, 9))
        .await
        .with_context(|| format!("no route to {remote}"))?;
    match probe.local_addr()?.ip() {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(v6) => anyhow::bail!("the route to {remote} leaves from {v6}, not IPv4"),
    }
}

fn reply(command: Option<ClientCommand>, outcome: ClientSendOutcome) {
    if let Some(c) = command {
        crate::client::command_support::reply(c, Ok(outcome));
    }
}

impl Host {
    fn emit(&self, t: &'static EventType, data: Value, depth: u32) {
        if self.events.try_send((Event::new(t, data), depth)).is_err() {
            tracing::warn!("GRE client {} dropped an event: the model is {TURNS} behind decision=turn_queue_full", self.client);
        }
    }

    /// Every packet leaves from this one task, so numbering packets as they are built keeps
    /// the sequence in sending order.
    async fn send_gre(&mut self, protocol: u16, payload: &[u8]) -> Result<()> {
        let mut header = gre::Header {
            protocol,
            ..self.header
        };
        if header.sequence.is_some() {
            header.sequence = Some(self.next_sequence);
            self.next_sequence = self.next_sequence.wrapping_add(1);
        }
        self.socket
            .send_to(&gre::encode(&header, payload), self.remote)
            .await
            .with_context(|| format!("sending to {}", self.remote))?;
        Ok(())
    }

    async fn send_ip(
        &mut self,
        dst: Ipv4Addr,
        dst_mac: Mac,
        protocol: u8,
        payload: &[u8],
    ) -> Result<()> {
        self.ip_id = self.ip_id.wrapping_add(1);
        let packet = frame::ipv4(self.ip, dst, protocol, self.ip_id, payload);
        match self.tunnel {
            Tunnel::Gre => self.send_gre(gre::PROTO_IPV4, &packet).await,
            Tunnel::Gretap => {
                let f = frame::ethernet(dst_mac, self.mac, frame::ETHERTYPE_IPV4, &packet);
                self.send_gre(gre::PROTO_TEB, &f).await
            }
        }
    }

    async fn run(
        &mut self,
        ctx: &ConnectContext,
        mut external: mpsc::Receiver<ClientCommand>,
        mut internal: mpsc::Receiver<(Value, u32)>,
    ) -> Result<()> {
        let mut buf = vec![0u8; raw::MAX_IP_PACKET];
        loop {
            let deadline = self.waiting.iter().map(|w| w.deadline).min();
            let (action, depth, command) = tokio::select! {
                r = self.socket.recv(&mut buf) => {
                    let r = r.context("the raw GRE socket failed")?;
                    if r.src == self.remote {
                        let packet = buf[r.start..r.end].to_vec();
                        self.incoming(&packet).await;
                    }
                    continue;
                }
                _ = async {
                    match deadline {
                        Some(d) => tokio::time::sleep_until(d).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    self.expire();
                    continue;
                }
                c = external.recv() => match c {
                    Some(c) => {
                        ctx.state.record_access_log(AccessLogOwner::Client(ctx.client_id.as_u32()), "GRE", None,
                            "injected_action", c.action.clone(), vec![]).await;
                        (c.action.clone(), 0, Some(c))
                    }
                    None => return Ok(()),
                },
                a = internal.recv() => match a {
                    Some((a, d)) => (a, d, None),
                    None => return Ok(()),
                },
            };
            if let Ok(ClientActionResult::Disconnect) =
                GreClientProtocol.execute_action(action.clone())
            {
                reply(command, ClientSendOutcome::Disconnected);
                return Ok(());
            }
            let request = match actions::check(&action, Some(self.tunnel)) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("GRE client {} refused an action: {e}", self.client);
                    reply(
                        command,
                        ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        },
                    );
                    continue;
                }
            };
            // A gretap host needs the destination's MAC first; a gre tunnel has no link layer.
            let needs_arp = match (self.tunnel, request.ip()) {
                (Tunnel::Gretap, Some(ip)) => match self.arp.get(&ip) {
                    Some(_) => matches!(request, Request::Resolve(_)),
                    None => true,
                },
                _ => false,
            };
            if !needs_arp {
                let mac = request
                    .ip()
                    .and_then(|ip| self.arp.get(&ip).copied())
                    .unwrap_or_default();
                match self.perform(&request, mac).await {
                    Ok(detail) => reply(command, ClientSendOutcome::Executed { detail }),
                    Err(e) => {
                        tracing::warn!("GRE client {}: {e:#}", self.client);
                        reply(
                            command,
                            ClientSendOutcome::Rejected {
                                error: e.to_string(),
                            },
                        );
                    }
                }
                continue;
            }
            let ip = request.ip().unwrap_or(Ipv4Addr::UNSPECIFIED);
            if self.waiting.len() >= MAX_PENDING {
                reply(
                    command,
                    ClientSendOutcome::Rejected {
                        error: format!("{MAX_PENDING} sends are already waiting on ARP"),
                    },
                );
                continue;
            }
            if !self.waiting.iter().any(|w| w.ip == ip) {
                let arp = frame::arp_frame(true, self.mac, self.ip, [0; 6], ip);
                if let Err(e) = self.send_gre(gre::PROTO_TEB, &arp).await {
                    tracing::warn!("GRE client {}: {e:#}", self.client);
                }
            }
            self.waiting.push(Waiting {
                ip,
                action,
                depth,
                deadline: Instant::now() + ARP_TIMEOUT,
                command,
            });
        }
    }

    /// Send what a request asks for (on gretap, to a host whose MAC is known).
    async fn perform(&mut self, request: &Request, mac: Mac) -> Result<String> {
        match request {
            Request::Resolve(ip) => {
                Ok(json!({"ip": ip.to_string(), "mac": frame::mac_str(&mac)}).to_string())
            }
            Request::Ping { ip, data } => {
                self.sequence = self.sequence.wrapping_add(1);
                let icmp = frame::icmp_echo(true, self.identifier, self.sequence, data);
                self.pings
                    .insert((self.identifier, self.sequence), Instant::now());
                if self.pings.len() > MAX_OUTSTANDING {
                    let oldest = self.pings.iter().min_by_key(|(_, t)| **t).map(|(k, _)| *k);
                    if let Some(k) = oldest {
                        self.pings.remove(&k);
                    }
                }
                self.send_ip(*ip, mac, 1, &icmp).await?;
                Ok(json!({"sent": "echo request", "ip": ip.to_string(), "sequence": self.sequence}).to_string())
            }
            Request::Udp {
                ip,
                port,
                source_port,
                data,
            } => {
                let src_port = source_port.unwrap_or(DEFAULT_SOURCE_PORT);
                let udp = frame::udp(self.ip, *ip, src_port, *port, data);
                self.send_ip(*ip, mac, 17, &udp).await?;
                Ok(
                    json!({"sent": "udp", "ip": ip.to_string(), "port": port, "bytes": data.len()})
                        .to_string(),
                )
            }
            Request::Ethernet {
                dst_mac,
                ethertype,
                data,
            } => {
                let f = frame::ethernet(*dst_mac, self.mac, *ethertype, data);
                self.send_gre(gre::PROTO_TEB, &f).await?;
                Ok(
                    json!({"sent": "ethernet", "dst_mac": frame::mac_str(dst_mac),
                    "ethertype": ethertype, "bytes": data.len()})
                    .to_string(),
                )
            }
            Request::Keepalive => {
                // RFC 2784 has no keepalive; this is Cisco's: an IPv4 packet from the remote
                // endpoint back to us carrying a bare GRE header, sent through the tunnel. The
                // remote decapsulates it, routes it, and so sends us a GRE packet of its own.
                let inner_gre = gre::encode(
                    &gre::Header {
                        protocol: gre::PROTO_KEEPALIVE,
                        ..Default::default()
                    },
                    &[],
                );
                self.ip_id = self.ip_id.wrapping_add(1);
                let local = self.socket.local();
                let inner =
                    frame::ipv4(self.remote, local, gre::IP_PROTOCOL, self.ip_id, &inner_gre);
                self.send_gre(gre::PROTO_IPV4, &inner).await?;
                self.keepalives.push_back(Instant::now());
                if self.keepalives.len() > MAX_OUTSTANDING {
                    self.keepalives.pop_front();
                }
                Ok(json!({"sent": "keepalive", "to": self.remote.to_string()}).to_string())
            }
        }
    }

    fn expire(&mut self) {
        let now = Instant::now();
        let (due, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.waiting)
            .into_iter()
            .partition(|w| w.deadline <= now);
        self.waiting = keep;
        for w in due {
            let kind = w.action["type"].as_str().unwrap_or_default().to_string();
            reply(
                w.command,
                ClientSendOutcome::Rejected {
                    error: format!("no ARP reply for {} within {ARP_TIMEOUT:?}", w.ip),
                },
            );
            self.emit(
                &actions::UNREACHABLE_EVENT,
                json!({"ip": w.ip.to_string(), "action": kind}),
                w.depth,
            );
        }
    }

    async fn learned(&mut self, ip: Ipv4Addr, mac: Mac) {
        self.arp.insert(ip, mac);
        let (ready, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.waiting)
            .into_iter()
            .partition(|w| w.ip == ip);
        self.waiting = keep;
        for w in ready {
            if w.action["type"] == "gre_resolve" {
                reply(
                    w.command,
                    ClientSendOutcome::Executed {
                        detail: json!({"ip": ip.to_string(), "mac": frame::mac_str(&mac)})
                            .to_string(),
                    },
                );
                self.emit(
                    &actions::RESOLVED_EVENT,
                    json!({"ip": ip.to_string(), "mac": frame::mac_str(&mac)}),
                    w.depth,
                );
                continue;
            }
            let outcome = match actions::check(&w.action, Some(self.tunnel)) {
                Ok(request) => self.perform(&request, mac).await,
                Err(e) => Err(e),
            };
            match outcome {
                Ok(detail) => reply(w.command, ClientSendOutcome::Executed { detail }),
                Err(e) => reply(
                    w.command,
                    ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    },
                ),
            }
        }
    }

    async fn incoming(&mut self, packet: &[u8]) {
        let (header, payload) = match gre::decode(packet) {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!("GRE client {} dropped a packet: {e:#}", self.client);
                return;
            }
        };
        // A reflected keepalive is the bare GRE header we built: no key, nothing carried.
        if header.protocol == gre::PROTO_KEEPALIVE && payload.is_empty() {
            let rtt = self
                .keepalives
                .pop_front()
                .map(|t| (t.elapsed().as_secs_f64() * 1e6).round() / 1000.0);
            self.emit(&actions::KEEPALIVE_REPLY_EVENT, json!({"rtt_ms": rtt}), 0);
            return;
        }
        // Our key only; keyless when we have none. And our tunnel's payload.
        if header.key != self.header.key || header.protocol != self.tunnel.protocol() {
            return;
        }
        let parsed = match self.tunnel {
            Tunnel::Gretap => frame::parse_frame(payload),
            Tunnel::Gre => frame::parse_ipv4_packet(payload),
        };
        let f = match parsed {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!("GRE client {} dropped a packet: {e:#}", self.client);
                return;
            }
        };
        match f.payload {
            Payload::Arp(arp) => {
                if arp.request && arp.target_ip == self.ip {
                    let answer =
                        frame::arp_frame(false, self.mac, self.ip, arp.sender_mac, arp.sender_ip);
                    if let Err(e) = self.send_gre(gre::PROTO_TEB, &answer).await {
                        tracing::warn!("GRE client {}: {e:#}", self.client);
                    }
                }
                if arp.request
                    && arp.target_ip != self.ip
                    && !self.waiting.iter().any(|w| w.ip == arp.sender_ip)
                {
                    return; // someone else's question; nothing to learn that we asked for
                }
                self.learned(arp.sender_ip, arp.sender_mac).await;
            }
            Payload::Echo {
                request,
                identifier,
                sequence,
                data,
            } if f.dst_ip == Some(self.ip) => {
                let Some(src) = f.src_ip else { return };
                if request {
                    let icmp = frame::icmp_echo(false, identifier, sequence, &data);
                    if let Err(e) = self.send_ip(src, f.src_mac, 1, &icmp).await {
                        tracing::warn!("GRE client {}: {e:#}", self.client);
                    }
                    return;
                }
                let rtt = self
                    .pings
                    .remove(&(identifier, sequence))
                    .map(|t| t.elapsed().as_secs_f64() * 1000.0);
                let (text, encoding) = frame::data_json(&data);
                self.emit(&actions::ECHO_REPLY_EVENT, json!({"src_ip": src.to_string(), "identifier": identifier,
                    "sequence": sequence, "data": text, "encoding": encoding, "rtt_ms": rtt.map(|r| (r * 1000.0).round() / 1000.0)}), 0);
            }
            Payload::Udp {
                src_port,
                dst_port,
                data,
            } if f.dst_ip == Some(self.ip) => {
                let (text, encoding) = frame::data_json(&data);
                self.emit(
                    &actions::UDP_EVENT,
                    json!({"src_ip": f.src_ip.map(|i| i.to_string()), "src_port": src_port,
                    "dst_port": dst_port, "data": text, "encoding": encoding}),
                    0,
                );
            }
            Payload::IcmpError {
                kind,
                code,
                original_dst,
                original_dst_port,
                ..
            } if f.dst_ip == Some(self.ip) => {
                let meaning = match (kind, code) {
                    (3, 3) => "port_unreachable",
                    (3, 1) => "host_unreachable",
                    (3, 0) => "net_unreachable",
                    (3, 2) => "protocol_unreachable",
                    (3, _) => "destination_unreachable",
                    _ => "ttl_exceeded",
                };
                self.emit(&actions::ICMP_ERROR_EVENT, json!({"from": f.src_ip.map(|i| i.to_string()), "meaning": meaning,
                    "type": kind, "code": code, "original_dst": original_dst.to_string(), "original_dst_port": original_dst_port}), 0);
            }
            _ => {}
        }
    }
}

async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32)>,
    internal: mpsc::Sender<(Value, u32)>,
) {
    let protocol = GreClientProtocol;
    while let Some((event, depth)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            tracing::warn!("GRE client {} not asking the model about {}: {depth} turns deep decision=followup_depth", ctx.client_id, event.id());
            continue;
        }
        let instruction = ctx
            .state
            .get_instruction_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        let memory = ctx
            .state
            .get_memory_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        match call_llm_for_client(
            &ctx.llm_client,
            &ctx.state,
            ctx.client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            &protocol,
            &ctx.status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(memory) = result.memory_updates {
                    ctx.state.set_memory_for_client(ctx.client_id, memory).await;
                }
                for action in result.actions {
                    if internal.send((action, depth + 1)).await.is_err() {
                        return;
                    }
                }
            }
            Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!("GRE client handler: {e}")),
        }
    }
}

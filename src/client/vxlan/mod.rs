//! VXLAN / Geneve / GRE (gretap, in UDP) client: one host on the overlay, behind a tunnel to
//! one remote tunnel endpoint. ARP and echo requests for its own IP are answered in Rust, as
//! any host's stack would; what the model asks for (resolve, ping, UDP) waits on ARP when the
//! MAC is not yet known, and what comes back is reported as events.
pub mod actions;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::vxlan::frame::{self, Encap, Header, Mac, Payload};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::VxlanClientProtocol;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// How long a send waits for ARP before it is reported unreachable.
pub const ARP_TIMEOUT: Duration = Duration::from_secs(2);
/// Sends waiting on ARP at once; the next is refused.
pub const MAX_PENDING: usize = 32;
/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
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
    socket: UdpSocket,
    remote: SocketAddr,
    encap: Encap,
    /// What every frame is sent with: the VNI or GRE key, and the GRE checksum and sequence
    /// flags. Frames that come back must carry the same VNI or key (or, keyless, none).
    header: Header,
    /// The next GRE sequence number, when `header.sequence` is on.
    next_sequence: u32,
    ip: Ipv4Addr,
    mac: Mac,
    arp: HashMap<Ipv4Addr, Mac>,
    waiting: Vec<Waiting>,
    /// Pings sent: (identifier, sequence) → when.
    pings: HashMap<(u16, u16), Instant>,
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
    let encap = Encap::parse(
        &get("encapsulation")?
            .unwrap_or_else(|| crate::server::vxlan::actions::DEFAULT_ENCAPSULATION.into()),
    )?;
    let ip: Ipv4Addr = get("overlay_ip")?
        .context("overlay_ip is required: this host's IPv4 address on the overlay")?
        .parse()
        .context("overlay_ip is an IPv4 address")?;
    let mac = frame::parse_mac(&get("overlay_mac")?.unwrap_or_else(|| frame::DEFAULT_MAC.into()))?;
    let vni = params
        .map(|p| p.get_optional_u64("vni"))
        .transpose()?
        .flatten();
    if let Some(v) = vni {
        anyhow::ensure!(
            v <= encap.max_vni() as u64,
            "vni must be at most {} for {}",
            encap.max_vni(),
            encap.name()
        );
    }
    let flag = |k: &str, default: bool| -> Result<bool> {
        let on = params
            .map(|p| p.get_optional_bool(k))
            .transpose()?
            .flatten()
            .unwrap_or(default);
        anyhow::ensure!(
            !on || encap == Encap::Gretap,
            "{k} applies to encapsulation gretap only, not {}",
            encap.name()
        );
        Ok(on)
    };
    let header = Header {
        // GRE without a vni is GRE without a key; VXLAN and Geneve always carry a VNI.
        vni: match encap {
            Encap::Gretap => vni.map(|v| v as u32),
            _ => Some(vni.map_or(actions::DEFAULT_VNI, |v| v as u32)),
        },
        checksum: flag("gre_checksum", actions::DEFAULT_GRE_CHECKSUM)?,
        sequence: flag("gre_sequence", actions::DEFAULT_GRE_SEQUENCE)?.then_some(0),
    };
    let vni_text = frame::vni_str(encap, header.vni);
    let remote = parse_remote(&ctx.remote_addr, encap).await?;
    let local_ip = match get("local_address")? {
        Some(raw) => raw
            .parse::<IpAddr>()
            .with_context(|| format!("local_address {raw:?} is not an IP"))?,
        None => route_source(remote).await?,
    };
    // The remote VTEP sends to our address at the tunnel port.
    let socket = UdpSocket::bind(SocketAddr::new(local_ip, remote.port()))
        .await
        .with_context(|| format!("cannot listen on {local_ip}:{}", remote.port()))?;
    let local = socket.local_addr()?;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "{} client {} is {ip} ({}) on {vni_text} via {remote}, from {local}",
        encap.name().to_uppercase(),
        ctx.client_id,
        frame::mac_str(&mac)
    ));
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURNS);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(64);
    let _ = event_tx.try_send((
        Event::new(
            &actions::READY_EVENT,
            json!({"overlay_ip": ip.to_string(), "overlay_mac": frame::mac_str(&mac), "remote_vtep": remote.to_string(),
                   "vni": header.vni, "encapsulation": encap.name()}),
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
        encap,
        header,
        next_sequence: 0,
        ip,
        mac,
        arp: HashMap::new(),
        waiting: vec![],
        pings: HashMap::new(),
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
                Log::new(Some(&session_ctx.status_tx)).warn(format!("VXLAN client ended: {e:#}"));
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
    Ok(local)
}

async fn parse_remote(raw: &str, encap: Encap) -> Result<SocketAddr> {
    let raw = raw.trim();
    anyhow::ensure!(!raw.is_empty(), "remote_addr is the remote tunnel endpoint");
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, encap.port()));
    }
    tokio::net::lookup_host(raw)
        .await
        .with_context(|| format!("cannot resolve {raw}"))?
        .next()
        .with_context(|| format!("{raw} resolved to no address"))
}

async fn route_source(remote: SocketAddr) -> Result<IpAddr> {
    let probe = UdpSocket::bind(if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    probe
        .connect(remote)
        .await
        .with_context(|| format!("no route to {remote}"))?;
    Ok(probe.local_addr()?.ip())
}

fn reply(command: Option<ClientCommand>, outcome: ClientSendOutcome) {
    if let Some(c) = command {
        crate::client::command_support::reply(c, Ok(outcome));
    }
}

impl Host {
    fn emit(&self, t: &'static EventType, data: Value, depth: u32) {
        if self.events.try_send((Event::new(t, data), depth)).is_err() {
            tracing::warn!("VXLAN client {} dropped an event: the model is {TURNS} behind decision=turn_queue_full", self.client);
        }
    }

    /// Every frame leaves from this one task, so numbering GRE frames as they are built keeps
    /// the sequence in sending order.
    async fn send_frame(&mut self, inner: Vec<u8>) -> Result<()> {
        let mut header = self.header;
        if header.sequence.is_some() {
            header.sequence = Some(self.next_sequence);
            self.next_sequence = self.next_sequence.wrapping_add(1);
        }
        self.socket
            .send_to(&frame::encap(self.encap, &header, &inner), self.remote)
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
        self.send_frame(frame::ethernet(
            dst_mac,
            self.mac,
            frame::ETHERTYPE_IPV4,
            &packet,
        ))
        .await
    }

    async fn run(
        &mut self,
        ctx: &ConnectContext,
        mut external: mpsc::Receiver<ClientCommand>,
        mut internal: mpsc::Receiver<(Value, u32)>,
    ) -> Result<()> {
        let mut buf = vec![0u8; 65_536];
        loop {
            let deadline = self.waiting.iter().map(|w| w.deadline).min();
            let (action, depth, command) = tokio::select! {
                r = self.socket.recv_from(&mut buf) => {
                    let (n, from) = r.context("the tunnel socket failed")?;
                    if from.ip() == self.remote.ip() {
                        let datagram = buf[..n].to_vec();
                        self.incoming(&datagram).await;
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
                        ctx.state.record_access_log(AccessLogOwner::Client(ctx.client_id.as_u32()), "VXLAN", None,
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
            match VxlanClientProtocol.execute_action(action.clone()) {
                Ok(ClientActionResult::Disconnect) => {
                    reply(command, ClientSendOutcome::Disconnected);
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("VXLAN client {} refused an action: {e}", self.client);
                    reply(
                        command,
                        ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        },
                    );
                    continue;
                }
            }
            let ip = actions::ip_of(&action)?;
            match self.arp.get(&ip).copied() {
                Some(mac) if action["type"] != "vxlan_resolve" => {
                    match self.perform(&action, mac).await {
                        Ok(detail) => reply(command, ClientSendOutcome::Executed { detail }),
                        Err(e) => {
                            tracing::warn!("VXLAN client {}: {e:#}", self.client);
                            reply(
                                command,
                                ClientSendOutcome::Rejected {
                                    error: e.to_string(),
                                },
                            );
                        }
                    }
                }
                _ => {
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
                        if let Err(e) = self
                            .send_frame(frame::arp_frame(true, self.mac, self.ip, [0; 6], ip))
                            .await
                        {
                            tracing::warn!("VXLAN client {}: {e:#}", self.client);
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
        }
    }

    /// Send what `action` asks for to a host whose MAC is known.
    async fn perform(&mut self, action: &Value, mac: Mac) -> Result<String> {
        let (ip, port, source) = actions::check(action)?;
        match action["type"].as_str().unwrap_or_default() {
            "vxlan_ping" => {
                self.sequence = self.sequence.wrapping_add(1);
                let data = action["data"]
                    .as_str()
                    .unwrap_or("netget")
                    .as_bytes()
                    .to_vec();
                let icmp = frame::icmp_echo(true, self.identifier, self.sequence, &data);
                self.pings
                    .insert((self.identifier, self.sequence), Instant::now());
                if self.pings.len() > 256 {
                    let oldest = self.pings.iter().min_by_key(|(_, t)| **t).map(|(k, _)| *k);
                    if let Some(k) = oldest {
                        self.pings.remove(&k);
                    }
                }
                self.send_ip(ip, mac, 1, &icmp).await?;
                Ok(json!({"sent": "echo request", "ip": ip.to_string(), "sequence": self.sequence}).to_string())
            }
            "vxlan_send_udp" => {
                let data = frame::data_bytes(action)?;
                let src_port = source.unwrap_or(DEFAULT_SOURCE_PORT);
                let udp = frame::udp(self.ip, ip, src_port, port.unwrap_or_default(), &data);
                self.send_ip(ip, mac, 17, &udp).await?;
                Ok(
                    json!({"sent": "udp", "ip": ip.to_string(), "port": port, "bytes": data.len()})
                        .to_string(),
                )
            }
            _ => Ok(json!({"ip": ip.to_string(), "mac": frame::mac_str(&mac)}).to_string()),
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
            if w.action["type"] == "vxlan_resolve" {
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
            match self.perform(&w.action, mac).await {
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

    async fn incoming(&mut self, datagram: &[u8]) {
        let parsed = frame::decap(self.encap, datagram)
            .and_then(|(header, inner)| Ok((header, frame::parse_frame(inner)?)));
        let (header, f) = match parsed {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("VXLAN client {} dropped a datagram: {e:#}", self.client);
                return;
            }
        };
        // Our VNI or GRE key only; keyless GRE when we have no key.
        if header.vni != self.header.vni {
            return;
        }
        match f.payload {
            Payload::Arp(arp) => {
                if arp.request && arp.target_ip == self.ip {
                    let answer =
                        frame::arp_frame(false, self.mac, self.ip, arp.sender_mac, arp.sender_ip);
                    if let Err(e) = self.send_frame(answer).await {
                        tracing::warn!("VXLAN client {}: {e:#}", self.client);
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
                        tracing::warn!("VXLAN client {}: {e:#}", self.client);
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
    let protocol = VxlanClientProtocol;
    while let Some((event, depth)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            tracing::warn!("VXLAN client {} not asking the model about {}: {depth} turns deep decision=followup_depth", ctx.client_id, event.id());
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
            Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!("VXLAN client handler: {e}")),
        }
    }
}

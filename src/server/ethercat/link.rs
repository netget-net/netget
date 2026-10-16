//! The two ways EtherCAT frames move, both defined by ETG.1000.4:
//!
//! * **`raw`** — Ethernet frames with EtherType 0x88A4 on a named interface, through the
//!   packet socket PROFINET also uses (`server::profinet::l2::open_packet_socket`: `AF_PACKET`
//!   on Linux, BPF on macOS; needs CAP_NET_RAW or BPF access).
//! * **`udp`** — EtherCAT-in-UDP: the EtherCAT payload (frame header and datagrams) as one UDP
//!   datagram to port 0x88A4 (34980). This is a real encapsulation an ESC processes and tshark
//!   dissects, not a lab invention, and it needs no privilege, which is why every macOS test
//!   uses it.
//!
//! A packet socket on macOS (BPF) hands back the frames it sent. Neither role may take its own
//! transmission for a peer's — a slave would process its own reply as a new request, a master
//! would read its request back as an answer that no slave touched — so every frame sent is
//! remembered for a second and an identical one received in that time is dropped. Linux does
//! not loop a packet socket's own frames back, so there this never fires.
use super::frame;
use crate::server::profinet::l2;
use crate::server::profinet::rt::EthFrame;
use anyhow::{anyhow, Context, Result};
use std::collections::hash_map::DefaultHasher;
use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

type Instant = crate::utils::clock::Instant;

pub const TRANSPORT_RAW: &str = "raw";
pub const TRANSPORT_UDP: &str = "udp";
/// The largest UDP datagram read (an EtherCAT payload is at most 1500 octets).
pub const MAX_UDP: usize = 1600;
const ECHO_MEMORY: usize = 64;
const ECHO_WINDOW: Duration = Duration::from_secs(1);

/// Frames this end sent recently, by content.
#[derive(Default)]
pub struct Echoes(Mutex<VecDeque<(u64, Instant)>>);

fn digest(b: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    b.hash(&mut h);
    h.finish()
}

impl Echoes {
    fn remember(&self, frame: &[u8]) {
        let mut q = self.0.lock().expect("ethercat echo memory");
        if q.len() >= ECHO_MEMORY {
            q.pop_front();
        }
        q.push_back((digest(frame), Instant::now()));
    }
    /// True (and forgotten) when `frame` is one of ours.
    fn is_echo(&self, frame: &[u8]) -> bool {
        let d = digest(frame);
        let now = Instant::now();
        let mut q = self.0.lock().expect("ethercat echo memory");
        q.retain(|(_, at)| now.duration_since(*at) < ECHO_WINDOW);
        if let Some(p) = q.iter().position(|(h, _)| *h == d) {
            q.remove(p);
            return true;
        }
        false
    }
}

/// Who sent a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Peer {
    Mac([u8; 6]),
    Udp(SocketAddr),
}

impl std::fmt::Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Peer::Mac(m) => write!(f, "{}", crate::server::profinet::dcp::format_mac(m)),
            Peer::Udp(a) => write!(f, "{a}"),
        }
    }
}

/// A received frame: its EtherCAT payload and how to send a reply back the way it came.
pub struct Received {
    pub payload: Vec<u8>,
    pub from: Peer,
    /// The Ethernet frame it arrived in (raw transport).
    pub eth: Option<EthFrame>,
}

pub enum Link {
    Raw {
        l2: l2::L2Link,
        echoes: Arc<Echoes>,
    },
    Udp {
        socket: Arc<UdpSocket>,
        /// Where a master sends (None on a slave, which answers whoever asked).
        remote: Option<SocketAddr>,
    },
}

/// A clonable sender for either transport.
#[derive(Clone)]
pub enum LinkTx {
    Raw {
        tx: l2::L2Tx,
        mac: [u8; 6],
        echoes: Arc<Echoes>,
    },
    Udp {
        socket: Arc<UdpSocket>,
        remote: Option<SocketAddr>,
    },
}

impl Link {
    pub fn open_raw(interface: &str) -> Result<Self> {
        let echoes = Arc::new(Echoes::default());
        let filter = echoes.clone();
        let l2 = l2::open_packet_socket(interface, "EtherCAT", move |raw, _own| {
            frame::ethernet_payload_offset(raw)?;
            if filter.is_echo(raw) {
                return None;
            }
            crate::server::profinet::rt::parse_eth(raw).filter(|f| f.ethertype == frame::ETHERTYPE)
        })?;
        Ok(Link::Raw { l2, echoes })
    }

    pub async fn open_udp(bind: SocketAddr, remote: Option<SocketAddr>) -> Result<Self> {
        let socket = UdpSocket::bind(bind)
            .await
            .with_context(|| format!("binding EtherCAT-in-UDP on {bind}"))?;
        Ok(Link::Udp {
            socket: Arc::new(socket),
            remote,
        })
    }

    pub fn mac(&self) -> Option<[u8; 6]> {
        match self {
            Link::Raw { l2, .. } => Some(l2.mac),
            Link::Udp { .. } => None,
        }
    }

    /// Why a raw link stopped receiving, when it did.
    pub fn last_error(&self) -> Option<String> {
        match self {
            Link::Raw { l2, .. } => l2.last_error.lock().ok().and_then(|e| e.clone()),
            Link::Udp { .. } => None,
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            Link::Raw { .. } => None,
            Link::Udp { socket, .. } => socket.local_addr().ok(),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Link::Raw { l2, .. } => l2.description.clone(),
            Link::Udp { socket, .. } => format!(
                "EtherCAT-in-UDP {}",
                socket
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_default()
            ),
        }
    }

    pub fn sender(&self) -> LinkTx {
        match self {
            Link::Raw { l2, echoes } => LinkTx::Raw {
                tx: l2.tx.clone(),
                mac: l2.mac,
                echoes: echoes.clone(),
            },
            Link::Udp { socket, remote } => LinkTx::Udp {
                socket: socket.clone(),
                remote: *remote,
            },
        }
    }

    /// The next frame. `None` when the link has closed.
    pub async fn recv(&mut self, buf: &mut [u8]) -> Option<Received> {
        match self {
            Link::Raw { l2, .. } => {
                let f = l2.rx.recv().await?;
                Some(Received {
                    payload: f.payload.clone(),
                    from: Peer::Mac(f.src),
                    eth: Some(f),
                })
            }
            Link::Udp { socket, .. } => loop {
                match socket.recv_from(buf).await {
                    Ok((n, from)) => {
                        if n > frame::MAX_PAYLOAD + frame::HEADER_LEN {
                            continue;
                        }
                        return Some(Received {
                            payload: buf[..n].to_vec(),
                            from: Peer::Udp(from),
                            eth: None,
                        });
                    }
                    Err(e) => {
                        tracing::debug!("EtherCAT-in-UDP receive error: {e}");
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
            },
        }
    }
}

impl LinkTx {
    /// Send a processed frame back the way `rx` came (a slave's reply). On Ethernet the source
    /// address gets the locally administered bit, as an ESC sets it.
    pub async fn reply(&self, rx: &Received, payload: &[u8]) -> Result<()> {
        match (self, &rx.eth, rx.from) {
            (LinkTx::Raw { tx, echoes, .. }, Some(eth), _) => {
                let mut f = Vec::with_capacity(18 + payload.len());
                f.extend_from_slice(&eth.dst);
                f.extend_from_slice(&frame::processed_source(eth.src));
                if let Some(tci) = eth.vlan_tci {
                    f.extend_from_slice(&0x8100u16.to_be_bytes());
                    f.extend_from_slice(&tci.to_be_bytes());
                }
                f.extend_from_slice(&frame::ETHERTYPE.to_be_bytes());
                f.extend_from_slice(payload);
                echoes.remember(&f);
                tx.send(f)
            }
            (LinkTx::Udp { socket, .. }, None, Peer::Udp(to)) => {
                socket
                    .send_to(payload, to)
                    .await
                    .with_context(|| format!("EtherCAT-in-UDP reply to {to}"))?;
                Ok(())
            }
            _ => Err(anyhow!(
                "a reply must go back on the transport it came in on"
            )),
        }
    }

    /// Send a master's frame (an EtherCAT payload) onto the segment.
    pub async fn send(&self, payload: &[u8]) -> Result<()> {
        match self {
            LinkTx::Raw { tx, mac, echoes } => {
                let f = frame::ethernet([0xFF; 6], *mac, payload);
                echoes.remember(&f);
                tx.send(f)
            }
            LinkTx::Udp { socket, remote } => {
                let to = remote.ok_or_else(|| anyhow!("EtherCAT-in-UDP has no remote"))?;
                socket
                    .send_to(payload, to)
                    .await
                    .with_context(|| format!("EtherCAT-in-UDP send to {to}"))?;
                Ok(())
            }
        }
    }
}

/// Received frames through a bounded queue, for a master that reads from its own task: the
/// receiver, the sender, and the reading loop for the caller to spawn (and own).
pub fn reader(
    mut link: Link,
) -> (
    mpsc::Receiver<Received>,
    LinkTx,
    impl std::future::Future<Output = ()> + Send,
) {
    let tx = link.sender();
    let (out, rx) = mpsc::channel(256);
    let pump = async move {
        let mut buf = vec![0u8; MAX_UDP];
        while let Some(r) = link.recv(&mut buf).await {
            if out.send(r).await.is_err() {
                break;
            }
        }
    };
    (rx, tx, pump)
}

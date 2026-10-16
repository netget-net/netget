//! The two ways PROFINET's layer-2 traffic (DCP and the cyclic RT frames) moves.
//!
//! * **`raw`** — real Ethernet on a named interface through `pnet`'s datalink channel:
//!   `AF_PACKET` on Linux, BPF on macOS/BSD. Needs `CAP_NET_RAW` (or root, or `/dev/bpf*`
//!   access), which is why the protocol declares `PacketCapture`. Only frames with EtherType
//!   `0x8892` (after any 802.1Q tags) reach the protocol, and frames this host sent are
//!   dropped on receive — a packet socket sees its own transmissions.
//! * **`udp`** — a lab transport: each complete Ethernet frame is one UDP datagram to a peer.
//!   No real PROFINET node speaks it; it exists so the whole DCP → model → Connect → cyclic
//!   path runs unprivileged between two NetGet instances, and it is labelled as such
//!   everywhere it appears. PNIO-CM's RPC is real UDP in both transports.
//!
//! Received frames go through a bounded channel; when the protocol falls behind, frames are
//! dropped and counted rather than queued without limit. A cyclic frame is superseded by the
//! next one anyway.
use super::rt::{parse_eth, EthFrame, MAX_FRAME_LEN};
use anyhow::{anyhow, Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// The `transport` startup parameter: real Ethernet (the default) or the lab transport.
pub const TRANSPORT_RAW: &str = "raw";
pub const TRANSPORT_LAB: &str = "udp";

/// Received PROFINET frames waiting for the protocol.
pub const RX_QUEUE: usize = 1024;

/// Sets its flag when dropped; the blocking threads of a raw link poll it.
pub struct StopGuard(Arc<AtomicBool>);

impl Drop for StopGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Aborts the lab link's reader task when the link is dropped.
struct AbortOnDrop(Option<tokio::task::JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
        }
    }
}

#[derive(Clone)]
enum TxInner {
    #[cfg(unix)]
    Raw(std::sync::mpsc::SyncSender<Vec<u8>>),
    Udp {
        /// Sends go through the plain socket: a tokio `try_send_to` on a socket the reactor
        /// has not yet polled reports WouldBlock, which silently lost a controller's first
        /// Identify. A UDP send on a non-blocking socket does not block in practice.
        socket: Arc<std::net::UdpSocket>,
        configured_peer: Option<SocketAddr>,
        last_peer: Arc<Mutex<Option<SocketAddr>>>,
    },
}

/// The sending half of a link. Cheap to clone; never blocks.
#[derive(Clone)]
pub struct L2Tx {
    inner: TxInner,
    pub sent: Arc<AtomicU64>,
}

impl L2Tx {
    /// Queue one complete Ethernet frame. Fails rather than blocks when the link is busy.
    pub fn send(&self, frame: Vec<u8>) -> Result<()> {
        match &self.inner {
            #[cfg(unix)]
            TxInner::Raw(tx) => tx
                .try_send(frame)
                .map_err(|e| anyhow!("raw link transmit queue: {e}"))?,
            TxInner::Udp {
                socket,
                configured_peer,
                last_peer,
            } => {
                let peer = match configured_peer {
                    Some(p) => *p,
                    None => last_peer
                        .lock()
                        .expect("profinet lab peer mutex")
                        .ok_or_else(|| {
                            anyhow!(
                                "lab link has no peer yet: nothing received and no lab peer \
                                 configured"
                            )
                        })?,
                };
                socket
                    .send_to(&frame, peer)
                    .with_context(|| format!("lab link send to {peer}"))?;
            }
        }
        self.sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// An open link: our MAC, the transmit half, the receive queue, and what keeps it alive.
pub struct L2Link {
    pub mac: [u8; 6],
    /// The interface's IPv4 address and mask, when the link is a real interface that has one.
    pub ipv4: Option<(Ipv4Addr, Ipv4Addr)>,
    pub tx: L2Tx,
    pub rx: mpsc::Receiver<EthFrame>,
    pub dropped: Arc<AtomicU64>,
    /// "raw eth0" or "lab udp 127.0.0.1:40000".
    pub description: String,
    /// The lab socket's own address (lab transport only).
    pub lab_addr: Option<SocketAddr>,
    _stop: StopGuard,
    _reader: AbortOnDrop,
}

fn accept(frame: &[u8], own: &[u8; 6]) -> Option<EthFrame> {
    let f = parse_eth(frame)?;
    (f.ethertype == super::dcp::ETHERTYPE_PROFINET && f.src != *own).then_some(f)
}

/// The lab transport: frames as UDP datagrams. `peer` fixes the destination; without it the
/// link answers whoever spoke last.
pub async fn open_udp(bind: SocketAddr, peer: Option<SocketAddr>, mac: [u8; 6]) -> Result<L2Link> {
    let std_socket = std::net::UdpSocket::bind(bind)
        .with_context(|| format!("binding the PROFINET lab link on {bind}"))?;
    std_socket.set_nonblocking(true)?;
    let socket = Arc::new(std_socket.try_clone()?);
    let reader = UdpSocket::from_std(std_socket)?;
    let local = socket.local_addr()?;
    let last_peer = Arc::new(Mutex::new(None));
    let (tx, rx) = mpsc::channel(RX_QUEUE);
    let dropped = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let peer_slot = last_peer.clone();
    let drops = dropped.clone();
    let stop_flag = stop.clone();
    // Ends when the receive queue's owner drops it, and is aborted with the link.
    let reader_task = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_FRAME_LEN + 1];
        while !stop_flag.load(Ordering::SeqCst) {
            let Ok((n, from)) = reader.recv_from(&mut buf).await else {
                break;
            };
            if n > MAX_FRAME_LEN {
                drops.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let Some(frame) = accept(&buf[..n], &mac) else {
                continue;
            };
            *peer_slot.lock().expect("profinet lab peer mutex") = Some(from);
            match tx.try_send(frame) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    drops.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => break,
            }
        }
    });
    Ok(L2Link {
        mac,
        ipv4: None,
        tx: L2Tx {
            inner: TxInner::Udp {
                socket,
                configured_peer: peer,
                last_peer,
            },
            sent: Arc::new(AtomicU64::new(0)),
        },
        rx,
        dropped,
        description: format!("lab udp {local}"),
        lab_addr: Some(local),
        _stop: StopGuard(stop),
        _reader: AbortOnDrop(Some(reader_task)),
    })
}

/// Real Ethernet on `interface`.
pub fn open_raw(interface: &str) -> Result<L2Link> {
    open_packet_socket(interface, "PROFINET", accept)
}

/// A packet socket on `interface` whose receive side keeps only the frames `keep` returns,
/// given the raw frame and the interface's own MAC. Shared with EtherCAT, which filters on its
/// own EtherType and cannot drop frames by source MAC (an ESC hands the master's frame back
/// with the master's address in it). `label` names the protocol in errors and thread names.
#[cfg(unix)]
pub fn open_packet_socket(
    interface: &str,
    label: &'static str,
    keep: impl Fn(&[u8], &[u8; 6]) -> Option<EthFrame> + Send + 'static,
) -> Result<L2Link> {
    use pnet::datalink::{self, Channel, Config};
    use std::time::Duration;

    let iface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == interface)
        .with_context(|| {
            format!(
                "no network interface named {interface:?} (have: {})",
                datalink::interfaces()
                    .iter()
                    .map(|i| i.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    let mac = iface
        .mac
        .map(|m| m.octets())
        .filter(|m| *m != [0; 6])
        .with_context(|| {
            format!(
                "interface {interface} has no Ethernet address; {label} needs an Ethernet \
                 link (loopback and tunnels have none)"
            )
        })?;
    let ipv4 = iface.ips.iter().find_map(|n| match n {
        pnet::ipnetwork::IpNetwork::V4(v4) => Some((v4.ip(), v4.mask())),
        _ => None,
    });
    let config = Config {
        read_timeout: Some(Duration::from_millis(50)),
        write_timeout: Some(Duration::from_millis(50)),
        read_buffer_size: 65536,
        ..Default::default()
    };
    let (mut dl_tx, mut dl_rx) = match datalink::channel(&iface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => anyhow::bail!("interface {interface} did not open as an Ethernet channel"),
        Err(e) => {
            return Err(anyhow!(
                "cannot open a packet socket on {interface}: {e}. Raw {label} needs \
                 CAP_NET_RAW (Linux), BPF device access (macOS), or root; the UDP transport \
                 (transport: \"udp\") needs none"
            ))
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel(RX_QUEUE);
    let dropped = Arc::new(AtomicU64::new(0));
    let (stop_rx, drops) = (stop.clone(), dropped.clone());
    std::thread::Builder::new()
        .name(format!("{}-rx-{interface}", label.to_ascii_lowercase()))
        .spawn(move || {
            while !stop_rx.load(Ordering::SeqCst) {
                match dl_rx.next() {
                    Ok(frame) => {
                        let Some(f) = keep(frame, &mac) else {
                            continue;
                        };
                        match tx.try_send(f) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                drops.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) => {}
                    Err(e) => {
                        tracing::error!("{label} receive on the raw link failed, stopping: {e}");
                        break;
                    }
                }
            }
        })
        .with_context(|| format!("starting the {label} receive thread"))?;
    let (frame_tx, frame_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(RX_QUEUE);
    let stop_tx = stop.clone();
    std::thread::Builder::new()
        .name(format!("{}-tx-{interface}", label.to_ascii_lowercase()))
        .spawn(move || {
            while !stop_tx.load(Ordering::SeqCst) {
                match frame_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(frame) => {
                        if let Some(Err(e)) = dl_tx.send_to(&frame, None) {
                            tracing::warn!("{label} transmit on the raw link failed: {e}");
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
        .with_context(|| format!("starting the {label} transmit thread"))?;
    Ok(L2Link {
        mac,
        ipv4,
        tx: L2Tx {
            inner: TxInner::Raw(frame_tx),
            sent: Arc::new(AtomicU64::new(0)),
        },
        rx,
        dropped,
        description: format!("raw {interface}"),
        lab_addr: None,
        _stop: StopGuard(stop),
        _reader: AbortOnDrop(None),
    })
}

#[cfg(not(unix))]
pub fn open_packet_socket(
    interface: &str,
    label: &'static str,
    _keep: impl Fn(&[u8], &[u8; 6]) -> Option<EthFrame> + Send + 'static,
) -> Result<L2Link> {
    anyhow::bail!(
        "raw {label} on {interface} needs a Unix packet socket (AF_PACKET or BPF), which this \
         platform does not have; use transport \"udp\""
    )
}

/// A locally administered MAC derived from a seed, for the lab transport.
pub fn lab_mac(seed: u32) -> [u8; 6] {
    let s = seed.to_be_bytes();
    [0x02, 0x50, s[0], s[1], s[2], s[3]]
}

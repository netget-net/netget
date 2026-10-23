//! A minimal N3 user plane (GTP-U, TS 29.281, UDP 2152) so the PDU sessions the AMF accepts carry
//! traffic: enough of a UPF to answer a UE's ICMP echo through the tunnel.
//!
//! Rust owns the tunnel: TEID allocation, decapsulating G-PDUs, checking the inner packet comes
//! from the UE's own address, building the ICMP echo reply (IPv4 and ICMP checksums), and
//! encapsulating it toward the gNB's downlink tunnel with a PDU Session Container carrying the
//! QFI (TS 38.415). The model owns which addresses answer: each accepted session carries the list
//! it chose, and a packet to anything else is dropped (`decision=up_not_answered`).
//!
//! Nothing else is routed: there is no N6, no NAT, no forwarding between UEs. A GTP-U Echo
//! Request is answered (path management needs no decision).

use crate::logging::emit::Log;
use crate::server::gtp::codec::{ExtensionHeader, GtpV1Header, GtpV1Message, GTPU_PORT};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::debug;

/// Sessions one user plane holds across every association.
pub const MAX_SESSIONS: usize = 4096;
/// Addresses one session may answer for.
pub const MAX_ANSWERING_ADDRESSES: usize = 16;
const G_PDU: u8 = 255;
const ECHO_REQUEST: u8 = 1;
const ECHO_RESPONSE: u8 = 2;
/// PDU Session Container extension header type (TS 29.281 5.2.1).
const PDU_SESSION_CONTAINER: u8 = 0x85;

/// One PDU session's user plane.
#[derive(Debug, Clone)]
pub struct UpSession {
    pub supi: String,
    pub pdu_session_id: u8,
    pub ue_ip: Ipv4Addr,
    pub qfi: u8,
    /// The gNB's downlink tunnel, once its PDU Session Resource Setup Response named it.
    pub downlink: Option<(IpAddr, u32)>,
    /// The addresses whose ICMP echo this session answers — the model's choice.
    pub answers: Vec<Ipv4Addr>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub uplink_packets: u64,
    pub echo_replies: u64,
    pub dropped: u64,
}

pub struct UserPlane {
    socket: UdpSocket,
    advertised: IpAddr,
    sessions: Mutex<HashMap<u32, UpSession>>,
    stats: Mutex<Stats>,
}

impl UserPlane {
    /// Bind the N3 socket. `advertised` is the address put in each session's UL tunnel.
    pub async fn bind(bind: SocketAddr, advertised: IpAddr) -> anyhow::Result<Arc<Self>> {
        let socket = UdpSocket::bind(bind).await.map_err(|e| {
            anyhow::anyhow!("binding the GTP-U user plane on {bind}: {e} (N3 is UDP {GTPU_PORT})")
        })?;
        Ok(Arc::new(UserPlane {
            socket,
            advertised,
            sessions: Mutex::new(HashMap::new()),
            stats: Mutex::new(Stats::default()),
        }))
    }

    pub fn advertised(&self) -> IpAddr {
        self.advertised
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn stats(&self) -> Stats {
        *self.stats.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Reserve an uplink TEID for a session and record it. Refused when the table is full or the
    /// UE address is already given to another session.
    pub fn add(&self, session: UpSession) -> Result<u32, String> {
        let mut s = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        if s.len() >= MAX_SESSIONS {
            return Err(format!(
                "{MAX_SESSIONS} user-plane sessions are already held"
            ));
        }
        if s.values().any(|x| x.ue_ip == session.ue_ip) {
            return Err(format!(
                "{} is already assigned to another session",
                session.ue_ip
            ));
        }
        let teid = loop {
            let t: u32 = rand::random();
            if t != 0 && !s.contains_key(&t) {
                break t;
            }
        };
        s.insert(teid, session);
        Ok(teid)
    }

    pub fn set_downlink(&self, teid: u32, address: IpAddr, dl_teid: u32) -> bool {
        let mut s = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        match s.get_mut(&teid) {
            Some(x) => {
                x.downlink = Some((address, dl_teid));
                true
            }
            None => false,
        }
    }

    pub fn remove(&self, teid: u32) {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&teid);
    }

    /// Serve N3 until the task is aborted.
    pub async fn run(self: Arc<Self>, status_tx: mpsc::UnboundedSender<String>) {
        let mut buf = vec![0u8; 65_535];
        loop {
            let (n, from) = match self.socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    debug!("GTP-U receive error: {e}");
                    continue;
                }
            };
            if let Some((reply, to)) = self.handle(&buf[..n], from, &status_tx) {
                if let Err(e) = self.socket.send_to(&reply, to).await {
                    debug!("GTP-U send to {to} failed: {e}");
                }
            }
        }
    }

    fn drop_packet(&self, why: &str, status_tx: &mpsc::UnboundedSender<String>) {
        self.stats.lock().unwrap_or_else(|p| p.into_inner()).dropped += 1;
        Log::new(Some(status_tx)).debug(format!("GTP-U packet dropped ({why})"));
    }

    /// One datagram in, at most one out.
    pub fn handle(
        &self,
        datagram: &[u8],
        from: SocketAddr,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Option<(Vec<u8>, SocketAddr)> {
        let msg = match GtpV1Message::decode(datagram) {
            Ok(m) => m,
            Err(e) => {
                self.drop_packet(&format!("decision=up_malformed {e:?}"), status_tx);
                return None;
            }
        };
        match msg.header.message_type {
            ECHO_REQUEST => {
                let mut h =
                    GtpV1Header::with_sequence(ECHO_RESPONSE, 0, msg.header.sequence.unwrap_or(0));
                h.protocol_type = true;
                // Recovery IE (type 14), restart counter 0: TS 29.281 7.2.2.
                let reply = GtpV1Message {
                    header: h,
                    body: vec![14, 0],
                };
                Some((reply.encode(), from))
            }
            G_PDU => self.uplink(msg.header.teid, &msg.body, status_tx),
            other => {
                self.drop_packet(
                    &format!("decision=up_unhandled message type {other}"),
                    status_tx,
                );
                None
            }
        }
    }

    fn uplink(
        &self,
        teid: u32,
        packet: &[u8],
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Option<(Vec<u8>, SocketAddr)> {
        self.stats
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .uplink_packets += 1;
        let session = {
            let s = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
            s.get(&teid).cloned()
        };
        let Some(session) = session else {
            self.drop_packet(&format!("decision=up_no_session teid={teid}"), status_tx);
            return None;
        };
        let Some((dl_addr, dl_teid)) = session.downlink else {
            self.drop_packet("decision=up_no_downlink_tunnel", status_tx);
            return None;
        };
        let Some(ip) = Ipv4Packet::parse(packet) else {
            self.drop_packet("decision=up_not_ipv4", status_tx);
            return None;
        };
        if ip.src != session.ue_ip {
            self.drop_packet(
                &format!(
                    "decision=up_spoofed_source {} is not the session's {}",
                    ip.src, session.ue_ip
                ),
                status_tx,
            );
            return None;
        }
        if !session.answers.contains(&ip.dst) {
            self.drop_packet(
                &format!("decision=up_not_answered {} -> {}", ip.src, ip.dst),
                status_tx,
            );
            return None;
        }
        let Some(reply) = echo_reply(packet) else {
            self.drop_packet("decision=up_not_echo_request", status_tx);
            return None;
        };
        self.stats
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .echo_replies += 1;
        Log::new(Some(status_tx)).debug(format!(
            "GTP-U echo reply {} -> {} for {} PDU session {} (decision=up_echo_reply)",
            ip.dst, ip.src, session.supi, session.pdu_session_id
        ));
        let mut h = GtpV1Header::new(G_PDU, dl_teid);
        // DL PDU SESSION INFORMATION: PDU type 0, then the QFI.
        h.extension_headers.push(ExtensionHeader {
            ext_type: PDU_SESSION_CONTAINER,
            content: vec![0x00, session.qfi & 0x3F],
        });
        let out = GtpV1Message {
            header: h,
            body: reply,
        };
        Some((out.encode(), SocketAddr::new(dl_addr, GTPU_PORT)))
    }
}

struct Ipv4Packet {
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

impl Ipv4Packet {
    fn parse(p: &[u8]) -> Option<Ipv4Packet> {
        if p.len() < 20 || p[0] >> 4 != 4 {
            return None;
        }
        let ihl = (p[0] & 0x0F) as usize * 4;
        let total = u16::from_be_bytes([p[2], p[3]]) as usize;
        if ihl < 20 || total < ihl || total > p.len() {
            return None;
        }
        Some(Ipv4Packet {
            src: Ipv4Addr::new(p[12], p[13], p[14], p[15]),
            dst: Ipv4Addr::new(p[16], p[17], p[18], p[19]),
        })
    }
}

/// The Internet checksum (RFC 1071).
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in data.chunks(2) {
        let w = if c.len() == 2 {
            u16::from_be_bytes([c[0], c[1]])
        } else {
            u16::from_be_bytes([c[0], 0])
        };
        sum += w as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// The echo reply to an IPv4 ICMP echo request (RFC 792), or `None` for anything else: the
/// addresses swapped, TTL 64, type 0, both checksums recomputed, identifier, sequence and data
/// returned as they came.
pub fn echo_reply(p: &[u8]) -> Option<Vec<u8>> {
    let ip = Ipv4Packet::parse(p)?;
    let ihl = (p[0] & 0x0F) as usize * 4;
    let total = u16::from_be_bytes([p[2], p[3]]) as usize;
    // Protocol ICMP, not a fragment, an echo request with code 0.
    let frag = u16::from_be_bytes([p[6], p[7]]);
    if p[9] != 1 || frag & 0x3FFF != 0 || total < ihl + 8 || p[ihl] != 8 || p[ihl + 1] != 0 {
        return None;
    }
    if checksum(&p[ihl..total]) != 0 {
        return None;
    }
    let mut out = p[..total].to_vec();
    out[8] = 64;
    out[12..16].copy_from_slice(&ip.dst.octets());
    out[16..20].copy_from_slice(&ip.src.octets());
    out[10] = 0;
    out[11] = 0;
    let h = checksum(&out[..ihl]);
    out[10..12].copy_from_slice(&h.to_be_bytes());
    out[ihl] = 0;
    out[ihl + 2] = 0;
    out[ihl + 3] = 0;
    let c = checksum(&out[ihl..total]);
    out[ihl + 2..ihl + 4].copy_from_slice(&c.to_be_bytes());
    Some(out)
}

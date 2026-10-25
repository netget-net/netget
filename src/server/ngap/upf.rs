//! A minimal N3 user plane (GTP-U, TS 29.281, UDP 2152) so the PDU sessions the AMF accepts carry
//! traffic: enough of a UPF to answer a UE's ICMP and ICMPv6 echo through the tunnel, and to give
//! an IPv6 UE its prefix.
//!
//! Rust owns the tunnel: TEID allocation, decapsulating G-PDUs, checking the inner packet comes
//! from the UE's own address (its IPv4 address, or for IPv6 its /64 prefix or the link-local
//! address built from its interface identifier), building the echo replies (the IPv4 header and
//! ICMP checksums; the ICMPv6 checksum over the IPv6 pseudo-header, RFC 4443), answering a
//! Router Solicitation with a Router Advertisement carrying the session's prefix (TS 23.501
//! 5.8.2.2.3: the PDU address gives the UE only an interface identifier), and encapsulating the
//! answer toward the gNB's downlink tunnel with a PDU Session Container carrying the QFI
//! (TS 38.415). The model owns which addresses answer: each accepted session carries the list it
//! chose, and a packet to anything else is dropped (`decision=up_not_answered`).
//!
//! Nothing else is routed: there is no N6, no NAT, no forwarding between UEs. A GTP-U Echo
//! Request is answered (path management needs no decision). A session whose UE is idle has no
//! downlink tunnel, so nothing is answered for it until a Service Request sets one up again;
//! a released session's TEID is forgotten and its packets are dropped as `up_no_session`.

use crate::logging::emit::Log;
use crate::server::gtp::codec::{ExtensionHeader, GtpV1Header, GtpV1Message, GTPU_PORT};
use crate::utils::clock::Instant;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
/// Valid and preferred lifetimes of the prefix in a Router Advertisement: a day, which outlives
/// any test and any session a lab keeps.
const PREFIX_LIFETIME_SECS: u32 = 86_400;

/// One PDU session's user plane.
#[derive(Debug, Clone)]
pub struct UpSession {
    pub supi: String,
    pub pdu_session_id: u8,
    /// The UE's IPv4 address (IPv4 and IPv4v6 sessions).
    pub ue_ip: Option<Ipv4Addr>,
    /// The UE's /64 prefix and interface identifier (IPv6 and IPv4v6 sessions).
    pub ue_ipv6: Option<([u8; 8], [u8; 8])>,
    pub qfi: u8,
    /// The gNB's downlink tunnel, once its PDU Session Resource Setup Response named it.
    pub downlink: Option<(IpAddr, u32)>,
    /// The addresses whose echo this session answers — the model's choice.
    pub answers: Vec<IpAddr>,
    /// When the last G-PDU arrived on this session's TEID.
    pub last_uplink: Option<Instant>,
}

impl UpSession {
    /// A session for an IPv4 address only.
    pub fn ipv4(supi: String, pdu_session_id: u8, ue_ip: Ipv4Addr, qfi: u8) -> Self {
        UpSession {
            supi,
            pdu_session_id,
            ue_ip: Some(ue_ip),
            ue_ipv6: None,
            qfi,
            downlink: None,
            answers: Vec::new(),
            last_uplink: None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub uplink_packets: u64,
    pub echo_replies: u64,
    pub router_advertisements: u64,
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

    fn table(&self) -> std::sync::MutexGuard<'_, HashMap<u32, UpSession>> {
        self.sessions.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Reserve an uplink TEID for a session and record it. Refused when the table is full, the
    /// session has no address, or an address or prefix is already another session's.
    pub fn add(&self, session: UpSession) -> Result<u32, String> {
        let mut s = self.table();
        if s.len() >= MAX_SESSIONS {
            return Err(format!(
                "{MAX_SESSIONS} user-plane sessions are already held"
            ));
        }
        if session.ue_ip.is_none() && session.ue_ipv6.is_none() {
            return Err("a session needs an IPv4 address or an IPv6 prefix".into());
        }
        if session.answers.len() > MAX_ANSWERING_ADDRESSES {
            return Err(format!(
                "at most {MAX_ANSWERING_ADDRESSES} answering addresses"
            ));
        }
        if let Some(ip) = session.ue_ip {
            if s.values().any(|x| x.ue_ip == Some(ip)) {
                return Err(format!("{ip} is already assigned to another session"));
            }
        }
        if let Some((prefix, _)) = session.ue_ipv6 {
            if s.values().any(|x| x.ue_ipv6.map(|(p, _)| p) == Some(prefix)) {
                return Err(format!(
                    "{} is already another session's prefix",
                    prefix_string(&prefix)
                ));
            }
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
        match self.table().get_mut(&teid) {
            Some(x) => {
                x.downlink = Some((address, dl_teid));
                true
            }
            None => false,
        }
    }

    /// Forget the gNB's downlink tunnel (the UE went idle); the uplink TEID stays reserved.
    pub fn clear_downlink(&self, teid: u32) {
        if let Some(x) = self.table().get_mut(&teid) {
            x.downlink = None;
        }
    }

    /// Change what a session answers for and with which QFI.
    pub fn update(&self, teid: u32, qfi: u8) {
        if let Some(x) = self.table().get_mut(&teid) {
            x.qfi = qfi;
        }
    }

    /// When the last uplink packet arrived on `teid`.
    pub fn last_uplink(&self, teid: u32) -> Option<Instant> {
        self.table().get(&teid).and_then(|x| x.last_uplink)
    }

    pub fn contains(&self, teid: u32) -> bool {
        self.table().contains_key(&teid)
    }

    pub fn remove(&self, teid: u32) {
        self.table().remove(&teid);
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
            let mut s = self.table();
            let x = s.get_mut(&teid);
            if let Some(x) = x {
                x.last_uplink = Some(Instant::now());
                Some(x.clone())
            } else {
                None
            }
        };
        let Some(session) = session else {
            self.drop_packet(&format!("decision=up_no_session teid={teid}"), status_tx);
            return None;
        };
        let Some((dl_addr, dl_teid)) = session.downlink else {
            self.drop_packet("decision=up_no_downlink_tunnel", status_tx);
            return None;
        };
        let reply = match packet.first().map(|b| b >> 4) {
            Some(4) => self.ipv4_reply(&session, packet, status_tx)?,
            Some(6) => self.ipv6_reply(&session, packet, status_tx)?,
            _ => {
                self.drop_packet("decision=up_not_ip", status_tx);
                return None;
            }
        };
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

    fn ipv4_reply(
        &self,
        session: &UpSession,
        packet: &[u8],
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Option<Vec<u8>> {
        let Some(ip) = Ipv4Packet::parse(packet) else {
            self.drop_packet("decision=up_not_ipv4", status_tx);
            return None;
        };
        if Some(ip.src) != session.ue_ip {
            self.drop_packet(
                &format!(
                    "decision=up_spoofed_source {} is not the session's {:?}",
                    ip.src, session.ue_ip
                ),
                status_tx,
            );
            return None;
        }
        if !session.answers.contains(&IpAddr::V4(ip.dst)) {
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
        self.answered(session, &ip.dst.to_string(), &ip.src.to_string(), status_tx);
        Some(reply)
    }

    fn ipv6_reply(
        &self,
        session: &UpSession,
        packet: &[u8],
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Option<Vec<u8>> {
        let Some((prefix, iid)) = session.ue_ipv6 else {
            self.drop_packet("decision=up_not_ipv6_session", status_tx);
            return None;
        };
        let Some(ip) = Ipv6Packet::parse(packet) else {
            self.drop_packet("decision=up_not_ipv6", status_tx);
            return None;
        };
        let src = ip.src.octets();
        let link_local = link_local(&iid);
        let from_prefix = src[..8] == prefix;
        if !(from_prefix || ip.src == link_local) {
            self.drop_packet(
                &format!(
                    "decision=up_spoofed_source {} is outside the session's {}",
                    ip.src,
                    prefix_string(&prefix)
                ),
                status_tx,
            );
            return None;
        }
        if ip.next_header != 58 {
            self.drop_packet("decision=up_not_icmpv6", status_tx);
            return None;
        }
        match packet.get(40) {
            // Router Solicitation: the session's prefix in a Router Advertisement.
            Some(133) => {
                let ra = router_advertisement(packet, &prefix)?;
                self.stats
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .router_advertisements += 1;
                Log::new(Some(status_tx)).debug(format!(
                    "GTP-U Router Advertisement {} to {} for {} PDU session {} \
                     (decision=up_router_advertisement)",
                    prefix_string(&prefix),
                    ip.src,
                    session.supi,
                    session.pdu_session_id
                ));
                Some(ra)
            }
            _ => {
                if !session.answers.contains(&IpAddr::V6(ip.dst)) {
                    self.drop_packet(
                        &format!("decision=up_not_answered {} -> {}", ip.src, ip.dst),
                        status_tx,
                    );
                    return None;
                }
                let Some(reply) = echo_reply_v6(packet) else {
                    self.drop_packet("decision=up_not_echo_request", status_tx);
                    return None;
                };
                self.answered(session, &ip.dst.to_string(), &ip.src.to_string(), status_tx);
                Some(reply)
            }
        }
    }

    fn answered(
        &self,
        session: &UpSession,
        from: &str,
        to: &str,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        self.stats
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .echo_replies += 1;
        Log::new(Some(status_tx)).debug(format!(
            "GTP-U echo reply {from} -> {to} for {} PDU session {} (decision=up_echo_reply)",
            session.supi, session.pdu_session_id
        ));
    }
}

/// `prefix::/64` for a log line.
pub fn prefix_string(prefix: &[u8; 8]) -> String {
    let mut o = [0u8; 16];
    o[..8].copy_from_slice(prefix);
    format!("{}/64", Ipv6Addr::from(o))
}

/// The link-local address a UE builds from its interface identifier (RFC 4291 2.5.6).
pub fn link_local(iid: &[u8; 8]) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o[0] = 0xfe;
    o[1] = 0x80;
    o[8..].copy_from_slice(iid);
    Ipv6Addr::from(o)
}

/// The user plane's own link-local address, the source of its Router Advertisements.
pub const ROUTER_LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

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

struct Ipv6Packet {
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
}

impl Ipv6Packet {
    /// The fixed header of an IPv6 packet whose payload length fits the datagram.
    fn parse(p: &[u8]) -> Option<Ipv6Packet> {
        if p.len() < 40 || p[0] >> 4 != 6 {
            return None;
        }
        let payload = u16::from_be_bytes([p[4], p[5]]) as usize;
        if 40 + payload > p.len() {
            return None;
        }
        let a = |r: &[u8]| -> Option<Ipv6Addr> {
            let o: [u8; 16] = r.try_into().ok()?;
            Some(Ipv6Addr::from(o))
        };
        Some(Ipv6Packet {
            src: a(&p[8..24])?,
            dst: a(&p[24..40])?,
            next_header: p[6],
        })
    }
}

/// The Internet checksum (RFC 1071).
pub fn checksum(data: &[u8]) -> u16 {
    !fold(sum16(0, data))
}

fn sum16(mut sum: u32, data: &[u8]) -> u32 {
    for c in data.chunks(2) {
        let w = if c.len() == 2 {
            u16::from_be_bytes([c[0], c[1]])
        } else {
            u16::from_be_bytes([c[0], 0])
        };
        sum += w as u32;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// The ICMPv6 checksum (RFC 4443 2.3) of `icmp` between `src` and `dst`: over the pseudo-header
/// (RFC 8200 8.1) and the message.
pub fn icmpv6_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut sum = sum16(0, &src.octets());
    sum = sum16(sum, &dst.octets());
    sum = sum16(sum, &(icmp.len() as u32).to_be_bytes());
    sum = sum16(sum, &[0, 0, 0, 58]);
    !fold(sum16(sum, icmp))
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

/// The echo reply to an ICMPv6 echo request (RFC 4443 4.1, 4.2) carried directly after the
/// fixed IPv6 header, or `None` for anything else: the addresses swapped, hop limit 64, type 129,
/// the checksum recomputed over the new pseudo-header; identifier, sequence and data returned.
pub fn echo_reply_v6(p: &[u8]) -> Option<Vec<u8>> {
    let ip = Ipv6Packet::parse(p)?;
    let end = 40 + u16::from_be_bytes([p[4], p[5]]) as usize;
    if ip.next_header != 58 || end < 48 || p[40] != 128 || p[41] != 0 {
        return None;
    }
    if icmpv6_checksum(&ip.src, &ip.dst, &p[40..end]) != 0 {
        return None;
    }
    let mut out = p[..end].to_vec();
    out[7] = 64;
    out[8..24].copy_from_slice(&ip.dst.octets());
    out[24..40].copy_from_slice(&ip.src.octets());
    out[40] = 129;
    out[42] = 0;
    out[43] = 0;
    let c = icmpv6_checksum(&ip.dst, &ip.src, &out[40..end]);
    out[42..44].copy_from_slice(&c.to_be_bytes());
    Some(out)
}

/// A Router Advertisement (RFC 4861 4.2) answering a Router Solicitation, from
/// [`ROUTER_LINK_LOCAL`] to the solicitor, hop limit 255, carrying one Prefix Information option
/// (4.6.2) for `prefix`/64 with the on-link and autonomous flags. `None` unless `rs` is a
/// well-formed solicitation (hop limit 255, code 0, valid checksum).
pub fn router_advertisement(rs: &[u8], prefix: &[u8; 8]) -> Option<Vec<u8>> {
    let ip = Ipv6Packet::parse(rs)?;
    let end = 40 + u16::from_be_bytes([rs[4], rs[5]]) as usize;
    if ip.next_header != 58 || end < 48 || rs[7] != 255 || rs[40] != 133 || rs[41] != 0 {
        return None;
    }
    if icmpv6_checksum(&ip.src, &ip.dst, &rs[40..end]) != 0 {
        return None;
    }
    let dst = if ip.src.is_unspecified() {
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
    } else {
        ip.src
    };
    let mut icmp = vec![
        134, 0, 0, 0, // type, code, checksum
        64, 0, // cur hop limit, M/O flags clear (SLAAC)
        0x07, 0x08, // router lifetime 1800 s
        0, 0, 0, 0, // reachable time unspecified
        0, 0, 0, 0, // retrans timer unspecified
    ];
    // Prefix Information: type 3, length 4 (32 octets), /64, L and A set.
    icmp.extend_from_slice(&[3, 4, 64, 0xC0]);
    icmp.extend_from_slice(&PREFIX_LIFETIME_SECS.to_be_bytes());
    icmp.extend_from_slice(&PREFIX_LIFETIME_SECS.to_be_bytes());
    icmp.extend_from_slice(&[0, 0, 0, 0]);
    icmp.extend_from_slice(prefix);
    icmp.extend_from_slice(&[0u8; 8]);
    let c = icmpv6_checksum(&ROUTER_LINK_LOCAL, &dst, &icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    let mut out = vec![0x60, 0, 0, 0];
    out.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
    out.push(58);
    out.push(255);
    out.extend_from_slice(&ROUTER_LINK_LOCAL.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(&icmp);
    Some(out)
}

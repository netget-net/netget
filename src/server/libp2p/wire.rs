//! The small libp2p encodings, shared by both roles: unsigned varints, the protobuf fields
//! libp2p uses, base58btc peer ids, binary multiaddrs, multistream-select 1.0 and the
//! identify message. Each decoder bounds what the peer may announce.
use anyhow::{bail, ensure, Context, Result};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};

/// A multistream-select message (a protocol id and its newline) is at most this long.
pub const MAX_MULTISTREAM_MESSAGE: usize = 1024;
/// Proposals a listener answers on one stream before giving up on it.
pub const MAX_PROPOSALS: usize = 16;
/// An identify message is at most this long (go-libp2p's own limit is 8 KiB of protobuf
/// plus the signed peer record; leave room for both).
pub const MAX_IDENTIFY_BYTES: usize = 64 * 1024;
pub const MULTISTREAM: &str = "/multistream/1.0.0";
pub const NOISE: &str = "/noise";
pub const YAMUX: &str = "/yamux/1.0.0";
pub const IDENTIFY: &str = "/ipfs/id/1.0.0";
pub const IDENTIFY_PUSH: &str = "/ipfs/id/push/1.0.0";
pub const PING: &str = "/ipfs/ping/1.0.0";

/// Byte-stream I/O that every libp2p layer offers the one above it.
pub trait Io: Send {
    fn read_exact<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = Result<()>> + Send + 'a;
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> impl Future<Output = Result<()>> + Send + 'a;
}

impl Io for tokio::net::TcpStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        tokio::io::AsyncReadExt::read_exact(self, buf).await?;
        Ok(())
    }
    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        tokio::io::AsyncWriteExt::write_all(self, buf).await?;
        Ok(())
    }
}

pub fn put_uvarint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Decode a uvarint at the start of `b`: (value, bytes used).
pub fn get_uvarint(b: &[u8]) -> Result<(u64, usize)> {
    let mut v = 0u64;
    for (i, byte) in b.iter().enumerate().take(10) {
        v |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok((v, i + 1));
        }
    }
    bail!("truncated or overlong varint")
}

/// Read one uvarint from a stream (at most 9 bytes: 63 bits).
pub async fn read_uvarint(io: &mut impl Io) -> Result<u64> {
    let mut v = 0u64;
    for i in 0..9 {
        let mut b = [0u8];
        io.read_exact(&mut b).await?;
        v |= u64::from(b[0] & 0x7f) << (7 * i);
        if b[0] & 0x80 == 0 {
            return Ok(v);
        }
    }
    bail!("varint longer than 9 bytes")
}

/// A uvarint-length-prefixed message, refused before reading past `max`.
pub async fn read_length_prefixed(io: &mut impl Io, max: usize) -> Result<Vec<u8>> {
    let n = read_uvarint(io).await?;
    ensure!(
        n as usize <= max,
        "message announces {n} bytes; the limit is {max}"
    );
    let mut buf = vec![0u8; n as usize];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

pub fn length_prefixed(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    put_uvarint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

// ---------------------------------------------------------------------------------------
// Protobuf: the handful of wire types libp2p's small messages use.

pub fn pb_bytes(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    put_uvarint(out, u64::from(field << 3 | 2));
    put_uvarint(out, value.len() as u64);
    out.extend_from_slice(value);
}

pub fn pb_varint(out: &mut Vec<u8>, field: u32, value: u64) {
    put_uvarint(out, u64::from(field << 3));
    put_uvarint(out, value);
}

pub enum PbValue<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

/// Every (field, value) in a message; unknown wire types are an error, fixed-width ones are
/// skipped.
pub fn pb_fields(b: &[u8]) -> Result<Vec<(u32, PbValue<'_>)>> {
    pb_fields_bounded(b, usize::MAX)
}

/// [`pb_fields`], refusing a message with more than `max` fields before collecting them, so
/// a peer cannot turn a few megabytes of two-byte fields into a vector many times larger.
pub fn pb_fields_bounded(mut b: &[u8], max: usize) -> Result<Vec<(u32, PbValue<'_>)>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        ensure!(
            out.len() < max,
            "protobuf message has more than {max} fields"
        );
        let (key, n) = get_uvarint(b)?;
        b = &b[n..];
        let field = (key >> 3) as u32;
        match key & 7 {
            0 => {
                let (v, n) = get_uvarint(b)?;
                b = &b[n..];
                out.push((field, PbValue::Varint(v)));
            }
            2 => {
                let (len, n) = get_uvarint(b)?;
                b = &b[n..];
                ensure!(
                    len as usize <= b.len(),
                    "protobuf field runs past the message"
                );
                out.push((field, PbValue::Bytes(&b[..len as usize])));
                b = &b[len as usize..];
            }
            1 => {
                ensure!(b.len() >= 8, "truncated fixed64");
                b = &b[8..];
            }
            5 => {
                ensure!(b.len() >= 4, "truncated fixed32");
                b = &b[4..];
            }
            w => bail!("unsupported protobuf wire type {w}"),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// Keys and peer ids.

/// `PublicKey{Type: Ed25519, Data: key}`, the form a peer id hashes.
pub fn ed25519_public_key_proto(key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    pb_varint(&mut out, 1, 1);
    pb_bytes(&mut out, 2, key);
    out
}

/// The Ed25519 key inside a `PublicKey` protobuf. Other key types are refused.
pub fn parse_public_key(proto: &[u8]) -> Result<[u8; 32]> {
    let mut kind = None;
    let mut data = None;
    for (f, v) in pb_fields(proto)? {
        match (f, v) {
            (1, PbValue::Varint(k)) => kind = Some(k),
            (2, PbValue::Bytes(d)) => data = Some(d),
            _ => {}
        }
    }
    match kind {
        Some(1) => {}
        Some(0) => bail!("RSA identity keys are not supported (only Ed25519)"),
        Some(2) => bail!("secp256k1 identity keys are not supported (only Ed25519)"),
        Some(3) => bail!("ECDSA identity keys are not supported (only Ed25519)"),
        _ => bail!("identity key has no type"),
    }
    data.context("identity key has no data")?
        .try_into()
        .ok()
        .context("Ed25519 key must be 32 bytes")
}

/// The peer id of a public key protobuf: an identity multihash, since every Ed25519 key's
/// protobuf is 36 bytes (≤ 42).
pub fn peer_id(public_key_proto: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, public_key_proto.len() as u8];
    out.extend_from_slice(public_key_proto);
    out
}

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn base58(b: &[u8]) -> String {
    let zeros = b.iter().take_while(|&&x| x == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in b {
        let mut carry = u32::from(byte);
        for d in digits.iter_mut() {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut s = String::with_capacity(zeros + digits.len());
    s.extend(std::iter::repeat_n('1', zeros));
    s.extend(digits.iter().rev().map(|&d| B58[d as usize] as char));
    s
}

pub fn unbase58(s: &str) -> Result<Vec<u8>> {
    ensure!(s.len() <= 128, "base58 string too long");
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry =
            B58.iter()
                .position(|&x| x == c)
                .with_context(|| format!("{:?} is not base58", c as char))? as u32;
        for b in bytes.iter_mut() {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Ok(out)
}

pub fn peer_id_string(peer_id: &[u8]) -> String {
    base58(peer_id)
}

// ---------------------------------------------------------------------------------------
// Multiaddrs: the /ip4|ip6/…/tcp/…[/p2p/…] subset.

const P_IP4: u64 = 0x04;
const P_TCP: u64 = 0x06;
const P_IP6: u64 = 0x29;
const P_P2P: u64 = 0x01a5;

pub fn multiaddr_bytes(addr: &SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match addr.ip() {
        IpAddr::V4(a) => {
            put_uvarint(&mut out, P_IP4);
            out.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            put_uvarint(&mut out, P_IP6);
            out.extend_from_slice(&a.octets());
        }
    }
    put_uvarint(&mut out, P_TCP);
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

pub fn multiaddr_string(addr: &SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(a) => format!("/ip4/{a}/tcp/{}", addr.port()),
        IpAddr::V6(a) => format!("/ip6/{a}/tcp/{}", addr.port()),
    }
}

/// A binary multiaddr as text; components outside the subset are shown by code.
pub fn multiaddr_text(mut b: &[u8]) -> Result<String> {
    let mut s = String::new();
    while !b.is_empty() {
        let (code, n) = get_uvarint(b)?;
        b = &b[n..];
        let take = |b: &mut &[u8], n: usize| -> Result<Vec<u8>> {
            ensure!(b.len() >= n, "truncated multiaddr");
            let v = b[..n].to_vec();
            *b = &b[n..];
            Ok(v)
        };
        match code {
            P_IP4 => {
                let v = take(&mut b, 4)?;
                s.push_str(&format!("/ip4/{}.{}.{}.{}", v[0], v[1], v[2], v[3]));
            }
            P_IP6 => {
                let v: [u8; 16] = take(&mut b, 16)?.try_into().unwrap_or([0; 16]);
                s.push_str(&format!("/ip6/{}", std::net::Ipv6Addr::from(v)));
            }
            P_TCP | 0x0111 => {
                let v = take(&mut b, 2)?;
                let name = if code == P_TCP { "tcp" } else { "udp" };
                s.push_str(&format!("/{name}/{}", u16::from_be_bytes([v[0], v[1]])));
            }
            0x01cc => s.push_str("/quic-v1"),
            0x01cd => s.push_str("/quic"),
            P_P2P => {
                let (len, n) = get_uvarint(b)?;
                b = &b[n..];
                let v = take(&mut b, len as usize)?;
                s.push_str(&format!("/p2p/{}", base58(&v)));
            }
            other => {
                // Unknown component of unknown length: stop rather than misread the rest.
                s.push_str(&format!("/<{other:#x}>"));
                break;
            }
        }
    }
    Ok(s)
}

/// A text multiaddr in binary: `/ip4|ip6/…`, `/tcp|udp/…`, `/quic-v1`, `/p2p/<id>`, in any
/// order the text gives them. Anything else is refused rather than guessed.
pub fn multiaddr_from_text(s: &str) -> Result<Vec<u8>> {
    ensure!(
        s.starts_with('/') && s.len() <= 256,
        "{s:?} is not a multiaddr"
    );
    let mut out = Vec::new();
    let mut parts = s.trim_end_matches('/').split('/').skip(1);
    while let Some(name) = parts.next() {
        let mut value = || {
            parts
                .next()
                .with_context(|| format!("{name} needs a value in {s}"))
        };
        match name {
            "ip4" => {
                let a: std::net::Ipv4Addr = value()?.parse().context("bad ip4 address")?;
                put_uvarint(&mut out, P_IP4);
                out.extend_from_slice(&a.octets());
            }
            "ip6" => {
                let a: std::net::Ipv6Addr = value()?.parse().context("bad ip6 address")?;
                put_uvarint(&mut out, P_IP6);
                out.extend_from_slice(&a.octets());
            }
            "tcp" | "udp" => {
                let port: u16 = value()?.parse().context("bad port")?;
                put_uvarint(&mut out, if name == "tcp" { P_TCP } else { 0x0111 });
                out.extend_from_slice(&port.to_be_bytes());
            }
            "quic-v1" => put_uvarint(&mut out, 0x01cc),
            "p2p" | "ipfs" => {
                let id = unbase58(value()?).context("the /p2p/ peer id is not base58")?;
                put_uvarint(&mut out, P_P2P);
                put_uvarint(&mut out, id.len() as u64);
                out.extend(id);
            }
            other => bail!("multiaddr component /{other} is not supported in {s}"),
        }
    }
    ensure!(!out.is_empty(), "empty multiaddr");
    Ok(out)
}

/// `host:port`, `/ip4/a/tcp/p[/p2p/id]` or `/ip6/…`: the address to dial and the expected
/// peer id, if named.
pub fn parse_dial_target(s: &str) -> Result<(String, Option<Vec<u8>>)> {
    if !s.starts_with('/') {
        return Ok((s.to_string(), None));
    }
    let parts: Vec<&str> = s.trim_end_matches('/').split('/').skip(1).collect();
    let (host, rest) = match parts.as_slice() {
        ["ip4", ip, "tcp", port, rest @ ..] => (format!("{ip}:{port}"), rest),
        ["ip6", ip, "tcp", port, rest @ ..] => (format!("[{ip}]:{port}"), rest),
        ["dns4" | "dns6" | "dns", name, "tcp", port, rest @ ..] => (format!("{name}:{port}"), rest),
        _ => bail!("only /ip4|ip6|dns/…/tcp/… multiaddrs can be dialled: {s}"),
    };
    let peer = match rest {
        [] => None,
        ["p2p" | "ipfs", id] => Some(unbase58(id).context("the /p2p/ peer id is not base58")?),
        _ => bail!("unsupported multiaddr suffix in {s}"),
    };
    Ok((host, peer))
}

// ---------------------------------------------------------------------------------------
// multistream-select 1.0

async fn ms_read(io: &mut impl Io) -> Result<String> {
    let b = read_length_prefixed(io, MAX_MULTISTREAM_MESSAGE).await?;
    let text = String::from_utf8(b).context("multistream message is not UTF-8")?;
    text.strip_suffix('\n')
        .map(str::to_string)
        .context("multistream message does not end in a newline")
}

fn ms_message(s: &str) -> Vec<u8> {
    length_prefixed(format!("{s}\n").as_bytes())
}

/// Answer a dialer's proposals until one is supported; returns it.
pub async fn ms_listen(io: &mut impl Io, supported: impl Fn(&str) -> bool) -> Result<String> {
    let header = ms_read(io).await?;
    ensure!(
        header == MULTISTREAM,
        "expected {MULTISTREAM}, got {header:?}"
    );
    io.write_all(&ms_message(MULTISTREAM)).await?;
    for _ in 0..MAX_PROPOSALS {
        let proposal = ms_read(io).await?;
        if supported(&proposal) {
            io.write_all(&ms_message(&proposal)).await?;
            return Ok(proposal);
        }
        io.write_all(&ms_message("na")).await?;
    }
    bail!("no supported protocol in {MAX_PROPOSALS} proposals")
}

/// Propose `protocol`; Ok(true) when the listener accepts it, Ok(false) on "na".
pub async fn ms_dial(io: &mut impl Io, protocol: &str) -> Result<bool> {
    let mut out = ms_message(MULTISTREAM);
    out.extend(ms_message(protocol));
    io.write_all(&out).await?;
    let header = ms_read(io).await?;
    ensure!(
        header == MULTISTREAM,
        "expected {MULTISTREAM}, got {header:?}"
    );
    let answer = ms_read(io).await?;
    if answer == protocol {
        Ok(true)
    } else if answer == "na" {
        Ok(false)
    } else {
        bail!("listener answered {answer:?} to {protocol:?}")
    }
}

/// Propose each protocol in turn on one stream; the first the listener accepts, or None when
/// it refuses them all.
pub async fn ms_dial_any(io: &mut impl Io, protocols: &[&str]) -> Result<Option<String>> {
    let Some((first, rest)) = protocols.split_first() else {
        return Ok(None);
    };
    let mut out = ms_message(MULTISTREAM);
    out.extend(ms_message(first));
    io.write_all(&out).await?;
    let header = ms_read(io).await?;
    ensure!(
        header == MULTISTREAM,
        "expected {MULTISTREAM}, got {header:?}"
    );
    let mut proposed = *first;
    let mut rest = rest.iter();
    loop {
        let answer = ms_read(io).await?;
        if answer == proposed {
            return Ok(Some(answer));
        }
        ensure!(
            answer == "na",
            "listener answered {answer:?} to {proposed:?}"
        );
        let Some(next) = rest.next() else {
            return Ok(None);
        };
        proposed = next;
        io.write_all(&ms_message(next)).await?;
    }
}

// ---------------------------------------------------------------------------------------
// identify

pub struct Identify {
    pub protocol_version: String,
    pub agent_version: String,
    pub public_key: Vec<u8>,
    pub listen_addrs: Vec<Vec<u8>>,
    pub observed_addr: Option<Vec<u8>>,
    pub protocols: Vec<String>,
}

pub fn encode_identify(id: &Identify) -> Vec<u8> {
    let mut out = Vec::new();
    pb_bytes(&mut out, 1, &id.public_key);
    for a in &id.listen_addrs {
        pb_bytes(&mut out, 2, a);
    }
    for p in &id.protocols {
        pb_bytes(&mut out, 3, p.as_bytes());
    }
    if let Some(o) = &id.observed_addr {
        pb_bytes(&mut out, 4, o);
    }
    pb_bytes(&mut out, 5, id.protocol_version.as_bytes());
    pb_bytes(&mut out, 6, id.agent_version.as_bytes());
    out
}

pub fn decode_identify(b: &[u8]) -> Result<Identify> {
    let mut id = Identify {
        protocol_version: String::new(),
        agent_version: String::new(),
        public_key: Vec::new(),
        listen_addrs: Vec::new(),
        observed_addr: None,
        protocols: Vec::new(),
    };
    let text = |v: &[u8]| String::from_utf8_lossy(v).into_owned();
    for (f, v) in pb_fields(b)? {
        if let PbValue::Bytes(v) = v {
            match f {
                1 => id.public_key = v.to_vec(),
                2 => id.listen_addrs.push(v.to_vec()),
                3 => id.protocols.push(text(v)),
                4 => id.observed_addr = Some(v.to_vec()),
                5 => id.protocol_version = text(v),
                6 => id.agent_version = text(v),
                _ => {}
            }
        }
    }
    Ok(id)
}

/// Message bytes as the model sees them: text, or hex when they are not printable UTF-8.
pub fn shown(b: &[u8]) -> (String, &'static str) {
    match std::str::from_utf8(b) {
        Ok(s)
            if !s
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') =>
        {
            (s.to_string(), "utf8")
        }
        _ => (hex::encode(b), "hex"),
    }
}

/// An action's `data` in its declared `encoding` (utf8 by default, or hex).
pub fn data_bytes(v: &serde_json::Value) -> Result<Vec<u8>> {
    let data = v["data"].as_str().context("data is required")?;
    match v["encoding"].as_str().unwrap_or("utf8") {
        "utf8" => Ok(data.as_bytes().to_vec()),
        "hex" => hex::decode(data).context("data is not valid hex"),
        e => bail!("encoding must be utf8 or hex, not {e:?}"),
    }
}

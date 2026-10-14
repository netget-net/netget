//! The Kademlia DHT message (`/ipfs/kad/1.0.0`, and the LAN DHT's `/ipfs/lan/kad/1.0.0`):
//! one uvarint-length-prefixed protobuf per request, answered on the same stream. Peers are
//! carried as (peer id, binary multiaddrs); both are checked on the way in and out.
use super::ipfs;
use super::wire::{
    base58, multiaddr_from_text, multiaddr_text, pb_bytes, pb_fields_bounded, pb_varint, unbase58,
    PbValue,
};
use anyhow::{bail, ensure, Context, Result};

pub const KAD: &str = "/ipfs/kad/1.0.0";
pub const LAN_KAD: &str = "/ipfs/lan/kad/1.0.0";
pub const PROTOCOLS: &[&str] = &[KAD, LAN_KAD];
/// A DHT message is at most this long. Requests are a key and a few addresses; a reply is
/// at most `MAX_PEERS` peers with `MAX_ADDRS` addresses each.
pub const MAX_MESSAGE: usize = 64 * 1024;
/// Peers one message may carry in each of its peer lists (Kademlia's k is 20).
pub const MAX_PEERS: usize = 20;
/// Addresses one peer entry may carry.
pub const MAX_ADDRS: usize = 16;
/// How long a dialler waits for a DHT answer.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

pub fn is_kad(protocol: &str) -> bool {
    PROTOCOLS.contains(&protocol)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    PutValue,
    GetValue,
    AddProvider,
    GetProviders,
    FindNode,
    Ping,
}

impl Kind {
    pub fn code(self) -> u64 {
        match self {
            Kind::PutValue => 0,
            Kind::GetValue => 1,
            Kind::AddProvider => 2,
            Kind::GetProviders => 3,
            Kind::FindNode => 4,
            Kind::Ping => 5,
        }
    }
    pub fn from_code(c: u64) -> Result<Kind> {
        Ok(match c {
            0 => Kind::PutValue,
            1 => Kind::GetValue,
            2 => Kind::AddProvider,
            3 => Kind::GetProviders,
            4 => Kind::FindNode,
            5 => Kind::Ping,
            other => bail!("unknown DHT message type {other}"),
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Kind::PutValue => "PUT_VALUE",
            Kind::GetValue => "GET_VALUE",
            Kind::AddProvider => "ADD_PROVIDER",
            Kind::GetProviders => "GET_PROVIDERS",
            Kind::FindNode => "FIND_NODE",
            Kind::Ping => "PING",
        }
    }
}

/// A peer as the DHT carries it.
#[derive(Clone, Debug, PartialEq)]
pub struct Peer {
    pub id: Vec<u8>,
    pub addrs: Vec<Vec<u8>>,
}

impl Peer {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "peer_id": base58(&self.id),
            "addrs": self.addrs.iter().filter_map(|a| multiaddr_text(a).ok()).collect::<Vec<_>>(),
        })
    }
    /// From `{peer_id, addrs}` as the model writes it.
    pub fn from_text(id: &str, addrs: &[String]) -> Result<Peer> {
        let id = parse_peer_id(id)?;
        ensure!(
            addrs.len() <= MAX_ADDRS,
            "a peer may carry at most {MAX_ADDRS} addresses"
        );
        let addrs = addrs
            .iter()
            .map(|a| multiaddr_from_text(a))
            .collect::<Result<Vec<_>>>()?;
        Ok(Peer { id, addrs })
    }
}

/// A peer id in text, checked to be a multihash (identity or sha2-256), as every libp2p peer
/// id is.
pub fn parse_peer_id(text: &str) -> Result<Vec<u8>> {
    let b = unbase58(text).with_context(|| format!("{text:?} is not a base58 peer id"))?;
    check_peer_id(&b).with_context(|| format!("{text:?} is not a peer id"))?;
    Ok(b)
}

fn check_peer_id(b: &[u8]) -> Result<()> {
    ensure!(b.len() >= 2, "too short");
    match b[0] {
        0x00 => ensure!(
            usize::from(b[1]) == b.len() - 2 && b.len() <= 44,
            "malformed identity multihash"
        ),
        0x12 => ensure!(b[1] == 32 && b.len() == 34, "malformed sha2-256 multihash"),
        other => bail!("multihash {other:#x} is not a peer id"),
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub kind: Kind,
    pub key: Vec<u8>,
    pub closer: Vec<Peer>,
    pub providers: Vec<Peer>,
    /// Whether a record (PUT_VALUE/GET_VALUE) was present; records are not supported.
    pub has_record: bool,
}

impl Message {
    pub fn request(kind: Kind, key: Vec<u8>) -> Message {
        Message {
            kind,
            key,
            closer: Vec::new(),
            providers: Vec::new(),
            has_record: false,
        }
    }
    /// The key as text: a peer id for FIND_NODE, the multihash (base58, the CIDv0 spelling of
    /// a sha2-256 key) otherwise.
    pub fn key_text(&self) -> String {
        base58(&self.key)
    }
    /// For a provider key: the CIDs (v0, v1 dag-pb, v1 raw) its multihash may stand for.
    pub fn key_cids(&self) -> Vec<String> {
        match ipfs::parse_multihash(&self.key) {
            Ok((digest, n)) if n == self.key.len() => ipfs::cids_for_digest(&digest),
            _ => Vec::new(),
        }
    }
}

fn decode_peer(b: &[u8]) -> Result<Peer> {
    let mut p = Peer {
        id: Vec::new(),
        addrs: Vec::new(),
    };
    for (f, v) in pb_fields_bounded(b, MAX_ADDRS + 4)? {
        match (f, v) {
            (1, PbValue::Bytes(id)) => p.id = id.to_vec(),
            (2, PbValue::Bytes(a)) => {
                ensure!(
                    p.addrs.len() < MAX_ADDRS,
                    "a DHT peer carries more than {MAX_ADDRS} addresses"
                );
                p.addrs.push(a.to_vec())
            }
            (3, PbValue::Varint(_)) => {}
            _ => bail!("malformed DHT peer"),
        }
    }
    check_peer_id(&p.id).context("a DHT peer's id is not a peer id")?;
    Ok(p)
}

pub fn decode(b: &[u8]) -> Result<Message> {
    ensure!(
        b.len() <= MAX_MESSAGE,
        "DHT message over {MAX_MESSAGE} bytes"
    );
    let mut kind = None;
    let mut m = Message::request(Kind::Ping, Vec::new());
    for (f, v) in pb_fields_bounded(b, 2 * MAX_PEERS + 8)? {
        match (f, v) {
            (1, PbValue::Varint(k)) => kind = Some(Kind::from_code(k)?),
            (2, PbValue::Bytes(k)) => {
                ensure!(k.len() <= 256, "DHT key longer than 256 bytes");
                m.key = k.to_vec()
            }
            (3, PbValue::Bytes(_)) => m.has_record = true,
            (8, PbValue::Bytes(p)) => {
                ensure!(
                    m.closer.len() < MAX_PEERS,
                    "more than {MAX_PEERS} closer peers"
                );
                m.closer.push(decode_peer(p)?)
            }
            (9, PbValue::Bytes(p)) => {
                ensure!(
                    m.providers.len() < MAX_PEERS,
                    "more than {MAX_PEERS} provider peers"
                );
                m.providers.push(decode_peer(p)?)
            }
            (10, PbValue::Varint(_)) => {}
            _ => bail!("malformed DHT message (field {f})"),
        }
    }
    m.kind = kind.unwrap_or(Kind::PutValue);
    Ok(m)
}

fn encode_peer(p: &Peer) -> Vec<u8> {
    let mut out = Vec::new();
    pb_bytes(&mut out, 1, &p.id);
    for a in &p.addrs {
        pb_bytes(&mut out, 2, a);
    }
    out
}

pub fn encode(m: &Message) -> Vec<u8> {
    let mut out = Vec::new();
    // proto3: a zero enum is the default and is not written.
    if m.kind.code() != 0 {
        pb_varint(&mut out, 1, m.kind.code());
    }
    if !m.key.is_empty() {
        pb_bytes(&mut out, 2, &m.key);
    }
    for p in &m.closer {
        pb_bytes(&mut out, 8, &encode_peer(p));
    }
    for p in &m.providers {
        pb_bytes(&mut out, 9, &encode_peer(p));
    }
    out
}

//! Bitswap 1.2.0 (and 1.1.0, 1.0.0): the message, and the two decisions Rust makes about it
//! before or after the model — which wanted blocks the model's content actually is
//! ([`answer_wants`]), and which received blocks are the ones that were asked for
//! ([`accept_blocks`]). In both, a block's identity is its hash, computed here.
//!
//! A Bitswap message is one uvarint-length-prefixed protobuf on a stream the sender opened;
//! answers travel on a stream the answerer opens. Every count and size a peer announces is
//! bounded before anything is collected for it.
use super::ipfs::{self, Cid};
use super::wire::{pb_bytes, pb_fields_bounded, pb_varint, PbValue};
use anyhow::{bail, ensure, Context, Result};
use std::collections::HashMap;

pub const BITSWAP_120: &str = "/ipfs/bitswap/1.2.0";
pub const BITSWAP_110: &str = "/ipfs/bitswap/1.1.0";
pub const BITSWAP_100: &str = "/ipfs/bitswap/1.0.0";
pub const BITSWAP_LEGACY: &str = "/ipfs/bitswap";
/// Every Bitswap protocol id NetGet accepts, newest first (the order it proposes them).
pub const PROTOCOLS: &[&str] = &[BITSWAP_120, BITSWAP_110, BITSWAP_100, BITSWAP_LEGACY];
/// A Bitswap message is at most this long (boxo's own `MessageSizeMax`).
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;
/// Wantlist entries one message may carry.
pub const MAX_WANTLIST_ENTRIES: usize = 1024;
/// Top-level fields (blocks, presences) one message may carry.
pub const MAX_MESSAGE_FIELDS: usize = 4096;
/// What NetGet packs into one outgoing message, leaving room for framing.
pub const MAX_OUTGOING: usize = MAX_MESSAGE - 64 * 1024;
/// Blocks the model may supply in one answer.
pub const MAX_SUPPLIED_BLOCKS: usize = 64;

pub fn is_bitswap(protocol: &str) -> bool {
    PROTOCOLS.contains(&protocol)
}

/// Which message format a protocol id speaks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Version {
    V100,
    V110,
    V120,
}

impl Version {
    pub fn of(protocol: &str) -> Version {
        match protocol {
            BITSWAP_120 => Version::V120,
            BITSWAP_110 => Version::V110,
            _ => Version::V100,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WantType {
    Block,
    Have,
}

impl WantType {
    pub fn name(self) -> &'static str {
        match self {
            WantType::Block => "block",
            WantType::Have => "have",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub cid: Cid,
    pub priority: i32,
    pub cancel: bool,
    pub want_type: WantType,
    pub send_dont_have: bool,
}

/// One received block: the CID its prefix and bytes name (the bytes hashed here), and the
/// bytes. A 1.0.0 block carries no prefix and is read as CIDv0 dag-pb.
#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub cid: Cid,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Message {
    pub entries: Vec<Entry>,
    pub full: bool,
    pub blocks: Vec<Block>,
    /// (cid, have): HAVE when true, DONT_HAVE when false.
    pub presences: Vec<(Cid, bool)>,
    /// Entries or presences naming a CID NetGet cannot represent (another hash function, a
    /// CID version it does not know), each with why. A malformed message is refused whole;
    /// these are refused one by one.
    pub unreadable: Vec<String>,
}

/// Decode one Bitswap message. Malformed protobuf, too many entries or fields, and a block
/// over [`ipfs::MAX_BLOCK`] refuse the whole message.
pub fn decode(b: &[u8]) -> Result<Message> {
    ensure!(
        b.len() <= MAX_MESSAGE,
        "Bitswap message of {} bytes is over {MAX_MESSAGE}",
        b.len()
    );
    let mut m = Message::default();
    for (f, v) in pb_fields_bounded(b, MAX_MESSAGE_FIELDS)? {
        match (f, v) {
            (1, PbValue::Bytes(w)) => decode_wantlist(w, &mut m)?,
            (2, PbValue::Bytes(data)) => {
                ensure!(
                    data.len() <= ipfs::MAX_BLOCK,
                    "block over {} bytes",
                    ipfs::MAX_BLOCK
                );
                m.blocks.push(Block {
                    cid: Cid {
                        version: 0,
                        codec: ipfs::DAG_PB,
                        digest: ipfs::sha256(data),
                    },
                    data: data.to_vec(),
                });
            }
            (3, PbValue::Bytes(p)) => {
                let (mut prefix, mut data) = (None, None);
                for (bf, bv) in pb_fields_bounded(p, 8)? {
                    match (bf, bv) {
                        (1, PbValue::Bytes(x)) => prefix = Some(x),
                        (2, PbValue::Bytes(x)) => data = Some(x),
                        _ => bail!("malformed Bitswap block"),
                    }
                }
                let data = data.unwrap_or_default();
                ensure!(
                    data.len() <= ipfs::MAX_BLOCK,
                    "block over {} bytes",
                    ipfs::MAX_BLOCK
                );
                match Cid::from_prefix(prefix.context("a Bitswap block has no prefix")?, data) {
                    Ok(cid) => m.blocks.push(Block {
                        cid,
                        data: data.to_vec(),
                    }),
                    Err(e) => m.unreadable.push(format!("block: {e:#}")),
                }
            }
            (4, PbValue::Bytes(p)) => {
                let (mut cid, mut kind) = (None, 0);
                for (pf, pv) in pb_fields_bounded(p, 8)? {
                    match (pf, pv) {
                        (1, PbValue::Bytes(x)) => cid = Some(x),
                        (2, PbValue::Varint(k)) => kind = k,
                        _ => bail!("malformed Bitswap block presence"),
                    }
                }
                match Cid::from_bytes(cid.context("a block presence has no CID")?) {
                    Ok(c) => m.presences.push((c, kind == 0)),
                    Err(e) => m.unreadable.push(format!("presence: {e:#}")),
                }
            }
            // pendingBytes
            (5, PbValue::Varint(_)) => {}
            _ => bail!("malformed Bitswap message (field {f})"),
        }
    }
    Ok(m)
}

fn decode_wantlist(w: &[u8], m: &mut Message) -> Result<()> {
    for (f, v) in pb_fields_bounded(w, MAX_WANTLIST_ENTRIES + 1)? {
        match (f, v) {
            (1, PbValue::Bytes(e)) => {
                ensure!(
                    m.entries.len() < MAX_WANTLIST_ENTRIES,
                    "wantlist has more than {MAX_WANTLIST_ENTRIES} entries"
                );
                let mut cid = None;
                let mut entry = Entry {
                    cid: Cid {
                        version: 0,
                        codec: 0,
                        digest: [0; 32],
                    },
                    priority: 0,
                    cancel: false,
                    want_type: WantType::Block,
                    send_dont_have: false,
                };
                for (ef, ev) in pb_fields_bounded(e, 16)? {
                    match (ef, ev) {
                        (1, PbValue::Bytes(c)) => cid = Some(c),
                        (2, PbValue::Varint(p)) => entry.priority = p as i32,
                        (3, PbValue::Varint(c)) => entry.cancel = c != 0,
                        (4, PbValue::Varint(t)) => {
                            entry.want_type = if t == 1 {
                                WantType::Have
                            } else {
                                WantType::Block
                            }
                        }
                        (5, PbValue::Varint(s)) => entry.send_dont_have = s != 0,
                        _ => bail!("malformed wantlist entry"),
                    }
                }
                let cid = cid.context("a wantlist entry has no CID")?;
                match Cid::from_bytes(cid) {
                    Ok(c) => {
                        entry.cid = c;
                        m.entries.push(entry);
                    }
                    Err(e) => m.unreadable.push(format!("want: {e:#}")),
                }
            }
            (2, PbValue::Varint(full)) => m.full = full != 0,
            _ => bail!("malformed wantlist (field {f})"),
        }
    }
    Ok(())
}

/// Encode a message in the format `version` speaks: 1.0.0 carries raw blocks (CIDv0 only)
/// and no presences; 1.1.0 carries prefixed blocks and no presences; 1.2.0 carries both.
pub fn encode(m: &Message, version: Version) -> Vec<u8> {
    let mut out = Vec::new();
    if !m.entries.is_empty() || m.full {
        let mut w = Vec::new();
        for e in &m.entries {
            let mut entry = Vec::new();
            let cid = if version == Version::V100 {
                // 1.0.0 names blocks by their multihash, as CIDv0 did.
                e.cid.multihash()
            } else {
                e.cid.to_bytes()
            };
            pb_bytes(&mut entry, 1, &cid);
            pb_varint(&mut entry, 2, e.priority as u32 as u64);
            if e.cancel {
                pb_varint(&mut entry, 3, 1);
            }
            if version == Version::V120 {
                if e.want_type == WantType::Have {
                    pb_varint(&mut entry, 4, 1);
                }
                if e.send_dont_have {
                    pb_varint(&mut entry, 5, 1);
                }
            }
            pb_bytes(&mut w, 1, &entry);
        }
        if m.full {
            pb_varint(&mut w, 2, 1);
        }
        pb_bytes(&mut out, 1, &w);
    }
    for b in &m.blocks {
        if version == Version::V100 {
            pb_bytes(&mut out, 2, &b.data);
        } else {
            let mut block = Vec::new();
            pb_bytes(&mut block, 1, &b.cid.prefix());
            pb_bytes(&mut block, 2, &b.data);
            pb_bytes(&mut out, 3, &block);
        }
    }
    if version == Version::V120 {
        for (cid, have) in &m.presences {
            let mut p = Vec::new();
            pb_bytes(&mut p, 1, &cid.to_bytes());
            pb_varint(&mut p, 2, if *have { 0 } else { 1 });
            pb_bytes(&mut out, 4, &p);
        }
    }
    out
}

/// Split an answer into messages no longer than [`MAX_OUTGOING`] each.
pub fn split(m: Message) -> Vec<Message> {
    let mut out = Vec::new();
    let mut cur = Message {
        presences: m.presences,
        ..Default::default()
    };
    let mut size = cur.presences.len() * 48;
    for b in m.blocks {
        let len = b.data.len() + 64;
        if size + len > MAX_OUTGOING && (!cur.blocks.is_empty() || !cur.presences.is_empty()) {
            out.push(std::mem::take(&mut cur));
            size = 0;
        }
        size += len;
        cur.blocks.push(b);
    }
    if !cur.blocks.is_empty() || !cur.presences.is_empty() {
        out.push(cur);
    }
    out
}

/// Message and entry counts, one direction of a connection's Bitswap traffic.
#[derive(Default, Debug, Clone, Copy)]
pub struct Counts {
    pub messages: u64,
    pub want_block: u64,
    pub want_have: u64,
    pub cancel: u64,
    pub full: u64,
    pub blocks: u64,
    pub block_bytes: u64,
    pub have: u64,
    pub dont_have: u64,
}

impl std::fmt::Display for Counts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "messages={} want_block={} want_have={} cancel={} full={} blocks={} block_bytes={} have={} dont_have={}",
            self.messages,
            self.want_block,
            self.want_have,
            self.cancel,
            self.full,
            self.blocks,
            self.block_bytes,
            self.have,
            self.dont_have
        )
    }
}

impl Counts {
    /// Count one message going this way.
    pub fn message(&mut self, m: &Message) {
        self.messages += 1;
        self.full += u64::from(m.full);
        for e in &m.entries {
            match (e.cancel, e.want_type) {
                (true, _) => self.cancel += 1,
                (false, WantType::Block) => self.want_block += 1,
                (false, WantType::Have) => self.want_have += 1,
            }
        }
        self.blocks += m.blocks.len() as u64;
        self.block_bytes += m.blocks.iter().map(|b| b.data.len() as u64).sum::<u64>();
        self.have += m.presences.iter().filter(|p| p.1).count() as u64;
        self.dont_have += m.presences.iter().filter(|p| !p.1).count() as u64;
    }
}

// ---------------------------------------------------------------------------------------
// Serving: what the model supplied, checked against what was wanted.

/// The form a supplied block's content takes on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    /// codec raw: the block is the content.
    Raw,
    /// codec dag-pb: a single-block UnixFS file holding the content.
    UnixFsFile,
}

impl Format {
    pub fn parse(s: &str) -> Result<Format> {
        match s {
            "raw" => Ok(Format::Raw),
            "unixfs" | "unixfs-file" | "file" => Ok(Format::UnixFsFile),
            other => bail!("format must be raw or unixfs, not {other:?}"),
        }
    }
}

/// A block the model offered: its bytes as they will travel, and the CID it claimed, if any.
#[derive(Clone, Debug)]
pub struct Supplied {
    pub codec: u64,
    pub bytes: Vec<u8>,
    pub claimed: Option<Cid>,
}

impl Supplied {
    pub fn new(content: &[u8], format: Format, claimed: Option<Cid>) -> Result<Supplied> {
        let (codec, bytes) = match format {
            Format::Raw => (ipfs::RAW, content.to_vec()),
            Format::UnixFsFile => (ipfs::DAG_PB, ipfs::unixfs_file_block(content)),
        };
        ensure!(
            bytes.len() <= ipfs::MAX_BLOCK,
            "a block is at most {} bytes; this one would be {}",
            ipfs::MAX_BLOCK,
            bytes.len()
        );
        Ok(Supplied {
            codec,
            bytes,
            claimed,
        })
    }
    /// The CID these bytes actually have (version 1; a v0 want matches it too).
    pub fn cid(&self) -> Cid {
        Cid::v1(self.codec, &self.bytes)
    }
}

/// What to send back for one wantlist.
#[derive(Debug, Default)]
pub struct Answer {
    /// Blocks, each under the CID that was wanted (so the version the peer asked for).
    pub blocks: Vec<Block>,
    pub dont_have: Vec<Cid>,
    /// Supplied blocks that were not sent, and why.
    pub refused: Vec<String>,
}

/// Match the model's blocks to the wants. A want is satisfied only by a block whose codec
/// and sha2-256 digest are the wanted CID's — computed from the bytes, never taken from the
/// model. A supplied block that claims a CID its bytes do not hash to is refused. A want-have
/// is answered with the block itself (Bitswap allows it, and it spares the model a second
/// question whose answer has to hash the same). Wants left unsatisfied are answered
/// DONT_HAVE where the peer asked for that.
pub fn answer_wants(wants: &[Entry], supplied: &[Supplied]) -> Answer {
    let mut answer = Answer::default();
    let mut usable: Vec<(Cid, &Supplied)> = Vec::new();
    for s in supplied {
        let actual = s.cid();
        match s.claimed {
            Some(claimed) if !claimed.same_block(&actual) => answer.refused.push(format!(
                "a block claimed as {claimed} hashes to {actual}; not sent"
            )),
            _ => usable.push((actual, s)),
        }
    }
    let mut used = vec![false; usable.len()];
    for want in wants.iter().filter(|w| !w.cancel) {
        match usable.iter().position(|(c, _)| c.same_block(&want.cid)) {
            Some(i)
                if usable[i].1.bytes.len() <= ipfs::MAX_BLOCK
                    && want.cid.matches(&usable[i].1.bytes) =>
            {
                used[i] = true;
                answer.blocks.push(Block {
                    cid: want.cid,
                    data: usable[i].1.bytes.clone(),
                });
            }
            _ if want.send_dont_have => answer.dont_have.push(want.cid),
            _ => {}
        }
    }
    for (i, (cid, _)) in usable.iter().enumerate() {
        if !used[i] {
            answer
                .refused
                .push(format!("a block hashing to {cid} was not wanted; not sent"));
        }
    }
    answer
}

// ---------------------------------------------------------------------------------------
// Fetching: what arrived, checked against what was asked for.

/// Wants a dialler has outstanding, keyed by the block they name (codec and digest, so a v0
/// and a v1 want for one block are one want), with the text the model asked by.
#[derive(Default)]
pub struct WantSet {
    wants: HashMap<(u64, [u8; 32]), (Cid, WantType)>,
}

/// Outstanding wants one connection may hold.
pub const MAX_OUTSTANDING_WANTS: usize = 1024;

impl WantSet {
    pub fn add(&mut self, cid: Cid, want: WantType) -> Result<()> {
        cid.supported()?;
        let key = (cid.codec, cid.digest);
        if !self.wants.contains_key(&key) {
            ensure!(
                self.wants.len() < MAX_OUTSTANDING_WANTS,
                "{MAX_OUTSTANDING_WANTS} wants are already outstanding"
            );
        }
        self.wants.insert(key, (cid, want));
        Ok(())
    }
    pub fn remove(&mut self, cid: &Cid) -> Option<(Cid, WantType)> {
        self.wants.remove(&(cid.codec, cid.digest))
    }
    pub fn get(&self, cid: &Cid) -> Option<(Cid, WantType)> {
        self.wants.get(&(cid.codec, cid.digest)).copied()
    }
    pub fn len(&self) -> usize {
        self.wants.len()
    }
    pub fn is_empty(&self) -> bool {
        self.wants.is_empty()
    }
}

/// What a received message is worth reporting.
#[derive(Debug, Default)]
pub struct Received {
    /// Blocks whose bytes hash to an outstanding want, reported under the CID that was asked
    /// for. Each satisfies (and removes) its want.
    pub blocks: Vec<Block>,
    /// Presences for outstanding wants: (the CID asked for, have).
    pub presences: Vec<(Cid, bool)>,
    pub refused: Vec<String>,
}

/// Keep only the blocks that are what was asked for. A block's CID is computed from its own
/// bytes, so a block whose bytes were altered names a different CID, which nothing wanted;
/// it is refused, never reported.
pub fn accept_blocks(m: &Message, wants: &mut WantSet) -> Received {
    let mut r = Received::default();
    for b in &m.blocks {
        match wants.get(&b.cid) {
            Some((asked, _)) if b.cid.supported().is_ok() && asked.matches(&b.data) => {
                wants.remove(&asked);
                r.blocks.push(Block {
                    cid: asked,
                    data: b.data.clone(),
                });
            }
            _ => r.refused.push(format!(
                "a {}-byte block hashing to {} matches nothing that was wanted; refused",
                b.data.len(),
                b.cid
            )),
        }
    }
    for (cid, have) in &m.presences {
        if let Some((asked, _)) = wants.get(cid) {
            if !*have {
                wants.remove(&asked);
            }
            r.presences.push((asked, *have));
        }
    }
    r.refused.extend(m.unreadable.iter().cloned());
    r
}

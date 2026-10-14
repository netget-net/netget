//! The IPFS data model, minimally: multihashes (sha2-256 only), CIDv0 and CIDv1 in binary and
//! text (base58btc, and base32 as `b…`), the `raw` and `dag-pb` codecs, and UnixFS nodes.
//!
//! A block's CID is always computed here from its bytes. Nothing a peer or the model says
//! about a block's identity is taken on trust: a block is sent, or reported, only when its
//! bytes hash to the CID it is sent or reported under.
//!
//! Protobuf nesting is fixed by the schema (PBNode → PBLink, PBNode.Data → UnixFS Data); no
//! decoder here recurses, so a peer cannot buy stack depth.
use super::wire::{base58, get_uvarint, pb_bytes, pb_fields_bounded, pb_varint, put_uvarint};
use super::wire::{unbase58, PbValue};
use anyhow::{bail, ensure, Context, Result};
use sha2::Digest;

/// Multicodec `raw`: the block is the bytes.
pub const RAW: u64 = 0x55;
/// Multicodec `dag-pb`: a protobuf PBNode, the codec UnixFS is written in.
pub const DAG_PB: u64 = 0x70;
/// Multihash `sha2-256`, 32-byte digests.
pub const SHA2_256: u64 = 0x12;
/// A block is at most this long (Bitswap's own limit, which Kubo enforces too).
pub const MAX_BLOCK: usize = 2 * 1024 * 1024;
/// A CID in text is at most this long; a sha2-256 CIDv1 in base32 is 59 characters.
pub const MAX_CID_TEXT: usize = 128;
/// Links one dag-pb node may carry before it is refused (Kubo writes at most 174 per file
/// node and 1024-ish per directory shard).
pub const MAX_LINKS: usize = 4096;

/// A content identifier: version, codec and a sha2-256 digest. Other hash functions are not
/// representable, so a CID naming one is refused at parse time.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Cid {
    pub version: u8,
    pub codec: u64,
    pub digest: [u8; 32],
}

/// Why a CID is not one NetGet can serve or verify.
pub fn codec_name(codec: u64) -> String {
    match codec {
        RAW => "raw".into(),
        DAG_PB => "dag-pb".into(),
        0x71 => "dag-cbor".into(),
        0x0129 => "dag-json".into(),
        0x72 => "libp2p-key".into(),
        c => format!("{c:#x}"),
    }
}

fn hash_name(code: u64) -> String {
    match code {
        0x00 => "identity".into(),
        0x11 => "sha1".into(),
        0x12 => "sha2-256".into(),
        0x13 => "sha2-512".into(),
        0x1e => "blake3".into(),
        0xb220 => "blake2b-256".into(),
        c => format!("{c:#x}"),
    }
}

/// `sha2-256` multihash of `data`: the 34 bytes `0x12 0x20 ‖ digest`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

/// A multihash's digest, refusing every function but sha2-256 with 32-byte output.
pub fn parse_multihash(b: &[u8]) -> Result<([u8; 32], usize)> {
    let (code, n) = get_uvarint(b)?;
    let (len, m) = get_uvarint(&b[n..])?;
    ensure!(
        code == SHA2_256,
        "multihash function {} is not supported (only sha2-256)",
        hash_name(code)
    );
    ensure!(
        len == 32,
        "a sha2-256 multihash must be 32 bytes, not {len}"
    );
    let start = n + m;
    ensure!(b.len() >= start + 32, "truncated multihash");
    let mut d = [0u8; 32];
    d.copy_from_slice(&b[start..start + 32]);
    Ok((d, start + 32))
}

pub fn multihash_bytes(digest: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![SHA2_256 as u8, 32];
    out.extend_from_slice(digest);
    out
}

impl Cid {
    pub fn v1(codec: u64, data: &[u8]) -> Cid {
        Cid {
            version: 1,
            codec,
            digest: sha256(data),
        }
    }
    /// Whether `data` hashes to this CID. The codec is the sender's claim about the bytes; the
    /// digest is what is checked.
    pub fn matches(&self, data: &[u8]) -> bool {
        sha256(data) == self.digest
    }
    /// The same block under any CID version: two CIDs name the same block when codec and
    /// digest agree.
    pub fn same_block(&self, other: &Cid) -> bool {
        self.codec == other.codec && self.digest == other.digest
    }
    pub fn multihash(&self) -> Vec<u8> {
        multihash_bytes(&self.digest)
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.version == 0 {
            return self.multihash();
        }
        let mut out = Vec::with_capacity(38);
        put_uvarint(&mut out, 1);
        put_uvarint(&mut out, self.codec);
        out.extend(self.multihash());
        out
    }
    /// Binary CID: v0 is a bare sha2-256 multihash, v1 is `0x01 ‖ codec ‖ multihash`.
    pub fn from_bytes(b: &[u8]) -> Result<Cid> {
        ensure!(!b.is_empty(), "empty CID");
        if b.len() == 34 && b[0] == SHA2_256 as u8 && b[1] == 32 {
            let (digest, _) = parse_multihash(b)?;
            return Ok(Cid {
                version: 0,
                codec: DAG_PB,
                digest,
            });
        }
        let (version, n) = get_uvarint(b)?;
        ensure!(version == 1, "CID version {version} is not supported");
        let (codec, m) = get_uvarint(&b[n..])?;
        let (digest, used) = parse_multihash(&b[n + m..])?;
        ensure!(n + m + used == b.len(), "trailing bytes after the CID");
        Ok(Cid {
            version: 1,
            codec,
            digest,
        })
    }
    /// Refuse codecs NetGet cannot interpret (everything but raw and dag-pb).
    pub fn supported(&self) -> Result<()> {
        ensure!(
            self.codec == RAW || self.codec == DAG_PB,
            "codec {} is not supported (only raw and dag-pb)",
            codec_name(self.codec)
        );
        Ok(())
    }
    /// Bitswap's block prefix: version, codec, hash function, digest length.
    pub fn prefix(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_uvarint(&mut out, u64::from(self.version));
        put_uvarint(&mut out, self.codec);
        put_uvarint(&mut out, SHA2_256);
        put_uvarint(&mut out, 32);
        out
    }
    /// The CID a Bitswap 1.1+ block names: its prefix applied to its bytes.
    pub fn from_prefix(prefix: &[u8], data: &[u8]) -> Result<Cid> {
        let mut b = prefix;
        let mut next = || -> Result<u64> {
            let (v, n) = get_uvarint(b)?;
            b = &b[n..];
            Ok(v)
        };
        let (version, codec, hash, len) = (next()?, next()?, next()?, next()?);
        ensure!(version <= 1, "CID version {version} is not supported");
        ensure!(
            hash == SHA2_256,
            "multihash function {} is not supported (only sha2-256)",
            hash_name(hash)
        );
        ensure!(len == 32, "a sha2-256 digest is 32 bytes, not {len}");
        ensure!(
            version == 1 || codec == DAG_PB,
            "a CIDv0 is always dag-pb, not {}",
            codec_name(codec)
        );
        Ok(Cid {
            version: version as u8,
            codec,
            digest: sha256(data),
        })
    }
    /// Text: `Qm…` (base58btc) for v0, `b…` (base32, lower case) for v1.
    pub fn parse(text: &str) -> Result<Cid> {
        let s = text.trim();
        ensure!(!s.is_empty(), "empty CID");
        ensure!(
            s.len() <= MAX_CID_TEXT,
            "CID text longer than {MAX_CID_TEXT}"
        );
        if s.len() == 46 && s.starts_with("Qm") {
            return Cid::from_bytes(&unbase58(s)?);
        }
        let (base, rest) = s.split_at(1);
        let bytes = match base {
            "b" => base32_decode(rest)?,
            "B" => base32_decode(&rest.to_ascii_lowercase())?,
            "z" => unbase58(rest)?,
            "f" | "F" => hex::decode(rest).context("not a base16 CID")?,
            _ => bail!("{s:?} is not a CID (expected Qm… or a base32 b… / base58 z… CIDv1)"),
        };
        let cid = Cid::from_bytes(&bytes).with_context(|| format!("{s:?} is not a CID"))?;
        ensure!(cid.version == 1, "a multibase CID must be version 1");
        Ok(cid)
    }
}

impl std::fmt::Display for Cid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.version == 0 {
            write!(f, "{}", base58(&self.to_bytes()))
        } else {
            write!(f, "b{}", base32_encode(&self.to_bytes()))
        }
    }
}

/// Every CID text a sha2-256 digest can stand for, in the two codecs NetGet knows: what a
/// DHT key (a bare multihash) may mean.
pub fn cids_for_digest(digest: &[u8; 32]) -> Vec<String> {
    let v0 = Cid {
        version: 0,
        codec: DAG_PB,
        digest: *digest,
    };
    let v1pb = Cid { version: 1, ..v0 };
    let v1raw = Cid { codec: RAW, ..v1pb };
    vec![v0.to_string(), v1pb.to_string(), v1raw.to_string()]
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32, lower case, no padding (multibase `b`).
pub fn base32_encode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &byte in b {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = B32
            .iter()
            .position(|&x| x == c)
            .with_context(|| format!("{:?} is not base32", c as char))? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// dag-pb and UnixFS

/// A dag-pb link: the child's CID, its name in a directory, and the size of its subtree.
#[derive(Clone, Debug, PartialEq)]
pub struct Link {
    pub cid: Cid,
    pub name: String,
    pub size: u64,
}

/// What a UnixFS node says about itself.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct UnixFs {
    /// raw, directory, file, metadata, symlink, hamt-shard.
    pub kind: String,
    pub data: Vec<u8>,
    pub file_size: Option<u64>,
    pub block_sizes: Vec<u64>,
}

/// A decoded dag-pb node.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct PbNode {
    pub links: Vec<Link>,
    pub data: Option<Vec<u8>>,
}

fn unixfs_kind(t: u64) -> String {
    match t {
        0 => "raw",
        1 => "directory",
        2 => "file",
        3 => "metadata",
        4 => "symlink",
        5 => "hamt-shard",
        _ => "unknown",
    }
    .into()
}

/// The canonical dag-pb encoding: every link (field 2) before the data (field 1).
pub fn encode_pb_node(node: &PbNode) -> Vec<u8> {
    let mut out = Vec::new();
    for l in &node.links {
        let mut link = Vec::new();
        pb_bytes(&mut link, 1, &l.cid.to_bytes());
        pb_bytes(&mut link, 2, l.name.as_bytes());
        pb_varint(&mut link, 3, l.size);
        pb_bytes(&mut out, 2, &link);
    }
    if let Some(d) = &node.data {
        pb_bytes(&mut out, 1, d);
    }
    out
}

pub fn decode_pb_node(b: &[u8]) -> Result<PbNode> {
    let mut node = PbNode::default();
    for (f, v) in pb_fields_bounded(b, MAX_LINKS + 1)? {
        match (f, v) {
            (1, PbValue::Bytes(d)) => node.data = Some(d.to_vec()),
            (2, PbValue::Bytes(l)) => {
                let (mut hash, mut name, mut size) = (None, String::new(), 0);
                for (lf, lv) in pb_fields_bounded(l, 16)? {
                    match (lf, lv) {
                        (1, PbValue::Bytes(h)) => hash = Some(Cid::from_bytes(h)?),
                        (2, PbValue::Bytes(n)) => {
                            name =
                                String::from_utf8(n.to_vec()).context("link name is not UTF-8")?
                        }
                        (3, PbValue::Varint(s)) => size = s,
                        _ => bail!("malformed dag-pb link"),
                    }
                }
                node.links.push(Link {
                    cid: hash.context("a dag-pb link has no hash")?,
                    name,
                    size,
                });
            }
            _ => bail!("malformed dag-pb node (field {f})"),
        }
    }
    Ok(node)
}

/// UnixFS `Data`: Type, Data, filesize, blocksizes, in field order as go-unixfs writes them.
pub fn encode_unixfs(u: &UnixFs) -> Vec<u8> {
    let kind = match u.kind.as_str() {
        "raw" => 0,
        "directory" => 1,
        "metadata" => 3,
        "symlink" => 4,
        "hamt-shard" => 5,
        _ => 2,
    };
    let mut out = Vec::new();
    pb_varint(&mut out, 1, kind);
    if !u.data.is_empty() {
        pb_bytes(&mut out, 2, &u.data);
    }
    if let Some(s) = u.file_size {
        pb_varint(&mut out, 3, s);
    }
    for s in &u.block_sizes {
        pb_varint(&mut out, 4, *s);
    }
    out
}

pub fn decode_unixfs(b: &[u8]) -> Result<UnixFs> {
    let mut u = UnixFs::default();
    let mut kind = None;
    for (f, v) in pb_fields_bounded(b, MAX_LINKS + 16)? {
        match (f, v) {
            (1, PbValue::Varint(t)) => kind = Some(t),
            (2, PbValue::Bytes(d)) => u.data = d.to_vec(),
            (3, PbValue::Varint(s)) => u.file_size = Some(s),
            (4, PbValue::Varint(s)) => u.block_sizes.push(s),
            // hashType, fanout, mode, mtime: read past.
            (5..=8, _) => {}
            _ => bail!("malformed UnixFS data (field {f})"),
        }
    }
    u.kind = unixfs_kind(kind.context("UnixFS data has no type")?);
    Ok(u)
}

/// A single-block UnixFS file holding `content`, as `ipfs add` writes a file no larger than
/// its chunk size when it does not use raw leaves.
pub fn unixfs_file_block(content: &[u8]) -> Vec<u8> {
    encode_pb_node(&PbNode {
        links: Vec::new(),
        data: Some(encode_unixfs(&UnixFs {
            kind: "file".into(),
            data: content.to_vec(),
            file_size: Some(content.len() as u64),
            block_sizes: Vec::new(),
        })),
    })
}

/// What a block looks like to whoever receives it: its codec, and for dag-pb its UnixFS
/// meaning and links.
pub struct Described {
    pub codec: &'static str,
    /// The bytes worth showing: the block for raw, the UnixFS data for a dag-pb file.
    pub content: Vec<u8>,
    pub unixfs_type: Option<String>,
    pub file_size: Option<u64>,
    pub links: Vec<Link>,
}

pub fn describe(cid: &Cid, data: &[u8]) -> Result<Described> {
    match cid.codec {
        RAW => Ok(Described {
            codec: "raw",
            content: data.to_vec(),
            unixfs_type: None,
            file_size: None,
            links: Vec::new(),
        }),
        DAG_PB => {
            let node = decode_pb_node(data)?;
            let u = node.data.as_deref().map(decode_unixfs).transpose()?;
            Ok(Described {
                codec: "dag-pb",
                content: u.as_ref().map(|u| u.data.clone()).unwrap_or_default(),
                unixfs_type: u.as_ref().map(|u| u.kind.clone()),
                file_size: u.as_ref().and_then(|u| u.file_size),
                links: node.links,
            })
        }
        c => bail!("codec {} is not supported", codec_name(c)),
    }
}

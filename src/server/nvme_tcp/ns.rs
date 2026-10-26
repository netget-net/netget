//! A subsystem as the model describes it when it admits a host: its namespaces, each a disk
//! described like an NBD export or an iSCSI LUN (size, extents, failing regions — see
//! `src/server/described_disk.rs`), with a block size and whether writes are accepted, and the
//! controller's identity. Reads are served by Rust from the description.
//!
//! **Writes.** A namespace the model marks `writable` takes writes into an in-memory overlay
//! owned by the controller (the association a host made with its admin queue Connect): every
//! I/O queue of that controller reads it back, and it is discarded when the controller goes —
//! the admin queue closes, or keep-alive expires. Nothing is written to a file and nothing
//! outlives the association, which is the project's rule that protocols keep no storage; the
//! overlay is what a drive holds between a Write and the next Read while the host is attached.
//! A namespace not marked writable answers every write NAMESPACE IS WRITE PROTECTED, and
//! Identify Namespace says so (NSATTR bit 0), so the Linux host makes its block device
//! read-only.
use super::nvme::{self, Status};
use crate::server::described_disk::{self as disk, ErrorRegion, Extent};
use anyhow::{bail, ensure, Context, Result};
use serde_json::Value as Json;
use std::collections::BTreeMap;

/// Namespaces one subsystem may present, and the highest NSID (Identify's NN).
pub const MAX_NAMESPACES: usize = 64;
pub const MAX_NSID: u32 = 1024;
/// A namespace is at most 64 TiB.
pub const MAX_NAMESPACE_BYTES: u64 = 64 << 40;
/// Bytes one controller may hold in its write overlay.
pub const MAX_OVERLAY_BYTES: usize = 64 * 1024 * 1024;
/// The most one Copy moves, and the source ranges it may name (Identify Namespace MCL and
/// MSRC).
pub const MAX_COPY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_COPY_RANGES: usize = 128;
/// What one block the overlay records as zeroes (Write Zeroes, deallocate) is charged.
const ZERO_BLOCK_COST: usize = 32;

/// What a failing region does to a command touching it.
pub const ERROR_MEDIUM: u32 = 1;
pub const ERROR_HARDWARE: u32 = 2;

fn error_code(name: &str) -> Option<u32> {
    match name {
        "medium_error" => Some(ERROR_MEDIUM),
        "hardware_error" => Some(ERROR_HARDWARE),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct Namespace {
    pub nsid: u32,
    pub block_size: u32,
    pub blocks: u64,
    pub extents: Vec<Extent>,
    pub errors: Vec<ErrorRegion>,
    pub writable: bool,
    pub nguid: [u8; 16],
    pub eui64: [u8; 8],
    pub uuid: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct SubsystemDescription {
    pub nqn: String,
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub namespaces: Vec<Namespace>,
    /// The host must prove itself with DH-HMAC-CHAP before anything else (the model's
    /// `require_authentication`).
    pub require_authentication: bool,
}

fn text_field(v: &Json, key: &str, max: usize) -> Result<Option<String>> {
    match v.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(s)) => {
            ensure!(
                s.len() <= max && s.bytes().all(|b| (0x20..0x7F).contains(&b)),
                "{key} is printable ASCII of at most {max} bytes"
            );
            Ok(Some(s.clone()))
        }
        _ => bail!("{key} is text"),
    }
}

/// Sixteen stable bytes for a name, so the same subsystem and NSID always carry the same
/// identifiers (the Linux host refuses a namespace whose identifiers change under it).
pub fn derived_id(parts: &[&str]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0]);
    }
    h.finalize()[..16].try_into().expect("16 bytes")
}

fn hex_id<const N: usize>(v: &Json, key: &str) -> Result<Option<[u8; N]>> {
    match v.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(s)) => {
            let b = hex::decode(s.replace('-', "")).with_context(|| format!("{key} is hex"))?;
            let a: [u8; N] = b
                .try_into()
                .map_err(|_| anyhow::anyhow!("{key} is {N} bytes of hex"))?;
            ensure!(a.iter().any(|x| *x != 0), "{key} is not all zeroes");
            Ok(Some(a))
        }
        _ => bail!("{key} is hex text"),
    }
}

impl SubsystemDescription {
    /// The subsystem an `nvme_tcp_accept_connect` action describes.
    pub fn from_action(v: &Json, nqn: &str) -> Result<Self> {
        let Some(list) = v.get("namespaces").and_then(Json::as_array) else {
            bail!("namespaces is an array of the subsystem's namespaces");
        };
        ensure!(
            !list.is_empty() && list.len() <= MAX_NAMESPACES,
            "a subsystem has 1 to {MAX_NAMESPACES} namespaces"
        );
        let mut out: Vec<Namespace> = Vec::new();
        let mut content = 0usize;
        for (i, n) in list.iter().enumerate() {
            let nsid = match n.get("nsid") {
                None | Some(Json::Null) => i as u64 + 1,
                Some(x) => x.as_u64().context("nsid is a number")?,
            };
            ensure!(
                (1..=MAX_NSID as u64).contains(&nsid),
                "nsid is 1 to {MAX_NSID}"
            );
            let nsid = nsid as u32;
            ensure!(
                out.iter().all(|o| o.nsid != nsid),
                "namespace {nsid} is described twice"
            );
            let block_size = match n.get("block_size") {
                None | Some(Json::Null) => 512,
                Some(b) => b.as_u64().context("block_size is a number")?,
            };
            ensure!(
                matches!(block_size, 512 | 1024 | 2048 | 4096),
                "block_size is 512, 1024, 2048 or 4096"
            );
            let size = disk::u64_of(n, "size")?;
            ensure!(
                size > 0 && size <= MAX_NAMESPACE_BYTES,
                "size is between one block and 64 TiB"
            );
            // A size that is not a whole number of blocks is rounded up; the tail reads as
            // zeroes like anything else no extent covers.
            let blocks = size.div_ceil(block_size);
            let bytes = blocks * block_size;
            let extents = disk::parse_extents(n, bytes)?;
            for e in &extents {
                if let disk::Content::Bytes(b) = &e.content {
                    content += b.len();
                }
            }
            ensure!(
                content <= disk::MAX_CONTENT,
                "the namespaces carry more than {} bytes of explicit content",
                disk::MAX_CONTENT
            );
            let errors = disk::parse_errors(
                n,
                bytes,
                error_code,
                "medium_error",
                "medium_error or hardware_error",
            )?;
            let writable = match n.get("writable") {
                None | Some(Json::Null) => false,
                Some(w) => w.as_bool().context("writable is true or false")?,
            };
            let id = derived_id(&[nqn, &nsid.to_string()]);
            let nguid = hex_id::<16>(n, "nguid")?.unwrap_or(id);
            let uuid = hex_id::<16>(n, "uuid")?.unwrap_or_else(|| {
                let mut u = derived_id(&[nqn, &nsid.to_string(), "uuid"]);
                // RFC 9562 version 8 (vendor-specific), variant 10.
                u[6] = (u[6] & 0x0F) | 0x80;
                u[8] = (u[8] & 0x3F) | 0x80;
                u
            });
            let eui64 =
                hex_id::<8>(n, "eui64")?.unwrap_or_else(|| id[8..16].try_into().expect("8 bytes"));
            out.push(Namespace {
                nsid,
                block_size: block_size as u32,
                blocks,
                extents,
                errors,
                writable,
                nguid,
                eui64,
                uuid,
            });
        }
        out.sort_by_key(|n| n.nsid);
        let serial = text_field(v, "serial", 20)?.unwrap_or_else(|| default_serial(nqn));
        ensure!(!serial.trim().is_empty(), "serial is not blank");
        Ok(Self {
            nqn: nqn.to_string(),
            model: text_field(v, "model", 40)?.unwrap_or_else(|| "NetGet NVMe/TCP".into()),
            serial,
            firmware: text_field(v, "firmware", 8)?.unwrap_or_else(|| "1.0".into()),
            namespaces: out,
            require_authentication: match v.get("require_authentication") {
                None | Some(Json::Null) => false,
                Some(b) => b
                    .as_bool()
                    .context("require_authentication is true or false")?,
            },
        })
    }

    pub fn namespace(&self, nsid: u32) -> Option<&Namespace> {
        self.namespaces.iter().find(|n| n.nsid == nsid)
    }

    /// Identify's NN: the highest NSID this subsystem may hold.
    pub fn nn(&self) -> u32 {
        self.namespaces.iter().map(|n| n.nsid).max().unwrap_or(0)
    }
}

/// A stable serial for a subsystem the model gave none, derived from its NQN.
pub fn default_serial(nqn: &str) -> String {
    format!("NG{}", hex::encode_upper(&derived_id(&[nqn])[..9]))
}

impl Namespace {
    /// Whether `blocks` blocks from `lba` lie inside the namespace.
    pub fn in_range(&self, lba: u64, blocks: u64) -> bool {
        lba.checked_add(blocks)
            .is_some_and(|end| end <= self.blocks)
    }

    /// The status a failing region gives a range, if it touches one.
    pub fn failure(&self, lba: u64, blocks: u64, write: bool) -> Option<Status> {
        let bs = self.block_size as u64;
        let (_, code) = disk::error_in(&self.errors, lba * bs, blocks * bs)?;
        Some(match (code, write) {
            (ERROR_HARDWARE, _) => Status::INTERNAL_ERROR,
            (_, false) => Status::UNRECOVERED_READ_ERROR,
            (_, true) => Status::WRITE_FAULT,
        })
    }

    /// The bytes of `blocks` blocks from `lba`, with the controller's writes over the
    /// description.
    pub fn read(&self, lba: u64, blocks: u64, overlay: &Overlay) -> Vec<u8> {
        let bs = self.block_size as usize;
        let mut out = disk::read(&self.extents, lba * bs as u64, blocks as usize * bs);
        if overlay.blocks.is_empty() {
            return out;
        }
        for (key, block) in overlay
            .blocks
            .range((self.nsid, lba)..(self.nsid, lba + blocks))
        {
            let i = (key.1 - lba) as usize;
            let dst = &mut out[i * bs..(i + 1) * bs];
            match block {
                Some(b) => dst.copy_from_slice(b),
                None => dst.fill(0),
            }
        }
        out
    }

    /// Copy limits in blocks: MSSRL (one source range) and MCL (the whole Copy).
    pub fn copy_limits(&self) -> (u16, u32) {
        let mcl = (MAX_COPY_BYTES / self.block_size as usize) as u32;
        (mcl.min(u16::MAX as u32) as u16, mcl)
    }

    /// LBA format 0, the one this namespace uses: LBADS = log2(block size).
    pub fn lbads(&self) -> u8 {
        self.block_size.trailing_zeros() as u8
    }

    /// Identify Namespace (CNS 00h).
    pub fn identify(&self) -> Vec<u8> {
        let mut b = vec![0u8; nvme::IDENTIFY_LEN];
        b[0..8].copy_from_slice(&self.blocks.to_le_bytes()); // NSZE
        b[8..16].copy_from_slice(&self.blocks.to_le_bytes()); // NCAP
        b[16..24].copy_from_slice(&self.blocks.to_le_bytes()); // NUSE
        b[25] = 0; // NLBAF: one format
        b[26] = 0; // FLBAS: format 0, no metadata
        b[30] = 1; // NMIC: may be attached to more than one controller
                   // DLFEAT 0: what a deallocated block reads as is not reported, because Dataset
                   // Management's deallocate is taken as the hint it is and changes nothing.
        b[33] = 0;
        b[31] = super::resv::RESCAP;
        let (mssrl, mcl) = self.copy_limits();
        b[74..76].copy_from_slice(&mssrl.to_le_bytes()); // MSSRL
        b[76..80].copy_from_slice(&mcl.to_le_bytes()); // MCL
        b[80] = (MAX_COPY_RANGES - 1) as u8; // MSRC, 0's based
        b[99] = if self.writable { 0 } else { 1 }; // NSATTR: write protected
        b[104..120].copy_from_slice(&self.nguid);
        b[120..128].copy_from_slice(&self.eui64);
        // LBAF0: no metadata, LBADS, best relative performance.
        b[128..132].copy_from_slice(&((self.lbads() as u32) << 16).to_le_bytes());
        b
    }

    /// Namespace identification descriptors (CNS 03h): EUI-64, NGUID, UUID and the command set
    /// identifier (NVM).
    pub fn descriptors(&self) -> Vec<u8> {
        let mut b = vec![0u8; nvme::IDENTIFY_LEN];
        let mut at = 0;
        for (t, v) in [
            (1u8, self.eui64.as_slice()),
            (2, self.nguid.as_slice()),
            (3, self.uuid.as_slice()),
            (4, &[0u8][..]),
        ] {
            b[at] = t;
            b[at + 1] = v.len() as u8;
            b[at + 4..at + 4 + v.len()].copy_from_slice(v);
            at += 4 + v.len();
        }
        b
    }
}

/// A controller's writes, block by block (`None`: a block written as zeroes). Discarded with
/// the controller.
#[derive(Default, Debug)]
pub struct Overlay {
    blocks: BTreeMap<(u32, u64), Option<Box<[u8]>>>,
    bytes: usize,
}

impl Overlay {
    fn cost(block: &Option<Box<[u8]>>) -> usize {
        block.as_ref().map_or(ZERO_BLOCK_COST, |b| b.len())
    }

    fn put(&mut self, nsid: u32, lba: u64, block: Option<Box<[u8]>>) {
        let cost = Self::cost(&block);
        if let Some(old) = self.blocks.insert((nsid, lba), block) {
            self.bytes -= Self::cost(&old);
        }
        self.bytes += cost;
    }

    /// Whether `extra` more bytes fit.
    fn fits(&self, extra: usize) -> bool {
        self.bytes.saturating_add(extra) <= MAX_OVERLAY_BYTES
    }

    /// Keep a write; refused whole when it would take the overlay past its bound.
    pub fn write(&mut self, ns: &Namespace, lba: u64, data: &[u8]) -> Result<(), Status> {
        let bs = ns.block_size as usize;
        if !self.fits(data.len()) {
            return Err(Status::CAPACITY_EXCEEDED);
        }
        for (i, chunk) in data.chunks(bs).enumerate() {
            let mut block = vec![0u8; bs].into_boxed_slice();
            block[..chunk.len()].copy_from_slice(chunk);
            self.put(ns.nsid, lba + i as u64, Some(block));
        }
        Ok(())
    }

    /// Record `blocks` blocks from `lba` as zeroes (Write Zeroes, or a deallocated range).
    pub fn zero(&mut self, ns: &Namespace, lba: u64, blocks: u64) -> Result<(), Status> {
        let n = usize::try_from(blocks).map_err(|_| Status::CAPACITY_EXCEEDED)?;
        if !self.fits(n.saturating_mul(ZERO_BLOCK_COST)) {
            return Err(Status::CAPACITY_EXCEEDED);
        }
        for i in 0..blocks {
            self.put(ns.nsid, lba + i, None);
        }
        Ok(())
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

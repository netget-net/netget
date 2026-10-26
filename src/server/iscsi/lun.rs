//! A target as the model describes it: its logical units, each a disk described like an NBD
//! export (size, extents, failing regions), with a block size, an identity and whether writes
//! are accepted. Reads are served by Rust from the description.
//!
//! **Writes.** A LUN the model marks `writable` accepts writes into an in-memory overlay that
//! belongs to the session: it is read back by that session and discarded when the session
//! ends. Nothing is written to a file and nothing outlives the connection — the protocol keeps
//! no storage of its own, which is the project's rule; the overlay is what a SCSI device does
//! with a write between WRITE and the next READ, for as long as the initiator is attached. A
//! LUN not marked writable refuses every write with DATA PROTECT / WRITE PROTECTED.
use crate::server::described_disk::{self as disk, ErrorRegion, Extent};
use crate::server::scsi_common::{Identity, Sense};
use anyhow::{bail, ensure, Context, Result};
use serde_json::Value as Json;
use std::collections::HashMap;

/// LUNs one target may present, and the highest LUN number (flat space addressing).
pub const MAX_LUNS: usize = 256;
pub const MAX_LUN_NUMBER: u64 = 16383;
/// A LUN is at most 64 TiB (2^37 blocks of 512 bytes, past the 32-bit LBA of READ(10)).
pub const MAX_LUN_BYTES: u64 = 64 << 40;
/// Bytes of explicit content across every LUN of one description.
pub const MAX_TARGET_CONTENT: usize = disk::MAX_CONTENT;
/// Bytes one session may hold in its write overlay.
pub const MAX_OVERLAY_BYTES: usize = 64 * 1024 * 1024;

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
pub struct Lun {
    pub number: u16,
    pub block_size: u32,
    pub blocks: u64,
    pub extents: Vec<Extent>,
    pub errors: Vec<ErrorRegion>,
    pub writable: bool,
    pub identity: Identity,
    pub serial: String,
}

#[derive(Clone, Debug)]
pub struct TargetDescription {
    pub alias: Option<String>,
    pub luns: Vec<Lun>,
}

fn text_field(v: &Json, key: &str, max: usize) -> Result<Option<String>> {
    match v.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(s)) => {
            ensure!(s.len() <= max, "{key} is at most {max} bytes");
            Ok(Some(s.clone()))
        }
        _ => bail!("{key} is text"),
    }
}

impl TargetDescription {
    /// The target an `iscsi_accept_login` action describes.
    pub fn from_action(v: &Json, target_name: &str) -> Result<Self> {
        let Some(luns) = v.get("luns").and_then(Json::as_array) else {
            bail!("luns is an array of the target's logical units");
        };
        ensure!(
            !luns.is_empty() && luns.len() <= MAX_LUNS,
            "a target has 1 to {MAX_LUNS} LUNs"
        );
        let mut out: Vec<Lun> = Vec::new();
        let mut content = 0usize;
        for (i, l) in luns.iter().enumerate() {
            let number = match l.get("lun") {
                None | Some(Json::Null) => i as u64,
                Some(n) => n.as_u64().context("lun is a number")?,
            };
            ensure!(number <= MAX_LUN_NUMBER, "lun is at most {MAX_LUN_NUMBER}");
            let number = number as u16;
            ensure!(
                out.iter().all(|o| o.number != number),
                "LUN {number} is described twice"
            );
            let block_size = match l.get("block_size") {
                None | Some(Json::Null) => 512,
                Some(b) => b.as_u64().context("block_size is a number")?,
            };
            ensure!(
                matches!(block_size, 512 | 1024 | 2048 | 4096),
                "block_size is 512, 1024, 2048 or 4096"
            );
            let size = disk::u64_of(l, "size")?;
            ensure!(
                size > 0 && size <= MAX_LUN_BYTES,
                "size is between one block and 64 TiB"
            );
            // A size that is not a whole number of blocks is rounded up: the tail reads as
            // zeroes like anything else no extent covers.
            let blocks = size.div_ceil(block_size);
            let disk_bytes = blocks * block_size;
            let extents = disk::parse_extents(l, disk_bytes)?;
            for e in &extents {
                if let disk::Content::Bytes(b) = &e.content {
                    content += b.len();
                }
            }
            ensure!(
                content <= MAX_TARGET_CONTENT,
                "the LUNs carry more than {MAX_TARGET_CONTENT} bytes of explicit content"
            );
            let errors = disk::parse_errors(
                l,
                disk_bytes,
                error_code,
                "medium_error",
                "medium_error or hardware_error",
            )?;
            let writable = match l.get("writable") {
                None | Some(Json::Null) => false,
                Some(w) => w.as_bool().context("writable is true or false")?,
            };
            let vendor = text_field(l, "vendor", 8)?.unwrap_or_else(|| "NETGET".into());
            let product = text_field(l, "product", 16)?.unwrap_or_else(|| "VIRTUAL-DISK".into());
            let revision = text_field(l, "revision", 4)?.unwrap_or_else(|| "0001".into());
            let serial =
                text_field(l, "serial", 64)?.unwrap_or_else(|| default_serial(target_name, number));
            ensure!(
                serial.bytes().all(|b| (0x21..0x7F).contains(&b)),
                "serial is printable ASCII without spaces"
            );
            out.push(Lun {
                number,
                block_size: block_size as u32,
                blocks,
                extents,
                errors,
                writable,
                identity: Identity {
                    vendor,
                    product,
                    revision,
                },
                serial,
            });
        }
        out.sort_by_key(|l| l.number);
        Ok(Self {
            alias: text_field(v, "alias", 255)?,
            luns: out,
        })
    }

    pub fn lun(&self, number: u16) -> Option<&Lun> {
        self.luns.iter().find(|l| l.number == number)
    }
}

/// A stable serial for a LUN the model gave none: derived from the target name and number.
pub fn default_serial(target: &str, lun: u16) -> String {
    use md5::{Digest, Md5};
    let h = Md5::digest(format!("{target}/{lun}").as_bytes());
    format!("NG{}", hex::encode_upper(&h[..8]))
}

impl Lun {
    pub fn last_lba(&self) -> u64 {
        self.blocks - 1
    }

    /// Whether `blocks` blocks from `lba` lie inside the LUN.
    pub fn in_range(&self, lba: u64, blocks: u64) -> bool {
        lba.checked_add(blocks)
            .is_some_and(|end| end <= self.blocks)
    }

    /// The condition a failing region raises for a range, if it touches one.
    pub fn failure(&self, lba: u64, blocks: u64, write: bool) -> Option<Sense> {
        let bs = self.block_size as u64;
        let (at, code) = disk::error_in(&self.errors, lba * bs, blocks * bs)?;
        let sense = match (code, write) {
            (ERROR_HARDWARE, _) => Sense::INTERNAL_TARGET_FAILURE,
            (_, false) => Sense::UNRECOVERED_READ_ERROR,
            (_, true) => Sense::WRITE_ERROR,
        };
        Some(sense.with_info(at / bs))
    }

    /// The bytes of `blocks` blocks from `lba`, with the session's own writes over the
    /// description.
    pub fn read(&self, lba: u64, blocks: u64, overlay: &Overlay) -> Vec<u8> {
        let bs = self.block_size as usize;
        let mut out = disk::read(&self.extents, lba * bs as u64, blocks as usize * bs);
        if overlay.blocks.is_empty() {
            return out;
        }
        for i in 0..blocks {
            if let Some(b) = overlay.blocks.get(&(self.number, lba + i)) {
                out[i as usize * bs..(i as usize + 1) * bs].copy_from_slice(b);
            }
        }
        out
    }
}

/// A session's writes, block by block. Discarded with the session.
#[derive(Default)]
pub struct Overlay {
    blocks: HashMap<(u16, u64), Box<[u8]>>,
    bytes: usize,
}

impl Overlay {
    /// Keep a write; refused whole when it would take the overlay past its bound.
    pub fn write(&mut self, lun: &Lun, lba: u64, data: &[u8]) -> Result<(), Sense> {
        let bs = lun.block_size as usize;
        let new_blocks = data
            .chunks(bs)
            .enumerate()
            .filter(|(i, _)| !self.blocks.contains_key(&(lun.number, lba + *i as u64)))
            .count();
        if self.bytes + new_blocks * bs > MAX_OVERLAY_BYTES {
            return Err(Sense::SPACE_ALLOCATION_FAILED);
        }
        for (i, chunk) in data.chunks(bs).enumerate() {
            let mut block = vec![0u8; bs].into_boxed_slice();
            block[..chunk.len()].copy_from_slice(chunk);
            if self
                .blocks
                .insert((lun.number, lba + i as u64), block)
                .is_none()
            {
                self.bytes += bs;
            }
        }
        Ok(())
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl std::fmt::Debug for Overlay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Overlay({} blocks, {} bytes)",
            self.blocks.len(),
            self.bytes
        )
    }
}

//! NBD constants (the fixed newstyle handshake, options, transmission) and the read-only export
//! a handler describes: a size, data extents, fill extents and error regions; everything else
//! reads as zeroes.
use anyhow::{ensure, Context, Result};
use serde_json::Value as Json;

pub const NBDMAGIC: u64 = 0x4e42444d41474943;
pub const IHAVEOPT: u64 = 0x49484156454F5054;
pub const REPLY_MAGIC: u64 = 0x0003e889045565a9;
pub const REQUEST_MAGIC: u32 = 0x25609513;
pub const SIMPLE_REPLY_MAGIC: u32 = 0x67446698;
pub const STRUCTURED_REPLY_MAGIC: u32 = 0x668e33ef;

pub const FLAG_FIXED_NEWSTYLE: u16 = 1;
pub const FLAG_NO_ZEROES: u16 = 2;

pub const OPT_EXPORT_NAME: u32 = 1;
pub const OPT_ABORT: u32 = 2;
pub const OPT_LIST: u32 = 3;
pub const OPT_STARTTLS: u32 = 5;
pub const OPT_INFO: u32 = 6;
pub const OPT_GO: u32 = 7;
pub const OPT_STRUCTURED_REPLY: u32 = 8;
pub const OPT_LIST_META_CONTEXT: u32 = 9;
pub const OPT_SET_META_CONTEXT: u32 = 10;

pub const REP_ACK: u32 = 1;
pub const REP_SERVER: u32 = 2;
pub const REP_INFO: u32 = 3;
pub const REP_META_CONTEXT: u32 = 4;
pub const REP_ERR_UNSUP: u32 = 0x8000_0001;
pub const REP_ERR_POLICY: u32 = 0x8000_0002;
pub const REP_ERR_INVALID: u32 = 0x8000_0003;
pub const REP_ERR_UNKNOWN: u32 = 0x8000_0006;
pub const REP_ERR_TOO_BIG: u32 = 0x8000_0009;

pub const INFO_EXPORT: u16 = 0;
pub const INFO_NAME: u16 = 1;
pub const INFO_DESCRIPTION: u16 = 2;
pub const INFO_BLOCK_SIZE: u16 = 3;

pub const TFLAG_HAS_FLAGS: u16 = 1;
pub const TFLAG_READ_ONLY: u16 = 1 << 1;
pub const TFLAG_SEND_FLUSH: u16 = 1 << 2;
pub const TFLAG_SEND_DF: u16 = 1 << 7;
pub const TFLAG_CAN_MULTI_CONN: u16 = 1 << 8;
pub const TFLAG_SEND_CACHE: u16 = 1 << 10;

pub const CMD_READ: u16 = 0;
pub const CMD_WRITE: u16 = 1;
pub const CMD_DISC: u16 = 2;
pub const CMD_FLUSH: u16 = 3;
pub const CMD_TRIM: u16 = 4;
pub const CMD_CACHE: u16 = 5;
pub const CMD_WRITE_ZEROES: u16 = 6;
pub const CMD_BLOCK_STATUS: u16 = 7;
pub const CMD_FLAG_DF: u16 = 1 << 2;

pub const REPLY_FLAG_DONE: u16 = 1;
pub const REPLY_NONE: u16 = 0;
pub const REPLY_OFFSET_DATA: u16 = 1;
pub const REPLY_OFFSET_HOLE: u16 = 2;
pub const REPLY_BLOCK_STATUS: u16 = 5;
pub const REPLY_ERROR: u16 = 0x8001;
pub const REPLY_ERROR_OFFSET: u16 = 0x8002;

pub const EPERM: u32 = 1;
pub const EIO: u32 = 5;
pub const ENOMEM: u32 = 12;
pub const EINVAL: u32 = 22;
pub const ENOSPC: u32 = 28;
pub const ENOTSUP: u32 = 95;
pub const ESHUTDOWN: u32 = 108;

pub const BASE_ALLOCATION: &str = "base:allocation";
pub const STATE_HOLE: u32 = 1;
pub const STATE_ZERO: u32 = 2;

/// One request or option payload at most; a read or block status at most.
pub const MAX_OPTION: usize = 64 * 1024;
pub const MAX_REQUEST: u32 = 32 * 1024 * 1024;
/// Bytes of explicit content one export may carry, and extents.
pub use crate::server::described_disk::{Content, Extent, MAX_CONTENT, MAX_EXTENTS};
use crate::server::described_disk as disk;
use disk::u64_of;

pub fn errno(name: &str) -> Option<u32> {
    Some(match name {
        "EPERM" => EPERM,
        "EIO" => EIO,
        "ENOMEM" => ENOMEM,
        "EINVAL" => EINVAL,
        "ENOSPC" => ENOSPC,
        _ => return None,
    })
}

pub fn errno_name(n: u32) -> String {
    match n {
        0 => "OK".into(),
        EPERM => "EPERM".into(),
        EIO => "EIO".into(),
        ENOMEM => "ENOMEM".into(),
        EINVAL => "EINVAL".into(),
        ENOSPC => "ENOSPC".into(),
        75 => "EOVERFLOW".into(),
        ENOTSUP => "ENOTSUP".into(),
        ESHUTDOWN => "ESHUTDOWN".into(),
        n => format!("errno {n}"),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Export {
    pub size: u64,
    pub description: Option<String>,
    pub extents: Vec<Extent>,
    pub errors: Vec<(u64, u64, u32)>,
    pub block_min: u32,
    pub block_preferred: u32,
    pub block_max: u32,
}

/// A piece of a read: data, or a run of zeroes.
#[derive(Clone, Debug, PartialEq)]
pub enum Piece {
    Data(u64, Vec<u8>),
    Hole(u64, u32),
}

impl Export {
    /// The export an `nbd_export` action describes.
    pub fn from_action(v: &Json) -> Result<Self> {
        let size = u64_of(v, "size")?;
        ensure!(size <= 1 << 40, "size is at most 1 TiB");
        let extents = disk::parse_extents(v, size)?;
        let errors = disk::parse_errors(
            v,
            size,
            errno,
            "EIO",
            "EIO, EPERM, ENOMEM, EINVAL or ENOSPC",
        )?;
        let bs = v.get("block_size").filter(|b| !b.is_null());
        let get = |k: &str, d: u32| -> Result<u32> {
            match bs.and_then(|b| b.get(k)).filter(|x| !x.is_null()) {
                None => Ok(d),
                Some(x) => x
                    .as_u64()
                    .and_then(|x| u32::try_from(x).ok())
                    .with_context(|| format!("block_size.{k} is a number")),
            }
        };
        let (block_min, block_preferred, block_max) = (
            get("minimum", 1)?,
            get("preferred", 4096)?,
            get("maximum", MAX_REQUEST)?,
        );
        ensure!(
            block_min.is_power_of_two() && block_min <= 65536,
            "block_size.minimum is a power of two up to 64 KiB"
        );
        ensure!(
            block_preferred.is_power_of_two()
                && block_preferred >= block_min
                && block_preferred <= MAX_REQUEST,
            "block_size.preferred is a power of two between the minimum and 32 MiB"
        );
        ensure!(block_max >= block_preferred && block_max <= MAX_REQUEST && block_max % block_min == 0, "block_size.maximum is a multiple of the minimum, at least the preferred size, at most 32 MiB");
        let description = v
            .get("description")
            .and_then(Json::as_str)
            .map(str::to_owned);
        ensure!(
            description.as_ref().is_none_or(|d| d.len() <= 4096),
            "description is at most 4096 bytes"
        );
        Ok(Self {
            size,
            description,
            extents,
            errors,
            block_min,
            block_preferred,
            block_max,
        })
    }

    /// The first errored byte in a range, with its errno.
    pub fn error_in(&self, offset: u64, length: u64) -> Option<(u64, u32)> {
        disk::error_in(&self.errors, offset, length)
    }

    /// The bytes of a range, zeroes where no extent covers it.
    pub fn read(&self, offset: u64, length: u32) -> Vec<u8> {
        disk::read(&self.extents, offset, length as usize)
    }

    /// Covered (data) and uncovered (zero) runs of a range, in order.
    pub fn runs(&self, offset: u64, length: u64) -> Vec<(u64, u64, bool)> {
        disk::runs(&self.extents, offset, length)
    }

    /// A read as structured-reply pieces: data where extents are, holes elsewhere.
    pub fn pieces(&self, offset: u64, length: u32) -> Vec<Piece> {
        self.runs(offset, length as u64)
            .into_iter()
            .map(|(o, l, data)| {
                if data {
                    Piece::Data(o, self.read(o, l as u32))
                } else {
                    Piece::Hole(o, l as u32)
                }
            })
            .collect()
    }
}

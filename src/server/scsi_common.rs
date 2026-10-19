//! SCSI as the block servers speak it: opcodes, sense keys, sense data, INQUIRY and its vital
//! product data pages, READ CAPACITY, MODE SENSE, REPORT LUNS and the READ/WRITE CDB families,
//! in both directions — the builders a device answers with and the decoders a host reads with.
//!
//! The USB mass-storage device (`src/server/usb/msc`) and the iSCSI target answer from these;
//! the iSCSI initiator builds its CDBs and reads its answers with them. Nothing here does I/O
//! or knows a transport: a transport carries a CDB in and data, a status and sense out.
//!
//! References: SPC-4 (INQUIRY, sense, MODE SENSE, REPORT LUNS), SBC-3 (READ/WRITE, READ
//! CAPACITY, SYNCHRONIZE CACHE), SAM-5 (LUN addressing).

/// Command opcodes.
pub mod opcode {
    pub const TEST_UNIT_READY: u8 = 0x00;
    pub const REQUEST_SENSE: u8 = 0x03;
    pub const READ_6: u8 = 0x08;
    pub const WRITE_6: u8 = 0x0A;
    pub const INQUIRY: u8 = 0x12;
    pub const MODE_SENSE_6: u8 = 0x1A;
    pub const START_STOP_UNIT: u8 = 0x1B;
    pub const PREVENT_ALLOW_MEDIUM_REMOVAL: u8 = 0x1E;
    pub const READ_FORMAT_CAPACITIES: u8 = 0x23;
    pub const READ_CAPACITY_10: u8 = 0x25;
    pub const READ_10: u8 = 0x28;
    pub const WRITE_10: u8 = 0x2A;
    pub const SYNCHRONIZE_CACHE_10: u8 = 0x35;
    pub const MODE_SENSE_10: u8 = 0x5A;
    pub const READ_16: u8 = 0x88;
    pub const WRITE_16: u8 = 0x8A;
    pub const SYNCHRONIZE_CACHE_16: u8 = 0x91;
    /// SERVICE ACTION IN(16); READ CAPACITY(16) is its service action 0x10.
    pub const SERVICE_ACTION_IN_16: u8 = 0x9E;
    pub const REPORT_LUNS: u8 = 0xA0;
    pub const READ_12: u8 = 0xA8;
    pub const WRITE_12: u8 = 0xAA;
}

/// The READ CAPACITY(16) service action of SERVICE ACTION IN(16).
pub const SA_READ_CAPACITY_16: u8 = 0x10;

/// Sense keys.
pub mod sense_key {
    pub const NO_SENSE: u8 = 0x00;
    pub const RECOVERED_ERROR: u8 = 0x01;
    pub const NOT_READY: u8 = 0x02;
    pub const MEDIUM_ERROR: u8 = 0x03;
    pub const HARDWARE_ERROR: u8 = 0x04;
    pub const ILLEGAL_REQUEST: u8 = 0x05;
    pub const UNIT_ATTENTION: u8 = 0x06;
    pub const DATA_PROTECT: u8 = 0x07;
    pub const ABORTED_COMMAND: u8 = 0x0B;
}

/// Status bytes (SAM-5).
pub mod status {
    pub const GOOD: u8 = 0x00;
    pub const CHECK_CONDITION: u8 = 0x02;
    pub const BUSY: u8 = 0x08;
    pub const RESERVATION_CONFLICT: u8 = 0x18;
    pub const TASK_SET_FULL: u8 = 0x28;
    pub const TASK_ABORTED: u8 = 0x40;
}

/// A sense condition: key, additional sense code and qualifier, and the INFORMATION field
/// (the first failing LBA of a medium error) when there is one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sense {
    pub key: u8,
    pub asc: u8,
    pub ascq: u8,
    pub info: Option<u64>,
}

impl Sense {
    pub const fn new(key: u8, asc: u8, ascq: u8) -> Self {
        Self {
            key,
            asc,
            ascq,
            info: None,
        }
    }
    pub const INVALID_OPCODE: Sense = Sense::new(sense_key::ILLEGAL_REQUEST, 0x20, 0x00);
    pub const LBA_OUT_OF_RANGE: Sense = Sense::new(sense_key::ILLEGAL_REQUEST, 0x21, 0x00);
    pub const INVALID_FIELD_IN_CDB: Sense = Sense::new(sense_key::ILLEGAL_REQUEST, 0x24, 0x00);
    pub const INVALID_FIELD_IN_IU: Sense = Sense::new(sense_key::ILLEGAL_REQUEST, 0x0E, 0x03);
    pub const LUN_NOT_SUPPORTED: Sense = Sense::new(sense_key::ILLEGAL_REQUEST, 0x25, 0x00);
    pub const SAVING_NOT_SUPPORTED: Sense = Sense::new(sense_key::ILLEGAL_REQUEST, 0x39, 0x00);
    pub const WRITE_PROTECTED: Sense = Sense::new(sense_key::DATA_PROTECT, 0x27, 0x00);
    /// SPACE ALLOCATION FAILED WRITE PROTECT: a thin device out of room for a write.
    pub const SPACE_ALLOCATION_FAILED: Sense = Sense::new(sense_key::DATA_PROTECT, 0x27, 0x07);
    pub const UNRECOVERED_READ_ERROR: Sense = Sense::new(sense_key::MEDIUM_ERROR, 0x11, 0x00);
    pub const WRITE_ERROR: Sense = Sense::new(sense_key::MEDIUM_ERROR, 0x0C, 0x00);
    pub const INTERNAL_TARGET_FAILURE: Sense = Sense::new(sense_key::HARDWARE_ERROR, 0x44, 0x00);
    /// LOGICAL UNIT COMMUNICATION FAILURE, the aborted-command condition for a task that
    /// could not be carried out.
    pub const COMMUNICATION_FAILURE: Sense = Sense::new(sense_key::ABORTED_COMMAND, 0x08, 0x00);
    pub const NO_SENSE: Sense = Sense::new(sense_key::NO_SENSE, 0x00, 0x00);

    pub fn with_info(mut self, info: u64) -> Self {
        self.info = Some(info);
        self
    }

    /// Fixed-format sense data (response code 0x70, 18 bytes). The INFORMATION field holds 32
    /// bits; a larger value is left out (VALID clear) rather than truncated.
    pub fn fixed(&self) -> [u8; 18] {
        let mut s = fixed_sense(self.key, self.asc, self.ascq);
        if let Some(info) = self.info.and_then(|i| u32::try_from(i).ok()) {
            s[0] |= 0x80;
            s[3..7].copy_from_slice(&info.to_be_bytes());
        }
        s
    }

    /// Decode fixed (0x70/0x71) or descriptor (0x72/0x73) format sense data.
    pub fn parse(b: &[u8]) -> Option<Sense> {
        match b.first()? & 0x7F {
            0x70 | 0x71 => {
                let key = b.get(2)? & 0x0F;
                let asc = b.get(12).copied().unwrap_or(0);
                let ascq = b.get(13).copied().unwrap_or(0);
                let info = (b[0] & 0x80 != 0)
                    .then(|| b.get(3..7))
                    .flatten()
                    .map(|i| u32::from_be_bytes([i[0], i[1], i[2], i[3]]) as u64);
                Some(Sense {
                    key,
                    asc,
                    ascq,
                    info,
                })
            }
            0x72 | 0x73 => {
                let key = b.get(1)? & 0x0F;
                let (asc, ascq) = (*b.get(2)?, *b.get(3)?);
                // Descriptor 0x00 is INFORMATION: [type, 0x0A, VALID, 0, 8 bytes].
                let mut info = None;
                let total = 8 + *b.get(7)? as usize;
                let mut at = 8;
                while at + 2 <= total.min(b.len()) {
                    let (kind, len) = (b[at], b[at + 1] as usize);
                    if kind == 0x00 && len == 0x0A {
                        if let Some(i) = b.get(at + 4..at + 12) {
                            info = Some(u64::from_be_bytes(i.try_into().ok()?));
                        }
                    }
                    at += 2 + len;
                }
                Some(Sense {
                    key,
                    asc,
                    ascq,
                    info,
                })
            }
            _ => None,
        }
    }

    /// What the condition means, for a person or a model reading it.
    pub fn describe(&self) -> String {
        format!(
            "{}: {}",
            sense_key_name(self.key),
            asc_meaning(self.asc, self.ascq)
        )
    }
}

/// Fixed-format sense data, 18 bytes: response code 0x70 (current error), the key, additional
/// sense length 10, ASC and ASCQ.
pub fn fixed_sense(key: u8, asc: u8, ascq: u8) -> [u8; 18] {
    #[rustfmt::skip]
    let s = [
        0x70, 0x00, key, 0x00, 0x00, 0x00, 0x00,
        0x0A,
        0x00, 0x00, 0x00, 0x00,
        asc, ascq,
        0x00, 0x00, 0x00, 0x00,
    ];
    s
}

pub fn sense_key_name(key: u8) -> &'static str {
    match key {
        0x00 => "NO SENSE",
        0x01 => "RECOVERED ERROR",
        0x02 => "NOT READY",
        0x03 => "MEDIUM ERROR",
        0x04 => "HARDWARE ERROR",
        0x05 => "ILLEGAL REQUEST",
        0x06 => "UNIT ATTENTION",
        0x07 => "DATA PROTECT",
        0x08 => "BLANK CHECK",
        0x0B => "ABORTED COMMAND",
        0x0E => "MISCOMPARE",
        _ => "OTHER",
    }
}

/// The additional sense codes a host commonly meets; anything else is named by its numbers.
pub fn asc_meaning(asc: u8, ascq: u8) -> String {
    let known = match (asc, ascq) {
        (0x00, 0x00) => "NO ADDITIONAL SENSE INFORMATION",
        (0x04, 0x00) => "LOGICAL UNIT NOT READY",
        (0x08, 0x00) => "LOGICAL UNIT COMMUNICATION FAILURE",
        (0x0C, 0x00) => "WRITE ERROR",
        (0x0E, 0x03) => "INVALID FIELD IN INFORMATION UNIT",
        (0x11, 0x00) => "UNRECOVERED READ ERROR",
        (0x1A, 0x00) => "PARAMETER LIST LENGTH ERROR",
        (0x20, 0x00) => "INVALID COMMAND OPERATION CODE",
        (0x21, 0x00) => "LOGICAL BLOCK ADDRESS OUT OF RANGE",
        (0x24, 0x00) => "INVALID FIELD IN CDB",
        (0x25, 0x00) => "LOGICAL UNIT NOT SUPPORTED",
        (0x26, 0x00) => "INVALID FIELD IN PARAMETER LIST",
        (0x27, 0x00) => "WRITE PROTECTED",
        (0x27, 0x07) => "SPACE ALLOCATION FAILED WRITE PROTECT",
        (0x28, 0x00) => "NOT READY TO READY CHANGE, MEDIUM MAY HAVE CHANGED",
        (0x29, 0x00) => "POWER ON, RESET, OR BUS DEVICE RESET OCCURRED",
        (0x29, 0x01) => "POWER ON OCCURRED",
        (0x2A, 0x09) => "CAPACITY DATA HAS CHANGED",
        (0x39, 0x00) => "SAVING PARAMETERS NOT SUPPORTED",
        (0x3A, 0x00) => "MEDIUM NOT PRESENT",
        (0x3F, 0x0E) => "REPORTED LUNS DATA HAS CHANGED",
        (0x44, 0x00) => "INTERNAL TARGET FAILURE",
        (0x47, 0x00) => "SCSI PARITY ERROR",
        (0x47, 0x05) => "PROTOCOL SERVICE CRC ERROR",
        (0x49, 0x00) => "INVALID MESSAGE ERROR",
        _ => "",
    };
    if known.is_empty() {
        format!("ASC 0x{asc:02X} ASCQ 0x{ascq:02X}")
    } else {
        known.to_string()
    }
}

pub fn status_name(s: u8) -> &'static str {
    match s {
        0x00 => "GOOD",
        0x02 => "CHECK CONDITION",
        0x04 => "CONDITION MET",
        0x08 => "BUSY",
        0x18 => "RESERVATION CONFLICT",
        0x28 => "TASK SET FULL",
        0x30 => "ACA ACTIVE",
        0x40 => "TASK ABORTED",
        _ => "OTHER",
    }
}

/// The identity strings of a standard INQUIRY answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub vendor: String,
    pub product: String,
    pub revision: String,
}

/// `s` as an ASCII field of `n` bytes, space-padded, anything unprintable replaced by `?`.
fn ascii_field(s: &str, n: usize) -> Vec<u8> {
    let mut out: Vec<u8> = s
        .bytes()
        .map(|b| if (0x20..0x7F).contains(&b) { b } else { b'?' })
        .take(n)
        .collect();
    out.resize(n, b' ');
    out
}

/// Version descriptors (SPC-4 table 49) for the standard INQUIRY data.
pub const VERSION_SAM5: u16 = 0x00A0;
pub const VERSION_ISCSI: u16 = 0x0960;
pub const VERSION_SPC4: u16 = 0x0460;
pub const VERSION_SBC3: u16 = 0x04C0;

/// Standard INQUIRY data for a direct-access block device (peripheral type 0): 36 bytes, or
/// 96 when it carries version descriptors (at most eight). `version` is the claimed SPC
/// version (0x05 SPC-3, 0x06 SPC-4); `cmdque` advertises tagged command queuing.
pub fn standard_inquiry(
    id: &Identity,
    removable: bool,
    version: u8,
    cmdque: bool,
    descriptors: &[u16],
) -> Vec<u8> {
    let len: u8 = if descriptors.is_empty() { 36 } else { 96 };
    let mut d = vec![
        0x00,
        if removable { 0x80 } else { 0x00 },
        version,
        0x02,    // response data format 2
        len - 5, // additional length
        0x00,
        0x00,
        if cmdque { 0x02 } else { 0x00 },
    ];
    d.extend(ascii_field(&id.vendor, 8));
    d.extend(ascii_field(&id.product, 16));
    d.extend(ascii_field(&id.revision, 4));
    if !descriptors.is_empty() {
        d.resize(58, 0);
        for v in descriptors.iter().take(8) {
            d.extend(v.to_be_bytes());
        }
        d.resize(96, 0);
    }
    d
}

/// Standard INQUIRY data for a LUN that does not exist: peripheral qualifier 3, type 0x1F.
pub fn absent_lun_inquiry() -> Vec<u8> {
    let mut d = vec![0x7F, 0x00, 0x05, 0x02, 0x1F, 0x00, 0x00, 0x00];
    d.resize(36, b' ');
    d
}

/// VPD page 0x00: the pages this device supports.
pub fn vpd_supported_pages(pages: &[u8]) -> Vec<u8> {
    let mut d = vec![0x00, 0x00, 0x00, pages.len() as u8];
    d.extend(pages);
    d
}

/// VPD page 0x80: the unit serial number (ASCII, at most 251 bytes).
pub fn vpd_serial(serial: &str) -> Vec<u8> {
    let s = ascii_field(serial, serial.len().min(251));
    let mut d = vec![0x00, 0x80, 0x00, s.len() as u8];
    d.extend(s);
    d
}

/// VPD page 0xB0: block limits — the largest transfer one command may ask for and the
/// preferred one, in blocks; no WRITE SAME, UNMAP or COMPARE AND WRITE limits (unsupported).
pub fn vpd_block_limits(max_transfer_blocks: u32, optimal_transfer_blocks: u32) -> Vec<u8> {
    let mut d = vec![0u8; 64];
    d[1] = 0xB0;
    d[3] = 0x3C;
    d[6..8].copy_from_slice(&1u16.to_be_bytes()); // optimal transfer length granularity
    d[8..12].copy_from_slice(&max_transfer_blocks.to_be_bytes());
    d[12..16].copy_from_slice(&optimal_transfer_blocks.to_be_bytes());
    d
}

/// VPD page 0xB1: block device characteristics — a non-rotating medium, form factor not
/// reported.
pub fn vpd_block_device_characteristics() -> Vec<u8> {
    let mut d = vec![0u8; 64];
    d[1] = 0xB1;
    d[3] = 0x3C;
    d[4..6].copy_from_slice(&1u16.to_be_bytes());
    d
}

/// One designator of VPD page 0x83.
pub enum Designator {
    /// NAA IEEE Registered Extended (type 3, NAA 6): 16 bytes naming the logical unit.
    Naa6([u8; 16]),
    /// T10 vendor ID (type 1): the vendor field, then a vendor-unique identifier.
    T10 { vendor: String, id: String },
    /// SCSI name string (type 8) of the iSCSI target device: protocol identifier iSCSI,
    /// association "target device".
    IscsiTargetName(String),
}

/// VPD page 0x83: device identification.
pub fn vpd_device_identification(designators: &[Designator]) -> Vec<u8> {
    let mut body = Vec::new();
    for d in designators {
        match d {
            Designator::Naa6(id) => {
                // Code set binary, association LU, type NAA.
                body.extend([0x01, 0x03, 0x00, 16]);
                body.extend(id);
            }
            Designator::T10 { vendor, id } => {
                let mut v = ascii_field(vendor, 8);
                v.extend(ascii_field(id, id.len().min(200)));
                // Code set ASCII, association LU, type T10 vendor ID.
                body.extend([0x02, 0x01, 0x00, v.len() as u8]);
                body.extend(v);
            }
            Designator::IscsiTargetName(name) => {
                // A null-terminated UTF-8 string padded to a multiple of four.
                let mut v = name.as_bytes()[..name.len().min(223)].to_vec();
                v.push(0);
                while v.len() % 4 != 0 {
                    v.push(0);
                }
                // Protocol iSCSI (5) with PIV, code set UTF-8 (3), association target device
                // (2), type SCSI name string (8).
                body.extend([0x53, 0xA8, 0x00, v.len() as u8]);
                body.extend(v);
            }
        }
    }
    let mut d = vec![0x00, 0x83];
    d.extend((body.len() as u16).to_be_bytes());
    d.extend(body);
    d
}

/// An NAA 6 identifier derived from a stable name: OUI 0x000000 (none registered; NAA 6 with a
/// zero OUI is the form tgt and LIO use for a locally made name) and a hash of the name.
pub fn naa6_from(name: &str) -> [u8; 16] {
    use md5::{Digest, Md5};
    let h = Md5::digest(name.as_bytes());
    let mut id = [0u8; 16];
    id[0] = 0x60;
    // 24-bit OUI (zero) occupies the low nibble of byte 0 through the high nibble of byte 3.
    id[3] = h[0] & 0x0F;
    id[4..16].copy_from_slice(&h[1..13]);
    id
}

/// READ CAPACITY(10) data: the last LBA (0xFFFFFFFF when it does not fit, sending the host to
/// READ CAPACITY(16)) and the block length.
pub fn read_capacity_10(last_lba: u64, block_len: u32) -> [u8; 8] {
    let lba = u32::try_from(last_lba).unwrap_or(u32::MAX);
    let mut d = [0u8; 8];
    d[..4].copy_from_slice(&lba.to_be_bytes());
    d[4..].copy_from_slice(&block_len.to_be_bytes());
    d
}

/// READ CAPACITY(16) data, 32 bytes: last LBA, block length, no protection, one logical block
/// per physical block, no provisioning.
pub fn read_capacity_16(last_lba: u64, block_len: u32) -> [u8; 32] {
    let mut d = [0u8; 32];
    d[..8].copy_from_slice(&last_lba.to_be_bytes());
    d[8..12].copy_from_slice(&block_len.to_be_bytes());
    d
}

/// The 8-byte LUN field of a single-level LUN: peripheral addressing below 256, flat space
/// addressing up to 16383 (SAM-5 4.7).
pub fn lun_field(lun: u16) -> [u8; 8] {
    let mut f = [0u8; 8];
    if lun < 256 {
        f[1] = lun as u8;
    } else {
        f[0] = 0x40 | ((lun >> 8) as u8 & 0x3F);
        f[1] = lun as u8;
    }
    f
}

/// The LUN a single-level 8-byte LUN field names, peripheral or flat space addressing; `None`
/// for any other form (hierarchical, extended, a second level).
pub fn lun_from_field(f: &[u8]) -> Option<u16> {
    let f: &[u8; 8] = f.get(..8)?.try_into().ok()?;
    if f[2..] != [0u8; 6] {
        return None;
    }
    match f[0] >> 6 {
        0b00 if f[0] == 0 => Some(f[1] as u16),
        0b01 => Some((((f[0] & 0x3F) as u16) << 8) | f[1] as u16),
        _ => None,
    }
}

/// REPORT LUNS parameter data for these LUNs.
pub fn report_luns(luns: &[u16]) -> Vec<u8> {
    let mut d = ((luns.len() * 8) as u32).to_be_bytes().to_vec();
    d.extend([0u8; 4]);
    for l in luns {
        d.extend(lun_field(*l));
    }
    d
}

/// The LUN fields of REPORT LUNS parameter data, as numbers where they are single-level and
/// as hex otherwise. The list length is believed only as far as the bytes go.
pub fn parse_report_luns(d: &[u8]) -> Vec<Result<u16, String>> {
    let Some(len) = d.get(..4) else {
        return vec![];
    };
    let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
    d.get(8..)
        .unwrap_or_default()
        .chunks_exact(8)
        .take(len / 8)
        .map(|f| lun_from_field(f).ok_or_else(|| hex::encode(f)))
        .collect()
}

/// A READ or WRITE command, whichever of the 6/10/12/16-byte forms carried it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadWrite {
    pub write: bool,
    pub lba: u64,
    pub blocks: u32,
    /// RDPROTECT / WRPROTECT: protection information the device does not have.
    pub protect: u8,
    pub fua: bool,
}

/// The length of a CDB by its group code (SPC-4 4.2.5.1), `None` for the vendor-specific and
/// reserved groups.
pub fn cdb_len(opcode: u8) -> Option<usize> {
    match opcode >> 5 {
        0 => Some(6),
        1 | 2 => Some(10),
        4 => Some(16),
        5 => Some(12),
        _ => None,
    }
}

/// Decode a READ or WRITE CDB; `None` when it is not one or is too short for its form.
pub fn decode_read_write(cdb: &[u8]) -> Option<ReadWrite> {
    use opcode::*;
    let op = *cdb.first()?;
    let write = matches!(op, WRITE_6 | WRITE_10 | WRITE_12 | WRITE_16);
    let be = |r: std::ops::Range<usize>| -> Option<u64> {
        Some(
            cdb.get(r)?
                .iter()
                .fold(0u64, |acc, b| (acc << 8) | *b as u64),
        )
    };
    let (lba, blocks, flags) = match op {
        READ_6 | WRITE_6 => {
            let c = cdb.get(..6)?;
            let lba = (((c[1] & 0x1F) as u64) << 16) | ((c[2] as u64) << 8) | c[3] as u64;
            // A transfer length of 0 means 256 blocks in the 6-byte form.
            let blocks = if c[4] == 0 { 256 } else { c[4] as u32 };
            (lba, blocks, 0)
        }
        READ_10 | WRITE_10 => (be(2..6)?, be(7..9)? as u32, cdb[1]),
        READ_12 | WRITE_12 => (be(2..6)?, be(6..10)? as u32, cdb[1]),
        READ_16 | WRITE_16 => (be(2..10)?, be(10..14)? as u32, cdb[1]),
        _ => return None,
    };
    Some(ReadWrite {
        write,
        lba,
        blocks,
        protect: flags >> 5,
        fua: flags & 0x08 != 0,
    })
}

/// A READ(10) or READ(16) CDB, whichever the LBA and length need.
pub fn read_cdb(lba: u64, blocks: u32) -> [u8; 16] {
    rw_cdb(false, lba, blocks)
}

/// A WRITE(10) or WRITE(16) CDB, whichever the LBA and length need.
pub fn write_cdb(lba: u64, blocks: u32) -> [u8; 16] {
    rw_cdb(true, lba, blocks)
}

fn rw_cdb(write: bool, lba: u64, blocks: u32) -> [u8; 16] {
    let mut c = [0u8; 16];
    if lba <= u32::MAX as u64 && blocks <= u16::MAX as u32 {
        c[0] = if write {
            opcode::WRITE_10
        } else {
            opcode::READ_10
        };
        c[2..6].copy_from_slice(&(lba as u32).to_be_bytes());
        c[7..9].copy_from_slice(&(blocks as u16).to_be_bytes());
    } else {
        c[0] = if write {
            opcode::WRITE_16
        } else {
            opcode::READ_16
        };
        c[2..10].copy_from_slice(&lba.to_be_bytes());
        c[10..14].copy_from_slice(&blocks.to_be_bytes());
    }
    c
}

/// INQUIRY CDB: standard data, or a VPD page when `page` is given.
pub fn inquiry_cdb(page: Option<u8>, alloc: u16) -> [u8; 16] {
    let mut c = [0u8; 16];
    c[0] = opcode::INQUIRY;
    if let Some(p) = page {
        c[1] = 0x01;
        c[2] = p;
    }
    c[3..5].copy_from_slice(&alloc.to_be_bytes());
    c
}

pub fn read_capacity_10_cdb() -> [u8; 16] {
    let mut c = [0u8; 16];
    c[0] = opcode::READ_CAPACITY_10;
    c
}

pub fn read_capacity_16_cdb() -> [u8; 16] {
    let mut c = [0u8; 16];
    c[0] = opcode::SERVICE_ACTION_IN_16;
    c[1] = SA_READ_CAPACITY_16;
    c[10..14].copy_from_slice(&32u32.to_be_bytes());
    c
}

pub fn report_luns_cdb(alloc: u32) -> [u8; 16] {
    let mut c = [0u8; 16];
    c[0] = opcode::REPORT_LUNS;
    c[6..10].copy_from_slice(&alloc.to_be_bytes());
    c
}

pub fn test_unit_ready_cdb() -> [u8; 16] {
    [0u8; 16]
}

pub fn synchronize_cache_cdb() -> [u8; 16] {
    let mut c = [0u8; 16];
    c[0] = opcode::SYNCHRONIZE_CACHE_10;
    c
}

/// What a standard INQUIRY answer says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InquiryInfo {
    pub qualifier: u8,
    pub device_type: u8,
    pub removable: bool,
    pub version: u8,
    pub vendor: String,
    pub product: String,
    pub revision: String,
}

/// A fixed-width ASCII field a device sent, as one line of text: controls become spaces and the
/// padding goes.
fn trimmed(b: &[u8]) -> String {
    crate::utils::sanitize::line_field(&String::from_utf8_lossy(b))
        .trim_end()
        .to_string()
}

pub fn parse_inquiry(d: &[u8]) -> Option<InquiryInfo> {
    let h = d.get(..8)?;
    Some(InquiryInfo {
        qualifier: h[0] >> 5,
        device_type: h[0] & 0x1F,
        removable: h[1] & 0x80 != 0,
        version: h[2],
        vendor: d.get(8..16).map(trimmed).unwrap_or_default(),
        product: d.get(16..32).map(trimmed).unwrap_or_default(),
        revision: d.get(32..36).map(trimmed).unwrap_or_default(),
    })
}

pub fn device_type_name(t: u8) -> &'static str {
    match t {
        0x00 => "direct-access block device",
        0x01 => "sequential-access device (tape)",
        0x03 => "processor",
        0x05 => "CD/DVD",
        0x07 => "optical memory",
        0x08 => "medium changer",
        0x0C => "storage array controller",
        0x0D => "enclosure services",
        0x0E => "simplified direct-access device",
        0x1F => "unknown or no device",
        _ => "other",
    }
}

/// READ CAPACITY data, either form: (last LBA, block length).
pub fn parse_read_capacity(d: &[u8]) -> Option<(u64, u32)> {
    match d.len() {
        n if n >= 12 => Some((
            u64::from_be_bytes(d[..8].try_into().ok()?),
            u32::from_be_bytes(d[8..12].try_into().ok()?),
        )),
        n if n >= 8 => Some((
            u32::from_be_bytes(d[..4].try_into().ok()?) as u64,
            u32::from_be_bytes(d[4..8].try_into().ok()?),
        )),
        _ => None,
    }
}

/// A VPD page's header: (page code, payload). The declared length is believed only as far as
/// the bytes go.
pub fn parse_vpd(d: &[u8]) -> Option<(u8, &[u8])> {
    let page = *d.get(1)?;
    let len = u16::from_be_bytes([*d.get(2)?, *d.get(3)?]) as usize;
    Some((page, &d[4..(4 + len).min(d.len())]))
}

/// The designators of a device identification page, as readable strings.
pub fn parse_designators(payload: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= payload.len() && out.len() < 32 {
        let code_set = payload[at] & 0x0F;
        let kind = payload[at + 1] & 0x0F;
        let len = payload[at + 3] as usize;
        let Some(v) = payload.get(at + 4..at + 4 + len) else {
            break;
        };
        let value = if code_set == 2 || code_set == 3 {
            trimmed(v.split(|b| *b == 0).next().unwrap_or_default())
        } else {
            hex::encode(v)
        };
        let name = match kind {
            0 => "vendor-specific",
            1 => "t10-vendor-id",
            2 => "eui-64",
            3 => "naa",
            4 => "relative-target-port",
            5 => "target-port-group",
            6 => "logical-unit-group",
            7 => "md5-logical-unit",
            8 => "scsi-name-string",
            _ => "other",
        };
        out.push(format!("{name}:{value}"));
        at += 4 + len;
    }
    out
}

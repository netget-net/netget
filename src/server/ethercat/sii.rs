//! The Slave Information Interface (SII, the "EEPROM", ETG.1000.6 §5.4 and ETG.2010): the
//! image a slave presents through its ESC's EEPROM registers, built here from a
//! [`DeviceSpec`], and the parser a master reads it back with.
//!
//! Word addresses (16-bit words, little-endian):
//!
//! ```text
//! 0x00-0x07  ESC configuration area: PDI control, PDI config, sync impulse, PDI config 2,
//!            station alias, reserved ×2, checksum (CRC-8 over words 0-6)
//! 0x08-0x0F  vendor ID, product code, revision, serial number (u32 each)
//! 0x14-0x17  bootstrap mailbox (offset, size ×2) — none here
//! 0x18-0x1B  standard receive mailbox offset/size, send mailbox offset/size
//! 0x1C       mailbox protocols (bit 2 = CoE)
//! 0x3E       EEPROM size in KiBit − 1;  0x3F  version (1)
//! 0x40-      categories: {type u16, length in words u16, data}, ending with type 0xFFFF
//! ```
//!
//! (ETG.1000.6 puts the bootstrap mailbox at 0x14 and the standard mailbox at 0x18; SOEM's
//! `ECT_SII_RXMBXADR` is 0x18 and its `ECT_SII_MBXPROTO` 0x1C, which this layout matches.)
use super::device::{DataType, DeviceSpec, Image};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};

pub mod word {
    pub const PDI_CONTROL: usize = 0x00;
    pub const ALIAS: usize = 0x04;
    pub const CHECKSUM: usize = 0x07;
    pub const VENDOR: usize = 0x08;
    pub const PRODUCT: usize = 0x0A;
    pub const REVISION: usize = 0x0C;
    pub const SERIAL: usize = 0x0E;
    pub const RX_MAILBOX_OFFSET: usize = 0x18;
    pub const RX_MAILBOX_SIZE: usize = 0x19;
    pub const TX_MAILBOX_OFFSET: usize = 0x1A;
    pub const TX_MAILBOX_SIZE: usize = 0x1B;
    pub const MAILBOX_PROTOCOLS: usize = 0x1C;
    pub const SIZE: usize = 0x3E;
    pub const VERSION: usize = 0x3F;
    pub const FIRST_CATEGORY: usize = 0x40;
}

pub mod category {
    pub const STRINGS: u16 = 10;
    pub const GENERAL: u16 = 30;
    pub const FMMU: u16 = 40;
    pub const SYNC_MANAGER: u16 = 41;
    pub const TXPDO: u16 = 50;
    pub const RXPDO: u16 = 51;
    pub const END: u16 = 0xFFFF;
}

/// Mailbox protocol bits (SII word 0x1C).
pub const MBX_COE: u16 = 0x0004;
/// CoE details (General category): SDO supported. SDO information, complete access and PDO
/// configuration are not offered.
pub const COE_DETAILS_SDO: u8 = 0x01;
/// SyncManager types (SyncM category).
pub mod sm_type {
    pub const MAILBOX_OUT: u8 = 1;
    pub const MAILBOX_IN: u8 = 2;
    pub const OUTPUTS: u8 = 3;
    pub const INPUTS: u8 = 4;
}
/// FMMU usage (FMMU category).
pub mod fmmu_usage {
    pub const OUTPUTS: u8 = 1;
    pub const INPUTS: u8 = 2;
    pub const MAILBOX_STATE: u8 = 3;
    pub const UNUSED: u8 = 0xFF;
}

/// The largest SII a master reads (8 KiB = 64 KiBit, the biggest common EEPROM).
pub const MAX_SII_BYTES: usize = 8192;
/// Categories walked before giving up.
pub const MAX_CATEGORIES: usize = 64;
/// Default and bounds of each mailbox's size.
pub const DEFAULT_MAILBOX: usize = 128;
pub const MIN_MAILBOX: usize = 64;
pub const MAX_MAILBOX: usize = 512;
/// ESC process memory starts here; registers are below.
pub const PROCESS_RAM: u16 = 0x1000;
/// Each process data SyncManager is given room for three buffers of the largest image.
pub const PD_AREA: u16 = 3 * super::device::MAX_PD_BYTES as u16;

/// A SyncManager as the SII describes it and the master programs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmConfig {
    pub start: u16,
    pub length: u16,
    pub control: u8,
    pub enable: u8,
    pub sm_type: u8,
}

/// Where an emulated slave's SyncManagers sit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub mailbox: usize,
    pub sm: [SmConfig; 4],
}

impl Layout {
    pub fn for_device(dev: &DeviceSpec, mailbox: usize) -> Self {
        let mbx = mailbox as u16;
        let pd_base = (PROCESS_RAM + 2 * mbx).div_ceil(0x100) * 0x100;
        let out = dev.outputs.bytes() as u16;
        let inp = dev.inputs.bytes() as u16;
        Layout {
            mailbox,
            sm: [
                SmConfig {
                    start: PROCESS_RAM,
                    length: mbx,
                    control: 0x26,
                    enable: 1,
                    sm_type: sm_type::MAILBOX_OUT,
                },
                SmConfig {
                    start: PROCESS_RAM + mbx,
                    length: mbx,
                    control: 0x22,
                    enable: 1,
                    sm_type: sm_type::MAILBOX_IN,
                },
                SmConfig {
                    start: pd_base,
                    length: out,
                    control: 0x64,
                    enable: (out > 0) as u8,
                    sm_type: sm_type::OUTPUTS,
                },
                SmConfig {
                    start: pd_base + PD_AREA,
                    length: inp,
                    control: 0x20,
                    enable: (inp > 0) as u8,
                    sm_type: sm_type::INPUTS,
                },
            ],
        }
    }

    /// The end of the memory the layout uses.
    pub fn end(&self) -> usize {
        self.sm[3].start as usize + PD_AREA as usize
    }
}

/// CRC-8 of the ESC configuration area (polynomial x⁸+x²+x+1, initial 0xFF), stored in the low
/// octet of word 7.
pub fn config_crc(bytes: &[u8]) -> u8 {
    let mut crc: u8 = 0xFF;
    for b in bytes {
        crc ^= b;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }
    crc
}

struct Strings(Vec<String>);

impl Strings {
    /// The 1-based index of `s`, adding it when new. 0 means "no string".
    fn index(&mut self, s: &str) -> u8 {
        if s.is_empty() {
            return 0;
        }
        if let Some(p) = self.0.iter().position(|x| x == s) {
            return (p + 1) as u8;
        }
        if self.0.len() >= 255 {
            return 0;
        }
        self.0.push(s.chars().take(255).collect());
        self.0.len() as u8
    }
}

fn put_category(out: &mut Vec<u8>, ty: u16, mut data: Vec<u8>) {
    if data.len() % 2 == 1 {
        data.push(0);
    }
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(&((data.len() / 2) as u16).to_le_bytes());
    out.extend_from_slice(&data);
}

fn pdo_category(index: u16, sm: u8, img: &Image, strings: &mut Strings, base: u16) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&index.to_le_bytes());
    d.push(img.entries.len() as u8);
    d.push(sm);
    d.push(0); // DC synchronisation
    d.push(strings.index(if base == super::coe::INPUT_OBJECT {
        "Inputs"
    } else {
        "Outputs"
    }));
    d.extend_from_slice(&0u16.to_le_bytes()); // flags
    for (i, e) in img.entries.iter().enumerate() {
        d.extend_from_slice(&base.to_le_bytes());
        d.push((i + 1) as u8);
        d.push(strings.index(&e.name));
        d.push(e.ty.code() as u8);
        d.push(e.ty.bits() as u8);
        d.extend_from_slice(&0u16.to_le_bytes());
    }
    d
}

/// The SII image of one emulated slave.
pub fn build(dev: &DeviceSpec, layout: &Layout) -> Vec<u8> {
    let mut w = vec![0u16; word::FIRST_CATEGORY];
    w[word::PDI_CONTROL] = 0x0005; // PDI: SPI slave, as a microcontroller-hosted slave has
    w[word::ALIAS] = dev.alias;
    let mut put32 = |at: usize, v: u32| {
        w[at] = v as u16;
        w[at + 1] = (v >> 16) as u16;
    };
    put32(word::VENDOR, dev.vendor_id);
    put32(word::PRODUCT, dev.product_code);
    put32(word::REVISION, dev.revision);
    put32(word::SERIAL, dev.serial);
    w[word::RX_MAILBOX_OFFSET] = layout.sm[0].start;
    w[word::RX_MAILBOX_SIZE] = layout.sm[0].length;
    w[word::TX_MAILBOX_OFFSET] = layout.sm[1].start;
    w[word::TX_MAILBOX_SIZE] = layout.sm[1].length;
    w[word::MAILBOX_PROTOCOLS] = MBX_COE;
    w[word::SIZE] = 15; // 16 KiBit
    w[word::VERSION] = 1;
    let mut out: Vec<u8> = w.iter().flat_map(|x| x.to_le_bytes()).collect();
    let crc = config_crc(&out[..14]);
    out[word::CHECKSUM * 2] = crc;
    out[word::CHECKSUM * 2 + 1] = 0;

    let mut strings = Strings(Vec::new());
    let name_idx = strings.index(&dev.name);
    let group_idx = strings.index("NetGet");
    // The order string is what a master shows as the device's type (ethercrab calls it the name);
    // a description has none of its own, so it is the name too.
    let order_idx = name_idx;
    let txpdo = (!dev.inputs.is_empty()).then(|| {
        pdo_category(
            super::coe::TXPDO_MAPPING,
            3,
            &dev.inputs,
            &mut strings,
            super::coe::INPUT_OBJECT,
        )
    });
    let rxpdo = (!dev.outputs.is_empty()).then(|| {
        pdo_category(
            super::coe::RXPDO_MAPPING,
            2,
            &dev.outputs,
            &mut strings,
            super::coe::OUTPUT_OBJECT,
        )
    });

    let mut s = vec![strings.0.len() as u8];
    for t in &strings.0 {
        s.push(t.len() as u8);
        s.extend_from_slice(t.as_bytes());
    }
    put_category(&mut out, category::STRINGS, s);

    let mut g = vec![0u8; 32];
    g[0] = group_idx;
    g[2] = order_idx;
    g[3] = name_idx;
    g[5] = COE_DETAILS_SDO;
    g[16..18].copy_from_slice(&0x0011u16.to_le_bytes()); // ports 0 and 1: MII
    put_category(&mut out, category::GENERAL, g);

    put_category(
        &mut out,
        category::FMMU,
        vec![
            fmmu_usage::OUTPUTS,
            fmmu_usage::INPUTS,
            fmmu_usage::MAILBOX_STATE,
            fmmu_usage::UNUSED,
        ],
    );

    let mut sm = Vec::new();
    for c in &layout.sm {
        sm.extend_from_slice(&c.start.to_le_bytes());
        sm.extend_from_slice(&c.length.to_le_bytes());
        sm.push(c.control);
        sm.push(0);
        sm.push(c.enable);
        sm.push(c.sm_type);
    }
    put_category(&mut out, category::SYNC_MANAGER, sm);
    if let Some(t) = txpdo {
        put_category(&mut out, category::TXPDO, t);
    }
    if let Some(r) = rxpdo {
        put_category(&mut out, category::RXPDO, r);
    }
    out.extend_from_slice(&category::END.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// A PDO entry a master read from the SII.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdoEntry {
    pub index: u16,
    pub subindex: u8,
    pub name: String,
    pub data_type: u8,
    pub bits: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdo {
    pub index: u16,
    pub sm: u8,
    pub name: String,
    pub entries: Vec<PdoEntry>,
}

/// What a master learns from a slave's SII.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiiInfo {
    pub alias: u16,
    pub vendor_id: u32,
    pub product_code: u32,
    pub revision: u32,
    pub serial: u32,
    pub rx_mailbox: (u16, u16),
    pub tx_mailbox: (u16, u16),
    pub mailbox_protocols: u16,
    pub name: Option<String>,
    pub order: Option<String>,
    pub coe_details: u8,
    pub fmmu_usage: Vec<u8>,
    pub sync_managers: Vec<SmConfig>,
    pub txpdos: Vec<Pdo>,
    pub rxpdos: Vec<Pdo>,
    pub checksum_ok: bool,
}

impl SiiInfo {
    pub fn has_coe(&self) -> bool {
        self.mailbox_protocols & MBX_COE != 0 && self.rx_mailbox.1 > 0
    }
}

/// Where the category chain ends in `bytes` (the offset after the END marker), if it does
/// within what has been read so far. `Err` when the chain is malformed.
pub fn chain_end(bytes: &[u8]) -> Result<Option<usize>> {
    let mut pos = word::FIRST_CATEGORY * 2;
    for _ in 0..MAX_CATEGORIES {
        if pos + 2 > bytes.len() {
            return Ok(None);
        }
        let ty = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        if ty == category::END {
            return Ok(Some(pos + 2));
        }
        if pos + 4 > bytes.len() {
            return Ok(None);
        }
        let len = u16::from_le_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize * 2;
        pos += 4 + len;
        ensure!(
            pos <= MAX_SII_BYTES,
            "the SII category chain runs past {MAX_SII_BYTES} octets"
        );
    }
    bail!("the SII has more than {MAX_CATEGORIES} categories")
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn parse_pdos(d: &[u8], strings: &[String]) -> Result<Vec<Pdo>> {
    let name = |i: u8| -> String {
        if i == 0 {
            String::new()
        } else {
            strings.get(i as usize - 1).cloned().unwrap_or_default()
        }
    };
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 8 <= d.len() {
        let n = d[pos + 2] as usize;
        ensure!(
            n <= super::device::MAX_ENTRIES * 8,
            "a PDO declares {n} entries"
        );
        let entries_end = pos + 8 + n * 8;
        ensure!(
            entries_end <= d.len(),
            "a PDO's entries run past its category"
        );
        let mut entries = Vec::with_capacity(n);
        for k in 0..n {
            let e = pos + 8 + k * 8;
            entries.push(PdoEntry {
                index: u16_at(d, e),
                subindex: d[e + 2],
                name: name(d[e + 3]),
                data_type: d[e + 4],
                bits: d[e + 5],
            });
        }
        out.push(Pdo {
            index: u16_at(d, pos),
            sm: d[pos + 3],
            name: name(d[pos + 5]),
            entries,
        });
        ensure!(out.len() <= 64, "more than 64 PDOs in one category");
        pos = entries_end;
    }
    Ok(out)
}

/// Parse an SII image (at least through its END category).
pub fn parse(bytes: &[u8]) -> Result<SiiInfo> {
    ensure!(
        bytes.len() >= word::FIRST_CATEGORY * 2,
        "the SII is shorter than its 128-octet header"
    );
    let end = chain_end(bytes)?.context("the SII category chain does not end")?;
    let mut info = SiiInfo {
        alias: u16_at(bytes, word::ALIAS * 2),
        vendor_id: u32_at(bytes, word::VENDOR * 2),
        product_code: u32_at(bytes, word::PRODUCT * 2),
        revision: u32_at(bytes, word::REVISION * 2),
        serial: u32_at(bytes, word::SERIAL * 2),
        rx_mailbox: (
            u16_at(bytes, word::RX_MAILBOX_OFFSET * 2),
            u16_at(bytes, word::RX_MAILBOX_SIZE * 2),
        ),
        tx_mailbox: (
            u16_at(bytes, word::TX_MAILBOX_OFFSET * 2),
            u16_at(bytes, word::TX_MAILBOX_SIZE * 2),
        ),
        mailbox_protocols: u16_at(bytes, word::MAILBOX_PROTOCOLS * 2),
        checksum_ok: config_crc(&bytes[..14]) == bytes[word::CHECKSUM * 2],
        ..Default::default()
    };
    let mut strings: Vec<String> = Vec::new();
    let mut general: Option<Vec<u8>> = None;
    let mut tx: Option<Vec<u8>> = None;
    let mut rx: Option<Vec<u8>> = None;
    let mut pos = word::FIRST_CATEGORY * 2;
    while pos + 2 < end {
        let ty = u16_at(bytes, pos);
        if ty == category::END {
            break;
        }
        let len = u16_at(bytes, pos + 2) as usize * 2;
        let d = &bytes[pos + 4..pos + 4 + len];
        match ty {
            category::STRINGS if !d.is_empty() => {
                let n = d[0] as usize;
                let mut p = 1;
                for _ in 0..n {
                    let Some(&l) = d.get(p) else { break };
                    let l = l as usize;
                    let Some(s) = d.get(p + 1..p + 1 + l) else {
                        break;
                    };
                    strings.push(crate::utils::sanitize::line_field(
                        &String::from_utf8_lossy(s),
                    ));
                    p += 1 + l;
                }
            }
            category::GENERAL => general = Some(d.to_vec()),
            category::FMMU => info.fmmu_usage = d.to_vec(),
            category::SYNC_MANAGER => {
                for c in d.chunks_exact(8).take(16) {
                    info.sync_managers.push(SmConfig {
                        start: u16_at(c, 0),
                        length: u16_at(c, 2),
                        control: c[4],
                        enable: c[6],
                        sm_type: c[7],
                    });
                }
            }
            category::TXPDO => tx = Some(d.to_vec()),
            category::RXPDO => rx = Some(d.to_vec()),
            _ => {}
        }
        pos += 4 + len;
    }
    let s = |i: u8| -> Option<String> {
        (i > 0)
            .then(|| strings.get(i as usize - 1).cloned())
            .flatten()
    };
    if let Some(g) = general.filter(|g| g.len() >= 6) {
        info.name = s(g[3]);
        info.order = s(g[2]);
        info.coe_details = g[5];
    }
    if info.name.is_none() {
        info.name = strings.first().cloned();
    }
    if let Some(t) = tx {
        info.txpdos = parse_pdos(&t, &strings)?;
    }
    if let Some(r) = rx {
        info.rxpdos = parse_pdos(&r, &strings)?;
    }
    Ok(info)
}

/// The process data image a list of SII PDOs describes, for one SyncManager type. Padding
/// entries (index 0) become unnamed gaps.
pub fn image_of(pdos: &[Pdo]) -> Image {
    let mut img = Image::default();
    for p in pdos {
        for e in &p.entries {
            let bits = e.bits as usize;
            if e.index != 0 {
                if let Some(ty) = DataType::from_code(e.data_type as u16)
                    .filter(|t| t.bits() == bits && *t != DataType::String)
                {
                    let name = if e.name.is_empty() {
                        format!("{:#06x}:{}", e.index, e.subindex)
                    } else {
                        e.name.clone()
                    };
                    let name = if img.entries.iter().any(|x| x.name == name) {
                        format!("{name}_{:#06x}_{}", e.index, e.subindex)
                    } else {
                        name
                    };
                    img.entries.push(super::device::Entry {
                        name,
                        ty,
                        bit_offset: img.bits,
                    });
                }
            }
            img.bits += bits;
        }
    }
    img
}

/// The identity and layout a master reports for one slave.
pub fn describe(info: &SiiInfo) -> Value {
    json!({
        "vendor_id": info.vendor_id,
        "product_code": info.product_code,
        "revision": info.revision,
        "serial": info.serial,
        "name": info.name,
        "order": info.order,
        "coe": info.has_coe(),
        "mailbox_size": info.rx_mailbox.1,
    })
}

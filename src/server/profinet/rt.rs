//! Ethernet framing, PROFINET RT_CLASS_1 cyclic frames, and where each submodule's data sits
//! inside one. Pure functions.
//!
//! An RT frame after the EtherType is `FrameID (2) · C_SDU (DataLength octets) ·
//! CycleCounter (2) · DataStatus (1) · TransferStatus (1)`. The C_SDU holds, at the offsets
//! the IOCR block named, each submodule's data followed by its IOPS (provider status), and
//! the one-octet IOCS (consumer status) the provider reports about the *other* direction's
//! submodules. A provider sends it every SendClockFactor × ReductionRatio × 31.25 µs; a
//! consumer that sees none for WatchdogFactor cycles drops the AR.
use super::blocks::{FrameDescriptor, MAX_C_SDU, MIN_C_SDU};
use super::dcp::ETHERTYPE_PROFINET;
use super::values::SubmoduleSpec;
use anyhow::{ensure, Result};

pub const ETHERTYPE_VLAN: u16 = 0x8100;
/// The longest frame accepted from the wire: an Ethernet MTU of payload, two VLAN tags,
/// addresses and EtherType.
pub const MAX_FRAME_LEN: usize = 1500 + 14 + 8;

/// RT_CLASS_1 FrameID range (IEC 61158-6-10; what p-net assigns from).
pub const RT_CLASS_1_FRAME_IDS: std::ops::RangeInclusive<u16> = 0xc000..=0xf7ff;
/// RTA (alarm) frames: high and low priority.
pub const FRAME_ID_ALARM_HIGH: u16 = 0xfc01;
pub const FRAME_ID_ALARM_LOW: u16 = 0xfe01;

/// DataStatus bits.
pub mod data_status {
    pub const STATE_PRIMARY: u8 = 0x01;
    pub const DATA_VALID: u8 = 0x04;
    pub const PROVIDER_RUN: u8 = 0x10;
    pub const STATION_PROBLEM_NORMAL: u8 = 0x20;
    /// Primary, data valid, provider in RUN, no station problem.
    pub const GOOD: u8 = STATE_PRIMARY | DATA_VALID | PROVIDER_RUN | STATION_PROBLEM_NORMAL;
    /// Primary and valid, but the provider is in STOP: what a frame says before the
    /// application has supplied anything, and after it stops.
    pub const STOP: u8 = STATE_PRIMARY | DATA_VALID | STATION_PROBLEM_NORMAL;
}

/// IOPS / IOCS values (IOxS: bit 7 DataState).
pub const IOXS_GOOD: u8 = 0x80;
pub const IOXS_BAD: u8 = 0x00;

/// One received Ethernet frame, VLAN tags removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthFrame {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub vlan_tci: Option<u16>,
    pub ethertype: u16,
    pub payload: Vec<u8>,
}

/// Parse an Ethernet II frame, skipping any number of 802.1Q tags (bounded by the frame).
pub fn parse_eth(frame: &[u8]) -> Option<EthFrame> {
    if frame.len() < 14 || frame.len() > MAX_FRAME_LEN {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&frame[0..6]);
    src.copy_from_slice(&frame[6..12]);
    let mut pos = 12;
    let mut vlan_tci = None;
    loop {
        let t = u16::from_be_bytes([*frame.get(pos)?, *frame.get(pos + 1)?]);
        if t == ETHERTYPE_VLAN {
            vlan_tci = Some(u16::from_be_bytes([
                *frame.get(pos + 2)?,
                *frame.get(pos + 3)?,
            ]));
            pos += 4;
            continue;
        }
        return Some(EthFrame {
            dst,
            src,
            vlan_tci,
            ethertype: t,
            payload: frame[pos + 2..].to_vec(),
        });
    }
}

/// Build an Ethernet II frame with EtherType 0x8892, optionally 802.1Q-tagged, padded to the
/// 60-octet minimum.
pub fn build_eth(dst: [u8; 6], src: [u8; 6], vlan_tci: Option<u16>, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(18 + payload.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    if let Some(tci) = vlan_tci {
        f.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        f.extend_from_slice(&tci.to_be_bytes());
    }
    f.extend_from_slice(&ETHERTYPE_PROFINET.to_be_bytes());
    f.extend_from_slice(payload);
    while f.len() < 60 {
        f.push(0);
    }
    f
}

/// A decoded RT_CLASS_1 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtFrame {
    pub frame_id: u16,
    pub c_sdu: Vec<u8>,
    pub cycle_counter: u16,
    pub data_status: u8,
    pub transfer_status: u8,
}

pub fn frame_id_of(payload: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*payload.first()?, *payload.get(1)?]))
}

/// Encode an RT frame's payload (what follows the EtherType).
pub fn build_rt(frame_id: u16, c_sdu: &[u8], cycle_counter: u16, data_status: u8) -> Vec<u8> {
    let mut p = Vec::with_capacity(6 + c_sdu.len());
    p.extend_from_slice(&frame_id.to_be_bytes());
    p.extend_from_slice(c_sdu);
    p.extend_from_slice(&cycle_counter.to_be_bytes());
    p.push(data_status);
    p.push(0);
    p
}

/// Decode an RT frame whose C_SDU is `data_length` octets (from the IOCR). Ethernet padding
/// after the APDU status is ignored.
pub fn parse_rt(payload: &[u8], data_length: usize) -> Result<RtFrame> {
    ensure!(
        payload.len() >= 2 + data_length + 4,
        "RT frame of {} octets is shorter than FrameID + {data_length} octets of C_SDU + APDU \
         status",
        payload.len()
    );
    let a = 2 + data_length;
    Ok(RtFrame {
        frame_id: u16::from_be_bytes([payload[0], payload[1]]),
        c_sdu: payload[2..a].to_vec(),
        cycle_counter: u16::from_be_bytes([payload[a], payload[a + 1]]),
        data_status: payload[a + 2],
        transfer_status: payload[a + 3],
    })
}

/// Where one submodule's data (and its IOPS right after) sits in a C_SDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataObject {
    pub slot: u16,
    pub subslot: u16,
    pub offset: usize,
    pub len: usize,
}

impl DataObject {
    pub fn iops_offset(&self) -> usize {
        self.offset + self.len
    }
}

/// Where one IOCS octet sits in a C_SDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IocsObject {
    pub slot: u16,
    pub subslot: u16,
    pub offset: usize,
}

/// The arrangement of one IOCR's C_SDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrLayout {
    pub data_length: usize,
    pub objects: Vec<DataObject>,
    pub iocs: Vec<IocsObject>,
}

impl CrLayout {
    /// The layout a controller proposes for `specs`. The input CR carries every input and
    /// every no-IO submodule's data and IOPS (a no-IO submodule has zero octets of data but
    /// still an IOPS), then the IOCS for every output submodule; the output CR the reverse.
    /// Data precedes IOCS, as profinet-py and Siemens controllers lay it out.
    pub fn for_controller(specs: &[SubmoduleSpec], input_cr: bool) -> Result<Self> {
        let mut objects = Vec::new();
        let mut iocs_for = Vec::new();
        let mut off = 0usize;
        for s in specs {
            let (in_len, out_len) = (s.input_len(), s.output_len());
            let provides = if input_cr {
                in_len > 0 || out_len == 0
            } else {
                out_len > 0
            };
            let consumes = if input_cr {
                out_len > 0
            } else {
                in_len > 0 || out_len == 0
            };
            if provides {
                let len = if input_cr { in_len } else { out_len };
                objects.push(DataObject {
                    slot: s.slot,
                    subslot: s.subslot,
                    offset: off,
                    len,
                });
                off += len + 1;
            }
            if consumes {
                iocs_for.push((s.slot, s.subslot));
            }
        }
        let mut iocs = Vec::new();
        for (slot, subslot) in iocs_for {
            iocs.push(IocsObject {
                slot,
                subslot,
                offset: off,
            });
            off += 1;
        }
        ensure!(
            off <= MAX_C_SDU as usize,
            "the {} data of this layout is {off} octets, more than the {MAX_C_SDU} one frame \
             carries",
            if input_cr { "input" } else { "output" }
        );
        Ok(Self {
            data_length: off.max(MIN_C_SDU as usize),
            objects,
            iocs,
        })
    }

    /// The layout an IOCR request describes, checked against the submodules' data lengths:
    /// every object and IOCS inside DataLength and no two overlapping.
    pub fn from_request(
        data_length: u16,
        io_data: &[FrameDescriptor],
        iocs: &[FrameDescriptor],
        len_of: impl Fn(u16, u16) -> Option<usize>,
    ) -> Result<Self> {
        ensure!(
            (MIN_C_SDU..=MAX_C_SDU).contains(&data_length),
            "IOCR DataLength {data_length} is outside {MIN_C_SDU}..={MAX_C_SDU}"
        );
        let dl = data_length as usize;
        let mut used = vec![false; dl];
        let mut claim = |start: usize, len: usize, what: String| -> Result<()> {
            ensure!(
                start + len <= dl,
                "{what} at offset {start} (+{len}) runs past DataLength {dl}"
            );
            for u in &mut used[start..start + len] {
                ensure!(!*u, "{what} at offset {start} overlaps another object");
                *u = true;
            }
            Ok(())
        };
        let mut objects = Vec::new();
        for d in io_data {
            let len = len_of(d.slot, d.subslot).unwrap_or(0);
            claim(
                d.frame_offset as usize,
                len + 1,
                format!("IO data of slot {}/{:#x}", d.slot, d.subslot),
            )?;
            objects.push(DataObject {
                slot: d.slot,
                subslot: d.subslot,
                offset: d.frame_offset as usize,
                len,
            });
        }
        let mut out_iocs = Vec::new();
        for d in iocs {
            claim(
                d.frame_offset as usize,
                1,
                format!("IOCS of slot {}/{:#x}", d.slot, d.subslot),
            )?;
            out_iocs.push(IocsObject {
                slot: d.slot,
                subslot: d.subslot,
                offset: d.frame_offset as usize,
            });
        }
        Ok(Self {
            data_length: dl,
            objects,
            iocs: out_iocs,
        })
    }

    pub fn descriptors(&self) -> (Vec<FrameDescriptor>, Vec<FrameDescriptor>) {
        (
            self.objects
                .iter()
                .map(|o| FrameDescriptor {
                    slot: o.slot,
                    subslot: o.subslot,
                    frame_offset: o.offset as u16,
                })
                .collect(),
            self.iocs
                .iter()
                .map(|o| FrameDescriptor {
                    slot: o.slot,
                    subslot: o.subslot,
                    frame_offset: o.offset as u16,
                })
                .collect(),
        )
    }

    pub fn object(&self, slot: u16, subslot: u16) -> Option<&DataObject> {
        self.objects
            .iter()
            .find(|o| o.slot == slot && o.subslot == subslot)
    }
}

/// The cycle time of an IOCR in microseconds, from SendClockFactor and ReductionRatio.
pub fn cycle_micros(send_clock_factor: u16, reduction_ratio: u16) -> u64 {
    send_clock_factor as u64 * reduction_ratio as u64 * 3125 / 100
}

/// The ReductionRatio values RT_CLASS_1 allows (powers of two, 1..=512).
pub fn valid_reduction_ratio(r: u16) -> bool {
    r.is_power_of_two() && r <= 512
}

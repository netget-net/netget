//! PNIO-CM blocks — what Connect, Control, Release, Read and Write carry inside their RPC
//! bodies. Pure codec, both directions (the device parses requests and builds responses; the
//! controller does the opposite).
//!
//! Every block starts with BlockType (2), BlockLength (2: the octets after this field,
//! version included), BlockVersionHigh (1), BlockVersionLow (1), and is big-endian whatever
//! the RPC drep says. Counts a peer declares — APIs, modules, submodules, IO data objects —
//! are bounded by the constants below before anything is allocated for them.
use super::rpc::Uuid;
use anyhow::{bail, ensure, Context, Result};

pub mod block_type {
    pub const ALARM_NOTIFICATION_HIGH: u16 = 0x0001;
    pub const ALARM_NOTIFICATION_LOW: u16 = 0x0002;
    pub const WRITE_REQ: u16 = 0x0008;
    pub const READ_REQ: u16 = 0x0009;
    pub const IM0: u16 = 0x0020;
    pub const IM1: u16 = 0x0021;
    pub const IM2: u16 = 0x0022;
    pub const IM3: u16 = 0x0023;
    pub const IM4: u16 = 0x0024;
    pub const AR_REQ: u16 = 0x0101;
    pub const IOCR_REQ: u16 = 0x0102;
    pub const ALARM_CR_REQ: u16 = 0x0103;
    pub const EXPECTED_SUBMODULE_REQ: u16 = 0x0104;
    pub const PRM_SERVER_REQ: u16 = 0x0105;
    pub const MCR_REQ: u16 = 0x0106;
    pub const AR_RPC_REQ: u16 = 0x0107;
    pub const AR_VENDOR_REQ: u16 = 0x0108;
    pub const IR_INFO_REQ: u16 = 0x0109;
    pub const SR_INFO_REQ: u16 = 0x010a;
    pub const PRM_END_REQ: u16 = 0x0110;
    pub const APP_READY_REQ: u16 = 0x0112;
    pub const RELEASE_REQ: u16 = 0x0114;
    pub const PRM_BEGIN_REQ: u16 = 0x0118;
    pub const ALARM_ACK_HIGH: u16 = 0x8001;
    pub const ALARM_ACK_LOW: u16 = 0x8002;
    pub const WRITE_RES: u16 = 0x8008;
    pub const READ_RES: u16 = 0x8009;
    pub const AR_RES: u16 = 0x8101;
    pub const IOCR_RES: u16 = 0x8102;
    pub const ALARM_CR_RES: u16 = 0x8103;
    pub const MODULE_DIFF: u16 = 0x8104;
    pub const AR_SERVER: u16 = 0x8106;
    pub const PRM_END_RES: u16 = 0x8110;
    pub const APP_READY_RES: u16 = 0x8112;
    pub const RELEASE_RES: u16 = 0x8114;
    pub const PRM_BEGIN_RES: u16 = 0x8118;
}

/// ControlCommand bits (IODControlReq / IOXControlReq / IODReleaseReq).
pub mod control_command {
    pub const PRM_END: u16 = 0x0001;
    pub const APPLICATION_READY: u16 = 0x0002;
    pub const RELEASE: u16 = 0x0004;
    pub const DONE: u16 = 0x0008;
    pub const PRM_BEGIN: u16 = 0x0040;
}

/// ARType values.
pub mod ar_type {
    pub const IOC_AR_SINGLE: u16 = 0x0001;
    pub const IOS_AR: u16 = 0x0006;
    pub const IOC_AR_SINGLE_RTC3: u16 = 0x0010;
    pub const IOC_AR_SR: u16 = 0x0020;
}

/// IOCRType values.
pub mod iocr_type {
    pub const INPUT: u16 = 1;
    pub const OUTPUT: u16 = 2;
    pub const MULTICAST_PROVIDER: u16 = 3;
    pub const MULTICAST_CONSUMER: u16 = 4;
}

/// Record indices with a meaning this module knows.
pub mod index {
    pub const IM0: u16 = 0xaff0;
    pub const IM1: u16 = 0xaff1;
    pub const IM2: u16 = 0xaff2;
    pub const IM3: u16 = 0xaff3;
    pub const IM4: u16 = 0xaff4;
    pub const WRITE_MULTIPLE: u16 = 0xe040;
    /// The highest user-specific (manufacturer) record index.
    pub const USER_MAX: u16 = 0x7fff;

    pub fn name(index: u16) -> String {
        match index {
            IM0 => "I&M0".into(),
            IM1 => "I&M1".into(),
            IM2 => "I&M2".into(),
            IM3 => "I&M3".into(),
            IM4 => "I&M4".into(),
            WRITE_MULTIPLE => "WriteMultiple".into(),
            0..=USER_MAX => format!("user record {index}"),
            _ => format!("record {index:#06x}"),
        }
    }
}

pub const BLOCK_VERSION_HIGH: u8 = 1;
pub const BLOCK_VERSION_LOW: u8 = 0;

/// Blocks in one request body.
pub const MAX_BLOCKS: usize = 64;
/// IOCRs in one Connect (one input and one output is all an IOCARSingle uses).
pub const MAX_IOCRS: usize = 4;
/// APIs per block.
pub const MAX_APIS: usize = 4;
/// IO data objects / IOCS entries per IOCR, and expected submodules per AR.
pub const MAX_SUBMODULES: usize = 64;
/// C_SDU length range of an RT_CLASS_1 IOCR (IEC 61158-6-10: 40..=1440).
pub const MIN_C_SDU: u16 = 40;
pub const MAX_C_SDU: u16 = 1440;
/// The longest CMInitiatorStationName / CMResponderStationName.
pub const MAX_STATION_NAME_LEN: usize = 240;

/// One block, header decoded, body borrowed.
#[derive(Debug, Clone, Copy)]
pub struct RawBlock<'a> {
    pub block_type: u16,
    pub version: (u8, u8),
    /// The octets after BlockVersionLow.
    pub body: &'a [u8],
}

/// Split a sequence of blocks. Each BlockLength is checked against what remains.
pub fn split_blocks(mut data: &[u8]) -> Result<Vec<RawBlock<'_>>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        ensure!(
            out.len() < MAX_BLOCKS,
            "more than {MAX_BLOCKS} blocks in one PNIO body"
        );
        ensure!(
            data.len() >= 6,
            "{} trailing octets are too short for a block header",
            data.len()
        );
        let block_type = u16::from_be_bytes([data[0], data[1]]);
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        ensure!(
            len >= 2,
            "block {block_type:#06x} declares length {len}, less than its version field"
        );
        ensure!(
            4 + len <= data.len(),
            "block {block_type:#06x} declares {len} octets but only {} remain",
            data.len() - 4
        );
        out.push(RawBlock {
            block_type,
            version: (data[4], data[5]),
            body: &data[6..4 + len],
        });
        data = &data[4 + len..];
    }
    Ok(out)
}

/// Prepend a block header to `body`.
pub fn block(block_type: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + body.len());
    out.extend_from_slice(&block_type.to_be_bytes());
    out.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
    out.push(BLOCK_VERSION_HIGH);
    out.push(BLOCK_VERSION_LOW);
    out.extend_from_slice(body);
    out
}

/// A big-endian cursor that fails, naming the field, instead of panicking.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8], what: &'static str) -> Self {
        Self { data, pos: 0, what }
    }

    pub fn take(&mut self, n: usize, field: &str) -> Result<&'a [u8]> {
        let s = self.data.get(self.pos..self.pos + n).with_context(|| {
            format!(
                "{} ends inside {field} (offset {}, {} octets needed, {} left)",
                self.what,
                self.pos,
                n,
                self.data.len().saturating_sub(self.pos)
            )
        })?;
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self, field: &str) -> Result<u8> {
        Ok(self.take(1, field)?[0])
    }

    pub fn u16(&mut self, field: &str) -> Result<u16> {
        let b = self.take(2, field)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self, field: &str) -> Result<u32> {
        let b = self.take(4, field)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn uuid(&mut self, field: &str) -> Result<Uuid> {
        let mut u = [0u8; 16];
        u.copy_from_slice(self.take(16, field)?);
        Ok(u)
    }

    pub fn mac(&mut self, field: &str) -> Result<[u8; 6]> {
        let mut m = [0u8; 6];
        m.copy_from_slice(self.take(6, field)?);
        Ok(m)
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let r = &self.data[self.pos.min(self.data.len())..];
        self.pos = self.data.len();
        r
    }
}

/// ARProperties bit 30: advanced start-up, which obliges the device to answer with an
/// ARServerBlock.
pub const AR_PROPERTIES_STARTUP_ADVANCED: u32 = 1 << 30;
/// ARProperties bit 8: DeviceAccess — an IOSAR that only reads and writes records.
pub const AR_PROPERTIES_DEVICE_ACCESS: u32 = 1 << 8;

/// ARBlockReq (0x0101).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArBlockReq {
    pub ar_type: u16,
    pub ar_uuid: Uuid,
    pub session_key: u16,
    pub initiator_mac: [u8; 6],
    pub initiator_object_uuid: Uuid,
    pub ar_properties: u32,
    pub activity_timeout_factor: u16,
    pub initiator_udp_rt_port: u16,
    pub station_name: String,
}

impl ArBlockReq {
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body, "ARBlockReq");
        let ar_type = r.u16("ARType")?;
        let ar_uuid = r.uuid("ARUUID")?;
        let session_key = r.u16("SessionKey")?;
        let initiator_mac = r.mac("CMInitiatorMacAdd")?;
        let initiator_object_uuid = r.uuid("CMInitiatorObjectUUID")?;
        let ar_properties = r.u32("ARProperties")?;
        let activity_timeout_factor = r.u16("CMInitiatorActivityTimeoutFactor")?;
        let initiator_udp_rt_port = r.u16("InitiatorUDPRTPort")?;
        let name_len = r.u16("StationNameLength")? as usize;
        ensure!(
            name_len <= MAX_STATION_NAME_LEN,
            "CMInitiatorStationName length {name_len} exceeds {MAX_STATION_NAME_LEN}"
        );
        let name = r.take(name_len, "CMInitiatorStationName")?;
        Ok(Self {
            ar_type,
            ar_uuid,
            session_key,
            initiator_mac,
            initiator_object_uuid,
            ar_properties,
            activity_timeout_factor,
            initiator_udp_rt_port,
            station_name: String::from_utf8_lossy(name).into_owned(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.ar_type.to_be_bytes());
        b.extend_from_slice(&self.ar_uuid);
        b.extend_from_slice(&self.session_key.to_be_bytes());
        b.extend_from_slice(&self.initiator_mac);
        b.extend_from_slice(&self.initiator_object_uuid);
        b.extend_from_slice(&self.ar_properties.to_be_bytes());
        b.extend_from_slice(&self.activity_timeout_factor.to_be_bytes());
        b.extend_from_slice(&self.initiator_udp_rt_port.to_be_bytes());
        b.extend_from_slice(&(self.station_name.len() as u16).to_be_bytes());
        b.extend_from_slice(self.station_name.as_bytes());
        block(block_type::AR_REQ, &b)
    }
}

/// ARBlockRes (0x8101).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArBlockRes {
    pub ar_type: u16,
    pub ar_uuid: Uuid,
    pub session_key: u16,
    pub responder_mac: [u8; 6],
    pub responder_udp_rt_port: u16,
}

impl ArBlockRes {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.ar_type.to_be_bytes());
        b.extend_from_slice(&self.ar_uuid);
        b.extend_from_slice(&self.session_key.to_be_bytes());
        b.extend_from_slice(&self.responder_mac);
        b.extend_from_slice(&self.responder_udp_rt_port.to_be_bytes());
        block(block_type::AR_RES, &b)
    }

    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body, "ARBlockRes");
        Ok(Self {
            ar_type: r.u16("ARType")?,
            ar_uuid: r.uuid("ARUUID")?,
            session_key: r.u16("SessionKey")?,
            responder_mac: r.mac("CMResponderMacAdd")?,
            responder_udp_rt_port: r.u16("ResponderUDPRTPort")?,
        })
    }
}

/// One IODataObject / IOCS entry of an IOCR: where a submodule's data sits in the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameDescriptor {
    pub slot: u16,
    pub subslot: u16,
    pub frame_offset: u16,
}

/// The per-API part of an IOCRBlockReq.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IocrApi {
    pub api: u32,
    pub io_data: Vec<FrameDescriptor>,
    pub iocs: Vec<FrameDescriptor>,
}

/// IOCRProperties bits 0-3: the RT class. RT_CLASS_1 is 1 (also "2" in the legacy encoding).
pub const RT_CLASS_1: u32 = 0x01;
pub const RT_CLASS_2: u32 = 0x02;

/// IOCRBlockReq (0x0102).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocrBlockReq {
    pub iocr_type: u16,
    pub iocr_reference: u16,
    pub lt: u16,
    pub properties: u32,
    pub data_length: u16,
    pub frame_id: u16,
    pub send_clock_factor: u16,
    pub reduction_ratio: u16,
    pub phase: u16,
    pub sequence: u16,
    pub frame_send_offset: u32,
    pub watchdog_factor: u16,
    pub data_hold_factor: u16,
    pub tag_header: u16,
    pub multicast_mac: [u8; 6],
    pub apis: Vec<IocrApi>,
}

fn read_descriptors(r: &mut Reader<'_>, what: &str) -> Result<Vec<FrameDescriptor>> {
    let n = r.u16(what)? as usize;
    ensure!(
        n <= MAX_SUBMODULES,
        "{what} {n} exceeds the {MAX_SUBMODULES} this device accepts"
    );
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(FrameDescriptor {
            slot: r.u16("SlotNumber")?,
            subslot: r.u16("SubslotNumber")?,
            frame_offset: r.u16("FrameOffset")?,
        });
    }
    Ok(v)
}

impl IocrBlockReq {
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body, "IOCRBlockReq");
        let mut req = Self {
            iocr_type: r.u16("IOCRType")?,
            iocr_reference: r.u16("IOCRReference")?,
            lt: r.u16("LT")?,
            properties: r.u32("IOCRProperties")?,
            data_length: r.u16("DataLength")?,
            frame_id: r.u16("FrameID")?,
            send_clock_factor: r.u16("SendClockFactor")?,
            reduction_ratio: r.u16("ReductionRatio")?,
            phase: r.u16("Phase")?,
            sequence: r.u16("Sequence")?,
            frame_send_offset: r.u32("FrameSendOffset")?,
            watchdog_factor: r.u16("WatchdogFactor")?,
            data_hold_factor: r.u16("DataHoldFactor")?,
            tag_header: r.u16("IOCRTagHeader")?,
            multicast_mac: r.mac("IOCRMulticastMACAdd")?,
            apis: Vec::new(),
        };
        let n = r.u16("NumberOfAPIs")? as usize;
        ensure!(
            n <= MAX_APIS,
            "IOCRBlockReq NumberOfAPIs {n} exceeds {MAX_APIS}"
        );
        for _ in 0..n {
            let api = r.u32("API")?;
            let io_data = read_descriptors(&mut r, "NumberOfIODataObjects")?;
            let iocs = read_descriptors(&mut r, "NumberOfIOCS")?;
            req.apis.push(IocrApi { api, io_data, iocs });
        }
        Ok(req)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        for v in [self.iocr_type, self.iocr_reference, self.lt] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        b.extend_from_slice(&self.properties.to_be_bytes());
        for v in [
            self.data_length,
            self.frame_id,
            self.send_clock_factor,
            self.reduction_ratio,
            self.phase,
            self.sequence,
        ] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        b.extend_from_slice(&self.frame_send_offset.to_be_bytes());
        for v in [self.watchdog_factor, self.data_hold_factor, self.tag_header] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        b.extend_from_slice(&self.multicast_mac);
        b.extend_from_slice(&(self.apis.len() as u16).to_be_bytes());
        for a in &self.apis {
            b.extend_from_slice(&a.api.to_be_bytes());
            for list in [&a.io_data, &a.iocs] {
                b.extend_from_slice(&(list.len() as u16).to_be_bytes());
                for d in list {
                    b.extend_from_slice(&d.slot.to_be_bytes());
                    b.extend_from_slice(&d.subslot.to_be_bytes());
                    b.extend_from_slice(&d.frame_offset.to_be_bytes());
                }
            }
        }
        block(block_type::IOCR_REQ, &b)
    }

    pub fn rt_class(&self) -> u32 {
        self.properties & 0x0f
    }

    /// The cycle this IOCR runs at: SendClockFactor × ReductionRatio × 31.25 µs.
    pub fn cycle_micros(&self) -> u64 {
        self.send_clock_factor as u64 * self.reduction_ratio as u64 * 3125 / 100
    }
}

/// IOCRBlockRes (0x8102).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IocrBlockRes {
    pub iocr_type: u16,
    pub iocr_reference: u16,
    pub frame_id: u16,
}

impl IocrBlockRes {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        for v in [self.iocr_type, self.iocr_reference, self.frame_id] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        block(block_type::IOCR_RES, &b)
    }

    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body, "IOCRBlockRes");
        Ok(Self {
            iocr_type: r.u16("IOCRType")?,
            iocr_reference: r.u16("IOCRReference")?,
            frame_id: r.u16("FrameID")?,
        })
    }
}

/// AlarmCRBlockReq (0x0103).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlarmCrBlockReq {
    pub alarm_cr_type: u16,
    pub lt: u16,
    pub properties: u32,
    pub rta_timeout_factor: u16,
    pub rta_retries: u16,
    pub local_alarm_reference: u16,
    pub max_alarm_data_length: u16,
    pub tag_header_high: u16,
    pub tag_header_low: u16,
}

impl AlarmCrBlockReq {
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body, "AlarmCRBlockReq");
        Ok(Self {
            alarm_cr_type: r.u16("AlarmCRType")?,
            lt: r.u16("LT")?,
            properties: r.u32("AlarmCRProperties")?,
            rta_timeout_factor: r.u16("RTATimeoutFactor")?,
            rta_retries: r.u16("RTARetries")?,
            local_alarm_reference: r.u16("LocalAlarmReference")?,
            max_alarm_data_length: r.u16("MaxAlarmDataLength")?,
            tag_header_high: r.u16("AlarmCRTagHeaderHigh")?,
            tag_header_low: r.u16("AlarmCRTagHeaderLow")?,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.alarm_cr_type.to_be_bytes());
        b.extend_from_slice(&self.lt.to_be_bytes());
        b.extend_from_slice(&self.properties.to_be_bytes());
        for v in [
            self.rta_timeout_factor,
            self.rta_retries,
            self.local_alarm_reference,
            self.max_alarm_data_length,
            self.tag_header_high,
            self.tag_header_low,
        ] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        block(block_type::ALARM_CR_REQ, &b)
    }
}

/// AlarmCRBlockRes (0x8103).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlarmCrBlockRes {
    pub alarm_cr_type: u16,
    pub local_alarm_reference: u16,
    pub max_alarm_data_length: u16,
}

impl AlarmCrBlockRes {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        for v in [
            self.alarm_cr_type,
            self.local_alarm_reference,
            self.max_alarm_data_length,
        ] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        block(block_type::ALARM_CR_RES, &b)
    }

    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body, "AlarmCRBlockRes");
        Ok(Self {
            alarm_cr_type: r.u16("AlarmCRType")?,
            local_alarm_reference: r.u16("LocalAlarmReference")?,
            max_alarm_data_length: r.u16("MaxAlarmDataLength")?,
        })
    }
}

/// SubmoduleProperties type (bits 0-1).
pub mod submodule_kind {
    pub const NO_IO: u16 = 0;
    pub const INPUT: u16 = 1;
    pub const OUTPUT: u16 = 2;
    pub const INPUT_OUTPUT: u16 = 3;
}

/// DataDescription direction.
pub mod data_direction {
    pub const INPUT: u16 = 1;
    pub const OUTPUT: u16 = 2;
}

/// One submodule of an ExpectedSubmoduleBlockReq, with its data lengths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedSubmodule {
    pub api: u32,
    pub slot: u16,
    pub module_ident: u32,
    pub module_properties: u16,
    pub subslot: u16,
    pub submodule_ident: u32,
    pub submodule_properties: u16,
    pub input_length: u16,
    pub output_length: u16,
}

impl ExpectedSubmodule {
    pub fn kind(&self) -> u16 {
        self.submodule_properties & 0x3
    }
}

/// Parse one ExpectedSubmoduleBlockReq into a flat list of its submodules.
pub fn parse_expected_submodules(body: &[u8]) -> Result<Vec<ExpectedSubmodule>> {
    let mut r = Reader::new(body, "ExpectedSubmoduleBlockReq");
    let n_api = r.u16("NumberOfAPIs")? as usize;
    ensure!(
        n_api <= MAX_APIS,
        "ExpectedSubmoduleBlockReq NumberOfAPIs {n_api} exceeds {MAX_APIS}"
    );
    let mut out = Vec::new();
    for _ in 0..n_api {
        let api = r.u32("API")?;
        let slot = r.u16("SlotNumber")?;
        let module_ident = r.u32("ModuleIdentNumber")?;
        let module_properties = r.u16("ModuleProperties")?;
        let n_sub = r.u16("NumberOfSubmodules")? as usize;
        ensure!(
            n_sub <= MAX_SUBMODULES,
            "NumberOfSubmodules {n_sub} in slot {slot} exceeds {MAX_SUBMODULES}"
        );
        for _ in 0..n_sub {
            ensure!(
                out.len() < MAX_SUBMODULES,
                "more than {MAX_SUBMODULES} expected submodules in one block"
            );
            let subslot = r.u16("SubslotNumber")?;
            let submodule_ident = r.u32("SubmoduleIdentNumber")?;
            let submodule_properties = r.u16("SubmoduleProperties")?;
            let kind = submodule_properties & 0x3;
            let descriptions = if kind == submodule_kind::INPUT_OUTPUT {
                2
            } else {
                1
            };
            let (mut input_length, mut output_length) = (0u16, 0u16);
            for _ in 0..descriptions {
                let direction = r.u16("DataDescription")?;
                let length = r.u16("SubmoduleDataLength")?;
                let iocs = r.u8("LengthIOCS")?;
                let iops = r.u8("LengthIOPS")?;
                ensure!(
                    iocs == 1 && iops == 1,
                    "slot {slot}/{subslot:#x}: LengthIOCS {iocs} / LengthIOPS {iops}, only 1 is \
                     defined"
                );
                ensure!(
                    length <= MAX_C_SDU,
                    "slot {slot}/{subslot:#x}: SubmoduleDataLength {length} exceeds \
                     {MAX_C_SDU}"
                );
                match direction {
                    data_direction::INPUT => input_length = length,
                    data_direction::OUTPUT => output_length = length,
                    other => bail!(
                        "slot {slot}/{subslot:#x}: DataDescription {other} is neither input \
                         (1) nor output (2)"
                    ),
                }
            }
            out.push(ExpectedSubmodule {
                api,
                slot,
                module_ident,
                module_properties,
                subslot,
                submodule_ident,
                submodule_properties,
                input_length,
                output_length,
            });
        }
    }
    Ok(out)
}

/// One ExpectedSubmoduleBlockReq for every submodule in one slot (the conventional shape:
/// one block per module).
pub fn encode_expected_slot(subs: &[&ExpectedSubmodule]) -> Result<Vec<u8>> {
    let first = subs
        .first()
        .context("an ExpectedSubmoduleBlockReq needs at least one submodule")?;
    let mut b = Vec::new();
    b.extend_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&first.api.to_be_bytes());
    b.extend_from_slice(&first.slot.to_be_bytes());
    b.extend_from_slice(&first.module_ident.to_be_bytes());
    b.extend_from_slice(&first.module_properties.to_be_bytes());
    b.extend_from_slice(&(subs.len() as u16).to_be_bytes());
    for s in subs {
        b.extend_from_slice(&s.subslot.to_be_bytes());
        b.extend_from_slice(&s.submodule_ident.to_be_bytes());
        b.extend_from_slice(&s.submodule_properties.to_be_bytes());
        let mut desc = |direction: u16, length: u16| {
            b.extend_from_slice(&direction.to_be_bytes());
            b.extend_from_slice(&length.to_be_bytes());
            b.push(1);
            b.push(1);
        };
        match s.kind() {
            submodule_kind::NO_IO => desc(data_direction::INPUT, 0),
            submodule_kind::INPUT => desc(data_direction::INPUT, s.input_length),
            submodule_kind::OUTPUT => desc(data_direction::OUTPUT, s.output_length),
            _ => {
                desc(data_direction::INPUT, s.input_length);
                desc(data_direction::OUTPUT, s.output_length);
            }
        }
    }
    Ok(block(block_type::EXPECTED_SUBMODULE_REQ, &b))
}

/// ModuleState values in a ModuleDiffBlock.
pub mod module_state {
    pub const NO_MODULE: u16 = 0;
    pub const WRONG_MODULE: u16 = 1;
    pub const PROPER_MODULE: u16 = 2;
    pub const SUBSTITUTE: u16 = 3;
}

/// SubmoduleState IdentInfo (bits 11-14) with FormatIndicator (bit 15) set.
pub mod submodule_state {
    pub const OK: u16 = 0x8000;
    pub const SUBSTITUTE: u16 = 0x8000 | (1 << 11);
    pub const WRONG: u16 = 0x8000 | (2 << 11);
    pub const NO_SUBMODULE: u16 = 0x8000 | (3 << 11);

    pub fn name(state: u16) -> &'static str {
        match (state >> 11) & 0xf {
            0 => "ok",
            1 => "substitute",
            2 => "wrong",
            3 => "no_submodule",
            _ => "unknown",
        }
    }
}

/// One entry of a ModuleDiffBlock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDiff {
    pub api: u32,
    pub slot: u16,
    pub module_ident: u32,
    pub module_state: u16,
    /// (subslot, real submodule ident, SubmoduleState)
    pub submodules: Vec<(u16, u32, u16)>,
}

pub fn module_state_name(state: u16) -> &'static str {
    match state {
        module_state::NO_MODULE => "no_module",
        module_state::WRONG_MODULE => "wrong_module",
        module_state::PROPER_MODULE => "proper_module",
        module_state::SUBSTITUTE => "substitute",
        _ => "unknown",
    }
}

/// Encode a ModuleDiffBlock (0x8104), grouping entries by API.
pub fn encode_module_diff(diffs: &[ModuleDiff]) -> Vec<u8> {
    let mut apis: Vec<u32> = diffs.iter().map(|d| d.api).collect();
    apis.dedup();
    let mut b = Vec::new();
    b.extend_from_slice(&(apis.len() as u16).to_be_bytes());
    for api in apis {
        let mods: Vec<&ModuleDiff> = diffs.iter().filter(|d| d.api == api).collect();
        b.extend_from_slice(&api.to_be_bytes());
        b.extend_from_slice(&(mods.len() as u16).to_be_bytes());
        for m in mods {
            b.extend_from_slice(&m.slot.to_be_bytes());
            b.extend_from_slice(&m.module_ident.to_be_bytes());
            b.extend_from_slice(&m.module_state.to_be_bytes());
            b.extend_from_slice(&(m.submodules.len() as u16).to_be_bytes());
            for (subslot, ident, state) in &m.submodules {
                b.extend_from_slice(&subslot.to_be_bytes());
                b.extend_from_slice(&ident.to_be_bytes());
                b.extend_from_slice(&state.to_be_bytes());
            }
        }
    }
    block(block_type::MODULE_DIFF, &b)
}

pub fn parse_module_diff(body: &[u8]) -> Result<Vec<ModuleDiff>> {
    let mut r = Reader::new(body, "ModuleDiffBlock");
    let n_api = r.u16("NumberOfAPIs")? as usize;
    ensure!(
        n_api <= MAX_APIS,
        "ModuleDiffBlock NumberOfAPIs {n_api} exceeds {MAX_APIS}"
    );
    let mut out = Vec::new();
    for _ in 0..n_api {
        let api = r.u32("API")?;
        let n_mod = r.u16("NumberOfModules")? as usize;
        ensure!(
            n_mod <= MAX_SUBMODULES,
            "ModuleDiffBlock NumberOfModules {n_mod} exceeds {MAX_SUBMODULES}"
        );
        for _ in 0..n_mod {
            let slot = r.u16("SlotNumber")?;
            let module_ident = r.u32("ModuleIdentNumber")?;
            let module_state = r.u16("ModuleState")?;
            let n_sub = r.u16("NumberOfSubmodules")? as usize;
            ensure!(
                n_sub <= MAX_SUBMODULES,
                "ModuleDiffBlock NumberOfSubmodules {n_sub} exceeds {MAX_SUBMODULES}"
            );
            let mut submodules = Vec::with_capacity(n_sub);
            for _ in 0..n_sub {
                submodules.push((
                    r.u16("SubslotNumber")?,
                    r.u32("SubmoduleIdentNumber")?,
                    r.u16("SubmoduleState")?,
                ));
            }
            out.push(ModuleDiff {
                api,
                slot,
                module_ident,
                module_state,
                submodules,
            });
        }
    }
    Ok(out)
}

/// ARServerBlock (0x8106): the responder's station name, padded to a multiple of four.
pub fn encode_ar_server(station_name: &str) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(station_name.len() as u16).to_be_bytes());
    b.extend_from_slice(station_name.as_bytes());
    // The whole block (6-octet header included) is aligned to four octets.
    while (6 + b.len()) % 4 != 0 {
        b.push(0);
    }
    block(block_type::AR_SERVER, &b)
}

/// IODControlReq / IOXControlReq / IODReleaseReq and their responses: they share one layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlBlock {
    pub block_type: u16,
    pub ar_uuid: Uuid,
    pub session_key: u16,
    pub control_command: u16,
    pub properties: u16,
}

impl ControlBlock {
    pub fn parse(raw: &RawBlock<'_>) -> Result<Self> {
        let mut r = Reader::new(raw.body, "IODControl block");
        r.take(2, "Reserved")?;
        let ar_uuid = r.uuid("ARUUID")?;
        let session_key = r.u16("SessionKey")?;
        r.take(2, "Reserved")?;
        Ok(Self {
            block_type: raw.block_type,
            ar_uuid,
            session_key,
            control_command: r.u16("ControlCommand")?,
            properties: r.u16("ControlBlockProperties")?,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0, 0];
        b.extend_from_slice(&self.ar_uuid);
        b.extend_from_slice(&self.session_key.to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&self.control_command.to_be_bytes());
        b.extend_from_slice(&self.properties.to_be_bytes());
        block(self.block_type, &b)
    }

    /// The Done response to this request (block type with the high bit set).
    pub fn done(&self) -> Self {
        Self {
            block_type: self.block_type | 0x8000,
            control_command: control_command::DONE,
            properties: 0,
            ..*self
        }
    }
}

/// IODReadReqHeader (0x0009) and IODWriteReqHeader (0x0008).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordRequest {
    pub write: bool,
    pub seq: u16,
    pub ar_uuid: Uuid,
    pub api: u32,
    pub slot: u16,
    pub subslot: u16,
    pub index: u16,
    pub record_data_length: u32,
    /// ReadImplicit names the AR it reads for here (all zero for none).
    pub target_ar_uuid: Uuid,
}

/// The longest record this device returns or accepts. Records that matter here — I&M, user
/// parameters — are tens of octets.
pub const MAX_RECORD_LEN: u32 = 1024;

impl RecordRequest {
    pub fn parse(raw: &RawBlock<'_>) -> Result<Self> {
        let write = match raw.block_type {
            block_type::READ_REQ => false,
            block_type::WRITE_REQ => true,
            other => bail!("block {other:#06x} is not IODReadReqHeader or IODWriteReqHeader"),
        };
        let mut r = Reader::new(raw.body, "IODReadReqHeader/IODWriteReqHeader");
        let seq = r.u16("SeqNumber")?;
        let ar_uuid = r.uuid("ARUUID")?;
        let api = r.u32("API")?;
        let slot = r.u16("SlotNumber")?;
        let subslot = r.u16("SubslotNumber")?;
        r.take(2, "Padding")?;
        let index = r.u16("Index")?;
        let record_data_length = r.u32("RecordDataLength")?;
        let target_ar_uuid = if write {
            r.take(24, "RWPadding")?;
            [0; 16]
        } else {
            let t = r.uuid("TargetARUUID")?;
            r.take(8, "RWPadding")?;
            t
        };
        Ok(Self {
            write,
            seq,
            ar_uuid,
            api,
            slot,
            subslot,
            index,
            record_data_length,
            target_ar_uuid,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.ar_uuid);
        b.extend_from_slice(&self.api.to_be_bytes());
        b.extend_from_slice(&self.slot.to_be_bytes());
        b.extend_from_slice(&self.subslot.to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&self.index.to_be_bytes());
        b.extend_from_slice(&self.record_data_length.to_be_bytes());
        if self.write {
            b.extend_from_slice(&[0; 24]);
            block(block_type::WRITE_REQ, &b)
        } else {
            b.extend_from_slice(&self.target_ar_uuid);
            b.extend_from_slice(&[0; 8]);
            block(block_type::READ_REQ, &b)
        }
    }

    /// IODReadResHeader (0x8009) for this read, announcing `len` octets of record data.
    pub fn read_response(&self, len: u32) -> Vec<u8> {
        let mut b = self.common_res(len);
        b.extend_from_slice(&[0; 20]);
        block(block_type::READ_RES, &b)
    }

    /// IODWriteResHeader (0x8008) for this write.
    pub fn write_response(&self, status: super::rpc::PnioStatus) -> Vec<u8> {
        let mut b = self.common_res(self.record_data_length);
        b.extend_from_slice(&status.to_u32().to_be_bytes());
        b.extend_from_slice(&[0; 16]);
        block(block_type::WRITE_RES, &b)
    }

    fn common_res(&self, len: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.ar_uuid);
        b.extend_from_slice(&self.api.to_be_bytes());
        b.extend_from_slice(&self.slot.to_be_bytes());
        b.extend_from_slice(&self.subslot.to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&self.index.to_be_bytes());
        b.extend_from_slice(&len.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]); // AdditionalValue1, AdditionalValue2
        b
    }
}

/// A read response's header and record data, from the response's blocks.
pub fn parse_read_response(blocks: &[u8]) -> Result<(u16, Vec<u8>)> {
    ensure!(
        blocks.len() >= 6,
        "Read response carries no IODReadResHeader"
    );
    let raw = split_first(blocks)?;
    ensure!(
        raw.0.block_type == block_type::READ_RES,
        "Read response starts with block {:#06x}, not IODReadResHeader",
        raw.0.block_type
    );
    let mut r = Reader::new(raw.0.body, "IODReadResHeader");
    r.take(2 + 16 + 4 + 2 + 2 + 2, "header")?;
    let index = r.u16("Index")?;
    let len = r.u32("RecordDataLength")?;
    ensure!(
        len <= MAX_RECORD_LEN,
        "RecordDataLength {len} exceeds the {MAX_RECORD_LEN} this controller reads"
    );
    let data = raw.1.get(..len as usize).with_context(|| {
        format!(
            "IODReadResHeader announces {len} octets of record data but {} follow",
            raw.1.len()
        )
    })?;
    Ok((index, data.to_vec()))
}

/// The first block and everything after it, without splitting the remainder (record data is
/// not a block sequence).
fn split_first(data: &[u8]) -> Result<(RawBlock<'_>, &[u8])> {
    ensure!(data.len() >= 6, "too short for a block header");
    let block_type = u16::from_be_bytes([data[0], data[1]]);
    let len = u16::from_be_bytes([data[2], data[3]]) as usize;
    ensure!(
        len >= 2 && 4 + len <= data.len(),
        "block {block_type:#06x} declares {len} octets, {} remain",
        data.len() - 4
    );
    Ok((
        RawBlock {
            block_type,
            version: (data[4], data[5]),
            body: &data[6..4 + len],
        },
        &data[4 + len..],
    ))
}

/// A write request's header block and its record data.
pub fn split_write_request(data: &[u8]) -> Result<(RecordRequest, &[u8])> {
    let (raw, rest) = split_first(data)?;
    let req = RecordRequest::parse(&raw)?;
    ensure!(
        req.write,
        "Write request does not start with IODWriteReqHeader"
    );
    ensure!(
        req.record_data_length <= MAX_RECORD_LEN,
        "RecordDataLength {} exceeds the {MAX_RECORD_LEN} this device accepts",
        req.record_data_length
    );
    let record = rest
        .get(..req.record_data_length as usize)
        .with_context(|| {
            format!(
                "IODWriteReqHeader announces {} octets of record data but {} follow",
                req.record_data_length,
                rest.len()
            )
        })?;
    Ok((req, record))
}

/// I&M0 (index 0xAFF0, block 0x0020).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Im0 {
    pub vendor_id: u16,
    pub order_id: String,
    pub serial_number: String,
    pub hardware_revision: u16,
    /// (prefix 'V'/'R'/'P'/'U'/'T', functional enhancement, bug fix, internal change)
    pub software_revision: (u8, u8, u8, u8),
    pub revision_counter: u16,
    pub profile_id: u16,
    pub profile_specific_type: u16,
    pub im_version: (u8, u8),
    pub im_supported: u16,
}

/// A visible string padded with spaces to its fixed width, refusing text that does not fit
/// or is not printable ASCII (VisibleString).
pub fn put_visible(out: &mut Vec<u8>, value: &str, width: usize, field: &str) -> Result<()> {
    ensure!(
        value.len() <= width,
        "{field} is {} characters, the field holds {width}",
        value.len()
    );
    ensure!(
        value.bytes().all(|c| (0x20..0x7f).contains(&c)),
        "{field} must be printable ASCII"
    );
    out.extend_from_slice(value.as_bytes());
    out.extend(std::iter::repeat_n(b' ', width - value.len()));
    Ok(())
}

pub fn get_visible(b: &[u8]) -> String {
    crate::utils::sanitize::line_field(String::from_utf8_lossy(b).trim_end_matches([' ', '\0']))
}

impl Im0 {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.vendor_id.to_be_bytes());
        put_visible(&mut b, &self.order_id, 20, "order_id")?;
        put_visible(&mut b, &self.serial_number, 16, "serial_number")?;
        b.extend_from_slice(&self.hardware_revision.to_be_bytes());
        let (p, f, x, i) = self.software_revision;
        b.extend_from_slice(&[p, f, x, i]);
        b.extend_from_slice(&self.revision_counter.to_be_bytes());
        b.extend_from_slice(&self.profile_id.to_be_bytes());
        b.extend_from_slice(&self.profile_specific_type.to_be_bytes());
        b.extend_from_slice(&[self.im_version.0, self.im_version.1]);
        b.extend_from_slice(&self.im_supported.to_be_bytes());
        Ok(block(block_type::IM0, &b))
    }

    pub fn parse(record: &[u8]) -> Result<Self> {
        let raw = split_first(record)?.0;
        ensure!(
            raw.block_type == block_type::IM0,
            "record is block {:#06x}, not I&M0Data (0x0020)",
            raw.block_type
        );
        let mut r = Reader::new(raw.body, "I&M0Data");
        Ok(Self {
            vendor_id: r.u16("VendorID")?,
            order_id: get_visible(r.take(20, "OrderID")?),
            serial_number: get_visible(r.take(16, "IM_Serial_Number")?),
            hardware_revision: r.u16("IM_Hardware_Revision")?,
            software_revision: {
                let s = r.take(4, "IM_Software_Revision")?;
                (s[0], s[1], s[2], s[3])
            },
            revision_counter: r.u16("IM_Revision_Counter")?,
            profile_id: r.u16("IM_Profile_ID")?,
            profile_specific_type: r.u16("IM_Profile_Specific_Type")?,
            im_version: {
                let v = r.take(2, "IM_Version")?;
                (v[0], v[1])
            },
            im_supported: r.u16("IM_Supported")?,
        })
    }

    pub fn software_revision_text(&self) -> String {
        let (p, f, x, i) = self.software_revision;
        format!("{}{f}.{x}.{i}", p as char)
    }
}

/// Parse "V1.2.3" into (prefix, functional enhancement, bug fix, internal change).
pub fn parse_software_revision(text: &str) -> Result<(u8, u8, u8, u8)> {
    let mut chars = text.chars();
    let prefix = chars.next().context("software_revision is empty")?;
    ensure!(
        matches!(prefix, 'V' | 'R' | 'P' | 'U' | 'T'),
        "software_revision {text:?} must start with V, R, P, U or T (e.g. \"V1.2.3\")"
    );
    let nums: Vec<&str> = chars.as_str().split('.').collect();
    ensure!(
        nums.len() == 3,
        "software_revision {text:?} must be prefix and three numbers, e.g. \"V1.2.3\""
    );
    let n = |s: &str| -> Result<u8> {
        s.parse::<u8>()
            .with_context(|| format!("software_revision {text:?}: {s:?} is not 0-255"))
    };
    Ok((prefix as u8, n(nums[0])?, n(nums[1])?, n(nums[2])?))
}

/// I&M1..I&M3 as text fields (I&M4 is a binary signature and is refused rather than shown).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImText {
    /// I&M1: TagFunction (32), TagLocation (22).
    Im1 {
        tag_function: String,
        tag_location: String,
    },
    /// I&M2: InstallationDate, "YYYY-MM-DD HH:MM" (16).
    Im2 { installation_date: String },
    /// I&M3: Descriptor (54).
    Im3 { descriptor: String },
}

impl ImText {
    pub fn index(&self) -> u16 {
        match self {
            ImText::Im1 { .. } => index::IM1,
            ImText::Im2 { .. } => index::IM2,
            ImText::Im3 { .. } => index::IM3,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut b = Vec::new();
        let t = match self {
            ImText::Im1 {
                tag_function,
                tag_location,
            } => {
                put_visible(&mut b, tag_function, 32, "tag_function")?;
                put_visible(&mut b, tag_location, 22, "tag_location")?;
                block_type::IM1
            }
            ImText::Im2 { installation_date } => {
                put_visible(&mut b, installation_date, 16, "installation_date")?;
                block_type::IM2
            }
            ImText::Im3 { descriptor } => {
                put_visible(&mut b, descriptor, 54, "descriptor")?;
                block_type::IM3
            }
        };
        Ok(block(t, &b))
    }

    pub fn parse(record: &[u8]) -> Result<Self> {
        let raw = split_first(record)?.0;
        let mut r = Reader::new(raw.body, "I&M record");
        Ok(match raw.block_type {
            block_type::IM1 => ImText::Im1 {
                tag_function: get_visible(r.take(32, "IM_Tag_Function")?),
                tag_location: get_visible(r.take(22, "IM_Tag_Location")?),
            },
            block_type::IM2 => ImText::Im2 {
                installation_date: get_visible(r.take(16, "IM_Date")?),
            },
            block_type::IM3 => ImText::Im3 {
                descriptor: get_visible(r.take(54, "IM_Descriptor")?),
            },
            other => bail!("record is block {other:#06x}, not I&M1-3"),
        })
    }
}

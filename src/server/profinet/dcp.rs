//! PROFINET DCP (Discovery and basic Configuration Protocol, IEC 61158-6-10 §4.3) — the pure
//! codec. No socket, no state: frames in, structured values out, and back.
//!
//! A DCP PDU rides directly on Ethernet (EtherType `0x8892`) after a two-byte FrameID:
//!
//! | FrameID | Meaning |
//! |---|---|
//! | `0xFEFC` | Hello (a device announcing itself; multicast `01:0E:CF:00:00:01`) |
//! | `0xFEFD` | Get / Set request and response (unicast) |
//! | `0xFEFE` | Identify request (multicast `01:0E:CF:00:00:00`, or unicast) |
//! | `0xFEFF` | Identify response (unicast) |
//!
//! then a ten-byte header — ServiceID, ServiceType, Xid (4), ResponseDelay (2),
//! DCPDataLength (2) — and a list of blocks: Option, Suboption, DCPBlockLength (2), the value,
//! and a pad byte when the length is odd. Every integer is big-endian.
//!
//! Three things make the block list less uniform than it looks, and each is a branch below:
//!
//! * A **Get request** carries bare `(option, suboption)` pairs — no length, no value.
//! * In an **Identify / Get response** every block value starts with a two-byte *BlockInfo*.
//! * In a **Set request** every block value starts with a two-byte *BlockQualifier*
//!   (bit 0: store permanently).
//!
//! Everything a peer declares is bounded before it is used: the data length against the
//! frame, each block length against what is left, the block count against [`MAX_BLOCKS`].
use anyhow::{bail, ensure, Context, Result};
use std::net::Ipv4Addr;

pub const ETHERTYPE_PROFINET: u16 = 0x8892;
pub const MULTICAST_IDENTIFY: [u8; 6] = [0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00];
pub const MULTICAST_HELLO: [u8; 6] = [0x01, 0x0e, 0xcf, 0x00, 0x00, 0x01];

pub mod frame_id {
    pub const HELLO: u16 = 0xfefc;
    pub const GET_SET: u16 = 0xfefd;
    pub const IDENTIFY_REQUEST: u16 = 0xfefe;
    pub const IDENTIFY_RESPONSE: u16 = 0xfeff;
}

pub mod service {
    pub const GET: u8 = 3;
    pub const SET: u8 = 4;
    pub const IDENTIFY: u8 = 5;
    pub const HELLO: u8 = 6;
}

pub mod service_type {
    pub const REQUEST: u8 = 0;
    pub const RESPONSE_SUCCESS: u8 = 1;
    pub const RESPONSE_NOT_SUPPORTED: u8 = 5;
}

pub mod opt {
    pub const IP: u8 = 0x01;
    pub const DEVICE: u8 = 0x02;
    pub const DHCP: u8 = 0x03;
    pub const CONTROL: u8 = 0x05;
    pub const DEVICE_INITIATIVE: u8 = 0x06;
    pub const ALL: u8 = 0xff;
}

pub mod sub {
    // IP
    pub const IP_MAC: u8 = 0x01;
    pub const IP_PARAMETER: u8 = 0x02;
    pub const IP_FULL_SUITE: u8 = 0x03;
    // Device properties
    pub const DEVICE_VENDOR: u8 = 0x01;
    pub const DEVICE_NAME_OF_STATION: u8 = 0x02;
    pub const DEVICE_ID: u8 = 0x03;
    pub const DEVICE_ROLE: u8 = 0x04;
    pub const DEVICE_OPTIONS: u8 = 0x05;
    pub const DEVICE_ALIAS: u8 = 0x06;
    pub const DEVICE_INSTANCE: u8 = 0x07;
    pub const DEVICE_OEM_ID: u8 = 0x08;
    // Control
    pub const CONTROL_START: u8 = 0x01;
    pub const CONTROL_STOP: u8 = 0x02;
    pub const CONTROL_SIGNAL: u8 = 0x03;
    pub const CONTROL_RESPONSE: u8 = 0x04;
    pub const CONTROL_FACTORY_RESET: u8 = 0x05;
    pub const CONTROL_RESET_TO_FACTORY: u8 = 0x06;
    // All selector
    pub const ALL: u8 = 0xff;
}

/// BlockError values in a Control/Response block (the answer to each block of a Set).
pub mod block_error {
    pub const OK: u8 = 0x00;
    pub const OPTION_NOT_SUPPORTED: u8 = 0x01;
    pub const SUBOPTION_NOT_SUPPORTED: u8 = 0x02;
    pub const SUBOPTION_NOT_SET: u8 = 0x03;
    pub const RESOURCE_ERROR: u8 = 0x04;
    pub const SET_NOT_POSSIBLE: u8 = 0x05;
    pub const IN_OPERATION: u8 = 0x06;

    pub fn name(code: u8) -> &'static str {
        match code {
            OK => "ok",
            OPTION_NOT_SUPPORTED => "option_not_supported",
            SUBOPTION_NOT_SUPPORTED => "suboption_not_supported",
            SUBOPTION_NOT_SET => "suboption_not_set",
            RESOURCE_ERROR => "resource_error",
            SET_NOT_POSSIBLE => "set_not_possible",
            IN_OPERATION => "in_operation",
            _ => "unknown",
        }
    }
}

/// Device roles (DeviceRoleDetails), bit flags.
pub mod role {
    pub const IO_DEVICE: u8 = 0x01;
    pub const IO_CONTROLLER: u8 = 0x02;
    pub const IO_MULTIDEVICE: u8 = 0x04;
    pub const IO_SUPERVISOR: u8 = 0x08;
}

/// The longest DCPDataLength a frame can carry: 1500 octets of Ethernet payload, less the
/// FrameID (2) and the DCP header (10).
pub const MAX_DCP_DATA_LEN: usize = 1488;
/// Blocks in one PDU. Every real request carries well under ten; an Identify response from a
/// fully featured device about fifteen.
pub const MAX_BLOCKS: usize = 32;
/// NameOfStation: at most 240 octets (IEC 61158-6-10, NameOfStationValue).
pub const MAX_STATION_NAME_LEN: usize = 240;
/// The longest DeviceVendorValue (TypeOfStation) accepted or sent.
pub const MAX_VENDOR_VALUE_LEN: usize = 255;
/// The largest ResponseDelayFactor a device honours (spec: 1..6400, times 10 ms).
pub const MAX_RESPONSE_DELAY_FACTOR: u16 = 6400;

/// One DCP block as it appears on the wire. `value` is everything after DCPBlockLength and
/// before the pad byte — including BlockInfo or BlockQualifier where the context has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub option: u8,
    pub suboption: u8,
    pub value: Vec<u8>,
}

impl Block {
    pub fn new(option: u8, suboption: u8, value: Vec<u8>) -> Self {
        Self {
            option,
            suboption,
            value,
        }
    }

    /// A block whose value is a BlockInfo / BlockQualifier followed by `data`.
    pub fn with_prefix(option: u8, suboption: u8, prefix: u16, data: &[u8]) -> Self {
        let mut value = prefix.to_be_bytes().to_vec();
        value.extend_from_slice(data);
        Self::new(option, suboption, value)
    }

    /// The two-byte BlockInfo / BlockQualifier and the rest, for a block that has one.
    pub fn split_prefix(&self) -> Result<(u16, &[u8])> {
        ensure!(
            self.value.len() >= 2,
            "DCP block {:#04x}/{:#04x} is {} octets, too short for its BlockInfo/BlockQualifier",
            self.option,
            self.suboption,
            self.value.len()
        );
        Ok((
            u16::from_be_bytes([self.value[0], self.value[1]]),
            &self.value[2..],
        ))
    }
}

/// A whole DCP PDU, FrameID included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    pub frame_id: u16,
    pub service_id: u8,
    pub service_type: u8,
    pub xid: u32,
    /// ResponseDelayFactor in an Identify request; reserved (0) elsewhere.
    pub response_delay: u16,
    pub blocks: Vec<Block>,
}

impl Pdu {
    pub fn is_request(&self) -> bool {
        self.service_type == service_type::REQUEST
    }

    pub fn block(&self, option: u8, suboption: u8) -> Option<&Block> {
        self.blocks
            .iter()
            .find(|b| b.option == option && b.suboption == suboption)
    }

    /// Wire bytes, starting at the FrameID (what follows the EtherType).
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.blocks.len() <= MAX_BLOCKS,
            "a DCP PDU carries at most {MAX_BLOCKS} blocks, this one has {}",
            self.blocks.len()
        );
        let get_request = self.service_id == service::GET && self.is_request();
        let mut data = Vec::new();
        for b in &self.blocks {
            data.push(b.option);
            data.push(b.suboption);
            if get_request {
                continue;
            }
            ensure!(
                b.value.len() <= u16::MAX as usize,
                "DCP block value of {} octets does not fit its 16-bit length",
                b.value.len()
            );
            data.extend_from_slice(&(b.value.len() as u16).to_be_bytes());
            data.extend_from_slice(&b.value);
            if b.value.len() % 2 == 1 {
                data.push(0);
            }
        }
        ensure!(
            data.len() <= MAX_DCP_DATA_LEN,
            "DCP data of {} octets exceeds the {MAX_DCP_DATA_LEN} an Ethernet frame carries",
            data.len()
        );
        let mut out = Vec::with_capacity(12 + data.len());
        out.extend_from_slice(&self.frame_id.to_be_bytes());
        out.push(self.service_id);
        out.push(self.service_type);
        out.extend_from_slice(&self.xid.to_be_bytes());
        out.extend_from_slice(&self.response_delay.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
        Ok(out)
    }

    /// Parse the bytes after the EtherType. Trailing octets past DCPDataLength (Ethernet
    /// padding up to the 60-octet minimum) are ignored, as the standard requires.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= 12,
            "DCP PDU of {} octets is shorter than FrameID + header (12)",
            bytes.len()
        );
        let frame_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        ensure!(
            is_dcp_frame_id(frame_id),
            "FrameID {frame_id:#06x} is not a DCP frame (0xFEFC-0xFEFF)"
        );
        let service_id = bytes[2];
        let service_type = bytes[3];
        let xid = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let response_delay = u16::from_be_bytes([bytes[8], bytes[9]]);
        let data_len = u16::from_be_bytes([bytes[10], bytes[11]]) as usize;
        ensure!(
            data_len <= MAX_DCP_DATA_LEN,
            "DCPDataLength {data_len} exceeds the {MAX_DCP_DATA_LEN} an Ethernet frame carries"
        );
        let data = bytes.get(12..12 + data_len).with_context(|| {
            format!(
                "DCPDataLength {data_len} runs past the end of the frame ({} octets of data)",
                bytes.len() - 12
            )
        })?;
        let get_request = service_id == service::GET && service_type == service_type::REQUEST;
        let mut blocks = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            ensure!(
                blocks.len() < MAX_BLOCKS,
                "more than {MAX_BLOCKS} DCP blocks in one PDU"
            );
            if get_request {
                ensure!(
                    pos + 2 <= data.len(),
                    "Get request ends inside an option/suboption pair"
                );
                blocks.push(Block::new(data[pos], data[pos + 1], Vec::new()));
                pos += 2;
                continue;
            }
            ensure!(
                pos + 4 <= data.len(),
                "DCP block header at offset {pos} runs past DCPDataLength {data_len}"
            );
            let option = data[pos];
            let suboption = data[pos + 1];
            let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let value = data.get(pos + 4..pos + 4 + len).with_context(|| {
                format!(
                    "DCP block {option:#04x}/{suboption:#04x} declares {len} octets but only {} \
                     remain",
                    data.len() - pos - 4
                )
            })?;
            blocks.push(Block::new(option, suboption, value.to_vec()));
            pos += 4 + len + (len % 2);
        }
        Ok(Self {
            frame_id,
            service_id,
            service_type,
            xid,
            response_delay,
            blocks,
        })
    }
}

pub fn is_dcp_frame_id(frame_id: u16) -> bool {
    (frame_id::HELLO..=frame_id::IDENTIFY_RESPONSE).contains(&frame_id)
}

/// A NameOfStation as IEC 61158-6-10 permits it: 1..=240 octets of dot-separated labels, each
/// 1..=63 of `a-z`, `0-9` and `-`, not starting or ending with `-`; not of the form `port-xyz`
/// or `port-xyz-abcde`; and not an IPv4 address in dotted decimal. Upper case is refused rather
/// than folded, because a device that lower-cased silently would answer to a different name
/// than the controller asked for.
pub fn validate_station_name(name: &str) -> Result<()> {
    ensure!(!name.is_empty(), "NameOfStation is empty");
    ensure!(
        name.len() <= MAX_STATION_NAME_LEN,
        "NameOfStation is {} octets, the limit is {MAX_STATION_NAME_LEN}",
        name.len()
    );
    ensure!(
        name.parse::<Ipv4Addr>().is_err(),
        "NameOfStation {name:?} has the form of an IP address, which the standard forbids"
    );
    for label in name.split('.') {
        ensure!(
            !label.is_empty() && label.len() <= 63,
            "NameOfStation {name:?} has a label of {} octets (1-63 allowed)",
            label.len()
        );
        ensure!(
            label
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
            "NameOfStation {name:?} may contain only a-z, 0-9, '-' and '.'"
        );
        ensure!(
            !label.starts_with('-') && !label.ends_with('-'),
            "NameOfStation {name:?} has a label starting or ending with '-'"
        );
    }
    let first = name.split('.').next().unwrap_or_default();
    let is_port_name = |s: &str| {
        let b = s.as_bytes();
        (b.len() == 8 || b.len() == 14)
            && s.starts_with("port-")
            && b[5..8].iter().all(u8::is_ascii_digit)
            && (b.len() == 8 || (b[8] == b'-' && b[9..14].iter().all(u8::is_ascii_digit)))
    };
    ensure!(
        !is_port_name(first),
        "NameOfStation {name:?} has the reserved form port-xyz[-abcde]"
    );
    Ok(())
}

/// IP parameters as DCP carries them (IPParameterValue: address, mask, gateway).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpParameters {
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
}

impl IpParameters {
    pub fn encode(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&self.ip.octets());
        b[4..8].copy_from_slice(&self.netmask.octets());
        b[8..12].copy_from_slice(&self.gateway.octets());
        b
    }

    pub fn parse(b: &[u8]) -> Result<Self> {
        ensure!(
            b.len() >= 12,
            "IPParameterValue is {} octets, 12 expected",
            b.len()
        );
        let ip = |o: usize| Ipv4Addr::new(b[o], b[o + 1], b[o + 2], b[o + 3]);
        Ok(Self {
            ip: ip(0),
            netmask: ip(4),
            gateway: ip(8),
        })
    }

    /// The checks a device makes before taking an address: a usable host address, a
    /// contiguous mask, and a gateway that is either unset or on the same subnet.
    pub fn validate(&self) -> Result<()> {
        let mask = u32::from(self.netmask);
        ensure!(
            mask.leading_ones() + mask.trailing_zeros() == 32,
            "netmask {} is not contiguous",
            self.netmask
        );
        let ip = u32::from(self.ip);
        if ip == 0 {
            // 0.0.0.0/0.0.0.0/0.0.0.0 means "no address", which a controller may set.
            ensure!(
                mask == 0 && u32::from(self.gateway) == 0,
                "IP 0.0.0.0 is only valid with mask and gateway 0.0.0.0"
            );
            return Ok(());
        }
        ensure!(
            !self.ip.is_multicast() && !self.ip.is_broadcast(),
            "{} is not a usable host address",
            self.ip
        );
        let gw = u32::from(self.gateway);
        ensure!(
            gw == 0 || gw == ip || (gw & mask) == (ip & mask),
            "gateway {} is not on {}'s subnet",
            self.gateway,
            self.ip
        );
        Ok(())
    }
}

/// What a device says about itself, in the fields Identify and Get report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub mac: [u8; 6],
    pub name_of_station: String,
    pub type_of_station: String,
    pub vendor_id: u16,
    pub device_id: u16,
    pub role: u8,
    pub ip: IpParameters,
    /// BlockInfo bit 0: an IP address is set.
    pub ip_set: bool,
    pub instance: Option<(u8, u8)>,
}

/// The (option, suboption) pairs a device supports, for the DeviceOptions block.
pub const DEVICE_OPTIONS: &[(u8, u8)] = &[
    (opt::IP, sub::IP_MAC),
    (opt::IP, sub::IP_PARAMETER),
    (opt::DEVICE, sub::DEVICE_VENDOR),
    (opt::DEVICE, sub::DEVICE_NAME_OF_STATION),
    (opt::DEVICE, sub::DEVICE_ID),
    (opt::DEVICE, sub::DEVICE_ROLE),
    (opt::DEVICE, sub::DEVICE_OPTIONS),
    (opt::DEVICE, sub::DEVICE_INSTANCE),
    (opt::CONTROL, sub::CONTROL_START),
    (opt::CONTROL, sub::CONTROL_STOP),
    (opt::CONTROL, sub::CONTROL_SIGNAL),
    (opt::CONTROL, sub::CONTROL_FACTORY_RESET),
    (opt::CONTROL, sub::CONTROL_RESET_TO_FACTORY),
];

impl Identity {
    /// The value of one (option, suboption) as an Identify/Get response block, BlockInfo
    /// included; `None` for one this device does not report.
    pub fn block(&self, option: u8, suboption: u8) -> Option<Block> {
        let info = 0u16;
        Some(match (option, suboption) {
            (opt::IP, sub::IP_MAC) => Block::with_prefix(option, suboption, info, &self.mac),
            (opt::IP, sub::IP_PARAMETER) => {
                Block::with_prefix(option, suboption, u16::from(self.ip_set), &self.ip.encode())
            }
            (opt::DEVICE, sub::DEVICE_VENDOR) => {
                Block::with_prefix(option, suboption, info, self.type_of_station.as_bytes())
            }
            (opt::DEVICE, sub::DEVICE_NAME_OF_STATION) => {
                Block::with_prefix(option, suboption, info, self.name_of_station.as_bytes())
            }
            (opt::DEVICE, sub::DEVICE_ID) => {
                let mut v = self.vendor_id.to_be_bytes().to_vec();
                v.extend_from_slice(&self.device_id.to_be_bytes());
                Block::with_prefix(option, suboption, info, &v)
            }
            (opt::DEVICE, sub::DEVICE_ROLE) => {
                Block::with_prefix(option, suboption, info, &[self.role, 0])
            }
            (opt::DEVICE, sub::DEVICE_OPTIONS) => {
                let v: Vec<u8> = DEVICE_OPTIONS.iter().flat_map(|(o, s)| [*o, *s]).collect();
                Block::with_prefix(option, suboption, info, &v)
            }
            (opt::DEVICE, sub::DEVICE_INSTANCE) => {
                let (hi, lo) = self.instance?;
                Block::with_prefix(option, suboption, info, &[hi, lo])
            }
            _ => return None,
        })
    }

    /// The blocks of an Identify response, in the order devices conventionally send them.
    pub fn identify_blocks(&self) -> Vec<Block> {
        [
            (opt::DEVICE, sub::DEVICE_VENDOR),
            (opt::DEVICE, sub::DEVICE_NAME_OF_STATION),
            (opt::DEVICE, sub::DEVICE_ID),
            (opt::DEVICE, sub::DEVICE_ROLE),
            (opt::DEVICE, sub::DEVICE_OPTIONS),
            (opt::DEVICE, sub::DEVICE_INSTANCE),
            (opt::IP, sub::IP_PARAMETER),
        ]
        .iter()
        .filter_map(|(o, s)| self.block(*o, *s))
        .collect()
    }

    /// Whether an Identify request's filter blocks select this device. An AllSelector matches;
    /// every other filter block must equal what this device would report.
    pub fn matches_filter(&self, blocks: &[Block]) -> bool {
        if blocks.is_empty() {
            return false;
        }
        blocks.iter().all(|f| {
            if f.option == opt::ALL && f.suboption == sub::ALL {
                return true;
            }
            match self.block(f.option, f.suboption) {
                // A filter carries the bare value; ours has BlockInfo in front.
                Some(ours) => ours.value.get(2..) == Some(&f.value[..]),
                None => false,
            }
        })
    }
}

/// What a controller learns about a device from an Identify (or Get) response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub mac: [u8; 6],
    pub name_of_station: Option<String>,
    pub type_of_station: Option<String>,
    pub vendor_id: Option<u16>,
    pub device_id: Option<u16>,
    pub role: Option<u8>,
    pub ip: Option<IpParameters>,
    pub ip_set: Option<bool>,
    pub alias: Option<String>,
}

impl DiscoveredDevice {
    /// Read the blocks of an Identify/Get response. A block that does not parse is skipped
    /// rather than discarding the device, but a name that is not valid UTF-8 is not invented.
    pub fn from_blocks(mac: [u8; 6], blocks: &[Block]) -> Self {
        let mut d = DiscoveredDevice {
            mac,
            ..Default::default()
        };
        for b in blocks {
            let Ok((info, v)) = b.split_prefix() else {
                continue;
            };
            match (b.option, b.suboption) {
                (opt::DEVICE, sub::DEVICE_NAME_OF_STATION) => {
                    d.name_of_station = std::str::from_utf8(v).ok().map(str::to_string)
                }
                (opt::DEVICE, sub::DEVICE_VENDOR) => {
                    d.type_of_station = Some(String::from_utf8_lossy(v).into_owned())
                }
                (opt::DEVICE, sub::DEVICE_ALIAS) => {
                    d.alias = std::str::from_utf8(v).ok().map(str::to_string)
                }
                (opt::DEVICE, sub::DEVICE_ID) if v.len() >= 4 => {
                    d.vendor_id = Some(u16::from_be_bytes([v[0], v[1]]));
                    d.device_id = Some(u16::from_be_bytes([v[2], v[3]]));
                }
                (opt::DEVICE, sub::DEVICE_ROLE) if !v.is_empty() => d.role = Some(v[0]),
                (opt::IP, sub::IP_PARAMETER) => {
                    if let Ok(ip) = IpParameters::parse(v) {
                        d.ip = Some(ip);
                        d.ip_set = Some(info & 0x0001 != 0);
                    }
                }
                _ => {}
            }
        }
        d
    }
}

/// One block of a Set request, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetItem {
    NameOfStation {
        name: String,
        permanent: bool,
    },
    Ip {
        ip: IpParameters,
        permanent: bool,
    },
    /// Flash the device's identification LED (Control/Signal).
    Signal,
    /// Control/Start and Control/Stop bracket a multi-block Set; they change nothing.
    Start,
    Stop,
    FactoryReset,
    ResetToFactory {
        mode: u16,
    },
    Unsupported {
        option: u8,
        suboption: u8,
    },
}

impl SetItem {
    pub fn option(&self) -> (u8, u8) {
        match self {
            SetItem::NameOfStation { .. } => (opt::DEVICE, sub::DEVICE_NAME_OF_STATION),
            SetItem::Ip { .. } => (opt::IP, sub::IP_PARAMETER),
            SetItem::Signal => (opt::CONTROL, sub::CONTROL_SIGNAL),
            SetItem::Start => (opt::CONTROL, sub::CONTROL_START),
            SetItem::Stop => (opt::CONTROL, sub::CONTROL_STOP),
            SetItem::FactoryReset => (opt::CONTROL, sub::CONTROL_FACTORY_RESET),
            SetItem::ResetToFactory { .. } => (opt::CONTROL, sub::CONTROL_RESET_TO_FACTORY),
            SetItem::Unsupported { option, suboption } => (*option, *suboption),
        }
    }

    /// Whether this item changes anything a model should decide about.
    pub fn is_decision(&self) -> bool {
        !matches!(
            self,
            SetItem::Start | SetItem::Stop | SetItem::Unsupported { .. }
        )
    }
}

/// Decode the blocks of a Set request. A block that is malformed is an error for the whole
/// request (the device then answers each block with an error rather than guessing).
pub fn parse_set_request(blocks: &[Block]) -> Result<Vec<SetItem>> {
    let mut items = Vec::with_capacity(blocks.len());
    for b in blocks {
        let (qualifier, v) = b.split_prefix()?;
        let permanent = qualifier & 0x0001 != 0;
        items.push(match (b.option, b.suboption) {
            (opt::DEVICE, sub::DEVICE_NAME_OF_STATION) => {
                let name = std::str::from_utf8(v)
                    .context("NameOfStation in a Set request is not text")?
                    .to_string();
                // An empty name is how a controller clears it; anything else must be valid.
                if !name.is_empty() {
                    validate_station_name(&name)?;
                }
                SetItem::NameOfStation { name, permanent }
            }
            (opt::IP, sub::IP_PARAMETER) => {
                let ip = IpParameters::parse(v)?;
                ip.validate()?;
                // The lab transport runs on loopback; a peer may not move a device there.
                ensure!(
                    !ip.ip.is_loopback(),
                    "{} is a loopback address, which no device on a link can take",
                    ip.ip
                );
                SetItem::Ip { ip, permanent }
            }
            (opt::CONTROL, sub::CONTROL_SIGNAL) => {
                ensure!(
                    v.len() >= 2,
                    "Control/Signal value is {} octets, 2 expected",
                    v.len()
                );
                SetItem::Signal
            }
            (opt::CONTROL, sub::CONTROL_START) => SetItem::Start,
            (opt::CONTROL, sub::CONTROL_STOP) => SetItem::Stop,
            (opt::CONTROL, sub::CONTROL_FACTORY_RESET) => SetItem::FactoryReset,
            (opt::CONTROL, sub::CONTROL_RESET_TO_FACTORY) => SetItem::ResetToFactory {
                mode: qualifier >> 1,
            },
            (option, suboption) => SetItem::Unsupported { option, suboption },
        });
    }
    Ok(items)
}

/// A Control/Response block: the answer to one block of a Set.
pub fn set_response_block(option: u8, suboption: u8, error: u8) -> Block {
    Block::new(
        opt::CONTROL,
        sub::CONTROL_RESPONSE,
        vec![option, suboption, error],
    )
}

/// Read a Set response: every Control/Response block as ((option, suboption), BlockError).
pub fn parse_set_response(pdu: &Pdu) -> Result<Vec<((u8, u8), u8)>> {
    let mut out = Vec::new();
    for b in &pdu.blocks {
        if b.option == opt::CONTROL && b.suboption == sub::CONTROL_RESPONSE {
            ensure!(
                b.value.len() >= 3,
                "Control/Response block is {} octets, 3 expected",
                b.value.len()
            );
            out.push(((b.value[0], b.value[1]), b.value[2]));
        }
    }
    if out.is_empty() {
        bail!("the Set response carried no Control/Response block");
    }
    Ok(out)
}

/// Build a Set request block (BlockQualifier first).
pub fn set_request_block(option: u8, suboption: u8, permanent: bool, data: &[u8]) -> Block {
    Block::with_prefix(option, suboption, u16::from(permanent), data)
}

/// An Identify request for every device (AllSelector) or for one NameOfStation.
pub fn identify_request(xid: u32, name: Option<&str>, response_delay: u16) -> Pdu {
    let block = match name {
        Some(n) => Block::new(
            opt::DEVICE,
            sub::DEVICE_NAME_OF_STATION,
            n.as_bytes().to_vec(),
        ),
        None => Block::new(opt::ALL, sub::ALL, Vec::new()),
    };
    Pdu {
        frame_id: frame_id::IDENTIFY_REQUEST,
        service_id: service::IDENTIFY,
        service_type: service_type::REQUEST,
        xid,
        response_delay,
        blocks: vec![block],
    }
}

pub fn parse_mac(text: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = text.trim().split([':', '-']).collect();
    ensure!(
        parts.len() == 6,
        "MAC address {text:?} must be six hex octets, e.g. 02:00:00:00:00:01"
    );
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        ensure!(
            p.len() == 2,
            "MAC address {text:?} must be six two-digit hex octets"
        );
        mac[i] = u8::from_str_radix(p, 16)
            .with_context(|| format!("MAC address {text:?} has a non-hex octet {p:?}"))?;
    }
    Ok(mac)
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

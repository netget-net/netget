//! The co-processor's EZSP command set: what an EmberZNet NCP answers to each command the open
//! hosts send at startup and while running, its "RAM" (negotiated version, configuration,
//! values, policies, registered endpoints — all lost on a reset) and its "NVRAM" (the formed
//! network, its keys and frame counters, the devices that joined — kept across resets and
//! across host connections, as a stick's flash is).
//!
//! Commands NetGet does not implement are answered `invalidCommand(ERROR_INVALID_FRAME_ID)`,
//! the answer a real NCP gives a frame id it does not know.
use super::device::{self, Device, Endpoint};
use super::ezsp::{self, id, sl, ApsFrame, Command, NetworkParameters, Reader, Writer};
use anyhow::Result;
use std::collections::BTreeMap;

/// The Zigbee interoperability ("ZigBeeAlliance09") link key every Zigbee 3.0 trust center
/// starts with.
pub const WELL_KNOWN_LINK_KEY: [u8; 16] = *b"ZigBeeAlliance09";
/// Silicon Labs' OUI with a fixed tail: the NCP's EUI-64 when none is configured.
pub const DEFAULT_EUI64: u64 = 0x000D_6F00_0A1B_2C3D;
pub const COORDINATOR_NWK: u16 = 0x0000;
/// Endpoints a host registers with `addEndpoint`.
pub const MAX_HOST_ENDPOINTS: usize = 8;
pub const MAX_LINK_KEYS: usize = 16;
pub const MAX_MULTICAST: usize = 32;
/// The manufacturer token strings `bellows info` and zigpy print.
pub const MFG_STRING: &[u8] = b"NetGet";
pub const MFG_BOARD_NAME: &[u8] = b"NetGet EZSP NCP";

/// The formed network.
#[derive(Debug, Clone)]
pub struct Network {
    pub params: NetworkParameters,
    pub network_key: [u8; 16],
    pub key_sequence: u8,
    pub tc_link_key: [u8; 16],
    pub hashed_tclk: bool,
}

/// What survives a reset and a host reconnecting.
#[derive(Debug, Clone)]
pub struct Nvram {
    pub eui64: u64,
    pub network: Option<Network>,
    pub nwk_frame_counter: u32,
    pub aps_frame_counter: u32,
    /// Devices in the network.
    pub joined: Vec<Device>,
    /// Devices described and not (or no longer) joined.
    pub waiting: Vec<Device>,
    pub link_keys: Vec<(u64, [u8; 16])>,
}

impl Nvram {
    pub fn joined_by_nwk(&self, nwk: u16) -> Option<usize> {
        self.joined.iter().position(|d| d.nwk == nwk)
    }
    pub fn joined_by_ieee(&self, ieee: u64) -> Option<usize> {
        self.joined.iter().position(|d| d.ieee == ieee)
    }
    pub fn nwks_in_use(&self) -> Vec<u16> {
        self.joined
            .iter()
            .chain(self.waiting.iter())
            .map(|d| d.nwk)
            .collect()
    }
    /// Erase the network (leave, factory reset): its devices leave with it and go back to
    /// waiting.
    pub fn erase_network(&mut self) {
        self.network = None;
        let left: Vec<Device> = std::mem::take(&mut self.joined);
        for d in left {
            if !self.waiting.iter().any(|w| w.ieee == d.ieee) {
                self.waiting.push(d);
            }
        }
        self.link_keys.clear();
    }
}

/// `setInitialSecurityState`, held until the network is formed.
#[derive(Debug, Clone)]
pub struct InitialSecurity {
    pub bitmask: u16,
    pub preconfigured_key: [u8; 16],
    pub network_key: [u8; 16],
    pub key_sequence: u8,
}

/// An endpoint the host registered.
#[derive(Debug, Clone)]
pub struct HostEndpoint {
    pub id: u8,
    pub profile: u16,
    pub device_id: u16,
    pub version: u8,
    pub in_clusters: Vec<u16>,
    pub out_clusters: Vec<u16>,
}

impl HostEndpoint {
    fn as_endpoint(&self) -> Endpoint {
        Endpoint {
            id: self.id,
            profile: self.profile,
            device_type: self.device_id,
            version: self.version,
            in_clusters: self.in_clusters.clone(),
            out_clusters: self.out_clusters.clone(),
            attributes: BTreeMap::new(),
        }
    }
}

/// What a reset clears.
#[derive(Debug, Clone)]
pub struct Ram {
    pub version: Option<u8>,
    pub up: bool,
    pub endpoints: Vec<HostEndpoint>,
    pub config: BTreeMap<u8, u16>,
    pub values: BTreeMap<u8, Vec<u8>>,
    pub policies: BTreeMap<u8, u8>,
    pub manufacturer_code: u16,
    pub security: Option<InitialSecurity>,
    pub aps_sequence: u8,
    pub multicast: BTreeMap<u8, (u16, u8)>,
    /// EUI-64s the host gave an extended (sleepy) delivery timeout.
    pub extended_timeouts: std::collections::BTreeSet<u64>,
    /// `permitJoining` duration in effect (0 = closed); `mod.rs` times it.
    pub permit_secs: u8,
}

/// Configuration values an EmberZNet NCP reports before the host changes them.
const CONFIG_DEFAULTS: &[(u8, u16)] = &[
    (1, 255),   // PACKET_BUFFER_COUNT
    (2, 16),    // NEIGHBOR_TABLE_SIZE
    (3, 10),    // APS_UNICAST_MESSAGE_COUNT
    (4, 16),    // BINDING_TABLE_SIZE
    (5, 8),     // ADDRESS_TABLE_SIZE
    (6, 8),     // MULTICAST_TABLE_SIZE
    (7, 16),    // ROUTE_TABLE_SIZE
    (8, 8),     // DISCOVERY_TABLE_SIZE
    (12, 2),    // STACK_PROFILE
    (13, 5),    // SECURITY_LEVEL
    (16, 30),   // MAX_HOPS
    (17, 6),    // MAX_END_DEVICE_CHILDREN
    (18, 7680), // INDIRECT_TRANSMISSION_TIMEOUT
    (19, 8),    // END_DEVICE_POLL_TIMEOUT
    (24, 0),    // DISABLE_RELAY
    (25, 2),    // TRUST_CENTER_ADDRESS_CACHE_SIZE
    (26, 7),    // SOURCE_ROUTE_TABLE_SIZE
    (28, 1),    // FRAGMENT_WINDOW_SIZE
    (29, 50),   // FRAGMENT_DELAY_MS
    (30, 4),    // KEY_TABLE_SIZE
    (31, 1600), // APS_ACK_TIMEOUT
    (32, 3),    // ACTIVE_SCAN_DURATION
    (34, 1),    // PAN_ID_CONFLICT_REPORT_THRESHOLD
    (36, 0),    // REQUEST_KEY_TIMEOUT
    (42, 0),    // APPLICATION_ZDO_FLAGS
    (43, 15),   // BROADCAST_TABLE_SIZE
    (45, 1),    // SUPPORTED_NETWORKS
    (52, 16),   // RETRY_QUEUE_SIZE
    (53, 10),   // NEW_BROADCAST_ENTRY_THRESHOLD
    (54, 300),  // TRANSIENT_KEY_TIMEOUT_S
    (55, 1),    // BROADCAST_MIN_ACKS_NEEDED
    (56, 30),   // TC_REJOINS_USING_WELL_KNOWN_KEY_TIMEOUT_S
];

pub const CONFIG_KEY_TABLE_SIZE: u8 = 30;
const CONFIG_MULTICAST_TABLE_SIZE: u8 = 6;
const CONFIG_MAX_END_DEVICE_CHILDREN: u8 = 17;

/// Value ids with fixed widths NetGet answers.
mod value {
    pub const FREE_BUFFERS: u8 = 3;
    pub const MAXIMUM_INCOMING_TRANSFER_SIZE: u8 = 5;
    pub const MAXIMUM_OUTGOING_TRANSFER_SIZE: u8 = 6;
    pub const STACK_TOKEN_WRITING: u8 = 7;
    pub const EXTENDED_SECURITY_BITMASK: u8 = 10;
    pub const VERSION_INFO: u8 = 17;
    pub const CCA_THRESHOLD: u8 = 21;
    pub const NWK_FRAME_COUNTER: u8 = 35;
    pub const APS_FRAME_COUNTER: u8 = 36;
    pub const FORCE_TX_AFTER_FAILED_CCA_ATTEMPTS: u8 = 58;
    pub const TRANSIENT_DEVICE_TIMEOUT: u8 = 67;
}

/// Policy and decision ids NetGet reads.
pub mod policy {
    pub const MESSAGE_CONTENTS_IN_CALLBACK: u8 = 4;
    pub const MESSAGE_TAG_AND_CONTENTS_IN_CALLBACK: u8 = 0x41;
}

/// The EmberZNet release each EZSP version shipped in: (major, minor, patch).
pub fn stack_release(version: u8) -> (u8, u8, u8) {
    match version {
        ..=8 => (6, 10, 3),
        9 => (7, 0, 1),
        10 => (7, 1, 1),
        11 => (7, 2, 2),
        12 => (7, 3, 1),
        13 => (7, 4, 3),
        14 => (8, 0, 0),
        15 => (8, 0, 1),
        16 => (8, 0, 2),
        _ => (8, 1, 0),
    }
}

impl Ram {
    pub fn new() -> Self {
        Self {
            version: None,
            up: false,
            endpoints: Vec::new(),
            config: CONFIG_DEFAULTS.iter().copied().collect(),
            values: BTreeMap::new(),
            policies: BTreeMap::new(),
            manufacturer_code: 0x0000,
            security: None,
            aps_sequence: 0,
            multicast: BTreeMap::new(),
            extended_timeouts: std::collections::BTreeSet::new(),
            permit_secs: 0,
        }
    }

    pub fn next_aps_sequence(&mut self) -> u8 {
        self.aps_sequence = self.aps_sequence.wrapping_add(1);
        self.aps_sequence
    }

    pub fn contents_in_callback(&self) -> bool {
        self.policies.get(&policy::MESSAGE_CONTENTS_IN_CALLBACK)
            == Some(&policy::MESSAGE_TAG_AND_CONTENTS_IN_CALLBACK)
    }

    /// The endpoints the host registered, as the coordinator's ZDO describes them.
    pub fn coordinator_endpoints(&self) -> Vec<Endpoint> {
        self.endpoints
            .iter()
            .map(HostEndpoint::as_endpoint)
            .collect()
    }
}

impl Default for Ram {
    fn default() -> Self {
        Self::new()
    }
}

/// The coordinator's Node Descriptor: logical type coordinator, 2.4 GHz, an FFD that is mains
/// powered, receives when idle and allocates addresses, primary trust center and network
/// manager, stack compliance revision 22.
pub fn coordinator_node_descriptor(manufacturer_code: u16) -> Vec<u8> {
    let mut v = vec![0x00, 0x40, 0x8F];
    v.extend_from_slice(&manufacturer_code.to_le_bytes());
    v.push(0x52);
    v.extend_from_slice(&0x0080u16.to_le_bytes());
    v.extend_from_slice(&0x2C41u16.to_le_bytes());
    v.extend_from_slice(&0x0080u16.to_le_bytes());
    v.push(0x00);
    v
}

/// A callback for the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callback {
    pub frame_id: u16,
    pub params: Vec<u8>,
}

/// Something the command asks of the network beyond the NCP itself.
#[derive(Debug, Clone)]
pub enum Effect {
    /// The host opened (non-zero) or closed joining.
    Permit(u8),
    Unicast {
        nwk: u16,
        aps: ApsFrame,
        tag: u16,
        message: Vec<u8>,
        message_type: u8,
    },
    Broadcast {
        destination: u16,
        aps: ApsFrame,
        tag: u16,
        message: Vec<u8>,
    },
    Multicast {
        aps: ApsFrame,
        tag: u16,
        message: Vec<u8>,
    },
    /// The network was formed with these parameters by the host.
    Formed,
    /// The network was left or erased.
    Left,
    /// `removeDevice` asked a device to leave.
    Remove(u64),
}

/// The NCP's answer to one command.
#[derive(Debug, Default)]
pub struct Handled {
    pub response: Vec<u8>,
    pub callbacks: Vec<Callback>,
    pub effects: Vec<Effect>,
    /// The command's name for logs; `None` when it is not one NetGet implements.
    pub name: Option<&'static str>,
}

fn status_only(st: u32) -> Vec<u8> {
    st.to_le_bytes().to_vec()
}

fn stack_status(st: u32) -> Callback {
    Callback {
        frame_id: id::STACK_STATUS_HANDLER,
        params: status_only(st),
    }
}

/// `messageSentHandler` (v14+).
pub fn message_sent(
    status: u32,
    message_type: u8,
    destination: u16,
    aps: &ApsFrame,
    tag: u16,
    contents: Option<&[u8]>,
) -> Callback {
    let mut w = Writer::new();
    w.u32(status).u8(message_type).u16(destination);
    aps.write(&mut w);
    w.u16(tag).lv(contents.unwrap_or(&[]));
    Callback {
        frame_id: id::MESSAGE_SENT_HANDLER,
        params: w.done(),
    }
}

/// `incomingMessageHandler` (v14+: the APS frame, then `sl_zigbee_rx_packet_info_t`).
pub fn incoming_message(
    message_type: u8,
    aps: &ApsFrame,
    sender: u16,
    sender_eui: u64,
    message: &[u8],
) -> Callback {
    let mut w = Writer::new();
    w.u8(message_type);
    aps.write(&mut w);
    w.u16(sender)
        .eui64(sender_eui)
        .u8(0xFF)
        .u8(0xFF)
        .u8(0xFF)
        .i8(-42)
        .u32(0)
        .lv(message);
    Callback {
        frame_id: id::INCOMING_MESSAGE_HANDLER,
        params: w.done(),
    }
}

/// `trustCenterJoinHandler`.
pub fn trust_center_join(nwk: u16, ieee: u64, update: u8, decision: u8) -> Callback {
    let mut w = Writer::new();
    w.u16(nwk)
        .eui64(ieee)
        .u8(update)
        .u8(decision)
        .u16(COORDINATOR_NWK);
    Callback {
        frame_id: id::TRUST_CENTER_JOIN_HANDLER,
        params: w.done(),
    }
}

/// `childJoinHandler`.
pub fn child_join(index: u8, joining: bool, nwk: u16, ieee: u64, node_type: u8) -> Callback {
    let mut w = Writer::new();
    w.u8(index)
        .u8(joining as u8)
        .u16(nwk)
        .eui64(ieee)
        .u8(node_type);
    Callback {
        frame_id: id::CHILD_JOIN_HANDLER,
        params: w.done(),
    }
}

pub fn network_opened(open: bool) -> Callback {
    stack_status(if open {
        sl::ZIGBEE_NETWORK_OPENED
    } else {
        sl::ZIGBEE_NETWORK_CLOSED
    })
}

/// What an energy scan reports for every channel: the noise floor, as there is no radio.
pub const NOISE_FLOOR_DBM: i8 = -100;

/// Incoming message types.
pub mod incoming {
    pub const UNICAST: u8 = 0x00;
    pub const BROADCAST: u8 = 0x04;
}

/// Outgoing message types.
pub mod outgoing {
    pub const DIRECT: u8 = 0x00;
    pub const VIA_ADDRESS_TABLE: u8 = 0x01;
    pub const VIA_BINDING: u8 = 0x02;
    pub const MULTICAST: u8 = 0x03;
    pub const BROADCAST: u8 = 0x06;
}

/// `EmberDeviceUpdate` and `EmberJoinDecision` values a join reports.
pub mod join {
    pub const STANDARD_SECURITY_UNSECURED_JOIN: u8 = 0x01;
    pub const DEVICE_LEFT: u8 = 0x02;
    pub const USE_PRECONFIGURED_KEY: u8 = 0x00;
    pub const NO_ACTION: u8 = 0x03;
}

/// The security-manager context (18 bytes) an exportKey answer echoes.
#[derive(Debug, Clone, Copy)]
struct KeyContext {
    core_key_type: u8,
    key_index: u8,
    raw: [u8; 18],
}

fn read_context(r: &mut Reader) -> Result<KeyContext> {
    let b = r.bytes(18)?;
    let mut raw = [0u8; 18];
    raw.copy_from_slice(b);
    Ok(KeyContext {
        core_key_type: raw[0],
        key_index: raw[1],
        raw,
    })
}

/// Answer one command. `version` is the EZSP version this NCP speaks.
pub fn handle(version: u8, ram: &mut Ram, nv: &mut Nvram, cmd: &Command) -> Handled {
    let mut h = Handled {
        name: ezsp::name(cmd.frame_id),
        ..Default::default()
    };
    if cmd.legacy && cmd.frame_id != id::VERSION {
        h.response = ezsp::invalid_command(cmd, ezsp::ezsp_status::ERROR_UNSUPPORTED_CONTROL);
        return h;
    }
    if cmd.frame_id != id::VERSION && ram.version.is_none() {
        h.response = ezsp::invalid_command(cmd, ezsp::ezsp_status::ERROR_VERSION_NOT_SET);
        return h;
    }
    if h.name.is_none() {
        h.response = ezsp::invalid_command(cmd, ezsp::ezsp_status::ERROR_INVALID_FRAME_ID);
        return h;
    }
    let mut r = Reader::new(&cmd.params);
    match answer(version, ram, nv, cmd.frame_id, &mut r, &mut h) {
        Ok(params) => h.response = ezsp::response(cmd, &params),
        Err(e) if e.is::<NotACommand>() => {
            h.callbacks.clear();
            h.effects.clear();
            h.response = ezsp::invalid_command(cmd, ezsp::ezsp_status::ERROR_INVALID_FRAME_ID);
        }
        Err(_) => {
            // The parameters ended before the command's fields did.
            h.callbacks.clear();
            h.effects.clear();
            h.response = ezsp::invalid_command(cmd, ERROR_INVALID_VALUE);
        }
    }
    h
}

/// `EzspStatus` ERROR_INVALID_VALUE, for a command whose parameters are truncated.
const ERROR_INVALID_VALUE: u8 = 0x36;

/// A frame id `ezsp::name` knows that is not a command the host may send.
#[derive(Debug)]
struct NotACommand;

impl std::fmt::Display for NotACommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not a command a host sends")
    }
}

impl std::error::Error for NotACommand {}

fn answer(
    version: u8,
    ram: &mut Ram,
    nv: &mut Nvram,
    frame_id: u16,
    r: &mut Reader,
    h: &mut Handled,
) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    match frame_id {
        id::VERSION => {
            let desired = r.u8()?;
            if desired == version {
                ram.version = Some(version);
            }
            let (ma, mi, pa) = stack_release(version);
            let stack_version = ((ma as u16) << 12) | ((mi as u16) << 8) | ((pa as u16) << 4);
            w.u8(version).u8(ezsp::STACK_TYPE_MESH).u16(stack_version);
        }
        id::NOP => {}
        id::ADD_ENDPOINT => {
            let ep = r.u8()?;
            let profile = r.u16()?;
            let device_id = r.u16()?;
            let dev_version = r.u8()?;
            let n_in = r.u8()? as usize;
            let n_out = r.u8()? as usize;
            let mut ins = Vec::new();
            for _ in 0..n_in {
                ins.push(r.u16()?);
            }
            let mut outs = Vec::new();
            for _ in 0..n_out {
                outs.push(r.u16()?);
            }
            let st = if ram.up {
                sl::INVALID_STATE
            } else if ep == 0 || ep > 240 && ep != 242 {
                sl::INVALID_PARAMETER
            } else if ram.endpoints.iter().any(|e| e.id == ep) {
                sl::ALREADY_EXISTS
            } else if ram.endpoints.len() >= MAX_HOST_ENDPOINTS {
                sl::FULL
            } else {
                ram.endpoints.push(HostEndpoint {
                    id: ep,
                    profile,
                    device_id,
                    version: dev_version,
                    in_clusters: ins,
                    out_clusters: outs,
                });
                sl::OK
            };
            w.u32(st);
        }
        id::GET_EXTENDED_VALUE => {
            let value_id = r.u8()?;
            let characteristics = r.u32()?;
            match value_id {
                // ENDPOINT_FLAGS: enabled for a registered endpoint.
                0 => {
                    let known = ram.endpoints.iter().any(|e| e.id as u32 == characteristics);
                    w.u32(if known { sl::OK } else { sl::INVALID_INDEX })
                        .lv(&if known { [1, 0] } else { [0, 0] });
                }
                // LAST_LEAVE_REASON: none, node id.
                1 => {
                    w.u32(sl::OK).lv(&[0, 0xFF, 0xFF]);
                }
                // GET_SOURCE_ROUTE_OVERHEAD: every device is one hop from the coordinator.
                2 => {
                    w.u32(sl::OK).lv(&[0]);
                }
                // MEMORY_USAGE_DATA.
                3 => {
                    w.u32(sl::OK).lv(&[0, 0, 0, 0]);
                }
                _ => {
                    w.u32(sl::INVALID_PARAMETER).lv(&[]);
                }
            }
        }
        id::GET_MFG_TOKEN => {
            let token = r.u8()?;
            let data: Vec<u8> = match token {
                1 => pad(MFG_STRING, 16),
                2 => pad(MFG_BOARD_NAME, 16),
                // MFG_CUSTOM_EUI_64: unset (all ones) — the chip's own EUI is in use.
                12 => vec![0xFF; 8],
                // MFG_MANUF_ID, MFG_CUSTOM_VERSION, MFG_PHY_CONFIG: unset.
                0 | 3 | 4 => vec![0xFF; 2],
                _ => Vec::new(),
            };
            w.lv(&data);
        }
        id::SET_CONCENTRATOR => {
            for _ in 0..5 {
                r.u8()?;
            }
            w.u32(sl::OK);
        }
        id::SET_MANUFACTURER_CODE => {
            ram.manufacturer_code = r.u16()?;
        }
        id::NETWORK_INIT => {
            let _bitmask = r.u16()?;
            if ram.up {
                w.u32(sl::INVALID_STATE);
            } else if nv.network.is_some() {
                ram.up = true;
                w.u32(sl::OK);
                h.callbacks.push(stack_status(sl::NETWORK_UP));
            } else {
                w.u32(sl::NOT_JOINED);
            }
        }
        id::NETWORK_STATE => {
            w.u8(if ram.up { 2 } else { 0 });
        }
        id::FORM_NETWORK => {
            let params = NetworkParameters::read(r)?;
            let st = if ram.up {
                sl::INVALID_STATE
            } else if !(11..=26).contains(&params.radio_channel) || params.pan_id == 0xFFFF {
                sl::INVALID_PARAMETER
            } else if let Some(sec) = ram.security.clone() {
                // Forming starts a new network: whatever was joined before is gone.
                nv.erase_network();
                let mut params = params;
                params.nwk_manager_id = COORDINATOR_NWK;
                if params.channels == 0 {
                    params.channels = 1 << params.radio_channel;
                }
                nv.network = Some(Network {
                    params,
                    network_key: sec.network_key,
                    key_sequence: sec.key_sequence,
                    tc_link_key: sec.preconfigured_key,
                    hashed_tclk: sec.bitmask & 0x0084 == 0x0084,
                });
                ram.up = true;
                h.callbacks.push(stack_status(sl::NETWORK_UP));
                h.effects.push(Effect::Formed);
                sl::OK
            } else {
                sl::ZIGBEE_SECURITY_STATE_NOT_SET
            };
            w.u32(st);
        }
        id::LEAVE_NETWORK => {
            // From v14 a host may append EmberLeaveNetworkOption; bellows sends none.
            if ram.up {
                ram.up = false;
                ram.permit_secs = 0;
                nv.erase_network();
                w.u32(sl::OK);
                h.callbacks.push(stack_status(sl::NETWORK_DOWN));
                h.effects.push(Effect::Left);
            } else {
                w.u32(sl::INVALID_STATE);
            }
        }
        id::PERMIT_JOINING => {
            let duration = r.u8()?;
            if ram.up {
                ram.permit_secs = duration;
                w.u32(sl::OK);
                h.callbacks.push(network_opened(duration > 0));
                h.effects.push(Effect::Permit(duration));
            } else {
                w.u32(sl::NOT_JOINED);
            }
        }
        id::GET_EUI64 => {
            w.eui64(nv.eui64);
        }
        id::GET_NODE_ID => {
            w.u16(if ram.up { COORDINATOR_NWK } else { 0xFFFE });
        }
        id::GET_NETWORK_PARAMETERS => match (&nv.network, ram.up) {
            (Some(n), true) => {
                w.u32(sl::OK).u8(0x01);
                n.params.write(&mut w);
            }
            _ => {
                w.u32(sl::NOT_JOINED).u8(0x00);
                NetworkParameters::default().write(&mut w);
            }
        },
        id::SEND_UNICAST => {
            let message_type = r.u8()?;
            let nwk = r.u16()?;
            let mut aps = ApsFrame::read(r)?;
            let tag = r.u16()?;
            let message = r.lv()?.to_vec();
            let st = send_check(ram, &message);
            let seq = if st == sl::OK {
                let seq = ram.next_aps_sequence();
                aps.sequence = seq;
                h.effects.push(Effect::Unicast {
                    nwk,
                    aps,
                    tag,
                    message,
                    message_type,
                });
                seq
            } else {
                0
            };
            w.u32(st).u8(seq);
        }
        id::SEND_BROADCAST => {
            let _alias = r.u16()?;
            let destination = r.u16()?;
            let _nwk_seq = r.u8()?;
            let mut aps = ApsFrame::read(r)?;
            let _radius = r.u8()?;
            let tag = r.u16()?;
            let message = r.lv()?.to_vec();
            let st = if destination < 0xFFF8 {
                sl::INVALID_PARAMETER
            } else {
                send_check(ram, &message)
            };
            let seq = if st == sl::OK {
                let seq = ram.next_aps_sequence();
                aps.sequence = seq;
                h.effects.push(Effect::Broadcast {
                    destination,
                    aps,
                    tag,
                    message,
                });
                seq
            } else {
                0
            };
            w.u32(st).u8(seq);
        }
        id::SEND_MULTICAST => {
            let mut aps = ApsFrame::read(r)?;
            let _hops = r.u8()?;
            let _bcast = r.u16()?;
            let _alias = r.u16()?;
            let _nwk_seq = r.u8()?;
            let tag = r.u16()?;
            let message = r.lv()?.to_vec();
            let st = send_check(ram, &message);
            let seq = if st == sl::OK {
                let seq = ram.next_aps_sequence();
                aps.sequence = seq;
                h.effects.push(Effect::Multicast { aps, tag, message });
                seq
            } else {
                0
            };
            w.u32(st).u8(seq);
        }
        id::START_SCAN => {
            // An energy scan reports every channel asked for and completes; there is no
            // radio, so each reads the noise floor. An active scan finds no beacon.
            let scan_type = r.u8()?;
            let mask = r.u32()? & 0x07FF_F800;
            let _duration = r.u8()?;
            if scan_type > 1 {
                w.u32(sl::INVALID_PARAMETER);
            } else {
                w.u32(sl::OK);
                if scan_type == 0 {
                    for channel in 11u8..=26 {
                        if mask & (1 << channel) != 0 {
                            let mut c = Writer::new();
                            c.u8(channel).i8(NOISE_FLOOR_DBM);
                            h.callbacks.push(Callback {
                                frame_id: id::ENERGY_SCAN_RESULT_HANDLER,
                                params: c.done(),
                            });
                        }
                    }
                }
                let mut c = Writer::new();
                c.u8(0).u32(sl::OK);
                h.callbacks.push(Callback {
                    frame_id: id::SCAN_COMPLETE_HANDLER,
                    params: c.done(),
                });
            }
        }
        id::CUSTOM_FRAME => {
            // No XNCP extensions: the stock firmware answer.
            let _ = r.lv()?;
            w.u32(sl::NOT_SUPPORTED).lv(&[]);
        }
        id::GET_CHILD_DATA => {
            let index = r.u8()? as usize;
            let child = nv.joined.iter().filter(|d| d.kind.is_child()).nth(index);
            match child {
                Some(d) => {
                    w.u32(sl::OK)
                        .eui64(d.ieee)
                        .u8(d.kind.ember_node_type())
                        .u16(d.nwk)
                        .u8(0)
                        .u8(0)
                        .u8(8)
                        .u32(0);
                }
                None => {
                    w.u32(sl::NOT_JOINED)
                        .eui64(0)
                        .u8(0)
                        .u16(0xFFFF)
                        .u8(0)
                        .u8(0)
                        .u8(0)
                        .u32(0);
                }
            }
        }
        id::GET_CONFIGURATION_VALUE => {
            let config_id = r.u8()?;
            match ram.config.get(&config_id) {
                Some(v) => w.u32(sl::OK).u16(*v),
                None => w.u32(sl::INVALID_PARAMETER).u16(0),
            };
        }
        id::SET_CONFIGURATION_VALUE => {
            let config_id = r.u8()?;
            let value = r.u16()?;
            let st = if ram.up {
                sl::INVALID_STATE
            } else if let Some(v) = ram.config.get_mut(&config_id) {
                *v = value;
                sl::OK
            } else {
                sl::INVALID_PARAMETER
            };
            w.u32(st);
        }
        id::SET_POLICY => {
            let policy_id = r.u8()?;
            let decision = r.u8()?;
            ram.policies.insert(policy_id, decision);
            w.u32(sl::OK);
        }
        id::GET_POLICY => {
            let policy_id = r.u8()?;
            w.u32(sl::OK)
                .u8(ram.policies.get(&policy_id).copied().unwrap_or(0));
        }
        id::SET_SOURCE_ROUTE_DISCOVERY_MODE => {
            let _mode = r.u8()?;
            w.u32(0);
        }
        id::GET_ADDRESS_TABLE_INFO => {
            let index = r.u8()? as usize;
            let entry = nv.joined.iter().filter(|d| !d.kind.is_child()).nth(index);
            match entry {
                Some(d) => w.u32(sl::OK).u16(d.nwk).eui64(d.ieee),
                None => w.u32(sl::NOT_FOUND).u16(0xFFFF).eui64(0),
            };
        }
        id::LOOKUP_NODE_ID_BY_EUI64 => {
            let eui = r.eui64()?;
            let nwk = if eui == nv.eui64 && ram.up {
                COORDINATOR_NWK
            } else {
                nv.joined_by_ieee(eui)
                    .map(|i| nv.joined[i].nwk)
                    .unwrap_or(0xFFFF)
            };
            w.u16(nwk);
        }
        id::LOOKUP_EUI64_BY_NODE_ID => {
            let nwk = r.u16()?;
            if nwk == COORDINATOR_NWK && ram.up {
                w.u32(sl::OK).eui64(nv.eui64);
            } else if let Some(i) = nv.joined_by_nwk(nwk) {
                w.u32(sl::OK).eui64(nv.joined[i].ieee);
            } else {
                w.u32(sl::NOT_FOUND).eui64(0);
            }
        }
        id::GET_MULTICAST_TABLE_ENTRY => {
            let index = r.u8()?;
            let size = ram
                .config
                .get(&CONFIG_MULTICAST_TABLE_SIZE)
                .copied()
                .unwrap_or(8);
            if (index as u16) < size.min(MAX_MULTICAST as u16) {
                let (group, ep) = ram.multicast.get(&index).copied().unwrap_or((0, 0));
                w.u32(sl::OK).u16(group).u8(ep).u8(0);
            } else {
                w.u32(sl::INVALID_INDEX).u16(0).u8(0).u8(0);
            }
        }
        id::SET_MULTICAST_TABLE_ENTRY => {
            let index = r.u8()?;
            let group = r.u16()?;
            let ep = r.u8()?;
            // The network index byte is optional in older hosts' encodings.
            if r.remaining() > 0 {
                r.u8()?;
            }
            let size = ram
                .config
                .get(&CONFIG_MULTICAST_TABLE_SIZE)
                .copied()
                .unwrap_or(8);
            let st = if index as usize >= MAX_MULTICAST || index as u16 >= size {
                sl::INVALID_INDEX
            } else {
                ram.multicast.insert(index, (group, ep));
                sl::OK
            };
            w.u32(st);
        }
        id::READ_COUNTERS | id::READ_AND_CLEAR_COUNTERS => {
            for _ in 0..ezsp::COUNTER_TYPE_COUNT {
                w.u16(0);
            }
        }
        id::SET_INITIAL_SECURITY_STATE => {
            let bitmask = r.u16()?;
            let preconfigured_key = r.key()?;
            let network_key = r.key()?;
            let key_sequence = r.u8()?;
            let _tc_eui = r.eui64()?;
            let st = if ram.up {
                sl::INVALID_STATE
            } else {
                ram.security = Some(InitialSecurity {
                    bitmask,
                    preconfigured_key,
                    network_key,
                    key_sequence,
                });
                sl::OK
            };
            w.u32(st);
        }
        id::GET_CURRENT_SECURITY_STATE => match (&nv.network, ram.up) {
            (Some(n), true) => {
                let mut bits = 0x0004 | 0x0010; // GLOBAL_LINK_KEY, HAVE_TRUST_CENTER_LINK_KEY
                if n.hashed_tclk {
                    bits |= 0x0084;
                }
                w.u32(sl::OK).u16(bits).eui64(nv.eui64);
            }
            _ => {
                w.u32(sl::NOT_JOINED).u16(0).eui64(0);
            }
        },
        id::CLEAR_TRANSIENT_LINK_KEYS => {}
        id::FIND_KEY_TABLE_ENTRY => {
            let eui = r.eui64()?;
            let _link = r.u8()?;
            let index = nv
                .link_keys
                .iter()
                .position(|(e, _)| *e == eui)
                .map(|i| i as u8)
                .unwrap_or(0xFF);
            w.u8(index);
        }
        id::ERASE_KEY_TABLE_ENTRY => {
            let index = r.u8()? as usize;
            let st = if index < nv.link_keys.len() {
                nv.link_keys.remove(index);
                sl::OK
            } else {
                sl::INVALID_INDEX
            };
            w.u32(st);
        }
        id::TOKEN_FACTORY_RESET => {
            let _exclude_fc = r.u8()?;
            let _exclude_boot = r.u8()?;
            nv.erase_network();
            nv.nwk_frame_counter = 0;
            nv.aps_frame_counter = 0;
            h.effects.push(Effect::Left);
        }
        id::SET_EXTENDED_TIMEOUT => {
            let eui = r.eui64()?;
            if r.u8()? != 0 {
                ram.extended_timeouts.insert(eui);
            } else {
                ram.extended_timeouts.remove(&eui);
            }
            w.u32(sl::OK);
        }
        id::GET_EXTENDED_TIMEOUT => {
            let eui = r.eui64()?;
            w.u8(ram.extended_timeouts.contains(&eui) as u8);
        }
        id::REPLACE_ADDRESS_TABLE_ENTRY => {
            let _index = r.u8()?;
            let eui = r.eui64()?;
            let _nwk = r.u16()?;
            if r.u8()? != 0 {
                ram.extended_timeouts.insert(eui);
            }
            // The entry it replaced was free.
            w.u32(sl::OK).eui64(0).u16(0xFFFF).u8(0);
        }
        id::SET_RADIO_IEEE802154_CCA_MODE => {
            let _mode = r.u8()?;
            w.u32(sl::OK);
        }
        id::SET_RADIO_POWER => {
            let power = r.u8()? as i8;
            if let Some(n) = nv.network.as_mut() {
                n.params.radio_tx_power = power as u8;
            }
            w.u32(sl::OK);
        }
        id::REMOVE_DEVICE => {
            let _short = r.u16()?;
            let _long = r.eui64()?;
            let target = r.eui64()?;
            if ram.up && nv.joined_by_ieee(target).is_some() {
                h.effects.push(Effect::Remove(target));
                w.u32(sl::OK);
            } else {
                w.u32(sl::NOT_FOUND);
            }
        }
        id::GET_VALUE => {
            let value_id = r.u8()?;
            match get_value(version, ram, nv, value_id) {
                Some(v) => w.u32(sl::OK).lv(&v),
                None => w.u32(sl::INVALID_PARAMETER).lv(&[]),
            };
        }
        id::SET_VALUE => {
            let value_id = r.u8()?;
            let data = r.lv()?.to_vec();
            let st = match value_id {
                value::NWK_FRAME_COUNTER | value::APS_FRAME_COUNTER => {
                    if data.len() != 4 {
                        sl::INVALID_PARAMETER
                    } else if ram.up {
                        sl::INVALID_STATE
                    } else {
                        let n = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                        if value_id == value::NWK_FRAME_COUNTER {
                            nv.nwk_frame_counter = n;
                        } else {
                            nv.aps_frame_counter = n;
                        }
                        sl::OK
                    }
                }
                value::VERSION_INFO | value::FREE_BUFFERS => sl::INVALID_PARAMETER,
                _ if data.len() <= 32 => {
                    ram.values.insert(value_id, data);
                    sl::OK
                }
                _ => sl::INVALID_PARAMETER,
            };
            w.u32(st);
        }
        id::SET_CHILD_DATA => {
            let _index = r.u8()?;
            r.bytes(18)?;
            w.u32(sl::OK);
        }
        id::SET_SOURCE_ROUTE => {
            let _dest = r.u16()?;
            let n = r.u8()? as usize;
            for _ in 0..n {
                r.u16()?;
            }
            w.u32(sl::OK);
        }
        id::CLEAR_KEY_TABLE => {
            nv.link_keys.clear();
            w.u32(sl::OK);
        }
        id::SET_LOGICAL_AND_RADIO_CHANNEL => {
            let _channel = r.u8()?;
            w.u32(sl::OK);
        }
        id::GET_TOKEN_DATA => {
            let _token = r.u32()?;
            let _index = r.u32()?;
            // No NVM3 tokens are exposed: the answer firmware gives a key it does not hold.
            w.u32(sl::NOT_FOUND);
        }
        id::SET_TOKEN_DATA => {
            let _token = r.u32()?;
            let _index = r.u32()?;
            let n = r.u8()? as usize;
            r.bytes(n)?;
            w.u32(sl::NOT_FOUND);
        }
        id::IMPORT_LINK_KEY => {
            let index = r.u8()? as usize;
            let eui = r.eui64()?;
            let key = r.key()?;
            let size = ram.config.get(&CONFIG_KEY_TABLE_SIZE).copied().unwrap_or(4) as usize;
            let st = if index >= size.min(MAX_LINK_KEYS) {
                sl::INVALID_INDEX
            } else {
                if let Some(slot) = nv.link_keys.iter_mut().find(|(e, _)| *e == eui) {
                    slot.1 = key;
                } else {
                    nv.link_keys.push((eui, key));
                }
                sl::OK
            };
            w.u32(st);
        }
        id::EXPORT_LINK_KEY_BY_INDEX => {
            let index = r.u8()? as usize;
            match nv.link_keys.get(index) {
                Some((eui, key)) => {
                    w.u32(sl::OK);
                    let mut ctx = [0u8; 18];
                    ctx[0] = 0x04; // APP_LINK
                    ctx[1] = index as u8;
                    ctx[4..12].copy_from_slice(&eui.to_le_bytes());
                    w.raw(&ctx).raw(key);
                    // Metadata: bitmask (has key data), frame counters, no timeout.
                    w.u16(0x0001).u32(0).u32(0).u16(0);
                }
                None => {
                    w.u32(sl::NOT_FOUND).raw(&[0u8; 18]).raw(&[0u8; 16]);
                    w.u16(0).u32(0).u32(0).u16(0);
                }
            }
        }
        id::IMPORT_TRANSIENT_KEY => {
            let _eui = r.eui64()?;
            let _key = r.key()?;
            // Version 14 dropped the flags byte; bellows still appends it, herdsman does not,
            // and firmware reads what it needs.
            if r.remaining() > 0 {
                r.u8()?;
            }
            w.u32(sl::OK);
        }
        id::EXPORT_KEY => {
            let ctx = read_context(r)?;
            let key = match (ctx.core_key_type, &nv.network, ram.security.as_ref()) {
                (1, Some(n), _) if ctx.key_index == 0 => Some(n.network_key),
                (2, Some(n), _) => Some(n.tc_link_key),
                (1, None, Some(s)) if ctx.key_index == 0 => Some(s.network_key),
                (2, None, Some(s)) => Some(s.preconfigured_key),
                _ => None,
            };
            match key {
                Some(k) => w.u32(sl::OK).raw(&k).raw(&ctx.raw),
                None => w.u32(sl::NOT_FOUND).raw(&[0u8; 16]).raw(&ctx.raw),
            };
        }
        id::GET_NETWORK_KEY_INFO => {
            let (set, seq) = match &nv.network {
                Some(n) => (true, n.key_sequence),
                None => (false, 0),
            };
            w.u32(sl::OK)
                .u8(set as u8)
                .u8(0)
                .u8(seq)
                .u8(0)
                .u32(nv.nwk_frame_counter);
        }
        // `ezsp::name` also names the callbacks, which only an NCP sends. A host that sends
        // one gets what firmware answers an id it does not accept (found by `zigbee_ash_ezsp`).
        _ => return Err(NotACommand.into()),
    }
    Ok(w.done())
}

fn send_check(ram: &Ram, message: &[u8]) -> u32 {
    if !ram.up {
        sl::NETWORK_DOWN
    } else if message.len() > device::MAX_APS_PAYLOAD {
        sl::MESSAGE_TOO_LONG
    } else {
        sl::OK
    }
}

fn pad(s: &[u8], n: usize) -> Vec<u8> {
    let mut v = s.to_vec();
    v.resize(n, 0xFF);
    v
}

fn get_value(version: u8, ram: &Ram, nv: &Nvram, value_id: u8) -> Option<Vec<u8>> {
    if let Some(v) = ram.values.get(&value_id) {
        return Some(v.clone());
    }
    Some(match value_id {
        value::VERSION_INFO => {
            let (ma, mi, pa) = stack_release(version);
            // build, major, minor, patch, special, type (GA).
            vec![0x00, 0x00, ma, mi, pa, 0x00, 0xAA]
        }
        value::FREE_BUFFERS => vec![0xF0],
        value::MAXIMUM_INCOMING_TRANSFER_SIZE | value::MAXIMUM_OUTGOING_TRANSFER_SIZE => {
            0x0052u16.to_le_bytes().to_vec()
        }
        value::STACK_TOKEN_WRITING => vec![1],
        value::EXTENDED_SECURITY_BITMASK => vec![0, 0],
        value::CCA_THRESHOLD => vec![0xB5],
        value::NWK_FRAME_COUNTER => nv.nwk_frame_counter.to_le_bytes().to_vec(),
        value::APS_FRAME_COUNTER => nv.aps_frame_counter.to_le_bytes().to_vec(),
        value::FORCE_TX_AFTER_FAILED_CCA_ATTEMPTS => vec![0],
        value::TRANSIENT_DEVICE_TIMEOUT => 10_000u16.to_le_bytes().to_vec(),
        _ => return None,
    })
}

/// Children the host may look up: how many end devices joined us directly.
pub fn child_count(nv: &Nvram) -> usize {
    nv.joined.iter().filter(|d| d.kind.is_child()).count()
}

/// The configured child-table size, for a join that would exceed it.
pub fn max_children(ram: &Ram) -> usize {
    ram.config
        .get(&CONFIG_MAX_END_DEVICE_CHILDREN)
        .copied()
        .unwrap_or(6) as usize
}

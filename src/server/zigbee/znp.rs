//! TI Z-Stack 3.x.0 as a network co-processor (ZNP): the MT commands the open Z-Stack hosts
//! send — zigpy-znp and zigbee-herdsman's `zstack` adapter — what the firmware answers to each,
//! its NV memory, and the indications it raises.
//!
//! **Which Z-Stack.** NetGet emulates Z-Stack 3.x.0 as Koenkk's CC2652/CC1352 coordinator
//! firmware builds it (`SYS_VERSION` product 1, release 2.7.1, build 20240710): the firmware
//! the network-attached TI coordinators run (SLZB-06 in Z-Stack mode, TubesZB CC2652, the
//! ser2net-bridged Sonoff ZBDongle-P). zigpy-znp calls it "3.30+" (it has the extended NV
//! system and `APP_CNF`), herdsman `ZStack3x0`. Z-Stack 3.0.x and 1.2 are the CC2530/CC2531
//! firmwares, USB sticks that never sit on TCP.
//!
//! **NV memory is the source of truth**, as on the chip: both hosts read the network from it
//! (the NIB, the active key, the security material table), and both form one by writing
//! commissioning items and asking for BDB formation. NetGet keeps every item a host writes,
//! answers lengths, reads and deletes as Z-Stack does, and on a reset applies
//! `STARTUP_OPTION` and recreates the items Z-Stack recreates. The shared network
//! (`Nvram::network`) is derived from the NIB whenever the firmware would read it: at a reset,
//! at formation, at startup.
use super::device::{self, Endpoint};
use super::ezsp::{ApsFrame, NetworkParameters};
use super::mt::{self, kind, rpc_error, subsystem, Frame, Reader, Truncated};
use super::ncp::{self, Network, Nvram};
use super::network::Up;
use std::collections::{BTreeMap, BTreeSet};

/// TI's OUI with a fixed tail: the chip's EUI-64 when none is configured.
pub const DEFAULT_EUI64: u64 = 0x0012_4B00_2A1B_2C3D;
pub const FIRMWARE_NAME: &str = "3.x.0 (build 20240710, CC2652)";
/// `SYS_VERSION`: transport revision, product (1 = Z-Stack 3.x.0), release 2.7.1, build.
pub const TRANSPORT_REV: u8 = 2;
pub const PRODUCT_ID: u8 = 1;
pub const RELEASE: (u8, u8, u8) = (2, 7, 1);
pub const CODE_REVISION: u32 = 20240710;
/// `SYS_PING` capabilities: the subsystems NetGet implements — SYS, AF, ZDO, UTIL, APP_CNF.
pub const CAPABILITIES: u16 = 0x0001 | 0x0008 | 0x0010 | 0x0040 | 0x0400;
/// NV items (OSAL and extended together) the flash holds.
pub const MAX_NV_ITEMS: usize = 512;
/// The longest NV item.
pub const MAX_NV_ITEM_LEN: usize = 1024;
/// The highest OSAL NV id writable over MT in Z-Stack 3.
pub const MAX_OSAL_ID: u16 = 0x03FF;
/// Endpoints a host registers with `AF_REGISTER` (herdsman registers 15).
pub const MAX_HOST_ENDPOINTS: usize = 32;
/// Group memberships `ZDO_EXT_ADD_GROUP` keeps.
pub const MAX_GROUPS: usize = 16;
/// Entries the APS link-key table has room for (`ZDSECMGR_ENTRY_MAX`).
pub const APS_LINK_KEY_ENTRIES: usize = 16;
/// The most value bytes one NV read answer carries.
pub const MAX_READ_CHUNK: usize = 246;

/// OSAL NV item ids.
pub mod nv {
    pub const EXTADDR: u16 = 0x0001;
    pub const STARTUP_OPTION: u16 = 0x0003;
    pub const NIB: u16 = 0x0021;
    pub const EXTENDED_PAN_ID: u16 = 0x002D;
    pub const BCAST_DELIVERY_TIME: u16 = 0x0030;
    pub const CONCENTRATOR_ENABLE: u16 = 0x0032;
    pub const CONCENTRATOR_DISCOVERY: u16 = 0x0033;
    pub const CONCENTRATOR_RADIUS: u16 = 0x0034;
    pub const CONCENTRATOR_RC: u16 = 0x0036;
    pub const SRC_RTG_EXPIRY_TIME: u16 = 0x0038;
    pub const NWK_ACTIVE_KEY_INFO: u16 = 0x003A;
    pub const NWK_ALTERN_KEY_INFO: u16 = 0x003B;
    pub const NWK_CHILD_AGE_ENABLE: u16 = 0x003E;
    pub const APS_USE_EXT_PANID: u16 = 0x0047;
    pub const APS_LINK_KEY_TABLE: u16 = 0x004C;
    pub const BDBNODEISONANETWORK: u16 = 0x0055;
    pub const HAS_CONFIGURED_ZSTACK3: u16 = 0x0060;
    pub const PRECFGKEY: u16 = 0x0062;
    pub const PRECFGKEYS_ENABLE: u16 = 0x0063;
    pub const NWKKEY: u16 = 0x0082;
    pub const PANID: u16 = 0x0083;
    pub const CHANLIST: u16 = 0x0084;
    pub const LOGICAL_TYPE: u16 = 0x0087;
    pub const ZDO_DIRECT_CB: u16 = 0x008F;
    pub const TCLK_SEED: u16 = 0x0101;
}

/// Extended (NVOCMP) item ids, system `ZSTACK` (1).
pub mod ex {
    pub const SYS_ZSTACK: u8 = 1;
    pub const ADDRMGR: u16 = 0x0001;
    pub const TCLK_TABLE: u16 = 0x0004;
    pub const APS_KEY_DATA_TABLE: u16 = 0x0006;
    pub const NWK_SEC_MATERIAL_TABLE: u16 = 0x0007;
}

/// `ZStatus_t` values the firmware answers with.
pub mod status {
    pub const SUCCESS: u8 = 0x00;
    pub const FAILURE: u8 = 0x01;
    pub const INVALID_PARAMETER: u8 = 0x02;
    pub const NV_ITEM_UNINIT: u8 = 0x09;
    pub const NV_OPER_FAILED: u8 = 0x0A;
    pub const NV_BAD_ITEM_LEN: u8 = 0x0C;
    pub const MEM_ERROR: u8 = 0x10;
    pub const APS_DUPLICATE_ENTRY: u8 = 0xB8;
    pub const NWK_INVALID_REQUEST: u8 = 0xC2;
    pub const NWK_NO_ROUTE: u8 = 0xCD;
}

/// `devStates_t` as `ZDO_STATE_CHANGE_IND` and `UTIL_GET_DEVICE_INFO` report them.
pub mod state {
    pub const HOLD: u8 = 0x00;
    pub const STARTING_COORDINATOR: u8 = 0x08;
    pub const COORDINATOR: u8 = 0x09;
}

/// BDB commissioning statuses and modes (`APP_CNF_BDB_COMMISSIONING_NOTIFICATION`).
pub mod bdb {
    pub const SUCCESS: u8 = 0x00;
    pub const IN_PROGRESS: u8 = 0x01;
    pub const NO_NETWORK: u8 = 0x02;
    pub const FORMATION_FAILURE: u8 = 0x08;
    pub const MODE_INITIALIZATION: u8 = 0x00;
    pub const MODE_FORMATION: u8 = 0x04;
}

/// Command ids, by subsystem.
pub mod cmd {
    pub mod sys {
        pub const RESET_REQ: u8 = 0x00;
        pub const PING: u8 = 0x01;
        pub const VERSION: u8 = 0x02;
        pub const GET_EXT_ADDR: u8 = 0x04;
        pub const OSAL_NV_ITEM_INIT: u8 = 0x07;
        pub const OSAL_NV_READ: u8 = 0x08;
        pub const OSAL_NV_DELETE: u8 = 0x12;
        pub const OSAL_NV_LENGTH: u8 = 0x13;
        pub const SET_TX_POWER: u8 = 0x14;
        pub const OSAL_NV_READ_EXT: u8 = 0x1C;
        pub const OSAL_NV_WRITE_EXT: u8 = 0x1D;
        pub const NV_CREATE: u8 = 0x30;
        pub const NV_DELETE: u8 = 0x31;
        pub const NV_LENGTH: u8 = 0x32;
        pub const NV_READ: u8 = 0x33;
        pub const NV_WRITE: u8 = 0x34;
        pub const RESET_IND: u8 = 0x80;
    }
    pub mod af {
        pub const REGISTER: u8 = 0x00;
        pub const DATA_REQUEST: u8 = 0x01;
        pub const DATA_REQUEST_EXT: u8 = 0x02;
        pub const DATA_REQUEST_SRC_RTG: u8 = 0x03;
        pub const DATA_CONFIRM: u8 = 0x80;
        pub const INCOMING_MSG: u8 = 0x81;
    }
    pub mod zdo {
        pub const NWK_ADDR_REQ: u8 = 0x00;
        pub const IEEE_ADDR_REQ: u8 = 0x01;
        pub const NODE_DESC_REQ: u8 = 0x02;
        pub const POWER_DESC_REQ: u8 = 0x03;
        pub const SIMPLE_DESC_REQ: u8 = 0x04;
        pub const ACTIVE_EP_REQ: u8 = 0x05;
        pub const MATCH_DESC_REQ: u8 = 0x06;
        pub const BIND_REQ: u8 = 0x21;
        pub const UNBIND_REQ: u8 = 0x22;
        pub const MGMT_LQI_REQ: u8 = 0x31;
        pub const MGMT_RTG_REQ: u8 = 0x32;
        pub const MGMT_BIND_REQ: u8 = 0x33;
        pub const MGMT_LEAVE_REQ: u8 = 0x34;
        pub const MGMT_PERMIT_JOIN_REQ: u8 = 0x36;
        pub const MSG_CB_REGISTER: u8 = 0x3E;
        pub const STARTUP_FROM_APP: u8 = 0x40;
        pub const EXT_ROUTE_DISC: u8 = 0x45;
        pub const EXT_ROUTE_CHK: u8 = 0x46;
        pub const EXT_FIND_GROUP: u8 = 0x4A;
        pub const EXT_ADD_GROUP: u8 = 0x4B;
        pub const EXT_NWK_INFO: u8 = 0x50;
        pub const MGMT_PERMIT_JOIN_RSP: u8 = 0xB6;
        pub const STATE_CHANGE_IND: u8 = 0xC0;
        pub const END_DEVICE_ANNCE_IND: u8 = 0xC1;
        pub const LEAVE_IND: u8 = 0xC9;
        pub const TC_DEV_IND: u8 = 0xCA;
        pub const MSG_CB_INCOMING: u8 = 0xFF;
    }
    pub mod util {
        pub const GET_DEVICE_INFO: u8 = 0x00;
        pub const LED_CONTROL: u8 = 0x0A;
        pub const ASSOC_FIND_DEVICE: u8 = 0x49;
        pub const ASSOC_GET_WITH_ADDRESS: u8 = 0x4A;
    }
    pub mod app_cnf {
        pub const BDB_START_COMMISSIONING: u8 = 0x05;
        pub const BDB_SET_CHANNEL: u8 = 0x08;
        pub const BDB_COMMISSIONING_NOTIFICATION: u8 = 0x80;
    }
}

/// The name of a host-to-firmware command NetGet implements, for logs and the census.
pub fn name(sub: u8, id: u8) -> Option<&'static str> {
    use cmd::*;
    Some(match (sub, id) {
        (subsystem::SYS, sys::RESET_REQ) => "SYS_RESET_REQ",
        (subsystem::SYS, sys::PING) => "SYS_PING",
        (subsystem::SYS, sys::VERSION) => "SYS_VERSION",
        (subsystem::SYS, sys::GET_EXT_ADDR) => "SYS_GET_EXTADDR",
        (subsystem::SYS, sys::OSAL_NV_ITEM_INIT) => "SYS_OSAL_NV_ITEM_INIT",
        (subsystem::SYS, sys::OSAL_NV_READ) => "SYS_OSAL_NV_READ",
        (subsystem::SYS, sys::OSAL_NV_DELETE) => "SYS_OSAL_NV_DELETE",
        (subsystem::SYS, sys::OSAL_NV_LENGTH) => "SYS_OSAL_NV_LENGTH",
        (subsystem::SYS, sys::SET_TX_POWER) => "SYS_SET_TX_POWER",
        (subsystem::SYS, sys::OSAL_NV_READ_EXT) => "SYS_OSAL_NV_READ_EXT",
        (subsystem::SYS, sys::OSAL_NV_WRITE_EXT) => "SYS_OSAL_NV_WRITE_EXT",
        (subsystem::SYS, sys::NV_CREATE) => "SYS_NV_CREATE",
        (subsystem::SYS, sys::NV_DELETE) => "SYS_NV_DELETE",
        (subsystem::SYS, sys::NV_LENGTH) => "SYS_NV_LENGTH",
        (subsystem::SYS, sys::NV_READ) => "SYS_NV_READ",
        (subsystem::SYS, sys::NV_WRITE) => "SYS_NV_WRITE",
        (subsystem::AF, af::REGISTER) => "AF_REGISTER",
        (subsystem::AF, af::DATA_REQUEST) => "AF_DATA_REQUEST",
        (subsystem::AF, af::DATA_REQUEST_EXT) => "AF_DATA_REQUEST_EXT",
        (subsystem::AF, af::DATA_REQUEST_SRC_RTG) => "AF_DATA_REQUEST_SRC_RTG",
        (subsystem::ZDO, zdo::NWK_ADDR_REQ) => "ZDO_NWK_ADDR_REQ",
        (subsystem::ZDO, zdo::IEEE_ADDR_REQ) => "ZDO_IEEE_ADDR_REQ",
        (subsystem::ZDO, zdo::NODE_DESC_REQ) => "ZDO_NODE_DESC_REQ",
        (subsystem::ZDO, zdo::POWER_DESC_REQ) => "ZDO_POWER_DESC_REQ",
        (subsystem::ZDO, zdo::SIMPLE_DESC_REQ) => "ZDO_SIMPLE_DESC_REQ",
        (subsystem::ZDO, zdo::ACTIVE_EP_REQ) => "ZDO_ACTIVE_EP_REQ",
        (subsystem::ZDO, zdo::MATCH_DESC_REQ) => "ZDO_MATCH_DESC_REQ",
        (subsystem::ZDO, zdo::BIND_REQ) => "ZDO_BIND_REQ",
        (subsystem::ZDO, zdo::UNBIND_REQ) => "ZDO_UNBIND_REQ",
        (subsystem::ZDO, zdo::MGMT_LQI_REQ) => "ZDO_MGMT_LQI_REQ",
        (subsystem::ZDO, zdo::MGMT_RTG_REQ) => "ZDO_MGMT_RTG_REQ",
        (subsystem::ZDO, zdo::MGMT_BIND_REQ) => "ZDO_MGMT_BIND_REQ",
        (subsystem::ZDO, zdo::MGMT_LEAVE_REQ) => "ZDO_MGMT_LEAVE_REQ",
        (subsystem::ZDO, zdo::MGMT_PERMIT_JOIN_REQ) => "ZDO_MGMT_PERMIT_JOIN_REQ",
        (subsystem::ZDO, zdo::MSG_CB_REGISTER) => "ZDO_MSG_CB_REGISTER",
        (subsystem::ZDO, zdo::STARTUP_FROM_APP) => "ZDO_STARTUP_FROM_APP",
        (subsystem::ZDO, zdo::EXT_ROUTE_DISC) => "ZDO_EXT_ROUTE_DISC",
        (subsystem::ZDO, zdo::EXT_ROUTE_CHK) => "ZDO_EXT_ROUTE_CHK",
        (subsystem::ZDO, zdo::EXT_FIND_GROUP) => "ZDO_EXT_FIND_GROUP",
        (subsystem::ZDO, zdo::EXT_ADD_GROUP) => "ZDO_EXT_ADD_GROUP",
        (subsystem::ZDO, zdo::EXT_NWK_INFO) => "ZDO_EXT_NWK_INFO",
        (subsystem::UTIL, util::GET_DEVICE_INFO) => "UTIL_GET_DEVICE_INFO",
        (subsystem::UTIL, util::LED_CONTROL) => "UTIL_LED_CONTROL",
        (subsystem::UTIL, util::ASSOC_FIND_DEVICE) => "UTIL_ASSOC_FIND_DEVICE",
        (subsystem::UTIL, util::ASSOC_GET_WITH_ADDRESS) => "UTIL_ASSOC_GET_WITH_ADDRESS",
        (subsystem::APP_CNF, app_cnf::BDB_START_COMMISSIONING) => "APP_CNF_BDB_START_COMMISSIONING",
        (subsystem::APP_CNF, app_cnf::BDB_SET_CHANNEL) => "APP_CNF_BDB_SET_CHANNEL",
        _ => return None,
    })
}

/// The subsystems the firmware has; an SREQ to any other is `MT_RPC_ERR_SUBSYSTEM`.
fn subsystem_present(sub: u8) -> bool {
    matches!(
        sub,
        subsystem::SYS | subsystem::AF | subsystem::ZDO | subsystem::UTIL | subsystem::APP_CNF
    )
}

/// The NV memory: OSAL items by id and extended items by (system, item, sub-item).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flash {
    pub osal: BTreeMap<u16, Vec<u8>>,
    pub ex: BTreeMap<(u8, u16, u16), Vec<u8>>,
}

/// The NIB as an aligned (CC26xx) `nwkIB_t`, 116 bytes.
pub mod nib {
    pub const LEN: usize = 116;
    pub const SECURITY_LEVEL: usize = 12;
    pub const DEV_ADDRESS: usize = 22;
    pub const LOGICAL_CHANNEL: usize = 24;
    pub const COORD_EXT_ADDRESS: usize = 28;
    pub const PAN_ID: usize = 36;
    pub const STATE: usize = 38;
    pub const CHANNEL_LIST: usize = 40;
    pub const EXTENDED_PAN_ID: usize = 57;
    pub const KEY_LOADED: usize = 65;
    pub const MANAGER_ADDR: usize = 110;
    pub const UPDATE_ID: usize = 114;
}

/// A formed network's NIB.
pub fn build_nib(
    channel: u8,
    pan_id: u16,
    epid_wire: [u8; 8],
    channels: u32,
    eui64: u64,
    update_id: u8,
) -> Vec<u8> {
    let mut n = vec![0u8; nib::LEN];
    // SequenceNum, PassiveAckTimeout, MaxBroadcastRetries, MaxChildren, MaxDepth,
    // MaxRouters, dummyNeighborTable, BroadcastDeliveryTime, ReportConstantCost,
    // RouteDiscRetries, dummyRoutingTable, SecureAllFrames, SecurityLevel, SymLink,
    // CapabilityFlags.
    n[..15].copy_from_slice(&[0, 5, 2, 51, 15, 51, 0, 30, 0, 0, 0, 1, 5, 1, 0x8F]);
    n[16..18].copy_from_slice(&7u16.to_le_bytes()); // TransactionPersistenceTime
    n[18] = 2; // nwkProtocolVersion
    n[19] = 13; // RouteDiscoveryTime
    n[20] = 30; // RouteExpiryTime
    n[nib::DEV_ADDRESS..nib::DEV_ADDRESS + 2].copy_from_slice(&0u16.to_le_bytes());
    n[nib::LOGICAL_CHANNEL] = channel;
    n[26..28].copy_from_slice(&0u16.to_le_bytes()); // nwkCoordAddress
    n[nib::COORD_EXT_ADDRESS..nib::COORD_EXT_ADDRESS + 8].copy_from_slice(&eui64.to_le_bytes());
    n[nib::PAN_ID..nib::PAN_ID + 2].copy_from_slice(&pan_id.to_le_bytes());
    n[nib::STATE] = 8; // NWK_ROUTER
    n[nib::CHANNEL_LIST..nib::CHANNEL_LIST + 4].copy_from_slice(&channels.to_le_bytes());
    n[44] = 15; // beaconOrder
    n[45] = 15; // superFrameOrder
    n[48..52].copy_from_slice(&1u32.to_le_bytes()); // allocatedRouterAddresses
    n[52..56].copy_from_slice(&1u32.to_le_bytes()); // allocatedEndDeviceAddresses
    n[nib::EXTENDED_PAN_ID..nib::EXTENDED_PAN_ID + 8].copy_from_slice(&epid_wire);
    n[nib::KEY_LOADED] = 1;
    n[102] = 15; // nwkLinkStatusPeriod
    n[103] = 5; // nwkRouterAgeLimit
    n[105] = 1; // nwkIsConcentrator
    n[106] = 120; // nwkConcentratorDiscoveryTime
    n[107] = 10; // nwkConcentratorRadius
    n[108] = 1; // nwkAllFresh
    n[nib::UPDATE_ID] = update_id;
    n
}

/// What a NIB says about the network it describes, if it describes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NibView {
    pub channel: u8,
    pub pan_id: u16,
    pub epid_wire: [u8; 8],
    pub channels: u32,
    pub update_id: u8,
    pub manager: u16,
    pub key_loaded: bool,
}

pub fn read_nib(n: &[u8]) -> Option<NibView> {
    if n.len() < nib::LEN {
        return None;
    }
    let mut epid_wire = [0u8; 8];
    epid_wire.copy_from_slice(&n[nib::EXTENDED_PAN_ID..nib::EXTENDED_PAN_ID + 8]);
    Some(NibView {
        channel: n[nib::LOGICAL_CHANNEL],
        pan_id: u16::from_le_bytes([n[nib::PAN_ID], n[nib::PAN_ID + 1]]),
        epid_wire,
        channels: u32::from_le_bytes([
            n[nib::CHANNEL_LIST],
            n[nib::CHANNEL_LIST + 1],
            n[nib::CHANNEL_LIST + 2],
            n[nib::CHANNEL_LIST + 3],
        ]),
        update_id: n[nib::UPDATE_ID],
        manager: u16::from_le_bytes([n[nib::MANAGER_ADDR], n[nib::MANAGER_ADDR + 1]]),
        key_loaded: n[nib::KEY_LOADED] != 0,
    })
}

/// Z-Stack's compiled-in default network key.
pub const DEFAULT_KEY: [u8; 16] = [
    0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0D,
];

/// An `nwkActiveKeyItems` (aligned): sequence, key, padding, frame counter.
fn nwk_key_item(seq: u8, key: &[u8; 16], counter: u32) -> Vec<u8> {
    let mut v = vec![seq];
    v.extend_from_slice(key);
    v.extend_from_slice(&[0, 0, 0]);
    v.extend_from_slice(&counter.to_le_bytes());
    v
}

fn key_desc(seq: u8, key: &[u8; 16]) -> Vec<u8> {
    let mut v = vec![seq];
    v.extend_from_slice(key);
    v
}

impl Flash {
    /// The flash a co-processor starts with: Z-Stack's defaults, and the network the
    /// operator described already formed in it — as it is after a host commissioned it,
    /// zigpy-znp and herdsman both leaving `HAS_CONFIGURED_ZSTACK3` set.
    pub fn initial(nv: &Nvram) -> Flash {
        let mut f = Flash::default();
        f.recreate_defaults(nv.eui64);
        if let Some(n) = &nv.network {
            f.write_formed(n, nv.eui64, nv.nwk_frame_counter);
            f.osal.insert(nv::HAS_CONFIGURED_ZSTACK3, vec![0x55]);
        }
        f
    }

    fn items(&self) -> usize {
        self.osal.len() + self.ex.len()
    }

    /// Recreate every item Z-Stack initialises at boot that is missing, with its default.
    pub fn recreate_defaults(&mut self, hardware_eui: u64) {
        let defaults: [(u16, Vec<u8>); 19] = [
            (nv::EXTADDR, hardware_eui.to_le_bytes().to_vec()),
            (nv::STARTUP_OPTION, vec![0]),
            (nv::EXTENDED_PAN_ID, vec![0; 8]),
            (nv::BCAST_DELIVERY_TIME, vec![30]),
            (nv::CONCENTRATOR_ENABLE, vec![1]),
            (nv::CONCENTRATOR_DISCOVERY, vec![120]),
            (nv::CONCENTRATOR_RADIUS, vec![10]),
            (nv::CONCENTRATOR_RC, vec![1]),
            (nv::SRC_RTG_EXPIRY_TIME, vec![255]),
            (nv::NWK_CHILD_AGE_ENABLE, vec![0]),
            (nv::APS_USE_EXT_PANID, vec![0; 8]),
            (nv::PRECFGKEY, DEFAULT_KEY.to_vec()),
            (nv::PRECFGKEYS_ENABLE, vec![0]),
            (nv::NWKKEY, nwk_key_item(0, &[0; 16], 0)),
            (nv::PANID, 0xFFFFu16.to_le_bytes().to_vec()),
            (nv::CHANLIST, 0x0000_0800u32.to_le_bytes().to_vec()),
            (nv::LOGICAL_TYPE, vec![0]),
            (nv::ZDO_DIRECT_CB, vec![0]),
            (nv::BDBNODEISONANETWORK, vec![0]),
        ];
        for (id, v) in defaults {
            self.osal.entry(id).or_insert(v);
        }
        // `APSLinkKeyTable`: an entry count and room for `ZDSECMGR_ENTRY_MAX` aligned
        // entries (address-manager index, key NV id, authentication state).
        self.osal
            .entry(nv::APS_LINK_KEY_TABLE)
            .or_insert_with(|| vec![0u8; 2 + 6 * APS_LINK_KEY_ENTRIES]);
        self.osal
            .entry(nv::NWK_ACTIVE_KEY_INFO)
            .or_insert_with(|| key_desc(0, &[0; 16]));
        self.osal
            .entry(nv::NWK_ALTERN_KEY_INFO)
            .or_insert_with(|| key_desc(0, &[0; 16]));
    }

    /// Write a formed network: the NIB, its keys, the security material entry, the BDB
    /// "on a network" attribute and a trust-center link-key seed.
    pub fn write_formed(&mut self, n: &Network, eui64: u64, frame_counter: u32) {
        let p = &n.params;
        let channels = if p.channels == 0 {
            1u32 << p.radio_channel
        } else {
            p.channels
        };
        self.osal.insert(
            nv::NIB,
            build_nib(
                p.radio_channel,
                p.pan_id,
                p.extended_pan_id,
                channels,
                eui64,
                p.nwk_update_id,
            ),
        );
        self.osal.insert(
            nv::NWK_ACTIVE_KEY_INFO,
            key_desc(n.key_sequence, &n.network_key),
        );
        self.osal.insert(
            nv::NWK_ALTERN_KEY_INFO,
            key_desc(n.key_sequence, &n.network_key),
        );
        self.osal.insert(
            nv::NWKKEY,
            nwk_key_item(n.key_sequence, &n.network_key, frame_counter),
        );
        self.osal.insert(nv::PRECFGKEY, n.network_key.to_vec());
        self.osal.insert(nv::PANID, p.pan_id.to_le_bytes().to_vec());
        self.osal
            .insert(nv::EXTENDED_PAN_ID, p.extended_pan_id.to_vec());
        self.osal
            .insert(nv::APS_USE_EXT_PANID, p.extended_pan_id.to_vec());
        self.osal
            .insert(nv::CHANLIST, channels.to_le_bytes().to_vec());
        self.osal.insert(nv::BDBNODEISONANETWORK, vec![1]);
        self.osal
            .entry(nv::TCLK_SEED)
            .or_insert_with(|| rand::random::<[u8; 16]>().to_vec());
        let mut material = frame_counter.to_le_bytes().to_vec();
        material.extend_from_slice(&p.extended_pan_id);
        self.ex
            .insert((ex::SYS_ZSTACK, ex::NWK_SEC_MATERIAL_TABLE, 0), material);
    }

    /// The network the NV memory describes, when the NIB says one is formed and BDB says the
    /// node is on it.
    pub fn network(&self) -> Option<Network> {
        let v = read_nib(self.osal.get(&nv::NIB)?)?;
        if v.channel == 0 || !v.key_loaded || !(11..=26).contains(&v.channel) {
            return None;
        }
        if self
            .osal
            .get(&nv::BDBNODEISONANETWORK)
            .map(|b| b.first() == Some(&1))
            == Some(false)
        {
            return None;
        }
        let active = self.osal.get(&nv::NWK_ACTIVE_KEY_INFO)?;
        if active.len() < 17 {
            return None;
        }
        let mut key = [0u8; 16];
        key.copy_from_slice(&active[1..17]);
        Some(Network {
            params: NetworkParameters {
                extended_pan_id: v.epid_wire,
                pan_id: v.pan_id,
                radio_tx_power: 8,
                radio_channel: v.channel,
                join_method: 0,
                nwk_manager_id: v.manager,
                nwk_update_id: v.update_id,
                channels: v.channels,
            },
            network_key: key,
            key_sequence: active[0],
            tc_link_key: ncp::WELL_KNOWN_LINK_KEY,
            hashed_tclk: false,
        })
    }

    /// The chip's IEEE address: `EXTADDR`, or the hardware address when it was deleted.
    pub fn eui64(&self, hardware: u64) -> u64 {
        self.osal
            .get(&nv::EXTADDR)
            .filter(|b| b.len() == 8)
            .map(|b| {
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                u64::from_le_bytes(a)
            })
            .unwrap_or(hardware)
    }

    /// A reset: apply `STARTUP_OPTION` (clear the network state, restore the default
    /// configuration), clear it, and recreate missing items.
    pub fn boot(&mut self, hardware_eui: u64) {
        let opt = self
            .osal
            .get(&nv::STARTUP_OPTION)
            .and_then(|b| b.first().copied())
            .unwrap_or(0);
        if opt & 0x02 != 0 {
            for id in [
                nv::NIB,
                nv::NWK_ACTIVE_KEY_INFO,
                nv::NWK_ALTERN_KEY_INFO,
                nv::NWKKEY,
                nv::BDBNODEISONANETWORK,
                nv::APS_LINK_KEY_TABLE,
            ] {
                self.osal.remove(&id);
            }
            self.ex.retain(|(_, item, _), _| {
                !matches!(
                    *item,
                    ex::ADDRMGR
                        | ex::TCLK_TABLE
                        | ex::APS_KEY_DATA_TABLE
                        | ex::NWK_SEC_MATERIAL_TABLE
                )
            });
        }
        if opt & 0x01 != 0 {
            for id in [
                nv::EXTENDED_PAN_ID,
                nv::APS_USE_EXT_PANID,
                nv::PRECFGKEY,
                nv::PRECFGKEYS_ENABLE,
                nv::PANID,
                nv::CHANLIST,
                nv::LOGICAL_TYPE,
                nv::ZDO_DIRECT_CB,
                nv::BCAST_DELIVERY_TIME,
                nv::CONCENTRATOR_ENABLE,
                nv::CONCENTRATOR_DISCOVERY,
                nv::CONCENTRATOR_RADIUS,
                nv::CONCENTRATOR_RC,
                nv::SRC_RTG_EXPIRY_TIME,
                nv::NWK_CHILD_AGE_ENABLE,
            ] {
                self.osal.remove(&id);
            }
        }
        if opt & 0x03 != 0 {
            self.osal.insert(nv::STARTUP_OPTION, vec![0]);
        }
        self.recreate_defaults(hardware_eui);
    }

    /// BDB network formation from the commissioning items: the PAN (random when 0xFFFF),
    /// the extended PAN (APS_USE_EXT_PANID, else EXTENDED_PAN_ID, else the chip's address),
    /// the lowest channel of the primary mask, and PRECFGKEY as the network key.
    pub fn form(&mut self, primary_channels: u32, hardware_eui: u64) -> Option<Network> {
        let channels = if primary_channels != 0 {
            primary_channels
        } else {
            self.osal
                .get(&nv::CHANLIST)
                .filter(|b| b.len() == 4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .unwrap_or(0)
        };
        let channel = (11u8..=26).find(|c| channels & (1 << c) != 0)?;
        let pan = self
            .osal
            .get(&nv::PANID)
            .filter(|b| b.len() == 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .unwrap_or(0xFFFF);
        let pan = if pan >= 0xFFF8 {
            rand::random::<u16>() % 0xFFF0 + 1
        } else {
            pan
        };
        let eight = |id| {
            self.osal
                .get(&id)
                .filter(|b: &&Vec<u8>| b.len() == 8 && b.iter().any(|x| *x != 0))
                .map(|b| {
                    let mut a = [0u8; 8];
                    a.copy_from_slice(b);
                    a
                })
        };
        let eui = self.eui64(hardware_eui);
        let epid = eight(nv::APS_USE_EXT_PANID)
            .or_else(|| eight(nv::EXTENDED_PAN_ID))
            .unwrap_or(eui.to_le_bytes());
        let key = self
            .osal
            .get(&nv::PRECFGKEY)
            .filter(|b| b.len() == 16)
            .map(|b| {
                let mut k = [0u8; 16];
                k.copy_from_slice(b);
                k
            })
            .unwrap_or_else(rand::random);
        let network = Network {
            params: NetworkParameters {
                extended_pan_id: epid,
                pan_id: pan,
                radio_tx_power: 8,
                radio_channel: channel,
                join_method: 0,
                nwk_manager_id: 0,
                nwk_update_id: 0,
                channels: 1 << channel,
            },
            network_key: key,
            key_sequence: 0,
            tc_link_key: ncp::WELL_KNOWN_LINK_KEY,
            hashed_tclk: false,
        };
        // Formation keeps the commissioning items as the host wrote them.
        let keep: Vec<(u16, Vec<u8>)> = [nv::PANID, nv::EXTENDED_PAN_ID, nv::APS_USE_EXT_PANID]
            .into_iter()
            .filter_map(|id| self.osal.get(&id).map(|v| (id, v.clone())))
            .collect();
        self.write_formed(&network, eui, 0);
        for (id, v) in keep {
            self.osal.insert(id, v);
        }
        Some(network)
    }

    fn osal_status_for_new(&self, len: usize) -> Option<u8> {
        if len > MAX_NV_ITEM_LEN || self.items() >= MAX_NV_ITEMS {
            Some(status::NV_OPER_FAILED)
        } else {
            None
        }
    }
}

/// An endpoint the host registered with `AF_REGISTER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEndpoint {
    pub id: u8,
    pub profile: u16,
    pub device_id: u16,
    pub version: u8,
    pub in_clusters: Vec<u16>,
    pub out_clusters: Vec<u16>,
}

/// What a reset clears.
#[derive(Debug, Clone, Default)]
pub struct Ram {
    /// `devStates_t`.
    pub state: u8,
    pub endpoints: Vec<HostEndpoint>,
    /// ZDO clusters the host asked `ZDO_MSG_CB_INCOMING` for (0xFFFF: all).
    pub zdo_callbacks: BTreeSet<u16>,
    pub bdb_primary: u32,
    pub bdb_secondary: u32,
    /// Joining open (0 = closed); the session times it.
    pub permit_secs: u8,
    pub groups: BTreeSet<(u8, u16)>,
    /// The ZDO sequence number of requests the firmware builds itself.
    pub zdo_tsn: u8,
    /// `AF_INCOMING_MSG` time stamps.
    pub timestamp: u32,
}

impl Ram {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn up(&self) -> bool {
        self.state == state::COORDINATOR
    }

    pub fn coordinator_endpoints(&self) -> Vec<Endpoint> {
        self.endpoints
            .iter()
            .map(|e| Endpoint {
                id: e.id,
                profile: e.profile,
                device_type: e.device_id,
                version: e.version,
                in_clusters: e.in_clusters.clone(),
                out_clusters: e.out_clusters.clone(),
                attributes: BTreeMap::new(),
            })
            .collect()
    }

    fn profile_of(&self, endpoint: u8) -> u16 {
        self.endpoints
            .iter()
            .find(|e| e.id == endpoint)
            .map(|e| e.profile)
            .unwrap_or(device::PROFILE_HA)
    }

    fn next_zdo_tsn(&mut self) -> u8 {
        self.zdo_tsn = self.zdo_tsn.wrapping_add(1);
        self.zdo_tsn
    }
}

/// Where a request goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dst {
    Nwk(u16),
    Broadcast(u16),
    Group(u16),
}

/// Something a command asks of the network beyond the firmware itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// The firmware rebooted: joining closes.
    Reset,
    /// The network came up; `formed` when this formation created it.
    Started { formed: bool },
    /// The host opened (non-zero) or closed joining at the coordinator.
    Permit(u8),
    /// An APS frame to deliver. `confirm` is the (source endpoint, transaction id) an
    /// `AF_DATA_CONFIRM` reports.
    Data {
        dst: Dst,
        aps: ApsFrame,
        message: Vec<u8>,
        confirm: Option<(u8, u8)>,
    },
}

/// What the firmware answers one frame with.
#[derive(Debug, Default)]
pub struct Handled {
    /// The SRSP (an SREQ always gets one; an AREQ never does).
    pub response: Option<Frame>,
    /// Indications raised at once, after the SRSP.
    pub areqs: Vec<Frame>,
    pub effects: Vec<Effect>,
    pub name: Option<&'static str>,
}

/// Answer one frame from the host.
pub fn handle(ram: &mut Ram, flash: &mut Flash, nv: &mut Nvram, frame: &Frame) -> Handled {
    let mut h = Handled {
        name: name(frame.subsystem, frame.id),
        ..Default::default()
    };
    match frame.kind {
        kind::SREQ => {}
        kind::AREQ => {
            if frame.subsystem == subsystem::SYS && frame.id == cmd::sys::RESET_REQ {
                reset(ram, flash, nv, &mut h);
            }
            // Any other AREQ from a host has no answer, in NetGet as on the chip.
            return h;
        }
        _ => return h,
    }
    if !subsystem_present(frame.subsystem) {
        h.response = Some(Frame::rpc_error(rpc_error::INVALID_SUBSYSTEM, frame));
        return h;
    }
    // SYS_RESET_REQ is an AREQ; as an SREQ it is a command the firmware does not have.
    let areq_only = frame.subsystem == subsystem::SYS && frame.id == cmd::sys::RESET_REQ;
    if h.name.is_none() || areq_only {
        h.name = None;
        h.response = Some(Frame::rpc_error(rpc_error::INVALID_COMMAND_ID, frame));
        return h;
    }
    let mut r = Reader::new(&frame.data);
    match answer(ram, flash, nv, frame, &mut r, &mut h) {
        Ok(data) => h.response = Some(Frame::srsp(frame.subsystem, frame.id, data)),
        Err(refused) => {
            h.areqs.clear();
            h.effects.clear();
            let code = match refused {
                Refused::Truncated => rpc_error::INVALID_LENGTH,
                Refused::NotAnSreq => rpc_error::INVALID_COMMAND_ID,
            };
            h.response = Some(Frame::rpc_error(code, frame));
        }
    }
    h
}

/// Why an SREQ was not executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    /// Its data ended before its fields did.
    Truncated,
    /// A name NetGet knows that is not a request a host sends.
    NotAnSreq,
}

impl From<Truncated> for Refused {
    fn from(_: Truncated) -> Self {
        Refused::Truncated
    }
}

fn reset(ram: &mut Ram, flash: &mut Flash, nv: &mut Nvram, h: &mut Handled) {
    *ram = Ram::new();
    flash.boot(nv.eui64);
    sync_network(flash, nv);
    h.effects.push(Effect::Reset);
    let (ma, mi, pa) = RELEASE;
    h.areqs.push(Frame::areq(
        subsystem::SYS,
        cmd::sys::RESET_IND,
        vec![0x00, TRANSPORT_REV, PRODUCT_ID, ma, mi, pa],
    ));
}

/// Make the shared network what the NV memory describes. A different network (or none)
/// erases the joined devices: they belonged to the old one.
pub fn sync_network(flash: &Flash, nv: &mut Nvram) {
    let now = flash.network();
    let same = match (&now, &nv.network) {
        (Some(a), Some(b)) => {
            a.params.extended_pan_id == b.params.extended_pan_id
                && a.params.pan_id == b.params.pan_id
                && a.params.radio_channel == b.params.radio_channel
                && a.network_key == b.network_key
        }
        (None, None) => true,
        _ => false,
    };
    if !same {
        nv.erase_network();
    }
    nv.network = now;
}

fn start(ram: &mut Ram, h: &mut Handled, formed: bool) {
    if ram.state != state::COORDINATOR {
        h.areqs.push(Frame::areq(
            subsystem::ZDO,
            cmd::zdo::STATE_CHANGE_IND,
            vec![state::STARTING_COORDINATOR],
        ));
        h.areqs.push(Frame::areq(
            subsystem::ZDO,
            cmd::zdo::STATE_CHANGE_IND,
            vec![state::COORDINATOR],
        ));
        ram.state = state::COORDINATOR;
        h.effects.push(Effect::Started { formed });
    }
}

fn bdb_notification(st: u8, mode: u8, remaining: u8) -> Frame {
    Frame::areq(
        subsystem::APP_CNF,
        cmd::app_cnf::BDB_COMMISSIONING_NOTIFICATION,
        vec![st, mode, remaining],
    )
}

fn answer(
    ram: &mut Ram,
    flash: &mut Flash,
    nv: &mut Nvram,
    frame: &Frame,
    r: &mut Reader,
    h: &mut Handled,
) -> Result<Vec<u8>, Refused> {
    use cmd::*;
    let mut w: Vec<u8> = Vec::new();
    match (frame.subsystem, frame.id) {
        (subsystem::SYS, sys::PING) => w.extend_from_slice(&CAPABILITIES.to_le_bytes()),
        (subsystem::SYS, sys::VERSION) => {
            let (ma, mi, pa) = RELEASE;
            w.extend_from_slice(&[TRANSPORT_REV, PRODUCT_ID, ma, mi, pa]);
            w.extend_from_slice(&CODE_REVISION.to_le_bytes());
        }
        (subsystem::SYS, sys::GET_EXT_ADDR) => {
            w.extend_from_slice(&flash.eui64(nv.eui64).to_le_bytes())
        }
        (subsystem::SYS, sys::SET_TX_POWER) => {
            let _dbm = r.u8()?;
            w.push(status::SUCCESS);
        }
        (subsystem::SYS, sys::OSAL_NV_LENGTH) => {
            let id = r.u16()?;
            let len = flash.osal.get(&id).map(|v| v.len()).unwrap_or(0) as u16;
            w.extend_from_slice(&len.to_le_bytes());
        }
        (subsystem::SYS, sys::OSAL_NV_ITEM_INIT) => {
            let id = r.u16()?;
            let len = r.u16()? as usize;
            let init = r.lv()?;
            w.push(if flash.osal.contains_key(&id) {
                status::SUCCESS
            } else if id > MAX_OSAL_ID || init.len() > len {
                status::NV_OPER_FAILED
            } else if let Some(st) = flash.osal_status_for_new(len) {
                st
            } else {
                let mut v = vec![0u8; len];
                v[..init.len()].copy_from_slice(init);
                flash.osal.insert(id, v);
                status::NV_ITEM_UNINIT
            });
        }
        (subsystem::SYS, sys::OSAL_NV_READ) | (subsystem::SYS, sys::OSAL_NV_READ_EXT) => {
            let id = r.u16()?;
            let offset = if frame.id == sys::OSAL_NV_READ {
                r.u8()? as usize
            } else {
                r.u16()? as usize
            };
            match flash.osal.get(&id) {
                Some(v) if offset <= v.len() => {
                    let chunk = &v[offset..v.len().min(offset + MAX_READ_CHUNK)];
                    w.push(status::SUCCESS);
                    w.push(chunk.len() as u8);
                    w.extend_from_slice(chunk);
                }
                Some(_) => w.extend_from_slice(&[status::INVALID_PARAMETER, 0]),
                None => w.extend_from_slice(&[status::NV_OPER_FAILED, 0]),
            }
        }
        (subsystem::SYS, sys::OSAL_NV_WRITE_EXT) => {
            let id = r.u16()?;
            let offset = r.u16()? as usize;
            let n = r.u16()? as usize;
            let value = r.bytes(n)?;
            w.push(match flash.osal.get_mut(&id) {
                None => status::NV_ITEM_UNINIT,
                Some(v) if offset + value.len() > v.len() => status::NV_OPER_FAILED,
                Some(v) => {
                    v[offset..offset + value.len()].copy_from_slice(value);
                    status::SUCCESS
                }
            });
        }
        (subsystem::SYS, sys::OSAL_NV_DELETE) => {
            let id = r.u16()?;
            let len = r.u16()? as usize;
            w.push(match flash.osal.get(&id) {
                None => status::NV_ITEM_UNINIT,
                Some(v) if v.len() != len => status::NV_BAD_ITEM_LEN,
                Some(_) => {
                    flash.osal.remove(&id);
                    status::SUCCESS
                }
            });
        }
        (subsystem::SYS, sys::NV_LENGTH) => {
            let key = (r.u8()?, r.u16()?, r.u16()?);
            let len = flash.ex.get(&key).map(|v| v.len()).unwrap_or(0) as u32;
            w.extend_from_slice(&len.to_le_bytes());
        }
        (subsystem::SYS, sys::NV_CREATE) => {
            let key = (r.u8()?, r.u16()?, r.u16()?);
            let len = r.u32()? as usize;
            w.push(if flash.ex.contains_key(&key) {
                status::SUCCESS
            } else if let Some(st) = flash.osal_status_for_new(len) {
                st
            } else {
                flash.ex.insert(key, vec![0u8; len]);
                status::SUCCESS
            });
        }
        (subsystem::SYS, sys::NV_DELETE) => {
            let key = (r.u8()?, r.u16()?, r.u16()?);
            w.push(if flash.ex.remove(&key).is_some() {
                status::SUCCESS
            } else {
                status::NV_ITEM_UNINIT
            });
        }
        (subsystem::SYS, sys::NV_READ) => {
            let key = (r.u8()?, r.u16()?, r.u16()?);
            let offset = r.u16()? as usize;
            let len = r.u8()? as usize;
            match flash.ex.get(&key) {
                Some(v) if offset <= v.len() => {
                    let end = v.len().min(offset + len.min(MAX_READ_CHUNK));
                    let chunk = &v[offset..end];
                    w.push(status::SUCCESS);
                    w.push(chunk.len() as u8);
                    w.extend_from_slice(chunk);
                }
                Some(_) => w.extend_from_slice(&[status::INVALID_PARAMETER, 0]),
                None => w.extend_from_slice(&[status::NV_ITEM_UNINIT, 0]),
            }
        }
        (subsystem::SYS, sys::NV_WRITE) => {
            let key = (r.u8()?, r.u16()?, r.u16()?);
            let offset = r.u16()? as usize;
            let value = r.lv()?;
            let exists = flash.ex.contains_key(&key);
            w.push(if !exists {
                // NVOCMP writes create the item.
                match flash.osal_status_for_new(offset + value.len()) {
                    Some(st) => st,
                    None => {
                        let mut v = vec![0u8; offset + value.len()];
                        v[offset..].copy_from_slice(value);
                        flash.ex.insert(key, v);
                        status::SUCCESS
                    }
                }
            } else {
                let v = flash.ex.get_mut(&key).expect("checked");
                if offset + value.len() > v.len() {
                    status::NV_OPER_FAILED
                } else {
                    v[offset..offset + value.len()].copy_from_slice(value);
                    status::SUCCESS
                }
            });
        }
        (subsystem::UTIL, util::GET_DEVICE_INFO) => {
            w.push(status::SUCCESS);
            w.extend_from_slice(&flash.eui64(nv.eui64).to_le_bytes());
            let nwk: u16 = if ram.up() { 0x0000 } else { 0xFFFE };
            w.extend_from_slice(&nwk.to_le_bytes());
            // Device types it can be: coordinator, router, end device.
            w.push(0x07);
            w.push(ram.state);
            let children: Vec<u16> = nv
                .joined
                .iter()
                .filter(|d| d.kind.is_child())
                .map(|d| d.nwk)
                .take(32)
                .collect();
            w.push(children.len() as u8);
            for c in children {
                w.extend_from_slice(&c.to_le_bytes());
            }
        }
        (subsystem::UTIL, util::LED_CONTROL) => {
            let _led = r.u8()?;
            let _mode = r.u8()?;
            w.push(status::SUCCESS);
        }
        (subsystem::UTIL, util::ASSOC_FIND_DEVICE) => {
            let index = r.u8()? as usize;
            let child = nv.joined.iter().filter(|d| d.kind.is_child()).nth(index);
            w.extend(associated_device(child.map(|d| d.nwk)));
        }
        (subsystem::UTIL, util::ASSOC_GET_WITH_ADDRESS) => {
            let ieee = r.eui64()?;
            let nwk = r.u16()?;
            let child = nv
                .joined
                .iter()
                .filter(|d| d.kind.is_child())
                .find(|d| d.ieee == ieee || (ieee == 0 && d.nwk == nwk));
            w.extend(associated_device(child.map(|d| d.nwk)));
        }
        (subsystem::AF, af::REGISTER) => {
            let id = r.u8()?;
            let profile = r.u16()?;
            let device_id = r.u16()?;
            let version = r.u8()?;
            let _latency = r.u8()?;
            let ins = r.u16_list()?;
            let outs = r.u16_list()?;
            w.push(if ram.endpoints.iter().any(|e| e.id == id) {
                status::APS_DUPLICATE_ENTRY
            } else if id == 0 || id > 240 && id != 242 {
                status::INVALID_PARAMETER
            } else if ram.endpoints.len() >= MAX_HOST_ENDPOINTS
                || ins.len() > device::MAX_CLUSTERS
                || outs.len() > device::MAX_CLUSTERS
            {
                status::MEM_ERROR
            } else {
                ram.endpoints.push(HostEndpoint {
                    id,
                    profile,
                    device_id,
                    version,
                    in_clusters: ins,
                    out_clusters: outs,
                });
                status::SUCCESS
            });
        }
        (subsystem::AF, af::DATA_REQUEST)
        | (subsystem::AF, af::DATA_REQUEST_EXT)
        | (subsystem::AF, af::DATA_REQUEST_SRC_RTG) => {
            let (dst, dst_ep, src_ep, cluster, tsn, data) = match frame.id {
                af::DATA_REQUEST => {
                    let nwk = r.u16()?;
                    let dst_ep = r.u8()?;
                    let src_ep = r.u8()?;
                    let cluster = r.u16()?;
                    let tsn = r.u8()?;
                    let _options = r.u8()?;
                    let _radius = r.u8()?;
                    let data = r.lv()?;
                    (Some(Dst::Nwk(nwk)), dst_ep, src_ep, cluster, tsn, data)
                }
                af::DATA_REQUEST_SRC_RTG => {
                    let nwk = r.u16()?;
                    let dst_ep = r.u8()?;
                    let src_ep = r.u8()?;
                    let cluster = r.u16()?;
                    let tsn = r.u8()?;
                    let _options = r.u8()?;
                    let _radius = r.u8()?;
                    let relays = r.u8()? as usize;
                    r.bytes(relays * 2)?;
                    let data = r.lv()?;
                    (Some(Dst::Nwk(nwk)), dst_ep, src_ep, cluster, tsn, data)
                }
                _ => {
                    let mode = r.u8()?;
                    let addr = r.eui64()?;
                    let dst_ep = r.u8()?;
                    let _pan = r.u16()?;
                    let src_ep = r.u8()?;
                    let cluster = r.u16()?;
                    let tsn = r.u8()?;
                    let _options = r.u8()?;
                    let _radius = r.u8()?;
                    let n = r.u16()? as usize;
                    let data = r.bytes(n)?;
                    let short = addr as u16;
                    let dst = match mode {
                        0x01 => Some(Dst::Group(short)),
                        0x02 if short >= 0xFFF8 => Some(Dst::Broadcast(short)),
                        0x02 => Some(Dst::Nwk(short)),
                        0x03 => {
                            if addr == flash.eui64(nv.eui64) {
                                Some(Dst::Nwk(ncp::COORDINATOR_NWK))
                            } else {
                                nv.joined_by_ieee(addr).map(|i| Dst::Nwk(nv.joined[i].nwk))
                            }
                        }
                        0x0F => Some(Dst::Broadcast(short)),
                        _ => None,
                    };
                    (dst, dst_ep, src_ep, cluster, tsn, data)
                }
            };
            let st = if !ram.up() {
                status::NWK_INVALID_REQUEST
            } else if data.len() > device::MAX_APS_PAYLOAD {
                status::INVALID_PARAMETER
            } else {
                status::SUCCESS
            };
            w.push(st);
            if st == status::SUCCESS {
                let zdo = dst_ep == 0;
                let aps = ApsFrame {
                    profile_id: if zdo {
                        device::PROFILE_ZDO
                    } else {
                        ram.profile_of(src_ep)
                    },
                    cluster_id: cluster,
                    source_endpoint: src_ep,
                    destination_endpoint: dst_ep,
                    options: 0,
                    group_id: match dst {
                        Some(Dst::Group(g)) => g,
                        _ => 0,
                    },
                    sequence: tsn,
                };
                match dst {
                    // ZDO through AF raises no data confirm; an unknown IEEE is a frame to
                    // nobody, confirmed as a route failure.
                    Some(dst) => h.effects.push(Effect::Data {
                        dst,
                        aps,
                        message: data.to_vec(),
                        confirm: (!zdo).then_some((src_ep, tsn)),
                    }),
                    None if !zdo => h
                        .areqs
                        .push(data_confirm(status::NWK_NO_ROUTE, src_ep, tsn)),
                    None => {}
                }
            }
        }
        (subsystem::ZDO, zdo::STARTUP_FROM_APP) => {
            let _delay = r.u16()?;
            if ram.up() {
                w.push(0x00);
            } else if flash.network().is_some() {
                sync_network(flash, nv);
                w.push(0x00); // restored
                start(ram, h, false);
            } else {
                match flash.form(ram.bdb_primary, nv.eui64) {
                    Some(_) => {
                        sync_network(flash, nv);
                        w.push(0x01); // new network
                        start(ram, h, true);
                    }
                    None => w.push(0x02), // not started
                }
            }
        }
        (subsystem::ZDO, zdo::MSG_CB_REGISTER) => {
            let cluster = r.u16()?;
            if ram.zdo_callbacks.len() < 64 {
                ram.zdo_callbacks.insert(cluster);
            }
            w.push(status::SUCCESS);
        }
        (subsystem::ZDO, zdo::EXT_ROUTE_DISC) => {
            let _dst = r.u16()?;
            let _options = r.u8()?;
            let _radius = r.u8()?;
            w.push(status::SUCCESS);
        }
        (subsystem::ZDO, zdo::EXT_ROUTE_CHK) => {
            let dst = r.u16()?;
            let _rt_status = r.u8()?;
            let _options = r.u8()?;
            let known = dst == ncp::COORDINATOR_NWK || nv.joined_by_nwk(dst).is_some();
            // RTG_SUCCESS: every device is one hop from the coordinator; RTG_NO_ENTRY else.
            w.push(if known { 0x00 } else { 0x04 });
        }
        (subsystem::ZDO, zdo::EXT_FIND_GROUP) => {
            let ep = r.u8()?;
            let group = r.u16()?;
            // Z-Stack answers the status and a whole `aps_Group_t` (id, then a 16-byte name
            // whose first byte is its length) whether it found the group or not.
            if ram.groups.contains(&(ep, group)) {
                w.push(status::SUCCESS);
                w.extend_from_slice(&group.to_le_bytes());
            } else {
                w.push(status::FAILURE);
                w.extend_from_slice(&[0, 0]);
            }
            w.extend_from_slice(&[0u8; 16]);
        }
        (subsystem::ZDO, zdo::EXT_ADD_GROUP) => {
            let ep = r.u8()?;
            let group = r.u16()?;
            let _name = r.lv()?;
            w.push(
                if ram.groups.contains(&(ep, group)) || ram.groups.len() < MAX_GROUPS {
                    ram.groups.insert((ep, group));
                    status::SUCCESS
                } else {
                    status::MEM_ERROR
                },
            );
        }
        (subsystem::ZDO, zdo::EXT_NWK_INFO) => {
            let net = nv.network.as_ref().filter(|_| ram.up());
            let nwk: u16 = if ram.up() { 0x0000 } else { 0xFFFE };
            w.extend_from_slice(&nwk.to_le_bytes());
            w.push(ram.state);
            w.extend_from_slice(&net.map(|n| n.params.pan_id).unwrap_or(0xFFFF).to_le_bytes());
            w.extend_from_slice(&0xFFFEu16.to_le_bytes()); // no parent
            w.extend_from_slice(&net.map(|n| n.params.extended_pan_id).unwrap_or([0; 8]));
            w.extend_from_slice(&[0xFF; 8]); // no parent
            w.push(net.map(|n| n.params.radio_channel).unwrap_or(0));
        }
        (subsystem::ZDO, id) if is_zdo_request(id) => {
            zdo_request(ram, id, r, h, &mut w)?;
        }
        (subsystem::APP_CNF, app_cnf::BDB_SET_CHANNEL) => {
            let primary = r.u8()? != 0;
            let mask = r.u32()?;
            if primary {
                ram.bdb_primary = mask;
            } else {
                ram.bdb_secondary = mask;
            }
            w.push(status::SUCCESS);
        }
        (subsystem::APP_CNF, app_cnf::BDB_START_COMMISSIONING) => {
            let mode = r.u8()?;
            w.push(status::SUCCESS);
            if mode & bdb::MODE_FORMATION == 0 {
                // Steering, finding & binding, touchlink: a coordinator has nothing to do.
                h.areqs.push(bdb_notification(bdb::NO_NETWORK, mode, 0));
            } else if ram.up() || flash.network().is_some() {
                // Already on a network: formation "fails", the node comes up on it.
                sync_network(flash, nv);
                start(ram, h, false);
                h.areqs.push(bdb_notification(
                    bdb::FORMATION_FAILURE,
                    bdb::MODE_FORMATION,
                    0,
                ));
            } else {
                h.areqs.push(bdb_notification(
                    bdb::IN_PROGRESS,
                    bdb::MODE_INITIALIZATION,
                    bdb::MODE_FORMATION,
                ));
                match flash.form(ram.bdb_primary, nv.eui64) {
                    Some(_) => {
                        sync_network(flash, nv);
                        start(ram, h, true);
                        h.areqs
                            .push(bdb_notification(bdb::SUCCESS, bdb::MODE_FORMATION, 0));
                    }
                    None => h.areqs.push(bdb_notification(
                        bdb::FORMATION_FAILURE,
                        bdb::MODE_FORMATION,
                        0,
                    )),
                }
            }
        }
        // Every named SREQ has an arm above; a name that reaches here is not one a host sends
        // (found by `zigbee_mt`: SYS_RESET_REQ's id sent as an SREQ).
        _ => return Err(Refused::NotAnSreq),
    }
    Ok(w)
}

/// An `associated_devices_t` (aligned, Z-Stack 3: 36 bytes) for a child of the coordinator,
/// or the empty slot Z-Stack returns when there is none.
fn associated_device(child: Option<u16>) -> Vec<u8> {
    let mut v = vec![0u8; 36];
    match child {
        Some(nwk) => {
            v[0..2].copy_from_slice(&nwk.to_le_bytes());
            v[2..4].copy_from_slice(&0u16.to_le_bytes()); // addrIdx
            v[4] = 1; // CHILD_RFD
            v[5] = 1; // devStatus
        }
        None => {
            v[0..2].copy_from_slice(&0xFFFEu16.to_le_bytes());
            v[2..4].copy_from_slice(&0xFFFFu16.to_le_bytes());
            v[4] = 0xFF; // NOTUSED
        }
    }
    v
}

fn data_confirm(st: u8, endpoint: u8, tsn: u8) -> Frame {
    Frame::areq(
        subsystem::AF,
        cmd::af::DATA_CONFIRM,
        vec![st, endpoint, tsn],
    )
}

/// `AF_DATA_CONFIRM` for a frame the network did or did not deliver.
pub fn confirm(delivered: bool, endpoint: u8, tsn: u8) -> Frame {
    data_confirm(
        if delivered {
            status::SUCCESS
        } else {
            status::NWK_NO_ROUTE
        },
        endpoint,
        tsn,
    )
}

fn is_zdo_request(id: u8) -> bool {
    use cmd::zdo::*;
    matches!(
        id,
        NWK_ADDR_REQ
            | IEEE_ADDR_REQ
            | NODE_DESC_REQ
            | POWER_DESC_REQ
            | SIMPLE_DESC_REQ
            | ACTIVE_EP_REQ
            | MATCH_DESC_REQ
            | BIND_REQ
            | UNBIND_REQ
            | MGMT_LQI_REQ
            | MGMT_RTG_REQ
            | MGMT_BIND_REQ
            | MGMT_LEAVE_REQ
            | MGMT_PERMIT_JOIN_REQ
    )
}

/// A ZDO request the host asks the firmware to send (`ZDO_*_REQ`): the firmware builds the
/// ZDO frame with its own sequence number and sends it; the answer comes back as the
/// `ZDO_*_RSP` indication.
fn zdo_request(
    ram: &mut Ram,
    id: u8,
    r: &mut Reader,
    h: &mut Handled,
    w: &mut Vec<u8>,
) -> Result<(), Truncated> {
    use cmd::zdo::*;
    let cluster = id as u16;
    let (dst, body): (Dst, Vec<u8>) = match id {
        NWK_ADDR_REQ => {
            let body = r.bytes(10)?.to_vec();
            (Dst::Broadcast(0xFFFD), body)
        }
        IEEE_ADDR_REQ => {
            let body = r.bytes(4)?.to_vec();
            (Dst::Nwk(u16::from_le_bytes([body[0], body[1]])), body)
        }
        MGMT_PERMIT_JOIN_REQ => {
            let mode = r.u8()?;
            let addr = r.u16()?;
            let duration = r.u8()?;
            let tc = r.u8()?;
            let dst = if mode == 0x0F || addr >= 0xFFF8 {
                Dst::Broadcast(addr)
            } else {
                Dst::Nwk(addr)
            };
            if !ram.up() {
                w.push(status::NWK_INVALID_REQUEST);
                return Ok(());
            }
            w.push(status::SUCCESS);
            let tsn = ram.next_zdo_tsn();
            if matches!(dst, Dst::Broadcast(_)) || dst == Dst::Nwk(ncp::COORDINATOR_NWK) {
                // The coordinator applies it and answers its own Mgmt_Permit_Joining_rsp.
                ram.permit_secs = duration;
                h.effects.push(Effect::Permit(duration));
                let mut p = ncp::COORDINATOR_NWK.to_le_bytes().to_vec();
                p.push(status::SUCCESS);
                h.areqs
                    .push(Frame::areq(subsystem::ZDO, MGMT_PERMIT_JOIN_RSP, p.clone()));
                if wants_callback(ram, 0x8036) {
                    h.areqs.push(msg_cb_incoming(
                        ncp::COORDINATOR_NWK,
                        false,
                        0x8036,
                        tsn,
                        &[status::SUCCESS],
                    ));
                }
            }
            if let Dst::Nwk(n) = dst {
                if n != ncp::COORDINATOR_NWK {
                    h.effects.push(Effect::Data {
                        dst,
                        aps: zdo_aps(cluster),
                        message: vec![tsn, duration, tc],
                        confirm: None,
                    });
                }
            }
            return Ok(());
        }
        _ => {
            let to = r.u16()?;
            let body = r.rest().to_vec();
            let dst = if to >= 0xFFF8 {
                Dst::Broadcast(to)
            } else {
                Dst::Nwk(to)
            };
            (dst, body)
        }
    };
    if !ram.up() {
        w.push(status::NWK_INVALID_REQUEST);
        return Ok(());
    }
    w.push(status::SUCCESS);
    let mut message = vec![ram.next_zdo_tsn()];
    message.extend_from_slice(&body);
    h.effects.push(Effect::Data {
        dst,
        aps: zdo_aps(cluster),
        message,
        confirm: None,
    });
    Ok(())
}

fn zdo_aps(cluster: u16) -> ApsFrame {
    ApsFrame {
        profile_id: device::PROFILE_ZDO,
        cluster_id: cluster,
        source_endpoint: 0,
        destination_endpoint: 0,
        options: 0,
        group_id: 0,
        sequence: 0,
    }
}

fn wants_callback(ram: &Ram, cluster: u16) -> bool {
    ram.zdo_callbacks.contains(&0xFFFF) || ram.zdo_callbacks.contains(&cluster)
}

fn msg_cb_incoming(src: u16, broadcast: bool, cluster: u16, tsn: u8, body: &[u8]) -> Frame {
    let mut p = src.to_le_bytes().to_vec();
    p.push(broadcast as u8);
    p.extend_from_slice(&cluster.to_le_bytes());
    p.push(0); // SecurityUse
    p.push(tsn);
    p.extend_from_slice(&(if broadcast { 0xFFFFu16 } else { 0x0000 }).to_le_bytes());
    p.extend_from_slice(body);
    Frame::areq(subsystem::ZDO, cmd::zdo::MSG_CB_INCOMING, p)
}

/// The `ZDO_*_RSP` indication id Z-Stack raises for a ZDO response cluster.
fn zdo_rsp_id(cluster: u16) -> Option<u8> {
    match cluster {
        0x8000..=0x8006 | 0x8021 | 0x8022 | 0x8031..=0x8034 | 0x8036 | 0x8038 => {
            Some(0x80 | (cluster & 0x7F) as u8)
        }
        _ => None,
    }
}

/// What the firmware raises for what the network tells the host.
pub fn up_frames(ram: &mut Ram, up: &Up) -> Vec<Frame> {
    use cmd::zdo::*;
    let mut out = Vec::new();
    match up {
        Up::Incoming {
            broadcast,
            aps,
            nwk,
            payload,
            ..
        } if aps.profile_id == device::PROFILE_ZDO => {
            let Some((&tsn, body)) = payload.split_first() else {
                return out;
            };
            let cluster = aps.cluster_id;
            if cluster == 0x0013 {
                let mut p = nwk.to_le_bytes().to_vec();
                p.extend_from_slice(body);
                out.push(Frame::areq(subsystem::ZDO, END_DEVICE_ANNCE_IND, p));
            } else if let Some(id) = zdo_rsp_id(cluster) {
                let p = if matches!(cluster, 0x8000 | 0x8001) {
                    body.to_vec()
                } else {
                    let mut p = nwk.to_le_bytes().to_vec();
                    p.extend_from_slice(body);
                    p
                };
                out.push(Frame::areq(subsystem::ZDO, id, p));
            }
            if wants_callback(ram, cluster) {
                out.push(msg_cb_incoming(*nwk, *broadcast, cluster, tsn, body));
            }
        }
        Up::Incoming {
            broadcast,
            aps,
            nwk,
            payload,
            ..
        } => {
            ram.timestamp = ram.timestamp.wrapping_add(1);
            let mut p = aps.group_id.to_le_bytes().to_vec();
            p.extend_from_slice(&aps.cluster_id.to_le_bytes());
            p.extend_from_slice(&nwk.to_le_bytes());
            p.push(aps.source_endpoint);
            p.push(aps.destination_endpoint);
            p.push(*broadcast as u8);
            p.push(0xFF); // link quality
            p.push(0); // security use
            p.extend_from_slice(&ram.timestamp.to_le_bytes());
            p.push(aps.sequence);
            p.push(payload.len().min(device::MAX_APS_PAYLOAD) as u8);
            p.extend_from_slice(&payload[..payload.len().min(device::MAX_APS_PAYLOAD)]);
            p.extend_from_slice(&nwk.to_le_bytes()); // MAC source: one hop
            p.push(0x1D); // radius left
            out.push(Frame::areq(subsystem::AF, cmd::af::INCOMING_MSG, p));
        }
        Up::Child { .. } => {}
        Up::TrustCenter {
            nwk,
            ieee,
            joined: true,
        } => {
            let mut p = nwk.to_le_bytes().to_vec();
            p.extend_from_slice(&ieee.to_le_bytes());
            p.extend_from_slice(&ncp::COORDINATOR_NWK.to_le_bytes());
            out.push(Frame::areq(subsystem::ZDO, TC_DEV_IND, p));
        }
        Up::TrustCenter {
            nwk,
            ieee,
            joined: false,
        } => {
            let mut p = nwk.to_le_bytes().to_vec();
            p.extend_from_slice(&ieee.to_le_bytes());
            p.extend_from_slice(&[0, 0, 0]); // request, remove children, rejoin
            out.push(Frame::areq(subsystem::ZDO, LEAVE_IND, p));
        }
    }
    out
}

/// Frames whose MT data a host is owed when the AREQ list is checked for bounds.
pub fn fits(frame: &Frame) -> bool {
    frame.data.len() <= mt::MAX_DATA
}

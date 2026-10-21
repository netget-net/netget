//! EZSP framing: the legacy header a host uses for its first `version` command and the
//! extended header (frame format version 1) of everything after it, the command and callback
//! identifiers and status codes NetGet speaks, and a bounded reader for command parameters.
//!
//! Versions 14 to 17 are implemented. They share every command NetGet implements: version 14
//! replaced the one-byte EmberStatus/EzspStatus of earlier versions with the four-byte
//! sl_status_t everywhere and moved incoming messages to the `sl_zigbee_rx_packet_info_t`
//! layout, and 16 and 17 changed nothing the open hosts send at startup or for messaging.
use anyhow::{bail, Result};

pub const MIN_VERSION: u8 = 14;
pub const MAX_VERSION: u8 = 17;
pub const DEFAULT_VERSION: u8 = 17;
/// `stackType` in the version response: a mesh stack (EmberZNet).
pub const STACK_TYPE_MESH: u8 = 0x02;

/// Frame identifiers.
pub mod id {
    pub const VERSION: u16 = 0x0000;
    pub const ADD_ENDPOINT: u16 = 0x0002;
    pub const GET_EXTENDED_VALUE: u16 = 0x0003;
    pub const NOP: u16 = 0x0005;
    pub const GET_MFG_TOKEN: u16 = 0x000B;
    pub const SET_CONCENTRATOR: u16 = 0x0010;
    pub const SET_MANUFACTURER_CODE: u16 = 0x0015;
    pub const NETWORK_INIT: u16 = 0x0017;
    pub const NETWORK_STATE: u16 = 0x0018;
    pub const STACK_STATUS_HANDLER: u16 = 0x0019;
    pub const FORM_NETWORK: u16 = 0x001E;
    pub const LEAVE_NETWORK: u16 = 0x0020;
    pub const PERMIT_JOINING: u16 = 0x0022;
    pub const CHILD_JOIN_HANDLER: u16 = 0x0023;
    pub const TRUST_CENTER_JOIN_HANDLER: u16 = 0x0024;
    pub const GET_EUI64: u16 = 0x0026;
    pub const GET_NODE_ID: u16 = 0x0027;
    pub const GET_NETWORK_PARAMETERS: u16 = 0x0028;
    pub const SEND_UNICAST: u16 = 0x0034;
    pub const SEND_BROADCAST: u16 = 0x0036;
    pub const SEND_MULTICAST: u16 = 0x0038;
    pub const MESSAGE_SENT_HANDLER: u16 = 0x003F;
    pub const INCOMING_MESSAGE_HANDLER: u16 = 0x0045;
    pub const CUSTOM_FRAME: u16 = 0x0047;
    pub const GET_CHILD_DATA: u16 = 0x004A;
    pub const GET_CONFIGURATION_VALUE: u16 = 0x0052;
    pub const SET_CONFIGURATION_VALUE: u16 = 0x0053;
    pub const SET_POLICY: u16 = 0x0055;
    pub const GET_POLICY: u16 = 0x0056;
    pub const INVALID_COMMAND: u16 = 0x0058;
    pub const SET_SOURCE_ROUTE_DISCOVERY_MODE: u16 = 0x005A;
    pub const GET_ADDRESS_TABLE_INFO: u16 = 0x005E;
    pub const LOOKUP_NODE_ID_BY_EUI64: u16 = 0x0060;
    pub const LOOKUP_EUI64_BY_NODE_ID: u16 = 0x0061;
    pub const GET_MULTICAST_TABLE_ENTRY: u16 = 0x0063;
    pub const SET_MULTICAST_TABLE_ENTRY: u16 = 0x0064;
    pub const READ_AND_CLEAR_COUNTERS: u16 = 0x0065;
    pub const SET_INITIAL_SECURITY_STATE: u16 = 0x0068;
    pub const GET_CURRENT_SECURITY_STATE: u16 = 0x0069;
    pub const CLEAR_TRANSIENT_LINK_KEYS: u16 = 0x006B;
    pub const FIND_KEY_TABLE_ENTRY: u16 = 0x0075;
    pub const ERASE_KEY_TABLE_ENTRY: u16 = 0x0076;
    pub const TOKEN_FACTORY_RESET: u16 = 0x0077;
    pub const SET_EXTENDED_TIMEOUT: u16 = 0x007E;
    pub const GET_EXTENDED_TIMEOUT: u16 = 0x007F;
    pub const REPLACE_ADDRESS_TABLE_ENTRY: u16 = 0x0082;
    pub const SET_RADIO_IEEE802154_CCA_MODE: u16 = 0x0095;
    pub const SET_RADIO_POWER: u16 = 0x0099;
    pub const REMOVE_DEVICE: u16 = 0x00A8;
    pub const GET_VALUE: u16 = 0x00AA;
    pub const SET_VALUE: u16 = 0x00AB;
    pub const SET_CHILD_DATA: u16 = 0x00AC;
    pub const SET_SOURCE_ROUTE: u16 = 0x00AE;
    pub const CLEAR_KEY_TABLE: u16 = 0x00B1;
    pub const SET_LOGICAL_AND_RADIO_CHANNEL: u16 = 0x00B9;
    pub const READ_COUNTERS: u16 = 0x00F1;
    pub const GET_TOKEN_DATA: u16 = 0x0102;
    pub const SET_TOKEN_DATA: u16 = 0x0103;
    pub const IMPORT_LINK_KEY: u16 = 0x010E;
    pub const EXPORT_LINK_KEY_BY_INDEX: u16 = 0x010F;
    pub const IMPORT_TRANSIENT_KEY: u16 = 0x0111;
    pub const EXPORT_KEY: u16 = 0x0114;
    pub const GET_NETWORK_KEY_INFO: u16 = 0x0116;
}

/// The name of a frame id NetGet implements, for logs and the command census.
pub fn name(frame_id: u16) -> Option<&'static str> {
    use id::*;
    Some(match frame_id {
        VERSION => "version",
        ADD_ENDPOINT => "addEndpoint",
        GET_EXTENDED_VALUE => "getExtendedValue",
        NOP => "nop",
        GET_MFG_TOKEN => "getMfgToken",
        SET_CONCENTRATOR => "setConcentrator",
        SET_MANUFACTURER_CODE => "setManufacturerCode",
        NETWORK_INIT => "networkInit",
        NETWORK_STATE => "networkState",
        STACK_STATUS_HANDLER => "stackStatusHandler",
        FORM_NETWORK => "formNetwork",
        LEAVE_NETWORK => "leaveNetwork",
        PERMIT_JOINING => "permitJoining",
        CHILD_JOIN_HANDLER => "childJoinHandler",
        TRUST_CENTER_JOIN_HANDLER => "trustCenterJoinHandler",
        GET_EUI64 => "getEui64",
        GET_NODE_ID => "getNodeId",
        GET_NETWORK_PARAMETERS => "getNetworkParameters",
        SEND_UNICAST => "sendUnicast",
        SEND_BROADCAST => "sendBroadcast",
        SEND_MULTICAST => "sendMulticast",
        MESSAGE_SENT_HANDLER => "messageSentHandler",
        INCOMING_MESSAGE_HANDLER => "incomingMessageHandler",
        CUSTOM_FRAME => "customFrame",
        GET_CHILD_DATA => "getChildData",
        GET_CONFIGURATION_VALUE => "getConfigurationValue",
        SET_CONFIGURATION_VALUE => "setConfigurationValue",
        SET_POLICY => "setPolicy",
        GET_POLICY => "getPolicy",
        INVALID_COMMAND => "invalidCommand",
        SET_SOURCE_ROUTE_DISCOVERY_MODE => "setSourceRouteDiscoveryMode",
        GET_ADDRESS_TABLE_INFO => "getAddressTableInfo",
        LOOKUP_NODE_ID_BY_EUI64 => "lookupNodeIdByEui64",
        LOOKUP_EUI64_BY_NODE_ID => "lookupEui64ByNodeId",
        GET_MULTICAST_TABLE_ENTRY => "getMulticastTableEntry",
        SET_MULTICAST_TABLE_ENTRY => "setMulticastTableEntry",
        READ_AND_CLEAR_COUNTERS => "readAndClearCounters",
        SET_INITIAL_SECURITY_STATE => "setInitialSecurityState",
        GET_CURRENT_SECURITY_STATE => "getCurrentSecurityState",
        CLEAR_TRANSIENT_LINK_KEYS => "clearTransientLinkKeys",
        FIND_KEY_TABLE_ENTRY => "findKeyTableEntry",
        ERASE_KEY_TABLE_ENTRY => "eraseKeyTableEntry",
        TOKEN_FACTORY_RESET => "tokenFactoryReset",
        SET_EXTENDED_TIMEOUT => "setExtendedTimeout",
        GET_EXTENDED_TIMEOUT => "getExtendedTimeout",
        REPLACE_ADDRESS_TABLE_ENTRY => "replaceAddressTableEntry",
        SET_RADIO_IEEE802154_CCA_MODE => "setRadioIeee802154CcaMode",
        SET_RADIO_POWER => "setRadioPower",
        REMOVE_DEVICE => "removeDevice",
        GET_VALUE => "getValue",
        SET_VALUE => "setValue",
        SET_CHILD_DATA => "setChildData",
        SET_SOURCE_ROUTE => "setSourceRoute",
        CLEAR_KEY_TABLE => "clearKeyTable",
        SET_LOGICAL_AND_RADIO_CHANNEL => "setLogicalAndRadioChannel",
        READ_COUNTERS => "readCounters",
        GET_TOKEN_DATA => "getTokenData",
        SET_TOKEN_DATA => "setTokenData",
        IMPORT_LINK_KEY => "importLinkKey",
        EXPORT_LINK_KEY_BY_INDEX => "exportLinkKeyByIndex",
        IMPORT_TRANSIENT_KEY => "importTransientKey",
        EXPORT_KEY => "exportKey",
        GET_NETWORK_KEY_INFO => "getNetworkKeyInfo",
        _ => return None,
    })
}

/// `sl_status_t` codes.
pub mod sl {
    pub const OK: u32 = 0x0000;
    pub const FAIL: u32 = 0x0001;
    pub const INVALID_STATE: u32 = 0x0002;
    pub const NOT_SUPPORTED: u32 = 0x000F;
    pub const NETWORK_UP: u32 = 0x0015;
    pub const NETWORK_DOWN: u32 = 0x0016;
    pub const NOT_JOINED: u32 = 0x0017;
    pub const FULL: u32 = 0x001C;
    pub const INVALID_PARAMETER: u32 = 0x0021;
    pub const INVALID_INDEX: u32 = 0x0027;
    pub const NOT_FOUND: u32 = 0x002D;
    pub const ALREADY_EXISTS: u32 = 0x002E;
    pub const MESSAGE_TOO_LONG: u32 = 0x0038;
    pub const ZIGBEE_DELIVERY_FAILED: u32 = 0x0C02;
    pub const ZIGBEE_SECURITY_STATE_NOT_SET: u32 = 0x0C0B;
    pub const ZIGBEE_NETWORK_OPENED: u32 = 0x0C18;
    pub const ZIGBEE_NETWORK_CLOSED: u32 = 0x0C19;
}

/// `EzspStatus` codes an `invalidCommand` response carries.
pub mod ezsp_status {
    pub const ERROR_VERSION_NOT_SET: u8 = 0x30;
    pub const ERROR_INVALID_FRAME_ID: u8 = 0x31;
    pub const ERROR_UNSUPPORTED_CONTROL: u8 = 0x49;
}

/// One command from the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub sequence: u8,
    pub frame_id: u16,
    /// Sent in the legacy (pre-v8) header, which only `version` may use.
    pub legacy: bool,
    pub params: Vec<u8>,
}

/// Why a frame could not be read as a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    TooShort,
    /// A response or callback travelling host-to-NCP.
    WrongDirection,
    /// Security, padding or reserved bits set in the extended frame control.
    UnsupportedControl,
}

/// Read the header of a frame from the host. The extended format is recognised by its frame
/// format version (1) in the low bits of the second frame-control byte; the legacy format has
/// the frame id there instead, and `version` (0x00) is the only legacy command there is.
pub fn parse_command(frame: &[u8]) -> Result<Command, (u8, HeaderError)> {
    let sequence = *frame.first().ok_or((0, HeaderError::TooShort))?;
    if frame.len() < 3 {
        return Err((sequence, HeaderError::TooShort));
    }
    if frame[1] & 0x80 != 0 {
        return Err((sequence, HeaderError::WrongDirection));
    }
    if frame[2] & 0x03 == 0x01 {
        if frame.len() < 5 {
            return Err((sequence, HeaderError::TooShort));
        }
        if frame[2] & 0xFC != 0 {
            return Err((sequence, HeaderError::UnsupportedControl));
        }
        return Ok(Command {
            sequence,
            frame_id: u16::from_le_bytes([frame[3], frame[4]]),
            legacy: false,
            params: frame[5..].to_vec(),
        });
    }
    Ok(Command {
        sequence,
        frame_id: frame[2] as u16,
        legacy: true,
        params: frame[3..].to_vec(),
    })
}

/// Frame control of a response: direction bit set.
pub const FC_RESPONSE: u8 = 0x80;
/// An asynchronous callback (UART only, with `VALUE_UART_SYNCH_CALLBACKS` 0).
pub const FC_ASYNC_CALLBACK: u8 = 0x10;

/// A response in the header of the command it answers.
pub fn response(cmd: &Command, params: &[u8]) -> Vec<u8> {
    if cmd.legacy {
        let mut f = vec![cmd.sequence, FC_RESPONSE, cmd.frame_id as u8];
        f.extend_from_slice(params);
        f
    } else {
        extended(cmd.sequence, FC_RESPONSE, cmd.frame_id, params)
    }
}

/// An asynchronous callback in the extended format.
pub fn callback(sequence: u8, frame_id: u16, params: &[u8]) -> Vec<u8> {
    extended(sequence, FC_RESPONSE | FC_ASYNC_CALLBACK, frame_id, params)
}

fn extended(sequence: u8, control: u8, frame_id: u16, params: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(5 + params.len());
    f.push(sequence);
    f.push(control);
    f.push(0x01);
    f.extend_from_slice(&frame_id.to_le_bytes());
    f.extend_from_slice(params);
    f
}

/// The `invalidCommand` response. From version 14 the status is a four-byte sl_status_t with
/// the EzspStatus in its low byte, which herdsman reads as one byte and bellows as four.
pub fn invalid_command(cmd: &Command, status: u8) -> Vec<u8> {
    let params = (status as u32).to_le_bytes();
    if cmd.legacy {
        let mut f = vec![cmd.sequence, FC_RESPONSE, id::INVALID_COMMAND as u8];
        f.extend_from_slice(&params);
        f
    } else {
        extended(cmd.sequence, FC_RESPONSE, id::INVALID_COMMAND, &params)
    }
}

/// A little-endian reader over command parameters that refuses to read past the end.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.data.len() - self.pos < n {
            bail!("parameters end after {} bytes, {} more needed", self.pos, n);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn eui64(&mut self) -> Result<u64> {
        let b = self.bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    pub fn key(&mut self) -> Result<[u8; 16]> {
        let mut k = [0u8; 16];
        k.copy_from_slice(self.bytes(16)?);
        Ok(k)
    }
    /// A one-byte length and that many bytes.
    pub fn lv(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.bytes(n)
    }
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
}

/// A little-endian writer.
#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn i8(&mut self, v: i8) -> &mut Self {
        self.0.push(v as u8);
        self
    }
    pub fn eui64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }
    /// A one-byte length and the bytes; callers bound the length first.
    pub fn lv(&mut self, v: &[u8]) -> &mut Self {
        self.0.push(v.len().min(255) as u8);
        self.0.extend_from_slice(&v[..v.len().min(255)]);
        self
    }
    pub fn done(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

/// An APS frame as EZSP carries it (`EmberApsFrame`, 11 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApsFrame {
    pub profile_id: u16,
    pub cluster_id: u16,
    pub source_endpoint: u8,
    pub destination_endpoint: u8,
    pub options: u16,
    pub group_id: u16,
    pub sequence: u8,
}

impl ApsFrame {
    pub fn read(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            profile_id: r.u16()?,
            cluster_id: r.u16()?,
            source_endpoint: r.u8()?,
            destination_endpoint: r.u8()?,
            options: r.u16()?,
            group_id: r.u16()?,
            sequence: r.u8()?,
        })
    }
    pub fn write(&self, w: &mut Writer) {
        w.u16(self.profile_id)
            .u16(self.cluster_id)
            .u8(self.source_endpoint)
            .u8(self.destination_endpoint)
            .u16(self.options)
            .u16(self.group_id)
            .u8(self.sequence);
    }
}

/// `EmberNetworkParameters` (20 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkParameters {
    /// Wire order.
    pub extended_pan_id: [u8; 8],
    pub pan_id: u16,
    pub radio_tx_power: u8,
    pub radio_channel: u8,
    pub join_method: u8,
    pub nwk_manager_id: u16,
    pub nwk_update_id: u8,
    pub channels: u32,
}

impl NetworkParameters {
    pub fn read(r: &mut Reader) -> Result<Self> {
        let mut extended_pan_id = [0u8; 8];
        extended_pan_id.copy_from_slice(r.bytes(8)?);
        Ok(Self {
            extended_pan_id,
            pan_id: r.u16()?,
            radio_tx_power: r.u8()?,
            radio_channel: r.u8()?,
            join_method: r.u8()?,
            nwk_manager_id: r.u16()?,
            nwk_update_id: r.u8()?,
            channels: r.u32()?,
        })
    }
    pub fn write(&self, w: &mut Writer) {
        w.raw(&self.extended_pan_id)
            .u16(self.pan_id)
            .u8(self.radio_tx_power)
            .u8(self.radio_channel)
            .u8(self.join_method)
            .u16(self.nwk_manager_id)
            .u8(self.nwk_update_id)
            .u32(self.channels);
    }
}

/// Number of counters `readCounters` returns (`EMBER_COUNTER_TYPE_COUNT`).
pub const COUNTER_TYPE_COUNT: usize = 42;

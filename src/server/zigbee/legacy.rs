//! EZSP versions 8 to 13: the same command set as 14+, carried in the older encodings.
//!
//! `ncp.rs` speaks version 14 and later. Version 14 replaced the one-byte `EmberStatus` and
//! `EzspStatus` of every earlier version with the four-byte `sl_status_t`, moved the status to
//! the front of the security-manager answers, widened message tags to 16 bits and gave
//! `incomingMessageHandler` the sender's EUI-64 and an `sl_zigbee_rx_packet_info_t`. This module
//! turns an older host's command into the v14 one, lets `ncp::handle` answer it, and turns the
//! answer and every callback back:
//!
//! - **statuses** are narrowed to one byte, `sl_status_t` mapped to the `EmberStatus` or
//!   `EzspStatus` code that command used (bellows' and herdsman's own tables, inverted);
//! - **layouts** that moved are rebuilt: `sendUnicast`/`sendBroadcast`/`sendMulticast`
//!   requests, `messageSentHandler`, `incomingMessageHandler`, `exportKey`,
//!   `exportLinkKeyByIndex`, `setExtendedTimeout` (no status before 14), `getChildData` and
//!   `setChildData` (the 14-byte `EmberChildData` of versions 8 and 9);
//! - **commands that only older versions have** are answered here: `getKey`,
//!   `getKeyTableEntry`, `addOrUpdateKeyTableEntry`, `addTransientLinkKey`,
//!   `becomeTrustCenter` (0x0077 before `tokenFactoryReset` took the id in 13),
//!   `getAddressTableRemoteEui64`/`NodeId` (0x005E before `getAddressTableInfo` took it in 14);
//! - **commands a version does not have yet** (`getNetworkKeyInfo` before 13, the security
//!   manager before 12, the token interface before 9) get `invalidCommand`, as that firmware
//!   answers them.
use super::ezsp::{self, id, sl, Command, Reader, Writer};
use super::ncp::{self, Callback, Handled, Nvram, Ram};

/// The oldest EZSP version NetGet speaks: the first in the extended frame format.
pub const OLDEST: u8 = 8;
/// The first version `ncp.rs` speaks natively.
pub const NATIVE: u8 = 14;

/// Frame ids whose meaning only older versions have.
pub mod old {
    pub const GET_ADDRESS_TABLE_REMOTE_EUI64: u16 = 0x005E;
    pub const GET_ADDRESS_TABLE_REMOTE_NODE_ID: u16 = 0x005F;
    pub const ADD_OR_UPDATE_KEY_TABLE_ENTRY: u16 = 0x0066;
    pub const GET_KEY: u16 = 0x006A;
    pub const GET_KEY_TABLE_ENTRY: u16 = 0x0071;
    pub const BECOME_TRUST_CENTER: u16 = 0x0077;
    pub const OVERRIDE_CURRENT_CHANNEL: u16 = 0x0095;
    pub const SET_GPIO_CURRENT_CONFIGURATION: u16 = 0x00AC;
    pub const ADD_TRANSIENT_LINK_KEY: u16 = 0x00AF;
}

/// `EmberStatus` codes.
pub mod ember {
    pub const SUCCESS: u8 = 0x00;
    pub const ERR_FATAL: u8 = 0x01;
    pub const BAD_ARGUMENT: u8 = 0x02;
    pub const NOT_FOUND: u8 = 0x03;
    pub const DELIVERY_FAILED: u8 = 0x66;
    pub const INVALID_CALL: u8 = 0x70;
    pub const MESSAGE_TOO_LONG: u8 = 0x74;
    pub const NETWORK_UP: u8 = 0x90;
    pub const NETWORK_DOWN: u8 = 0x91;
    pub const NOT_JOINED: u8 = 0x93;
    pub const NETWORK_OPENED: u8 = 0x9C;
    pub const NETWORK_CLOSED: u8 = 0x9D;
    pub const SECURITY_STATE_NOT_SET: u8 = 0xA8;
    pub const INDEX_OUT_OF_RANGE: u8 = 0xB1;
    pub const TABLE_FULL: u8 = 0xB4;
    pub const TABLE_ENTRY_ERASED: u8 = 0xB6;
}

/// `EzspStatus` codes a command answers with.
pub mod ezsp_code {
    pub const SUCCESS: u8 = 0x00;
    pub const ERROR_OUT_OF_MEMORY: u8 = 0x35;
    pub const ERROR_INVALID_VALUE: u8 = 0x36;
    pub const ERROR_INVALID_ID: u8 = 0x37;
    pub const ERROR_INVALID_CALL: u8 = 0x38;
}

/// The `EmberStatus` a pre-14 firmware gave for what 14+ reports as this `sl_status_t`.
pub fn ember_status(st: u32) -> u8 {
    match st {
        sl::OK => ember::SUCCESS,
        sl::INVALID_STATE => ember::INVALID_CALL,
        sl::NETWORK_UP => ember::NETWORK_UP,
        sl::NETWORK_DOWN => ember::NETWORK_DOWN,
        sl::NOT_JOINED => ember::NOT_JOINED,
        sl::FULL => ember::TABLE_FULL,
        sl::INVALID_PARAMETER => ember::BAD_ARGUMENT,
        sl::INVALID_INDEX => ember::INDEX_OUT_OF_RANGE,
        sl::NOT_FOUND => ember::NOT_FOUND,
        sl::ALREADY_EXISTS => ember::INVALID_CALL,
        sl::MESSAGE_TOO_LONG => ember::MESSAGE_TOO_LONG,
        sl::ZIGBEE_DELIVERY_FAILED => ember::DELIVERY_FAILED,
        sl::ZIGBEE_SECURITY_STATE_NOT_SET => ember::SECURITY_STATE_NOT_SET,
        sl::ZIGBEE_NETWORK_OPENED => ember::NETWORK_OPENED,
        sl::ZIGBEE_NETWORK_CLOSED => ember::NETWORK_CLOSED,
        sl::NOT_SUPPORTED => ember::INVALID_CALL,
        _ => ember::ERR_FATAL,
    }
}

/// The `EzspStatus` a pre-14 firmware gave for what 14+ reports as this `sl_status_t`.
pub fn ezsp_status(st: u32) -> u8 {
    match st {
        sl::OK => ezsp_code::SUCCESS,
        sl::INVALID_PARAMETER | sl::INVALID_INDEX | sl::NOT_FOUND => ezsp_code::ERROR_INVALID_ID,
        sl::FULL => ezsp_code::ERROR_OUT_OF_MEMORY,
        _ => ezsp_code::ERROR_INVALID_CALL,
    }
}

/// How a command's status travelled before version 14.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// One-byte `EmberStatus`, first.
    Ember,
    /// One-byte `EzspStatus`, first.
    Ezsp,
    /// Already `sl_status_t` (the security manager, from 12).
    Sl,
    /// No status field, or no change.
    Unchanged,
}

fn status_kind(frame_id: u16) -> Status {
    use id::*;
    match frame_id {
        SET_CONCENTRATOR
        | START_SCAN
        | NETWORK_INIT
        | FORM_NETWORK
        | LEAVE_NETWORK
        | PERMIT_JOINING
        | GET_NETWORK_PARAMETERS
        | SEND_UNICAST
        | SEND_BROADCAST
        | SEND_MULTICAST
        | CUSTOM_FRAME
        | GET_CHILD_DATA
        | LOOKUP_EUI64_BY_NODE_ID
        | GET_MULTICAST_TABLE_ENTRY
        | SET_MULTICAST_TABLE_ENTRY
        | SET_INITIAL_SECURITY_STATE
        | GET_CURRENT_SECURITY_STATE
        | ERASE_KEY_TABLE_ENTRY
        | REPLACE_ADDRESS_TABLE_ENTRY
        | SET_RADIO_IEEE802154_CCA_MODE
        | SET_RADIO_POWER
        | REMOVE_DEVICE
        | SET_CHILD_DATA
        | SET_SOURCE_ROUTE
        | CLEAR_KEY_TABLE
        | SET_LOGICAL_AND_RADIO_CHANNEL
        | GET_TOKEN_DATA
        | SET_TOKEN_DATA => Status::Ember,
        ADD_ENDPOINT
        | GET_EXTENDED_VALUE
        | GET_CONFIGURATION_VALUE
        | SET_CONFIGURATION_VALUE
        | SET_POLICY
        | GET_POLICY
        | INVALID_COMMAND
        | GET_VALUE
        | SET_VALUE => Status::Ezsp,
        IMPORT_LINK_KEY | IMPORT_TRANSIENT_KEY | GET_NETWORK_KEY_INFO => Status::Sl,
        _ => Status::Unchanged,
    }
}

/// Whether version `v` (8..=13) has this frame id with the meaning `ncp.rs` gives it.
fn native_in(v: u8, frame_id: u16) -> bool {
    use id::*;
    match frame_id {
        GET_ADDRESS_TABLE_INFO => v >= 14,
        GET_NETWORK_KEY_INFO | TOKEN_FACTORY_RESET => v >= 13,
        IMPORT_LINK_KEY | EXPORT_LINK_KEY_BY_INDEX | IMPORT_TRANSIENT_KEY | EXPORT_KEY => v >= 12,
        GET_TOKEN_DATA | SET_TOKEN_DATA | SET_RADIO_IEEE802154_CCA_MODE | SET_CHILD_DATA => v >= 9,
        _ => true,
    }
}

/// The name a version gives a frame id NetGet answers, for logs and the census.
pub fn name(v: u8, frame_id: u16) -> Option<&'static str> {
    if v < NATIVE {
        match frame_id {
            old::GET_ADDRESS_TABLE_REMOTE_EUI64 => return Some("getAddressTableRemoteEui64"),
            old::GET_ADDRESS_TABLE_REMOTE_NODE_ID => return Some("getAddressTableRemoteNodeId"),
            old::ADD_OR_UPDATE_KEY_TABLE_ENTRY if v < 13 => {
                return Some("addOrUpdateKeyTableEntry")
            }
            old::GET_KEY if v < 13 => return Some("getKey"),
            old::GET_KEY_TABLE_ENTRY if v < 13 => return Some("getKeyTableEntry"),
            old::BECOME_TRUST_CENTER if v < 13 => return Some("becomeTrustCenter"),
            old::OVERRIDE_CURRENT_CHANNEL if v < 9 => return Some("overrideCurrentChannel"),
            old::SET_GPIO_CURRENT_CONFIGURATION if v < 9 => {
                return Some("setGpioCurrentConfiguration")
            }
            old::ADD_TRANSIENT_LINK_KEY if v < 13 => return Some("addTransientLinkKey"),
            f if !native_in(v, f) => return None,
            _ => {}
        }
    }
    ezsp::name(frame_id)
}

/// Answer one command in version `v`'s encoding.
pub fn handle(v: u8, ram: &mut Ram, nv: &mut Nvram, cmd: &Command) -> Handled {
    if v >= NATIVE || cmd.frame_id == id::VERSION {
        let mut h = ncp::handle(v, ram, nv, cmd);
        if v < NATIVE {
            h.response = downgrade_frame(v, cmd, &h.response);
        }
        return h;
    }
    let mut h = Handled {
        name: name(v, cmd.frame_id),
        ..Default::default()
    };
    if cmd.legacy || ram.version.is_none() {
        // ncp::handle refuses both without executing anything; narrow its status.
        let native = ncp::handle(v, ram, nv, cmd);
        h.response = downgrade_frame(v, cmd, &native.response);
        return h;
    }
    if h.name.is_none() {
        // Not a command this version has (or not one NetGet implements).
        let refusal = ezsp::invalid_command(cmd, ezsp::ezsp_status::ERROR_INVALID_FRAME_ID);
        h.response = downgrade_frame(v, cmd, &refusal);
        return h;
    }
    if let Some(params) = old_only(v, ram, nv, cmd) {
        h.response = match params {
            Ok(p) => ezsp::response(cmd, &p),
            // The parameters ended before the command's fields did.
            Err(_) => downgrade_frame(
                v,
                cmd,
                &ezsp::invalid_command(cmd, ezsp_code::ERROR_INVALID_VALUE),
            ),
        };
        return h;
    }
    let upgraded = Command {
        params: upgrade_request(v, cmd.frame_id, &cmd.params),
        ..cmd.clone()
    };
    let native = ncp::handle(v, ram, nv, &upgraded);
    h.response = downgrade_frame(v, cmd, &native.response);
    h.callbacks = native.callbacks;
    h.effects = native.effects;
    h
}

/// A command's v14 parameters from version `v`'s.
fn upgrade_request(v: u8, frame_id: u16, p: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(p);
    let mut w = Writer::new();
    let rebuilt = (|| -> anyhow::Result<Vec<u8>> {
        match frame_id {
            id::SEND_UNICAST => {
                // type, destination, APS frame, then an 8-bit tag (16 from v14).
                let head = r.bytes(1 + 2 + 11)?;
                let tag = r.u8()?;
                w.raw(head)
                    .u16(tag as u16)
                    .raw(&p[p.len() - r.remaining()..]);
            }
            id::SEND_BROADCAST => {
                // destination, APS frame, radius, tag, contents; v14 adds the alias and
                // NWK sequence before the APS frame and widens the tag.
                let destination = r.u16()?;
                let aps = r.bytes(11)?;
                let radius = r.u8()?;
                let tag = r.u8()?;
                w.u16(0)
                    .u16(destination)
                    .u8(0)
                    .raw(aps)
                    .u8(radius)
                    .u16(tag as u16)
                    .raw(&p[p.len() - r.remaining()..]);
            }
            id::SEND_MULTICAST => {
                // APS frame, hops, non-member radius, tag, contents; v14 replaces the
                // non-member radius with broadcast address, alias and NWK sequence.
                let aps = r.bytes(11)?;
                let hops = r.u8()?;
                let _nonmember_radius = r.u8()?;
                let tag = r.u8()?;
                w.raw(aps)
                    .u8(hops)
                    .u16(0xFFFD)
                    .u16(0)
                    .u8(0)
                    .u16(tag as u16)
                    .raw(&p[p.len() - r.remaining()..]);
            }
            id::SET_CHILD_DATA if v < 10 => {
                // The 14-byte EmberChildData of 8 and 9 has no timeout_remaining.
                let index = r.u8()?;
                let child = r.bytes(14)?;
                w.u8(index).raw(child).u32(0);
            }
            _ => return Ok(p.to_vec()),
        }
        Ok(w.done())
    })();
    // A request too short to rebuild is passed on as sent: `ncp::handle` finds it short.
    rebuilt.unwrap_or_else(|_| p.to_vec())
}

/// The response frame in version `v`'s encoding.
pub fn downgrade_frame(v: u8, cmd: &Command, frame: &[u8]) -> Vec<u8> {
    // Header: legacy (3 bytes) for `version` in the legacy format, else extended (5).
    let header = if cmd.legacy { 3 } else { 5 };
    if frame.len() < header {
        return frame.to_vec();
    }
    let frame_id = if cmd.legacy {
        frame[2] as u16
    } else {
        u16::from_le_bytes([frame[3], frame[4]])
    };
    let params = downgrade_params(v, frame_id, &frame[header..]);
    let mut out = frame[..header].to_vec();
    out.extend(params);
    out
}

/// A response's parameters in version `v`'s encoding.
pub fn downgrade_params(v: u8, frame_id: u16, p: &[u8]) -> Vec<u8> {
    let status = |p: &[u8]| -> Option<u32> {
        (p.len() >= 4).then(|| u32::from_le_bytes([p[0], p[1], p[2], p[3]]))
    };
    match frame_id {
        id::EXPORT_KEY => {
            // v14: status, key, context. Before: key, status.
            if p.len() >= 20 {
                let mut out = p[4..20].to_vec();
                out.extend_from_slice(&p[..4]);
                return out;
            }
            p.to_vec()
        }
        id::EXPORT_LINK_KEY_BY_INDEX => {
            // v14: status, context(18), key(16), metadata(12). Before: eui64, key,
            // metadata, status — the EUI-64 is the context's.
            if p.len() >= 4 + 18 + 16 + 12 {
                let ctx = &p[4..22];
                let mut out = ctx[4..12].to_vec();
                out.extend_from_slice(&p[22..38]);
                out.extend_from_slice(&p[38..50]);
                out.extend_from_slice(&p[..4]);
                return out;
            }
            p.to_vec()
        }
        id::SET_EXTENDED_TIMEOUT => Vec::new(),
        id::GET_CHILD_DATA if v < 10 => {
            let mut out = narrow(Status::Ember, p);
            // Drop timeout_remaining from the 18-byte EmberChildData.
            if out.len() >= 1 + 18 {
                out.truncate(out.len() - 4);
            }
            out
        }
        id::INVALID_COMMAND => match status(p) {
            // EzspStatus is the low byte already.
            Some(st) => vec![st as u8],
            None => p.to_vec(),
        },
        _ => narrow(status_kind(frame_id), p),
    }
}

fn narrow(kind: Status, p: &[u8]) -> Vec<u8> {
    if p.len() < 4 {
        return p.to_vec();
    }
    let st = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
    let one = match kind {
        Status::Ember => ember_status(st),
        Status::Ezsp => ezsp_status(st),
        Status::Sl | Status::Unchanged => return p.to_vec(),
    };
    let mut out = vec![one];
    out.extend_from_slice(&p[4..]);
    out
}

/// A callback in version `v`'s encoding.
pub fn callback(v: u8, cb: Callback) -> Callback {
    if v >= NATIVE {
        return cb;
    }
    let p = &cb.params;
    let params = match cb.frame_id {
        id::STACK_STATUS_HANDLER => narrow(Status::Ember, p),
        id::SCAN_COMPLETE_HANDLER if p.len() >= 5 => {
            // channel, then the status: one byte before 14.
            vec![
                p[0],
                ember_status(u32::from_le_bytes([p[1], p[2], p[3], p[4]])),
            ]
        }
        id::MESSAGE_SENT_HANDLER if p.len() >= 4 + 1 + 2 + 11 + 2 + 1 => {
            // v14: status, type, destination, APS, tag(16), contents.
            // Before: type, destination, APS, tag(8), status, contents.
            let st = ember_status(u32::from_le_bytes([p[0], p[1], p[2], p[3]]));
            let mut w = Writer::new();
            w.raw(&p[4..4 + 1 + 2 + 11]).u8(p[18]).u8(st).raw(&p[20..]);
            w.done()
        }
        id::INCOMING_MESSAGE_HANDLER if p.len() >= 1 + 11 + 2 + 8 + 1 + 1 + 1 + 1 + 4 + 1 => {
            // v14: type, APS, sender, EUI-64, binding, address index, LQI, RSSI, timestamp,
            // contents. Before: type, APS, LQI, RSSI, sender, binding, address index,
            // contents — no EUI-64, no timestamp.
            let mut w = Writer::new();
            w.raw(&p[..12]) // type, APS
                .u8(p[24]) // LQI
                .u8(p[25]) // RSSI
                .raw(&p[12..14]) // sender
                .u8(p[22]) // binding index
                .u8(p[23]) // address index
                .raw(&p[30..]); // contents
            w.done()
        }
        _ => p.clone(),
    };
    Callback {
        frame_id: cb.frame_id,
        params,
    }
}

/// `EmberKeyStruct`: bitmask, type, key, outgoing and incoming frame counters, sequence,
/// partner EUI-64 (36 bytes).
fn key_struct(
    w: &mut Writer,
    bitmask: u16,
    kind: u8,
    key: &[u8; 16],
    outgoing: u32,
    sequence: u8,
    partner: u64,
) {
    w.u16(bitmask)
        .u8(kind)
        .raw(key)
        .u32(outgoing)
        .u32(0)
        .u8(sequence)
        .eui64(partner);
}

/// `EmberKeyStructBitmask` bits.
const HAS_SEQUENCE_NUMBER: u16 = 0x0001;
const HAS_OUTGOING_FRAME_COUNTER: u16 = 0x0002;
const HAS_PARTNER_EUI64: u16 = 0x0008;
/// `EmberKeyType`.
const TRUST_CENTER_LINK_KEY: u8 = 1;
const CURRENT_NETWORK_KEY: u8 = 3;
const APPLICATION_LINK_KEY: u8 = 5;

/// Commands only versions before 13 (or 14) have; `None` for every other.
fn old_only(
    v: u8,
    ram: &mut Ram,
    nv: &mut Nvram,
    cmd: &Command,
) -> Option<anyhow::Result<Vec<u8>>> {
    let pre13 = v < 13;
    let handled = match cmd.frame_id {
        old::GET_ADDRESS_TABLE_REMOTE_EUI64 | old::GET_ADDRESS_TABLE_REMOTE_NODE_ID => true,
        old::GET_KEY
        | old::GET_KEY_TABLE_ENTRY
        | old::ADD_OR_UPDATE_KEY_TABLE_ENTRY
        | old::ADD_TRANSIENT_LINK_KEY
        | old::BECOME_TRUST_CENTER => pre13,
        old::OVERRIDE_CURRENT_CHANNEL | old::SET_GPIO_CURRENT_CONFIGURATION => v < 9,
        _ => false,
    };
    if !handled {
        return None;
    }
    let mut r = Reader::new(&cmd.params);
    let mut w = Writer::new();
    let result = (|| -> anyhow::Result<Vec<u8>> {
        match cmd.frame_id {
            old::GET_ADDRESS_TABLE_REMOTE_EUI64 | old::GET_ADDRESS_TABLE_REMOTE_NODE_ID => {
                let index = r.u8()? as usize;
                let entry = nv.joined.iter().filter(|d| !d.kind.is_child()).nth(index);
                if cmd.frame_id == old::GET_ADDRESS_TABLE_REMOTE_EUI64 {
                    w.eui64(entry.map(|d| d.ieee).unwrap_or(0));
                } else {
                    // EMBER_TABLE_ENTRY_UNUSED_NODE_ID for an empty slot.
                    w.u16(entry.map(|d| d.nwk).unwrap_or(0xFFFF));
                }
            }
            old::GET_KEY => {
                let kind = r.u8()?;
                match (kind, &nv.network) {
                    (CURRENT_NETWORK_KEY, Some(n)) => {
                        w.u8(ember::SUCCESS);
                        key_struct(
                            &mut w,
                            HAS_SEQUENCE_NUMBER | HAS_OUTGOING_FRAME_COUNTER,
                            CURRENT_NETWORK_KEY,
                            &n.network_key,
                            nv.nwk_frame_counter,
                            n.key_sequence,
                            0,
                        );
                    }
                    (TRUST_CENTER_LINK_KEY, Some(n)) => {
                        w.u8(ember::SUCCESS);
                        key_struct(
                            &mut w,
                            HAS_PARTNER_EUI64,
                            TRUST_CENTER_LINK_KEY,
                            &n.tc_link_key,
                            0,
                            0,
                            nv.eui64,
                        );
                    }
                    _ => {
                        w.u8(ember::NOT_FOUND);
                        key_struct(&mut w, 0, kind, &[0; 16], 0, 0, 0);
                    }
                }
            }
            old::GET_KEY_TABLE_ENTRY => {
                let index = r.u8()? as usize;
                let size = ram
                    .config
                    .get(&ncp::CONFIG_KEY_TABLE_SIZE)
                    .copied()
                    .unwrap_or(4)
                    .min(ncp::MAX_LINK_KEYS as u16) as usize;
                match nv.link_keys.get(index) {
                    _ if index >= size => {
                        w.u8(ember::INDEX_OUT_OF_RANGE);
                        key_struct(&mut w, 0, 0, &[0; 16], 0, 0, 0);
                    }
                    Some((eui, key)) => {
                        w.u8(ember::SUCCESS);
                        key_struct(
                            &mut w,
                            HAS_PARTNER_EUI64,
                            APPLICATION_LINK_KEY,
                            key,
                            0,
                            0,
                            *eui,
                        );
                    }
                    None => {
                        w.u8(ember::TABLE_ENTRY_ERASED);
                        key_struct(&mut w, 0, 0, &[0; 16], 0, 0, 0);
                    }
                }
            }
            old::ADD_OR_UPDATE_KEY_TABLE_ENTRY => {
                let eui = r.eui64()?;
                let _link_key = r.u8()?;
                let key = r.key()?;
                let st = if let Some(slot) = nv.link_keys.iter_mut().find(|(e, _)| *e == eui) {
                    slot.1 = key;
                    ember::SUCCESS
                } else if nv.link_keys.len() >= ncp::MAX_LINK_KEYS {
                    ember::TABLE_FULL
                } else {
                    nv.link_keys.push((eui, key));
                    ember::SUCCESS
                };
                w.u8(st);
            }
            old::ADD_TRANSIENT_LINK_KEY => {
                let _eui = r.eui64()?;
                let _key = r.key()?;
                w.u8(ember::SUCCESS);
            }
            old::BECOME_TRUST_CENTER => {
                let _key = r.key()?;
                w.u8(ember::SUCCESS);
            }
            old::OVERRIDE_CURRENT_CHANNEL => {
                let _channel = r.u8()?;
                w.u8(ember::SUCCESS);
            }
            old::SET_GPIO_CURRENT_CONFIGURATION => {
                r.bytes(3)?;
                w.u8(ezsp_code::SUCCESS);
            }
            _ => unreachable!("selected above"),
        }
        Ok(w.done())
    })();
    Some(result)
}

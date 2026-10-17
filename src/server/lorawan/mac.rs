//! The LoRaWAN 1.0.x MAC layer: PHYPayload framing, the AES-128 and AES-CMAC operations the
//! specification defines over it (MIC, FRMPayload encryption, Join Accept encryption, session
//! key derivation), frame-counter reconstruction and the MAC commands this implementation
//! names. Shared by the network server and the gateway client; nothing here touches a socket.
//!
//! Byte order follows the specification: EUIs, DevAddr, DevNonce, FCnt and the 24-bit nonces
//! are little-endian on air. NetGet keeps EUIs and DevAddr in their display (big-endian) order
//! and reverses them only at the edge of a frame.
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};

pub type Key = [u8; 16];
pub type Eui = [u8; 8];

pub const MTYPE_JOIN_REQUEST: u8 = 0;
pub const MTYPE_JOIN_ACCEPT: u8 = 1;
pub const MTYPE_UNCONFIRMED_UP: u8 = 2;
pub const MTYPE_UNCONFIRMED_DOWN: u8 = 3;
pub const MTYPE_CONFIRMED_UP: u8 = 4;
pub const MTYPE_CONFIRMED_DOWN: u8 = 5;
pub const MTYPE_REJOIN: u8 = 6;
pub const MTYPE_PROPRIETARY: u8 = 7;

/// LoRaWAN R1 in the MHDR's Major field.
pub const MAJOR_R1: u8 = 0;
/// A frame counter that jumps further than this from the last one accepted is refused
/// (LoRaWAN 1.0.x MAX_FCNT_GAP).
pub const MAX_FCNT_GAP: u32 = 16_384;
/// FOpts is a 4-bit length.
pub const MAX_FOPTS: usize = 15;
/// The largest PHYPayload any region allows (EU868 DR7: M = 250, plus MHDR and MIC).
pub const MAX_PHY_PAYLOAD: usize = 255;
/// Join Request: MHDR, AppEUI, DevEUI, DevNonce, MIC.
pub const JOIN_REQUEST_LEN: usize = 23;
/// The smallest data frame: MHDR, DevAddr, FCtrl, FCnt, MIC.
pub const MIN_DATA_LEN: usize = 12;

pub fn mhdr(mtype: u8) -> u8 {
    (mtype << 5) | MAJOR_R1
}

pub fn mtype_name(mtype: u8) -> &'static str {
    match mtype {
        MTYPE_JOIN_REQUEST => "join_request",
        MTYPE_JOIN_ACCEPT => "join_accept",
        MTYPE_UNCONFIRMED_UP => "unconfirmed_data_up",
        MTYPE_UNCONFIRMED_DOWN => "unconfirmed_data_down",
        MTYPE_CONFIRMED_UP => "confirmed_data_up",
        MTYPE_CONFIRMED_DOWN => "confirmed_data_down",
        MTYPE_REJOIN => "rejoin_request",
        _ => "proprietary",
    }
}

// ---------------------------------------------------------------------------------------
// AES-128 and AES-CMAC (RFC 4493)
// ---------------------------------------------------------------------------------------

pub fn aes_encrypt(key: &Key, block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(&(*key).into());
    let mut b = (*block).into();
    cipher.encrypt_block(&mut b);
    b.into()
}

pub fn aes_decrypt(key: &Key, block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(&(*key).into());
    let mut b = (*block).into();
    cipher.decrypt_block(&mut b);
    b.into()
}

fn shift_left(b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (b[i] << 1) | carry;
        carry = b[i] >> 7;
    }
    out
}

/// The two CMAC subkeys (RFC 4493 §2.3).
fn subkeys(key: &Key) -> ([u8; 16], [u8; 16]) {
    let l = aes_encrypt(key, &[0u8; 16]);
    let mut k1 = shift_left(&l);
    if l[0] & 0x80 != 0 {
        k1[15] ^= 0x87;
    }
    let mut k2 = shift_left(&k1);
    if k1[0] & 0x80 != 0 {
        k2[15] ^= 0x87;
    }
    (k1, k2)
}

/// AES-CMAC (RFC 4493 §2.4).
pub fn aes_cmac(key: &Key, message: &[u8]) -> [u8; 16] {
    let (k1, k2) = subkeys(key);
    let blocks = message.len().div_ceil(16).max(1);
    let complete = !message.is_empty() && message.len() % 16 == 0;
    let mut x = [0u8; 16];
    for i in 0..blocks {
        let start = i * 16;
        let mut block = [0u8; 16];
        if i + 1 < blocks {
            block.copy_from_slice(&message[start..start + 16]);
        } else {
            let tail = &message[start..];
            block[..tail.len()].copy_from_slice(tail);
            if complete {
                for (b, k) in block.iter_mut().zip(k1) {
                    *b ^= k;
                }
            } else {
                block[tail.len()] = 0x80;
                for (b, k) in block.iter_mut().zip(k2) {
                    *b ^= k;
                }
            }
        }
        for (xb, bb) in x.iter_mut().zip(block) {
            *xb ^= bb;
        }
        x = aes_encrypt(key, &x);
    }
    x
}

/// The four-byte MIC: the first four bytes of the CMAC.
pub fn mic(key: &Key, message: &[u8]) -> [u8; 4] {
    let c = aes_cmac(key, message);
    [c[0], c[1], c[2], c[3]]
}

// ---------------------------------------------------------------------------------------
// Hex helpers for EUIs, DevAddr and keys as written in configuration and events
// ---------------------------------------------------------------------------------------

fn parse_hex<const N: usize>(what: &str, s: &str) -> Result<[u8; N]> {
    let cleaned: String = s
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | ' '))
        .collect();
    let bytes = hex::decode(&cleaned).with_context(|| format!("{what} is not hex"))?;
    ensure!(
        bytes.len() == N,
        "{what} is {N} bytes ({} hex digits), not {}",
        N * 2,
        bytes.len()
    );
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn parse_eui(what: &str, s: &str) -> Result<Eui> {
    parse_hex::<8>(what, s)
}
pub fn parse_key(what: &str, s: &str) -> Result<Key> {
    parse_hex::<16>(what, s)
}
pub fn parse_dev_addr(s: &str) -> Result<u32> {
    Ok(u32::from_be_bytes(parse_hex::<4>("dev_addr", s)?))
}
pub fn eui_hex(e: &Eui) -> String {
    hex::encode(e)
}
pub fn dev_addr_hex(a: u32) -> String {
    format!("{a:08x}")
}

fn reversed<const N: usize>(b: &[u8; N]) -> [u8; N] {
    let mut o = *b;
    o.reverse();
    o
}

// ---------------------------------------------------------------------------------------
// Join Request / Join Accept and session keys
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    pub app_eui: Eui,
    pub dev_eui: Eui,
    pub dev_nonce: u16,
}

pub fn encode_join_request(jr: &JoinRequest, app_key: &Key) -> Vec<u8> {
    let mut b = vec![mhdr(MTYPE_JOIN_REQUEST)];
    b.extend(reversed(&jr.app_eui));
    b.extend(reversed(&jr.dev_eui));
    b.extend(jr.dev_nonce.to_le_bytes());
    let m = mic(app_key, &b);
    b.extend(m);
    b
}

/// The fields of a Join Request, before its MIC is checked (the DevEUI says which key to use).
pub fn parse_join_request(phy: &[u8]) -> Result<JoinRequest> {
    ensure!(
        phy.len() == JOIN_REQUEST_LEN,
        "a Join Request is {JOIN_REQUEST_LEN} bytes, not {}",
        phy.len()
    );
    ensure!(phy[0] >> 5 == MTYPE_JOIN_REQUEST, "not a Join Request");
    let mut app = [0u8; 8];
    app.copy_from_slice(&phy[1..9]);
    let mut dev = [0u8; 8];
    dev.copy_from_slice(&phy[9..17]);
    Ok(JoinRequest {
        app_eui: reversed(&app),
        dev_eui: reversed(&dev),
        dev_nonce: u16::from_le_bytes([phy[17], phy[18]]),
    })
}

pub fn join_request_mic_ok(phy: &[u8], app_key: &Key) -> bool {
    phy.len() == JOIN_REQUEST_LEN && mic(app_key, &phy[..19])[..] == phy[19..23]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinAccept {
    /// 24 bits.
    pub app_nonce: u32,
    /// 24 bits.
    pub net_id: u32,
    pub dev_addr: u32,
    pub rx1_dr_offset: u8,
    pub rx2_data_rate: u8,
    /// Seconds before RX1; 0 means 1.
    pub rx_delay: u8,
    pub cf_list: Option<[u8; 16]>,
}

fn join_accept_plain(ja: &JoinAccept) -> Vec<u8> {
    let mut b = vec![mhdr(MTYPE_JOIN_ACCEPT)];
    b.extend(&ja.app_nonce.to_le_bytes()[..3]);
    b.extend(&ja.net_id.to_le_bytes()[..3]);
    b.extend(ja.dev_addr.to_le_bytes());
    b.push(((ja.rx1_dr_offset & 0x07) << 4) | (ja.rx2_data_rate & 0x0f));
    b.push(ja.rx_delay & 0x0f);
    if let Some(cf) = ja.cf_list {
        b.extend(cf);
    }
    b
}

/// The Join Accept on air: the MIC is computed over the plaintext, then everything after the
/// MHDR is put through AES *decrypt* with the AppKey, so the device recovers it with encrypt.
pub fn encode_join_accept(ja: &JoinAccept, app_key: &Key) -> Vec<u8> {
    let mut plain = join_accept_plain(ja);
    let m = mic(app_key, &plain);
    plain.extend(m);
    let mut out = vec![plain[0]];
    for chunk in plain[1..].chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        out.extend(aes_decrypt(app_key, &block));
    }
    out
}

/// Decrypt a Join Accept and check its MIC; an error names which of the two failed.
pub fn decode_join_accept(phy: &[u8], app_key: &Key) -> Result<JoinAccept> {
    ensure!(
        phy.len() == 17 || phy.len() == 33,
        "a Join Accept is 17 or 33 bytes, not {}",
        phy.len()
    );
    ensure!(phy[0] >> 5 == MTYPE_JOIN_ACCEPT, "not a Join Accept");
    let mut plain = vec![phy[0]];
    for chunk in phy[1..].chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        plain.extend(aes_encrypt(app_key, &block));
    }
    let n = plain.len();
    ensure!(
        mic(app_key, &plain[..n - 4])[..] == plain[n - 4..],
        "the Join Accept's MIC does not verify under this AppKey"
    );
    let b = &plain[1..n - 4];
    let le24 = |s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], 0]);
    let cf_list = if b.len() == 28 {
        let mut cf = [0u8; 16];
        cf.copy_from_slice(&b[12..28]);
        Some(cf)
    } else {
        None
    };
    Ok(JoinAccept {
        app_nonce: le24(&b[0..3]),
        net_id: le24(&b[3..6]),
        dev_addr: u32::from_le_bytes([b[6], b[7], b[8], b[9]]),
        rx1_dr_offset: (b[10] >> 4) & 0x07,
        rx2_data_rate: b[10] & 0x0f,
        rx_delay: b[11] & 0x0f,
        cf_list,
    })
}

/// NwkSKey and AppSKey (LoRaWAN 1.0.x §6.2.5).
pub fn session_keys(app_key: &Key, app_nonce: u32, net_id: u32, dev_nonce: u16) -> (Key, Key) {
    let derive = |prefix: u8| {
        let mut b = [0u8; 16];
        b[0] = prefix;
        b[1..4].copy_from_slice(&app_nonce.to_le_bytes()[..3]);
        b[4..7].copy_from_slice(&net_id.to_le_bytes()[..3]);
        b[7..9].copy_from_slice(&dev_nonce.to_le_bytes());
        aes_encrypt(app_key, &b)
    };
    (derive(0x01), derive(0x02))
}

// ---------------------------------------------------------------------------------------
// Data frames
// ---------------------------------------------------------------------------------------

pub const DIR_UP: u8 = 0;
pub const DIR_DOWN: u8 = 1;

/// A data frame as it is on air: FRMPayload still encrypted, FCnt still 16 bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFrame {
    pub mtype: u8,
    pub dev_addr: u32,
    pub adr: bool,
    /// ADRACKReq on an uplink; unused (RFU) on a downlink.
    pub adr_ack_req: bool,
    pub ack: bool,
    /// FPending on a downlink; ClassB on an uplink.
    pub f_pending: bool,
    pub f_cnt: u16,
    pub f_opts: Vec<u8>,
    pub f_port: Option<u8>,
    pub frm_payload: Vec<u8>,
    pub mic: [u8; 4],
}

impl DataFrame {
    pub fn uplink(&self) -> bool {
        matches!(self.mtype, MTYPE_UNCONFIRMED_UP | MTYPE_CONFIRMED_UP)
    }
    pub fn confirmed(&self) -> bool {
        matches!(self.mtype, MTYPE_CONFIRMED_UP | MTYPE_CONFIRMED_DOWN)
    }
}

pub fn mtype_of(phy: &[u8]) -> Result<u8> {
    let first = *phy.first().context("empty PHYPayload")?;
    ensure!(
        first & 0x03 == MAJOR_R1,
        "MHDR major version {} is not LoRaWAN R1",
        first & 0x03
    );
    Ok(first >> 5)
}

pub fn parse_data(phy: &[u8]) -> Result<DataFrame> {
    ensure!(
        phy.len() >= MIN_DATA_LEN,
        "a data frame is at least {MIN_DATA_LEN} bytes"
    );
    ensure!(
        phy.len() <= MAX_PHY_PAYLOAD,
        "a PHYPayload is at most {MAX_PHY_PAYLOAD} bytes"
    );
    let mtype = mtype_of(phy)?;
    ensure!(
        matches!(
            mtype,
            MTYPE_UNCONFIRMED_UP
                | MTYPE_CONFIRMED_UP
                | MTYPE_UNCONFIRMED_DOWN
                | MTYPE_CONFIRMED_DOWN
        ),
        "{} is not a data frame",
        mtype_name(mtype)
    );
    let dev_addr = u32::from_le_bytes([phy[1], phy[2], phy[3], phy[4]]);
    let fctrl = phy[5];
    let f_cnt = u16::from_le_bytes([phy[6], phy[7]]);
    let fopts_len = (fctrl & 0x0f) as usize;
    let body_end = phy.len() - 4;
    let fopts_end = 8 + fopts_len;
    ensure!(fopts_end <= body_end, "FOptsLen runs past the frame");
    let f_opts = phy[8..fopts_end].to_vec();
    let (f_port, frm_payload) = if fopts_end < body_end {
        (Some(phy[fopts_end]), phy[fopts_end + 1..body_end].to_vec())
    } else {
        (None, Vec::new())
    };
    if f_port == Some(0) {
        ensure!(
            f_opts.is_empty(),
            "MAC commands in both FOpts and FPort 0 are not allowed"
        );
    }
    let mut mic = [0u8; 4];
    mic.copy_from_slice(&phy[body_end..]);
    Ok(DataFrame {
        mtype,
        dev_addr,
        adr: fctrl & 0x80 != 0,
        adr_ack_req: fctrl & 0x40 != 0,
        ack: fctrl & 0x20 != 0,
        f_pending: fctrl & 0x10 != 0,
        f_cnt,
        f_opts,
        f_port,
        frm_payload,
        mic,
    })
}

fn block(first: u8, dir: u8, dev_addr: u32, f_cnt: u32, last: u8) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = first;
    b[5] = dir;
    b[6..10].copy_from_slice(&dev_addr.to_le_bytes());
    b[10..14].copy_from_slice(&f_cnt.to_le_bytes());
    b[15] = last;
    b
}

/// The data-frame MIC over `msg` (MHDR through FRMPayload) with the 32-bit frame counter.
pub fn data_mic(nwk_s_key: &Key, dir: u8, dev_addr: u32, f_cnt: u32, msg: &[u8]) -> [u8; 4] {
    let mut b = block(0x49, dir, dev_addr, f_cnt, msg.len() as u8).to_vec();
    b.extend_from_slice(msg);
    mic(nwk_s_key, &b)
}

/// Whether the frame's MIC verifies with this key at this full counter.
pub fn data_mic_ok(phy: &[u8], nwk_s_key: &Key, dir: u8, dev_addr: u32, f_cnt: u32) -> bool {
    if phy.len() < MIN_DATA_LEN {
        return false;
    }
    let n = phy.len() - 4;
    data_mic(nwk_s_key, dir, dev_addr, f_cnt, &phy[..n])[..] == phy[n..]
}

/// FRMPayload encryption and decryption are the same keystream XOR (§4.3.3).
pub fn crypt_frm(key: &Key, dir: u8, dev_addr: u32, f_cnt: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len());
    for (i, chunk) in payload.chunks(16).enumerate() {
        let s = aes_encrypt(key, &block(0x01, dir, dev_addr, f_cnt, (i + 1) as u8));
        out.extend(chunk.iter().zip(s).map(|(p, k)| p ^ k));
    }
    out
}

/// A frame to build: the payload is plaintext; Rust encrypts it and signs the frame.
pub struct OutFrame<'a> {
    pub mtype: u8,
    pub dev_addr: u32,
    pub adr: bool,
    pub adr_ack_req: bool,
    pub ack: bool,
    pub f_pending: bool,
    pub f_cnt: u32,
    pub f_opts: &'a [u8],
    pub f_port: Option<u8>,
    pub payload: &'a [u8],
}

pub fn encode_data(f: &OutFrame<'_>, nwk_s_key: &Key, app_s_key: &Key) -> Result<Vec<u8>> {
    ensure!(f.f_opts.len() <= MAX_FOPTS, "FOpts is at most 15 bytes");
    let dir = if matches!(f.mtype, MTYPE_UNCONFIRMED_UP | MTYPE_CONFIRMED_UP) {
        DIR_UP
    } else {
        DIR_DOWN
    };
    if f.f_port.is_none() {
        ensure!(f.payload.is_empty(), "a payload needs an FPort");
    }
    let mut b = vec![mhdr(f.mtype)];
    b.extend(f.dev_addr.to_le_bytes());
    b.push(
        (u8::from(f.adr) << 7)
            | (u8::from(f.adr_ack_req) << 6)
            | (u8::from(f.ack) << 5)
            | (u8::from(f.f_pending) << 4)
            | f.f_opts.len() as u8,
    );
    b.extend((f.f_cnt as u16).to_le_bytes());
    b.extend_from_slice(f.f_opts);
    if let Some(port) = f.f_port {
        b.push(port);
        let key = if port == 0 { nwk_s_key } else { app_s_key };
        b.extend(crypt_frm(key, dir, f.dev_addr, f.f_cnt, f.payload));
    }
    let m = data_mic(nwk_s_key, dir, f.dev_addr, f.f_cnt, &b);
    b.extend(m);
    ensure!(b.len() <= MAX_PHY_PAYLOAD, "the frame exceeds 255 bytes");
    Ok(b)
}

/// The full 32-bit counter a 16-bit one on air stands for, given the last one accepted: the
/// last counter's upper half, moved on by one wrap when the low half went backwards.
pub fn full_fcnt(last: Option<u32>, wire: u16) -> u32 {
    match last {
        None => wire as u32,
        Some(last) => {
            let candidate = (last & 0xffff_0000) | wire as u32;
            if candidate < last {
                candidate.wrapping_add(0x1_0000)
            } else {
                candidate
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FcntCheck {
    /// Newer than anything accepted, within MAX_FCNT_GAP.
    Fresh(u32),
    /// The same counter as the last accepted frame: a retransmission.
    Repeat(u32),
    /// Further ahead than MAX_FCNT_GAP: an old frame replayed across the 16-bit wrap, or a
    /// device whose counter can no longer be trusted.
    TooFar(u32),
}

pub fn classify_fcnt(last: Option<u32>, wire: u16) -> FcntCheck {
    let full = full_fcnt(last, wire);
    match last {
        // The first frame of a session: an OTAA session starts at 0, and an ABP device that
        // rebooted starts wherever it does.
        None => FcntCheck::Fresh(full),
        Some(l) if full == l => FcntCheck::Repeat(full),
        Some(l) if full - l > MAX_FCNT_GAP => FcntCheck::TooFar(full),
        Some(_) => FcntCheck::Fresh(full),
    }
}

// ---------------------------------------------------------------------------------------
// MAC commands
// ---------------------------------------------------------------------------------------

pub const CID_LINK_CHECK: u8 = 0x02;
pub const CID_LINK_ADR: u8 = 0x03;
pub const CID_DUTY_CYCLE: u8 = 0x04;
pub const CID_RX_PARAM_SETUP: u8 = 0x05;
pub const CID_DEV_STATUS: u8 = 0x06;
pub const CID_NEW_CHANNEL: u8 = 0x07;
pub const CID_RX_TIMING_SETUP: u8 = 0x08;
pub const CID_TX_PARAM_SETUP: u8 = 0x09;
pub const CID_DL_CHANNEL: u8 = 0x0a;
pub const CID_DEVICE_TIME: u8 = 0x0d;

/// Payload length of each command in each direction (uplink = sent by the device).
fn mac_len(cid: u8, uplink: bool) -> Option<usize> {
    Some(match (cid, uplink) {
        (CID_LINK_CHECK, true) => 0,
        (CID_LINK_CHECK, false) => 2,
        (CID_LINK_ADR, true) => 1,
        (CID_LINK_ADR, false) => 4,
        (CID_DUTY_CYCLE, true) => 0,
        (CID_DUTY_CYCLE, false) => 1,
        (CID_RX_PARAM_SETUP, true) => 1,
        (CID_RX_PARAM_SETUP, false) => 4,
        (CID_DEV_STATUS, true) => 2,
        (CID_DEV_STATUS, false) => 0,
        (CID_NEW_CHANNEL, true) => 1,
        (CID_NEW_CHANNEL, false) => 5,
        (CID_RX_TIMING_SETUP, true) => 0,
        (CID_RX_TIMING_SETUP, false) => 1,
        (CID_TX_PARAM_SETUP, true) => 0,
        (CID_TX_PARAM_SETUP, false) => 1,
        (CID_DL_CHANNEL, true) => 1,
        (CID_DL_CHANNEL, false) => 4,
        (CID_DEVICE_TIME, true) => 0,
        (CID_DEVICE_TIME, false) => 5,
        _ => return None,
    })
}

fn freq_hz(b: &[u8]) -> u64 {
    u32::from_le_bytes([b[0], b[1], b[2], 0]) as u64 * 100
}

fn six_bit_signed(v: u8) -> i8 {
    let v = v & 0x3f;
    if v & 0x20 != 0 {
        (v as i8) - 64
    } else {
        v as i8
    }
}

/// Decode a run of MAC commands into named objects. A command NetGet does not know ends the
/// run (its length is unknowable), reported as `{"command":"unknown","cid":n}`.
pub fn decode_mac_commands(bytes: &[u8], uplink: bool) -> Vec<Value> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let cid = bytes[i];
        let Some(len) = mac_len(cid, uplink) else {
            out.push(json!({"command": "unknown", "cid": cid}));
            break;
        };
        let Some(p) = bytes.get(i + 1..i + 1 + len) else {
            out.push(json!({"command": "truncated", "cid": cid}));
            break;
        };
        let bit = |b: u8, n: u8| b & (1 << n) != 0;
        out.push(match (cid, uplink) {
            (CID_LINK_CHECK, true) => json!({"command": "link_check_req"}),
            (CID_LINK_CHECK, false) => {
                json!({"command": "link_check_ans", "margin_db": p[0], "gateway_count": p[1]})
            }
            (CID_LINK_ADR, true) => json!({"command": "link_adr_ans",
                "power_ack": bit(p[0], 2), "data_rate_ack": bit(p[0], 1), "channel_mask_ack": bit(p[0], 0)}),
            (CID_LINK_ADR, false) => json!({"command": "link_adr_req",
                "data_rate": p[0] >> 4, "tx_power": p[0] & 0x0f,
                "channel_mask": format!("{:016b}", u16::from_le_bytes([p[1], p[2]])),
                "channel_mask_control": (p[3] >> 4) & 0x07, "nb_trans": p[3] & 0x0f}),
            (CID_DUTY_CYCLE, true) => json!({"command": "duty_cycle_ans"}),
            (CID_DUTY_CYCLE, false) => {
                json!({"command": "duty_cycle_req", "max_duty_cycle": p[0] & 0x0f})
            }
            (CID_RX_PARAM_SETUP, true) => json!({"command": "rx_param_setup_ans",
                "rx1_dr_offset_ack": bit(p[0], 2), "rx2_data_rate_ack": bit(p[0], 1), "channel_ack": bit(p[0], 0)}),
            (CID_RX_PARAM_SETUP, false) => json!({"command": "rx_param_setup_req",
                "rx1_dr_offset": (p[0] >> 4) & 0x07, "rx2_data_rate": p[0] & 0x0f, "frequency_hz": freq_hz(&p[1..4])}),
            (CID_DEV_STATUS, true) => json!({"command": "dev_status_ans",
                "battery": p[0], "margin_db": six_bit_signed(p[1])}),
            (CID_DEV_STATUS, false) => json!({"command": "dev_status_req"}),
            (CID_NEW_CHANNEL, true) => json!({"command": "new_channel_ans",
                "data_rate_range_ok": bit(p[0], 1), "channel_frequency_ok": bit(p[0], 0)}),
            (CID_NEW_CHANNEL, false) => json!({"command": "new_channel_req",
                "channel_index": p[0], "frequency_hz": freq_hz(&p[1..4]), "max_dr": p[4] >> 4, "min_dr": p[4] & 0x0f}),
            (CID_RX_TIMING_SETUP, true) => json!({"command": "rx_timing_setup_ans"}),
            (CID_RX_TIMING_SETUP, false) => {
                json!({"command": "rx_timing_setup_req", "delay": p[0] & 0x0f})
            }
            (CID_TX_PARAM_SETUP, true) => json!({"command": "tx_param_setup_ans"}),
            (CID_TX_PARAM_SETUP, false) => json!({"command": "tx_param_setup_req",
                "downlink_dwell_time": bit(p[0], 5), "uplink_dwell_time": bit(p[0], 4), "max_eirp": p[0] & 0x0f}),
            (CID_DL_CHANNEL, true) => json!({"command": "dl_channel_ans",
                "uplink_frequency_exists": bit(p[0], 1), "channel_frequency_ok": bit(p[0], 0)}),
            (CID_DL_CHANNEL, false) => json!({"command": "dl_channel_req",
                "channel_index": p[0], "frequency_hz": freq_hz(&p[1..4])}),
            (CID_DEVICE_TIME, true) => json!({"command": "device_time_req"}),
            (CID_DEVICE_TIME, _) => json!({"command": "device_time_ans",
                "gps_seconds": u32::from_le_bytes([p[0], p[1], p[2], p[3]]), "fraction_256ths": p[4]}),
            _ => unreachable!("mac_len only knows the commands matched above"),
        });
        i += 1 + len;
    }
    out
}

/// LinkCheckAns (network → device).
pub fn link_check_ans(margin_db: u8, gateway_count: u8) -> [u8; 3] {
    [CID_LINK_CHECK, margin_db, gateway_count]
}

/// DevStatusAns (device → network): battery 0 = external power, 1..254 level, 255 unknown;
/// margin is the last downlink's SNR, a 6-bit signed value.
pub fn dev_status_ans(battery: u8, margin_db: i8) -> [u8; 3] {
    [
        CID_DEV_STATUS,
        battery,
        (margin_db.clamp(-32, 31) as u8) & 0x3f,
    ]
}

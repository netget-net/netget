//! An OpenVPN codec written independently of the one under test.
//!
//! Everything here is derived from the protocol layout with explicit offsets and
//! deliberately does not call into `netget::server::openvpn::packet`. Tests that
//! check NetGet's parser against NetGet's serializer prove nothing: both can be
//! wrong in the same way, which is exactly how this protocol shipped a reset
//! reply that no real client would accept.
//!
//! # Layout
//!
//! ```text
//! u8       opcode << 3 | key_id
//! u64      sender's session id
//! u8       ACK count n
//! u32 * n  acknowledged packet ids
//! u64      peer session id      -- only when n > 0
//! u32      message packet id    -- absent for P_ACK_V1
//! ...      payload
//! ```
//!
//! The constants are frames captured from OpenVPN 2.7.4 (`aarch64-apple-darwin`,
//! OpenSSL 3.6.2). The two server frames are the exact bytes that client
//! accepted.

#![cfg(unix)]
#![allow(dead_code)]

pub const OP_CONTROL_V1: u8 = 4;
pub const OP_ACK_V1: u8 = 5;
pub const OP_HARD_RESET_CLIENT_V2: u8 = 7;
pub const OP_HARD_RESET_SERVER_V2: u8 = 8;
pub const OP_DATA_V2: u8 = 9;
pub const OP_HARD_RESET_CLIENT_V3: u8 = 10;

/// `P_CONTROL_HARD_RESET_CLIENT_V2` exactly as OpenVPN 2.7.4 sends it (14 bytes).
pub const CAPTURED_CLIENT_RESET_V2: &str = "38090a7265e64d55ee0000000000";

/// `P_CONTROL_HARD_RESET_SERVER_V2` that OpenVPN 2.7.4 accepted (26 bytes).
///
/// On receiving it the client logged
/// `TLS: Initial packet from [AF_INET]127.0.0.1:11941, sid=44045c9b 5510b914`.
pub const CAPTURED_SERVER_RESET_V2: &str = "4044045c9b5510b9140100000000f3bcd18111a444d700000000";

/// `P_ACK_V1` that OpenVPN 2.7.4 accepted (22 bytes).
///
/// The client logged `UDPv4 READ [22] ... P_ACK_V1 kid=0 [ 1 ] DATA len=0` and
/// stopped retransmitting.
pub const CAPTURED_SERVER_ACK_V1: &str = "28e28f68665dda2c98010000000167505a5dc91f20ba";

/// First 64 bytes of the `P_CONTROL_V1` carrying the client's TLS ClientHello.
pub const CAPTURED_CLIENT_CONTROL_V1: &str = "20f3bcd18111a444d7010000000044045c9b5510b91400000001\
     16030105dd010005d903032efac9423c4a6b6467da0684b3e4a2fbadb843d81144f0a078d32e";

pub fn hex(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(cleaned.len() % 2 == 0, "odd-length hex literal");
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("bad hex literal"))
        .collect()
}

pub fn to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// A control or ACK frame, decoded by offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawControl {
    pub opcode: u8,
    pub key_id: u8,
    pub session_id: u64,
    pub acks: Vec<u32>,
    pub remote_session_id: Option<u64>,
    pub packet_id: Option<u32>,
    pub payload: Vec<u8>,
}

/// Decode a control/ACK frame. Panics on truncation — callers pass frames they
/// have already asserted the length of, and a panic in a test is a failure, not
/// a silent hazard.
pub fn decode_control(data: &[u8]) -> RawControl {
    assert!(
        data.len() >= 10,
        "frame too short to be a control packet: {}",
        to_hex(data)
    );
    let opcode = data[0] >> 3;
    let key_id = data[0] & 0x07;
    let session_id = u64::from_be_bytes(data[1..9].try_into().unwrap());
    let ack_len = data[9] as usize;

    let mut off = 10;
    let mut acks = Vec::new();
    for _ in 0..ack_len {
        assert!(
            data.len() >= off + 4,
            "truncated ACK array: {}",
            to_hex(data)
        );
        acks.push(u32::from_be_bytes(data[off..off + 4].try_into().unwrap()));
        off += 4;
    }

    let remote_session_id = if ack_len > 0 {
        assert!(
            data.len() >= off + 8,
            "truncated peer session id: {}",
            to_hex(data)
        );
        let v = u64::from_be_bytes(data[off..off + 8].try_into().unwrap());
        off += 8;
        Some(v)
    } else {
        None
    };

    let packet_id = if opcode == OP_ACK_V1 {
        None
    } else {
        assert!(
            data.len() >= off + 4,
            "truncated message packet id: {}",
            to_hex(data)
        );
        let v = u32::from_be_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;
        Some(v)
    };

    RawControl {
        opcode,
        key_id,
        session_id,
        acks,
        remote_session_id,
        packet_id,
        payload: data[off..].to_vec(),
    }
}

/// Encode a control/ACK frame by offset.
pub fn encode_control(
    opcode: u8,
    key_id: u8,
    session_id: u64,
    acks: &[u32],
    remote_session_id: Option<u64>,
    packet_id: Option<u32>,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = vec![(opcode << 3) | (key_id & 0x07)];
    out.extend_from_slice(&session_id.to_be_bytes());
    out.push(acks.len() as u8);
    for id in acks {
        out.extend_from_slice(&id.to_be_bytes());
    }
    if !acks.is_empty() {
        out.extend_from_slice(
            &remote_session_id
                .expect("peer session id required with ACKs")
                .to_be_bytes(),
        );
    }
    if opcode != OP_ACK_V1 {
        out.extend_from_slice(&packet_id.expect("message packet id required").to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

/// A `P_CONTROL_HARD_RESET_CLIENT_V2` in the shape a real client sends it.
pub fn client_reset_v2(session_id: u64, packet_id: u32) -> Vec<u8> {
    encode_control(
        OP_HARD_RESET_CLIENT_V2,
        0,
        session_id,
        &[],
        None,
        Some(packet_id),
        &[],
    )
}

/// A `P_CONTROL_V1` carrying a payload, acknowledging the server's packet id.
pub fn client_control_v1(
    session_id: u64,
    server_session_id: u64,
    ack: u32,
    packet_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    encode_control(
        OP_CONTROL_V1,
        0,
        session_id,
        &[ack],
        Some(server_session_id),
        Some(packet_id),
        payload,
    )
}

/// A `P_DATA_V2` with a 24-bit peer id and opaque ciphertext.
pub fn data_v2(peer_id: u32, ciphertext: &[u8]) -> Vec<u8> {
    let mut out = vec![OP_DATA_V2 << 3];
    out.extend_from_slice(&[(peer_id >> 16) as u8, (peer_id >> 8) as u8, peer_id as u8]);
    out.extend_from_slice(ciphertext);
    out
}

/// A minimal TLS 1.2/1.3 handshake record header followed by filler, so the
/// server sees something that looks like the start of a ClientHello.
pub fn tls_handshake_record(body_len: usize) -> Vec<u8> {
    let mut out = vec![0x16, 0x03, 0x01];
    out.extend_from_slice(&(body_len as u16).to_be_bytes());
    out.extend(std::iter::repeat(0x41).take(body_len));
    out
}

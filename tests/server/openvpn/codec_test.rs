//! OpenVPN wire-format tests.
//!
//! # Where the expected bytes come from
//!
//! Every literal used here was captured off the wire from **OpenVPN 2.7.4**
//! (`aarch64-apple-darwin`, OpenSSL 3.6.2) talking to a reference responder
//! written independently of NetGet — not produced by the codec under test. The
//! two server frames are the exact bytes that client accepted: it logged
//! `TLS: Initial packet from [AF_INET]127.0.0.1:PORT, sid=...` on receiving the
//! reset reply, and `UDPv4 READ [22] ... P_ACK_V1 kid=0 [ 1 ] DATA len=0` on
//! receiving the ACK, after which it stopped retransmitting.
//!
//! Frames are additionally decoded by [`super::wire::decode_control`], which is
//! written straight from the protocol layout and never calls NetGet's codec. A
//! test that only checked NetGet's parser against NetGet's serializer would pass
//! no matter how wrong both were — which is how this protocol came to ship a
//! reset reply with its fields in the wrong order.

#![cfg(unix)]

use super::wire::*;
use netget::server::openvpn::packet::{parse_opcode_byte, ControlFrame, DataFrame, Opcode};

// ---------------------------------------------------------------------------
// Parsing frames a real client produced
// ---------------------------------------------------------------------------

#[test]
fn parses_real_client_hard_reset_v2() {
    let bytes = hex(CAPTURED_CLIENT_RESET_V2);
    assert_eq!(bytes.len(), 14, "captured client reset is 14 bytes");

    let frame = ControlFrame::parse(&bytes).expect("real client reset must parse");

    assert_eq!(frame.opcode, Opcode::ControlHardResetClientV2);
    assert_eq!(frame.key_id, 0);
    assert_eq!(frame.session_id, 0x090a_7265_e64d_55ee);
    assert!(frame.ack_packet_ids.is_empty());
    assert_eq!(
        frame.remote_session_id, None,
        "no peer session id exists when the ACK array is empty; sniffing for one by length \
         would eat four bytes of the message packet id"
    );
    assert_eq!(
        frame.packet_id,
        Some(0),
        "a real client numbers its first control packet 0"
    );
    assert!(frame.payload.is_empty());
    assert!(frame.is_plain_reset());

    let raw = decode_control(&bytes);
    assert_eq!(raw.opcode, OP_HARD_RESET_CLIENT_V2);
    assert_eq!(raw.session_id, frame.session_id);
    assert_eq!(raw.packet_id, frame.packet_id);
    assert_eq!(raw.payload, frame.payload);
}

#[test]
fn parses_real_client_control_v1_with_acks() {
    let bytes = hex(CAPTURED_CLIENT_CONTROL_V1);
    let frame = ControlFrame::parse(&bytes).expect("real client CONTROL_V1 must parse");
    let raw = decode_control(&bytes);

    assert_eq!(frame.opcode, Opcode::ControlV1);
    assert_eq!(frame.session_id, 0xf3bc_d181_11a4_44d7);
    assert_eq!(frame.ack_packet_ids, vec![0]);
    assert_eq!(
        frame.remote_session_id,
        Some(0x4404_5c9b_5510_b914),
        "the peer session id sits between the ACK array and the message packet id"
    );
    assert_eq!(
        frame.packet_id,
        Some(1),
        "the message packet id follows the ACK array and peer session id, it does not precede them"
    );
    assert_eq!(
        &frame.payload[..5],
        &[0x16, 0x03, 0x01, 0x05, 0xdd],
        "the payload must begin at the TLS record header of the ClientHello"
    );
    assert_eq!(frame.payload.len(), bytes.len() - 26);
    assert!(!frame.is_plain_reset());

    assert_eq!(raw.acks, frame.ack_packet_ids);
    assert_eq!(raw.remote_session_id, frame.remote_session_id);
    assert_eq!(raw.packet_id, frame.packet_id);
    assert_eq!(raw.payload, frame.payload);
}

// ---------------------------------------------------------------------------
// Producing frames a real client accepted
// ---------------------------------------------------------------------------

#[test]
fn emits_the_hard_reset_reply_the_real_client_accepted() {
    let expected = hex(CAPTURED_SERVER_RESET_V2);

    let produced = ControlFrame::hard_reset_server_v2(
        0,
        0x4404_5c9b_5510_b914, // the responder's session id in that capture
        0xf3bc_d181_11a4_44d7, // the client's session id
        0,                     // acknowledging the client's packet 0
        0,                     // our own first packet id
    )
    .serialize()
    .to_vec();

    assert_eq!(
        produced,
        expected,
        "reset reply must be byte-identical to the frame OpenVPN 2.7.4 accepted\n\
         produced: {}\nexpected: {}",
        to_hex(&produced),
        CAPTURED_SERVER_RESET_V2
    );
    assert_eq!(produced.len(), 26);

    let raw = decode_control(&produced);
    assert_eq!(raw.opcode, OP_HARD_RESET_SERVER_V2);
    assert_eq!(raw.acks, vec![0]);
    assert_eq!(raw.remote_session_id, Some(0xf3bc_d181_11a4_44d7));
    assert_eq!(raw.packet_id, Some(0));
    assert!(raw.payload.is_empty(), "a reset reply carries no payload");
}

#[test]
fn emits_the_ack_the_real_client_accepted() {
    let expected = hex(CAPTURED_SERVER_ACK_V1);

    let produced = ControlFrame::ack(0, 0xe28f_6866_5dda_2c98, 0x6750_5a5d_c91f_20ba, vec![1])
        .serialize()
        .to_vec();

    assert_eq!(
        produced,
        expected,
        "ACK must be byte-identical to the frame the client logged\nproduced: {}\nexpected: {}",
        to_hex(&produced),
        CAPTURED_SERVER_ACK_V1
    );
    assert_eq!(
        produced.len(),
        22,
        "an ACK is 22 bytes because it carries no message packet id"
    );

    let raw = decode_control(&produced);
    assert_eq!(raw.opcode, OP_ACK_V1);
    assert_eq!(raw.acks, vec![1]);
    assert_eq!(raw.remote_session_id, Some(0x6750_5a5d_c91f_20ba));
    assert_eq!(raw.packet_id, None);
    assert!(
        raw.payload.is_empty(),
        "trailing bytes would make the client log DATA len>0"
    );
}

#[test]
fn control_frames_round_trip() {
    let frames = vec![
        ControlFrame::hard_reset_server_v2(3, 0xdead_beef_cafe_0001, 0x0102_0304_0506_0708, 7, 0),
        ControlFrame::ack(0, 1, 2, vec![1, 2, 3]),
        ControlFrame {
            opcode: Opcode::ControlV1,
            key_id: 1,
            session_id: 0xaaaa_bbbb_cccc_dddd,
            ack_packet_ids: vec![],
            remote_session_id: None,
            packet_id: Some(42),
            payload: vec![0x16, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5],
        },
    ];

    for frame in frames {
        let bytes = frame.serialize().to_vec();
        let parsed = ControlFrame::parse(&bytes).expect("own frame must re-parse");
        assert_eq!(parsed, frame, "round trip changed the frame");
    }
}

#[test]
fn data_frames_round_trip_and_carry_a_24_bit_peer_id() {
    let v2 = DataFrame {
        opcode: Opcode::DataV2,
        key_id: 2,
        peer_id: Some(0x00ab_cdef),
        payload: vec![9; 40],
    };
    let bytes = v2.serialize().to_vec();
    assert_eq!(
        &bytes[..4],
        &[(9 << 3) | 2, 0xab, 0xcd, 0xef],
        "P_DATA_V2 is one opcode byte followed by a 24-bit peer id, not an 8-byte session id"
    );
    assert_eq!(DataFrame::parse(&bytes).unwrap(), v2);

    let v1 = DataFrame {
        opcode: Opcode::DataV1,
        key_id: 0,
        peer_id: None,
        payload: vec![7; 10],
    };
    let bytes = v1.serialize().to_vec();
    assert_eq!(bytes.len(), 11, "P_DATA_V1 has no peer id");
    assert_eq!(DataFrame::parse(&bytes).unwrap(), v1);
}

// ---------------------------------------------------------------------------
// Hostile input
// ---------------------------------------------------------------------------

#[test]
fn rejects_malformed_control_frames_without_panicking() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty datagram", vec![]),
        ("opcode byte only", hex("38")),
        ("truncated session id", hex("38090a7265e64d")),
        ("missing ACK array length", hex("38090a7265e64d55ee")),
        (
            "ACK length 255 with no ACK array",
            hex("38090a7265e64d55eeff"),
        ),
        (
            "ACK length 1 but no peer session id",
            hex("20f3bcd18111a444d70100000000"),
        ),
        (
            "ACK array present but message packet id truncated",
            hex("20f3bcd18111a444d7010000000044045c9b5510b914000000"),
        ),
        ("unknown opcode 31", hex("f80000000000000000")),
        ("unknown opcode 0", hex("000000000000000000")),
        ("data opcode fed to the control parser", hex("48aabbcc00")),
    ];

    for (name, bytes) in cases {
        let result = ControlFrame::parse(&bytes);
        assert!(
            result.is_err(),
            "{}: must be rejected, got {:?}",
            name,
            result.ok()
        );
    }
}

#[test]
fn refuses_tls_crypt_v2_rather_than_misparsing_it() {
    // Opcode 10 = P_CONTROL_HARD_RESET_CLIENT_V3, opcode 11 = P_CONTROL_WKC_V1.
    // Everything after the session id is encrypted, so applying the plaintext
    // layout to them would yield confident nonsense.
    for (opcode, label) in [
        (OP_HARD_RESET_CLIENT_V3, "HARD_RESET_CLIENT_V3"),
        (11u8, "WKC_V1"),
    ] {
        let mut bytes = vec![opcode << 3];
        bytes.extend_from_slice(&[0xAB; 40]);

        let (parsed_opcode, _) = parse_opcode_byte(&bytes).expect("opcode is a known one");
        assert!(
            parsed_opcode.is_tls_crypt_v2(),
            "{} must be recognised as tls-crypt-v2",
            label
        );
        assert!(
            !parsed_opcode.is_control(),
            "{} must not be routed through the plaintext control layout",
            label
        );

        let err = ControlFrame::parse(&bytes)
            .expect_err(&format!("{} must not be parsed as plaintext", label));
        assert!(
            err.to_string().contains("tls-crypt-v2"),
            "{}: the error should name the reason, got: {}",
            label,
            err
        );
    }
}

#[test]
fn rejects_malformed_data_frames_without_panicking() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty datagram", vec![]),
        ("P_DATA_V2 with a truncated peer id", hex("48aabb")),
        (
            "control opcode fed to the data parser",
            hex("38090a7265e64d55ee0000000000"),
        ),
    ];

    for (name, bytes) in cases {
        assert!(
            DataFrame::parse(&bytes).is_err(),
            "{}: must be rejected",
            name
        );
    }
}

#[test]
fn no_byte_string_can_panic_either_parser() {
    // A UDP socket hands these parsers whatever an attacker sends. A panic in
    // the receive loop is silent and leaves the server reporting Running, so
    // every input must produce Ok or Err and nothing else.
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for i in 0..20_000u32 {
        let len = (next() % 80) as usize;
        let mut bytes: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();

        // Half the cases start from a plausible opcode so the parsers get past
        // the first check and exercise the length handling behind it.
        if i % 2 == 0 && !bytes.is_empty() {
            let opcode = (next() % 12) as u8;
            bytes[0] = (opcode << 3) | ((next() & 0x07) as u8);
        }

        let _ = ControlFrame::parse(&bytes);
        let _ = DataFrame::parse(&bytes);
        let _ = parse_opcode_byte(&bytes);
    }
}

// ---------------------------------------------------------------------------
// The reliability layer
// ---------------------------------------------------------------------------
//
// The control channel is a reliable layer over UDP. These tests drive
// `ReliableSender`/`ReliableReceiver` directly, because the properties that
// matter -- in-order delivery, duplicate suppression, retransmission with
// backoff -- are hard to provoke over a loopback socket that never loses
// anything, and a TLS handshake silently fails to complete if any of them is
// wrong.

use netget::server::openvpn::reliable::{fragment, ReliableReceiver, ReliableSender};
use std::time::{Duration, Instant};

#[test]
fn receiver_delivers_in_order_and_buffers_what_arrives_early() {
    let mut recv = ReliableReceiver::new(0);

    // Packet 2 before packet 0 and 1: nothing may be delivered yet, because a
    // TLS record stream reassembled out of order is garbage.
    assert!(recv.accept(2, b"third".to_vec()).is_empty());
    assert!(recv.accept(1, b"second".to_vec()).is_empty());

    let delivered = recv.accept(0, b"first".to_vec());
    assert_eq!(
        delivered,
        vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
        "the gap closing must release everything that was waiting behind it, in order"
    );
    assert_eq!(recv.next_expected(), 3);
}

#[test]
fn receiver_drops_duplicates_but_still_acknowledges_them() {
    let mut recv = ReliableReceiver::new(0);
    assert_eq!(recv.accept(0, b"hello".to_vec()), vec![b"hello".to_vec()]);
    let _ = recv.take_acks();

    // The peer retransmits only because it missed the first acknowledgement, so
    // the duplicate must produce a new ACK and no second delivery.
    assert!(
        recv.accept(0, b"hello".to_vec()).is_empty(),
        "a duplicate must not be delivered twice"
    );
    assert_eq!(
        recv.take_acks(),
        vec![0],
        "a duplicate must still be acknowledged, or the peer retransmits forever"
    );
}

#[test]
fn receiver_ignores_packets_outside_the_window() {
    let mut recv = ReliableReceiver::new(0);
    assert!(recv.accept(10_000, b"far future".to_vec()).is_empty());
    assert!(
        !recv.has_pending_acks(),
        "a packet outside the window must NOT be acknowledged: the peer has to keep it and \
         send it again once the window has moved"
    );
}

#[test]
fn sender_retransmits_until_acknowledged_then_stops() {
    let mut send = ReliableSender::new();
    let id = send.queue(Opcode::ControlV1, vec![], b"tls records".to_vec());
    assert_eq!(id, 0, "the first control packet a side sends is numbered 0");

    let t0 = Instant::now();
    assert_eq!(
        send.take_due(t0).len(),
        1,
        "a fresh packet goes out at once"
    );
    assert!(
        send.take_due(t0).is_empty(),
        "it must not be sent twice in the same instant"
    );
    assert!(
        send.take_due(t0 + Duration::from_millis(500)).is_empty(),
        "the retransmission delay must actually be waited out"
    );

    let again = send.take_due(t0 + Duration::from_millis(1_100));
    assert_eq!(again.len(), 1, "an unacknowledged packet must go out again");
    assert_eq!(
        again[0].packet_id, 0,
        "a retransmission keeps the packet id"
    );
    assert_eq!(
        again[0].payload,
        b"tls records".to_vec(),
        "a retransmission must be byte-identical"
    );

    send.on_ack(&[0]);
    assert_eq!(send.in_flight(), 0);
    assert!(
        send.take_due(t0 + Duration::from_secs(60)).is_empty(),
        "an acknowledged packet must never be sent again"
    );
}

#[test]
fn sender_gives_up_on_a_peer_that_never_acknowledges() {
    let mut send = ReliableSender::new();
    send.queue(Opcode::ControlV1, vec![], b"x".to_vec());

    let mut now = Instant::now();
    for _ in 0..12 {
        let _ = send.take_due(now);
        now += Duration::from_secs(30);
    }
    assert!(
        send.is_exhausted(),
        "a session whose packets are never acknowledged must be declared dead rather than \
         retransmitted forever"
    );
}

#[test]
fn sender_holds_back_anything_past_the_window() {
    let mut send = ReliableSender::new();
    for i in 0..10 {
        send.queue(Opcode::ControlV1, vec![], vec![i as u8]);
    }
    let due = send.take_due(Instant::now());
    assert_eq!(
        due.len(),
        4,
        "only the send window may be in flight; the peer's reliability buffer is finite and \
         anything beyond it is dropped silently"
    );
    assert_eq!(
        due.iter().map(|d| d.packet_id).collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );
}

#[test]
fn fragmenting_splits_a_tls_flight_and_loses_nothing() {
    let flight: Vec<u8> = (0..5_000u32).map(|i| (i % 251) as u8).collect();
    let chunks = fragment(&flight);
    assert!(chunks.len() > 1, "a multi-kilobyte flight must be split");
    for chunk in &chunks {
        assert!(
            chunk.len() <= 1100,
            "a fragment larger than the peer's control-channel buffer is dropped silently"
        );
    }
    assert_eq!(
        chunks.concat(),
        flight,
        "reassembling the fragments must reproduce the flight exactly"
    );
}

// ---------------------------------------------------------------------------
// Key method 2
// ---------------------------------------------------------------------------
//
// The expected byte layout below is written from `ssl.c`'s
// `key_method_2_write` / `key_method_2_read`, by hand, in this file -- it is
// never produced by the code under test. A `u16`-prefixed string counts its own
// NUL terminator, and `write_empty_string` emits a length of zero with no bytes
// at all, which is a different encoding from a string containing only a NUL.

use netget::server::openvpn::keymethod::{
    build_server_key_method_2, parse_client_key_method_2, peer_info_map, server_options_from_client,
};

/// Encode a `u16`-prefixed, NUL-terminated string the way OpenVPN does.
fn ovpn_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&((s.len() + 1) as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

/// A client key-method-2 message, built by offset.
fn client_key_method_2(options: &str, user: &str, pass: &str, peer_info: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u32.to_be_bytes());
    out.push(2);
    out.extend(std::iter::repeat(0xA1).take(48)); // pre-master
    out.extend(std::iter::repeat(0xB2).take(32)); // random1
    out.extend(std::iter::repeat(0xC3).take(32)); // random2
    ovpn_string(&mut out, options);
    ovpn_string(&mut out, user);
    ovpn_string(&mut out, pass);
    ovpn_string(&mut out, peer_info);
    out
}

#[test]
fn parses_a_client_key_method_2_message() {
    let options = "V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,key-method 2,tls-client";
    let bytes = client_key_method_2(options, "alice", "s3cret", "IV_VER=2.7.6\nIV_PLAT=mac\n");

    let (msg, consumed) = parse_client_key_method_2(&bytes)
        .expect("a well-formed message must parse")
        .expect("and must not be reported as incomplete");

    assert_eq!(consumed, bytes.len(), "the whole message must be consumed");
    assert_eq!(msg.pre_master.len(), 48);
    assert_eq!(msg.random1, vec![0xB2; 32]);
    assert_eq!(msg.random2, vec![0xC3; 32]);
    assert_eq!(msg.options, options);
    assert_eq!(msg.username, "alice");
    assert_eq!(msg.password, "s3cret");
    assert_eq!(msg.peer_info, "IV_VER=2.7.6\nIV_PLAT=mac\n");

    let info = peer_info_map(&msg.peer_info);
    assert_eq!(info.get("IV_VER").and_then(|v| v.as_str()), Some("2.7.6"));
    assert_eq!(info.get("IV_PLAT").and_then(|v| v.as_str()), Some("mac"));
}

#[test]
fn a_partial_key_method_2_message_is_incomplete_not_invalid() {
    // The control channel is a byte stream over several P_CONTROL_V1 packets,
    // so a prefix means "wait", not "reject". Treating it as an error would
    // kill every session whose key exchange spans two packets.
    let bytes = client_key_method_2("V4,tls-client", "u", "p", "IV_VER=2.7.6");
    for cut in [0, 1, 4, 5, 60, 116, 117, bytes.len() - 1] {
        let outcome = parse_client_key_method_2(&bytes[..cut]);
        assert!(
            matches!(outcome, Ok(None)),
            "a {}-byte prefix must be reported as incomplete, got {:?}",
            cut,
            outcome.map(|o| o.is_some())
        );
    }
}

#[test]
fn a_message_that_is_not_key_method_2_is_rejected() {
    let mut wrong_leading = client_key_method_2("V4", "u", "p", "");
    wrong_leading[0] = 0xFF;
    assert!(
        parse_client_key_method_2(&wrong_leading).is_err(),
        "the leading u32 is a literal zero in every version that speaks key method 2"
    );

    let mut wrong_method = client_key_method_2("V4", "u", "p", "");
    wrong_method[4] = 1;
    assert!(
        parse_client_key_method_2(&wrong_method).is_err(),
        "key method 1 was removed from OpenVPN long ago and is not implemented here"
    );
}

#[test]
fn server_key_method_2_matches_the_layout_a_client_reads() {
    let random1 = [0x11u8; 32];
    let random2 = [0x22u8; 32];
    let options = "V4,dev-type tun,key-method 2,tls-server";
    let built = build_server_key_method_2(&random1, &random2, options);

    // Written by hand from key_method_2_write with server=true: no pre-master,
    // then three *empty* strings (u16 0, no bytes) for username, password and
    // peer info -- exactly what a server with no --auth-user-pass-verify emits.
    let mut expected = Vec::new();
    expected.extend_from_slice(&0u32.to_be_bytes());
    expected.push(2);
    expected.extend_from_slice(&random1);
    expected.extend_from_slice(&random2);
    ovpn_string(&mut expected, options);
    expected.extend_from_slice(&0u16.to_be_bytes());
    expected.extend_from_slice(&0u16.to_be_bytes());
    expected.extend_from_slice(&0u16.to_be_bytes());

    assert_eq!(
        to_hex(&built),
        to_hex(&expected),
        "the server's key method 2 message must match the layout the client reads; a client \
         that cannot parse it reports a TLS error rather than a mismatch"
    );
    assert_eq!(
        built.len(),
        4 + 1 + 64 + 2 + options.len() + 1 + 6,
        "no pre-master secret may be sent by the server"
    );
}

#[test]
fn the_answering_options_string_flips_only_the_role() {
    assert_eq!(
        server_options_from_client("V4,dev-type tun,key-method 2,tls-client"),
        "V4,dev-type tun,key-method 2,tls-server",
        "mirroring the client's own string and flipping the role is what stops the client \
         warning about every field it compares"
    );
    assert!(
        server_options_from_client("").contains("tls-server"),
        "an empty options string is a protocol error at the peer, not 'no opinion'"
    );
}

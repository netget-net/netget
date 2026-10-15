//! The CAN codec, against literal values.
//!
//! This file is the reason the `can` protocol is an honest `Experimental` rather than an
//! unverifiable one. `AF_CAN` exists only in the Linux kernel, so the transport cannot be
//! executed on the machine that wrote it — but every decision about *what the bytes are* is made
//! in `src/server/can/frame.rs`, which is pure, and is proven here.
//!
//! Every expectation below is a literal: a byte array written out, or a number written out. None
//! of them is computed by calling the code under test with different arguments, because that
//! proves only that a function agrees with itself. (`rss` sat at Experimental for months on
//! exactly that mistake — the `rss` crate parsing what the `rss` crate had built.)
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features can --test server can::frame \
//!       -- --test-threads=100

#![cfg(unix)]

use netget::server::can::frame::{
    dlc_for_len, len_for_dlc, BusState, CanFrame, CANFD_BRS, CANFD_ESI, CANFD_FDF, CANFD_MTU,
    CAN_EFF_FLAG, CAN_ERR_FLAG, CAN_MTU, CAN_RTR_FLAG,
};
use serde_json::json;

// =================================================================================================
// The DLC tables — the classic implementation error, pinned from both sides
// =================================================================================================

/// Classic CAN: the DLC *is* the byte count, all the way to 8.
#[test]
fn classic_dlc_equals_the_byte_count() {
    for len in 0..=8usize {
        assert_eq!(
            dlc_for_len(len, false).expect("0-8 bytes is always encodable in classic CAN"),
            len as u8,
            "classic CAN DLC and length are the same number"
        );
        assert_eq!(len_for_dlc(len as u8, false), len);
    }
}

/// **The trap.** For CAN FD the DLC is a length *code*, not a byte count, above 8.
///
/// Every one of the sixteen codes is written out. A stack that assumes `len == dlc` produces a
/// frame that is silently the wrong size on the wire, which is the single most common CAN FD
/// implementation error.
#[test]
fn fd_dlc_is_a_length_code_not_a_byte_count() {
    let expected: [(u8, usize); 16] = [
        (0, 0),
        (1, 1),
        (2, 2),
        (3, 3),
        (4, 4),
        (5, 5),
        (6, 6),
        (7, 7),
        (8, 8),
        (9, 12),
        (10, 16),
        (11, 20),
        (12, 24),
        (13, 32),
        (14, 48),
        (15, 64),
    ];

    for (dlc, len) in expected {
        assert_eq!(
            len_for_dlc(dlc, true),
            len,
            "CAN FD DLC {dlc} encodes {len} bytes"
        );
        assert_eq!(
            dlc_for_len(len, true).expect("every listed length is encodable"),
            dlc,
            "{len} bytes is encoded as DLC {dlc}"
        );
    }

    // And the difference from classic is real, not cosmetic.
    assert_eq!(
        len_for_dlc(15, false),
        8,
        "classic CAN saturates at 8 bytes"
    );
    assert_eq!(len_for_dlc(15, true), 64, "CAN FD's DLC 15 means 64 bytes");
}

/// CAN FD has no encoding for 9, 10, 11, 13... bytes. Those must be **refused**, not rounded.
///
/// Rounding up appends bytes the model did not write; rounding down drops bytes it did. Either
/// puts a different message on the bus from the one that was asked for.
#[test]
fn an_unencodable_fd_length_is_refused_rather_than_padded() {
    for len in [9usize, 10, 11, 13, 17, 25, 33, 49, 63] {
        let err = dlc_for_len(len, true)
            .expect_err("CAN FD cannot express this length")
            .to_string();
        assert!(
            err.contains("0-8, 12, 16, 20, 24, 32, 48 or 64"),
            "the refusal must list the encodable lengths, got: {err}"
        );
        assert!(
            err.contains("will not invent bytes"),
            "the refusal must say why it is not padding, got: {err}"
        );
    }
}

/// An over-length payload is rejected, not truncated — in both formats.
#[test]
fn an_over_length_payload_is_rejected_not_truncated() {
    let err = CanFrame::classic(0x123, false, vec![0xAA; 9])
        .expect_err("9 bytes does not fit in a classic CAN frame")
        .to_string();
    assert!(
        err.contains("at most 8 bytes"),
        "a classic over-length payload must name the limit, got: {err}"
    );
    assert!(
        err.contains("\"fd\": true"),
        "and must point at the format that can carry it, got: {err}"
    );

    let err = CanFrame::fd(0x123, false, vec![0xAA; 65], false)
        .expect_err("65 bytes exceeds CAN FD")
        .to_string();
    assert!(
        err.contains("not an encodable length"),
        "an over-length FD payload must be refused, got: {err}"
    );
}

// =================================================================================================
// Identifiers: standard vs extended, explicit and never inferred
// =================================================================================================

/// The 11-bit limit, from both sides, with the message naming the way out.
#[test]
fn a_standard_identifier_is_eleven_bits() {
    assert!(
        CanFrame::classic(0x7FF, false, vec![]).is_ok(),
        "0x7FF is the largest standard identifier"
    );

    let err = CanFrame::classic(0x800, false, vec![])
        .expect_err("0x800 needs 12 bits")
        .to_string();
    assert!(err.contains("11 bits"), "got: {err}");
    assert!(err.contains("0x7FF"), "the limit must be stated: {err}");
    assert!(
        err.contains("\"extended\": true"),
        "and the way out named: {err}"
    );
}

/// The 29-bit limit, from both sides.
#[test]
fn an_extended_identifier_is_twenty_nine_bits() {
    assert!(
        CanFrame::classic(0x1FFF_FFFF, true, vec![]).is_ok(),
        "0x1FFFFFFF is the largest extended identifier"
    );
    let err = CanFrame::classic(0x2000_0000, true, vec![])
        .expect_err("0x20000000 needs 30 bits")
        .to_string();
    assert!(err.contains("29 bits"), "got: {err}");
    assert!(
        err.contains("largest CAN identifier there is"),
        "there is nothing to escalate to, and the message should say so: {err}"
    );
}

/// **`extended` is a field, not a guess.** Standard 0x123 and extended 0x123 are different frames
/// that different nodes answer, and they differ on the wire by one flag bit.
#[test]
fn standard_and_extended_zero_x_123_are_different_frames() {
    let standard = CanFrame::classic(0x123, false, vec![0x01]).unwrap();
    let extended = CanFrame::classic(0x123, true, vec![0x01]).unwrap();

    assert_eq!(standard.id_word(), 0x0000_0123);
    assert_eq!(extended.id_word(), 0x8000_0123);
    assert_ne!(
        standard.to_wire_bytes().unwrap(),
        extended.to_wire_bytes().unwrap(),
        "an identifier's format is part of its identity, so the encodings must differ"
    );

    // And the format survives a round trip through the wire, which is what a receiver reads.
    let decoded = CanFrame::from_wire_bytes(&extended.to_wire_bytes().unwrap()).unwrap();
    assert!(
        decoded.extended,
        "the EFF flag must come back as `extended`"
    );
    assert_eq!(decoded.id, 0x123);
}

// =================================================================================================
// The SocketCAN wire layout, byte for byte
// =================================================================================================

/// `struct can_frame` for a standard data frame, written out octet by octet.
///
/// ```text
/// can_id: 0x0000_07DF, little-endian -> DF 07 00 00
/// len:    2                          -> 02
/// __pad, __res0, len8_dlc            -> 00 00 00
/// data[8]: 01 0C, then zero padding
/// ```
#[test]
fn a_standard_data_frame_encodes_to_the_can_frame_struct() {
    let frame = CanFrame::classic(0x7DF, false, vec![0x01, 0x0C]).unwrap();
    let bytes = frame.to_wire_bytes().unwrap();

    assert_eq!(bytes.len(), CAN_MTU, "struct can_frame is 16 octets");
    assert_eq!(
        bytes,
        vec![
            0xDF, 0x07, 0x00, 0x00, // can_id, little-endian, no flags
            0x02, // len
            0x00, 0x00, 0x00, // __pad, __res0, len8_dlc
            0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // data[8]
        ]
    );

    let decoded = CanFrame::from_wire_bytes(&bytes).unwrap();
    assert_eq!(decoded.id, 0x7DF);
    assert!(!decoded.extended);
    assert!(!decoded.rtr);
    assert!(!decoded.error);
    assert!(!decoded.fd);
    assert_eq!(decoded.data, vec![0x01, 0x0C]);
    assert_eq!(decoded.dlc(), 2);
}

/// An extended identifier sets `CAN_EFF_FLAG` in the identifier word's top bit.
///
/// `0x18DAF110` is the ISO 15765-4 29-bit diagnostic response address, so this is a real
/// identifier rather than an invented one.
#[test]
fn an_extended_data_frame_sets_the_eff_flag() {
    let frame = CanFrame::classic(0x18DA_F110, true, vec![0x02, 0x10, 0x03]).unwrap();
    let bytes = frame.to_wire_bytes().unwrap();

    assert_eq!(
        &bytes[0..4],
        // 0x18DAF110 | 0x80000000 = 0x98DAF110, little-endian
        &[0x10, 0xF1, 0xDA, 0x98],
        "the EFF flag is the top bit of the identifier word"
    );
    assert_eq!(bytes[4], 3, "len");
    assert_eq!(&bytes[8..11], &[0x02, 0x10, 0x03]);
    assert_eq!(frame.id_word() & CAN_EFF_FLAG, CAN_EFF_FLAG);
}

/// A remote frame carries **no data** and a DLC that says how much is being *requested*.
#[test]
fn a_remote_frame_carries_a_request_length_and_no_data() {
    let frame = CanFrame::remote(0x123, false, 8).unwrap();
    let bytes = frame.to_wire_bytes().unwrap();

    assert_eq!(
        &bytes[0..4],
        // 0x123 | CAN_RTR_FLAG(0x40000000) = 0x40000123, little-endian
        &[0x23, 0x01, 0x00, 0x40]
    );
    assert_eq!(bytes[4], 8, "the RTR frame's DLC is the requested length");
    assert_eq!(
        &bytes[8..16],
        &[0u8; 8],
        "a remote frame's payload octets carry nothing"
    );
    assert_eq!(frame.id_word() & CAN_RTR_FLAG, CAN_RTR_FLAG);

    let decoded = CanFrame::from_wire_bytes(&bytes).unwrap();
    assert!(decoded.rtr);
    assert!(decoded.data.is_empty(), "an RTR frame has no payload");
    assert_eq!(decoded.rtr_dlc, 8, "and its DLC is the request");
    assert_eq!(decoded.dlc(), 8);
}

/// A remote frame given a payload is refused: it is a contradiction, not a detail to ignore.
#[test]
fn a_remote_frame_with_data_is_refused() {
    let mut frame = CanFrame::remote(0x123, false, 4).unwrap();
    frame.data = vec![0xFF];
    let err = frame
        .validate()
        .expect_err("RTR frames carry no data")
        .to_string();
    assert!(err.contains("carries no data by definition"), "got: {err}");
}

/// **CAN FD has no remote frames.** The RTR bit was reused as RRS and is always dominant.
#[test]
fn can_fd_has_no_remote_frames() {
    let err = CanFrame::from_action(&json!({
        "type": "send_can_frame",
        "id": "0x123",
        "rtr": true,
        "fd": true
    }))
    .expect_err("rtr and fd together are not a frame that exists")
    .to_string();
    assert!(err.contains("CAN FD has no remote frames"), "got: {err}");
    assert!(err.contains("RRS"), "the reason should be given: {err}");
}

/// `struct canfd_frame`: 72 octets, a `flags` byte where classic has padding, and 64 data octets.
#[test]
fn a_can_fd_frame_encodes_to_the_canfd_frame_struct() {
    // 12 bytes: the first length above 8 that CAN FD can express, and therefore DLC 9.
    let data: Vec<u8> = (0u8..12).collect();
    let frame = CanFrame::fd(0x456, false, data.clone(), true).unwrap();
    let bytes = frame.to_wire_bytes().unwrap();

    assert_eq!(bytes.len(), CANFD_MTU, "struct canfd_frame is 72 octets");
    assert_eq!(&bytes[0..4], &[0x56, 0x04, 0x00, 0x00], "can_id");
    assert_eq!(
        bytes[4], 12,
        "the struct's `len` field is a byte COUNT; the kernel encodes the DLC itself"
    );
    assert_eq!(
        bytes[5],
        CANFD_FDF | CANFD_BRS,
        "flags: FDF because it is an FD frame, BRS because the bit-rate switch was asked for"
    );
    assert_eq!(&bytes[6..8], &[0x00, 0x00], "__res0, __res1");
    assert_eq!(&bytes[8..20], data.as_slice());
    assert_eq!(&bytes[20..72], &[0u8; 52], "the rest of data[64] is zero");

    assert_eq!(
        frame.dlc(),
        9,
        "12 bytes is DLC 9 on the wire, which is what a DBC file and a bus analyser see"
    );

    let decoded = CanFrame::from_wire_bytes(&bytes).unwrap();
    assert!(decoded.fd);
    assert!(decoded.brs);
    assert!(!decoded.esi);
    assert_eq!(decoded.data, data);
    assert_eq!(decoded.dlc(), 9);
}

/// The largest CAN FD frame there is: 64 bytes, DLC 15, and the struct completely full.
#[test]
fn the_largest_can_fd_frame_is_sixty_four_bytes_at_dlc_fifteen() {
    let data: Vec<u8> = (0u8..64).collect();
    let frame = CanFrame::fd(0x1FFF_FFFF, true, data.clone(), false).unwrap();
    let bytes = frame.to_wire_bytes().unwrap();

    assert_eq!(bytes[4], 64);
    assert_eq!(bytes[5], CANFD_FDF, "FDF only: no BRS was requested");
    assert_eq!(&bytes[8..72], data.as_slice(), "data[64] is entirely used");
    assert_eq!(frame.dlc(), 15);
}

/// ESI is receive-side only, and comes back off the wire.
#[test]
fn the_error_state_indicator_survives_a_round_trip() {
    let mut bytes = vec![0u8; CANFD_MTU];
    bytes[0..4].copy_from_slice(&0x0000_0321u32.to_le_bytes());
    bytes[4] = 8;
    bytes[5] = CANFD_FDF | CANFD_ESI;
    bytes[8..16].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33]);

    let decoded = CanFrame::from_wire_bytes(&bytes).unwrap();
    assert!(decoded.fd);
    assert!(decoded.esi, "the transmitter was error-passive");
    assert!(!decoded.brs);
    assert_eq!(decoded.data.len(), 8);
}

/// The bit-rate switch belongs to CAN FD. Asking for it on a classic frame is refused.
#[test]
fn the_bit_rate_switch_requires_can_fd() {
    let err = CanFrame::from_action(&json!({
        "type": "send_can_frame",
        "id": "0x100",
        "brs": true,
        "data": "00"
    }))
    .expect_err("a classic frame has one bit rate")
    .to_string();
    assert!(
        err.contains("bit-rate switch is a CAN FD feature"),
        "got: {err}"
    );
}

/// Anything that is neither 16 nor 72 octets is not a SocketCAN frame.
#[test]
fn only_sixteen_and_seventy_two_octet_structs_decode() {
    for len in [0usize, 8, 15, 17, 64, 71, 73] {
        let err = CanFrame::from_wire_bytes(&vec![0u8; len])
            .expect_err("not a SocketCAN frame struct")
            .to_string();
        assert!(
            err.contains("16 octets") && err.contains("72 octets"),
            "the refusal must name both layouts, got: {err}"
        );
    }
}

// =================================================================================================
// Error frames and the bus-state ladder
// =================================================================================================

/// An error frame's identifier is a class bitmask, and the classes come back as names.
#[test]
fn error_classes_decode_to_names() {
    // CAN_ERR_ACK (0x20) | CAN_ERR_BUSERROR (0x80), with the error flag set.
    let mut bytes = vec![0u8; CAN_MTU];
    bytes[0..4].copy_from_slice(&(CAN_ERR_FLAG | 0x0000_00A0).to_le_bytes());
    bytes[4] = 8;

    let frame = CanFrame::from_wire_bytes(&bytes).unwrap();
    assert!(frame.error, "the ERR flag must decode as an error frame");
    assert_eq!(
        frame.error_classes().unwrap(),
        vec!["no_acknowledgement", "bus_error"]
    );
    assert!(
        frame.bus_state().is_none(),
        "a missing acknowledgement is not a confinement state change"
    );

    let data = frame.to_event_data();
    assert_eq!(data["error"], json!(true));
    assert_eq!(
        data["error_classes"],
        json!(["no_acknowledgement", "bus_error"])
    );
}

/// The confinement ladder, driven from `CAN_ERR_CRTL` and `data[1]` exactly as the kernel reports
/// it, plus the two identifier bits that report a state on their own.
#[test]
fn the_bus_state_ladder_decodes_from_the_controller_status_octet() {
    /// One frame with `CAN_ERR_CRTL` set and `status` in `data[1]`.
    fn crtl(status: u8) -> CanFrame {
        let mut bytes = vec![0u8; CAN_MTU];
        // CAN_ERR_CRTL = 0x004
        bytes[0..4].copy_from_slice(&(CAN_ERR_FLAG | 0x0000_0004).to_le_bytes());
        bytes[4] = 8;
        bytes[9] = status; // data[1] is at offset 8 + 1
        CanFrame::from_wire_bytes(&bytes).unwrap()
    }

    // CAN_ERR_CRTL_RX_WARNING = 0x04, TX_WARNING = 0x08
    assert_eq!(crtl(0x04).bus_state(), Some(BusState::ErrorWarning));
    assert_eq!(crtl(0x08).bus_state(), Some(BusState::ErrorWarning));
    // CAN_ERR_CRTL_RX_PASSIVE = 0x10, TX_PASSIVE = 0x20 — and passive outranks warning.
    assert_eq!(crtl(0x10).bus_state(), Some(BusState::ErrorPassive));
    assert_eq!(crtl(0x20).bus_state(), Some(BusState::ErrorPassive));
    assert_eq!(crtl(0x24).bus_state(), Some(BusState::ErrorPassive));
    // CAN_ERR_CRTL_ACTIVE = 0x40 — back to normal.
    assert_eq!(crtl(0x40).bus_state(), Some(BusState::ErrorActive));
    // An overflow is a real problem but not a confinement state.
    assert_eq!(crtl(0x01).bus_state(), None);

    // CAN_ERR_BUSOFF = 0x040 in the identifier: the controller has left the bus.
    let mut bytes = vec![0u8; CAN_MTU];
    bytes[0..4].copy_from_slice(&(CAN_ERR_FLAG | 0x0000_0040).to_le_bytes());
    bytes[4] = 8;
    let busoff = CanFrame::from_wire_bytes(&bytes).unwrap();
    assert_eq!(busoff.bus_state(), Some(BusState::BusOff));
    assert_eq!(busoff.error_classes().unwrap(), vec!["bus_off"]);

    // CAN_ERR_RESTARTED = 0x100: the controller came back.
    let mut bytes = vec![0u8; CAN_MTU];
    bytes[0..4].copy_from_slice(&(CAN_ERR_FLAG | 0x0000_0100).to_le_bytes());
    bytes[4] = 8;
    let restarted = CanFrame::from_wire_bytes(&bytes).unwrap();
    assert_eq!(restarted.bus_state(), Some(BusState::ErrorActive));

    assert_eq!(BusState::ErrorActive.as_str(), "error_active");
    assert_eq!(BusState::ErrorWarning.as_str(), "error_warning");
    assert_eq!(BusState::ErrorPassive.as_str(), "error_passive");
    assert_eq!(BusState::BusOff.as_str(), "bus_off");
}

/// A data frame reports no error classes and no bus state at all.
#[test]
fn a_data_frame_reports_no_error_information() {
    let frame = CanFrame::classic(0x100, false, vec![0x01]).unwrap();
    assert!(frame.error_classes().is_none());
    assert!(frame.bus_state().is_none());
    let data = frame.to_event_data();
    assert!(
        !data.contains_key("error_classes"),
        "absent, not null, so a script can test with a plain `in`"
    );
}

// =================================================================================================
// The action vocabulary: `encoding` is READ, never sniffed
// =================================================================================================

/// The declared default is hex, and the executor really decodes it.
///
/// This is the `send_tcp_data` defect the root `CLAUDE.md` records: documented as hex in three
/// places, executed with `as_bytes()`, so a model following the documentation put literal ASCII
/// on the wire.
#[test]
fn hex_is_the_default_and_it_is_really_decoded() {
    let frame = CanFrame::from_action(&json!({
        "type": "send_can_frame",
        "id": "0x7E8",
        "data": "0341050f"
    }))
    .expect("hex is the default encoding for CAN payloads");

    assert_eq!(
        frame.data,
        vec![0x03, 0x41, 0x05, 0x0F],
        "four decoded octets, not eight ASCII characters"
    );
    assert_eq!(frame.data.len(), 4);
}

/// `"text"` means the characters, and it produces *different bytes* from the same string read as
/// hex. That difference is the whole point of the field.
#[test]
fn text_and_hex_are_different_encodings_of_the_same_string() {
    let as_hex = CanFrame::from_action(&json!({
        "type": "send_can_frame", "id": "0x100", "data": "48656c6c6f", "encoding": "hex"
    }))
    .unwrap();
    assert_eq!(as_hex.data, b"Hello".to_vec());

    let as_text = CanFrame::from_action(&json!({
        "type": "send_can_frame", "id": "0x100", "data": "48656c", "encoding": "text"
    }))
    .unwrap();
    assert_eq!(
        as_text.data,
        b"48656c".to_vec(),
        "as text, the characters themselves"
    );

    // Both are valid readings of the same characters; only the sender knows which was meant,
    // which is exactly why nothing here sniffs.
    assert_ne!(
        CanFrame::from_action(&json!({
            "type": "send_can_frame", "id": "0x100", "data": "48656c", "encoding": "hex"
        }))
        .unwrap()
        .data,
        as_text.data
    );
}

/// Hex that is not hex is refused, and the message names the way out.
#[test]
fn invalid_hex_is_refused_with_the_alternative_named() {
    let err = CanFrame::from_action(&json!({
        "type": "send_can_frame", "id": "0x100", "data": "HELLO"
    }))
    .expect_err("HELLO is not hex")
    .to_string();
    assert!(err.contains("not valid hex"), "got: {err}");
    assert!(
        err.contains("\"encoding\": \"text\""),
        "the alternative must be named: {err}"
    );

    let err = CanFrame::from_action(&json!({
        "type": "send_can_frame", "id": "0x100", "data": "00", "encoding": "base64"
    }))
    .expect_err("base64 is not offered")
    .to_string();
    assert!(err.contains("unknown encoding"), "got: {err}");
}

/// The notations a CAN identifier is actually written in all mean the same identifier.
#[test]
fn identifiers_parse_from_every_notation_a_can_document_uses() {
    for id in [json!("0x7DF"), json!("7DF"), json!("0X7df"), json!(2015)] {
        let frame = CanFrame::from_action(&json!({
            "type": "send_can_frame", "id": id, "data": ""
        }))
        .unwrap_or_else(|e| panic!("{id} should parse: {e}"));
        assert_eq!(frame.id, 0x7DF, "{id} is 0x7DF");
    }

    // A bare string is hex, because that is the universal notation for a CAN identifier.
    // Reading "0700" as seven hundred decimal would address a different ECU.
    let frame = CanFrame::from_action(&json!({
        "type": "send_can_frame", "id": "0700", "data": ""
    }))
    .unwrap();
    assert_eq!(frame.id, 0x700);
}

/// A script handler naturally produces a byte array; refusing it would push authors into
/// hand-encoding hex.
#[test]
fn a_byte_array_payload_is_accepted_and_bounds_checked() {
    let frame = CanFrame::from_action(&json!({
        "type": "send_can_frame", "id": "0x100", "data": [1, 2, 255]
    }))
    .unwrap();
    assert_eq!(frame.data, vec![1, 2, 255]);

    let err = CanFrame::from_action(&json!({
        "type": "send_can_frame", "id": "0x100", "data": [256]
    }))
    .expect_err("256 is not a byte")
    .to_string();
    assert!(err.contains("must be 0-255"), "got: {err}");
}

/// A zero-length frame is legal CAN, and omitting `data` is how you write one.
#[test]
fn an_absent_payload_is_a_zero_length_frame() {
    let frame = CanFrame::from_action(&json!({"type": "send_can_frame", "id": "0x100"})).unwrap();
    assert!(frame.data.is_empty());
    assert_eq!(frame.dlc(), 0);
    assert_eq!(frame.to_wire_bytes().unwrap()[4], 0);
}

/// `id` is the one thing that cannot be defaulted.
#[test]
fn an_action_without_an_identifier_is_refused() {
    let err = CanFrame::from_action(&json!({"type": "send_can_frame", "data": "00"}))
        .expect_err("a CAN frame without an identifier is not a frame")
        .to_string();
    assert!(err.contains("requires 'id'"), "got: {err}");
}

/// The description shown in the log distinguishes the four frame shapes.
#[test]
fn describe_names_the_frame_shape() {
    assert_eq!(
        CanFrame::classic(0x7E8, false, vec![0x03, 0x41])
            .unwrap()
            .describe(),
        "CAN 0x7E8 dlc=2 0341"
    );
    assert_eq!(
        CanFrame::remote(0x123, false, 4).unwrap().describe(),
        "RTR 0x123 dlc=4 (no data)"
    );
    assert_eq!(
        CanFrame::fd(0x456, false, vec![0u8; 16], true)
            .unwrap()
            .describe(),
        format!("FD/BRS 0x456 dlc=10 {}", "00".repeat(16))
    );
    assert_eq!(
        CanFrame::classic(0x18DA_F110, true, vec![])
            .unwrap()
            .id_hex(),
        "0x18DAF110",
        "an extended identifier is written to its full width"
    );
}

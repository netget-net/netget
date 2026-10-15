//! `LineCoding::from_bytes` is total: a short payload returns `None`, it does not panic.
//!
//! It is `pub`, it takes an arbitrary `&[u8]`, and it used to index `bytes[0..6]` with no
//! length check — relying entirely on its single call site in `usb/serial/handler.rs` guarding
//! with `req.len() >= 7`. The payload is a SET_LINE_CODING body, so its length is chosen by the
//! USB host rather than by us; the defect was latent, one new caller away.
//!
//! It is also the kind of panic that hides. `handle_urb` runs inside a `tokio::spawn`ed
//! connection task, and a panic there is swallowed by the task: the server stays `Running`, the
//! log shows the control transfer succeeding, and the peer hangs. (`src/panic_log.rs` now
//! writes such a panic to `netget.log`, which makes it findable rather than silent — but
//! findable is not fixed.)
//!
//! Both directions are asserted: every short length refuses, and a well-formed payload still
//! decodes exactly, little-endian baud rate included. A guard that returned `None` for
//! everything would satisfy the first half alone.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features usb-serial \
//!       --test server -- usb_serial::line_coding --test-threads=100

#![cfg(all(unix, feature = "libusb"))]

use netget::server::usb::descriptors::LineCoding;

/// 115200 8N1, little-endian: 0x0001C200.
const NINE_SIX_HUNDRED: [u8; 7] = [0x80, 0x25, 0x00, 0x00, 0x02, 0x01, 0x07];

/// Every length the wire can present below the structure's size must refuse, not panic.
///
/// Zero is the one that matters most: a control OUT with an empty data stage is trivial to
/// send and used to index `bytes[0]`.
#[test]
fn a_payload_shorter_than_the_structure_returns_none() {
    let full = [0x00u8, 0xC2, 0x01, 0x00, 0x00, 0x00, 0x08];
    for len in 0..LineCoding::WIRE_LEN {
        assert!(
            LineCoding::from_bytes(&full[..len]).is_none(),
            "a {len}-octet SET_LINE_CODING payload must refuse, not index past its end"
        );
    }
}

/// **The control.** A well-formed payload still decodes, field for field.
#[test]
fn a_well_formed_payload_still_decodes() {
    // 115200 = 0x0001C200, little-endian; 1 stop bit, no parity, 8 data bits.
    let coding = LineCoding::from_bytes(&[0x00, 0xC2, 0x01, 0x00, 0x00, 0x00, 0x08])
        .expect("seven octets is a complete line coding");
    assert_eq!(coding.baud_rate, 115_200);
    assert_eq!(coding.stop_bits, 0);
    assert_eq!(coding.parity, 0);
    assert_eq!(coding.data_bits, 8);

    // 9600 = 0x00002580; 2 stop bits, odd parity, 7 data bits.
    let other =
        LineCoding::from_bytes(&NINE_SIX_HUNDRED).expect("seven octets is a complete line coding");
    assert_eq!(other.baud_rate, 9_600);
    assert_eq!(other.stop_bits, 2);
    assert_eq!(other.parity, 1);
    assert_eq!(other.data_bits, 7);
}

/// A longer payload is accepted and the trailing octets are ignored, which is what a device
/// does with a data stage carrying more than the structure it asked for.
#[test]
fn a_longer_payload_reads_only_the_structure() {
    let mut padded = NINE_SIX_HUNDRED.to_vec();
    padded.extend_from_slice(&[0xFF; 9]);
    let coding = LineCoding::from_bytes(&padded).expect("a longer payload still contains all 7");
    assert_eq!(coding.baud_rate, 9_600);
    assert_eq!(coding.data_bits, 7);
}

/// `to_bytes` and `from_bytes` are inverses, so the guard did not change what is decoded.
#[test]
fn the_round_trip_is_unchanged() {
    let original = LineCoding::default_115200_8n1();
    let bytes = original.to_bytes();
    assert_eq!(bytes.len(), LineCoding::WIRE_LEN);
    let back = LineCoding::from_bytes(&bytes).expect("to_bytes always produces a full structure");
    assert_eq!(back.baud_rate, original.baud_rate);
    assert_eq!(back.stop_bits, original.stop_bits);
    assert_eq!(back.parity, original.parity);
    assert_eq!(back.data_bits, original.data_bits);
}

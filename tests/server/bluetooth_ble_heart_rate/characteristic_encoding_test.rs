//! `encode_heart_rate` against the Bluetooth SIG Heart Rate Service layout.
//!
//! Heart Rate Measurement (0x2A37) is a mandatory 8-bit Flags octet followed by the measurement
//! value, and **flags bit 0 selects the value's type**: 0 for a one-octet `uint8`, 1 for a
//! two-octet little-endian `uint16` (Heart Rate Service 1.0, section 3.1). The bit and the width
//! have to agree, which is why the encoder chooses them together rather than taking the bit from
//! its caller.
//!
//! No Bluetooth adapter needed, so this is not ignored.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::server::bluetooth_ble_heart_rate::encode_heart_rate;

/// `encode_heart_rate` picks the flags bit and the field width together, because a caller
/// choosing them separately is how they come to disagree.
#[test]
fn encode_heart_rate_picks_the_format_bit_to_match_the_field_width() {
    // uint8 format: flags bit 0 clear, one value octet.
    assert_eq!(encode_heart_rate(72), vec![0x00, 0x48]);
    assert_eq!(encode_heart_rate(0), vec![0x00, 0x00]);
    assert_eq!(
        encode_heart_rate(255),
        vec![0x00, 0xFF],
        "255 still fits a uint8"
    );

    // uint16 format: flags bit 0 set, two value octets, little-endian. 0x0100 = 256 must not
    // come back as `00 01` (big-endian) or `01 00` (the low octet alone).
    assert_eq!(encode_heart_rate(256), vec![0x01, 0x00, 0x01]);
    assert_eq!(
        encode_heart_rate(0x1234),
        vec![0x01, 0x34, 0x12],
        "GATT is little-endian"
    );

    // No clamp. This was `bpm.clamp(30, 220)`, which answered 25 with 30 and 250 with 220 —
    // a caller's obvious error rewritten into a believable claim about a human heart.
    assert_eq!(
        encode_heart_rate(25),
        vec![0x00, 25],
        "25 BPM must not become 30"
    );
    assert_eq!(
        encode_heart_rate(250),
        vec![0x00, 250],
        "250 BPM must not become 220"
    );
}

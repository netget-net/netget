//! `encode_battery_level` against the Bluetooth SIG Battery Service layout.
//!
//! Battery Level (0x2A19) is a single `uint8` carrying a **percentage**; Battery Service 1.0
//! section 3.1 defines 0 to 100 and reserves every other value. That makes it the one field where
//! clamping is least survivable: every out-of-range input lands on a perfectly ordinary reading,
//! so a caller's obvious mistake becomes an unfalsifiable claim about a device's charge.
//!
//! No Bluetooth adapter needed, so this is not ignored.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::server::bluetooth_ble_battery::encode_battery_level;

/// `encode_battery_level` is the encoder for that same octet, and it must refuse what it
/// cannot honestly represent rather than clamping it into a plausible reading.
#[test]
fn encode_battery_level_refuses_a_value_that_is_not_a_percentage() {
    assert_eq!(encode_battery_level(0).unwrap(), [0x00]);
    assert_eq!(encode_battery_level(75).unwrap(), [0x4B], "75% is 0x4B");
    assert_eq!(encode_battery_level(100).unwrap(), [0x64]);

    // The whole point: 200 must not become a confident 100. `level.min(100)` did exactly
    // that, and a clamped percentage is indistinguishable from a real full battery.
    for over in [101u8, 200, 255] {
        let err = encode_battery_level(over).expect_err(
            "a value above 100 has no honest Battery Level encoding and must be refused",
        );
        assert!(
            err.to_string().contains(&over.to_string()),
            "the refusal should name the offending value, said: {err}"
        );
    }
}

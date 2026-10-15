//! BLE UUID shorthand expansion.
//!
//! Every example in `src/server/bluetooth_ble/actions.rs` and its CLAUDE.md uses the
//! Bluetooth SIG 16-bit shorthand (`180D` for Heart Rate, `2A37` for its measurement
//! characteristic), and the docs stated it was "expanded to" the 128-bit form. Nothing
//! expanded it, and `Uuid::parse_str("180D")` fails — so a model copying the protocol's
//! own documented example got `Invalid service UUID`.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::server::bluetooth_ble::parse_ble_uuid;

/// The base UUID all Bluetooth SIG short identifiers expand into.
fn base(short32: &str) -> String {
    format!("{short32}-0000-1000-8000-00805f9b34fb")
}

#[test]
fn expands_the_16_bit_shorthand_the_docs_promise() {
    // The exact values used in the protocol's own action examples.
    for (short, expect32) in [
        ("180D", "0000180d"),
        ("2A37", "00002a37"),
        ("180F", "0000180f"),
    ] {
        let got = parse_ble_uuid(short).expect("documented shorthand must parse");
        assert_eq!(got.to_string(), base(expect32), "expanding {short}");
    }
}

#[test]
fn shorthand_is_case_insensitive() {
    assert_eq!(
        parse_ble_uuid("180d").unwrap(),
        parse_ble_uuid("180D").unwrap()
    );
}

#[test]
fn expands_the_32_bit_shorthand() {
    let got = parse_ble_uuid("0000180D").expect("32-bit shorthand must parse");
    assert_eq!(got.to_string(), base("0000180d"));
}

#[test]
fn a_full_128_bit_uuid_round_trips_unchanged() {
    let full = "0000180d-0000-1000-8000-00805f9b34fb";
    assert_eq!(parse_ble_uuid(full).unwrap().to_string(), full);
}

#[test]
fn a_custom_128_bit_uuid_is_not_rewritten() {
    // A vendor-specific UUID must survive verbatim — expansion applies only to
    // the short forms, never to something that already is a full UUID.
    let custom = "12345678-1234-5678-1234-567812345678";
    assert_eq!(parse_ble_uuid(custom).unwrap().to_string(), custom);
}

#[test]
fn surrounding_whitespace_is_tolerated() {
    assert_eq!(
        parse_ble_uuid("  180D  ").unwrap().to_string(),
        base("0000180d")
    );
}

#[test]
fn garbage_is_rejected_with_a_message_naming_the_input() {
    // Not hex, and not a UUID: must fail rather than silently expand to something.
    let err = parse_ble_uuid("ZZZZ").expect_err("non-hex must be rejected");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("ZZZZ"),
        "error should name the input, got: {msg}"
    );

    // Wrong length for a shorthand and not a valid UUID either.
    assert!(
        parse_ble_uuid("180").is_err(),
        "3 hex digits is not a valid shorthand"
    );
    assert!(parse_ble_uuid("").is_err(), "empty input must be rejected");
}

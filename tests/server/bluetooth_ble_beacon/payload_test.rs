//! Beacon advertising payload tests.
//!
//! This is the part of `bluetooth-ble-beacon` that can be verified without a Bluetooth adapter,
//! a Linux host or a D-Bus daemon, so it is verified hard: every expected byte string below is
//! written out literally, derived from the published layout rather than from the implementation.
//!
//! Sources for the expected bytes:
//!
//! - iBeacon: Apple, "Getting Started with iBeacon" (2014), §2.1. The advertisement is
//!   `1A FF 4C 00 02 15` followed by the 16-byte proximity UUID, big-endian major, big-endian
//!   minor and the signed measured power.
//! - Eddystone: <https://github.com/google/eddystone>, `eddystone-uid/README.md` and
//!   `eddystone-url/README.md`, including the scheme-prefix and HTTP-URL encoding tables.
//! - AD structure framing and the 31-octet limit: Bluetooth Core Specification Supplement,
//!   Part A, §1.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::server::bluetooth_ble_beacon::actions::{
    frame_from_action, BluetoothBleBeaconProtocol, BEACON_STARTED_EVENT,
};
use netget::server::bluetooth_ble_beacon::payload::{
    eddystone_uid_service_data, eddystone_url_service_data, encode_eddystone_url,
    ibeacon_manufacturer_data, parse_uuid128, BeaconFrame, PayloadError, APPLE_COMPANY_ID,
    EDDYSTONE_SERVICE_UUID16, MAX_ADVERTISING_PAYLOAD,
};

/// Apple's own example proximity UUID, used throughout the iBeacon documentation.
const APPLE_EXAMPLE_UUID: &str = "e2c56db5-dffb-48d2-b060-d0f5a71096e0";
const APPLE_EXAMPLE_UUID_BYTES: [u8; 16] = [
    0xE2, 0xC5, 0x6D, 0xB5, 0xDF, 0xFB, 0x48, 0xD2, 0xB0, 0x60, 0xD0, 0xF5, 0xA7, 0x10, 0x96, 0xE0,
];

// ---------------------------------------------------------------------------------------------
// iBeacon
// ---------------------------------------------------------------------------------------------

#[test]
fn ibeacon_manufacturer_data_matches_apple_layout() {
    let data = ibeacon_manufacturer_data(&APPLE_EXAMPLE_UUID_BYTES, 1, 100, -59);

    // 02 15 | UUID (16) | major (2, BE) | minor (2, BE) | measured power (1, signed)
    let expected: Vec<u8> = vec![
        0x02, 0x15, // iBeacon sub-type and its 21-octet length
        0xE2, 0xC5, 0x6D, 0xB5, 0xDF, 0xFB, 0x48, 0xD2, 0xB0, 0x60, 0xD0, 0xF5, 0xA7, 0x10, 0x96,
        0xE0, // proximity UUID
        0x00, 0x01, // major = 1
        0x00, 0x64, // minor = 100
        0xC5, // measured power = -59 dBm
    ];

    assert_eq!(data, expected);
    assert_eq!(data.len(), 23, "iBeacon manufacturer data is 23 octets");
}

#[test]
fn ibeacon_major_and_minor_are_big_endian() {
    // 0x1234 / 0xABCD must not be byte-swapped: a little-endian slip is invisible on small
    // values like 1 and 100 and breaks every real deployment.
    let data = ibeacon_manufacturer_data(&APPLE_EXAMPLE_UUID_BYTES, 0x1234, 0xABCD, -12);
    assert_eq!(&data[18..20], &[0x12, 0x34]);
    assert_eq!(&data[20..22], &[0xAB, 0xCD]);
    assert_eq!(data[22], 0xF4, "-12 dBm is 0xF4 as a signed octet");
}

#[test]
fn ibeacon_full_advertising_data_matches_apple_layout() {
    let frame = BeaconFrame::ibeacon(APPLE_EXAMPLE_UUID, 1, 100, -59).expect("valid iBeacon");

    let expected: Vec<u8> = vec![
        0x02, 0x01, 0x06, // flags: LE General Discoverable, BR/EDR not supported
        0x1A, 0xFF, // 26 octets of manufacturer specific data
        0x4C, 0x00, // company 0x004C (Apple), little-endian on the wire
        0x02, 0x15, // iBeacon sub-type and length
        0xE2, 0xC5, 0x6D, 0xB5, 0xDF, 0xFB, 0x48, 0xD2, 0xB0, 0x60, 0xD0, 0xF5, 0xA7, 0x10, 0x96,
        0xE0, 0x00, 0x01, 0x00, 0x64, 0xC5,
    ];

    assert_eq!(frame.advertising_data(), expected);
    assert_eq!(
        frame.advertising_data().len(),
        30,
        "an iBeacon fills 30 of the 31 available octets"
    );
}

#[test]
fn ibeacon_uses_manufacturer_data_only() {
    let frame = BeaconFrame::ibeacon(APPLE_EXAMPLE_UUID, 1, 100, -59).unwrap();
    let (company, data) = frame.manufacturer_data().expect("iBeacon has mfg data");
    assert_eq!(company, APPLE_COMPANY_ID);
    assert_eq!(data.len(), 23);
    assert!(
        frame.service_data().is_none(),
        "an iBeacon carries no service data"
    );
    assert!(
        frame.service_uuids16().is_empty(),
        "an iBeacon advertises no service UUIDs"
    );
}

#[test]
fn ibeacon_leaves_no_room_for_a_device_name() {
    let frame = BeaconFrame::ibeacon(APPLE_EXAMPLE_UUID, 1, 100, -59).unwrap();
    // 31 - 30 = 1 octet spare, and a local-name AD structure costs 2 before any characters.
    assert_eq!(frame.local_name_budget(), 0);
    assert_eq!(frame.fit_local_name("NetGet-Beacon"), None);
    assert_eq!(
        frame.advertising_data_with_name("NetGet-Beacon"),
        frame.advertising_data(),
        "the name must be dropped, not overflow the payload"
    );
}

// ---------------------------------------------------------------------------------------------
// Eddystone-UID
// ---------------------------------------------------------------------------------------------

#[test]
fn eddystone_uid_service_data_matches_spec_layout() {
    let namespace: [u8; 10] = [0xED, 0xD1, 0xEB, 0xEA, 0xC0, 0x4E, 0x5D, 0xEF, 0xA0, 0x17];
    let instance: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    let data = eddystone_uid_service_data(&namespace, &instance, -20);

    let expected: Vec<u8> = vec![
        0x00, // frame type: UID
        0xEC, // ranging data: -20 dBm
        0xED, 0xD1, 0xEB, 0xEA, 0xC0, 0x4E, 0x5D, 0xEF, 0xA0, 0x17, // namespace
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // instance
        0x00, 0x00, // RFU
    ];

    assert_eq!(data, expected);
    assert_eq!(data.len(), 20, "Eddystone-UID service data is 20 octets");
}

#[test]
fn eddystone_uid_full_advertising_data_matches_spec_layout() {
    let frame = BeaconFrame::eddystone_uid("edd1ebeac04e5defa017", "000000000001", -20)
        .expect("valid Eddystone-UID");

    let expected: Vec<u8> = vec![
        0x02, 0x01, 0x06, // flags
        0x03, 0x03, 0xAA, 0xFE, // complete list of 16-bit UUIDs: 0xFEAA, little-endian
        0x17, 0x16, 0xAA, 0xFE, // 23-octet service data for 0xFEAA
        0x00, 0xEC, // frame type UID, -20 dBm
        0xED, 0xD1, 0xEB, 0xEA, 0xC0, 0x4E, 0x5D, 0xEF, 0xA0, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00,
    ];

    assert_eq!(frame.advertising_data(), expected);
    assert_eq!(
        frame.advertising_data().len(),
        MAX_ADVERTISING_PAYLOAD,
        "Eddystone-UID uses the whole 31-octet payload exactly"
    );
    assert_eq!(frame.local_name_budget(), 0);
}

#[test]
fn eddystone_uid_accepts_a_uuid_namespace() {
    // The spec allows deriving a namespace from the first 10 bytes of a UUID.
    let from_uuid = BeaconFrame::eddystone_uid(APPLE_EXAMPLE_UUID, "0102030405AB", -20).unwrap();
    let from_hex = BeaconFrame::eddystone_uid("e2c56db5dffb48d2b060", "0102030405ab", -20).unwrap();
    assert_eq!(from_uuid, from_hex);

    match from_uuid {
        BeaconFrame::EddystoneUid { instance, .. } => {
            assert_eq!(instance, [0x01, 0x02, 0x03, 0x04, 0x05, 0xAB]);
        }
        other => panic!("expected an Eddystone-UID frame, got {other:?}"),
    }
}

#[test]
fn eddystone_uid_rejects_wrong_length_identifiers() {
    // 18 hex digits is 9 bytes, not 10.
    let err = BeaconFrame::eddystone_uid("edd1ebeac04e5defa0", "000000000001", -20).unwrap_err();
    assert!(
        matches!(
            err,
            PayloadError::InvalidHexId {
                field: "namespace",
                expected_bytes: 10,
                ..
            }
        ),
        "expected a namespace length complaint, got {err}"
    );

    let err = BeaconFrame::eddystone_uid("edd1ebeac04e5defa017", "00000001", -20).unwrap_err();
    assert!(
        matches!(
            err,
            PayloadError::InvalidHexId {
                field: "instance",
                expected_bytes: 6,
                ..
            }
        ),
        "expected an instance length complaint, got {err}"
    );

    // Non-hex is rejected rather than silently zero-filled.
    let err = BeaconFrame::eddystone_uid("zzd1ebeac04e5defa017", "000000000001", -20).unwrap_err();
    assert!(matches!(err, PayloadError::InvalidHexId { .. }), "{err}");
}

// ---------------------------------------------------------------------------------------------
// Eddystone-URL
// ---------------------------------------------------------------------------------------------

#[test]
fn eddystone_url_encodes_scheme_and_suffix_tables() {
    // https:// -> 0x03, and ".com/" collapses to a single 0x00 octet.
    let (scheme, encoded) = encode_eddystone_url("https://example.com/").unwrap();
    assert_eq!(scheme, 0x03);
    assert_eq!(
        encoded,
        vec![b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00]
    );

    // All four scheme prefixes, longest-first so "http://www." is not read as "http://".
    assert_eq!(encode_eddystone_url("http://www.a.com").unwrap().0, 0x00);
    assert_eq!(encode_eddystone_url("https://www.a.com").unwrap().0, 0x01);
    assert_eq!(encode_eddystone_url("http://a.com").unwrap().0, 0x02);
    assert_eq!(encode_eddystone_url("https://a.com").unwrap().0, 0x03);

    // Every suffix code, in the spec's order.
    let cases: [(&str, u8); 14] = [
        (".com/", 0x00),
        (".org/", 0x01),
        (".edu/", 0x02),
        (".net/", 0x03),
        (".info/", 0x04),
        (".biz/", 0x05),
        (".gov/", 0x06),
        (".com", 0x07),
        (".org", 0x08),
        (".edu", 0x09),
        (".net", 0x0A),
        (".info", 0x0B),
        (".biz", 0x0C),
        (".gov", 0x0D),
    ];
    for (suffix, code) in cases {
        let url = format!("https://a{suffix}");
        let (_, encoded) = encode_eddystone_url(&url).unwrap();
        assert_eq!(encoded, vec![b'a', code], "encoding {url}");
    }
}

#[test]
fn eddystone_url_full_advertising_data_matches_spec_layout() {
    let frame = BeaconFrame::eddystone_url("https://example.com/", -20).expect("valid URL");

    let expected: Vec<u8> = vec![
        0x02, 0x01, 0x06, // flags
        0x03, 0x03, 0xAA, 0xFE, // complete list of 16-bit UUIDs: 0xFEAA
        0x0E, 0x16, 0xAA, 0xFE, // 14-octet service data for 0xFEAA
        0x10, // frame type: URL
        0xEC, // TX power: -20 dBm
        0x03, // scheme: https://
        b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00, // "example" + ".com/"
    ];

    assert_eq!(frame.advertising_data(), expected);
    assert_eq!(frame.advertising_data().len(), 22);

    let (uuid16, service_data) = frame.service_data().expect("URL frame has service data");
    assert_eq!(uuid16, EDDYSTONE_SERVICE_UUID16);
    assert_eq!(
        service_data,
        eddystone_url_service_data(0x03, &[b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00], -20)
    );
    assert!(frame.manufacturer_data().is_none());
}

#[test]
fn eddystone_url_leaves_room_for_a_truncated_device_name() {
    let frame = BeaconFrame::eddystone_url("https://example.com/", -20).unwrap();
    // 31 - 22 = 9 octets spare, minus the 2-octet AD header.
    assert_eq!(frame.local_name_budget(), 7);
    assert_eq!(frame.fit_local_name("NetGet-Beacon"), Some("NetGet-"));
    assert_eq!(frame.fit_local_name("Bcn"), Some("Bcn"));

    let with_name = frame.advertising_data_with_name("NetGet-Beacon");
    assert_eq!(
        with_name.len(),
        MAX_ADVERTISING_PAYLOAD,
        "a truncated name must fill the payload exactly, never overflow it"
    );
    assert_eq!(
        &with_name[22..],
        &[0x08, 0x08, b'N', b'e', b't', b'G', b'e', b't', b'-'],
        "shortened local name AD structure"
    );

    // A name that fits whole is marked complete (0x09) rather than shortened (0x08).
    let short = frame.advertising_data_with_name("Bcn");
    assert_eq!(&short[22..], &[0x04, 0x09, b'B', b'c', b'n']);
}

#[test]
fn eddystone_url_name_truncation_is_char_safe() {
    let frame = BeaconFrame::eddystone_url("https://example.com/", -20).unwrap();
    // 7 octets of budget cuts through the third 3-byte character; the cut must land on a
    // boundary rather than panicking or emitting invalid UTF-8.
    let fitted = frame.fit_local_name("日本語ビーコン").unwrap();
    assert_eq!(fitted, "日本");
    assert!(fitted.len() <= 7);
}

#[test]
fn eddystone_url_rejects_what_it_cannot_encode() {
    let err = BeaconFrame::eddystone_url("ftp://example.com/", -20).unwrap_err();
    assert!(
        matches!(err, PayloadError::UnsupportedUrlScheme(_)),
        "{err}"
    );

    // 18 encoded octets: one over the 17-octet budget.
    let err = BeaconFrame::eddystone_url("https://abcdefghijklmnopqr", -20).unwrap_err();
    assert!(
        matches!(err, PayloadError::UrlTooLong { encoded_len: 18 }),
        "{err}"
    );

    // Exactly 17 is accepted, which pins the boundary rather than assuming it.
    let ok = BeaconFrame::eddystone_url("https://abcdefghijklmnopq", -20).unwrap();
    assert_eq!(ok.advertising_data().len(), MAX_ADVERTISING_PAYLOAD);

    let err = BeaconFrame::eddystone_url("https://exa mple.com/", -20).unwrap_err();
    assert!(
        matches!(err, PayloadError::UrlUnencodableCharacter(' ')),
        "{err}"
    );

    let err = BeaconFrame::eddystone_url("https://exämple.com/", -20).unwrap_err();
    assert!(
        matches!(err, PayloadError::UrlUnencodableCharacter('ä')),
        "{err}"
    );
}

#[test]
fn eddystone_url_encoder_does_not_slice_through_a_multibyte_character() {
    // The suffix table is matched by comparing the next `n` bytes of the remaining URL. With a
    // byte-index slice, "aaaaä" panics: `.com/` is 5 bytes long and byte 5 falls inside the
    // two-byte 'ä'. The character is unencodable and must be *reported*, not crashed on.
    for url in [
        "https://aaaaäb",
        "https://aaaaaä",
        "https://a\u{1F600}",
        "https://\u{1F600}.com/",
    ] {
        let err = BeaconFrame::eddystone_url(url, -20)
            .expect_err("non-ASCII cannot be encoded and must be refused, not panic");
        assert!(
            matches!(err, PayloadError::UrlUnencodableCharacter(_)),
            "{url}: {err}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Structured action parameters -> frames
// ---------------------------------------------------------------------------------------------

#[test]
fn actions_carry_structured_fields_not_bytes() {
    // Everything the model produces is a UUID string, an integer or a URL. Nothing here is a
    // byte blob, and the protocol - not the model - builds the octets.
    let frame = frame_from_action(&serde_json::json!({
        "type": "start_ibeacon",
        "uuid": APPLE_EXAMPLE_UUID,
        "major": 1,
        "minor": 100,
        "measured_power": -59
    }))
    .unwrap()
    .unwrap();
    assert_eq!(
        frame,
        BeaconFrame::ibeacon(APPLE_EXAMPLE_UUID, 1, 100, -59).unwrap()
    );

    let frame = frame_from_action(&serde_json::json!({
        "type": "start_eddystone_uid",
        "namespace": "edd1ebeac04e5defa017",
        "instance": "000000000001"
    }))
    .unwrap()
    .unwrap();
    assert_eq!(
        frame,
        BeaconFrame::eddystone_uid("edd1ebeac04e5defa017", "000000000001", -20).unwrap(),
        "tx_power defaults to -20 dBm"
    );

    let frame = frame_from_action(&serde_json::json!({
        "type": "start_eddystone_url",
        "url": "https://example.com/"
    }))
    .unwrap()
    .unwrap();
    assert_eq!(
        frame,
        BeaconFrame::eddystone_url("https://example.com/", -20).unwrap()
    );

    // stop_beacon names no frame.
    assert!(
        frame_from_action(&serde_json::json!({"type": "stop_beacon"}))
            .unwrap()
            .is_none()
    );
}

#[test]
fn actions_default_measured_power_to_the_ibeacon_convention() {
    let frame = frame_from_action(&serde_json::json!({
        "type": "start_ibeacon",
        "uuid": APPLE_EXAMPLE_UUID,
        "major": 0,
        "minor": 0
    }))
    .unwrap()
    .unwrap();
    // -59 dBm at 1 m is the value Apple's calibration procedure produces for most hardware.
    assert_eq!(frame.advertising_data().last(), Some(&0xC5));
}

#[test]
fn actions_reject_malformed_input_rather_than_broadcasting_garbage() {
    // Unknown action name.
    assert!(frame_from_action(&serde_json::json!({"type": "start_altbeacon"})).is_err());
    // Missing required field.
    assert!(frame_from_action(&serde_json::json!({"type": "start_ibeacon", "major": 1})).is_err());
    // Out-of-range major.
    assert!(frame_from_action(&serde_json::json!({
        "type": "start_ibeacon",
        "uuid": APPLE_EXAMPLE_UUID,
        "major": 70000,
        "minor": 0
    }))
    .is_err());
    // Malformed UUID.
    assert!(frame_from_action(&serde_json::json!({
        "type": "start_ibeacon",
        "uuid": "not-a-uuid",
        "major": 1,
        "minor": 1
    }))
    .is_err());
}

#[test]
fn uuid_parsing_accepts_the_forms_a_model_actually_writes() {
    assert_eq!(
        parse_uuid128(APPLE_EXAMPLE_UUID).unwrap(),
        APPLE_EXAMPLE_UUID_BYTES
    );
    assert_eq!(
        parse_uuid128("E2C56DB5DFFB48D2B060D0F5A71096E0").unwrap(),
        APPLE_EXAMPLE_UUID_BYTES
    );
    assert_eq!(
        parse_uuid128("  e2c56db5-dffb-48d2-b060-d0f5a71096e0  ").unwrap(),
        APPLE_EXAMPLE_UUID_BYTES
    );
    assert!(parse_uuid128("e2c56db5-dffb-48d2-b060").is_err());
}

// ---------------------------------------------------------------------------------------------
// Declaration invariants
// ---------------------------------------------------------------------------------------------

#[test]
fn every_frame_fits_the_advertising_budget() {
    let frames = [
        BeaconFrame::ibeacon(APPLE_EXAMPLE_UUID, 0xFFFF, 0xFFFF, -127).unwrap(),
        BeaconFrame::eddystone_uid("ffffffffffffffffffff", "ffffffffffff", -127).unwrap(),
        BeaconFrame::eddystone_url("https://abcdefghijklmnopq", -127).unwrap(),
        BeaconFrame::eddystone_url("http://www.a.gov/", -127).unwrap(),
    ];
    for frame in frames {
        let ad = frame.advertising_data();
        assert!(
            ad.len() <= MAX_ADVERTISING_PAYLOAD,
            "{} produced {} octets: {ad:02x?}",
            frame.kind(),
            ad.len()
        );
        let named = frame.advertising_data_with_name("NetGet-Beacon-With-A-Long-Name");
        assert!(
            named.len() <= MAX_ADVERTISING_PAYLOAD,
            "{} with a name produced {} octets",
            frame.kind(),
            named.len()
        );
    }
}

/// The `bluetooth_ble` family trap: a profile's actions are unreachable unless the event the
/// model is prompted with carries them. `call_llm` builds its tool list from
/// `event.event_type.actions`, not from `get_sync_actions()`.
#[test]
fn the_started_event_offers_the_beacon_actions() {
    let offered: Vec<&str> = BEACON_STARTED_EVENT
        .actions
        .iter()
        .map(|a| a.name.as_str())
        .collect();
    for expected in [
        "start_ibeacon",
        "start_eddystone_uid",
        "start_eddystone_url",
        "stop_beacon",
    ] {
        assert!(
            offered.contains(&expected),
            "beacon_started must offer {expected}, offers {offered:?}"
        );
    }
    assert!(!BEACON_STARTED_EVENT.has_no_usable_actions());
}

#[test]
fn every_declared_action_example_is_executable() {
    use netget::llm::actions::protocol_trait::Protocol;

    let protocol = BluetoothBleBeaconProtocol::new();
    let state = netget::state::app_state::AppState::new();
    for action in protocol.get_async_actions(&state) {
        frame_from_action(&action.example)
            .unwrap_or_else(|e| panic!("declared example for {} does not parse: {e}", action.name));
    }
    for example in std::iter::once(BEACON_STARTED_EVENT.response_example.clone())
        .chain(BEACON_STARTED_EVENT.alternative_examples.iter().cloned())
    {
        frame_from_action(&example)
            .unwrap_or_else(|e| panic!("event example {example} does not parse: {e}"));
    }
}

/// The protocol must be offered to the model now that it can actually work.
#[test]
fn the_protocol_is_experimental_and_visible_to_the_llm() {
    use netget::llm::actions::protocol_trait::Protocol;
    use netget::protocol::metadata::DevelopmentState;

    let metadata = BluetoothBleBeaconProtocol::new().metadata();
    assert_eq!(metadata.state, DevelopmentState::Experimental);
    assert!(metadata.is_available_to_llm());
}

/// On any platform that cannot set an advertising payload, opening the adapter must fail with
/// the reason rather than succeeding and broadcasting nothing.
#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn non_linux_refuses_to_start() {
    use netget::server::bluetooth_ble_beacon::advertise::{
        BeaconAdvertiser, UNSUPPORTED_PLATFORM_MESSAGE,
    };

    // `BeaconAdvertiser` wraps platform handles and is deliberately not `Debug`, so unwrap the
    // Result by hand rather than with `expect_err`.
    let message = match BeaconAdvertiser::open("NetGet-Beacon".to_string(), None).await {
        Ok(_) => panic!("a platform without advertising-payload support must refuse to open"),
        Err(e) => e.to_string(),
    };
    assert!(
        message.contains("Linux/BlueZ"),
        "the refusal must name the platform that does work: {message}"
    );
    assert_eq!(message, UNSUPPORTED_PLATFORM_MESSAGE);
}

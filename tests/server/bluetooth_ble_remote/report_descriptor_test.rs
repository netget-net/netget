//! The BLE media remote's report descriptor, its bit assignments, and the GATT values it
//! publishes to the model.
//!
//! Pure unit tests: no adapter, no radio, no `#[ignore]`. See the header of
//! `tests/server/bluetooth_ble_keyboard/hid_descriptor.rs` for why the walker lives there.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::llm::actions::protocol_trait::Protocol;
use netget::server::bluetooth_ble_remote::actions::BluetoothBleRemoteProtocol;
use netget::server::bluetooth_ble_remote::{
    build_remote_report, consumer_control, HID_REMOTE_INPUT_REPORT_LEN,
    HID_REMOTE_REPORT_DESCRIPTOR,
};

#[path = "../bluetooth_ble_keyboard/hid_descriptor.rs"]
mod hid_descriptor;

use hid_descriptor::{
    assert_describes_report_of, assert_hid_information, example_characteristic_value, walk,
};

#[test]
fn descriptor_matches_the_spec_byte_for_byte() {
    let expected: &[u8] = &[
        0x05, 0x0C, // Usage Page (Consumer)
        0x09, 0x01, // Usage (Consumer Control)
        0xA1, 0x01, // Collection (Application)
        0x15, 0x00, //   Logical Minimum (0)
        0x25, 0x01, //   Logical Maximum (1)
        0x75, 0x01, //   Report Size (1)
        0x95, 0x0C, //   Report Count (12)
        0x09, 0xCD, //   Usage (Play/Pause)
        0x09, 0xB5, //   Usage (Scan Next Track)
        0x09, 0xB6, //   Usage (Scan Previous Track)
        0x09, 0xB7, //   Usage (Stop)
        0x09, 0xB3, //   Usage (Fast Forward)
        0x09, 0xB4, //   Usage (Rewind)
        0x09, 0xE9, //   Usage (Volume Increment)
        0x09, 0xEA, //   Usage (Volume Decrement)
        0x09, 0xE2, //   Usage (Mute)
        0x09, 0x30, //   Usage (Power)
        0x09, 0x40, //   Usage (Menu)
        0x0A, 0x23, 0x02, //   Usage (AC Home) - two-byte usage needs the 0x0A form
        0x81, 0x02, //   Input (Data, Variable, Absolute)
        0x95, 0x04, //   Report Count (4)
        0x81, 0x03, //   Input (Constant, Variable, Absolute) - pad to 16 bits
        0xC0, // End Collection
    ];
    assert_eq!(
        HID_REMOTE_REPORT_DESCRIPTOR, expected,
        "the remote report descriptor changed; update the decoding above with it"
    );
}

#[test]
fn descriptor_is_well_formed_and_describes_the_published_report_length() {
    assert_describes_report_of(
        HID_REMOTE_REPORT_DESCRIPTOR,
        HID_REMOTE_INPUT_REPORT_LEN,
        "bluetooth_ble_remote",
    );
}

/// AC Home (0x0223) needs the two-byte Usage item, `0x0A`, not the one-byte `0x09`.
///
/// This is the defect the whole file exists for. Written `0x09, 0x23, 0x02`, the trailing
/// `0x02` is not the usage's high byte at all: it parses as a fresh item with bType Main and
/// bTag 0000, which the specification reserves, and it then consumes the two bytes after it.
/// Everything downstream of that point is garbage, and a host's parser stops there — but
/// nothing inside NetGet ever looks, so the descriptor shipped broken.
#[test]
fn ac_home_uses_the_two_byte_usage_item() {
    let d = HID_REMOTE_REPORT_DESCRIPTOR;
    let pos = d
        .windows(3)
        .position(|w| w == [0x0A, 0x23, 0x02])
        .expect("descriptor must declare Usage (AC Home) as 0x0A 0x23 0x02");

    assert_ne!(
        d[pos], 0x09,
        "AC Home written with the one-byte Usage item would make the next byte a reserved \
         Main item"
    );

    // And prove the claim rather than asserting the fix: the broken encoding really does
    // fail to parse, so this test would have caught it.
    let mut broken = d.to_vec();
    broken[pos] = 0x09;
    let err = walk(&broken).expect_err("0x09 0x23 0x02 must not parse as a valid descriptor");
    assert!(
        err.contains("reserved"),
        "expected a reserved-tag complaint, got: {err}"
    );
}

/// The descriptor names twelve controls and pads to two whole bytes.
#[test]
fn twelve_controls_then_four_padding_bits() {
    let walked = walk(HID_REMOTE_REPORT_DESCRIPTOR).expect("descriptor must be well formed");
    assert_eq!(
        walked.input_usages.len(),
        2,
        "expected two Input items: the twelve controls and the padding"
    );
    assert_eq!(walked.input_usages[0].len(), 12, "twelve named controls");
    assert!(
        walked.input_usages[1].is_empty(),
        "the padding item must name no usage"
    );
    assert_eq!(walked.input_bits, 16);
}

/// Every usage in the descriptor is on the Consumer page and matches the named constants.
#[test]
fn usages_match_the_consumer_page_constants() {
    let walked = walk(HID_REMOTE_REPORT_DESCRIPTOR).expect("descriptor must be well formed");
    let controls = &walked.input_usages[0];

    // The walker returns fully-qualified usages: page in the high 16 bits.
    for (bit, u) in controls.iter().enumerate() {
        assert_eq!(
            u >> 16,
            0x000C,
            "bit {bit} names usage page 0x{:04x}, not Consumer (0x000C)",
            u >> 16
        );
    }
    let ids: Vec<u16> = controls.iter().map(|u| (u & 0xffff) as u16).collect();
    assert_eq!(
        ids,
        vec![
            consumer_control::PLAY_PAUSE,
            consumer_control::NEXT_TRACK,
            consumer_control::PREVIOUS_TRACK,
            consumer_control::STOP,
            consumer_control::FAST_FORWARD,
            consumer_control::REWIND,
            consumer_control::VOLUME_UP,
            consumer_control::VOLUME_DOWN,
            consumer_control::MUTE,
            consumer_control::POWER,
            consumer_control::MENU,
            consumer_control::HOME,
        ],
        "the descriptor's usage order must be the order build_remote_report assigns bits in"
    );
}

/// `build_remote_report` puts each control on the bit the descriptor gives it.
///
/// The descriptor and the report builder are two halves of one statement — "bit *n* means
/// this control" — written in different files. Before this test they disagreed completely:
/// the startup example's report map declared an entirely different control order from the
/// one the builder used, so a host would have acted on the wrong button.
#[test]
fn report_bits_line_up_with_the_descriptor() {
    let walked = walk(HID_REMOTE_REPORT_DESCRIPTOR).expect("descriptor must be well formed");
    let expected_order = [
        ("play_pause", consumer_control::PLAY_PAUSE),
        ("next_track", consumer_control::NEXT_TRACK),
        ("previous_track", consumer_control::PREVIOUS_TRACK),
        ("stop", consumer_control::STOP),
        ("fast_forward", consumer_control::FAST_FORWARD),
        ("rewind", consumer_control::REWIND),
        ("volume_up", consumer_control::VOLUME_UP),
        ("volume_down", consumer_control::VOLUME_DOWN),
        ("mute", consumer_control::MUTE),
        ("power", consumer_control::POWER),
        ("menu", consumer_control::MENU),
        ("home", consumer_control::HOME),
    ];

    for (bit, (name, usage)) in expected_order.iter().enumerate() {
        let report = build_remote_report(name)
            .unwrap_or_else(|| panic!("build_remote_report({name:?}) returned None"));

        let value = u16::from_le_bytes(report);
        assert_eq!(
            value,
            1u16 << bit,
            "{name} should set bit {bit} and nothing else, got 0b{value:016b}"
        );

        let descriptor_usage = (walked.input_usages[0][bit] & 0xffff) as u16;
        assert_eq!(
            descriptor_usage, *usage,
            "{name} is bit {bit} in build_remote_report but the descriptor puts usage \
             0x{descriptor_usage:04x} there"
        );
    }
}

/// An unrecognised control name yields no report at all.
///
/// A zeroed report is not "nothing"; it is a valid HID report asserting that every control is
/// released. Synthesising one for a name the profile does not define would put an unasked-for
/// statement on the wire, which is the failure mode the BLE profiles are on the deliberately
/// silent list to avoid.
#[test]
fn an_unknown_control_produces_no_report() {
    assert_eq!(build_remote_report("volume_mute"), None);
    assert_eq!(build_remote_report(""), None);
    assert_eq!(build_remote_report("PLAY_PAUSE"), None);
    assert_eq!(build_remote_report("eject"), None);
}

#[test]
fn startup_examples_publish_the_same_descriptor() {
    let examples = BluetoothBleRemoteProtocol::new().get_startup_examples();
    let static_mode = &examples.static_mode;

    let report_map = example_characteristic_value(static_mode, "2a4b");
    assert_eq!(
        report_map,
        hex::encode(HID_REMOTE_REPORT_DESCRIPTOR),
        "the Report Map (0x2A4B) in the startup example is not the profile's descriptor"
    );

    let decoded = hex::decode(&report_map).expect("report map must be valid hex");
    assert_describes_report_of(
        &decoded,
        HID_REMOTE_INPUT_REPORT_LEN,
        "bluetooth_ble_remote startup example",
    );

    let input_report = example_characteristic_value(static_mode, "2a4d");
    assert_eq!(
        hex::decode(&input_report)
            .expect("input report must be valid hex")
            .len(),
        HID_REMOTE_INPUT_REPORT_LEN,
        "the Report (0x2A4D) initial value is not the length the descriptor declares"
    );

    assert_hid_information(
        &example_characteristic_value(static_mode, "2a4a"),
        "bluetooth_ble_remote",
    );
}

#[test]
fn script_mode_example_answers_with_a_correctly_sized_report() {
    let examples = BluetoothBleRemoteProtocol::new().get_startup_examples();
    let code = examples.script_mode["event_handlers"][0]["handler"]["code"]
        .as_str()
        .expect("script_mode handler must carry code");
    let empty = hex::encode(vec![0u8; HID_REMOTE_INPUT_REPORT_LEN]);
    assert!(
        code.contains(&empty),
        "script example answers with something other than a {HID_REMOTE_INPUT_REPORT_LEN}-byte \
         report: {code}"
    );
}

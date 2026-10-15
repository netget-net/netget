//! The BLE HID gamepad's report descriptor and the GATT values it publishes to the model.
//!
//! Pure unit tests: no adapter, no radio, no `#[ignore]`. See the header of
//! `tests/server/bluetooth_ble_keyboard/hid_descriptor.rs` for why the walker lives there.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::llm::actions::protocol_trait::Protocol;
use netget::server::bluetooth_ble_gamepad::actions::BluetoothBleGamepadProtocol;
use netget::server::bluetooth_ble_gamepad::{
    HID_GAMEPAD_INPUT_REPORT_LEN, HID_GAMEPAD_REPORT_DESCRIPTOR,
};

#[path = "../bluetooth_ble_keyboard/hid_descriptor.rs"]
mod hid_descriptor;

use hid_descriptor::{
    assert_describes_report_of, assert_hid_information, example_characteristic_value, walk,
};

#[test]
fn descriptor_matches_the_spec_byte_for_byte() {
    let expected: &[u8] = &[
        0x05, 0x01, // Usage Page (Generic Desktop)
        0x09, 0x05, // Usage (Game Pad)
        0xA1, 0x01, // Collection (Application)
        0x05, 0x09, //   Usage Page (Button)
        0x19, 0x01, //   Usage Minimum (Button 1)
        0x29, 0x10, //   Usage Maximum (Button 16)
        0x15, 0x00, //   Logical Minimum (0)
        0x25, 0x01, //   Logical Maximum (1)
        0x75, 0x01, //   Report Size (1)
        0x95, 0x10, //   Report Count (16)
        0x81, 0x02, //   Input (Data, Variable, Absolute) - 16 bits, two whole bytes
        0xC0, // End Collection
    ];
    assert_eq!(
        HID_GAMEPAD_REPORT_DESCRIPTOR, expected,
        "the gamepad report descriptor changed; update the decoding above with it"
    );
}

#[test]
fn descriptor_is_well_formed_and_describes_the_published_report_length() {
    assert_describes_report_of(
        HID_GAMEPAD_REPORT_DESCRIPTOR,
        HID_GAMEPAD_INPUT_REPORT_LEN,
        "bluetooth_ble_gamepad",
    );
}

/// Sixteen buttons is exactly two bytes, so the descriptor must carry no padding item.
///
/// The descriptor this replaced appended a `Report Count (1)` / `Input (Constant)` pad to an
/// already byte-aligned sixteen bits. That is not harmless tidiness: it makes the report
/// seventeen bits, so a host pads it to three bytes while every value the profile publishes
/// is two, and the button bits land where nothing expects them.
#[test]
fn sixteen_buttons_need_no_padding() {
    let walked = walk(HID_GAMEPAD_REPORT_DESCRIPTOR).expect("descriptor must be well formed");
    assert_eq!(
        walked.input_usages.len(),
        1,
        "expected exactly one Input item; a second one is a padding item that should not exist"
    );
    assert_eq!(
        walked.input_usages[0].len(),
        16,
        "the button block must name all sixteen button usages"
    );
    assert_eq!(walked.input_bits, 16, "sixteen one-bit buttons");
    assert_eq!(HID_GAMEPAD_INPUT_REPORT_LEN, 2);
}

#[test]
fn startup_examples_publish_the_same_descriptor() {
    let examples = BluetoothBleGamepadProtocol::new().get_startup_examples();
    let static_mode = &examples.static_mode;

    let report_map = example_characteristic_value(static_mode, "2a4b");
    assert_eq!(
        report_map,
        hex::encode(HID_GAMEPAD_REPORT_DESCRIPTOR),
        "the Report Map (0x2A4B) in the startup example is not the profile's descriptor"
    );

    let decoded = hex::decode(&report_map).expect("report map must be valid hex");
    assert_describes_report_of(
        &decoded,
        HID_GAMEPAD_INPUT_REPORT_LEN,
        "bluetooth_ble_gamepad startup example",
    );

    let input_report = example_characteristic_value(static_mode, "2a4d");
    assert_eq!(
        hex::decode(&input_report)
            .expect("input report must be valid hex")
            .len(),
        HID_GAMEPAD_INPUT_REPORT_LEN,
        "the Report (0x2A4D) initial value is not the length the descriptor declares"
    );

    assert_hid_information(
        &example_characteristic_value(static_mode, "2a4a"),
        "bluetooth_ble_gamepad",
    );
}

#[test]
fn script_mode_example_answers_with_a_correctly_sized_report() {
    let examples = BluetoothBleGamepadProtocol::new().get_startup_examples();
    let code = examples.script_mode["event_handlers"][0]["handler"]["code"]
        .as_str()
        .expect("script_mode handler must carry code");
    let empty = hex::encode(vec![0u8; HID_GAMEPAD_INPUT_REPORT_LEN]);
    assert!(
        code.contains(&empty),
        "script example answers with something other than a {HID_GAMEPAD_INPUT_REPORT_LEN}-byte \
         report: {code}"
    );
}

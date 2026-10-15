//! The BLE HID mouse's report descriptor and the GATT values it publishes to the model.
//!
//! Pure unit tests: no adapter, no radio, no `#[ignore]`. See the header of
//! `tests/server/bluetooth_ble_keyboard/hid_descriptor.rs` for why the walker lives there.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::llm::actions::protocol_trait::Protocol;
use netget::server::bluetooth_ble_mouse::actions::BluetoothBleMouseProtocol;
use netget::server::bluetooth_ble_mouse::{
    HID_MOUSE_INPUT_REPORT_LEN, HID_MOUSE_REPORT_DESCRIPTOR,
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
        0x09, 0x02, // Usage (Mouse)
        0xA1, 0x01, // Collection (Application)
        0x09, 0x01, //   Usage (Pointer)
        0xA1, 0x00, //   Collection (Physical)
        0x05, 0x09, //     Usage Page (Button)
        0x19, 0x01, //     Usage Minimum (Button 1)
        0x29, 0x03, //     Usage Maximum (Button 3)
        0x15, 0x00, //     Logical Minimum (0)
        0x25, 0x01, //     Logical Maximum (1)
        0x95, 0x03, //     Report Count (3)
        0x75, 0x01, //     Report Size (1)
        0x81, 0x02, //     Input (Data, Variable, Absolute) - 3 button bits
        0x95, 0x01, //     Report Count (1)
        0x75, 0x05, //     Report Size (5)
        0x81, 0x01, //     Input (Constant)                 - 5 bits, byte 0 complete
        0x05, 0x01, //     Usage Page (Generic Desktop)
        0x09, 0x30, //     Usage (X)
        0x09, 0x31, //     Usage (Y)
        0x09, 0x38, //     Usage (Wheel)
        0x15, 0x81, //     Logical Minimum (-127)
        0x25, 0x7F, //     Logical Maximum (127)
        0x75, 0x08, //     Report Size (8)
        0x95, 0x03, //     Report Count (3)
        0x81, 0x06, //     Input (Data, Variable, Relative) - bytes 1-3
        0xC0, //   End Collection (Physical)
        0xC0, // End Collection (Application)
    ];
    assert_eq!(
        HID_MOUSE_REPORT_DESCRIPTOR, expected,
        "the mouse report descriptor changed; update the decoding above with it"
    );
}

#[test]
fn descriptor_is_well_formed_and_describes_the_published_report_length() {
    assert_describes_report_of(
        HID_MOUSE_REPORT_DESCRIPTOR,
        HID_MOUSE_INPUT_REPORT_LEN,
        "bluetooth_ble_mouse",
    );
}

/// X, Y and Wheel must be **signed** and **relative**.
///
/// This is the one place in the BLE HID family where a wrong byte silently reverses a
/// direction rather than breaking the descriptor outright: read as unsigned, every leftward
/// movement (-1, encoded 0xFF) becomes a 255-pixel jump to the right. Declared Absolute
/// instead of Relative, the pointer teleports to a coordinate rather than moving by a delta.
/// Neither shows up as a parse error, so nothing but an explicit assertion catches them.
#[test]
fn pointer_axes_are_signed_and_relative() {
    let d = HID_MOUSE_REPORT_DESCRIPTOR;
    let pos = d
        .windows(2)
        .position(|w| w == [0x09, 0x38])
        .expect("descriptor must declare Usage (Wheel)");

    assert_eq!(
        &d[pos + 2..pos + 6],
        &[0x15, 0x81, 0x25, 0x7F],
        "the axis block must declare Logical Minimum (-127) / Logical Maximum (127); an \
         unsigned range makes every negative delta a large positive one"
    );

    let input = pos + 10;
    assert_eq!(
        d[input], 0x81,
        "expected the axis Input item immediately after Report Size / Report Count"
    );
    assert_eq!(
        d[input + 1] & 0x04,
        0x04,
        "the axis Input item must set the Relative bit (0x06, not 0x02); Absolute makes the \
         pointer jump to a coordinate instead of moving by a delta"
    );

    // -127..=127 really is what a signed byte carries, i.e. the descriptor is not promising a
    // range the report cannot encode.
    assert_eq!(i8::from_le_bytes([0x81]), -127);
    assert_eq!(i8::from_le_bytes([0x7F]), 127);
}

#[test]
fn descriptor_declares_three_buttons_and_three_axes() {
    let walked = walk(HID_MOUSE_REPORT_DESCRIPTOR).expect("descriptor must be well formed");
    assert_eq!(
        walked.input_usages.len(),
        3,
        "expected three Input items: buttons, padding, axes"
    );
    assert_eq!(walked.input_usages[0].len(), 3, "three buttons");
    assert!(
        walked.input_usages[1].is_empty(),
        "the padding item must name no usage"
    );
    assert_eq!(walked.input_usages[2].len(), 3, "X, Y and Wheel");
}

#[test]
fn startup_examples_publish_the_same_descriptor() {
    let examples = BluetoothBleMouseProtocol::new().get_startup_examples();
    let static_mode = &examples.static_mode;

    let report_map = example_characteristic_value(static_mode, "2a4b");
    assert_eq!(
        report_map,
        hex::encode(HID_MOUSE_REPORT_DESCRIPTOR),
        "the Report Map (0x2A4B) in the startup example is not the profile's descriptor"
    );

    let decoded = hex::decode(&report_map).expect("report map must be valid hex");
    assert_describes_report_of(
        &decoded,
        HID_MOUSE_INPUT_REPORT_LEN,
        "bluetooth_ble_mouse startup example",
    );

    let input_report = example_characteristic_value(static_mode, "2a4d");
    assert_eq!(
        hex::decode(&input_report)
            .expect("input report must be valid hex")
            .len(),
        HID_MOUSE_INPUT_REPORT_LEN,
        "the Report (0x2A4D) initial value is not the length the descriptor declares"
    );

    assert_hid_information(
        &example_characteristic_value(static_mode, "2a4a"),
        "bluetooth_ble_mouse",
    );
}

#[test]
fn script_mode_example_answers_with_a_correctly_sized_report() {
    let examples = BluetoothBleMouseProtocol::new().get_startup_examples();
    let code = examples.script_mode["event_handlers"][0]["handler"]["code"]
        .as_str()
        .expect("script_mode handler must carry code");
    let empty = hex::encode(vec![0u8; HID_MOUSE_INPUT_REPORT_LEN]);
    assert!(
        code.contains(&empty),
        "script example answers with something other than a {HID_MOUSE_INPUT_REPORT_LEN}-byte \
         report: {code}"
    );
}

/// The button bit masks are the low three bits, in the order the descriptor declares them.
#[test]
fn button_masks_match_the_declared_button_order() {
    use netget::server::bluetooth_ble_mouse::hid_mouse_buttons::{
        BUTTON_LEFT, BUTTON_MIDDLE, BUTTON_RIGHT,
    };
    assert_eq!(BUTTON_LEFT, 0x01, "Button 1 is bit 0");
    assert_eq!(BUTTON_RIGHT, 0x02, "Button 2 is bit 1");
    assert_eq!(BUTTON_MIDDLE, 0x04, "Button 3 is bit 2");
    assert_eq!(
        BUTTON_LEFT | BUTTON_RIGHT | BUTTON_MIDDLE,
        0x07,
        "the three buttons must fit the descriptor's three-bit field"
    );
}

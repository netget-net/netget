//! The BLE HID keyboard's report descriptor and the GATT values it publishes to the model.
//!
//! Pure unit tests: no adapter, no radio, no `#[ignore]`. Nothing inside NetGet parses a HID
//! report map — the base stack carries it as an opaque byte string — so without these the
//! first thing to validate the descriptor is a real host, on a real machine, after shipping.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::llm::actions::protocol_trait::Protocol;
use netget::server::bluetooth_ble_keyboard::actions::BluetoothBleKeyboardProtocol;
use netget::server::bluetooth_ble_keyboard::{
    HID_KEYBOARD_INPUT_REPORT_LEN, HID_KEYBOARD_REPORT_DESCRIPTOR,
};

use super::hid_descriptor::{
    assert_describes_report_of, assert_hid_information, example_characteristic_value, walk,
};

/// The descriptor, byte for byte, as the USB HID specification encodes it.
///
/// Spelled out rather than derived so that a change to the const has to be made twice, once
/// here with the item decoding written next to it. That is the point of the test: the bytes
/// are unreadable, so the only way a wrong one is noticed is if something states what each
/// is supposed to be.
#[test]
fn descriptor_matches_the_spec_byte_for_byte() {
    let expected: &[u8] = &[
        0x05, 0x01, // Usage Page (Generic Desktop)
        0x09, 0x06, // Usage (Keyboard)
        0xA1, 0x01, // Collection (Application)
        0x05, 0x07, //   Usage Page (Keyboard/Keypad)
        0x19, 0xE0, //   Usage Minimum (Left Control)
        0x29, 0xE7, //   Usage Maximum (Right GUI)
        0x15, 0x00, //   Logical Minimum (0)
        0x25, 0x01, //   Logical Maximum (1)
        0x75, 0x01, //   Report Size (1)
        0x95, 0x08, //   Report Count (8)
        0x81, 0x02, //   Input (Data, Variable, Absolute)  - byte 0, modifiers
        0x95, 0x01, //   Report Count (1)
        0x75, 0x08, //   Report Size (8)
        0x81, 0x01, //   Input (Constant)                  - byte 1, reserved
        0x95, 0x06, //   Report Count (6)
        0x75, 0x08, //   Report Size (8)
        0x15, 0x00, //   Logical Minimum (0)
        0x25, 0x65, //   Logical Maximum (101)
        0x05, 0x07, //   Usage Page (Keyboard/Keypad)
        0x19, 0x00, //   Usage Minimum (0)
        0x29, 0x65, //   Usage Maximum (101)
        0x81, 0x00, //   Input (Data, Array)               - bytes 2-7, six key slots
        0xC0, // End Collection
    ];
    assert_eq!(
        HID_KEYBOARD_REPORT_DESCRIPTOR, expected,
        "the keyboard report descriptor changed; update the decoding above with it"
    );
}

#[test]
fn descriptor_is_well_formed_and_describes_the_published_report_length() {
    assert_describes_report_of(
        HID_KEYBOARD_REPORT_DESCRIPTOR,
        HID_KEYBOARD_INPUT_REPORT_LEN,
        "bluetooth_ble_keyboard",
    );
}

/// The modifier byte covers all eight modifiers and the key array covers six slots.
///
/// Checked through the walker's usage bookkeeping rather than by eye, because the two blocks
/// are declared with `Usage Minimum`/`Usage Maximum` ranges whose width is not visible in the
/// bytes.
#[test]
fn descriptor_declares_eight_modifiers_and_six_key_slots() {
    let walked = walk(HID_KEYBOARD_REPORT_DESCRIPTOR).expect("descriptor must be well formed");
    assert_eq!(
        walked.input_usages.len(),
        3,
        "expected three Input items: modifiers, reserved byte, key array"
    );
    assert_eq!(
        walked.input_usages[0].len(),
        8,
        "the modifier block must name all eight modifier usages (0xE0-0xE7)"
    );
    assert!(
        walked.input_usages[1].is_empty(),
        "the reserved byte is constant padding and must name no usage"
    );
    assert_eq!(
        walked.input_usages[2].len(),
        102,
        "the key array must span usages 0x00-0x65 inclusive"
    );
}

/// The startup examples are what a model copies onto a real GATT table, so they must carry
/// the same bytes the profile documents — not a second, hand-maintained transcription.
#[test]
fn startup_examples_publish_the_same_descriptor() {
    let examples = BluetoothBleKeyboardProtocol::new().get_startup_examples();
    let static_mode = &examples.static_mode;

    let report_map = example_characteristic_value(static_mode, "2a4b");
    assert_eq!(
        report_map,
        hex::encode(HID_KEYBOARD_REPORT_DESCRIPTOR),
        "the Report Map (0x2A4B) in the startup example is not the profile's descriptor"
    );

    // Belt and braces: walk what the example actually publishes, not only what it equals.
    let decoded = hex::decode(&report_map).expect("report map must be valid hex");
    assert_describes_report_of(
        &decoded,
        HID_KEYBOARD_INPUT_REPORT_LEN,
        "bluetooth_ble_keyboard startup example",
    );

    let input_report = example_characteristic_value(static_mode, "2a4d");
    assert_eq!(
        hex::decode(&input_report)
            .expect("input report must be valid hex")
            .len(),
        HID_KEYBOARD_INPUT_REPORT_LEN,
        "the Report (0x2A4D) initial value is not the length the descriptor declares"
    );

    assert_hid_information(
        &example_characteristic_value(static_mode, "2a4a"),
        "bluetooth_ble_keyboard",
    );
}

/// The script-mode example answers a read with a report of the right length too. It is the
/// example most likely to be copied verbatim, because it is the shortest.
#[test]
fn script_mode_example_answers_with_a_correctly_sized_report() {
    let examples = BluetoothBleKeyboardProtocol::new().get_startup_examples();
    let code = examples.script_mode["event_handlers"][0]["handler"]["code"]
        .as_str()
        .expect("script_mode handler must carry code");
    let empty = hex::encode(vec![0u8; HID_KEYBOARD_INPUT_REPORT_LEN]);
    assert!(
        code.contains(&empty),
        "script example answers with something other than a {HID_KEYBOARD_INPUT_REPORT_LEN}-byte \
         report: {code}"
    );
}

/// `char_to_keycode` maps into the range the descriptor's key array actually covers.
///
/// The array is declared `Logical Maximum (101)`, so a keycode above 0x65 is outside what the
/// descriptor admits and a host is entitled to discard the whole report.
#[test]
fn char_to_keycode_stays_inside_the_declared_key_range() {
    use netget::server::bluetooth_ble_keyboard::hid_keycodes::{
        char_to_keycode, KEY_ENTER, KEY_SPACE, MOD_LEFT_SHIFT,
    };

    assert_eq!(char_to_keycode('a'), Some((0, 0x04)));
    assert_eq!(char_to_keycode('z'), Some((0, 0x1D)));
    assert_eq!(char_to_keycode('A'), Some((MOD_LEFT_SHIFT, 0x04)));
    assert_eq!(char_to_keycode('Z'), Some((MOD_LEFT_SHIFT, 0x1D)));
    assert_eq!(char_to_keycode(' '), Some((0, KEY_SPACE)));
    assert_eq!(char_to_keycode('\n'), Some((0, KEY_ENTER)));

    // Unmapped characters must produce nothing rather than a plausible-looking keycode: a
    // fabricated keystroke is an assertion that a key was pressed.
    assert_eq!(char_to_keycode('€'), None);
    assert_eq!(char_to_keycode('!'), None);

    for c in '\u{0}'..='\u{10ff}' {
        if let Some((modifiers, code)) = char_to_keycode(c) {
            assert!(
                code <= 0x65,
                "char_to_keycode({c:?}) returned keycode 0x{code:02x}, above the descriptor's \
                 Logical Maximum of 101 (0x65)"
            );
            assert!(
                modifiers & !MOD_LEFT_SHIFT == 0,
                "char_to_keycode({c:?}) set modifier bits 0x{modifiers:02x} it never claims to"
            );
        }
    }
}

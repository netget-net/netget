//! The BLE presentation clicker's report descriptor, its keycodes, and the GATT values it
//! publishes to the model.
//!
//! Pure unit tests: no adapter, no radio, no `#[ignore]`. See the header of
//! `tests/server/bluetooth_ble_keyboard/hid_descriptor.rs` for why the walker lives there and
//! what it is: an independent reading of the USB HID 1.11 item encoding, written so that a
//! malformed report map fails here rather than on a stranger's host.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::llm::actions::protocol_trait::Protocol;
use netget::server::bluetooth_ble_presenter::actions::BluetoothBlePresenterProtocol;
use netget::server::bluetooth_ble_presenter::{
    build_presenter_report, presenter_keys, HID_PRESENTER_INPUT_REPORT_LEN,
    HID_PRESENTER_REPORT_DESCRIPTOR,
};

#[path = "../bluetooth_ble_keyboard/hid_descriptor.rs"]
mod hid_descriptor;

use hid_descriptor::{
    assert_describes_report_of, assert_hid_information, example_characteristic_value, walk,
};

/// The descriptor, decoded item by item, written out so a reviewer can check it against the
/// specification without a hex editor. If this fails, the const changed and the decoding here
/// has to be redone with it — not silenced.
#[test]
fn descriptor_matches_the_spec_byte_for_byte() {
    let expected: &[u8] = &[
        0x05, 0x01, // Usage Page (Generic Desktop)
        0x09, 0x06, // Usage (Keyboard)
        0xA1, 0x01, // Collection (Application)
        0x05, 0x07, //   Usage Page (Keyboard/Keypad)
        0x19, 0xE0, //   Usage Minimum (224 = LeftControl)
        0x29, 0xE7, //   Usage Maximum (231 = RightGUI)
        0x15, 0x00, //   Logical Minimum (0)
        0x25, 0x01, //   Logical Maximum (1)
        0x75, 0x01, //   Report Size (1)
        0x95, 0x08, //   Report Count (8)
        0x81, 0x02, //   Input (Data, Variable, Absolute) - modifier byte
        0x95, 0x01, //   Report Count (1)
        0x75, 0x08, //   Report Size (8)
        0x81, 0x01, //   Input (Constant) - reserved byte
        0x95, 0x06, //   Report Count (6)
        0x75, 0x08, //   Report Size (8)
        0x15, 0x00, //   Logical Minimum (0)
        0x25, 0x65, //   Logical Maximum (101)
        0x05, 0x07, //   Usage Page (Keyboard/Keypad)
        0x19, 0x00, //   Usage Minimum (0)
        0x29, 0x65, //   Usage Maximum (101)
        0x81, 0x00, //   Input (Data, Array) - six key slots
        0xC0, // End Collection
    ];
    assert_eq!(
        HID_PRESENTER_REPORT_DESCRIPTOR, expected,
        "the presenter report descriptor changed; update the decoding above with it"
    );
}

#[test]
fn descriptor_is_well_formed_and_describes_the_published_report_length() {
    assert_describes_report_of(
        HID_PRESENTER_REPORT_DESCRIPTOR,
        HID_PRESENTER_INPUT_REPORT_LEN,
        "bluetooth_ble_presenter",
    );
}

/// The report is 8 modifier bits + 8 constant bits + six 8-bit key slots.
#[test]
fn three_input_items_make_exactly_eight_bytes() {
    let walked = walk(HID_PRESENTER_REPORT_DESCRIPTOR).expect("descriptor must be well formed");
    assert_eq!(
        walked.input_usages.len(),
        3,
        "expected three Input items: modifiers, the reserved byte, and the key array"
    );
    assert_eq!(
        walked.input_usages[0].len(),
        8,
        "the modifier item names the eight usages 0xE0-0xE7"
    );
    assert!(
        walked.input_usages[1].is_empty(),
        "the reserved byte is Constant and must name no usage"
    );
    assert_eq!(
        walked.input_usages[2].len(),
        102,
        "the key array names the usage range 0-101"
    );
    assert_eq!(walked.input_bits, 64, "8 + 8 + 6*8 bits");
    assert_eq!(
        walked.input_report_len().expect("byte aligned"),
        HID_PRESENTER_INPUT_REPORT_LEN
    );
}

/// The defect this file exists for, proven rather than asserted away.
///
/// The descriptor that shipped in the startup example wrote its padding item as
/// `0x05, 0x75` — `Usage Page (0x75)`, a page the specification reserves — where
/// `0x75, 0x05` (`Report Size (5)`) was meant. The two bytes were simply transposed. Because
/// `Report Size` was then never updated it stayed at 1 from the button block above, the pad
/// contributed one bit instead of five, and the whole report came to **ten bits**: not a whole
/// number of bytes, and four times shorter than the eight-byte value published on the very
/// same characteristic. Nothing in NetGet parses a report map, so nothing failed.
///
/// Walk the original bytes and show the walker rejects them. Without this the test above only
/// agrees with the fix; with it, the test is shown to catch the bug.
#[test]
fn the_descriptor_that_shipped_is_rejected_by_the_walker() {
    let shipped = hex::decode(concat!(
        "05010906a1010507190029ff150026ff0075089501810005091901",
        "290115002501750195018102057595018103c0",
    ))
    .expect("the shipped literal must be valid hex");
    assert_eq!(shipped.len(), 46, "the shipped report map was 46 bytes");

    let walked = walk(&shipped).expect("the shipped bytes do parse as items - that is the trap");
    assert_eq!(
        walked.input_bits, 10,
        "the shipped descriptor declared a ten-bit report"
    );
    let err = walked
        .input_report_len()
        .expect_err("a ten-bit report is not a whole number of bytes and must be rejected");
    assert!(
        err.contains("10 bits"),
        "expected a bit-alignment complaint, got: {err}"
    );

    // And the transposition itself: `05 75` is Usage Page (0x75), which is reserved.
    assert!(
        shipped.windows(2).any(|w| w == [0x05, 0x75]),
        "the shipped descriptor contained the transposed `Usage Page (0x75)` item"
    );
    assert!(
        !HID_PRESENTER_REPORT_DESCRIPTOR
            .windows(2)
            .any(|w| w == [0x05, 0x75]),
        "the fixed descriptor must not name the reserved usage page 0x75"
    );
}

/// Every keycode this profile can send is inside the range the descriptor declares.
///
/// The bounds are read back out of the descriptor rather than restated here, so moving the
/// `Logical Maximum` without moving the keycodes fails.
#[test]
fn every_keycode_is_inside_the_declared_range() {
    let walked = walk(HID_PRESENTER_REPORT_DESCRIPTOR).expect("descriptor must be well formed");
    let key_slots = &walked.input_usages[2];
    let lowest = *key_slots.iter().min().expect("key array names usages");
    let highest = *key_slots.iter().max().expect("key array names usages");

    for (name, keycode) in named_controls() {
        // The walker returns fully-qualified usages: page in the high 16 bits.
        let usage = (0x0007u32 << 16) | u32::from(keycode);
        assert!(
            usage >= lowest && usage <= highest,
            "{name} sends keycode 0x{keycode:02X}, which is outside the Usage \
             Minimum/Maximum range 0x{:04x}-0x{:04x} the key array declares; a host would \
             drop it",
            lowest & 0xffff,
            highest & 0xffff
        );
        // Logical Maximum is 101 for the key array; a keycode above it is out of range
        // whatever the usage list says.
        assert!(
            keycode <= 101,
            "{name}'s keycode 0x{keycode:02X} exceeds the descriptor's Logical Maximum of 101"
        );
    }
}

/// `build_presenter_report` puts each control where the descriptor says it goes, and sets
/// nothing else.
#[test]
fn reports_carry_the_keycode_and_no_stray_modifier() {
    for (name, keycode) in named_controls() {
        let report = build_presenter_report(name)
            .unwrap_or_else(|| panic!("build_presenter_report({name:?}) returned None"));

        assert_eq!(report.len(), HID_PRESENTER_INPUT_REPORT_LEN);
        assert_eq!(
            report[0], 0x00,
            "{name} set modifier bits 0b{:08b}; none of this profile's controls needs a \
             modifier, and an undeclared one is a keypress the caller never asked for",
            report[0]
        );
        assert_eq!(
            report[1], 0x00,
            "{name} wrote to the descriptor's Constant reserved byte"
        );
        assert_eq!(report[2], keycode, "{name} must sit in the first key slot");
        assert!(
            report[3..].iter().all(|b| *b == 0),
            "{name} filled more than one key slot: {report:02x?}"
        );
    }
}

/// An unrecognised control name says nothing at all rather than releasing every key.
///
/// A zeroed HID report is not "no answer": it asserts that no key is held. Returning one for a
/// name the profile does not define would put an unasked-for statement on the wire, which is
/// the same failure mode `CLAUDE.md`'s deliberately-silent rule exists to prevent.
#[test]
fn an_unknown_control_returns_none_rather_than_a_zeroed_report() {
    for name in ["", "laser_pointer", "NEXT_SLIDE", "next slide", "page_down"] {
        assert!(
            build_presenter_report(name).is_none(),
            "build_presenter_report({name:?}) must return None, not a report"
        );
    }
}

/// The GATT values in the startup examples are the ones the profile's constants describe.
///
/// A model copies these examples verbatim onto a real GATT table, so a hand-written second
/// copy of the report map is a descriptor that drifts. They are now generated from the consts;
/// this asserts that the generation is what actually reaches the example.
#[test]
fn the_startup_example_publishes_the_descriptor_and_a_matching_report() {
    let protocol = BluetoothBlePresenterProtocol::new();
    let examples = protocol.get_startup_examples();
    let static_mode = &examples.static_mode;

    let report_map = example_characteristic_value(static_mode, "2A4B");
    assert_eq!(
        hex::decode(&report_map).expect("report map must be valid hex"),
        HID_PRESENTER_REPORT_DESCRIPTOR,
        "the HID Report Map characteristic must carry the descriptor const verbatim"
    );

    let input_report = example_characteristic_value(static_mode, "2A4D");
    let bytes = hex::decode(&input_report).expect("input report must be valid hex");
    assert_eq!(
        bytes.len(),
        HID_PRESENTER_INPUT_REPORT_LEN,
        "the input report characteristic's initial value must be the length the descriptor \
         declares"
    );
    assert!(
        bytes.iter().all(|b| *b == 0),
        "the initial value should be the all-zero 'no key held' report"
    );
}

/// HID Information is a little-endian uint16 — `1101`, not `0111`.
///
/// The example published `01110002`, which a host reads as HID version 17.01. Every GATT
/// integer is little-endian; this profile shared the defect with all four of its siblings.
#[test]
fn hid_information_says_version_one_point_eleven() {
    let protocol = BluetoothBlePresenterProtocol::new();
    let examples = protocol.get_startup_examples();
    let value = example_characteristic_value(&examples.static_mode, "2A4A");
    assert_hid_information(&value, "bluetooth_ble_presenter");
}

/// The script-mode example answers a read with a report of the declared length.
#[test]
fn the_script_example_answers_with_a_correctly_sized_report() {
    let protocol = BluetoothBlePresenterProtocol::new();
    let examples = protocol.get_startup_examples();
    let code = examples.script_mode["event_handlers"][0]["handler"]["code"]
        .as_str()
        .expect("script mode must carry python code");

    let expected = hex::encode(vec![0u8; HID_PRESENTER_INPUT_REPORT_LEN]);
    assert!(
        code.contains(&expected),
        "the script example should answer with the {}-byte all-zero report, got: {code}",
        HID_PRESENTER_INPUT_REPORT_LEN
    );
}

/// The profile forwards its whole vocabulary to the base stack.
///
/// `BluetoothBle::spawn_with_llm_actions` hardcodes `BluetoothBleProtocol` when it calls
/// `call_llm`, so the base's actions and events are the only ones that can ever be offered or
/// executed. A profile that declared its own would document a vocabulary no code path reaches.
#[test]
fn the_profile_delegates_its_vocabulary_to_the_base() {
    use netget::server::bluetooth_ble::actions::BluetoothBleProtocol;

    let profile = BluetoothBlePresenterProtocol::new();
    let base = BluetoothBleProtocol::new();

    let profile_events: Vec<String> = profile
        .get_event_types()
        .iter()
        .map(|e| e.id.clone())
        .collect();
    let base_events: Vec<String> = base
        .get_event_types()
        .iter()
        .map(|e| e.id.clone())
        .collect();
    assert_eq!(
        profile_events, base_events,
        "the presenter must forward the base's event types verbatim"
    );

    let profile_sync: Vec<String> = profile
        .get_sync_actions()
        .iter()
        .map(|a| a.name.clone())
        .collect();
    let base_sync: Vec<String> = base
        .get_sync_actions()
        .iter()
        .map(|a| a.name.clone())
        .collect();
    assert_eq!(
        profile_sync, base_sync,
        "the presenter must forward the base's sync actions verbatim"
    );
}

/// The five controls this profile defines, paired with the keycode each must send.
fn named_controls() -> Vec<(&'static str, u8)> {
    vec![
        ("next_slide", presenter_keys::NEXT_SLIDE),
        ("previous_slide", presenter_keys::PREVIOUS_SLIDE),
        ("start_presentation", presenter_keys::START_PRESENTATION),
        ("end_presentation", presenter_keys::END_PRESENTATION),
        ("blank_screen", presenter_keys::BLANK_SCREEN),
    ]
}

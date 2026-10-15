//! HID Service (0x1812) startup-example bytes, checked against the SIG layout.
//!
//! The startup examples in `actions.rs` are the GATT layout a model copies verbatim, and every
//! UUID and value byte in them is a literal nobody checks at runtime. A swapped-endian value or
//! a characteristic UUID one digit off still starts, still advertises and still answers reads —
//! it is wrong only in the eyes of a real central, which no test in this tree has. So the
//! literals are pinned here instead, against the published layout rather than against the
//! implementation, in the style of `tests/server/bluetooth_ble_beacon/payload_test.rs`.
//!
//! Sources: Bluetooth SIG Assigned Numbers (service and characteristic UUIDs) and
//! HID over GATT Profile 1.0 / HID Service 1.0, section 2.5 (HID Information) and USB HID 1.11 (report descriptors).
//!
//! These tests need no Bluetooth adapter, so they are not `#[ignore]`d.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::llm::actions::protocol_trait::Protocol;
use netget::server::bluetooth_ble_presenter::actions::BluetoothBlePresenterProtocol;
use serde_json::Value;

/// A 16-bit Bluetooth SIG alias in the 128-bit form the examples are written in.
fn sig(alias: u16) -> String {
    format!("{alias:08x}-0000-1000-8000-00805f9b34fb")
}

/// The `add_service` action inside the static-mode example's `bluetooth_ble_started` handler.
fn static_service() -> Value {
    let example = BluetoothBlePresenterProtocol
        .get_startup_examples()
        .static_mode;
    example["event_handlers"]
        .as_array()
        .expect("static example declares event_handlers")
        .iter()
        .find(|h| h["event_pattern"] == "bluetooth_ble_started")
        .expect("static example handles bluetooth_ble_started")["handler"]["actions"]
        .as_array()
        .expect("the started handler carries an action list")
        .iter()
        .find(|a| a["type"] == "add_service")
        .expect("the started handler adds a service")
        .clone()
}

/// Every characteristic of the static example's service, in declaration order.
fn characteristics() -> Vec<Value> {
    static_service()["characteristics"]
        .as_array()
        .expect("the service declares characteristics")
        .clone()
}

/// The characteristic with this SIG alias, or a panic naming what was there instead.
fn characteristic(alias: u16) -> Value {
    let want = sig(alias);
    characteristics()
        .into_iter()
        .find(|c| c["uuid"] == Value::String(want.clone()))
        .unwrap_or_else(|| {
            panic!(
                "no characteristic {want} (0x{alias:04X}) in the static example; it declares {:?}",
                characteristics()
                    .iter()
                    .map(|c| c["uuid"].as_str().unwrap_or("?").to_string())
                    .collect::<Vec<_>>()
            )
        })
}

/// A characteristic's `initial_value`, decoded from the hex the base stack really parses.
fn initial_bytes(alias: u16) -> Vec<u8> {
    let c = characteristic(alias);
    let hex = c["initial_value"]
        .as_str()
        .unwrap_or_else(|| panic!("characteristic 0x{alias:04X} declares no initial_value"));
    hex::decode(hex.trim_start_matches("0x"))
        .unwrap_or_else(|e| panic!("initial_value {hex:?} for 0x{alias:04X} is not hex: {e}"))
}

fn has_property(alias: u16, property: &str) -> bool {
    characteristic(alias)["properties"]
        .as_array()
        .is_some_and(|p| p.iter().any(|v| v == property))
}

#[test]
fn the_static_example_builds_the_right_service() {
    let service = static_service();
    assert_eq!(
        service["uuid"],
        Value::String(sig(0x1812)),
        "the static example must build the HID Service (0x1812)"
    );
    assert_eq!(
        service["primary"],
        Value::Bool(true),
        "the HID Service is a primary service"
    );

    // The advertisement must name the same service, or a central scanning for it never finds
    // this device — a mismatch no amount of correct GATT makes up for.
    let advertised = BluetoothBlePresenterProtocol
        .get_startup_examples()
        .static_mode["event_handlers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["event_pattern"] == "bluetooth_ble_started")
        .unwrap()["handler"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["type"] == "start_advertising")
        .expect("the static example starts advertising")["service_uuids"]
        .clone();
    assert_eq!(
        advertised,
        serde_json::json!([sig(0x1812)]),
        "the advertisement must name the service the example just built"
    );
}

/// HID Information (0x2A4A) is four octets: `bcdHID` as a little-endian `uint16`, then
/// `bCountryCode`, then a flags octet (bit 0 RemoteWake, bit 1 NormallyConnectable).
/// `11010002` is bcdHID 0x0111 = 1.11, country 0x00 (not localised), flags 0x02
/// (NormallyConnectable).
///
/// The version is the trap, and this test was on the wrong side of it: it asserted `01110002`
/// and called the result "1.11". bcdHID is *binary-coded decimal*, so version 1.11 is the
/// literal digits 0x0111 and the little-endian wire order is `11 01`. Read the other way the
/// same octets are 0x1101 — version 11.01 — which a host may refuse outright. Arriving at
/// "1.11" from `01 11` requires reading the value big-endian and the digits as decimal, two
/// errors that cancel in the prose and not on the wire.
#[test]
fn hid_information_is_a_little_endian_version_then_country_then_flags() {
    let bytes = initial_bytes(0x2A4A);
    assert_eq!(bytes, vec![0x11, 0x01, 0x00, 0x02]);
    assert_eq!(bytes.len(), 4, "HID Information is exactly four octets");

    let bcd_hid = u16::from_le_bytes([bytes[0], bytes[1]]);
    assert_eq!(bcd_hid, 0x0111, "bcdHID 0x0111 is HID 1.11 in BCD");
    assert_eq!(bytes[2], 0x00, "bCountryCode 0 means not localised");
    assert_eq!(bytes[3] & 0b10, 0b10, "flags bit 1: NormallyConnectable");

    assert!(has_property(0x2A4A, "read"), "HID Information is read-only");
}

/// The Report Map (0x2A4B) is the USB HID report descriptor, and it is the one characteristic
/// a host *must* read correctly: everything it later receives is interpreted through it. A
/// descriptor that does not parse makes every report meaningless.
///
/// This asserts the descriptor's own framing rather than restating its bytes — it opens with
/// Usage Page (Generic Desktop) / Usage (Keyboard) / Collection (Application) and closes with
/// End Collection, with balanced collections in between.
#[test]
fn the_report_map_is_a_well_formed_hid_descriptor() {
    let d = initial_bytes(0x2A4B);
    assert!(
        d.len() > 8,
        "a HID report descriptor is not eight octets long"
    );

    assert_eq!(
        &d[0..3],
        &[0x05, 0x01, 0x09],
        "Usage Page (0x05 0x01) then Usage (0x09 ...)"
    );
    assert_eq!(d[3], 0x06, "Usage (Keyboard)");
    assert_eq!(&d[4..6], &[0xA1, 0x01], "Collection (Application)");
    assert_eq!(
        *d.last().unwrap(),
        0xC0,
        "a descriptor ends with End Collection"
    );
    assert_eq!(
        d.iter().filter(|&&b| b == 0xA1).count(),
        d.iter().filter(|&&b| b == 0xC0).count(),
        "every Collection needs its End Collection"
    );

    assert!(
        has_property(0x2A4B, "read"),
        "the Report Map must be readable"
    );
}

/// A host that reads the Report Map and gets the Report's eight zero octets cannot parse any
/// report the device later sends — the whole profile is dead on arrival, silently. That is
/// what one fixed `respond_to_read` across three readable characteristics did here.
#[test]
fn the_report_map_and_the_report_are_not_the_same_bytes() {
    assert_ne!(
        initial_bytes(0x2A4B),
        initial_bytes(0x2A4D),
        "the report descriptor and a report are different things and must not share bytes"
    );
}

/// A `static` handler cannot see which characteristic a read is for, so one fixed
/// `respond_to_read` answers every readable characteristic in the service with the same bytes.
/// Where a service has more than one, that is a field-confusion bug: the central gets the wrong
/// characteristic's value carrying the right characteristic's units, and nothing looks wrong
/// until real hardware reads it.
///
/// The correct static answer for such a service is *no* action. `read_decision` maps an empty
/// list to `ReadDecision::UseStored`, so the base serves each characteristic's own stored value,
/// and a zero-action static handler still suppresses the LLM call.
#[test]
fn a_multi_readable_service_does_not_answer_every_read_with_one_fixed_value() {
    let readable: Vec<String> = characteristics()
        .iter()
        .filter(|c| {
            c["properties"]
                .as_array()
                .is_some_and(|p| p.iter().any(|v| v == "read"))
        })
        .map(|c| c["uuid"].as_str().unwrap_or("?").to_string())
        .collect();

    let example = BluetoothBlePresenterProtocol
        .get_startup_examples()
        .static_mode;
    let fixed_values: Vec<&Value> = example["event_handlers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|h| h["event_pattern"] == "bluetooth_read_request")
        .filter_map(|h| h["handler"]["actions"].as_array())
        .flatten()
        .filter(|a| a["type"] == "respond_to_read")
        .collect();

    if readable.len() > 1 {
        assert!(
            fixed_values.is_empty(),
            "{} readable characteristics ({readable:?}) but the static example answers every \
             read with a fixed value ({fixed_values:?}). Every one of those characteristics \
             would return the same bytes under a different characteristic's units. Use an empty \
             action list so the base serves each characteristic's stored value.",
            readable.len()
        );
    }
}

/// A `bluetooth_read_request` handler on a service with nothing readable is an answer to a
/// question that cannot be asked — it validates at startup and then never matches, in the
/// example a model copies.
#[test]
fn a_read_handler_implies_a_readable_characteristic() {
    let any_readable = characteristics().iter().any(|c| {
        c["properties"]
            .as_array()
            .is_some_and(|p| p.iter().any(|v| v == "read"))
    });

    let read_handlers = BluetoothBlePresenterProtocol
        .get_startup_examples()
        .static_mode["event_handlers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|h| h["event_pattern"] == "bluetooth_read_request")
        .count();

    if read_handlers > 0 {
        assert!(
            any_readable,
            "the static example routes bluetooth_read_request but declares no characteristic \
             with the `read` property, so that handler can never fire"
        );
    }
}

/// A script handler *can* see `characteristic_uuid`, which is the whole reason to reach for one
/// on a multi-readable service. One that never looks at it is the static bug wearing a different
/// hat: every characteristic gets the same bytes, under a different characteristic's units.
#[test]
fn a_multi_readable_service_does_not_script_one_answer_for_every_characteristic() {
    let readable = characteristics()
        .iter()
        .filter(|c| {
            c["properties"]
                .as_array()
                .is_some_and(|p| p.iter().any(|v| v == "read"))
        })
        .count();
    if readable <= 1 {
        return;
    }

    for mode in [
        BluetoothBlePresenterProtocol
            .get_startup_examples()
            .script_mode,
        BluetoothBlePresenterProtocol
            .get_startup_examples()
            .static_mode,
    ] {
        let Some(handlers) = mode["event_handlers"].as_array() else {
            continue;
        };
        for handler in handlers {
            if handler["event_pattern"] != "bluetooth_read_request" {
                continue;
            }
            let h = &handler["handler"];
            if h["type"] != "script" {
                continue;
            }
            let code = h["code"].as_str().unwrap_or("");
            assert!(
                code.contains("characteristic_uuid"),
                "a read script on a service with {readable} readable characteristics never \
                 reads `characteristic_uuid`, so it answers all of them alike: {code}"
            );
        }
    }
}

/// Every Python read script must actually put its answer on stdout. `python3 -c <code>` is run
/// unwrapped, and the executor requires stdout to be exactly one JSON value — so
/// `actions = [...]`, which every one of these examples used to be, assigns a local, prints
/// nothing, exits 0, and is treated as a failed handler that falls back to the LLM. The comment
/// above each example promises "no model call"; the example did the opposite.
#[test]
fn every_python_read_script_reads_stdin_and_prints_its_answer() {
    for mode in [
        BluetoothBlePresenterProtocol
            .get_startup_examples()
            .script_mode,
        BluetoothBlePresenterProtocol
            .get_startup_examples()
            .static_mode,
    ] {
        let Some(handlers) = mode["event_handlers"].as_array() else {
            continue;
        };
        for handler in handlers {
            let h = &handler["handler"];
            if h["type"] != "script" || h["language"] != "python" {
                continue;
            }
            let code = h["code"].as_str().expect("a script handler carries code");
            assert!(
                code.contains("sys.stdin"),
                "a python handler that never reads stdin cannot see the event: {code}"
            );
            assert!(
                code.contains("print("),
                "a python handler that never prints produces empty stdout, which the executor \
                 treats as a failure and falls back to the LLM: {code}"
            );
        }
    }
}

//! Battery Service (0x180F) startup-example bytes, checked against the SIG layout.
//!
//! The startup examples in `actions.rs` are the GATT layout a model copies verbatim, and every
//! UUID and value byte in them is a literal nobody checks at runtime. A swapped-endian value or
//! a characteristic UUID one digit off still starts, still advertises and still answers reads —
//! it is wrong only in the eyes of a real central, which no test in this tree has. So the
//! literals are pinned here instead, against the published layout rather than against the
//! implementation, in the style of `tests/server/bluetooth_ble_beacon/payload_test.rs`.
//!
//! Sources: Bluetooth SIG Assigned Numbers (service and characteristic UUIDs) and
//! Battery Service 1.0, section 3.1 (Battery Level is a `uint8` percentage, 0-100).
//!
//! These tests need no Bluetooth adapter, so they are not `#[ignore]`d.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::llm::actions::protocol_trait::Protocol;
use netget::server::bluetooth_ble_battery::actions::BluetoothBleBatteryProtocol;
use serde_json::Value;

/// A 16-bit Bluetooth SIG alias in the 128-bit form the examples are written in.
fn sig(alias: u16) -> String {
    format!("{alias:08x}-0000-1000-8000-00805f9b34fb")
}

/// The `add_service` action inside the static-mode example's `bluetooth_ble_started` handler.
fn static_service() -> Value {
    let example = BluetoothBleBatteryProtocol
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
        Value::String(sig(0x180f)),
        "the static example must build the Battery Service (0x180F)"
    );
    assert_eq!(
        service["primary"],
        Value::Bool(true),
        "the Battery Service is a primary service"
    );

    // The advertisement must name the same service, or a central scanning for it never finds
    // this device — a mismatch no amount of correct GATT makes up for.
    let advertised = BluetoothBleBatteryProtocol
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
        serde_json::json!([sig(0x180f)]),
        "the advertisement must name the service the example just built"
    );
}

/// Battery Level (0x2A19) is one octet holding a percentage. `0x64` is 100, a full battery.
/// A two-octet value here, or `0x64` read as anything but 100, means the example is wrong.
#[test]
fn battery_level_is_one_octet_holding_a_percentage() {
    let bytes = initial_bytes(0x2A19);
    assert_eq!(
        bytes,
        vec![0x64],
        "Battery Level (0x2A19) is a single uint8; 100% is the one octet 0x64"
    );
    assert!(
        bytes[0] <= 100,
        "Battery Level is a percentage: the SIG reserves every value above 100, got {}",
        bytes[0]
    );
    assert!(
        has_property(0x2A19, "read"),
        "Battery Level must be readable; a central reads it rather than waiting to be told"
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

    let example = BluetoothBleBatteryProtocol
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

    let read_handlers = BluetoothBleBatteryProtocol
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
        BluetoothBleBatteryProtocol
            .get_startup_examples()
            .script_mode,
        BluetoothBleBatteryProtocol
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
        BluetoothBleBatteryProtocol
            .get_startup_examples()
            .script_mode,
        BluetoothBleBatteryProtocol
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

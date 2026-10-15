//! BLE file-transfer startup-example coherence, checked without a spec or an adapter.
//!
//! This profile's startup examples use **custom** UUIDs with no Bluetooth SIG layout behind
//! them, so there is no independent specification to check the value bytes against, and a test
//! that restated them would assert only that the literals equal themselves. What *is* checkable
//! without a spec — and without a Bluetooth adapter — is whether the example is internally
//! coherent: whether the handlers it routes can ever match the service it builds.
//!
//! That is not a hypothetical. This example used to route `bluetooth_read_request` to a fixed
//! `respond_to_read` while both of its characteristics were write/notify — a handler that
//! could never match anything, sitting in the example as if it worked.
//!
//! These tests need no Bluetooth adapter, so they are not ignored.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::llm::actions::protocol_trait::Protocol;
use netget::server::bluetooth_ble_file_transfer::actions::BluetoothBleFileTransferProtocol;
use serde_json::Value;

fn handlers() -> Vec<Value> {
    BluetoothBleFileTransferProtocol
        .get_startup_examples()
        .static_mode["event_handlers"]
        .as_array()
        .expect("the static example declares event_handlers")
        .clone()
}

/// Every characteristic of the service the static example builds.
fn characteristics() -> Vec<Value> {
    handlers()
        .iter()
        .find(|h| h["event_pattern"] == "bluetooth_ble_started")
        .expect("the static example handles bluetooth_ble_started")["handler"]["actions"]
        .as_array()
        .expect("the started handler carries an action list")
        .iter()
        .find(|a| a["type"] == "add_service")
        .expect("the started handler adds a service")["characteristics"]
        .as_array()
        .expect("the service declares characteristics")
        .clone()
}

fn count_with_property(property: &str) -> usize {
    characteristics()
        .iter()
        .filter(|c| {
            c["properties"]
                .as_array()
                .is_some_and(|p| p.iter().any(|v| v == property))
        })
        .count()
}

fn handler_count(event: &str) -> usize {
    handlers()
        .iter()
        .filter(|h| h["event_pattern"] == event)
        .count()
}

/// Every `respond_to_read` the static example would answer a read with.
fn fixed_read_values() -> Vec<Value> {
    handlers()
        .iter()
        .filter(|h| h["event_pattern"] == "bluetooth_read_request")
        .filter_map(|h| h["handler"]["actions"].as_array())
        .flatten()
        .filter(|a| a["type"] == "respond_to_read")
        .cloned()
        .collect()
}

/// A `bluetooth_read_request` handler on a service with nothing readable is an answer to a
/// question that cannot be asked. It validates at startup, matches nothing, and sits in the
/// example a model copies verbatim looking like working configuration.
#[test]
fn a_read_handler_implies_a_readable_characteristic() {
    if handler_count("bluetooth_read_request") > 0 {
        assert!(
            count_with_property("read") > 0,
            "the static example routes bluetooth_read_request but no characteristic declares \
             the `read` property, so that handler can never fire. Characteristics: {:?}",
            characteristics()
                .iter()
                .map(|c| (
                    c["uuid"].as_str().unwrap_or("?").to_string(),
                    c["properties"].clone()
                ))
                .collect::<Vec<_>>()
        );
    }
}

/// The mirror of the above: a write handler needs somewhere to write.
#[test]
fn a_write_handler_implies_a_writable_characteristic() {
    if handler_count("bluetooth_write_request") > 0 {
        let writable = count_with_property("write") + count_with_property("write_without_response");
        assert!(
            writable > 0,
            "the static example routes bluetooth_write_request but no characteristic is \
             writable, so that handler can never fire"
        );
    }
}

/// The example must demonstrate *something*: a service nobody can read from or write to, with
/// no handler for either, is a layout rather than a working configuration.
#[test]
fn the_static_example_routes_an_event_its_service_can_actually_raise() {
    let routed = handler_count("bluetooth_read_request")
        + handler_count("bluetooth_write_request")
        + handler_count("bluetooth_subscribe");
    assert!(
        routed > 0,
        "the static example builds a service and advertises it but handles no traffic event, \
         so it demonstrates nothing a model could copy for the interesting half"
    );
}

/// A `static` handler cannot see which characteristic a read is for, so one fixed
/// `respond_to_read` answers every readable characteristic alike. Where a service has more than
/// one, that hands the central the wrong characteristic's bytes under the right
/// characteristic's units. The correct static answer there is an empty action list:
/// `read_decision` maps it to `ReadDecision::UseStored` and the base serves each
/// characteristic's own value, still without an LLM call.
#[test]
fn a_multi_readable_service_does_not_answer_every_read_with_one_fixed_value() {
    let readable = count_with_property("read");
    if readable > 1 {
        assert!(
            fixed_read_values().is_empty(),
            "{readable} readable characteristics but the static example answers every read \
             with a fixed value ({:?}); use an empty action list so the base serves each \
             characteristic's stored value",
            fixed_read_values()
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
        BluetoothBleFileTransferProtocol
            .get_startup_examples()
            .script_mode,
        BluetoothBleFileTransferProtocol
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
        BluetoothBleFileTransferProtocol
            .get_startup_examples()
            .script_mode,
        BluetoothBleFileTransferProtocol
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

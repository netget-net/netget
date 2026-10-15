//! The `decision=` tag on the one terminal outcome this profile decides for itself.
//!
//! # Why this is a unit-shaped test and not an end-to-end one
//!
//! This profile is a thin wrapper: it prepends a sentence describing the Heart Rate Service
//! (0x180D) and hands everything to `BluetoothBle::spawn_with_llm_actions`. Once the radio is
//! up, the base stack owns the event loop, so every `decision=` a read, write or subscribe
//! produces is emitted in `src/server/bluetooth_ble/mod.rs` against `BluetoothBleProtocol` —
//! including the ATT Unlikely Error (0x0E) the base replies with when a handler fails. There is
//! nothing in this profile for an end-to-end test to reach on that path.
//!
//! What the profile *does* own is the failure of the radio itself, and that path cannot be
//! driven deterministically from a test: on a machine with a working Bluetooth adapter it
//! succeeds, and on one without it fails. So the decision text is exercised directly, which is
//! the shape `tests/server/bluetooth_ble_beacon/llm_failure_test.rs` already uses for the same
//! reason.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::server::bluetooth_ble_heart_rate::radio_start_failure;

/// The radio refusal carries its own token, names the instance, and keeps the cause.
///
/// The token matters because nothing reaches the air on this path: a BLE Heart Rate Service
/// that never started and one whose handler declined to answer look identical to anyone who is
/// not reading the log.
#[test]
fn the_radio_refusal_is_tagged_and_names_the_instance() {
    let err = anyhow::anyhow!("Bluetooth adapter failed to power on after 10 seconds");
    let message = radio_start_failure("NetGet-HeartRate", &err);

    assert!(
        message.contains("decision=refused_adapter_unavailable"),
        "`grep decision=` is the one diagnostic this repo teaches, and an untagged line is \
         invisible to it: {message}"
    );
    assert!(
        message.contains("NetGet-HeartRate"),
        "a tag with no subject cannot be attributed to an instance: {message}"
    );
    assert!(
        message.contains("Bluetooth adapter failed to power on"),
        "the underlying cause must survive into the log: {message}"
    );
    assert!(
        message.contains("nothing is advertising"),
        "the consequence must be stated, not inferred - `Error` on its own reads as transient: \
         {message}"
    );
}

/// A radio that will not come up is not a backend failure, and must not be tagged as one.
///
/// No model is consulted on this path: the adapter fails before any event exists. Reusing
/// `fail_closed_llm_error` here would send someone to restart Ollama over a Bluetooth adapter
/// that is switched off, which is the exact confusion the vocabulary exists to prevent.
#[test]
fn the_radio_refusal_is_not_blamed_on_the_model() {
    let message = radio_start_failure("NetGet-HeartRate", &anyhow::anyhow!("no adapter"));

    assert!(
        !message.contains("decision=fail_closed_llm_error")
            && !message.contains("decision=fail_closed_llm_overloaded")
            && !message.contains("decision=model_"),
        "the radio path must not borrow a model-decision token: {message}"
    );
}

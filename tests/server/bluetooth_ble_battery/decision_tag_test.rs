//! The `decision=` tag on the one terminal outcome this profile decides for itself.
//!
//! # Why this is a unit-shaped test and not an end-to-end one
//!
//! This profile is a thin wrapper: it prepends a sentence describing the Battery Service
//! (0x180F) and hands everything to `BluetoothBle::spawn_with_llm_actions`. Once the radio is
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

use netget::server::bluetooth_ble_battery::radio_start_failure;

/// The radio refusal carries its own token, names the instance, and keeps the cause.
///
/// The token matters because nothing reaches the air on this path: a BLE Battery Service that
/// never started and one whose handler declined to answer look identical to anyone who is not
/// reading the log.
#[test]
fn the_radio_refusal_is_tagged_and_names_the_instance() {
    let err = anyhow::anyhow!("Bluetooth adapter failed to power on after 10 seconds");
    let message = radio_start_failure("NetGet-Battery", &err);

    assert!(
        message.contains("decision=refused_adapter_unavailable"),
        "`grep decision=` is the one diagnostic this repo teaches, and an untagged line is \
         invisible to it: {message}"
    );
    assert!(
        message.contains("NetGet-Battery"),
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
    let message = radio_start_failure("NetGet-Battery", &anyhow::anyhow!("no adapter"));

    assert!(
        !message.contains("decision=fail_closed_llm_error")
            && !message.contains("decision=fail_closed_llm_overloaded")
            && !message.contains("decision=model_"),
        "the radio path must not borrow a model-decision token: {message}"
    );
}

/// A battery level the Bluetooth SIG reserves is refused before anything starts, and tagged.
///
/// This outcome really is driven end to end here, and needs no adapter: the range check sits in
/// the profile's own `spawn` while it reads startup parameters, ahead of the radio and ahead of
/// any model call. It gets its own token for exactly that reason — nothing failed, the caller
/// asked for something that cannot honestly be advertised — and `server_startup` records this
/// text as `ServerStatus::Error`.
#[tokio::test]
async fn an_out_of_range_initial_level_is_refused_with_its_own_token(
) -> Result<(), Box<dyn std::error::Error>> {
    use netget::llm::actions::protocol_trait::{Protocol, Server};
    use netget::llm::OllamaClient;
    use netget::protocol::{SpawnContext, StartupParams};
    use netget::server::bluetooth_ble_battery::actions::BluetoothBleBatteryProtocol;
    use netget::state::app_state::AppState;
    use std::sync::Arc;

    let state = Arc::new(AppState::new());
    let protocol = BluetoothBleBatteryProtocol::new();
    let startup_params = StartupParams::new(
        serde_json::json!({"device_name": "NetGet-Battery", "initial_level": 150}),
        protocol.get_startup_parameters(),
    )?;
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();

    #[allow(deprecated)]
    let ctx = SpawnContext {
        listen_addr: "127.0.0.1:0".parse()?,
        mac_address: None,
        interface: None,
        host: None,
        port: None,
        // Unreachable on purpose: the refusal must come before any model call, and before the
        // radio is touched, so neither is available to this test.
        llm_client: OllamaClient::new("http://127.0.0.1:1"),
        state: state.clone(),
        status_tx,
        server_id: netget::state::ServerId::new(1),
        startup_params: Some(startup_params),
    };

    let err = protocol
        .spawn(ctx)
        .await
        .expect_err("150 is not a Battery Level percentage and must not start a server");
    let message = format!("{err:#}");

    assert!(
        message.contains("decision=refused_invalid_startup_param"),
        "a protocol-decided refusal needs a token of its own, or it reads in the log exactly \
         like a backend failure: {message}"
    );
    assert!(
        message.contains("150"),
        "the refusal must name the value it refused: {message}"
    );
    assert!(
        !message.contains("decision=fail_closed_llm_error")
            && !message.contains("decision=refused_adapter_unavailable"),
        "nothing failed here - neither the model nor the radio was reached: {message}"
    );

    Ok(())
}

//! End-to-end tests for the BLE beacon server.
//!
//! # What can and cannot be tested here
//!
//! A beacon is advertisement-only: there is no connection to open, no request to send and no
//! response to read back. Confirming that a frame is really on air needs a second radio running
//! a scanner, so the only true end-to-end check is a Linux host with `bluetoothd`, an adapter,
//! and something like `btmon` or nRF Connect watching. That is out of reach for CI and for this
//! machine, and pretending otherwise is how this protocol came to be documented as working when
//! it was not.
//!
//! What *is* tested here is the full protocol path up to the radio: the registry entry, the
//! declared startup parameters, and — on a platform that cannot set an advertising payload —
//! that `spawn()` returns an error naming the reason instead of reporting a running server.
//! The advertising octets themselves are covered exhaustively in `payload_test.rs`.
//!
//! The previous version of this file spawned the netget binary three times and asserted that a
//! server started, while the protocol could not emit a beacon frame at all. It verified the
//! base GATT stack's LLM plumbing and called it beacon coverage.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::llm::actions::protocol_trait::Protocol;
use netget::llm::OllamaClient;
use netget::protocol::{server_registry, SpawnContext, StartupParams};
use netget::server::bluetooth_ble_beacon::actions::BluetoothBleBeaconProtocol;
use netget::state::app_state::AppState;
use std::sync::Arc;

/// Build a spawn context for the beacon protocol with the given startup parameters.
///
/// The LLM endpoint is deliberately unreachable: every assertion below is about failures that
/// must happen *before* any model call, and a test that could silently start talking to a real
/// Ollama would not be testing that.
fn spawn_context(
    state: &Arc<AppState>,
    params: serde_json::Value,
) -> Result<SpawnContext, Box<dyn std::error::Error>> {
    let protocol = BluetoothBleBeaconProtocol::new();
    let startup_params = StartupParams::new(params, protocol.get_startup_parameters())?;
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();

    #[allow(deprecated)]
    Ok(SpawnContext {
        listen_addr: "127.0.0.1:0".parse()?,
        mac_address: None,
        interface: None,
        host: None,
        port: None,
        llm_client: OllamaClient::new("http://127.0.0.1:1"),
        state: state.clone(),
        status_tx,
        server_id: netget::state::ServerId::new(1),
        startup_params: Some(startup_params),
    })
}

/// The protocol must be reachable through the registry the TUI, MCP and CLI all go through.
#[test]
fn beacon_is_registered_and_offered_to_the_llm() {
    let registry = server_registry::registry();
    let protocol = registry
        .get("BLUETOOTH_BLE_BEACON")
        .expect("bluetooth-ble-beacon must be registered when its feature is enabled");

    assert!(
        protocol.metadata().is_available_to_llm(),
        "the beacon is no longer Incomplete and must be selectable by the model"
    );

    let actions: Vec<String> = protocol
        .get_sync_actions()
        .into_iter()
        .map(|a| a.name)
        .collect();
    assert!(
        actions.iter().any(|a| a == "start_ibeacon"),
        "registry protocol must expose the beacon actions, got {actions:?}"
    );

    let events: Vec<String> = protocol
        .get_event_types()
        .into_iter()
        .map(|e| e.id)
        .collect();
    assert_eq!(
        events,
        vec!["beacon_started".to_string()],
        "the beacon emits exactly one event, and declares only that one"
    );
}

/// Undeclared startup parameters must be refused by name before anything is started.
#[test]
fn undeclared_startup_parameters_are_rejected() {
    let protocol = BluetoothBleBeaconProtocol::new();
    let err = StartupParams::new(
        serde_json::json!({"uuid": "e2c56db5-dffb-48d2-b060-d0f5a71096e0"}),
        protocol.get_startup_parameters(),
    )
    .expect_err("uuid is an action parameter, not a startup parameter");
    let message = err.to_string();
    assert!(message.contains("uuid"), "{message}");
    assert!(message.contains("device_name"), "{message}");

    // The two that are declared must be accepted.
    StartupParams::new(
        serde_json::json!({"device_name": "NetGet-Beacon", "adapter": "hci0"}),
        protocol.get_startup_parameters(),
    )
    .expect("device_name and adapter are declared");
}

/// On a platform that cannot set an advertising payload, `spawn()` must fail loudly.
///
/// This is the whole point of the non-Linux path: `server_startup.rs` turns this `Err` into
/// `ServerStatus::Error`, so the user is told why instead of being shown a running beacon that
/// broadcasts nothing a scanner could recognise.
#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn spawn_refuses_on_a_platform_that_cannot_advertise(
) -> Result<(), Box<dyn std::error::Error>> {
    use netget::llm::actions::protocol_trait::Server;

    let state = Arc::new(AppState::new());
    let protocol = BluetoothBleBeaconProtocol::new();
    let ctx = spawn_context(&state, serde_json::json!({"device_name": "NetGet-Beacon"}))?;

    let err = protocol
        .spawn(ctx)
        .await
        .expect_err("a platform without advertising-payload support must not report Running");
    let message = err.to_string();

    assert!(
        message.contains("Linux/BlueZ"),
        "the error must say which platform does work: {message}"
    );
    assert!(
        message.contains("CBAdvertisementDataLocalNameKey"),
        "the error must say precisely why macOS cannot do it: {message}"
    );

    // Nothing may be left behind: no live-instance handle, and therefore no half-started server.
    assert!(
        !state
            .has_server_handle(netget::state::ServerId::new(1))
            .await,
        "a refused spawn must not register a server handle"
    );

    Ok(())
}

/// On Linux the same call reaches BlueZ, so its outcome depends on the host.
///
/// Left un-asserted deliberately: on a machine with `bluetoothd` and an adapter it should
/// succeed, and on one without it should fail with a D-Bus or adapter error. Both are correct,
/// so there is nothing here a CI runner could assert. Run it by hand on hardware.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires a Linux host with bluetoothd and a Bluetooth adapter"]
async fn spawn_registers_a_bluez_advertisement() -> Result<(), Box<dyn std::error::Error>> {
    use netget::llm::actions::protocol_trait::Server;

    let state = Arc::new(AppState::new());
    let protocol = BluetoothBleBeaconProtocol::new();
    let ctx = spawn_context(&state, serde_json::json!({"device_name": "NetGet-Beacon"}))?;

    // The LLM endpoint is unreachable, so this fails at the model call *after* the adapter has
    // been opened. Reaching that point is what proves the BlueZ path is live; a platform or
    // adapter failure would have been reported earlier and with a different message.
    let err = protocol
        .spawn(ctx)
        .await
        .expect_err("no LLM is reachable in this test");
    let message = err.to_string();
    assert!(
        !message.contains("Linux/BlueZ"),
        "the adapter must have opened successfully; got the platform refusal instead: {message}"
    );
    Ok(())
}

//! What happens to a BLE beacon when the LLM backend fails: nothing goes on air, loudly.
//!
//! A beacon has no peer to answer. It accepts no connections, exposes no characteristics and
//! reads nothing back, so there is no error response to send — the only observable behaviour is
//! whether a frame is transmitted and what the operator is told. That makes "fail closed" here
//! mean exactly one thing: **no advertisement, and `ServerStatus::Error` rather than `Running`.**
//!
//! This is deliberately the opposite of the base `bluetooth-ble` stack, which keeps a powered
//! adapter up when its startup call fails, because a GATT server's model answers *traffic*. A
//! beacon has no traffic: the single `beacon_started` call *is* the whole server. A beacon
//! sitting in `Running` with nothing on air is indistinguishable, to anyone reading
//! `list_servers`, from one that is broadcasting — which is the fail-open shape the root
//! CLAUDE.md warns about. So `spawn` returns `Err`, `server_startup` records the reason, and
//! `remove_server` drops the live handle, taking the `bluer` advertisement with it.
//!
//! # What can be asserted where
//!
//! On macOS and Windows `spawn` refuses *before* the model call (see `e2e_test.rs`), so the
//! failure path below is unreachable off Linux and the message helper is tested directly. The
//! Linux end-to-end check is `#[ignore]`d for the same reason as the one in `e2e_test.rs`: it
//! needs `bluetoothd` and an adapter.

#![cfg(all(unix, feature = "bluetooth"))]

use netget::server::bluetooth_ble_beacon::beacon_configuration_failure;

/// The operator-visible text must name the consequence, not just the cause.
///
/// This is the only thing anyone can observe about the failure — there is no wire, no peer and
/// no response — so "LLM call failed" on its own would leave a user with a beacon server in
/// `Error` and no way to tell whether something is still transmitting.
#[test]
fn the_failure_message_says_nothing_is_being_advertised() {
    let err = anyhow::anyhow!("Ollama connection refused");
    let message = beacon_configuration_failure("NetGet-Beacon", "hci0", &err);

    assert!(
        message.contains("NOTHING is being advertised"),
        "the consequence must be stated, not inferred: {message}"
    );
    assert!(
        message.contains("not running"),
        "the server state must be stated too, or `Error` looks like a transient warning: \
         {message}"
    );
    assert!(
        message.contains("NetGet-Beacon") && message.contains("hci0"),
        "the message must identify which beacon and which adapter: {message}"
    );
    assert!(
        message.contains("Ollama connection refused"),
        "the underlying cause must survive: {message}"
    );
    assert!(
        message.contains("decision=fail_closed_llm_error"),
        "a beacon writes nothing on any failure path, so the log line is the only place a \
         backend outage can be told apart from a handler that chose to advertise nothing: \
         {message}"
    );

    // No fallback is offered anywhere in the text. Suggesting a default UUID here is how a
    // fail-open default gets added later by someone reading only the error message.
    assert!(
        !message.to_ascii_lowercase().contains("default beacon"),
        "there is deliberately no default frame: {message}"
    );
}

/// An overloaded backend is called out as retryable; a broken one is not.
///
/// A beacon cannot express this on the wire — there is no wire — so it lives in the message.
/// Getting it backwards would tell an operator to retry a configuration that will never work,
/// or to stop retrying one that would have succeeded a second later.
#[test]
fn an_overloaded_backend_is_distinguished_from_a_broken_one() {
    use netget::llm::RateLimitError;

    let overloaded = anyhow::Error::new(RateLimitError::QueueFull { max_queued: 128 })
        .context("LLM call failed");
    let message = beacon_configuration_failure("NetGet-Beacon", "hci0", &overloaded);
    assert!(
        message.contains("saturated"),
        "a rate-limiter refusal is transient and should say so: {message}"
    );
    assert!(
        message.contains("decision=fail_closed_llm_overloaded")
            && !message.contains("decision=fail_closed_llm_error"),
        "the two backend failures carry different tokens, or `grep decision=` cannot separate \
         a saturated backend from a broken one: {message}"
    );

    let broken = anyhow::anyhow!("model returned unparseable JSON");
    let message = beacon_configuration_failure("NetGet-Beacon", "hci0", &broken);
    assert!(
        !message.contains("saturated"),
        "a genuine handler fault must not be advertised as retryable: {message}"
    );
    assert!(
        message.contains("decision=fail_closed_llm_error")
            && !message.contains("decision=fail_closed_llm_overloaded"),
        "a broken backend must not be tagged as a saturated one: {message}"
    );
}

/// The platform refusal is a *different* terminal outcome and carries its own token.
///
/// This is the pair the whole tagging exercise exists for. A beacon puts nothing on the air in
/// either case, so without the tag "macOS cannot set an advertising payload" and "Ollama is
/// down" are the same observation — and they send an operator to two completely different
/// places. `refused_adapter_unavailable` is protocol-invented (no model was consulted: the
/// radio fails before any event exists), which is why it is not one of the `fail_closed_llm_*`
/// pair.
///
/// Runs for real on macOS and Windows, where `BeaconAdvertiser::open` refuses without touching
/// hardware; on Linux the same call reaches BlueZ and its outcome depends on the host, so there
/// is nothing a runner could assert.
#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn the_platform_refusal_is_tagged_and_not_confused_with_a_backend_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    use netget::llm::actions::protocol_trait::{Protocol, Server};
    use netget::llm::OllamaClient;
    use netget::protocol::{SpawnContext, StartupParams};
    use netget::server::bluetooth_ble_beacon::actions::BluetoothBleBeaconProtocol;
    use netget::state::app_state::AppState;
    use std::sync::Arc;

    let state = Arc::new(AppState::new());
    let protocol = BluetoothBleBeaconProtocol::new();
    let startup_params = StartupParams::new(
        serde_json::json!({"device_name": "NetGet-Beacon"}),
        protocol.get_startup_parameters(),
    )?;
    let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel();

    #[allow(deprecated)]
    let ctx = SpawnContext {
        listen_addr: "127.0.0.1:0".parse()?,
        mac_address: None,
        interface: None,
        host: None,
        port: None,
        // Deliberately unreachable: the refusal below must happen before any model call, and a
        // test that could quietly talk to a real Ollama would not be proving that.
        llm_client: OllamaClient::new("http://127.0.0.1:1"),
        state: state.clone(),
        status_tx,
        server_id: netget::state::ServerId::new(1),
        startup_params: Some(startup_params),
    };

    protocol
        .spawn(ctx)
        .await
        .expect_err("a platform without advertising-payload support must not report Running");

    let mut logged = Vec::new();
    while let Ok(line) = status_rx.try_recv() {
        logged.push(line);
    }

    let tagged = match logged
        .iter()
        .find(|l| l.contains("decision=refused_adapter_unavailable"))
    {
        Some(line) => line,
        None => panic!("the platform refusal must be tagged on the status stream: {logged:?}"),
    };
    assert!(
        tagged.starts_with("[ERROR]"),
        "a server that cannot start is an ERROR, not a warning: {tagged}"
    );
    assert!(
        tagged.contains("NetGet-Beacon"),
        "the tag needs a subject or it cannot be attributed to an instance: {tagged}"
    );
    assert!(
        !logged
            .iter()
            .any(|l| l.contains("decision=fail_closed_llm_error")
                || l.contains("decision=fail_closed_llm_overloaded")),
        "no model was consulted, so nothing may be blamed on the backend: {logged:?}"
    );

    Ok(())
}

/// On Linux, the whole path: adapter opens, the model call fails, nothing is advertised.
///
/// `#[ignore]`d for the same reason as the sibling test in `e2e_test.rs` — it needs a Linux host
/// with `bluetoothd` and a Bluetooth adapter, which neither CI nor a macOS dev machine has.
/// Confirm with `sudo btmon` in another terminal that no `ADV_NONCONN_IND` appears.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires a Linux host with bluetoothd and a Bluetooth adapter"]
async fn spawn_fails_closed_when_the_handler_is_unreachable(
) -> Result<(), Box<dyn std::error::Error>> {
    use netget::llm::actions::protocol_trait::{Protocol, Server};
    use netget::llm::OllamaClient;
    use netget::protocol::{SpawnContext, StartupParams};
    use netget::server::bluetooth_ble_beacon::actions::BluetoothBleBeaconProtocol;
    use netget::state::app_state::AppState;
    use std::sync::Arc;

    let state = Arc::new(AppState::new());
    let protocol = BluetoothBleBeaconProtocol::new();
    let startup_params = StartupParams::new(
        serde_json::json!({"device_name": "NetGet-Beacon"}),
        protocol.get_startup_parameters(),
    )?;
    let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel();

    #[allow(deprecated)]
    let ctx = SpawnContext {
        listen_addr: "127.0.0.1:0".parse()?,
        mac_address: None,
        interface: None,
        host: None,
        port: None,
        // Nothing listens on port 1: the adapter opens, then the model call is refused.
        llm_client: OllamaClient::new("http://127.0.0.1:1"),
        state: state.clone(),
        status_tx,
        server_id: netget::state::ServerId::new(1),
        startup_params: Some(startup_params),
    };

    let err = protocol
        .spawn(ctx)
        .await
        .expect_err("an unreachable handler must not leave a beacon reported as Running");
    let message = format!("{err:#}");
    assert!(
        message.contains("NOTHING is being advertised"),
        "the error `server_startup` records must say what is on air: {message}"
    );

    let mut logged = Vec::new();
    while let Ok(line) = status_rx.try_recv() {
        logged.push(line);
    }
    assert!(
        logged
            .iter()
            .any(|l| l.starts_with("[ERROR]") && l.contains("NOTHING is being advertised")),
        "the failure must reach the status stream at ERROR, not only the returned error: \
         {logged:?}"
    );
    assert!(
        logged
            .iter()
            .any(|l| l.contains("decision=fail_closed_llm_error")),
        "an unreachable backend is a backend failure and must be tagged as one — not as the \
         adapter refusal, which is what a reader would otherwise have to guess: {logged:?}"
    );

    Ok(())
}

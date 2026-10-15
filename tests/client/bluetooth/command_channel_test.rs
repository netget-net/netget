//! The dashboard's `[ send ]` path on a Bluetooth LE client.
//!
//! **What this environment can and cannot check.** The BLE client needs a real adapter to start
//! at all (`Manager::adapters()` must return one), and every GATT verb additionally needs a
//! peripheral in radio range. There is no loopback BLE and no software peripheral, so the parts
//! that touch a device are `#[ignore]`d rather than faked.
//!
//! The always-running test adapts to whichever is true here:
//!
//! * No adapter — the client's connect fails and the only thing left to assert is rule 3: no
//!   stale command handle, and `send_to_client` refuses instead of hanging.
//! * An adapter — the client starts (its initial scan runs in its own task), so the injection
//!   half runs for real: an unknown verb comes back `Rejected`, and a GATT read with no
//!   peripheral connected comes back as an error naming that, never as a fake success.
//!
//! Zero LLM calls either way: the client's LLM points at `http://127.0.0.1:1`, so the scan-
//! complete call fails and the loop must tolerate it — which is the point, because the command
//! channel is registered before it.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bluetooth-ble-client --test client -- bluetooth::command_channel --test-threads=100

#![cfg(all(unix, feature = "bluetooth"))]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use tokio::sync::mpsc;

const BATTERY_SERVICE: &str = "0000180f-0000-1000-8000-00805f9b34fb";
const BATTERY_LEVEL: &str = "00002a19-0000-1000-8000-00805f9b34fb";

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "Bluetooth client #{} never registered a command handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn command_channel_follows_the_adapter() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // "scan" keeps the client alive on its scan/idle task instead of failing on a bogus
    // device address, so the handle stays registered for the whole test.
    let created = ClientForm {
        protocol: "bluetooth".to_string(),
        remote_addr: Some("scan".to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await;

    let client_id = match created {
        Err(e) => {
            for client in state.get_all_clients().await {
                assert!(
                    !state.has_client_handle(client.id).await,
                    "client #{} left a stale command handle after a failed adapter open",
                    client.id.as_u32()
                );
                let sent = state
                    .send_to_client(
                        client.id,
                        serde_json::json!({"type": "discover_services"}),
                        Duration::from_secs(2),
                    )
                    .await;
                assert!(
                    sent.is_err(),
                    "send_to_client must fail for a client with no handle, got {sent:?}"
                );
            }
            eprintln!("no BLE adapter here, injection half skipped: {e:#}");
            return;
        }
        Ok(id) => id,
    };

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_ble_verb"}),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Rejected { error } => assert!(
            error.contains("no_such_ble_verb"),
            "the rejection must name the verb, got {error:?}"
        ),
        other => panic!("expected Rejected{{..}}, got {other:?}"),
    }

    // No peripheral is connected, so a GATT read must surface that error rather than
    // reporting a success the caller cannot distinguish from a real read.
    let sent = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "read_characteristic",
                "service_uuid": BATTERY_SERVICE,
                "characteristic_uuid": BATTERY_LEVEL,
            }),
            Duration::from_secs(15),
        )
        .await;
    match sent {
        Err(e) => assert!(
            format!("{e:#}").contains("Not connected"),
            "the error must say no peripheral is connected, got {e:#}"
        ),
        Ok(other) => panic!("expected an error with no peripheral connected, got {other:?}"),
    }

    for entry in state
        .list_access_logs_for(Some(AccessLogOwner::Client(client_id.as_u32())), None)
        .await
    {
        if serde_json::to_string(&entry)
            .unwrap_or_default()
            .contains("injected_action")
        {
            return;
        }
    }
    panic!("injected actions must be recorded in the client's access log");
}

/// Requires a BLE peripheral in range. Set `NETGET_BLE_TEST_ADDRESS` to its address, and
/// `NETGET_BLE_TEST_SERVICE` / `NETGET_BLE_TEST_CHARACTERISTIC` to a writable characteristic on
/// it, then run with `--ignored`.
///
/// Ignored because btleplug has no software peripheral: a GATT write needs a real device.
#[tokio::test]
#[ignore = "requires a BLE peripheral in range (set NETGET_BLE_TEST_ADDRESS / _SERVICE / _CHARACTERISTIC)"]
async fn injected_gatt_write_reaches_a_real_peripheral() {
    let address = std::env::var("NETGET_BLE_TEST_ADDRESS").expect("set NETGET_BLE_TEST_ADDRESS");
    let service = std::env::var("NETGET_BLE_TEST_SERVICE").expect("set NETGET_BLE_TEST_SERVICE");
    let characteristic = std::env::var("NETGET_BLE_TEST_CHARACTERISTIC")
        .expect("set NETGET_BLE_TEST_CHARACTERISTIC");

    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "bluetooth".to_string(),
        remote_addr: Some(address),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("a BLE adapter must be present");

    wait_for_client_handle(&state, client_id).await;
    // Give the connect task time to reach the peripheral before writing.
    tokio::time::sleep(Duration::from_secs(10)).await;

    // 2 payload bytes. A completed GATT write is the one BLE verb that may claim Sent.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "write_characteristic",
                "service_uuid": service,
                "characteristic_uuid": characteristic,
                "value_hex": "beef",
            }),
            Duration::from_secs(20),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 2 }),
        "expected Sent{{2}}, got {outcome:?}"
    );
}

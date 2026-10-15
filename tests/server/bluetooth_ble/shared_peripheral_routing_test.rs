//! DEFECT 2 regression: routing on the process-wide shared BLE radio.
//!
//! `ble-peripheral-rust` serialises every `Peripheral` through one process-global CoreBluetooth
//! manager, so the second `Peripheral::new()` in a process gets a dead command channel and its
//! `is_powered()` never returns true — the second BLE server start burned ~10s and falsely
//! reported "adapter failed to power on" (IMPROVEMENTS item 2). NetGet now creates the radio once
//! (`BleHub` behind a `OnceCell`) and reuses it. Because there is then a single shared event
//! stream, a `BleRouter` fans each event out to the server that owns the characteristic.
//!
//! Acquiring the real shared radio needs a Bluetooth adapter and permission, which the E2E suite
//! covers under `#[ignore]`. The routing that makes reuse *correct* — the part with the actual
//! logic — needs no radio, so `BleRouter` holds no `Peripheral` and is exercised directly here:
//! register stub servers, dispatch events, assert who received what.

#![cfg(all(unix, feature = "bluetooth"))]

use ble_peripheral_rust::gatt::peripheral_event::{
    PeripheralEvent, PeripheralRequest, ReadRequestResponse, RequestResponse,
};
use netget::server::bluetooth_ble::BleRouter;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SERVICE: &str = "0000180d-0000-1000-8000-00805f9b34fb";
const CHAR_A: &str = "00002a37-0000-1000-8000-00805f9b34fb";
const CHAR_B: &str = "00002a19-0000-1000-8000-00805f9b34fb";
const CHAR_UNKNOWN: &str = "00002a6e-0000-1000-8000-00805f9b34fb";

/// A read request whose responder is thrown away — the routing test only cares which server
/// channel the event lands on, not the ATT reply.
fn read_request(char_uuid: &str) -> PeripheralEvent {
    let (responder, _resp_rx) = oneshot::channel::<ReadRequestResponse>();
    PeripheralEvent::ReadRequest {
        request: PeripheralRequest {
            client: "central".to_string(),
            service: uuid::Uuid::parse_str(SERVICE).unwrap(),
            characteristic: uuid::Uuid::parse_str(char_uuid).unwrap(),
        },
        offset: 0,
        responder,
    }
}

/// The characteristic UUID carried by a received event, lowercased, if it is a read request.
fn received_char(ev: &PeripheralEvent) -> Option<String> {
    match ev {
        PeripheralEvent::ReadRequest { request, .. } => {
            Some(request.characteristic.to_string().to_lowercase())
        }
        _ => None,
    }
}

#[tokio::test]
async fn read_is_routed_to_the_server_that_owns_the_characteristic() -> TestResult {
    let router = BleRouter::new();

    let (a_tx, mut a_rx) = mpsc::channel::<PeripheralEvent>(8);
    let (b_tx, mut b_rx) = mpsc::channel::<PeripheralEvent>(8);
    router.register_server(a_tx.clone());
    router.register_server(b_tx.clone());
    router.register_characteristic(CHAR_A, a_tx);
    router.register_characteristic(CHAR_B, b_tx);

    // Read on A's characteristic must reach A and only A.
    router.dispatch(read_request(CHAR_A)).await;

    let got = tokio::time::timeout(Duration::from_secs(2), a_rx.recv())
        .await?
        .ok_or("server A received nothing")?;
    assert_eq!(received_char(&got).as_deref(), Some(CHAR_A));
    assert!(
        b_rx.try_recv().is_err(),
        "server B owns a different characteristic and must not receive A's read"
    );

    // And symmetrically for B.
    router.dispatch(read_request(CHAR_B)).await;
    let got = tokio::time::timeout(Duration::from_secs(2), b_rx.recv())
        .await?
        .ok_or("server B received nothing")?;
    assert_eq!(received_char(&got).as_deref(), Some(CHAR_B));

    Ok(())
}

#[tokio::test]
async fn state_update_is_broadcast_to_every_live_server() -> TestResult {
    let router = BleRouter::new();

    let (a_tx, mut a_rx) = mpsc::channel::<PeripheralEvent>(8);
    let (b_tx, mut b_rx) = mpsc::channel::<PeripheralEvent>(8);
    router.register_server(a_tx);
    router.register_server(b_tx);

    router
        .dispatch(PeripheralEvent::StateUpdate { is_powered: true })
        .await;

    for (name, rx) in [("A", &mut a_rx), ("B", &mut b_rx)] {
        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await?
            .ok_or_else(|| format!("server {name} received no state update"))?;
        assert!(
            matches!(got, PeripheralEvent::StateUpdate { is_powered: true }),
            "server {name} should get the adapter state change"
        );
    }

    Ok(())
}

#[tokio::test]
async fn unowned_characteristic_falls_back_to_the_newest_live_server() -> TestResult {
    let router = BleRouter::new();

    let (a_tx, mut a_rx) = mpsc::channel::<PeripheralEvent>(8);
    let (b_tx, mut b_rx) = mpsc::channel::<PeripheralEvent>(8);
    // A registered first, B second: B is the newest, so it is the fallback target.
    router.register_server(a_tx);
    router.register_server(b_tx);

    router.dispatch(read_request(CHAR_UNKNOWN)).await;

    let got = tokio::time::timeout(Duration::from_secs(2), b_rx.recv())
        .await?
        .ok_or("newest server B should have received the unowned read")?;
    assert_eq!(received_char(&got).as_deref(), Some(CHAR_UNKNOWN));
    assert!(
        a_rx.try_recv().is_err(),
        "older server A must not receive the fallback"
    );

    Ok(())
}

#[tokio::test]
async fn a_stopped_owner_is_skipped_in_favour_of_a_live_server() -> TestResult {
    let router = BleRouter::new();

    // Server A owns CHAR_A but has stopped: its receiver is dropped, so its sender is closed.
    let (a_tx, a_rx) = mpsc::channel::<PeripheralEvent>(8);
    router.register_server(a_tx.clone());
    router.register_characteristic(CHAR_A, a_tx);
    drop(a_rx);

    // Server B is live.
    let (b_tx, mut b_rx) = mpsc::channel::<PeripheralEvent>(8);
    router.register_server(b_tx);

    // A read on CHAR_A must not vanish into the dead owner; it falls back to the live server.
    router.dispatch(read_request(CHAR_A)).await;

    let got = tokio::time::timeout(Duration::from_secs(2), b_rx.recv())
        .await?
        .ok_or("a dead owner must be skipped and the live server used instead")?;
    assert_eq!(received_char(&got).as_deref(), Some(CHAR_A));

    Ok(())
}

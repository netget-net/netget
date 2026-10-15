//! What a BLE central gets when the LLM backend fails: an ATT error response, not a value.
//!
//! BLE has no status line and no error document. What it has is the ATT error response, and the
//! only honest one available through `ble-peripheral-rust` is `UnlikelyError` (ATT error code
//! 0x0E) — there is no "temporarily unavailable" in the `RequestResponse` enum, so the overload
//! distinction that etcd and gRPC can express on the wire stays in the log here.
//!
//! Getting it wrong on a read is the more dangerous half. The success path falls back to the
//! characteristic's last cached value when the handler produced no `respond_to_read` action, so
//! answering `Success` on a *failure* would hand the central a stale reading it would treat as
//! current — the fail-open shape the root CLAUDE.md warns about, in a protocol where the value
//! is the whole payload. On a write the acknowledgement is the lie: an ATT Write Response means
//! "accepted", and the handler that would have accepted it never ran.
//!
//! # Why these tests drive the event loop directly
//!
//! Every test in `e2e_test.rs` is `#[ignore]`d, because a GATT read needs a Bluetooth adapter
//! *and* a second radio acting as a central, and under the project's standard
//! `--test-threads=100` they contend for the machine's single adapter and all time out. The
//! request/response paths under test here are entirely radio-independent: they run inside
//! `BluetoothBle::event_loop`, which consumes `PeripheralEvent`s from a channel and answers on a
//! `oneshot` responder. `BluetoothBle::run_event_loop_without_radio` exposes that loop with a
//! `ServerData` holding no `Peripheral`, so these tests exercise the real code with no hardware,
//! deterministically, in milliseconds.
//!
//! The LLM failure is forced by pointing the client at `127.0.0.1:1`, where nothing listens.
//! That is a connection refusal rather than an HTTP 500, but it arrives at exactly the same
//! place — `call_llm` returning `Err` — and it needs no mock harness, which cannot be used here
//! because starting the netget binary with a BLE server needs the adapter these tests avoid.

#![cfg(all(unix, feature = "bluetooth"))]

use ble_peripheral_rust::gatt::peripheral_event::{
    PeripheralEvent, PeripheralRequest, RequestResponse,
};
use netget::llm::ollama_client::OllamaClient;
use netget::server::bluetooth_ble::BluetoothBle;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Heart Rate Measurement (0x2A37) inside the Heart Rate Service (0x180D).
const SERVICE: &str = "0000180d-0000-1000-8000-00805f9b34fb";
const CHARACTERISTIC: &str = "00002a37-0000-1000-8000-00805f9b34fb";

fn peripheral_request() -> Result<PeripheralRequest, uuid::Error> {
    Ok(PeripheralRequest {
        client: "test-central".to_string(),
        service: uuid::Uuid::parse_str(SERVICE)?,
        characteristic: uuid::Uuid::parse_str(CHARACTERISTIC)?,
    })
}

/// Start the loop with an unreachable LLM endpoint. Returns the event sender and the status
/// stream, which is the "dual logging" half of the contract.
fn start_loop_with_unreachable_llm() -> (
    mpsc::Sender<PeripheralEvent>,
    mpsc::UnboundedReceiver<String>,
) {
    let (event_tx, event_rx) = mpsc::channel::<PeripheralEvent>(8);
    let (status_tx, status_rx) = mpsc::unbounded_channel::<String>();

    tokio::spawn(BluetoothBle::run_event_loop_without_radio(
        event_rx,
        ServerId::new(1),
        // Nothing listens on port 1, so the call is refused immediately rather than hanging.
        OllamaClient::new("http://127.0.0.1:1"),
        Arc::new(AppState::new()),
        status_tx,
        // No seeded GATT table: these tests are about the backend failing, not about the
        // stored-value fallback.
        Vec::new(),
    ));

    (event_tx, status_rx)
}

/// Drain whatever the status stream has produced so far.
fn drain(status_rx: &mut mpsc::UnboundedReceiver<String>) -> Vec<String> {
    let mut lines = Vec::new();
    while let Ok(line) = status_rx.try_recv() {
        lines.push(line);
    }
    lines
}

#[tokio::test]
async fn read_request_gets_an_att_error_and_no_fabricated_value() -> TestResult {
    let (event_tx, mut status_rx) = start_loop_with_unreachable_llm();

    let (responder, response) = oneshot::channel();
    event_tx
        .send(PeripheralEvent::ReadRequest {
            request: peripheral_request()?,
            offset: 0,
            responder,
        })
        .await?;

    let reply = tokio::time::timeout(Duration::from_secs(20), response)
        .await
        .map_err(|_| {
            "No ATT response within 20s - the server left the central's read unanswered, which \
             a real stack reports only after its own timeout"
        })??;

    assert_eq!(
        reply.response,
        RequestResponse::UnlikelyError,
        "an unreachable handler must produce an ATT error; `Success` would hand the central a \
         value the handler never authorised"
    );
    assert!(
        reply.value.is_empty(),
        "an ATT error response carries no attribute value, got {:?}",
        reply.value
    );

    let status = drain(&mut status_rx);
    assert!(
        status
            .iter()
            .any(|l| l.starts_with("[ERROR]") && l.contains(CHARACTERISTIC)),
        "the failure must reach the status stream at ERROR, naming the characteristic; got \
         {status:?}"
    );

    Ok(())
}

#[tokio::test]
async fn write_request_is_not_acknowledged_when_the_handler_is_unreachable() -> TestResult {
    let (event_tx, mut status_rx) = start_loop_with_unreachable_llm();

    let (responder, response) = oneshot::channel();
    event_tx
        .send(PeripheralEvent::WriteRequest {
            request: peripheral_request()?,
            value: vec![0x00, 0x48],
            offset: 0,
            responder,
        })
        .await?;

    let reply = tokio::time::timeout(Duration::from_secs(20), response)
        .await
        .map_err(|_| {
            "No ATT response within 20s - the server left the central's write unanswered"
        })??;

    assert_eq!(
        reply.response,
        RequestResponse::UnlikelyError,
        "an ATT Write Response means the value was accepted; a handler that never ran cannot \
         have accepted it"
    );

    let status = drain(&mut status_rx);
    assert!(
        status
            .iter()
            .any(|l| l.starts_with("[ERROR]") && l.contains(CHARACTERISTIC)),
        "the failure must reach the status stream at ERROR, naming the characteristic; got \
         {status:?}"
    );

    Ok(())
}

/// The two events with no responder must stay silent towards the radio — and loud in the log.
///
/// There is nothing to answer: an adapter state change is not a request, and a CCCD
/// subscription update is reported after the stack has already acknowledged the descriptor
/// write. Both used to be `let _ = call_llm_for_event(...)`, which discarded the error with no
/// log on either channel, so an outage that left a subscribed central waiting for notifications
/// that would never come was completely invisible.
#[tokio::test]
async fn responderless_events_are_logged_rather_than_swallowed() -> TestResult {
    let (event_tx, mut status_rx) = start_loop_with_unreachable_llm();

    event_tx
        .send(PeripheralEvent::StateUpdate { is_powered: true })
        .await?;
    event_tx
        .send(PeripheralEvent::CharacteristicSubscriptionUpdate {
            request: peripheral_request()?,
            subscribed: true,
        })
        .await?;

    // Both calls have to fail against 127.0.0.1:1 and be logged; poll rather than sleeping a
    // fixed amount so the test is not tied to how long a refused connection takes.
    let mut status = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        status.extend(drain(&mut status_rx));
        if status.iter().filter(|l| l.starts_with("[ERROR]")).count() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let errors: Vec<&String> = status.iter().filter(|l| l.starts_with("[ERROR]")).collect();
    assert!(
        errors.iter().any(|l| l.contains("state change")),
        "the adapter state change failure must be reported; got {status:?}"
    );
    assert!(
        errors.iter().any(|l| l.contains("subscription change")),
        "the subscription failure must be reported, because the central is now waiting for \
         notifications that were never configured; got {status:?}"
    );

    Ok(())
}

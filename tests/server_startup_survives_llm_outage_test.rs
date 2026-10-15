//! Starting a server must not require the LLM backend to be reachable.
//!
//! The model is needed to answer traffic, not to open a socket. Three protocols called
//! `call_llm` from inside `spawn()` and propagated the error with `?`, so an Ollama outage —
//! or simply a wrong `--ollama-url` — made `spawn()` return `Err` and the server never started
//! at all:
//!
//! * `nfc` — `nfc_server_started`, to configure the virtual tag's ATR and NDEF records
//! * `usb-smartcard` — `usb_smartcard_reader_ready`, to configure the card's ATR
//! * `bluetooth_ble` — `bluetooth_ble_started`, to add GATT services and start advertising
//!
//! All three now log the failure at ERROR on both channels and carry on. `nfc` and
//! `usb-smartcard` have real built-in defaults (tag type/UID/ATR, and `DEFAULT_ATR` with a card
//! inserted), so an unconfigured server is still a working one; `bluetooth_ble` has none, so it
//! comes up powered but advertising nothing and says exactly that. In every case a backend blip
//! no longer takes down a server that would have worked for every peer arriving afterwards.
//!
//! The LLM endpoint here is `http://127.0.0.1:1` — connection-refused on the first packet, so
//! this *is* the outage, not a simulation of one. Nothing external is contacted.
//!
//! ```bash
//! ./cargo-isolated.sh test --no-default-features --features nfc,usb-smartcard \
//!     --test server_startup_survives_llm_outage_test -- --test-threads=100
//! ```

#![cfg(unix)]

#[allow(unused_imports)]
use netget::state::app_state::AppState;
#[allow(unused_imports)]
use netget::state::server::ServerStatus;
#[allow(unused_imports)]
use std::sync::Arc;
#[allow(unused_imports)]
use std::time::Duration;

/// What the startup path recorded, probed **before** the server is torn down.
#[allow(dead_code)]
struct Started {
    status: ServerStatus,
    addr: Option<std::net::SocketAddr>,
    /// Whether the kernel completed a TCP handshake on `addr` while the server was still up.
    /// Probed inside the helper on purpose: `remove_server` aborts the accept loop, so a probe
    /// afterwards measures nothing.
    accepted: bool,
}

/// Start `protocol` through the real startup path with an unreachable LLM.
#[allow(dead_code)]
async fn start_with_no_llm(protocol: &str) -> Started {
    let state = Arc::new(AppState::new());
    // Nothing on this machine listens on port 1: every LLM call fails on connect.
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;

    let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let drain = tokio::spawn(async move {
        let mut rx = status_rx;
        while rx.recv().await.is_some() {}
    });

    let server_id = netget::cli::server_startup::start_server_from_action(
        &state,
        None,       // mac_address
        None,       // interface
        None,       // host — the protocol's declared default (loopback)
        Some(0u16), // ephemeral port
        protocol,
        false, // send_first
        None,  // initial_memory
        "startup must not depend on the LLM being up".to_string(),
        None, // startup_params
        None, // event_handlers
        None, // scheduled_tasks
        None, // feedback_instructions
        status_tx,
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "{protocol} refused to start with the LLM unreachable: {e:#}\n\
             Opening a socket must not require the model backend. Log the configuration \
             failure and carry on instead of propagating it out of spawn()."
        )
    });

    let server = state.get_server(server_id).await.expect("server recorded");
    let status = server.status.clone();
    let addr = server.local_addr;

    let accepted = addr
        .map(|a| std::net::TcpStream::connect_timeout(&a, Duration::from_secs(2)).is_ok())
        .unwrap_or(false);

    state.remove_server(server_id).await;
    drain.abort();

    Started {
        status,
        addr,
        accepted,
    }
}

/// A socket-backed protocol must not only *start* without the LLM — it must be reachable.
/// Otherwise "Running" is the same lie the startup smoke test exists to catch.
#[allow(dead_code)]
fn assert_listening(protocol: &str, started: &Started) {
    assert!(
        matches!(started.status, ServerStatus::Running),
        "{protocol} must be Running after starting without an LLM, got {:?}",
        started.status
    );
    let addr = started.addr.unwrap_or_else(|| {
        panic!("{protocol} reported no endpoint; it binds a TCP listener and must report it")
    });
    assert!(
        started.accepted,
        "{protocol} says it is Running on {addr} but the port does not accept a connection"
    );
}

/// NFC keeps its built-in tag defaults when the configuration call fails, so it is fully
/// usable: every reader APDU goes through `call_llm` separately and fails closed on its own.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nfc_starts_and_listens_with_the_llm_unreachable() {
    let started = start_with_no_llm("nfc").await;
    assert_listening("nfc", &started);
}

/// Same for the USB smart card reader: `DEFAULT_ATR` and a card inserted are already in place
/// before the configuration call, so the reader is exportable over USB/IP regardless.
#[cfg(all(unix, feature = "libusb"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn usb_smartcard_starts_and_listens_with_the_llm_unreachable() {
    let started = start_with_no_llm("usb-smartcard").await;
    assert_listening("usb-smartcard", &started);
}

/// BLE has no socket, so the assertion is weaker by necessity: it must reach `Running` rather
/// than `Error`. It needs a powered adapter, so it is `#[ignore]`d and — when invoked with
/// `--ignored` on a machine without one — **fails loudly** rather than skipping. A skip that
/// reads as a pass is the failure mode this repo keeps hitting.
///
/// It **has** been run: on macOS with a powered adapter it passes (`--ignored`), reaching
/// `Running` with no endpoint reported. It stays `#[ignore]`d because CI has no adapter.
#[cfg(all(unix, feature = "bluetooth"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a powered Bluetooth adapter; run with --ignored"]
async fn bluetooth_ble_starts_with_the_llm_unreachable() {
    assert!(
        netget::privilege::SystemCapabilities::detect().has_bluetooth_access,
        "bluetooth_ble_starts_with_the_llm_unreachable requires a reachable Bluetooth adapter \
         and this machine has none. It asserts nothing without one and must not report a pass."
    );

    let started = start_with_no_llm("bluetooth_ble").await;
    assert!(
        matches!(started.status, ServerStatus::Running),
        "bluetooth_ble must be Running after starting without an LLM, got {:?}",
        started.status
    );
    assert!(
        started.addr.is_none(),
        "BLE speaks to a radio, not a socket, so it must advertise no endpoint; got {:?}",
        started.addr
    );
}

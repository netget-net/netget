//! Removing an IS-IS client must stop its pcap capture loop.
//!
//! # The defect this guards
//!
//! The capture loop used to decide whether to keep going like this:
//!
//! ```ignore
//! if let Some(client) = runtime.block_on(app_state.get_client(client_id)) {
//!     if matches!(client.status, ClientStatus::Disconnected | ClientStatus::Error(_)) {
//!         break;
//!     }
//! }
//! ```
//!
//! That covers `stop_capture`, which *sets* `ClientStatus::Disconnected`. It does not cover
//! removing the client, because [`AppState::remove_client`] **deletes the entry**
//! (`inner.clients.remove(&id)`) rather than marking it. `get_client` then returns `None`,
//! the `if let` does not match, and the loop keeps running -- still capturing, still calling
//! the LLM on every IS-IS PDU -- until the process exits.
//!
//! Aborting the blocking task is not an available fix: Tokio cannot unwind a thread parked in
//! `pcap::Capture::next_packet()`. That is what `crate::utils::StopSignal` exists for, and
//! `crate::server::isis` already used it. The client now does too.
//!
//! # What these tests do and do not prove
//!
//! They are **privilege-independent**: neither opens a pcap handle, so neither exercises the
//! capture loop itself. What they pin down is the two facts the fix rests on, both of which
//! were wrong or unchecked before:
//!
//! 1. `remove_client` really does delete the entry, so a `Some`-only liveness poll is dead
//!    code. (Test one. If this ever changes to a status update, the old poll would start
//!    working and this test tells you why the belt-and-braces `None` arm exists.)
//! 2. A `StopSignal` registered the way `src/client/isis/mod.rs` registers it -- via
//!    `register_client_task(client_id, stop.park_task())` -- is actually tripped by
//!    `remove_client`. (Test two: this is the link that was missing.)
//!
//! Neither of those, on its own, would fail against the old code: test two registers its own
//! signal and would pass even if the client registered none. Test three closes that gap the
//! way this repo's other whole-tree ratchets do -- by reading the source -- and asserts that
//! `src/client/isis/mod.rs` really does create a `StopSignal`, poll it in the capture loop,
//! and hand `park_task()` to `register_client_task`. Whether the loop breaks when the flag is
//! set cannot be observed here without root and a real interface, so source is the honest
//! level to check it at.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features isis --test client -- isis::capture_stop --test-threads=100

#![cfg(all(unix, feature = "libpcap"))]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::ClientId;
use netget::utils::StopSignal;
use tokio::sync::mpsc;

/// An interface name no host has, so no capture is ever attempted and the test needs no
/// privileges. IS-IS is Ethernet-only and is rejected on loopback anyway.
const MISSING_INTERFACE: &str = "netget-no-such-if0";

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn new_isis_client(state: &AppState) -> ClientId {
    let (tx, _rx) = mpsc::unbounded_channel();
    // For the IS-IS client, `remote_addr` is the interface to capture on.
    ClientForm {
        protocol: "isis".to_string(),
        remote_addr: Some(MISSING_INTERFACE.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect("create isis client")
}

/// `remove_client` deletes the entry, so `get_client` returns `None` -- not a `Disconnected`
/// status. This is why the old liveness poll could never fire on this path.
#[tokio::test]
async fn remove_client_deletes_the_entry_rather_than_marking_it_disconnected() {
    let state = new_state().await;
    let client_id = new_isis_client(&state).await;

    assert!(
        state.get_client(client_id).await.is_some(),
        "precondition: the client exists before it is removed"
    );

    state.remove_client(client_id).await;

    assert!(
        state.get_client(client_id).await.is_none(),
        "remove_client must delete the entry; if this ever becomes a status update instead, \
         the capture loop's Some(..) arm starts mattering again"
    );
}

/// The link that was missing: a `StopSignal` handed to `register_client_task` as
/// `stop.park_task()` is tripped when the client is removed.
///
/// This is exactly the arrangement in `src/client/isis/mod.rs`. `remove_client` aborts the
/// registered task, Tokio drops its future, the guard's `Drop` sets the flag, and the capture
/// loop breaks at its next poll.
#[tokio::test]
async fn removing_the_client_trips_the_capture_stop_signal() {
    let state = new_state().await;
    let client_id = new_isis_client(&state).await;

    let stop = StopSignal::new();
    state
        .register_client_task(client_id, stop.park_task())
        .await;

    assert!(
        !stop.is_stopped(),
        "precondition: the signal is untripped while the client is alive"
    );

    state.remove_client(client_id).await;

    // The abort takes effect when the runtime next drops the task's future, so poll rather
    // than assuming it has already happened.
    for _ in 0..1_000 {
        if stop.is_stopped() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!(
        "remove_client must trip the capture StopSignal; without this the pcap loop keeps \
         running -- and keeps calling the LLM -- after the client is gone"
    );
}

/// The half the runtime tests cannot see: that the client actually *uses* the arrangement
/// above. Without this, both tests above pass against a client that registers no signal at
/// all -- which is precisely the state the code was in.
///
/// Source-level, in the style of `tests/client_event_wiring_test.rs` and
/// `tests/event_emit_sites_test.rs`.
#[test]
fn the_isis_client_registers_and_polls_a_capture_stop_signal() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/client/isis/mod.rs"),
    )
    .expect("read src/client/isis/mod.rs");

    assert!(
        src.contains("StopSignal::new()"),
        "the IS-IS client must create a StopSignal; aborting the blocking capture task \
         cannot stop a thread parked in next_packet()"
    );
    assert!(
        src.contains("is_stopped()"),
        "the capture loop must poll the StopSignal every iteration, or the flag is never read"
    );
    assert!(
        src.contains("register_client_task(client_id, stop.park_task())"),
        "the parked task must be registered, or remove_client has nothing to abort and the \
         flag is never tripped"
    );
    assert!(
        src.contains(".timeout(1000)"),
        "the capture must keep its pcap read timeout: the loop only polls the flag when the \
         blocking read returns, so without it shutdown is unbounded on an idle interface"
    );
}

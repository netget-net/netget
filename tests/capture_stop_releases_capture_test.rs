//! Regression guard: stopping a packet-capture server must actually stop the capture.
//!
//! `arp`, `datalink`, `icmp` and `isis` ran their loop in a detached
//! `tokio::task::spawn_blocking` whose `JoinHandle` was **discarded**. Nothing was registered
//! with `AppState::register_server_task`, and there was no shutdown signal of any kind, so on a
//! host with the privileges to actually run them (root, `/dev/bpf*` on macOS/BSD, `CAP_NET_RAW`
//! on Linux) `stop_server` left the capture running until the process exited — still capturing,
//! still calling the LLM for every packet, while the operator believed it had stopped.
//!
//! The startup smoke test cannot catch this: on an unprivileged machine these protocols
//! correctly *refuse to start*, so the sweep never reaches the stop path. That is precisely why
//! it survived every previous audit of this family.
//!
//! Registering the handle is necessary but **not sufficient**, and that is the subtle part:
//! `JoinHandle::abort()` cannot interrupt a thread parked inside `pcap::Capture::next_packet()`
//! or `Socket::recv_from()`. Tokio can only cancel a task at an await point, and a blocking
//! loop has none. The fix is therefore two pieces that must both be present:
//!
//! 1. a [`StopSignal`] the blocking loop polls every iteration, and
//! 2. a parked Tokio task registered via `register_server_task` that trips the signal when it
//!    is aborted — so the existing stop plumbing drives it with no new API.
//!
//! # What runs where
//!
//! | Test | Privilege | Asserts |
//! |---|---|---|
//! | `stop_signal_ends_a_blocking_loop_when_the_server_is_removed` | none | the mechanism: `remove_server` → abort → flag → blocking loop exits |
//! | `a_dropped_park_task_handle_does_not_trip_the_signal` | none | the signal is tripped by cancellation, not by mere detachment |
//! | `arp_capture_stops_when_the_server_is_removed` | capture | the real ARP capture loop exits |
//! | `datalink_capture_stops_when_the_server_is_removed` | capture | the real DataLink capture loop exits |
//! | `isis_capture_stops_when_the_server_is_removed` | capture | the real IS-IS capture loop exits |
//! | `icmp_receive_loop_stops_when_the_server_is_removed` | raw sockets (root) | the real ICMP receive loop exits |
//!
//! The four privileged tests are `#[ignore]`d, so cargo reports them as *ignored* and never as
//! passed. When they are invoked (`--ignored`) on a process that lacks the privilege they
//! **fail loudly** rather than skipping: a skip that reads as a pass is the exact failure mode
//! this codebase keeps hitting.
//!
//! **They have not been run.** The machine this was written on is macOS with
//! `crw------- root:wheel /dev/bpf*` and no root, and `sudo` was not available; the mechanism
//! tests below are what *is* verified. Run the privileged half with:
//!
//! ```bash
//! sudo -E ./cargo-isolated.sh test --no-default-features --features arp,datalink,icmp,isis \
//!     --test capture_stop_releases_capture_test -- --ignored --test-threads=100
//! ```

use netget::utils::StopSignal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[allow(unused_imports)]
use netget::llm::ollama_client::OllamaClient;
#[allow(unused_imports)]
use netget::privilege::SystemCapabilities;
#[allow(unused_imports)]
use netget::state::app_state::AppState;
#[allow(unused_imports)]
use netget::state::server::ServerInstance;
#[allow(unused_imports)]
use netget::state::ServerId;

// ---------------------------------------------------------------------------
// The mechanism, with no privileges at all.
//
// These do not touch pcap or a raw socket. They pin the *stop path* — the part that was
// missing — against a stand-in blocking loop shaped exactly like the four real ones: a
// synchronous `loop` on a `spawn_blocking` thread that polls the signal between reads.
// ---------------------------------------------------------------------------

/// The end-to-end mechanism, driven through the real `AppState` plumbing rather than by
/// calling `StopSignal::stop()` directly — calling `stop()` would prove only that an
/// `AtomicBool` works.
///
/// `register_server_task` + `remove_server` is the path `stop_server` and the MCP
/// `stop_server` tool take, so this asserts the thing that actually happens when a user stops
/// one of these servers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stop_signal_ends_a_blocking_loop_when_the_server_is_removed() {
    let state = Arc::new(AppState::new());
    let server = ServerInstance::new(
        ServerId::new(0),
        0,
        "capture-stub".to_string(),
        String::new(),
    );
    let server_id = state.add_server(server).await;

    let stop = StopSignal::new();
    let stop_in_loop = stop.clone();

    // Stands in for `next_packet()` / `recv_from()`: a synchronous loop on a blocking thread
    // that Tokio cannot cancel, polling the signal between (simulated) reads.
    let exited = Arc::new(AtomicBool::new(false));
    let exited_in_loop = exited.clone();
    let iterations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let iterations_in_loop = iterations.clone();
    let blocking = tokio::task::spawn_blocking(move || {
        loop {
            if stop_in_loop.is_stopped() {
                break;
            }
            iterations_in_loop.fetch_add(1, Ordering::SeqCst);
            // The blocking read's own timeout. pcap uses 1000ms; ICMP sleeps 10ms on
            // WouldBlock. 5ms keeps the test fast without changing the shape.
            std::thread::sleep(Duration::from_millis(5));
        }
        exited_in_loop.store(true, Ordering::SeqCst);
    });

    state
        .register_server_task(server_id, stop.park_task())
        .await;

    assert_eq!(
        state.server_task_count(server_id).await,
        1,
        "the capture server must register exactly one shutdown task; a discarded JoinHandle is \
         the defect this file exists for"
    );

    // Let it actually spin, so "it exited" cannot be an artefact of never having started.
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(
        !exited.load(Ordering::SeqCst),
        "the loop must still be running before the server is stopped"
    );
    let spun = iterations.load(Ordering::SeqCst);
    assert!(spun > 0, "the loop never iterated; it is not under test");

    state.remove_server(server_id).await;

    // Abort → the parked future is dropped → its guard trips the flag → the loop breaks at its
    // next poll. Generous bound: on the real protocols this is one pcap read timeout.
    let joined = tokio::time::timeout(Duration::from_secs(5), blocking).await;
    assert!(
        joined.is_ok(),
        "the blocking loop did not exit within 5s of remove_server(); a discarded JoinHandle or \
         a loop that never polls the stop signal both look exactly like this, and both leave the \
         capture running until the process exits"
    );
    joined.unwrap().expect("blocking task panicked");
    assert!(
        exited.load(Ordering::SeqCst),
        "the loop's exit path did not run"
    );
}

/// The signal must be tripped by **cancellation**, not by the handle merely going out of
/// scope. Dropping a `JoinHandle` in Tokio only detaches the task — that is the whole reason
/// the four protocols leaked in the first place, and a `StopSignal` that tripped on drop would
/// paper over a `register_server_task` call that was forgotten again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_park_task_handle_does_not_trip_the_signal() {
    let stop = StopSignal::new();
    drop(stop.park_task());

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !stop.is_stopped(),
        "dropping the handle detaches the task; it must not read as a stop, or a protocol that \
         forgets register_server_task would appear to work"
    );

    // …and an explicit stop still works, so the flag is not simply stuck.
    stop.stop();
    assert!(stop.is_stopped());
}

// ---------------------------------------------------------------------------
// The real capture loops. Privileged, `#[ignore]`d, and loud when the privilege is absent.
// ---------------------------------------------------------------------------

/// Loopback under whichever name this platform uses. Matches `DEFAULT_LOOPBACK_INTERFACE`.
#[allow(dead_code)]
fn loopback() -> &'static str {
    if cfg!(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )) {
        "lo0"
    } else {
        "lo"
    }
}

/// Loud, unmissable refusal. These tests are `#[ignore]`d, so the only way to reach this is
/// `--ignored`, i.e. someone explicitly asked for the privileged test. Failing is then the
/// honest answer: skipping would report a pass for a test that verified nothing.
#[allow(dead_code)]
fn require_capture(test: &str) {
    assert!(
        SystemCapabilities::detect().has_packet_capture_access,
        "{test} requires layer-2 packet capture access and this process does not have it \
         (macOS/BSD: read access to /dev/bpf*, via sudo or Wireshark's ChmodBPF; Linux: root or \
         `setcap cap_net_raw+ep`). It asserts nothing without it and must not report a pass."
    );
}

#[allow(dead_code)]
fn require_raw_sockets(test: &str) {
    assert!(
        SystemCapabilities::detect().has_raw_socket_access,
        "{test} requires raw IP socket access (SOCK_RAW) and this process does not have it \
         (macOS/BSD: root; Linux: root or CAP_NET_RAW). It asserts nothing without it and must \
         not report a pass."
    );
}

/// A server registered in state, plus an LLM endpoint that is deliberately unroutable: these
/// tests never process a packet, so reaching a model would itself be a failure.
#[allow(dead_code)]
async fn harness(
    protocol: &str,
) -> (
    OllamaClient,
    Arc<AppState>,
    tokio::sync::mpsc::UnboundedSender<String>,
    tokio::sync::mpsc::UnboundedReceiver<String>,
    ServerId,
) {
    let state = Arc::new(AppState::new());
    let server = ServerInstance::new(ServerId::new(0), 0, protocol.to_string(), String::new());
    let server_id = state.add_server(server).await;
    let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel();
    (
        OllamaClient::new("http://127.0.0.1:1"),
        state,
        status_tx,
        status_rx,
        server_id,
    )
}

/// Wait for the capture loop to announce that it is stopping.
///
/// The loop's exit is otherwise unobservable from outside the process — it owns its own
/// thread and its handle is inside `AppState`. Every one of the four emits a `… stopping`
/// status line on the way out, on the same `status_tx` the TUI reads, so that line *is* the
/// observable and asserting on it is asserting on what a user would see.
#[allow(dead_code)]
async fn await_stop_message(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    needle: &str,
    within: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(line)) => {
                if line.contains(needle) {
                    return true;
                }
            }
            // Sender gone: the capture task dropped `status_tx`, which only happens when it
            // returned. That is the outcome under test, so it counts.
            Ok(None) => return true,
            Err(_) => return false,
        }
    }
}

/// Assert the shared shape: a live capture registers exactly one shutdown task, and removing
/// the server ends the loop within a bounded time.
///
/// `within` is generous because the pcap protocols only poll the stop flag when
/// `next_packet()` returns, i.e. at most one read timeout (1000ms) after the abort.
#[allow(dead_code)]
async fn assert_stops(
    state: &Arc<AppState>,
    server_id: ServerId,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    needle: &str,
    protocol: &str,
) {
    assert_eq!(
        state.server_task_count(server_id).await,
        1,
        "{protocol} must register its shutdown task with register_server_task(); without it \
         stop_server cannot reach the blocking loop at all"
    );

    state.remove_server(server_id).await;

    assert!(
        await_stop_message(rx, needle, Duration::from_secs(10)).await,
        "{protocol}'s capture loop did not stop within 10s of remove_server(). It is still \
         capturing and still calling the LLM; the operator has been told it stopped."
    );
}

#[cfg(all(unix, feature = "libpcap"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs layer-2 capture access (/dev/bpf* or CAP_NET_RAW); run with --ignored"]
async fn arp_capture_stops_when_the_server_is_removed() {
    require_capture("arp_capture_stops_when_the_server_is_removed");
    let (llm, state, status_tx, mut status_rx, server_id) = harness("arp").await;

    netget::server::ArpServer::spawn_with_llm(
        loopback().to_string(),
        llm,
        state.clone(),
        status_tx,
        server_id,
    )
    .await
    .expect("ARP capture should start with capture privileges");

    assert_stops(&state, server_id, &mut status_rx, "stopping", "ARP").await;
}

#[cfg(all(unix, feature = "libpcap"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs layer-2 capture access (/dev/bpf* or CAP_NET_RAW); run with --ignored"]
async fn datalink_capture_stops_when_the_server_is_removed() {
    require_capture("datalink_capture_stops_when_the_server_is_removed");
    let (llm, state, status_tx, mut status_rx, server_id) = harness("datalink").await;

    netget::server::DataLinkServer::spawn_with_llm(
        loopback().to_string(),
        llm,
        state.clone(),
        status_tx,
        None,
        server_id,
    )
    .await
    .expect("DataLink capture should start with capture privileges");

    assert_stops(&state, server_id, &mut status_rx, "stopping", "DataLink").await;
}

#[cfg(all(unix, feature = "libpcap"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs layer-2 capture access (/dev/bpf* or CAP_NET_RAW); run with --ignored"]
async fn isis_capture_stops_when_the_server_is_removed() {
    require_capture("isis_capture_stops_when_the_server_is_removed");
    let (llm, state, status_tx, mut status_rx, server_id) = harness("isis").await;

    netget::server::IsisServer::spawn_with_llm_actions(
        loopback().to_string(),
        llm,
        state.clone(),
        status_tx,
        server_id,
        None,
    )
    .await
    .expect("IS-IS capture should start with capture privileges");

    assert_stops(&state, server_id, &mut status_rx, "stopping", "IS-IS").await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs raw IP socket access (root, or CAP_NET_RAW on Linux); run with --ignored"]
async fn icmp_receive_loop_stops_when_the_server_is_removed() {
    require_raw_sockets("icmp_receive_loop_stops_when_the_server_is_removed");
    let (llm, state, status_tx, mut status_rx, server_id) = harness("icmp").await;

    netget::server::IcmpServer::spawn_with_llm(
        loopback().to_string(),
        llm,
        state.clone(),
        status_tx,
        server_id,
    )
    .await
    .expect("ICMP raw sockets should open with raw socket privileges");

    assert_stops(&state, server_id, &mut status_rx, "stopping", "ICMP").await;
}

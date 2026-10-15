//! Regression guard: a packet-capture server must never report `Running` while capturing
//! nothing.
//!
//! ARP, DataLink and ICMP each shipped a `spawn()` that fired the privileged open off inside
//! `tokio::task::spawn_blocking` and returned `Ok(..)` before the result was known. On a machine
//! without `/dev/bpf*` access (macOS/BSD) or `CAP_NET_RAW` (Linux) the blocking task logged an
//! error and returned, while `server_startup` had already recorded `ServerStatus::Running`. The
//! user saw a healthy server that could not possibly see a packet. All three were fixed
//! individually — and **IS-IS, which has exactly the same shape, was missed each time**. This
//! file exists so the fourth recurrence is a failing test rather than another audit finding.
//!
//! The invariant under test is not "capture works" (that needs privileges nobody has in CI); it
//! is the far cheaper and far more important one: **`spawn()` must not return `Ok` unless the
//! privileged resource is genuinely open.** Both branches are asserted, so the test has teeth
//! whether or not the runner is privileged:
//!
//! * privileged  → `spawn()` returns `Ok` and the capture is live;
//! * unprivileged → `spawn()` returns `Err` naming the resource that could not be opened.
//!
//! A regression to fire-and-forget fails the unprivileged branch immediately, which is the
//! branch every developer machine and every CI runner takes.
//!
//! No Ollama is needed: nothing here gets far enough to emit an event.
//!
//! ```bash
//! cargo test --no-default-features --features arp,datalink,isis,icmp \
//!   --test capture_startup_reports_failure_test -- --test-threads=100
//! ```

#![cfg(unix)]

#[allow(unused_imports)]
use netget::llm::ollama_client::OllamaClient;
#[allow(unused_imports)]
use netget::privilege::SystemCapabilities;
#[allow(unused_imports)]
use netget::state::app_state::AppState;
#[allow(unused_imports)]
use netget::state::ServerId;
#[allow(unused_imports)]
use std::sync::Arc;

/// An interface name no host has. Used to prove the failure is *reported*, not swallowed —
/// this branch needs no privileges at all, because device lookup happens before the open.
#[allow(dead_code)]
const NO_SUCH_DEVICE: &str = "netget-no-such-device0";

/// Loopback under whichever name this platform uses.
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

/// Fresh state plus an LLM endpoint that is deliberately unroutable: reaching it would mean a
/// packet was processed, which none of these tests get far enough to do.
#[allow(dead_code)]
fn harness() -> (
    OllamaClient,
    Arc<AppState>,
    tokio::sync::mpsc::UnboundedSender<String>,
    tokio::sync::mpsc::UnboundedReceiver<String>,
    ServerId,
) {
    let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel();
    (
        OllamaClient::new("http://127.0.0.1:1"),
        Arc::new(AppState::new()),
        status_tx,
        status_rx,
        ServerId::new(0),
    )
}

// ---------------------------------------------------------------------------
// DataLink
// ---------------------------------------------------------------------------

#[cfg(all(unix, feature = "libpcap"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datalink_spawn_reports_unknown_device() {
    use netget::server::DataLinkServer;

    let (llm, state, status_tx, _rx, server_id) = harness();
    let err = DataLinkServer::spawn_with_llm(
        NO_SUCH_DEVICE.to_string(),
        llm,
        state,
        status_tx,
        None,
        server_id,
    )
    .await
    .expect_err("spawn must not report success for a device that does not exist");

    let msg = format!("{:#}", err);
    assert!(
        msg.contains(NO_SUCH_DEVICE),
        "the error must name the device that could not be opened, got: {msg}"
    );
    assert!(
        msg.contains("no such capture device"),
        "expected the device-lookup failure to propagate, got: {msg}"
    );
}

#[cfg(all(unix, feature = "libpcap"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datalink_spawn_outcome_matches_capture_privilege() {
    use netget::server::DataLinkServer;

    let privileged = SystemCapabilities::detect().has_packet_capture_access;
    let (llm, state, status_tx, _rx, server_id) = harness();
    let result = DataLinkServer::spawn_with_llm(
        loopback().to_string(),
        llm,
        state,
        status_tx,
        None,
        server_id,
    )
    .await;

    assert_capture_outcome("DataLink", privileged, result);
}

// ---------------------------------------------------------------------------
// ARP
// ---------------------------------------------------------------------------

#[cfg(all(unix, feature = "libpcap"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn arp_spawn_reports_unknown_device() {
    use netget::server::ArpServer;

    let (llm, state, status_tx, _rx, server_id) = harness();
    let err =
        ArpServer::spawn_with_llm(NO_SUCH_DEVICE.to_string(), llm, state, status_tx, server_id)
            .await
            .expect_err("spawn must not report success for a device that does not exist");

    let msg = format!("{:#}", err);
    assert!(
        msg.contains(NO_SUCH_DEVICE) && msg.contains("no such capture device"),
        "the error must name the device that could not be opened, got: {msg}"
    );
}

/// ARP on loopback must **refuse**, and say why.
///
/// This used to go through `assert_capture_outcome`, which asserts "capture access implies
/// spawn succeeds". That holds for `datalink` and `isis` and is false for ARP: `arp` is an
/// Ethernet-only BPF keyword, and on a link type that cannot carry ARP — loopback is
/// DLT_NULL/DLT_LOOP — libpcap compiles it to "expression rejects all packets" and errors.
/// So on a host that *does* have `/dev/bpf*` access the old expectation failed, and on a host
/// without it the test passed for the unrelated reason that the open failed first. It was
/// green in CI and red on any developer machine with capture access.
///
/// Refusing is the correct behaviour, not a defect to route around: an ARP server on loopback
/// would sit in `ServerStatus::Running` having captured nothing, forever, which is the exact
/// failure the rest of this file exists to prevent. What was wrong is that the refusal named
/// libpcap's optimiser instead of the reason.
#[cfg(all(unix, feature = "libpcap"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn arp_spawn_refuses_loopback_and_says_why() {
    use netget::server::ArpServer;

    let privileged = SystemCapabilities::detect().has_packet_capture_access;
    let (llm, state, status_tx, _rx, server_id) = harness();
    let err = ArpServer::spawn_with_llm(loopback().to_string(), llm, state, status_tx, server_id)
        .await
        .expect_err("ARP cannot run on loopback: there is no Ethernet link layer to carry it");

    let msg = format!("{:#}", err);
    if privileged {
        // The capture opened, so the failure is the filter — and the message must explain
        // the link layer rather than quoting the optimiser.
        assert!(
            msg.contains("Ethernet-only") && msg.contains(loopback()),
            "the refusal must name the interface and why ARP cannot live on it, got: {msg}"
        );
    } else {
        // No capture access, so it never reached the filter.
        assert!(
            msg.contains("failed to open pcap capture"),
            "without capture access the refusal must be about opening the handle, got: {msg}"
        );
    }
}

// ---------------------------------------------------------------------------
// IS-IS — the one that was missed three times
// ---------------------------------------------------------------------------

#[cfg(all(unix, feature = "libpcap"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn isis_spawn_reports_unknown_device() {
    use netget::server::IsisServer;

    let (llm, state, status_tx, _rx, server_id) = harness();
    let err = IsisServer::spawn_with_llm_actions(
        NO_SUCH_DEVICE.to_string(),
        llm,
        state,
        status_tx,
        server_id,
        None,
    )
    .await
    .expect_err(
        "IS-IS spawn must not report success for a device that does not exist - this is the \
         fire-and-forget spawn_blocking bug that was fixed in ARP, DataLink and ICMP and missed \
         here",
    );

    let msg = format!("{:#}", err);
    assert!(
        msg.contains(NO_SUCH_DEVICE) && msg.contains("no such capture device"),
        "the error must name the device that could not be opened, got: {msg}"
    );
}

#[cfg(all(unix, feature = "libpcap"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn isis_spawn_outcome_matches_capture_privilege() {
    use netget::server::IsisServer;

    let privileged = SystemCapabilities::detect().has_packet_capture_access;
    let (llm, state, status_tx, _rx, server_id) = harness();
    let result = IsisServer::spawn_with_llm_actions(
        loopback().to_string(),
        llm,
        state,
        status_tx,
        server_id,
        None,
    )
    .await;

    assert_capture_outcome("IS-IS", privileged, result);
}

// ---------------------------------------------------------------------------
// ICMP — raw IP sockets rather than layer-2 capture, so a different capability
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn icmp_spawn_outcome_matches_raw_socket_privilege() {
    use netget::server::IcmpServer;

    // ICMP does not look a device up (its `interface` argument is accepted and ignored), so the
    // raw socket is the only thing that can fail - and it is exactly the thing that used to fail
    // invisibly.
    let privileged = SystemCapabilities::detect().has_raw_socket_access;
    let (llm, state, status_tx, _rx, server_id) = harness();
    let result =
        IcmpServer::spawn_with_llm(loopback().to_string(), llm, state, status_tx, server_id).await;

    match (privileged, result) {
        (true, Ok(_)) => {}
        (true, Err(e)) => panic!(
            "raw IP sockets are available on this host but ICMP spawn failed: {:#}",
            e
        ),
        (false, Ok(_)) => panic!(
            "ICMP spawn returned Ok without raw-socket privilege. The raw socket cannot have \
             opened, so this server would sit in ServerStatus::Running having received nothing - \
             the fire-and-forget spawn_blocking regression."
        ),
        (false, Err(e)) => {
            let msg = format!("{:#}", e);
            assert!(
                msg.contains("raw ICMP") && msg.contains("root"),
                "the refusal must name the raw socket and how to get it, got: {msg}"
            );
        }
    }
}

// ---------------------------------------------------------------------------

/// Assert the shared invariant for the three pcap-based protocols.
#[allow(dead_code)]
fn assert_capture_outcome(protocol: &str, privileged: bool, result: anyhow::Result<String>) {
    match (privileged, result) {
        (true, Ok(_)) => {}
        (true, Err(e)) => panic!(
            "{protocol}: this host has layer-2 capture access but spawn failed: {:#}",
            e
        ),
        (false, Ok(_)) => panic!(
            "{protocol}: spawn returned Ok without capture privilege. The pcap handle cannot \
             have opened, so this server would sit in ServerStatus::Running having captured \
             nothing. This is the fire-and-forget spawn_blocking regression."
        ),
        (false, Err(e)) => {
            let msg = format!("{:#}", e);
            assert!(
                msg.contains("failed to open pcap capture"),
                "{protocol}: the refusal must say the pcap handle could not be opened, got: {msg}"
            );
            assert!(
                msg.contains("/dev/bpf") || msg.contains("CAP_NET_RAW"),
                "{protocol}: the refusal must tell the user which privilege is missing, \
                 got: {msg}"
            );
        }
    }
}

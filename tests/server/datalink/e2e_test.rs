//! E2E tests for the DataLink (Layer 2) server.
//!
//! These drive `DataLinkServer::spawn_with_llm` **in process** rather than through the netget
//! binary. The previous version of this file spawned the binary against a mock Ollama and then
//! admitted, in a comment, that "mock verification is not possible in subprocess tests" - so its
//! three tests asserted nothing at all, called `verify_mocks()` never, and passed on a machine
//! where packet capture is impossible. The protocol was rated `Beta` on that suite.
//!
//! What is asserted here, and by which test:
//!
//! | Test | Privilege | Asserts |
//! |---|---|---|
//! | `datalink_unknown_interface_is_refused` | none | `spawn` returns `Err` naming the device |
//! | `datalink_startup_outcome_matches_capture_privilege` | none | `Ok` iff the pcap handle really opened |
//! | `datalink_invalid_bpf_filter_is_refused` | capture | a bad filter is `Err`, not a warning |
//! | `datalink_captures_a_real_loopback_frame` | capture | a UDP datagram's exact bytes reach the LLM path |
//!
//! The last two need `/dev/bpf*` (macOS/BSD) or `CAP_NET_RAW` (Linux) and are therefore
//! `#[ignore]`d: cargo reports them as *ignored*, never as passed, so an unprivileged run cannot
//! be mistaken for evidence that capture works. They have never been run; see the `notes` in
//! `src/server/datalink/actions.rs`, which is why the protocol is `Experimental` and not `Beta`.
//!
//! No Ollama is needed. The capture test answers `datalink_packet_captured` with a **static
//! handler**, which `call_llm` executes in-process, and points the LLM client at an unroutable
//! address so that reaching a model would itself be a failure.
//!
//! ```bash
//! ./cargo-isolated.sh test --no-default-features --features datalink \
//!     --test server -- server::datalink --test-threads=100
//! # privileged, on a machine where you have BPF access:
//! sudo -E ./cargo-isolated.sh test --no-default-features --features datalink \
//!     --test server -- server::datalink --ignored --test-threads=100
//! ```

#![cfg(all(unix, feature = "libpcap"))]

use netget::llm::ollama_client::OllamaClient;
use netget::privilege::SystemCapabilities;
use netget::scripting::{EventHandler, EventHandlerConfig, EventHandlerType, EventPattern};
use netget::server::DataLinkServer;
use netget::state::app_state::AppState;
use netget::state::server::ServerInstance;
use netget::state::ServerId;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// An interface name no host has.
const NO_SUCH_DEVICE: &str = "netget-no-such-device0";

/// Loopback under whichever name this platform uses. Matches
/// `DEFAULT_LOOPBACK_INTERFACE` in `src/server/datalink/actions.rs`.
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

/// Register a DataLink server whose capture events are answered by a static handler, so the
/// whole path runs with no model. The LLM endpoint is unroutable on purpose.
async fn harness() -> (
    OllamaClient,
    Arc<AppState>,
    UnboundedSender<String>,
    UnboundedReceiver<String>,
    ServerId,
) {
    let state = Arc::new(AppState::new());
    let server = ServerInstance::new(ServerId::new(0), 0, "datalink".to_string(), String::new());
    let server_id = state.add_server(server).await;

    let mut config = EventHandlerConfig::new();
    config.add_handler(EventHandler::new(
        EventPattern::specific("datalink_packet_captured"),
        EventHandlerType::static_response(vec![serde_json::json!({"type": "ignore_packet"})]),
    ));
    state
        .set_event_handler_config(server_id, Some(config))
        .await;

    let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel();
    (
        OllamaClient::new("http://127.0.0.1:1"),
        state,
        status_tx,
        status_rx,
        server_id,
    )
}

/// Whether this process can open a layer-2 capture handle at all.
fn can_capture() -> bool {
    SystemCapabilities::detect().has_packet_capture_access
}

/// Loud, unmissable refusal for the privileged tests.
///
/// These are `#[ignore]`d, so the only way to get here is `--ignored`, i.e. someone explicitly
/// asked for the privileged test. Failing is then the honest answer: skipping would report a
/// pass for a test that verified nothing, which is the exact defect this file replaced.
fn require_capture(test: &str) {
    assert!(
        can_capture(),
        "{test} requires layer-2 packet capture access and this process does not have it \
         (macOS/BSD: read access to /dev/bpf*, via sudo or Wireshark's ChmodBPF; Linux: root or \
         `setcap cap_net_raw+ep`). It asserts nothing without it and must not report a pass."
    );
}

// ---------------------------------------------------------------------------
// Unprivileged: the startup contract
// ---------------------------------------------------------------------------

/// A device that does not exist must be refused before `spawn` returns. Device lookup happens
/// before the privileged open, so this branch runs on every host.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datalink_unknown_interface_is_refused() {
    let (llm, state, status_tx, _rx, server_id) = harness().await;

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
        msg.contains("no such capture device") && msg.contains(NO_SUCH_DEVICE),
        "the error must name the device that could not be opened, got: {msg}"
    );
}

/// `spawn` returns `Ok` **iff** the pcap handle genuinely opened. Asserting both branches is
/// what gives this test teeth on an unprivileged runner: a return to the old fire-and-forget
/// `spawn_blocking` makes the unprivileged branch return `Ok` and fail here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datalink_startup_outcome_matches_capture_privilege() {
    let privileged = can_capture();
    let (llm, state, status_tx, _rx, server_id) = harness().await;

    let result = DataLinkServer::spawn_with_llm(
        loopback().to_string(),
        llm,
        state,
        status_tx,
        None,
        server_id,
    )
    .await;

    match (privileged, result) {
        (true, Ok(iface)) => assert_eq!(iface, loopback(), "spawn must report the bound device"),
        (true, Err(e)) => panic!(
            "this host has layer-2 capture access but DataLink spawn failed: {:#}",
            e
        ),
        (false, Ok(_)) => panic!(
            "DataLink spawn returned Ok without capture privilege. The pcap handle cannot have \
             opened, so the server would sit in ServerStatus::Running having captured nothing."
        ),
        (false, Err(e)) => {
            let msg = format!("{:#}", e);
            assert!(
                msg.contains("failed to open pcap capture") && msg.contains(loopback()),
                "the refusal must say which handle failed to open, got: {msg}"
            );
            assert!(
                msg.contains("/dev/bpf") || msg.contains("CAP_NET_RAW"),
                "the refusal must tell the user which privilege is missing, got: {msg}"
            );
        }
    }
}

/// What a captured frame looks like to the model, asserted against literal bytes.
///
/// `packet_event_data` is the payload builder the capture loop uses, and it is pure — so this
/// is the one thing about a pcap protocol that *can* be checked with no capture handle at all.
/// It is worth checking: a frame is up to 65535 bytes and used to be handed to the model whole,
/// which is 131070 characters of prompt for one packet.
#[test]
fn datalink_event_payload_reports_the_frame_and_any_truncation() {
    use netget::server::datalink::{packet_event_data, MAX_HEX_BYTES_TO_MODEL};

    // A minimal ARP request over Ethernet (RFC 826 payload), 42 bytes.
    const ARP: &str =
        "ffffffffffff001122334455080600010800060400010011223344550a0000010000000000000a000002";
    let frame = hex::decode(ARP).expect("literal test vector");

    let data = packet_event_data(&frame);
    assert_eq!(data["packet_hex"], ARP, "a short frame is reported whole");
    assert_eq!(data["packet_length"], 42);
    assert_eq!(data["captured_length"], 42);
    assert_eq!(data["truncated"], false);

    // Long frame: a prefix, and the event says so rather than silently misreporting the size.
    let long = vec![0x5au8; MAX_HEX_BYTES_TO_MODEL + 1];
    let data = packet_event_data(&long);
    assert_eq!(data["packet_length"], (MAX_HEX_BYTES_TO_MODEL + 1) as u64);
    assert_eq!(data["captured_length"], MAX_HEX_BYTES_TO_MODEL as u64);
    assert_eq!(data["truncated"], true);
    assert_eq!(
        data["packet_hex"].as_str().unwrap().len(),
        MAX_HEX_BYTES_TO_MODEL * 2
    );

    // Exactly at the boundary nothing is cut.
    assert_eq!(
        packet_event_data(&vec![0u8; MAX_HEX_BYTES_TO_MODEL])["truncated"],
        false
    );

    // Every field the payload carries must be one the event declares, or the model is shown a
    // value with no description and no type.
    let declared: Vec<String> = netget::server::datalink::actions::DATALINK_PACKET_CAPTURED_EVENT
        .parameters
        .iter()
        .map(|p| p.name.clone())
        .collect();
    for key in data.as_object().unwrap().keys() {
        assert!(
            declared.contains(key),
            "the event payload carries '{key}', which datalink_packet_captured does not declare \
             (declared: {declared:?})"
        );
    }
}

// ---------------------------------------------------------------------------
// Privileged: the capture itself
// ---------------------------------------------------------------------------

/// A BPF expression that does not compile must fail startup, not merely warn. libpcap only
/// parses a filter against an already-open handle, so this cannot be checked unprivileged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs layer-2 capture access (/dev/bpf* on macOS/BSD, CAP_NET_RAW on Linux): libpcap \
            compiles a BPF filter only against an open handle. Run under sudo with --ignored."]
async fn datalink_invalid_bpf_filter_is_refused() {
    require_capture("datalink_invalid_bpf_filter_is_refused");
    let (llm, state, status_tx, _rx, server_id) = harness().await;

    let err = DataLinkServer::spawn_with_llm(
        loopback().to_string(),
        llm,
        state,
        status_tx,
        Some("this is not a bpf filter".to_string()),
        server_id,
    )
    .await
    .expect_err("an uncompilable BPF filter must fail startup");

    let msg = format!("{:#}", err);
    assert!(
        msg.contains("invalid BPF filter"),
        "the error must identify the filter as the cause, got: {msg}"
    );
}

/// The real thing: libpcap must hand a frame we put on loopback to the event path, byte for
/// byte. The magic payload is asserted inside the captured hex, which is what the model would
/// receive as `packet_hex`.
///
/// Loopback is captured as DLT_NULL on macOS/BSD (4-byte address-family header) and as Ethernet
/// on Linux, so the assertion is deliberately about the *payload* bytes and not about framing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs layer-2 capture access (/dev/bpf* on macOS/BSD, CAP_NET_RAW on Linux). This is \
            the only test that proves DataLink captures anything; until it is run, the protocol \
            stays Experimental. Run under sudo with --ignored."]
async fn datalink_captures_a_real_loopback_frame() {
    require_capture("datalink_captures_a_real_loopback_frame");

    // Distinctive enough that it cannot appear in unrelated loopback chatter.
    const MAGIC: &[u8] = b"NETGET-DATALINK-CAPTURE-PROBE-7f3a";
    let magic_hex = hex::encode(MAGIC);

    let (llm, state, status_tx, mut status_rx, server_id) = harness().await;

    DataLinkServer::spawn_with_llm(
        loopback().to_string(),
        llm,
        state,
        status_tx,
        Some("udp".to_string()),
        server_id,
    )
    .await
    .expect("capture must start on a host with BPF access");

    // Give the blocking capture loop a moment to reach its first next_packet().
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Put the probe on loopback. The destination need not be listening: the datagram is on the
    // wire either way, which is all pcap cares about.
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback source socket");
    for _ in 0..5 {
        let _ = sock.send_to(MAGIC, "127.0.0.1:9").await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // The capture loop TRACEs every frame it received, and emits "packet processed" only after
    // the event has been through call_llm (here: the static handler). Both are required - the
    // first proves libpcap saw our bytes, the second proves they reached the LLM path.
    let mut saw_frame = false;
    let mut saw_processed = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    while tokio::time::Instant::now() < deadline && !(saw_frame && saw_processed) {
        match tokio::time::timeout_at(deadline, status_rx.recv()).await {
            Ok(Some(line)) => {
                if line.contains("Datalink data (hex)") && line.contains(&magic_hex) {
                    saw_frame = true;
                }
                if saw_frame && line.contains("Datalink packet processed") {
                    saw_processed = true;
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }

    assert!(
        saw_frame,
        "libpcap never delivered the probe datagram: no captured frame contained {magic_hex}"
    );
    assert!(
        saw_processed,
        "the captured frame never reached the event/LLM path (no 'Datalink packet processed')"
    );
}

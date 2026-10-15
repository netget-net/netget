//! The DataLink client's lifecycle and the dashboard's `[ send ]` path:
//! `AppState::send_to_client` injects an action from outside the client's pcap loop.
//!
//! Zero LLM calls — the client's LLM points at an unreachable URL, and the connected-event
//! turn it makes fails there without touching anything asserted here.
//!
//! # The split, and why it is where it is
//!
//! Raw frame injection goes through libpcap, which needs `/dev/bpf*` access on macOS/BSD or
//! root/`CAP_NET_RAW` on Linux. `connect()` now **awaits** that handle and returns `Err` when
//! it cannot be opened, so on an unprivileged host there is no live client to inject into —
//! which is the honest outcome, and is what [`datalink_client_refuses_an_interface_it_cannot_open`]
//! asserts on every host. Everything that needs a live capture is in
//! [`injected_frame_is_transmitted`], `#[ignore]`d, and it *fails loudly* rather than skipping
//! if it is run without the access it needs.
//!
//! The model-facing half — which frames `execute_action` accepts and refuses, and what the
//! event payloads look like — needs no client at all and lives in `action_test.rs`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features datalink --test client -- datalink::command_channel --test-threads=100
//!   # privileged half, on a host with BPF access:
//!   ./cargo-isolated.sh test --no-default-features --features datalink --test client -- datalink::command_channel --ignored

#![cfg(all(unix, feature = "libpcap"))]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::privilege::SystemCapabilities;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use tokio::sync::mpsc;

/// An interface name no host has, so `Device::list()` cannot match it and the capture never
/// opens — deterministically, with or without privileges.
const MISSING_INTERFACE: &str = "netget-no-such-if0";

/// A 56-byte Ethernet frame (broadcast destination, ARP ethertype, zero payload). Only
/// its length matters here - the outcome must report it back.
const FRAME_HEX: &str = "ffffffffffff0011223344550806000100000000000000000000000000000000000000000000000000000000000000000000000000000000";

fn loopback() -> &'static str {
    if cfg!(target_os = "linux") {
        "lo"
    } else {
        "lo0"
    }
}

/// Whether this process can open a layer-2 capture handle at all.
fn can_capture() -> bool {
    SystemCapabilities::detect().has_packet_capture_access
}

/// Loud, unmissable refusal for the privileged test.
///
/// It is `#[ignore]`d, so the only way to get here is `--ignored`, i.e. someone explicitly
/// asked for it. Failing is then the honest answer: skipping would report a pass for a test
/// that verified nothing.
fn require_capture(test: &str) {
    assert!(
        can_capture(),
        "{test} requires layer-2 packet capture access and this process does not have it \
         (macOS/BSD: read access to /dev/bpf*, via sudo or Wireshark's ChmodBPF; Linux: root or \
         `setcap cap_net_raw+ep`). It asserts nothing without it and must not report a pass."
    );
}

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn create_client(
    state: &AppState,
    interface: &str,
    tx: mpsc::UnboundedSender<String>,
) -> anyhow::Result<ClientId> {
    ClientForm {
        protocol: "datalink".to_string(),
        // Unused by this client (the interface is a startup parameter) but required by the
        // form; the pcap loop is what actually talks to the network.
        remote_addr: Some("127.0.0.1:0".to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(serde_json::json!({"interface": interface})),
        ..Default::default()
    }
    .create(
        state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "DataLink client #{} never registered a command handle",
        id.as_u32()
    );
}

/// Wait for a status line containing `needle` (lower-cased comparison).
async fn wait_for_status_line(rx: &mut mpsc::UnboundedReceiver<String>, needle: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(line)) => {
                if line.to_lowercase().contains(needle) {
                    return;
                }
            }
            Ok(None) => panic!("status channel closed before {needle:?} was seen"),
            Err(_) => panic!("timed out waiting for a status line containing {needle:?}"),
        }
    }
}

async fn wait_for_log_containing(state: &AppState, owner: AccessLogOwner, needle: &str) {
    for _ in 0..1_000 {
        for entry in state.list_access_logs_for(Some(owner), None).await {
            if serde_json::to_string(&entry)
                .unwrap_or_default()
                .contains(needle)
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

// ---------------------------------------------------------------------------
// Unprivileged: the startup contract
// ---------------------------------------------------------------------------

/// A client whose interface cannot be opened must **fail to connect**, not report `Connected`
/// having opened nothing.
///
/// This is the capture family's notorious bug, and this client had it: the pcap work was
/// fire-and-forget `spawn_blocking`, so `connect` returned `Ok` while the blocking task was
/// still deciding whether the device even existed — and on a host with no BPF access it
/// returned `Ok` for a client that could never inject a byte. The dashboard drew it as
/// connected and `[ send ]` answered with an explanation instead of a frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datalink_client_refuses_an_interface_it_cannot_open() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let err = create_client(&state, MISSING_INTERFACE, tx)
        .await
        .expect_err("a device that does not exist must not produce a connected client");

    let msg = format!("{err:#}");
    assert!(
        msg.contains(MISSING_INTERFACE),
        "the error must name the device that could not be opened, got: {msg}"
    );

    // The instance is kept so the operator can see why, but it is in Error, and nothing
    // offers to send frames through it.
    let clients = state.get_all_clients().await;
    let client = clients
        .iter()
        .find(|c| c.protocol_name.eq_ignore_ascii_case("datalink"))
        .expect("the failed client is still listed so the operator can see the error");
    assert!(
        matches!(client.status, ClientStatus::Error(_)),
        "expected ClientStatus::Error, got {:?}",
        client.status
    );
    assert!(
        !state.has_client_handle(client.id).await,
        "a client with no capture handle must not advertise [ send ]"
    );
}

/// The privileged path is the only one that can put a frame on a wire, so the unprivileged run
/// must not silently look like it covered it. This asserts the split itself: on a host without
/// capture access `connect` fails for the *loopback* interface too, with a message that says
/// which privilege is missing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_outcome_on_loopback_matches_capture_privilege() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let result = create_client(&state, loopback(), tx).await;

    match (can_capture(), result) {
        (true, Ok(id)) => {
            wait_for_client_handle(&state, id).await;
            state.remove_client(id).await;
        }
        (true, Err(e)) => panic!(
            "this host has layer-2 capture access but the DataLink client failed to open {}: {e:#}",
            loopback()
        ),
        (false, Ok(_)) => panic!(
            "the DataLink client connected without capture privilege. libpcap cannot have \
             opened, so the client would sit in Connected unable to inject anything."
        ),
        (false, Err(e)) => {
            let msg = format!("{e:#}");
            assert!(
                msg.contains("/dev/bpf") || msg.contains("CAP_NET_RAW"),
                "the refusal must tell the user which privilege is missing, got: {msg}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Privileged: injection, honest outcomes, and shutdown
// ---------------------------------------------------------------------------

/// With a real capture open: an injected frame is acknowledged by the pcap loop and the
/// outcome carries the real frame length; refusals stay refusals; the injection is recorded on
/// the client's access log; and `disconnect` really stops the capture.
///
/// **That last assertion is not decoration.** The pcap loop had no exit path at all: it ran
/// until the process died, holding the capture handle after the client was gone, and this test
/// did not fail so much as *hang* — the runtime's `BlockingPool::shutdown` waited forever for a
/// `loop { … thread::sleep(10ms) }` that nothing could stop. If it hangs again, that is back.
///
/// `#[ignore]` because opening a pcap handle needs `/dev/bpf*` on macOS or `CAP_NET_RAW` on
/// Linux. Run it deliberately:
///
/// ```text
/// ./cargo-isolated.sh test --no-default-features --features datalink --test client -- \
///     datalink::command_channel::injected_frame_is_transmitted --ignored --exact
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs layer-2 capture access (/dev/bpf* on macOS/BSD, root or CAP_NET_RAW on Linux) \
            to open a libpcap handle and put a frame on the wire"]
async fn injected_frame_is_transmitted() {
    require_capture("injected_frame_is_transmitted");

    let state = new_state().await;
    let (tx, mut rx) = mpsc::unbounded_channel();

    let client_id = create_client(&state, loopback(), tx.clone())
        .await
        .expect("a host with capture access must be able to open loopback");
    wait_for_client_handle(&state, client_id).await;

    // The frame really goes out, and the outcome is the acknowledged byte count rather than a
    // guess made at the moment the command was queued.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "inject_frame", "frame_hex": FRAME_HEX}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client inject_frame");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent } if bytes_sent == FRAME_HEX.len() / 2),
        "expected Sent from an acknowledged pcap injection, got {outcome:?}"
    );

    // Recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // Undecodable hex is rejected by the protocol, not silently dropped or put on the wire.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "inject_frame", "frame_hex": "zzzz"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client bad hex");
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.to_lowercase().contains("hex")),
        "expected Rejected, got {outcome:?}"
    );

    // So is a verb the protocol does not know.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "inject_vlan_frame"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client unknown verb");
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("inject_vlan_frame")),
        "expected Rejected, got {outcome:?}"
    );

    // `disconnect` ends the command loop, drops the handle, marks the client disconnected -
    // and stops the pcap loop, which is what the status line below proves.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    // The blocking loop announces its own exit. Without a stop path this line never arrives
    // and the capture handle outlives the client.
    wait_for_status_line(&mut rx, "disconnected").await;

    for _ in 0..1_000 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
            state.remove_client(client_id).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "client should be Disconnected with no command handle; status={:?} has_handle={}",
        state.get_client(client_id).await.map(|c| c.status),
        state.has_client_handle(client_id).await
    );
}

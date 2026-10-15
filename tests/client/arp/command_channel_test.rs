//! The dashboard's `[ send ]` path on an ARP client, and the startup contract that decides
//! whether such a client exists at all.
//!
//! Zero LLM calls - the client's LLM points at an unreachable URL, so nothing here depends on
//! a model being reachable.
//!
//! # Why the unprivileged tests do not drive a live client
//!
//! ARP capture *and* injection go through libpcap, which needs root (or `/dev/bpf*` access on
//! macOS, `CAP_NET_RAW` on Linux), so no ordinary run can have a working ARP client. What is
//! covered without privilege is therefore split in two:
//!
//! * [`capture_that_never_opened_is_reported_as_an_error`] - `connect()` must return `Err`
//!   rather than reporting a `Connected` client that opened nothing. This is the client-side
//!   twin of `tests/capture_startup_reports_failure_test.rs`.
//! * [`injected_actions_the_protocol_cannot_build_are_refused`] - the rejection paths of the
//!   injected-command surface, asserted directly against `Client::execute_action`, which is
//!   the layer that actually decides them.
//!
//! The privileged half - the command handle registered before the started-event LLM call, and
//! `sendpacket` really putting 42 bytes on a wire, acknowledged back through the channel so
//! the outcome can be `Sent { bytes_sent: 42 }` - is
//! [`injected_arp_request_is_transmitted`], `#[ignore]`d because it needs root.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features arp --test client -- arp::command_channel --test-threads=100

#![cfg(all(unix, feature = "libpcap"))]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use tokio::sync::mpsc;

/// An interface name no host has, so `Device::list()` cannot match it and the pcap thread
/// never opens a handle - deterministically, with or without privileges.
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

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "ARP client #{} never registered a command handle",
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

/// A capture that cannot be opened must be reported, not papered over.
///
/// This is the client-side twin of `tests/capture_startup_reports_failure_test.rs`. That file
/// exists because ARP, DataLink and ICMP *servers* each shipped a `spawn()` that fired the
/// privileged pcap open off inside `spawn_blocking` and returned `Ok` before the result was
/// known, so the user saw a healthy server that could not possibly see a packet. The ARP
/// client had the same shape and was never covered: it reported `ClientStatus::Connected`
/// while its `spawn_blocking` task logged an error and returned.
///
/// There is no middle option, which is worth knowing before "fixing" this test by relaxing
/// it: `client_startup::connect_client` overwrites the status with `ClientStatus::Connected`
/// on **any** `Ok(..)` from `connect()`, so a client that returns `Ok` having opened nothing
/// is necessarily displayed as connected. The only honest report is an `Err`.
///
/// This branch needs no privileges — device lookup happens before the open — so it runs on
/// every developer machine and every CI runner, which is exactly the branch a regression to
/// fire-and-forget would break first.
#[tokio::test]
async fn capture_that_never_opened_is_reported_as_an_error() {
    let state = new_state().await;
    let (tx, mut rx) = mpsc::unbounded_channel();

    // For the ARP client, `remote_addr` is the interface to capture on.
    let err = ClientForm {
        protocol: "arp".to_string(),
        remote_addr: Some(MISSING_INTERFACE.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect_err("an ARP client whose capture cannot open must not report success");

    let text = format!("{err:#}");
    assert!(
        text.contains(MISSING_INTERFACE),
        "the error must name the device that could not be opened, got {text:?}"
    );

    // The reason also reaches the operator's status stream, not only the returned error.
    wait_for_status_line(&mut rx, "capture startup failed").await;

    // Nothing is left behind in `Connected`: the dashboard must not offer [ send ] into a
    // client that never opened a capture.
    for client in state.get_all_clients().await {
        assert!(
            !matches!(client.status, ClientStatus::Connected),
            "no ARP client should be left Connected, found #{} {:?}",
            client.id.as_u32(),
            client.status
        );
        assert!(
            !state.has_client_handle(client.id).await,
            "a failed ARP client must leave no command handle registered"
        );
    }
}

/// Every rejection path of the injected-command surface, asserted directly against the
/// protocol rather than through a half-started client.
///
/// This used to be covered by driving a client pointed at a nonexistent interface, which only
/// worked while such a client was allowed to exist. It no longer is (see the test above), so
/// the assertions move to the layer that actually decides them: `Client::execute_action` is
/// what turns an injected action into `Rejected` rather than swallowing it, and it needs no
/// socket, no interface and no privilege.
#[test]
fn injected_actions_the_protocol_cannot_build_are_refused() {
    use netget::client::arp::ArpClientProtocol;
    use netget::llm::actions::client_trait::Client;

    let protocol = ArpClientProtocol::new();

    // A verb the protocol does not know.
    let err = protocol
        .execute_action(serde_json::json!({"type": "send_rarp_request"}))
        .expect_err("an unknown verb must be refused");
    assert!(
        format!("{err:#}").contains("send_rarp_request"),
        "the refusal must name the verb, got {err:#}"
    );

    // Fields the protocol accepts as *present* but that cannot become a frame. This is
    // decided one layer down, in `build_packet_for_custom_result` - `execute_action` only
    // checks presence - so that is where the assertion belongs. The injected-command path
    // turns a `None` here into `Rejected { error }`.
    for (what, name, data) in [
        (
            "a MAC that is not a MAC",
            "send_arp_reply",
            serde_json::json!({
                "sender_mac": "not-a-mac",
                "sender_ip": "127.0.0.1",
                "target_mac": "aa:bb:cc:dd:ee:ff",
                "target_ip": "127.0.0.2",
            }),
        ),
        (
            "an IPv6 address where IPv4 is required",
            "send_arp_request",
            serde_json::json!({
                "sender_mac": "aa:bb:cc:dd:ee:ff",
                "sender_ip": "::1",
                "target_ip": "127.0.0.2",
            }),
        ),
        (
            "a MAC with the wrong number of octets",
            "send_arp_request",
            serde_json::json!({
                "sender_mac": "aa:bb:cc:dd:ee",
                "sender_ip": "127.0.0.1",
                "target_ip": "127.0.0.2",
            }),
        ),
    ] {
        assert!(
            netget::client::arp::build_packet_for_custom_result(name, &data).is_none(),
            "{what} must not produce a frame"
        );
    }

    // A well-formed request does build one, so the assertions above are not vacuous.
    let frame = netget::client::arp::build_packet_for_custom_result(
        "send_arp_request",
        &serde_json::json!({
            "sender_mac": "aa:bb:cc:dd:ee:ff",
            "sender_ip": "127.0.0.1",
            "target_ip": "127.0.0.2",
        }),
    )
    .expect("a well-formed send_arp_request must build a frame");
    assert_eq!(
        frame.len(),
        42,
        "Ethernet II header (14) + ARP for IPv4 (28)"
    );

    // A field that is missing outright is caught earlier, by `execute_action` itself.
    assert!(
        protocol
            .execute_action(serde_json::json!({
                "type": "send_arp_request",
                "sender_mac": "aa:bb:cc:dd:ee:ff",
            }))
            .is_err(),
        "a missing required field must be refused"
    );
}

/// The privileged half: with a real capture open, an injected ARP request is acknowledged by
/// the pcap injection thread and the outcome carries the real frame length (42 bytes: 14 of
/// Ethernet header + 28 of ARP).
///
/// `#[ignore]` because opening a pcap handle needs root on macOS (`/dev/bpf*`) and
/// `CAP_NET_RAW` on Linux. Run it deliberately:
///
/// ```text
/// sudo ./cargo-isolated.sh test --no-default-features --features arp --test client -- \
///     arp::command_channel::injected_arp_request_is_transmitted --ignored --exact
/// ```
#[tokio::test]
#[ignore = "requires root / CAP_NET_RAW to open a libpcap handle"]
async fn injected_arp_request_is_transmitted() {
    let loopback = if cfg!(target_os = "linux") {
        "lo"
    } else {
        "lo0"
    };

    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "arp".to_string(),
        remote_addr: Some(loopback.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create arp client");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_arp_request",
                "sender_mac": "aa:bb:cc:dd:ee:ff",
                "sender_ip": "127.0.0.1",
                "target_ip": "127.0.0.2",
            }),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client send_arp_request");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 42 }),
        "expected Sent{{42}} from an acknowledged pcap injection, got {outcome:?}"
    );
}

/// The dashboard's `[ send ]` surface, driven end to end without pcap.
///
/// `capture_that_never_opened_is_reported_as_an_error` above is the reason this test exists in
/// this shape. The command loop used to be reached by starting a client on an interface that
/// does not exist and injecting into the wreckage; a client like that is no longer allowed to
/// exist, so driving `ArpClient::command_loop` directly is what is left — and it is strictly
/// more coverage, because standing in for the pcap injection thread makes the `Sent` outcome
/// reachable without root. Every branch of `execute_injected_action` is asserted here except
/// the two pcap-thread-death cases, which need the real thread.
#[tokio::test]
async fn the_injected_command_surface_reports_every_outcome() {
    use netget::client::arp::{ArpClient, ArpClientProtocol, InjectedPacket};
    use std::sync::Arc;

    let state = Arc::new(new_state().await);
    let (tx, _rx) = mpsc::unbounded_channel();

    // A client entry to own the handle and the access log. It is never started: this test is
    // about the command loop, and starting one would need a capture.
    let client_id = state
        .add_client(netget::state::ClientInstance::new(
            netget::state::ClientId::new(0),
            MISSING_INTERFACE.to_string(),
            "arp".to_string(),
            "test client".to_string(),
        ))
        .await;

    let command_rx =
        netget::client::command_support::register_command_channel(&state, client_id).await;
    let (packet_tx, mut packet_rx) = mpsc::unbounded_channel::<InjectedPacket>();

    let loop_task = tokio::spawn(ArpClient::command_loop(
        command_rx,
        Arc::new(ArpClientProtocol::new()),
        packet_tx,
        client_id,
        state.clone(),
        tx.clone(),
    ));

    // Stand in for the pcap injection thread: acknowledge whatever arrives with the real
    // frame length, which is what makes `Sent { bytes_sent }` an honest number.
    let injector = tokio::spawn(async move {
        let mut frames: Vec<Vec<u8>> = Vec::new();
        while let Some(packet) = packet_rx.recv().await {
            let len = packet.frame.len();
            frames.push(packet.frame);
            if let Some(ack) = packet.ack {
                let _ = ack.send(Ok(len));
            }
        }
        frames
    });

    // A well-formed request really goes out, and the byte count is the frame's, not a guess.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_arp_request",
                "sender_mac": "aa:bb:cc:dd:ee:ff",
                "sender_ip": "127.0.0.1",
                "target_ip": "127.0.0.2",
            }),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client send_arp_request");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 42 }),
        "expected Sent with the real 42-byte frame length, got {outcome:?}"
    );

    // Recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // Fields the protocol accepts as present but that cannot become a frame: refused at the
    // command loop, not silently dropped and not reported as sent.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_arp_reply",
                "sender_mac": "not-a-mac",
                "sender_ip": "127.0.0.1",
                "target_mac": "aa:bb:cc:dd:ee:ff",
                "target_ip": "127.0.0.2",
            }),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client malformed send_arp_reply");
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("send_arp_reply")),
        "expected Rejected naming the action, got {outcome:?}"
    );

    // A verb the protocol does not know.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_rarp_request"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client unknown verb");
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("send_rarp_request")),
        "expected Rejected naming the verb, got {outcome:?}"
    );

    // `stop_capture` ends the loop, drops the handle and marks the client disconnected.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "stop_capture"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client stop_capture");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    loop_task.await.expect("the command loop must exit cleanly");
    let frames = injector.await.expect("injector task");
    assert_eq!(
        frames.len(),
        1,
        "only the well-formed request may reach the wire"
    );

    for _ in 0..1_000 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
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

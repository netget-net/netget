//! The dashboard's `[ send ]` path on a WireGuard client.
//!
//! **What this environment can and cannot check, stated plainly.** NetGet implements none of the
//! WireGuard protocol: this client orchestrates `defguard_wireguard_rs`, which creates and
//! configures a real network interface. That needs root, and on macOS additionally an external
//! `wireguard-go` binary. So `connect()` cannot succeed in a normal test process, and the
//! injection half of this feature cannot be exercised here at all. This file says so rather than
//! mocking an action or an event to manufacture a pass — the previous WireGuard test did exactly
//! that (it mocked a `wireguard_packet_received` event and a `log_packet` action that do not
//! exist) and it is why the protocol lost its Stable rating.
//!
//! What the always-running test checks is the one rule reachable without root: a client whose
//! interface was never configured must not be left offering `[ send ]`, and `send_to_client`
//! must refuse rather than hang. If someone moves `register_command_channel` above
//! `configure_interface`, this fails.
//!
//! The privileged half is `injected_status_query_reads_a_real_interface`, `#[ignore]`d, with the
//! exact outcome it must produce. Note that WireGuard can never report `Sent`: NetGet writes no
//! WireGuard packets, so every verb it has reads interface state or tears the interface down,
//! and `Executed` with a specific reading is the only truthful answer.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features wireguard --test client -- wireguard::command_channel --test-threads=100

#![cfg(unix)]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use tokio::sync::mpsc;

/// 32 zero bytes, base64 — a syntactically valid Curve25519 key, so the failure this test
/// observes is the privileged interface setup and not key parsing.
const ZERO_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

fn params() -> serde_json::Value {
    serde_json::json!({
        "server_public_key": ZERO_KEY,
        "server_endpoint": "127.0.0.1:51820",
        "client_address": "10.20.30.2/32",
        "allowed_ips": ["10.20.30.0/24"],
    })
}

#[tokio::test]
async fn unprivileged_connect_leaves_no_command_handle() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let created = ClientForm {
        protocol: "wireguard".to_string(),
        remote_addr: Some("127.0.0.1:51820".to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(params()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await;

    if let Ok(id) = created {
        // Only reachable as root with a working WireGuard backend. Do not pretend the
        // unprivileged assertion held; run the real thing instead.
        let _ = state.remove_client(id).await;
        eprintln!(
            "WireGuard client #{} actually came up (running privileged?) - \
             run injected_status_query_reads_a_real_interface with --ignored for the real check",
            id.as_u32()
        );
        return;
    }

    for client in state.get_all_clients().await {
        assert!(
            !state.has_client_handle(client.id).await,
            "client #{} left a stale command handle after the interface failed to configure",
            client.id.as_u32()
        );
        let sent = state
            .send_to_client(
                client.id,
                serde_json::json!({"type": "get_connection_status"}),
                Duration::from_secs(2),
            )
            .await;
        assert!(
            sent.is_err(),
            "send_to_client must fail for a client with no handle, got {sent:?}"
        );
    }
}

/// Requires root and a working WireGuard backend (kernel module on Linux, `wireguard-go` on
/// macOS). Run with `sudo ... --ignored`.
///
/// Ignored because `configure_interface` creates a real network interface; there is no
/// unprivileged or emulated path to it, and mocking one would assert nothing about the wire.
#[tokio::test]
#[ignore = "requires root and a working WireGuard backend (kernel module / wireguard-go)"]
async fn injected_status_query_reads_a_real_interface() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let client_id = ClientForm {
        protocol: "wireguard".to_string(),
        remote_addr: Some("127.0.0.1:51820".to_string()),
        instruction: Some("test client".to_string()),
        startup_params: Some(params()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("root and a WireGuard backend are required");

    for _ in 0..1_000 {
        if state.has_client_handle(client_id).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        state.has_client_handle(client_id).await,
        "the command handle must be registered before the wireguard_connected LLM call"
    );

    // Never Sent: this reads interface counters, it does not put packets on the wire.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "get_connection_status"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("get_connection_status") && detail.contains("tx_bytes"),
            "detail must carry the interface reading, got {detail:?}"
        ),
        other => panic!("expected Executed{{..}}, got {other:?}"),
    }

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
    assert!(
        !state.has_client_handle(client_id).await,
        "the handle must be dropped when the interface is torn down"
    );
}

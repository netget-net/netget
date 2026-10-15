//! The dashboard's `[ send ]` path on an ICMP client.
//!
//! ICMP needs a raw socket (`SOCK_RAW`/`IPPROTO_ICMP`), which is root/`CAP_NET_RAW` only, so
//! this file is split in two:
//!
//! * [`command_channel_wiring`] always runs. Without the capability the client cannot even
//!   be created, and what it asserts is the part of the contract that failure still has to
//!   honour: `connect()` returns `Err`, **no command handle is left registered**, and a
//!   later `send_to_client` fails fast with the "does not accept injected commands" error
//!   rather than hanging. That is rule 3 of the command-channel contract, and it is exactly
//!   the case that would strand a dead `[ send ]` row in the dashboard. With the capability
//!   the same test asserts the live wiring instead: the handle is registered, an unknown
//!   verb comes back `Rejected`, and `wait_for_more` comes back `Executed`.
//! * [`injected_echo_request_puts_a_packet_on_the_wire`] is `#[ignore]`d because it sends a
//!   real ICMP echo request and therefore genuinely needs the privilege. Run it with
//!   `sudo -E ... --ignored`.
//!
//! Zero LLM calls either way: the client's LLM points at an unreachable URL.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features icmp --test client -- icmp::command_channel --test-threads=100

#![cfg(unix)]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use tokio::sync::mpsc;

/// Can this process open the raw ICMP socket the client needs?
fn has_raw_socket_capability() -> bool {
    Socket::new(Domain::IPV4, Type::RAW, Some(SocketProtocol::ICMPV4)).is_ok()
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

async fn create_client(state: &AppState) -> anyhow::Result<ClientId> {
    let (tx, _rx) = mpsc::unbounded_channel();
    ClientForm {
        protocol: "ICMP".to_string(),
        remote_addr: Some("127.0.0.1".to_string()),
        instruction: Some("test client".to_string()),
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
        "ICMP client #{} never registered a command handle",
        id.as_u32()
    );
}

#[tokio::test]
async fn command_channel_wiring() {
    let state = new_state().await;
    let privileged = has_raw_socket_capability();
    let created = create_client(&state).await;

    if !privileged {
        let err = created.expect_err(
            "ICMP client must not report success without CAP_NET_RAW - the raw socket cannot \
             be opened",
        );
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("raw") || msg.contains("permission") || msg.contains("denied"),
            "expected a raw-socket privilege error, got {err:#}"
        );

        // The failed client is still registered in state (with Error status). It must have
        // no command handle: the dashboard greys [ send ] out from exactly this.
        let clients = state.get_all_clients().await;
        assert_eq!(clients.len(), 1, "expected the failed client in state");
        let id = clients[0].id;
        assert!(
            !state.has_client_handle(id).await,
            "a client whose connect failed must not leave a command handle behind"
        );
        let err = state
            .send_to_client(
                id,
                serde_json::json!({"type": "wait_for_more"}),
                Duration::from_secs(2),
            )
            .await
            .expect_err("send_to_client must fail fast on a client with no handle");
        assert!(
            err.to_string()
                .contains("does not accept injected commands"),
            "expected the no-handle error, got {err:#}"
        );
        return;
    }

    // Privileged: the live wiring. The packet-sending half is the `#[ignore]`d test below.
    let client_id = created.expect("create icmp client");
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "definitely_not_an_icmp_verb"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "wait_for_more"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client wait_for_more");
    match outcome {
        ClientSendOutcome::Executed { ref detail } => {
            assert!(detail.contains("wait_for_more"), "detail was {detail:?}")
        }
        other => panic!("expected Executed, got {other:?}"),
    }
}

/// Sends a real ICMP echo request through the injected-command path, which is only possible
/// with root/`CAP_NET_RAW`. `#[ignore]`d rather than skipped-with-a-pass: an unconditional
/// `return Ok(())` on an unprivileged machine would report green coverage for a packet that
/// was never built.
///
///   sudo -E ./cargo-isolated.sh test --no-default-features --features icmp --test client -- \
///       icmp::command_channel --ignored --test-threads=100
#[tokio::test]
#[ignore = "requires CAP_NET_RAW/root: opens a raw ICMP socket and sends a real echo request"]
async fn injected_echo_request_puts_a_packet_on_the_wire() {
    let state = new_state().await;
    let client_id = create_client(&state).await.expect("create icmp client");
    wait_for_client_handle(&state, client_id).await;

    // IP header (20) + ICMP echo header (8) + 5-byte payload.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_echo_request",
                "destination_ip": "127.0.0.1",
                "identifier": 4242,
                "sequence": 1,
                "payload_hex": "48656c6c6f",
                "ttl": 64
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 33 }),
        "expected Sent{{33}}, got {outcome:?}"
    );

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );
    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("command handle should be gone after an injected disconnect");
}

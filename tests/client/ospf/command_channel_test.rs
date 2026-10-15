//! The dashboard's `[ send ]` path on an OSPF client.
//!
//! OSPF needs a raw IP socket (protocol 89), which wants `CAP_NET_RAW` - the protocol's own
//! metadata declares `PrivilegeRequirement::RawSockets` accordingly. So this file is split
//! in two:
//!
//! * [`command_channel_wiring`] always runs. Without the capability the client cannot be
//!   created at all, and what it asserts is the part of the contract that failure still has
//!   to honour: `connect()` returns `Err`, **no command handle is left registered**, and a
//!   later `send_to_client` fails fast with the "does not accept injected commands" error
//!   rather than hanging. That is rule 3 of the command-channel contract, and it is exactly
//!   the case that would strand a dead `[ send ]` row in the dashboard. With the capability
//!   the same test asserts the live wiring instead: the handle is registered, an unknown
//!   verb comes back `Rejected`, and `wait_for_more` comes back `Executed`.
//! * [`injected_hello_puts_a_packet_on_the_wire`] is `#[ignore]`d because it emits a real
//!   OSPF Hello to 224.0.0.5 and therefore genuinely needs the privilege (and a
//!   multicast-capable interface).
//!
//! Zero LLM calls either way: the client's LLM points at an unreachable URL, so its
//! connected-event call - which OSPF runs in its own task - fails immediately.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ospf --test client -- ospf::command_channel --test-threads=100

#![cfg(unix)]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::sync::mpsc;

/// Can this process open the raw OSPF socket the client needs?
fn has_raw_socket_capability() -> bool {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, 89);
        if fd < 0 {
            return false;
        }
        libc::close(fd);
        true
    }
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
        protocol: "ospf".to_string(),
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
        "OSPF client #{} never registered a command handle",
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
            "OSPF client must not report success without CAP_NET_RAW - the raw socket cannot \
             be opened",
        );
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("raw") || msg.contains("root") || msg.contains("permission"),
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
    let client_id = created.expect("create ospf client");
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "definitely_not_an_ospf_verb"}),
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

/// Emits a real OSPF Hello through the injected-command path, which needs root/`CAP_NET_RAW`
/// and an interface that can carry 224.0.0.5. `#[ignore]`d rather than skipped-with-a-pass:
/// an unconditional success on an unprivileged machine would report green coverage for a
/// packet that was never built.
///
///   sudo -E ./cargo-isolated.sh test --no-default-features --features ospf --test client -- \
///       ospf::command_channel --ignored --test-threads=100
#[tokio::test]
#[ignore = "requires CAP_NET_RAW/root: opens a raw IP-89 socket and multicasts a real OSPF Hello"]
async fn injected_hello_puts_a_packet_on_the_wire() {
    let state = new_state().await;
    let client_id = create_client(&state).await.expect("create ospf client");
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_hello",
                "router_id": "1.1.1.1",
                "area_id": "0.0.0.0",
                "network_mask": "255.255.255.0",
                "priority": 0,
                "neighbors": [],
                "destination": "multicast"
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    match outcome {
        // A Hello with no neighbours is 24 bytes of OSPF header + 20 bytes of Hello body.
        ClientSendOutcome::Sent { bytes_sent } => assert_eq!(bytes_sent, 44),
        other => panic!("expected Sent, got {other:?}"),
    }

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

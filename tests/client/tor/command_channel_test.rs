//! The dashboard's `[ send ]` path on a Tor client — the closest cheap variant, and why.
//!
//! A live "bytes arrive on the wire" test is disproportionate here. Reaching the Tor client's
//! read loop (where `command_support::register_command_channel` runs) requires
//! `arti_client::TorClient::create_bootstrapped()` to complete a real directory bootstrap and
//! then build a circuit to the destination. There is no cheap loopback for that: it needs the
//! `tor_relay` server speaking the OR protocol + BEGIN_DIR (see `tests/client/tor/CLAUDE.md`),
//! which is a whole multi-server harness, not a command-channel injection test. And by policy
//! the client refuses to bootstrap at all without an explicit opt-in (see `test.rs`).
//!
//! So this verifies the reachable halves of the command-channel contract without a circuit:
//!  1. `send_to_client` to a client with no registered handle is refused (the negative path the
//!     dashboard relies on to grey out `[ send ]`), and
//!  2. the Tor client's `execute_action` maps `send_tor_data` → `SendData` and `disconnect` →
//!     `Disconnect` — exactly the vocabulary the generic `handle_stream_client_command` arm this
//!     client wires up would put on the wire once a handle exists.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tor --test client -- tor::command_channel --test-threads=100

#![cfg(unix)]

use std::time::Duration;

use netget::llm::actions::client_trait::{Client, ClientActionResult};
use netget::state::app_state::AppState;
use netget::state::ClientId;

#[tokio::test]
async fn send_to_client_without_a_handle_is_refused() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());

    // No client 42 exists, so no command handle is registered: the injection must be refused,
    // never silently accepted. This is what the dashboard reads to keep `[ send ]` greyed out
    // on a Tor client whose circuit has not (yet) reached the read loop.
    let err = state
        .send_to_client(
            ClientId::new(42),
            serde_json::json!({"type": "send_tor_data", "data_hex": "48656c6c6f"}),
            Duration::from_secs(1),
        )
        .await
        .expect_err("a client with no command handle must be refused");
    assert!(
        err.to_string()
            .contains("does not accept injected commands"),
        "unexpected error: {err}"
    );
}

#[test]
fn command_channel_vocabulary_is_encodable_by_the_generic_arm() {
    let protocol = netget::client::tor::TorClientProtocol::new();

    // The generic command arm only writes `SendData` and honours `Disconnect`; these are the
    // two verbs an injected send/disconnect resolves to, so the plumbing is correct once a
    // circuit registers the handle.
    match protocol
        .execute_action(serde_json::json!({"type": "send_tor_data", "data_hex": "48656c6c6f"}))
        .expect("send_tor_data executes")
    {
        ClientActionResult::SendData(bytes) => assert_eq!(bytes, b"Hello"),
        other => panic!("expected SendData, got {other:?}"),
    }

    assert!(
        matches!(
            protocol
                .execute_action(serde_json::json!({"type": "disconnect"}))
                .expect("disconnect executes"),
            ClientActionResult::Disconnect
        ),
        "disconnect must resolve to Disconnect"
    );

    // Unknown verbs are rejected — the generic arm turns this into ClientSendOutcome::Rejected.
    assert!(protocol
        .execute_action(serde_json::json!({"type": "no_such_action"}))
        .is_err());
}

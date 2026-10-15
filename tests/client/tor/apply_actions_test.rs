//! The Tor client's shared action executor — the thing that was missing.
//!
//! `tor_connected` and `tor_bootstrap_complete` both asked the model what to do and threw the
//! answer away (`Ok(_) => trace!("LLM called successfully")`, and an `if let Err(..)` whose
//! success arm did not exist). Both now run their actions through [`apply_actions`], which is
//! also what the read loop uses, so the vocabulary is executed in exactly one place.
//!
//! A live test would need `create_bootstrapped()` to complete a real directory bootstrap and
//! build a circuit — see `command_channel_test.rs` for why there is no cheap loopback for
//! that. What is reachable, and what the two fixed call sites actually depend on, is the
//! executor's contract:
//!
//!  1. `disconnect` returns `true`, which is how the read loop learns to stop. Before the fix
//!     a `disconnect` only `break`ed the `for action in actions` loop, so the model could
//!     never close a Tor client at all.
//!  2. With no circuit yet — `tor_bootstrap_complete` fires while `connect()` is still
//!     bootstrapping — `send_tor_data` is refused *loudly* rather than dropped, and does not
//!     abort the rest of the answer.
//!  3. An action the protocol rejects is reported, not swallowed.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tor --test client -- tor::apply_actions --test-threads=100

#![cfg(unix)]

use std::sync::Arc;

use netget::client::tor::apply_actions;
use netget::state::app_state::AppState;
use netget::state::ClientId;
use tokio::sync::mpsc;

fn fixture() -> (
    Arc<AppState>,
    mpsc::UnboundedSender<String>,
    mpsc::UnboundedReceiver<String>,
) {
    let state = Arc::new(AppState::new_with_options(
        false,
        "http://127.0.0.1:1".to_string(),
    ));
    let (tx, rx) = mpsc::unbounded_channel();
    (state, tx, rx)
}

fn drain(rx: &mut mpsc::UnboundedReceiver<String>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(m) = rx.try_recv() {
        out.push(m);
    }
    out
}

#[tokio::test]
async fn a_disconnect_action_tells_the_caller_to_stop() {
    let (state, tx, _rx) = fixture();

    let stop = apply_actions(
        vec![serde_json::json!({"type": "disconnect"})],
        None,
        ClientId::new(1),
        &state,
        &tx,
    )
    .await;

    assert!(
        stop,
        "`disconnect` must return true — that return value is the only way the read loop \
         learns the model asked to close the circuit"
    );
}

#[tokio::test]
async fn send_without_a_circuit_is_refused_out_loud_and_does_not_stop_the_answer() {
    let (state, tx, mut rx) = fixture();

    // The shape `tor_bootstrap_complete` can produce: a send the model cannot yet have,
    // followed by a directory verb that is perfectly valid at that moment.
    let stop = apply_actions(
        vec![
            serde_json::json!({"type": "send_tor_data", "data_hex": "48656c6c6f"}),
            serde_json::json!({"type": "get_consensus_info"}),
        ],
        None,
        ClientId::new(2),
        &state,
        &tx,
    )
    .await;

    assert!(!stop, "neither action asks to disconnect");

    let messages = drain(&mut rx);
    assert!(
        messages.iter().any(|m| m.contains("circuit is not open yet")),
        "a send with no circuit must say so on the status stream rather than vanish; got {messages:?}"
    );
    // The second action was still attempted: `get_consensus_info` has no consensus in this
    // fixture, so it reports an error — the point is that it ran at all.
    assert!(
        messages.len() >= 2,
        "the refused send must not abort the rest of the model's answer; got {messages:?}"
    );
}

#[tokio::test]
async fn an_action_the_protocol_rejects_is_reported() {
    let (state, tx, mut rx) = fixture();

    let stop = apply_actions(
        vec![serde_json::json!({"type": "not_a_tor_verb"})],
        None,
        ClientId::new(3),
        &state,
        &tx,
    )
    .await;

    assert!(!stop);
    let messages = drain(&mut rx);
    assert!(
        messages.iter().any(|m| m.contains("rejected action")),
        "an unknown verb must reach the operator, not just the log; got {messages:?}"
    );
}

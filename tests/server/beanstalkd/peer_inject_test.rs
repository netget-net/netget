//! The dashboard's `[ message ]` / `[ disconnect ]` on a Beanstalkd connection, and the one
//! place it matters most: a worker left waiting in `reserve`.
//!
//! `send_to_peer` injects an action into one live connection; it is rendered by the same
//! executor the model's answers go through and written by `peer_support`'s own task, not by the
//! session loop. A waiting reserve must still notice it was answered — otherwise a
//! `reserve-with-timeout` would get the injected `RESERVED` *and then* a `TIMED_OUT`, and the
//! worker would read the second as the answer to its next command. Zero model calls.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features beanstalkd --test server -- beanstalkd::peer_inject --test-threads=100


use super::common::{self, Peer};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use std::time::Duration;

async fn wait_for_peer_handle(state: &AppState, id: ServerId) -> u32 {
    for _ in 0..200 {
        if let Some(s) = state.get_server(id).await {
            for conn in s.connections.values() {
                if state.has_peer_handle(id, conn.id.as_u32()).await {
                    return conn.id.as_u32();
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Beanstalkd server never registered a peer handle");
}

fn waiting_handler() -> serde_json::Value {
    serde_json::json!({
        "event_pattern": "beanstalkd_reserve",
        "handler": {"type": "static", "actions": [{"type": "wait_for_beanstalkd_job"}]}
    })
}

async fn inject(state: &AppState, server: ServerId, conn: u32, action: serde_json::Value) {
    let outcome = state
        .send_to_peer(server, conn, action, Duration::from_secs(5))
        .await
        .expect("send_to_peer");
    assert!(
        matches!(
            outcome,
            ClientSendOutcome::Sent { .. } | ClientSendOutcome::Disconnected
        ),
        "got {outcome:?}"
    );
}

#[tokio::test]
async fn a_job_injected_into_a_waiting_reserve_answers_it_exactly_once() {
    let state = common::new_state().await;
    let (server_id, port, mut rx) = common::start(&state, vec![waiting_handler()], None).await;
    let mut worker = Peer::connect(port).await;
    let conn = wait_for_peer_handle(&state, server_id).await;

    worker.send("reserve-with-timeout 4").await;
    common::wait_for_log(&mut rx, "decision=model_wait", 30).await;
    inject(
        &state,
        server_id,
        conn,
        serde_json::json!({"type": "reserve_beanstalkd_job", "job_id": 31, "body": "from the operator"}),
    )
    .await;
    let (line, payload) = worker.reply(10).await;
    assert_eq!(line, "RESERVED 31 17\r\n");
    assert_eq!(payload.unwrap(), b"from the operator");

    // Past the reserve's own 4 s: no TIMED_OUT may follow the injected answer.
    worker
        .assert_silent_and_open(6, "a reserve that was already answered")
        .await;
    // And the session is back to reading commands.
    worker.send("list-tube-used").await;
    assert_eq!(worker.line(10).await, "USING default\r\n");

    inject(
        &state,
        server_id,
        conn,
        serde_json::json!({"type": "close_connection"}),
    )
    .await;
    assert_eq!(
        worker.line(10).await,
        "",
        "disconnect must reach the peer as EOF"
    );
}

#[tokio::test]
async fn an_injected_reply_is_framed_like_the_models() {
    let state = common::new_state().await;
    let (server_id, port, _rx) = common::start(&state, Vec::new(), None).await;
    let mut peer = Peer::connect(port).await;
    let conn = wait_for_peer_handle(&state, server_id).await;

    inject(
        &state,
        server_id,
        conn,
        serde_json::json!({"type": "send_beanstalkd_stats", "stats": {"current-jobs-ready": 4}}),
    )
    .await;
    let (line, payload) = peer.reply(10).await;
    assert_eq!(line, "OK 26\r\n");
    assert_eq!(payload.unwrap(), b"---\ncurrent-jobs-ready: 4\n");
}

//! The dashboard's `[ message ]` / `[ disconnect ]` on a Gearman connection whose job is
//! parked for a human: an injected action naming the job handle is rendered by the same code
//! as the model's answer, and `close_connection` reaches the client as EOF. Zero model calls.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features gearman --test server -- gearman::peer_inject --test-threads=100


use super::common::{self, req, Peer};
use netget::server::gearman::wire;
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
    panic!("Gearman server never registered a peer handle");
}

#[tokio::test]
async fn an_injected_result_reaches_the_client_and_disconnect_sends_eof() {
    let state = common::new_state().await;
    let (server_id, port, _rx) = common::start(&state, vec![common::manual_handler()], None).await;
    let mut peer = Peer::connect(port).await;
    peer.send(&req(wire::SUBMIT_JOB, &[b"reverse", b"", b"abc"]))
        .await;
    let (t, created, _) = peer.packet(10).await;
    assert_eq!(t, wire::JOB_CREATED);
    let handle = String::from_utf8(created[0].clone()).unwrap();
    let conn = wait_for_peer_handle(&state, server_id).await;

    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "complete_gearman_job", "result": "cba", "job_handle": handle}),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "got {outcome:?}"
    );
    let (t, args, _) = peer.packet(10).await;
    assert_eq!(
        (t, args),
        (
            wire::WORK_COMPLETE,
            vec![created[0].clone(), b"cba".to_vec()]
        )
    );

    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "close_connection"}),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer close");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "got {outcome:?}"
    );
    assert!(
        peer.rest(10).await.is_empty(),
        "disconnect must reach the client as EOF"
    );
}

//! The dashboard's `[ message ]` / `[ disconnect ]` on a Bolt connection.
//!
//! Bolt defines no message a server may send unprompted — every SUCCESS, RECORD, IGNORED and
//! FAILURE answers a request — so an injected answer action is validated by the executor and
//! reported as executed, and nothing reaches the socket (bytes out of turn would desynchronise
//! the client's response queue). `close_connection` half-closes the socket and the peer reads
//! EOF. Zero model calls.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bolt --test server -- bolt::peer_inject --test-threads=100


use super::common::{self, *};
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
    panic!("Bolt server never registered a peer handle");
}

#[tokio::test]
async fn an_injected_answer_writes_nothing_and_disconnect_sends_eof() {
    let state = common::new_state().await;
    let (server_id, port, _rx) = common::start(
        &state,
        vec![common::accept_logins(), common::graph_handler()],
        None,
    )
    .await;
    let mut peer = Peer::connect_and_login(port).await;
    let conn = wait_for_peer_handle(&state, server_id).await;

    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_bolt_records", "fields": ["x"], "records": [[1]]}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "got {outcome:?}"
    );

    // Nothing was written out of turn: the next thing on the wire answers the next request.
    peer.send_all(&[run("MATCH (n:Person) RETURN n.name AS name"), pull(-1)])
        .await;
    let run_ok = peer.recv().await;
    assert_success(&run_ok);
    assert_eq!(
        meta(&run_ok).get("fields"),
        Some(&netget::server::bolt::packstream::Value::List(vec![
            netget::server::bolt::packstream::Value::string("name")
        ]))
    );
    record_values(&peer.recv().await);
    record_values(&peer.recv().await);
    assert_success(&peer.recv().await);

    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "close_connection"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer close");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "got {outcome:?}"
    );
    peer.expect_eof(10).await;
}

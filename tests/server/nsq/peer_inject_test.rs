//! The dashboard's `[ message ]` / `[ disconnect ]` on a subscribed NSQ connection: an injected
//! `deliver_nsq_messages` goes through the same queue and RDY limit as the model's, and
//! `close_connection` reaches the client as EOF. Zero model calls.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nsq --test server -- nsq::peer_inject --test-threads=100


use super::common::{self, static_handler, Peer};
use netget::server::nsq::wire::Command;
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
    panic!("NSQ server never registered a peer handle");
}

#[tokio::test]
async fn injected_messages_respect_rdy_and_disconnect_sends_eof() {
    let state = common::new_state().await;
    let handlers = vec![
        static_handler(
            "nsq_subscribe",
            serde_json::json!([{"type": "send_nsq_ok"}]),
        ),
        static_handler("nsq_ready", serde_json::json!([])),
        static_handler("nsq_finish", serde_json::json!([])),
    ];
    let (server_id, port, mut rx) = common::start(&state, handlers, None).await;
    let mut peer = Peer::connect(port).await;
    peer.command(&Command::Sub {
        topic: "t".into(),
        channel: "c".into(),
    })
    .await;
    peer.expect_response(b"OK", 30).await;
    peer.command(&Command::Rdy(1)).await;
    common::wait_for_log(&mut rx, "NSQ RDY from", 30).await;
    let conn = wait_for_peer_handle(&state, server_id).await;

    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "deliver_nsq_messages",
                               "messages": [{"body": "first"}, {"body": "second"}]}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "got {outcome:?}"
    );
    let first = peer.expect_message(10).await;
    assert_eq!(first.body, b"first");
    // RDY 1: the second waits for the FIN.
    peer.quiet_for(1).await;
    peer.command(&Command::Fin(String::from_utf8(first.id.to_vec()).unwrap()))
        .await;
    assert_eq!(peer.expect_message(10).await.body, b"second");

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
    assert!(
        peer.rest(10).await.is_empty(),
        "disconnect must reach the client as EOF"
    );
}

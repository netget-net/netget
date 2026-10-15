//! The dashboard's `[ message ]` / `[ disconnect ]` on a DICT connection: `send_to_peer`
//! injects an action into one live connection, it is rendered by the same executor the model's
//! answers go through, and the bytes reach the socket. Zero model calls.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dict --test server -- dict::peer_inject --test-threads=100


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
    panic!("DICT server never registered a peer handle");
}

#[tokio::test]
async fn an_injected_dict_reply_reaches_the_socket_and_disconnect_sends_eof() {
    let state = common::new_state().await;
    let (server_id, port, _rx) = common::start(&state, Vec::new(), None).await;
    let mut peer = Peer::connect(port).await;
    assert!(peer.line(10).await.starts_with("220 "));
    let conn = wait_for_peer_handle(&state, server_id).await;

    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_dict_text", "code": 114, "text": "injected\n.dot"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "got {outcome:?}"
    );
    let reply = peer.until_status(&["250"], 10).await;
    assert_eq!(
        reply,
        [
            "114 server information follows\r\n",
            "injected\r\n",
            "..dot\r\n",
            ".\r\n",
            "250 ok\r\n"
        ],
        "an injected reply is framed and dot-stuffed exactly like the model's"
    );

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
    assert_eq!(
        peer.line(10).await,
        "",
        "disconnect must reach the peer as EOF"
    );
}

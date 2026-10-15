//! The dashboard's `[ message ]` / `[ disconnect ]` on a Gemini connection whose request is
//! parked for a human: `send_to_peer` injects a response rendered by the same executor as the
//! model's, and `close_connection` ends the connection. Zero model calls.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features gemini --test server -- gemini::peer_inject --test-threads=100

use super::common::{self, split_response, tls_connect};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

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
    panic!("Gemini server never registered a peer handle");
}

#[tokio::test]
async fn an_injected_gemtext_response_and_disconnect_reach_the_peer() {
    let state = common::new_state().await;
    let manual = serde_json::json!({
        "event_pattern": "*",
        "handler": {"type": "manual", "timeout_secs": 300}
    });
    let (server_id, port, _rx) = common::start(&state, vec![manual], None).await;
    let mut tls = tls_connect(port).await;
    tls.write_all(b"gemini://localhost/\r\n")
        .await
        .expect("write");
    tls.flush().await.expect("flush");
    let conn = wait_for_peer_handle(&state, server_id).await;

    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_gemtext", "lines": [
                {"type": "heading1", "text": "From the operator"},
                {"type": "text", "text": "# not a heading"}
            ]}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "got {outcome:?}"
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

    let response = common::read_all(&mut tls, 10).await;
    let (header, body) = split_response(&response);
    assert_eq!(header, "20 text/gemini; charset=utf-8");
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "# From the operator\n # not a heading\n",
        "an injected page is rendered exactly like the model's"
    );
}

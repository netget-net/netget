//! The dashboard's `[ message ]` / `[ disconnect ]` on a Nostr connection (MCP `send_to_peer` /
//! `disconnect_peer`). An injected action is rendered by the same executor the model's answers
//! go through and arrives as one WebSocket text frame per relay message. Zero model calls.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nostr --test server -- nostr::peer_inject --test-threads=100

use super::common::{self, relay_handlers, Peer, Read, RELAY_SECRET};
use netget::server::nostr::wire::{verify_event, RelayKey};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use serde_json::json;
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
    panic!("the Nostr relay never registered a peer handle");
}

async fn inject(
    state: &AppState,
    server: ServerId,
    conn: u32,
    action: serde_json::Value,
) -> ClientSendOutcome {
    state
        .send_to_peer(server, conn, action, Duration::from_secs(5))
        .await
        .expect("send_to_peer")
}

#[tokio::test]
async fn an_operator_can_notice_push_events_close_a_subscription_and_disconnect() {
    let state = common::new_state().await;
    let (server_id, port, _rx) = common::start(
        &state,
        relay_handlers(json!([])),
        Some(json!({"relay_secret_key": RELAY_SECRET})),
    )
    .await;
    let mut peer = Peer::connect(port).await;
    let conn = wait_for_peer_handle(&state, server_id).await;

    let outcome = inject(
        &state,
        server_id,
        conn,
        json!({"type": "send_nostr_notice", "message": "maintenance at noon"}),
    )
    .await;
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        peer.json(10).await,
        json!(["NOTICE", "maintenance at noon"])
    );

    // A live push into an open subscription: signed by the relay, held to its filters.
    peer.send_json(json!(["REQ", "news", {"kinds": [1]}])).await;
    assert_eq!(peer.json(10).await, json!(["EOSE", "news"]));
    inject(
        &state,
        server_id,
        conn,
        json!({"type": "send_nostr_events", "subscription_id": "news", "events": [
            {"kind": 1, "content": "breaking"},
            {"kind": 7, "content": "+"}
        ]}),
    )
    .await;
    let pushed = peer.json(10).await;
    assert_eq!(pushed[0], "EVENT");
    assert_eq!(pushed[1], "news");
    let event = verify_event(&pushed[2]).expect("the relay signed it");
    assert_eq!(event.content, "breaking");
    assert_eq!(
        event.pubkey,
        RelayKey::from_hex(RELAY_SECRET).unwrap().pubkey_hex()
    );
    // The kind 7 did not match and was not sent: the next frame is the CLOSED below.

    inject(
        &state,
        server_id,
        conn,
        json!({"type": "close_nostr_subscription", "subscription_id": "news", "reason": "closing time"}),
    )
    .await;
    assert_eq!(
        peer.json(10).await,
        json!(["CLOSED", "news", "restricted: closing time"])
    );

    let outcome = inject(&state, server_id, conn, json!({"type": "close_connection"})).await;
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "{outcome:?}"
    );
    match peer.read(10).await {
        Read::Closed(Some((code, _))) => assert_eq!(code, 1000),
        other => panic!("expected a close frame, got {other:?}"),
    }
}

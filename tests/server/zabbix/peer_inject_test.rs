//! The dashboard's `[ message ]` / `[ disconnect ]` on a Zabbix connection whose request is
//! parked for a human: `send_to_peer` renders the same response the model's answer would, and
//! `close_connection` reaches the sender as EOF. Zero model calls.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features zabbix --test server -- zabbix::peer_inject --test-threads=100

use super::common::{self, response, sender_data};
use netget::server::zabbix::wire;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ServerId;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
    panic!("Zabbix server never registered a peer handle");
}

#[tokio::test]
async fn an_injected_result_reaches_the_sender_and_disconnect_sends_eof() {
    let state = common::new_state().await;
    let manual = serde_json::json!({
        "event_pattern": "*",
        "handler": {"type": "manual", "timeout_secs": 300}
    });
    let (server_id, port, _rx) = common::start(&state, vec![manual], None).await;
    let mut peer = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    peer.write_all(&wire::encode(&sender_data(&[("h", "k", "1")])))
        .await
        .unwrap();
    let conn = wait_for_peer_handle(&state, server_id).await;

    let outcome = state
        .send_to_peer(
            server_id,
            conn,
            serde_json::json!({"type": "send_zabbix_result", "processed": 1, "failed": 0}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_peer");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "got {outcome:?}"
    );

    let mut header = vec![0u8; wire::HEADER_LEN];
    tokio::time::timeout(Duration::from_secs(10), peer.read_exact(&mut header))
        .await
        .expect("no injected response")
        .unwrap();
    let len = wire::parse_header(&header).unwrap().data_len as usize;
    let mut body = vec![0u8; len];
    peer.read_exact(&mut body).await.unwrap();
    header.extend_from_slice(&body);
    let (_, _, json) = response(&header);
    assert_eq!(
        json["info"], "processed: 1; failed: 0; total: 1; seconds spent: 0.000000",
        "an injected result is rendered by the same code as the model's"
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
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), peer.read_to_end(&mut rest))
        .await
        .expect("disconnect must reach the sender as EOF")
        .unwrap();
}

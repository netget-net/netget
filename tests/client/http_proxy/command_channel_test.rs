//! Dashboard injection into a running HTTP proxy client (`AppState::send_to_client`): a NetGet
//! HTTP proxy client connected to a raw tokio listener standing in for the proxy, with actions
//! injected from outside the client's loop. Zero LLM calls: the client's LLM points at an
//! unreachable URL (the loop tolerates that error and keeps the socket open).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features http_proxy --test client -- http_proxy::command_channel --test-threads=100

#![cfg(unix)]

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("client #{} never registered a command handle", id.as_u32());
}

async fn wait_for_log_containing(state: &AppState, owner: AccessLogOwner, needle: &str) {
    for _ in 0..1_000 {
        for entry in state.list_access_logs_for(Some(owner), None).await {
            if serde_json::to_string(&entry)
                .unwrap_or_default()
                .contains(needle)
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

/// Read from the socket until `expected` bytes have arrived (or EOF / timeout).
async fn read_exactly(sock: &mut tokio::net::TcpStream, expected: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(expected);
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while out.len() < expected {
        let n = tokio::time::timeout_at(deadline, sock.read(&mut buf))
            .await
            .expect("timed out waiting for injected bytes")
            .expect("read");
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    out
}

#[tokio::test]
async fn injected_http_proxy_actions_reach_the_proxy_socket() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // A raw listener plays the proxy: it only needs to receive what the client writes.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();

    let client_id = ClientForm {
        protocol: "HTTP Proxy".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create http_proxy client");

    let (mut proxy_side, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("client never connected")
        .expect("accept");
    wait_for_client_handle(&state, client_id).await;

    // send_http_request → SendData through the generic arm.
    let expected = "GET /from-dashboard HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_http_request",
                "method": "GET",
                "path": "/from-dashboard",
                "headers": {"Host": "example.test"}
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    match outcome {
        ClientSendOutcome::Sent { bytes_sent } => assert_eq!(bytes_sent, expected.len()),
        other => panic!("expected Sent, got {other:?}"),
    }
    let got = read_exactly(&mut proxy_side, expected.len()).await;
    assert_eq!(String::from_utf8_lossy(&got), expected);

    // send_data → hex-decoded SendData.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_data", "data_hex": hex::encode("raw bytes")}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (send_data)");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 9 }),
        "{outcome:?}"
    );
    let got = read_exactly(&mut proxy_side, 9).await;
    assert_eq!(got, b"raw bytes");

    // establish_tunnel is a Custom result: the bespoke arm encodes the CONNECT line.
    let expected = "CONNECT target.test:443 HTTP/1.1\r\nHost: target.test:443\r\n\r\n";
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "establish_tunnel",
                "target_host": "target.test",
                "target_port": 443
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (establish_tunnel)");
    match outcome {
        ClientSendOutcome::Sent { bytes_sent } => assert_eq!(bytes_sent, expected.len()),
        other => panic!("expected Sent, got {other:?}"),
    }
    let got = read_exactly(&mut proxy_side, expected.len()).await;
    assert_eq!(String::from_utf8_lossy(&got), expected);

    // The injections are in the client's own request log.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "establish_tunnel",
    )
    .await;

    // Unknown actions are rejected, not swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (bad action)");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "{outcome:?}"
    );

    // Disconnect through the channel: half-close, proxy reads EOF, read loop ends on the
    // proxy's close, handle gone.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (disconnect)");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "{outcome:?}"
    );
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), proxy_side.read(&mut buf))
        .await
        .expect("proxy never saw EOF")
        .expect("read");
    assert_eq!(
        n, 0,
        "expected EOF on the proxy side after injected disconnect"
    );
    drop(proxy_side);

    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("client handle still registered after disconnect");
}

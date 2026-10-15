//! The dashboard's `[ send ]` path on a Bitcoin RPC client: `AppState::send_to_client`
//! injects an action from outside the client's own tasks and the JSON-RPC request reaches a
//! server. Zero LLM calls - the client's LLM points at an unreachable URL, so its
//! connected-event call fails and the loop must tolerate that; verifying it does is part of
//! the point.
//!
//! There is no NetGet "Bitcoin RPC" *server* protocol (`src/server/bitcoin` speaks the P2P
//! wire protocol, not JSON-RPC over HTTP), so the peer here is a ~40-line HTTP/1.1 responder
//! bound to 127.0.0.1 that records the JSON-RPC method it was asked for.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bitcoin --test client -- bitcoin::command_channel --test-threads=100


use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

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
    panic!(
        "Bitcoin client #{} never registered a command handle",
        id.as_u32()
    );
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

/// A minimal localhost JSON-RPC-over-HTTP endpoint. Returns its port and a handle to the
/// list of request bodies it has received.
async fn start_rpc_stub() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();

    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let seen = seen_task.clone();
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                // Read headers, then exactly Content-Length bytes of body.
                let body = loop {
                    let n = match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    raw.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&raw).to_string();
                    let Some(header_end) = text.find("\r\n\r\n") else {
                        continue;
                    };
                    let content_len = text[..header_end]
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    if raw.len() >= header_end + 4 + content_len {
                        break String::from_utf8_lossy(&raw[header_end + 4..]).to_string();
                    }
                };

                seen.lock().await.push(body);

                let payload =
                    r#"{"result":{"chain":"regtest","blocks":42},"error":null,"id":"netget"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });

    (port, seen)
}

#[tokio::test]
async fn injected_bitcoin_rpc_reaches_the_node() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let (port, seen) = start_rpc_stub().await;

    let client_id = ClientForm {
        protocol: "bitcoin".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create bitcoin client");

    // Regression guard for "register the channel BEFORE the connected-event LLM call":
    // the handle must exist without anything having answered that call.
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "get_blockchain_info"}),
            Duration::from_secs(20),
        )
        .await
        .expect("send_to_client");

    // Deliberately `Executed`, never `Sent`: reqwest owns the socket and never reports how
    // many bytes the request serialised to, so a byte count here would be invented.
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("getblockchaininfo") && detail.contains("200"),
                "detail should name the method and the HTTP status, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // It really went out.
    let bodies = seen.lock().await.clone();
    assert_eq!(bodies.len(), 1, "stub should have seen one request");
    assert!(
        bodies[0].contains("getblockchaininfo"),
        "stub received {:?}",
        bodies[0]
    );

    // Recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // An unknown verb is refused, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "definitely_not_a_bitcoin_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected disconnect ends the command loop and takes the handle with it.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "client should be Disconnected with no command handle; status={:?} has_handle={}",
        state.get_client(client_id).await.map(|c| c.status),
        state.has_client_handle(client_id).await
    );
}

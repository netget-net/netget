//! The dashboard's `[ send ]` path on a DoH client: `AppState::send_to_client` injects a
//! `query_dns` from outside the client's own task and a real RFC 8484 request goes on the wire.
//!
//! The peer is a tiny in-test HTTP/1.1 stub rather than NetGet's own DoH server: that server is
//! TLS-only with a self-signed certificate, and this client builds a default `reqwest::Client`,
//! which correctly refuses it. The stub echoes the request body back as the response body — a
//! DNS query message is itself a well-formed DNS message, so the client parses it, sees zero
//! answers and rcode NoError, and the assertion still proves the encoded query left the process
//! and came back through the real parsing path.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so both its connected-event
//! call and the response-event call it makes after the injected query fail and are tolerated.
//!
//! Why `Executed` and not `Sent`: reqwest owns the socket and reports no wire byte count, so a
//! number would be invented. The detail carries the answer count and DNS rcode instead.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features doh --test client -- doh::command_channel --test-threads=100

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    panic!(
        "DoH client #{} never registered a command handle",
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

fn headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// A minimal `application/dns-message` endpoint that echoes the POSTed query back.
/// Returns its port and a counter of served requests.
async fn spawn_doh_echo_stub() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();

    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let head_end = match headers_end(&buf) {
                        Some(pos) => pos,
                        None => match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                buf.extend_from_slice(&chunk[..n]);
                                continue;
                            }
                        },
                    };

                    let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
                    let content_length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let body_start = head_end + 4;

                    while buf.len() < body_start + content_length {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }

                    let body = buf[body_start..body_start + content_length].to_vec();
                    counter.fetch_add(1, Ordering::SeqCst);

                    let mut response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    response.extend_from_slice(&body);
                    let _ = sock.write_all(&response).await;
                    let _ = sock.flush().await;
                    return;
                }
            });
        }
    });

    (port, hits)
}

#[tokio::test]
async fn injected_dns_query_goes_on_the_wire() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let (stub_port, stub_hits) = spawn_doh_echo_stub().await;

    let client_id = ClientForm {
        protocol: "doh".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{stub_port}/dns-query")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create doh client");

    // Registered before the connected-event LLM call, not after it - the regression guard
    // for a client whose connect event parks on a manual rule.
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "query_dns",
                "domain": "dashboard-marker.example.com",
                "record_type": "A"
            }),
            Duration::from_secs(20),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("query_dns dashboard-marker.example.com A")
                    && detail.contains("0 answers"),
                "expected the awaited query in the detail, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }
    assert_eq!(
        stub_hits.load(Ordering::SeqCst),
        1,
        "the injected query should have reached the DoH endpoint exactly once"
    );

    // Recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // An action the protocol does not know is rejected, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected disconnect ends the command loop and drops the handle.
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

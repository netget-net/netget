//! A spec must not be able to retarget the client away from the address it was given.
//!
//! The base URL used to be taken from the spec's `servers[0]` in preference to `remote_addr`,
//! so an operator who said "connect to 127.0.0.1:9000" and handed over a spec declaring
//! `https://api.production.example.com` got the production host — with no log line saying the
//! named address had been discarded. A spec is data supplied with the request, often by the
//! model, so this is the DynamoDB shape from `CLAUDE.md`: a client that loses its target and
//! reaches a real service instead of failing.
//!
//! The tell was already in the suite. `e2e_test.rs` rewrites `{port}` *inside the spec* before
//! every run, which is the workaround you write when `remote_addr` is not what decides.
//!
//! Zero LLM calls: a `*` static handler with no actions answers every client event.


use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

/// A spec whose declared server is somewhere the test could never reach — so if a request
/// arrives at the stub below, `remote_addr` is what decided.
const SPEC_POINTING_ELSEWHERE: &str = r#"
openapi: 3.1.0
info:
  title: Retarget Test API
  version: 1.0.0
servers:
  - url: https://api.production.example.invalid/v2
    description: a host this test must never contact
paths:
  /users:
    get:
      operationId: listUsers
      responses:
        '200':
          description: ok
"#;

fn no_llm_handlers() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "event_pattern": "*",
        "handler": { "type": "static", "actions": [] }
    })]
}

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
        "OpenAPI client #{} never registered a command handle",
        id.as_u32()
    );
}

/// A loopback HTTP/1.1 stub that records the request line and Host of everything it sees.
async fn spawn_stub() -> (u16, Arc<Mutex<Vec<String>>>) {
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
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(n) = socket.read(&mut chunk).await else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if String::from_utf8_lossy(&buf).contains("\r\n\r\n") {
                        break;
                    }
                }
                seen.lock()
                    .await
                    .push(String::from_utf8_lossy(&buf).into_owned());
                let body = r#"{"users":[]}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, seen)
}

async fn open_client(
    state: &AppState,
    remote_addr: &str,
    extra_params: serde_json::Value,
) -> ClientId {
    let mut params = serde_json::json!({ "spec": SPEC_POINTING_ELSEWHERE });
    if let (Some(dst), Some(src)) = (params.as_object_mut(), extra_params.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    let (tx, _rx) = mpsc::unbounded_channel();
    ClientForm {
        protocol: "openapi".to_string(),
        remote_addr: Some(remote_addr.to_string()),
        instruction: Some("test client".to_string()),
        event_handlers: Some(no_llm_handlers()),
        startup_params: Some(params),
        ..Default::default()
    }
    .create(
        state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect("create openapi client")
}

#[tokio::test]
async fn the_named_address_wins_over_the_specs_declared_server() {
    let (port, seen) = spawn_stub().await;
    let state = new_state().await;
    let client_id = open_client(&state, &format!("127.0.0.1:{port}"), serde_json::json!({})).await;
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "execute_operation", "operation_id": "listUsers"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "the operation did not complete: {outcome:?}"
    );

    let requests = seen.lock().await.clone();
    assert_eq!(
        requests.len(),
        1,
        "the request must have reached the address the operator named: {requests:?}"
    );
    assert!(
        requests[0].contains(&format!("127.0.0.1:{port}")),
        "the request went somewhere other than the named address: {}",
        requests[0]
    );
    assert!(
        !requests[0].contains("api.production.example.invalid"),
        "the spec's servers[0] retargeted the client: {}",
        requests[0]
    );
}

#[tokio::test]
async fn an_explicit_base_url_still_wins_over_both() {
    let (port, seen) = spawn_stub().await;
    let state = new_state().await;
    // `remote_addr` is a dead port; `base_url` names the live stub. The override has to be
    // the strongest of the three, or it would be useless for pointing a spec at a sandbox.
    let client_id = open_client(
        &state,
        "127.0.0.1:1",
        serde_json::json!({ "base_url": format!("http://127.0.0.1:{port}") }),
    )
    .await;
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "execute_operation", "operation_id": "listUsers"}),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "the operation did not complete: {outcome:?}"
    );

    let requests = seen.lock().await.clone();
    assert_eq!(
        requests.len(),
        1,
        "base_url must override both remote_addr and the spec: {requests:?}"
    );
}

#[tokio::test]
async fn a_bare_address_gets_a_scheme_rather_than_failing_as_a_relative_url() {
    // `reqwest` needs an absolute URL: a bare `host:port` fails every request with
    // "relative URL without a base", which presents as the server being unreachable.
    let (port, seen) = spawn_stub().await;
    let state = new_state().await;
    let client_id = open_client(&state, &format!("127.0.0.1:{port}"), serde_json::json!({})).await;
    wait_for_client_handle(&state, client_id).await;

    state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "execute_operation", "operation_id": "listUsers"}),
            Duration::from_secs(30),
        )
        .await
        .expect("a scheme-less remote_addr must still produce a usable URL");

    assert_eq!(
        seen.lock().await.len(),
        1,
        "the request never arrived, which is what a relative URL looks like from here"
    );
}

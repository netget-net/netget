//! A hostile XML-RPC server cannot kill NetGet with its answer to the first call.
//!
//! `xmlrpc` 0.15's `Parser::parse_value` → `parse_value_inner` → `parse_value` recurses once
//! per `<value>` with no depth counter, and the crate reads the response body with no size
//! limit. `<value><array><data>` is about twenty bytes per level, so roughly a megabyte drives
//! the parser tens of thousands of frames deep. A Rust stack overflow is a `SIGSEGV` against
//! the guard page, not a panic: `spawn_blocking` cannot contain it, `catch_unwind` cannot see
//! it, and the whole process — every other server and client in it — dies.
//!
//! `src/client/xmlrpc/response_guard.rs` screens the bytes before the crate's parser is
//! allowed to run. Remove [`MAX_ELEMENT_DEPTH`] and this test does not fail politely: the test
//! binary aborts with `stack overflow`, which is the same way the AMQP field-table bound was
//! verified.
//!
//! The benign half of the test is not decoration. A guard that refused everything would pass
//! the first assertion, so the second one — an ordinary shallow reply, parsed and handed to
//! the model — is what says the bound is a bound and not a wall.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features xmlrpc --test client -- xmlrpc::response_guard --test-threads=100


use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::client::xmlrpc::response_guard::MAX_ELEMENT_DEPTH;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// Nesting levels the hostile server answers with.
///
/// Deep enough that the crate's parser is guaranteed to run out of stack (the AMQP precedent
/// blew up at ~26 000), and small enough that the body stays near a megabyte — well inside
/// `MAX_RESPONSE_BYTES`, so it is the *depth* bound being tested and not the size one.
const HOSTILE_DEPTH: usize = 50_000;

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
        "XML-RPC client #{} never registered a command handle",
        id.as_u32()
    );
}

/// `<value><array><data>` × depth around a single string — about twenty bytes per level, which
/// is what makes this cheap enough to be a real attack rather than a curiosity.
fn nested_response(depth: usize) -> String {
    let mut body = String::with_capacity(depth * 44 + 128);
    body.push_str(r#"<?xml version="1.0"?><methodResponse><params><param>"#);
    for _ in 0..depth {
        body.push_str("<value><array><data>");
    }
    body.push_str("<value><string>deep</string></value>");
    for _ in 0..depth {
        body.push_str("</data></array></value>");
    }
    body.push_str("</param></params></methodResponse>");
    body
}

/// A minimal HTTP/1.1 responder that answers every POST with one fixed XML-RPC body.
///
/// Hand-written rather than built on a server framework because the whole point is to say
/// something no cooperating XML-RPC library would say.
async fn spawn_xmlrpc_responder(body: String) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hostile server");
    let port = listener.local_addr().expect("local_addr").port();

    tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let body = body.clone();
            tokio::spawn(async move {
                // Read until the request is complete: headers, then Content-Length bytes.
                let mut request = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    let split = request
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|p| p + 4);
                    if let Some(body_start) = split {
                        let headers =
                            String::from_utf8_lossy(&request[..body_start]).to_ascii_lowercase();
                        let declared = headers
                            .split("content-length:")
                            .nth(1)
                            .and_then(|rest| rest.split('\r').next())
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if request.len() >= body_start + declared {
                            break;
                        }
                    }
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }

                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(body.as_bytes()).await;
                let _ = socket.flush().await;
                let _ = socket.shutdown().await;
            });
        }
    });

    port
}

async fn client_against(
    state: &AppState,
    tx: &mpsc::UnboundedSender<String>,
    port: u16,
) -> ClientId {
    let id = ClientForm {
        protocol: "XML-RPC".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{port}/RPC2")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create xmlrpc client");
    wait_for_client_handle(state, id).await;
    id
}

#[tokio::test]
async fn deep_response_is_refused_and_a_normal_one_is_not() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // ---- the hostile server -----------------------------------------------------------
    let hostile_body = nested_response(HOSTILE_DEPTH);
    assert!(
        hostile_body.len() < netget::client::xmlrpc::response_guard::MAX_RESPONSE_BYTES,
        "the attack must fit inside the size cap, or this tests the wrong bound ({} bytes)",
        hostile_body.len()
    );
    let hostile_port = spawn_xmlrpc_responder(hostile_body).await;
    let hostile_client = client_against(&state, &tx, hostile_port).await;

    let err = state
        .send_to_client(
            hostile_client,
            serde_json::json!({
                "type": "call_xmlrpc_method",
                "method_name": "anything",
                "params": []
            }),
            Duration::from_secs(30),
        )
        .await
        .expect_err(
            "a reply nested 50 000 levels deep must be refused; if this returned Ok the \
             parser was handed it and the process is only alive by luck",
        );
    let message = err.to_string();
    assert!(
        message.contains("nested deeper than") && message.contains(&MAX_ELEMENT_DEPTH.to_string()),
        "the refusal must say what it refused and why, got {message:?}"
    );

    // ---- the control: an ordinary reply still works ------------------------------------
    let benign_port = spawn_xmlrpc_responder(nested_response(3)).await;
    let benign_client = client_against(&state, &tx, benign_port).await;

    let outcome = state
        .send_to_client(
            benign_client,
            serde_json::json!({
                "type": "call_xmlrpc_method",
                "method_name": "anything",
                "params": []
            }),
            Duration::from_secs(30),
        )
        .await
        .expect("a three-level reply is ordinary and must still be parsed");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("server returned a result"),
            "the benign server answered with a value, so the detail must say so: {detail:?}"
        ),
        other => panic!("expected Executed, got {other:?}"),
    }
}

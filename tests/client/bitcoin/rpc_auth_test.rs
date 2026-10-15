//! The Bitcoin RPC credential: declared, applied, and kept off every screen.
//!
//! # What was wrong
//!
//! `rpc_user` and `rpc_password` were declared startup parameters that **nothing read**. Their
//! own examples in `src/client/bitcoin/actions.rs` set them, the dashboard offered the fields,
//! and the value went nowhere. bitcoind's RPC is auth-mandatory — it answers every
//! unauthenticated request `401` — so authenticated Bitcoin Core RPC could not work at all
//! through this client. `tests/startup_param_drift_test.rs` carried both on its baseline.
//!
//! The documented alternative was broken too, and less visibly. The client's own comment says
//! it accepts `http://user:pass@host:port`, and that URL was handed straight to `reqwest` —
//! which does **not** derive Basic auth from URL userinfo. So the one form an operator was told
//! to use also produced a 401, and nothing said so.
//!
//! # And the credential was being published
//!
//! The userinfo URL was stored in `rpc_url`, which the dashboard renders on the client's facts
//! line; it was echoed to the status stream on connect; and it was put into the
//! `bitcoin_client_connected` event, which is handed to **the model**. A password in the prompt
//! is not a display bug.
//!
//! # What this asserts
//!
//! A stub node that records what it receives, so the assertion is on the wire rather than on
//! our own formatting, plus the redaction in the three places a human or the model reads.

use netget::client::bitcoin::{redact_userinfo, split_userinfo};
use netget::state::client::{ClientId, ClientInstance};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A stub bitcoind: answers one JSON-RPC call and records the request headers it saw.
///
/// Deliberately raw TCP rather than a framework — the whole assertion is "what bytes arrived",
/// and a framework would decode them for us and hide a malformed header.
async fn stub_node(seen: Arc<Mutex<Vec<String>>>) -> std::io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                seen.lock().expect("stub node lock").push(request);

                let body = br#"{"result":{"chain":"regtest"},"error":null,"id":"netget"}"#;
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(body).await;
                let _ = socket.flush().await;
            });
        }
    });

    Ok(port)
}

/// Decode one `Authorization: Basic …` header out of a raw request.
fn basic_credential(request: &str) -> Option<String> {
    use base64::Engine;
    let line = request
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))?;
    let value = line.split_once(':')?.1.trim();
    let encoded = value.strip_prefix("Basic ")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    String::from_utf8(bytes).ok()
}

#[tokio::test]
async fn rpc_user_and_password_reach_the_node_as_basic_auth(
) -> Result<(), Box<dyn std::error::Error>> {
    use netget::client::bitcoin::BitcoinClient;
    use netget::state::app_state::AppState;

    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = stub_node(seen.clone()).await?;

    let state = Arc::new(AppState::new());
    let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel();
    // Empty instruction: no model is reachable here and none is wanted. The credential path
    // must work without one, which is also what keeps this test free of a mock.
    let client_id = state
        .add_client(ClientInstance::new(
            ClientId::new(0),
            format!("127.0.0.1:{port}"),
            "bitcoin".to_string(),
            String::new(),
        ))
        .await;

    BitcoinClient::connect_with_llm_actions(
        format!("127.0.0.1:{port}"),
        Some("bitcoinrpc".to_string()),
        Some("hunter2".to_string()),
        netget::llm::ollama_client::OllamaClient::new("http://127.0.0.1:1"),
        state.clone(),
        status_tx.clone(),
        client_id,
    )
    .await?;

    BitcoinClient::execute_rpc_command(
        client_id,
        "getblockchaininfo".to_string(),
        vec![],
        state.clone(),
        netget::llm::ollama_client::OllamaClient::new("http://127.0.0.1:1"),
        status_tx.clone(),
    )
    .await?;

    let requests = seen.lock().expect("stub node lock").clone();
    assert!(
        !requests.is_empty(),
        "the stub node received nothing, so the client never issued the RPC at all"
    );

    let credential = basic_credential(&requests[0]);
    assert_eq!(
        credential.as_deref(),
        Some("bitcoinrpc:hunter2"),
        "the declared rpc_user/rpc_password never reached the node. bitcoind answers every \
         unauthenticated request 401, so this is the difference between the client working \
         against a real node and not working at all.\n\nrequest was:\n{}",
        requests[0]
    );

    // The credential must not also be in the request line, where servers log it.
    let request_line = requests[0].lines().next().unwrap_or_default();
    assert!(
        !request_line.contains("hunter2"),
        "the password is in the request line: {request_line}"
    );

    // Nothing on the status stream may carry it either — that stream is the dashboard.
    let mut streamed = String::new();
    while let Ok(line) = status_rx.try_recv() {
        streamed.push_str(&line);
        streamed.push('\n');
    }
    assert!(
        !streamed.contains("hunter2"),
        "the password was published to the dashboard status stream:\n{streamed}"
    );

    Ok(())
}

/// The documented `http://user:pass@host:port` form works, which it never did.
#[tokio::test]
async fn a_userinfo_url_is_sent_as_basic_auth_too() -> Result<(), Box<dyn std::error::Error>> {
    use netget::client::bitcoin::BitcoinClient;
    use netget::state::app_state::AppState;

    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = stub_node(seen.clone()).await?;

    let state = Arc::new(AppState::new());
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();
    let addr = format!("http://alice:s3cret@127.0.0.1:{port}");
    let client_id = state
        .add_client(ClientInstance::new(
            ClientId::new(0),
            addr.clone(),
            "bitcoin".to_string(),
            String::new(),
        ))
        .await;

    BitcoinClient::connect_with_llm_actions(
        addr,
        None,
        None,
        netget::llm::ollama_client::OllamaClient::new("http://127.0.0.1:1"),
        state.clone(),
        status_tx.clone(),
        client_id,
    )
    .await?;

    BitcoinClient::execute_rpc_command(
        client_id,
        "getblockchaininfo".to_string(),
        vec![],
        state.clone(),
        netget::llm::ollama_client::OllamaClient::new("http://127.0.0.1:1"),
        status_tx,
    )
    .await?;

    let requests = seen.lock().expect("stub node lock").clone();
    assert!(!requests.is_empty(), "the client never issued the RPC");
    assert_eq!(
        basic_credential(&requests[0]).as_deref(),
        Some("alice:s3cret"),
        "reqwest does not derive Basic auth from URL userinfo, so the form this client's own \
         comment documents produced a 401 on every call.\n\nrequest was:\n{}",
        requests[0]
    );

    Ok(())
}

/// The splitting itself, including the cases a naive `split('@')` gets wrong.
#[test]
fn userinfo_splitting_handles_the_awkward_cases() {
    // No credential: unchanged, and nothing invented.
    assert_eq!(
        split_userinfo("http://127.0.0.1:8332"),
        ("http://127.0.0.1:8332".to_string(), None)
    );

    // A password containing `@` — the last one in the authority is the separator, not the first.
    let (url, credential) = split_userinfo("http://bob:p@ss@127.0.0.1:8332/");
    assert_eq!(url, "http://127.0.0.1:8332/");
    assert_eq!(
        credential,
        Some(("bob".to_string(), Some("p@ss".to_string())))
    );

    // An `@` in the PATH is not userinfo, and reading it as one would corrupt the URL.
    assert_eq!(
        split_userinfo("http://127.0.0.1:8332/wallet/my@wallet"),
        ("http://127.0.0.1:8332/wallet/my@wallet".to_string(), None)
    );

    // A user with no password is legal.
    let (_, credential) = split_userinfo("http://solo@127.0.0.1:8332");
    assert_eq!(credential, Some(("solo".to_string(), None)));
}

#[test]
fn redaction_keeps_the_host_and_drops_the_secret() {
    assert_eq!(
        redact_userinfo("http://alice:hunter2@127.0.0.1:8332"),
        "http://***@127.0.0.1:8332"
    );
    // Nothing to redact: unchanged, so a plain URL is not made uglier for no reason.
    assert_eq!(
        redact_userinfo("http://127.0.0.1:8332"),
        "http://127.0.0.1:8332"
    );
}

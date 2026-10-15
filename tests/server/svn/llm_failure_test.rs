//! The peer must be answered when the backend fails — with a category, never a diagnosis.
//!
//! The LLM endpoint is a port nothing listens on, so `call_llm` errors on the very first
//! event (`svn_greeting`). Before this path existed the server logged a warning and closed
//! the socket, leaving a real `svn` client to block on a greeting that never came.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features svn --test server -- svn::llm_failure --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

/// Port 1 on loopback: nothing listens, so every LLM call fails immediately.
async fn state_with_dead_backend() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
            if s.port != 0 {
                return s.port;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

/// Nothing internal may appear in what the peer reads. These are the tokens that leaked
/// across ~25 protocols in the original incident (see tests/wire_failure_test.rs).
fn assert_no_internals(line: &str) {
    for token in [
        "✗",
        "retries",
        "http://",
        "127.0.0.1",
        "11434",
        "qwen",
        "/Users/",
        "LLM",
        "Ollama",
        "ollama",
        "error sending request",
    ] {
        assert!(
            !line.contains(token),
            "svn failure tuple leaked {token:?}: {line:?}"
        );
    }
}

#[tokio::test]
async fn backend_failure_sends_a_failure_tuple_carrying_only_a_category() {
    let state = state_with_dead_backend().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // No event handlers at all: every event goes to the (dead) backend.
    let server_id = ServerForm {
        protocol: "svn".to_string(),
        port: Some(0),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create svn server");
    let port = wait_for_port(&state, server_id).await;

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let mut reader = BufReader::new(stream);

    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(60), reader.read_line(&mut line))
        .await
        .expect("the peer must be answered, not left hanging")
        .expect("read");

    assert!(n > 0, "peer got EOF instead of a failure tuple");

    // ra_svn's own error shape, with a counted-string message.
    assert!(
        line.starts_with("( failure ( ( "),
        "not an svn failure tuple: {line:?}"
    );
    assert!(
        line.trim_end().ends_with("0: 0 ) ) )"),
        "malformed: {line:?}"
    );
    // 210003 SVN_ERR_RA_SVN_IO_ERROR (overloaded, transient) or 210000
    // SVN_ERR_RA_SVN_CMD_ERR (unavailable). A refused connection is the latter.
    assert!(
        line.contains("210000 ") || line.contains("210003 "),
        "no apr error code: {line:?}"
    );
    assert!(
        line.contains("30:request could not be processed")
            || line.contains("32:backend at capacity, retry later"),
        "message is not a WireFailure category: {line:?}"
    );
    assert_no_internals(&line);

    // And the connection is closed rather than left half-alive.
    line.clear();
    let n = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line))
        .await
        .expect("EOF within 10s")
        .expect("read");
    assert_eq!(n, 0, "expected EOF after the failure tuple, got {line:?}");
}

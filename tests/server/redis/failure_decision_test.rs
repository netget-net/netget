//! The failure section of `src/server/redis/AGENTS.md`, as assertions on both the wire and the
//! log.
//!
//! On the wire a model's refusal, an answer with nothing usable in it, a backend failure and a
//! saturated backend all arrive as one `-…` simple error, so the server's own log is the only
//! place they differ, and the document promises a `decision=` tag for each. Each case here
//! reads the reply off a raw socket and the tag off the server's status channel:
//!
//! | case | wire | log |
//! |---|---|---|
//! | the model answers `redis_error` | its message | `decision=model_reject` |
//! | the model answers with no action | `-ERR no response produced for this command` | `decision=fail_closed_no_action` |
//! | the backend fails | `-ERR <category>`, nothing of the error itself | `decision=fail_closed_llm_error` |
//! | the backend is saturated | `-LOADING <category>`, which clients retry | `decision=fail_closed_llm_overloaded` |
//!
//! No model is reachable: the backend is a dead port, and the saturated case is the rate
//! limiter's own refusal (a token budget of zero), which is decided before any request.

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    // Pinned, so a call reaches the backend (or the rate limiter) instead of failing earlier
    // at auto-selecting a model.
    state
        .set_ollama_model(Some("absent-model".to_string()))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Redis server #{} never bound a port", id.as_u32());
}

/// Start a server, send `GET k`, and return the reply and every status line the server wrote
/// while answering it.
async fn get_k(
    state: &AppState,
    instruction: &str,
    event_handlers: Option<Vec<serde_json::Value>>,
) -> (String, Vec<String>) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "redis".to_string(),
        port: Some(0),
        instruction: Some(instruction.to_string()),
        event_handlers,
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create redis server");
    let port = wait_for_port(state, id).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    stream
        .write_all(b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n")
        .await
        .expect("write");
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut buf))
        .await
        .expect("a reply within 30s")
        .expect("read");
    let reply = String::from_utf8_lossy(&buf[..n]).to_string();

    // The decision is logged before the reply is written, so it is already in the channel.
    let mut lines = Vec::new();
    while let Ok(line) = rx.try_recv() {
        lines.push(line);
    }
    (reply, lines)
}

fn logged(lines: &[String], decision: &str) -> bool {
    lines.iter().any(|l| l.contains(decision))
}

#[tokio::test]
async fn a_model_refusal_and_an_empty_answer_are_told_apart_in_the_log() {
    let state = new_state().await;

    let (reply, lines) = get_k(
        &state,
        "",
        Some(vec![serde_json::json!({
            "event_pattern": "redis_command",
            "handler": {"type": "static", "actions": [
                {"type": "redis_error", "message": "NOPERM this user has no permissions to run the 'get' command"}
            ]}
        })]),
    )
    .await;
    assert_eq!(
        reply,
        "-NOPERM this user has no permissions to run the 'get' command\r\n"
    );
    assert!(
        logged(&lines, "decision=model_reject"),
        "a redis_error answer must be logged as the model's refusal: {lines:#?}"
    );

    let (reply, lines) = get_k(
        &state,
        "",
        Some(vec![serde_json::json!({
            "event_pattern": "redis_command",
            "handler": {"type": "static", "actions": []}
        })]),
    )
    .await;
    assert_eq!(reply, "-ERR no response produced for this command\r\n");
    assert!(
        logged(&lines, "decision=fail_closed_no_action"),
        "an answer with no reply in it must be logged as such: {lines:#?}"
    );
    assert!(!logged(&lines, "decision=model_reject"), "{lines:#?}");
}

#[tokio::test]
async fn a_failed_backend_is_err_and_a_saturated_one_is_loading() {
    let state = new_state().await;
    let (reply, lines) = get_k(&state, "Answer every command", None).await;
    assert!(
        reply.starts_with("-ERR ") && reply.ends_with("\r\n"),
        "a failed backend is a plain error: {reply:?}"
    );
    assert!(
        !reply.contains("127.0.0.1") && !reply.contains("absent-model"),
        "the peer gets a category, never the error itself: {reply:?}"
    );
    assert!(
        logged(&lines, "decision=fail_closed_llm_error"),
        "{lines:#?}"
    );

    // A token budget of zero: the rate limiter refuses every call before it is made, which is
    // the saturated case `is_overload_error` recognises.
    let saturated = new_state().await;
    saturated
        .configure_rate_limiter(netget::llm::RateLimiterConfig {
            token_limit: Some(0),
            ..Default::default()
        })
        .await
        .expect("configure the rate limiter");
    let (reply, lines) = get_k(&saturated, "Answer every command", None).await;
    assert!(
        reply.starts_with("-LOADING ") && reply.ends_with("\r\n"),
        "a saturated backend is LOADING, which clients treat as \"retry\": {reply:?}"
    );
    assert!(
        logged(&lines, "decision=fail_closed_llm_overloaded"),
        "{lines:#?}"
    );
}

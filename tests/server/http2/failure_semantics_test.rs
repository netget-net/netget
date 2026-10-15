//! What an HTTP/2 client gets when netget cannot, or will not, answer.
//!
//! The HTTP/1.1 equivalent (`tests/server/http/failure_semantics_test.rs`) is the one root
//! `CLAUDE.md` tells other protocols to copy. HTTP/2 answered a flat 500 for both an
//! overloaded backend and a broken one, and read `default_response` nowhere despite
//! advertising it as a startup parameter. These tests pin the corrected behaviour.
//!
//! As on HTTP/1.1, the assertion that the failure body carries a *category* and not the
//! error text is doing as much work as the status assertion: the backend URL, the model
//! name, netget's own retry text and `anyhow` context chains all reached the wire in ~25
//! protocols at once, because each one was written by copying its neighbour.

use super::super::helpers::{self, E2EResult};
use std::time::Duration;

/// Start an HTTP/2 server whose *only* mocked call is the startup instruction. Every
/// `http2_request` event is unmatched, so the mock answers HTTP 500 and netget reports an
/// LLM failure for that stream.
async fn server_with_failing_model() -> E2EResult<helpers::server::NetGetServer> {
    let config = helpers::NetGetConfig::new("Start an HTTP/2 server on port {AVAILABLE_PORT}")
        .with_mock(|mock| {
            mock.on_custom(|ctx| !ctx.instruction.contains("Event ID:"))
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP2",
                        "instruction": "HTTP/2 server"
                    }
                ]))
                .expect_calls(1)
                .and()
        });
    helpers::start_netget_server(config).await
}

fn h2_client() -> E2EResult<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .http2_prior_knowledge()
        .build()?)
}

/// A backend failure must produce a status code on the stream, not a hang and not a bare
/// reset.
#[tokio::test]
async fn test_http2_answers_500_when_the_llm_fails() -> E2EResult<()> {
    let server = server_with_failing_model().await?;

    let response = h2_client()?
        .get(format!("http://127.0.0.1:{}/", server.port))
        .send()
        .await
        .map_err(|e| {
            format!("the HTTP/2 server neither answered nor reset the stream within 20s: {e}")
        })?;

    // A mock returning HTTP 500 is a backend error, not an overload. 503 + Retry-After is
    // reserved for a saturated backend so a client can tell a retryable failure from a
    // permanent one — a distinction HTTP/2 could not express before.
    assert_eq!(
        response.status().as_u16(),
        500,
        "a backend error must answer 500; 503 + Retry-After is reserved for overload"
    );
    assert!(
        response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .is_none(),
        "Retry-After must not be sent for a permanent fault — it invites a pointless retry"
    );

    let body = response.text().await?;
    assert!(
        body.contains("netget"),
        "the failure body should name netget so an operator knows which process answered, \
         got: {body:?}"
    );
    for leak in [
        "ollama",
        "LLM failed",
        "retries",
        "Caused by",
        "http://127.0.0.1:11",
    ] {
        assert!(
            !body
                .to_ascii_lowercase()
                .contains(&leak.to_ascii_lowercase()),
            "internal detail {leak:?} leaked into the response body {body:?} — the peer gets \
             a category, the log gets the error"
        );
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A request body over `MAX_REQUEST_BODY_BYTES` is refused with 413, without an LLM call.
///
/// `release_capacity` re-opens the HTTP/2 flow-control window after each chunk, so without
/// a total limit a peer could stream an unbounded amount into the buffer that then becomes
/// an LLM prompt. `expect_calls(1)` on the startup rule is what proves no model call was
/// spent: an unmatched `http2_request` would be a second recorded call.
#[tokio::test]
async fn test_http2_refuses_an_oversized_request_body() -> E2EResult<()> {
    let server = server_with_failing_model().await?;

    let oversized = vec![b'a'; netget::server::http_common::MAX_REQUEST_BODY_BYTES + 1];

    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .http2_prior_knowledge()
        .build()?
        .post(format!("http://127.0.0.1:{}/upload", server.port))
        .body(oversized)
        .send()
        .await
        .map_err(|e| format!("the server neither answered nor closed on an oversized body: {e}"))?;

    assert_eq!(
        response.status().as_u16(),
        413,
        "an oversized request body must be refused with 413, not buffered and handed to the \
         model"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

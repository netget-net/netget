//! What an HTTP client gets when netget cannot, or will not, answer.
//!
//! `CLAUDE.md` names HTTP as the reference implementation for answering a peer on LLM
//! failure ("copy `http` (503 + `Retry-After` vs 500)"), so ~44 other protocols were
//! written by looking at it. Nothing tested it. These two tests pin the parts other
//! protocols are told to copy:
//!
//! - a backend failure produces a real status code, promptly, instead of leaving the
//!   client to hang until its own timeout, and
//! - the response body carries a *category*, never the error text. Backend URLs, model
//!   names, file paths and `anyhow` context chains reached the wire in ~25 protocols at
//!   once because each copied its neighbour; the assertion below is what stops that
//!   coming back here.
//!
//! The third test covers the request-body bound. An HTTP body is buffered whole and then
//! embedded in an LLM prompt, so an unbounded one is a memory exhaustion with no upside;
//! over the cap the server answers 413 and spends no LLM call at all.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;

/// Start an HTTP server whose *only* mocked call is the startup instruction. Every
/// `http_request` event is unmatched, so the mock answers HTTP 500 and netget reports an
/// LLM failure for that turn — the condition both failure tests need.
async fn server_with_failing_model() -> E2EResult<helpers::server::NetGetServer> {
    let config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via http stack").with_mock(|mock| {
            mock.on_custom(|ctx| !ctx.instruction.contains("Event ID:"))
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "HTTP",
                        "instruction": "HTTP server"
                    }
                ]))
                .expect_calls(1)
                .and()
        });
    helpers::start_netget_server(config).await
}

/// A backend failure must produce a status code, not silence.
#[tokio::test]
async fn test_http_answers_500_when_the_llm_fails() -> E2EResult<()> {
    let server = server_with_failing_model().await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;
    let response = client
        .get(format!("http://127.0.0.1:{}/", server.port))
        .send()
        .await
        .map_err(|e| {
            format!(
                "the HTTP server neither answered nor closed within 20s on LLM failure \
                 (this is the 'reset to Idle and write nothing' defect): {e}"
            )
        })?;

    // A mock returning HTTP 500 is a backend error, not an overload, so this is the
    // permanent-fault code. 503 is reserved for a saturated backend precisely so a
    // client can tell a retryable failure from a permanent one.
    assert_eq!(
        response.status().as_u16(),
        500,
        "a backend error must answer 500; 503 + Retry-After is reserved for overload"
    );

    let body = response.text().await?;

    // The category reaches the peer; the diagnosis does not.
    assert!(
        body.contains("netget"),
        "the failure body should name netget so an operator poking at their own server \
         knows which process answered, got: {body:?}"
    );
    for leak in [
        "ollama",
        "http://127.0.0.1:11",
        "LLM failed",
        "retries",
        "model",
        "Caused by",
    ] {
        assert!(
            !body
                .to_ascii_lowercase()
                .contains(&leak.to_ascii_lowercase()),
            "internal detail {leak:?} leaked into the response body {body:?} — the peer \
             gets a category, the log gets the error"
        );
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The failure response must be a well-formed HTTP message, not merely a status code
/// `reqwest` was willing to accept.
///
/// `CLAUDE.md` names this server as the thing ~44 other protocols were written by
/// copying, so its error path is the most-replicated wire format in the tree — and it
/// is hand-assembled, on a branch no model is involved in, which is where a missing
/// `Content-Length` or a header block terminated by a bare LF lives. `reqwest` cannot
/// see any of that: it is lenient by design and reports the status either way.
///
/// So this test takes a raw socket, reads the whole response, and hands it to
/// Wireshark's HTTP dissector. A `Content-Length` that disagrees with the body makes
/// the dissector wait for bytes that never arrive, and the response is reported as
/// undissectable plain TCP.
#[tokio::test]
async fn test_http_failure_response_is_well_formed_on_the_wire() -> E2EResult<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let server = server_with_failing_model().await?;

    let request = format!(
        "GET /oracle HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        server.port
    );

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port)).await?;
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    // Read to EOF: `Connection: close` means the whole response is everything that
    // arrives before the close, so nothing is left buffered for the oracle to miss.
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut response))
        .await
        .map_err(|_| "the HTTP server neither answered nor closed within 20s on LLM failure")??;

    assert!(
        response.starts_with(b"HTTP/1.1 500 "),
        "expected a 500 status line, got: {:?}",
        String::from_utf8_lossy(&response[..response.len().min(120)])
    );

    crate::helpers::pcap_oracle::PcapOracle::tcp("http")
        .to_server(request.as_bytes())
        .from_server(&response)
        .assert_clean();

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The same failure must not leak through a body-carrying method either, and must still
/// be prompt. POST is the path that also exercises request-body extraction.
#[tokio::test]
async fn test_http_failure_body_is_a_category_on_post_too() -> E2EResult<()> {
    let server = server_with_failing_model().await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;
    let response = client
        .post(format!("http://127.0.0.1:{}/api", server.port))
        .body("{\"hello\": \"world\"}")
        .send()
        .await
        .map_err(|e| format!("HTTP server went silent on LLM failure for POST: {e}"))?;

    assert_eq!(response.status().as_u16(), 500);
    let body = response.text().await?;
    assert!(
        !body.contains("Ollama") && !body.contains("http://"),
        "internal detail leaked into the response body: {body:?}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A request body over `MAX_REQUEST_BODY_BYTES` is refused with 413, without an LLM call.
///
/// The `expect_calls(1)` on the startup rule is what proves "without an LLM call": if the
/// oversized request reached the model, the unmatched `http_request` event would be a
/// second call the mock records and `verify_mocks` would report the mismatch.
#[tokio::test]
async fn test_http_refuses_an_oversized_request_body() -> E2EResult<()> {
    let server = server_with_failing_model().await?;

    // One byte over the 8 MiB cap in `http_common::handler::MAX_REQUEST_BODY_BYTES`.
    let oversized = vec![b'a'; netget::server::http_common::MAX_REQUEST_BODY_BYTES + 1];

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let response = client
        .post(format!("http://127.0.0.1:{}/upload", server.port))
        .body(oversized)
        .send()
        .await
        .map_err(|e| format!("the server neither answered nor closed on an oversized body: {e}"))?;

    assert_eq!(
        response.status().as_u16(),
        413,
        "an oversized request body must be refused with 413, not buffered and handed to \
         the model"
    );

    // A request the server refused before reading must not have cost an LLM call: only
    // the startup instruction is expected, and an extra call would fail verify_mocks.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

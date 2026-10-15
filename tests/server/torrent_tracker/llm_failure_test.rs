//! What a BitTorrent client gets when the LLM backend fails.
//!
//! An announce is a request/response exchange: the client waits for a peer list, retries, and
//! eventually marks the tracker dead. Silence is therefore a stall rather than a "not me",
//! and until this pass the answer was a bare
//! `HTTP/1.1 500 Internal Server Error\r\n\r\n` — no `Content-Length`, no
//! `Connection: close`, no body, and no way for a client to tell "come back later" from
//! "this tracker is broken".
//!
//! The failure is forced by configuring a mock for the *startup* instruction only. The
//! `tracker_announce_request` event then matches no rule, the mock Ollama server answers HTTP
//! 500, and `call_llm` returns `Err` — the same shape as a real backend outage.
//!
//! Three things are asserted, and each is a separate defect if it regresses:
//!
//! 1. A **complete** HTTP response arrives, with a `Content-Length` and `Connection: close`.
//! 2. Its body is a bencoded `failure reason` — the one refusal BEP 3 defines and the only
//!    thing a BitTorrent client displays.
//! 3. That text carries **nothing** from the error: no backend URL, no model name, no path,
//!    no `anyhow` chain. It is the fixed `WireFailure` category.

use crate::helpers::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The dual-logged line that proves the refusal came from the LLM-error path rather than from
/// the model answering with `send_error_response`.
const FAIL_CLOSED_LOG: &str = "decision=fail_closed_llm_error";

/// Anything from netget's internals that must never reach a stranger's BitTorrent client.
const FORBIDDEN_IN_WIRE_TEXT: &[&str] = &[
    "✗", "retries", "http://", "11434", "qwen", "/Users/", "llama", "Ollama", "ollama", "model",
];

#[tokio::test]
async fn tracker_answers_a_category_when_the_llm_fails() -> E2EResult<()> {
    let config = NetGetConfig::new_no_scripts(
        "Listen on port {AVAILABLE_PORT} via torrent-tracker and answer announces.".to_string(),
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("torrent-tracker")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "Torrent-Tracker",
                "instruction": "BitTorrent tracker"
            }]))
            .expect_calls(1)
            .and()
        // Deliberately NO rule for tracker_announce_request: the mock answers HTTP 500,
        // which drives the server down its LLM-failure path.
    });

    let server = start_netget_server(config).await?;

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    stream
        .write_all(
            b"GET /announce?info_hash=%01%02%03%04%05%06%07%08%09%0a%0b%0c%0d%0e%0f%10%11%12%13%14\
              &peer_id=-NG0001-abcdefghijkl&port=6881&uploaded=0&downloaded=0&left=100 HTTP/1.1\r\n\
              Host: 127.0.0.1\r\n\r\n",
        )
        .await?;

    // `Connection: close` means the server hangs up, so reading to EOF is the whole response.
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut raw))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no HTTP reply: an LLM failure left the announcing client waiting out its own \
                 timeout, which is the defect this test exists for",
            )
        })??;

    let text = String::from_utf8_lossy(&raw).to_string();
    assert!(!raw.is_empty(), "the tracker wrote nothing at all");

    // A real status line, and a framed response rather than a bare two-CRLF stub.
    assert!(
        text.starts_with("HTTP/1.1 503") || text.starts_with("HTTP/1.1 500"),
        "expected 503 (overloaded) or 500 (other), got: {text:?}"
    );
    assert!(
        text.to_ascii_lowercase().contains("content-length:"),
        "the refusal must be framed; a client cannot tell where a body-less 500 ends: {text:?}"
    );
    assert!(
        text.to_ascii_lowercase().contains("connection: close"),
        "the refusal must say the connection is finished: {text:?}"
    );

    // The body is BEP 3's own refusal, so a BitTorrent client displays it.
    let body_start = text
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .expect("a complete HTTP response has a header terminator");
    let body = &raw[body_start..];
    assert!(
        !body.is_empty(),
        "the refusal must carry a bencoded `failure reason` body"
    );
    let decoded: serde_bencode::value::Value = serde_bencode::from_bytes(body)
        .unwrap_or_else(|e| panic!("body must be bencode, got {body:?}: {e}"));
    let serde_bencode::value::Value::Dict(dict) = decoded else {
        panic!("a tracker refusal is a bencoded dictionary");
    };
    let reason = match dict.get::<[u8]>(b"failure reason") {
        Some(serde_bencode::value::Value::Bytes(b)) => String::from_utf8_lossy(b).to_string(),
        other => panic!("expected a `failure reason` byte string, got {other:?}"),
    };
    assert!(
        !reason.is_empty(),
        "the failure reason must say something about the category"
    );
    for token in FORBIDDEN_IN_WIRE_TEXT {
        assert!(
            !reason.to_lowercase().contains(&token.to_lowercase()),
            "the tracker's failure reason leaked {token:?} from netget's internals: {reason:?}. \
             The peer gets a category; the error goes to the log.",
        );
    }

    // The refusal must be recorded, and distinguishably: a model answering with
    // `send_error_response` never writes this line, only a failed call does.
    server.wait_for_log(FAIL_CLOSED_LOG, 15).await?;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

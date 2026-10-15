//! What a Telnet client gets when the LLM backend fails: a plain notice on its own line.
//!
//! Telnet is where "send a protocol-appropriate error" has the least to work with. There is no
//! status code, no framing and no transaction id - it is an unstructured byte stream with a
//! human on the other end. So the protocol-appropriate answer is literally a sentence, written
//! on its own CRLF-delimited line so it cannot be mistaken for the output of whatever the user
//! typed, and prefixed `[netget]` so it is clearly the server speaking rather than the
//! simulated system.
//!
//! Silence would be the wrong call here even though the protocol has no error frame, because
//! unlike bare UDP there is a connection and a human waiting on it: a Telnet session that
//! stops answering is indistinguishable from one that has hung.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_telnet_writes_a_notice_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via telnet. Echo back what you receive";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via telnet")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Telnet",
                    "instruction": "Echo back what you receive"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `telnet_message_received`, so every line fails.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write_half.write_all(b"hello\r\n").await?;
    write_half.flush().await?;

    // The notice opens with CRLF so it starts on a fresh line; skip that empty line.
    let notice = loop {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
            .await
            .map_err(|_| {
                "No Telnet output within 20s - the server went silent on LLM failure, which is \
                 the exact defect this test exists to catch"
            })??;
        if n == 0 {
            return Err("Telnet connection closed without writing anything".into());
        }
        if !line.trim().is_empty() {
            break line;
        }
    };

    println!("Telnet notice: {}", notice.trim());
    assert!(
        notice.trim_start().starts_with("[netget]"),
        "expected a [netget] notice telling the user the server could not answer, got: {notice}"
    );
    assert!(
        !notice.contains("hello"),
        "the notice must not look like the echo the handler would have produced: {notice}"
    );

    // The notice used to interpolate the error, so a plain telnet session printed
    // `[netget] cannot answer right now: ✗  LLM failed to generate valid response after
    // retries.` — netget's own retry machinery on a stranger's terminal. Nothing about how
    // this server is built is the peer's to read; the detail belongs in the log and the TUI.
    // See `tests/wire_failure_test.rs` and `src/utils/wire_failure.rs`.
    for token in [
        "✗",
        "retries",
        "LLM",
        "llm",
        "Ollama",
        "ollama",
        "http://",
        "127.0.0.1",
        "telnet_message_received",
        "anyhow",
        "Error(",
    ] {
        assert!(
            !notice.contains(token),
            "the notice leaked netget's internals to the peer ({token:?}): {notice}"
        );
    }

    // The notice tells the human; the log has to tell the operator *which* failure it was.
    // A `[netget] …` line on the wire is a category — it reads the same whether the backend
    // was overloaded, unreachable, or the model refused — so the grep-able token is the only
    // thing separating this from the model's own silence (see `decision_tag_test.rs`).
    server
        .wait_for_any(
            &[
                "decision=fail_closed_llm_error",
                "decision=fail_closed_llm_overloaded",
            ],
            30,
        )
        .await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=fail_closed_llm_error")
                || l.contains("decision=fail_closed_llm_overloaded")),
        "the backend failure must be tagged decision=fail_closed_llm_* so `grep \
         decision=fail_closed` finds it. Output was:\n{}",
        lines.join("\n")
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

//! What a memcached client gets when the LLM backend fails: `SERVER_ERROR`.
//!
//! `SERVER_ERROR <text>` is protocol.txt's own form for "the command was valid and the server
//! failed to run it". No client treats it as data, so it cannot be read as a cache hit, a
//! stored value or a successful delete - which matters more here than in most protocols,
//! because `END` (a miss) is a perfectly ordinary answer that a broken server could otherwise
//! produce by accident.
//!
//! The reason text is stripped of CR/LF: memcached replies are CRLF-terminated with no length
//! prefix, so a newline inside the text ends the reply early and the remainder is parsed as
//! the next one.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_memcached_answers_server_error_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via memcached. Serve a small cache";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via memcached")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "memcached",
                    "instruction": "Serve a small cache"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for any memcached event, so every command fails.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write_half.write_all(b"get greeting\r\n").await?;
    write_half.flush().await?;

    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| {
            "No memcached reply within 20s - the server went silent on LLM failure, which is \
             the exact defect this test exists to catch"
        })??;
    assert!(n > 0, "memcached closed the connection without replying");

    println!("memcached reply: {}", line.trim());
    assert!(
        line.starts_with("SERVER_ERROR "),
        "expected SERVER_ERROR for a command the backend could not answer, got: {line}"
    );
    assert!(
        !line.starts_with("END") && !line.starts_with("VALUE"),
        "a backend failure must not be reported as a cache miss or a value: {line}"
    );
    assert!(
        line.contains("netget"),
        "the text should name the source of the failure: {line}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

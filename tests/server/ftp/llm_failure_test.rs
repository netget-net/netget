//! What an FTP client gets when the LLM backend fails: a 4xx, never silence.
//!
//! The command path already answered 421. The greeting did not: it logged the failure and
//! carried on into the command loop, so the client sat blocked reading a banner it may not
//! proceed without - an FTP client is not permitted to send a command until it has read a
//! greeting, so the whole session stalled before it began.
//!
//! RFC 959 defines 421 as the reply a server sends when it is declining the session, and the
//! control connection closes afterwards. Same shape as SMTP's 421, for the same reason.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_ftp_answers_421_when_greeting_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via ftp. Serve an anonymous archive";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via ftp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "FTP",
                    "instruction": "Serve an anonymous archive"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `ftp_command`, so even CONNECTION_ESTABLISHED fails.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, _write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let mut greeting = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut greeting))
        .await
        .map_err(|_| {
            "No FTP greeting within 20s - the server went silent on LLM failure, which is the \
             exact defect this test exists to catch"
        })??;
    assert!(n > 0, "FTP closed the connection without a greeting");

    println!("FTP greeting: {}", greeting.trim());
    assert!(
        greeting.starts_with("421 "),
        "expected 421 (service not available) instead of a 220 that cannot be honoured, got: \
         {greeting}"
    );
    assert!(
        !greeting.starts_with('2'),
        "a 2xx greeting would invite the client into a session the server cannot serve: \
         {greeting}"
    );
    assert!(
        greeting.contains("netget"),
        "the text should name the source of the failure: {greeting}"
    );

    // 421 closes the control connection.
    let mut trailing = String::new();
    let n = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut trailing))
        .await
        .map_err(|_| "the server did not close the control connection after 421")??;
    assert_eq!(n, 0, "expected EOF after 421, got: {trailing}");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

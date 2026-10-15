//! FTP tags every terminal outcome with a `decision=` token, and the failure paths never
//! produce a 2xx.
//!
//! The second half is the one that matters. FTP's most dangerous possible defect is a
//! fail-open on authentication: if a backend outage or a silent model turned into a `230
//! User logged in`, an LLM failure would be an authentication bypass, which is precisely the
//! OAuth2 post-mortem in the root `CLAUDE.md`. Nothing in `src/server/ftp/actions.rs` can
//! synthesise a reply - `execute_action` produces only the packet a named action asked for -
//! so the property holds structurally, and this test pins it from the wire.
//!
//! The first test drives a backend failure on `USER` and asserts a 421 plus the
//! `decision=fail_closed_llm_*` tag. The second drives an explicit `close_connection` and
//! asserts `decision=model_reject`, because a refusal and an outage both end the session and
//! only the log says which.
//!
//! See `src/server/ftp/CLAUDE.md`, "Failure behaviour".


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Read one CRLF-terminated control line, failing loudly rather than hanging.
async fn read_reply(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    what: &str,
) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(30), reader.read_line(&mut line))
        .await
        .map_err(|_| format!("no FTP reply to {what} within 30s"))??;
    assert!(n > 0, "FTP closed the control connection instead of {what}");
    Ok(line)
}

/// The backend fails while answering `USER`. The client must get a 421, never a 2xx.
#[tokio::test]
async fn test_ftp_backend_failure_is_tagged_and_never_answers_2xx() -> E2EResult<()> {
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
            // Only the greeting is answered. `CONNECTION_ESTABLISHED` is a sentinel the
            // server raises itself, never a command a client sends, so this rule cannot
            // match the USER below - which is what makes the two distinguishable at all.
            .on_event("ftp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([{
                "type": "send_ftp_response",
                "code": 220,
                "message": "NetGet FTP ready"
            }]))
            .expect_calls(1)
            .and()
        // No rule for USER: the mock answers HTTP 500 and `call_llm` returns Err.
    });

    let server = start_netget_server(config).await?;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_reply(&mut reader, "the greeting").await?;
    assert!(
        greeting.starts_with("220 "),
        "expected the mocked 220 greeting, got: {greeting}"
    );

    write_half.write_all(b"USER anonymous\r\n").await?;
    write_half.flush().await?;

    let reply = read_reply(&mut reader, "USER").await?;
    println!("FTP answered USER with: {}", reply.trim());

    assert!(
        !reply.starts_with('2'),
        "A 2xx reply to USER when the backend failed would be a fail-open on authentication: \
         the model never approved anything. Got: {reply}"
    );
    assert!(
        reply.starts_with("421 "),
        "RFC 959 421 is how a server declines the session; got: {reply}"
    );
    assert!(
        !reply.contains("LLM") && !reply.contains("Ollama") && !reply.contains("http"),
        "the peer gets a WireFailure category, never netget's internal error text: {reply}"
    );

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
        lines.iter().any(|l| l.contains("decision=fail_closed_llm")),
        "a backend failure must be greppable as decision=fail_closed_llm_*. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=model_answer") && l.contains("220")),
        "the greeting the model did answer must be tagged model_answer with its reply code, \
         or the tag carries no information. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// `close_connection` is the model refusing. It ends the session exactly as a 421 does, and
/// only the log distinguishes the two.
#[tokio::test]
async fn test_ftp_close_connection_is_tagged_model_reject() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via ftp. Hang up on anyone who sends QUIT";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via ftp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "FTP",
                    "instruction": "Hang up on anyone who sends QUIT"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("ftp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(serde_json::json!([{
                "type": "send_ftp_response",
                "code": 220,
                "message": "NetGet FTP ready"
            }]))
            .expect_calls(1)
            .and()
            .on_event("ftp_command")
            .and_event_data_contains("command", "QUIT")
            .respond_with_actions(serde_json::json!([{ "type": "close_connection" }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_reply(&mut reader, "the greeting").await?;
    assert!(greeting.starts_with("220 "), "got: {greeting}");

    write_half.write_all(b"QUIT\r\n").await?;
    write_half.flush().await?;

    // `close_connection` writes nothing, so the next thing the client sees is EOF.
    let mut trailing = String::new();
    let n = tokio::time::timeout(Duration::from_secs(30), reader.read_line(&mut trailing))
        .await
        .map_err(|_| "the server did not close the control connection after close_connection")??;
    assert_eq!(
        n, 0,
        "close_connection sends no reply; expected EOF, got: {trailing}"
    );

    server.wait_for_any(&["decision=model_reject"], 30).await;

    let lines = server.get_output().await;
    assert!(
        lines.iter().any(|l| l.contains("decision=model_reject")),
        "an explicit close_connection must be tagged model_reject, distinct from the 421 a \
         backend failure produces. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=fail_closed")),
        "nothing failed here; the model decided. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

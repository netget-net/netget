//! Telnet's three quiet endings, told apart in the log.
//!
//! `llm_failure_test.rs` beside this one covers the loud ending: when the backend fails the
//! peer gets a `[netget] …` notice (a category, never the error) and the log carries
//! `decision=fail_closed_llm_*`.
//!
//! The other three write **nothing** to the socket, which is where the ambiguity lives:
//!
//! | the model… | what the peer sees |
//! |---|---|
//! | answered `close_connection` | the session ends, with no reply |
//! | answered `wait_for_more` | nothing; the session stays open |
//! | answered with no action at all | nothing; the session stays open |
//!
//! The last two are indistinguishable from the peer's seat — a human sitting at a terminal
//! that looks hung — and were indistinguishable in the log too, because neither wrote a line.
//! `decision=model_reject`, `decision=model_wait_for_more` and `decision=model_silent` are
//! what separate them now.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn open_telnet_server() -> serde_json::Value {
    serde_json::json!([
        {
            "type": "open_server",
            "port": 0,
            "base_stack": "Telnet",
            "instruction": "Answer lines"
        }
    ])
}

/// The model hung up instead of answering. The session ends with no reply, and the log says
/// it was the model's choice rather than a backend that fell over.
#[tokio::test]
async fn test_telnet_close_connection_is_logged_as_a_refusal() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via telnet. Hang up on anything you dislike";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via telnet")
            .respond_with_actions(open_telnet_server())
            .expect_calls(1)
            .and()
            .on_event("telnet_connection_opened")
            // Raised for every connection; this server has nothing to say first.
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            .on_event("telnet_message_received")
            .respond_with_actions(serde_json::json!([{ "type": "close_connection" }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    stream.write_all(b"hello\r\n").await?;
    stream.flush().await?;

    // The session must end, and end silently: a `close_connection` with no output action is
    // the model declining to say anything, not an error to narrate at the peer.
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(20), stream.read(&mut buf))
        .await
        .map_err(|_| {
            "the Telnet session neither answered nor closed within 20s after close_connection"
        })??;
    assert_eq!(
        n,
        0,
        "close_connection with no reply must close the session without writing anything, got: \
         {:?}",
        String::from_utf8_lossy(&buf[..n])
    );

    server.wait_for_any(&["decision=model_reject"], 30).await;

    let lines = server.get_output().await;
    assert!(
        lines.iter().any(|l| l.contains("decision=model_reject")),
        "a close_connection with no reply must be logged decision=model_reject, distinct from \
         a backend failure and from the model saying nothing. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=fail_closed")),
        "the model answered; nothing here failed closed. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The model was reached and answered with no action at all. The peer gets nothing and the
/// session stays open — a terminal that looks hung — so the log is the only record that a
/// turn happened at all.
#[tokio::test]
async fn test_telnet_empty_answer_is_logged_as_model_silence() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via telnet. Answer lines";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via telnet")
            .respond_with_actions(open_telnet_server())
            .expect_calls(1)
            .and()
            .on_event("telnet_connection_opened")
            // Raised for every connection; this server has nothing to say first.
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            .on_event("telnet_message_received")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    stream.write_all(b"hello\r\n").await?;
    stream.flush().await?;

    server.wait_for_any(&["decision=model_silent"], 30).await;

    // Nothing is written and the session is left open. This is the current behaviour, not an
    // endorsement of it: the peer cannot tell this from a server that has hung. It is
    // asserted so that changing it is deliberate, and the log line is what makes it
    // diagnosable in the meantime.
    let mut buf = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
        Err(_) => { /* nothing written, session still open: the expected outcome */ }
        Ok(Ok(0)) => {
            return Err("the session was closed; an empty model answer must not hang up".into())
        }
        Ok(Ok(n)) => {
            return Err(format!(
                "the server wrote {n} bytes for an answer that contained no action: {:?}",
                String::from_utf8_lossy(&buf[..n])
            )
            .into())
        }
        Ok(Err(e)) => return Err(format!("Telnet read failed: {e}").into()),
    }

    let lines = server.get_output().await;
    assert!(
        lines.iter().any(|l| l.contains("decision=model_silent")),
        "a model that returned no usable action must be logged decision=model_silent — the \
         peer sees an idle session and has no other way to learn a turn even happened. Output \
         was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=model_answer")),
        "the model answered nothing; it must not be logged as having answered. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

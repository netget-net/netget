//! `send_ftp_command` ends every command with exactly one CRLF, read from the wire.
//!
//! The peer is a plain `TcpListener` standing in for an FTP server, so the bytes asserted are
//! the bytes the client wrote and nothing NetGet's own server might normalise. A command the
//! model ends with `\n` is the case that matters: written as `NOOP\r` with no LF, a server
//! reading to the newline never sees the end of the command.
//!
//! Zero LLM calls: the client's backend is a dead port (the read loop tolerates the error) and
//! every command is injected through `AppState::send_to_client`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,mcp-http,sqlite,terminal-snapshot \
//!       --test client -- ftp::line_ending_test

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("client #{} never registered a command handle", id.as_u32());
}

#[tokio::test]
async fn send_ftp_command_ends_every_command_with_one_crlf() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "ftp".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect("create ftp client");

    let (mut peer, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the FTP client never connected")
        .unwrap();
    peer.write_all(b"220 stand-in server\r\n").await.unwrap();
    wait_for_client_handle(&state, client_id).await;

    // Each ending a model might write: "\n", none, "\r\n", and a stray "\r".
    let commands = ["NOOP\n", "PWD", "SYST\r\n", "TYPE I\r"];
    for command in commands {
        let outcome = state
            .send_to_client(
                client_id,
                serde_json::json!({"type": "send_ftp_command", "command": command}),
                Duration::from_secs(5),
            )
            .await
            .expect("send_to_client");
        assert!(
            matches!(outcome, ClientSendOutcome::Sent { .. }),
            "{command:?}: {outcome:?}"
        );
    }

    let expected = b"NOOP\r\nPWD\r\nSYST\r\nTYPE I\r\n";
    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    while got.len() < expected.len() {
        let n = tokio::time::timeout(Duration::from_secs(10), peer.read(&mut buf))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the server side received {:?} and then nothing for 10s",
                    String::from_utf8_lossy(&got)
                )
            })
            .unwrap();
        assert!(
            n > 0,
            "client closed after {:?}",
            String::from_utf8_lossy(&got)
        );
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(expected),
        "every command must reach the server ending in exactly one CRLF"
    );
}

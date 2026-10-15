//! The dashboard's `[ send ]` path on an SMTP client: `AppState::send_to_client` injects a
//! `send_email` from outside the client's own task and a real message lands on a real socket.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so its connected-event call
//! fails — the loop tolerates that, and the command task is registered *and already draining*
//! before that call, which is the regression this test guards.
//!
//! **Why the peer here is a hand-rolled listener rather than a NetGet SMTP server.** NetGet's
//! SMTP server raises exactly one event id (`smtp_command`) for the banner and for every
//! command, so a `static` handler is forced to answer `CONNECTION_ESTABLISHED`, `EHLO`,
//! `MAIL FROM`, `RCPT TO`, `DATA` and `.` with identical bytes and no session can complete.
//! Driving it would take a `script` handler; a ~40-line responder is the smaller, more
//! honest dependency, and the assertion is still on bytes that crossed a socket.
//!
//! Outcome semantics under test: `lettre` opens its own connection per message and reports no
//! byte count, so a delivered message is `Executed` naming the recipients and the endpoint,
//! never `Sent`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features smtp --test client -- smtp::command_channel --test-threads=100


use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "SMTP client #{} never registered a command handle",
        id.as_u32()
    );
}

/// Just enough SMTP to accept one message from `lettre`. Returns the bound port and a handle
/// on everything the client said, so the test can assert on bytes that really crossed.
async fn start_mock_smtp() -> (u16, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();
    let transcript = Arc::new(Mutex::new(String::new()));
    let sink = transcript.clone();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let sink = sink.clone();
            tokio::spawn(async move {
                let (read_half, mut write_half) = tokio::io::split(stream);
                let mut reader = BufReader::new(read_half);
                if write_half
                    .write_all(b"220 mock.netget.test ESMTP\r\n")
                    .await
                    .is_err()
                {
                    return;
                }

                let mut in_data = false;
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                    sink.lock().await.push_str(&line);

                    let reply: &[u8] = if in_data {
                        if line.trim_end() == "." {
                            in_data = false;
                            b"250 2.0.0 Ok: queued\r\n"
                        } else {
                            continue; // message body line
                        }
                    } else {
                        let verb = line
                            .split_whitespace()
                            .next()
                            .unwrap_or_default()
                            .to_uppercase();
                        match verb.as_str() {
                            // The last line of a multiline reply uses a space, not a hyphen.
                            "EHLO" | "LHLO" => b"250-mock.netget.test\r\n250 8BITMIME\r\n",
                            "HELO" => b"250 mock.netget.test\r\n",
                            "MAIL" | "RCPT" | "RSET" | "NOOP" => b"250 2.0.0 Ok\r\n",
                            "DATA" => {
                                in_data = true;
                                b"354 End data with <CR><LF>.<CR><LF>\r\n"
                            }
                            "QUIT" => {
                                let _ = write_half.write_all(b"221 2.0.0 Bye\r\n").await;
                                return;
                            }
                            _ => b"502 5.5.2 Command not implemented\r\n",
                        }
                    };
                    if write_half.write_all(reply).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    (port, transcript)
}

#[tokio::test]
async fn injected_send_email_reaches_a_real_smtp_peer() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let (port, transcript) = start_mock_smtp().await;

    let client_id = ClientForm {
        protocol: "smtp".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create smtp client");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_email",
                "from": "sender@netget.test",
                "to": ["recipient@netget.test"],
                "subject": "dashboard-marker",
                "body": "injected from the dashboard",
                "use_tls": false
            }),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client send_email");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("dashboard-marker") && detail.contains(&port.to_string()),
                "detail should name the message and the endpoint it went to, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // The message really crossed the socket — including via the port from `remote_addr`,
    // which this client used to strip, sending every message to lettre's default instead.
    let seen = transcript.lock().await.clone();
    assert!(
        seen.contains("RCPT TO:<recipient@netget.test>"),
        "peer should have seen the recipient; transcript was:\n{seen}"
    );
    assert!(
        seen.contains("dashboard-marker"),
        "peer should have seen the subject; transcript was:\n{seen}"
    );

    // Recorded on the client like LLM-produced traffic.
    for _ in 0..1_000 {
        let logs = state
            .list_access_logs_for(Some(AccessLogOwner::Client(client_id.as_u32())), None)
            .await;
        if logs.iter().any(|e| {
            serde_json::to_string(e)
                .unwrap_or_default()
                .contains("injected_action")
        }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    // An action the protocol refuses never reaches the peer.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_email", "from": "sender@netget.test"}),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client incomplete send_email");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "client should be Disconnected with no command handle; status={:?} has_handle={}",
        state.get_client(client_id).await.map(|c| c.status),
        state.has_client_handle(client_id).await
    );
}

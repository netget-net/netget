//! Messages a WebSocket peer sends while the model is answering are answered together.
//!
//! The first text message is answered slowly; two more arrive during that call and wait in
//! the connection's queue. With batching off each must be its own model call — the control,
//! without which the batched result below could be a mock that never saw the later messages
//! at all. With batching on the queue must be drained into one call whose trigger is the
//! newest message and whose prompt lists the earlier one as arrived and not yet answered.
//! Control and claim are one test, so a dead control takes the claim down with it.
//!
//! The handshake and the connection-opened event are answered by static rules, so every
//! model call counted here is a data message. The client is a few lines of RFC 6455 framing
//! written here, not the crate the server frames with.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

/// A masked client text frame (RFC 6455 §5.2, §5.3); payloads here are under 126 bytes.
fn text_frame(text: &str) -> Vec<u8> {
    let payload = text.as_bytes();
    assert!(payload.len() < 126);
    let mask = [0x11u8, 0x22, 0x33, 0x44];
    let mut out = vec![0x81, 0x80 | payload.len() as u8];
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

/// Read until the server's frames, taken as raw bytes, contain `needle`. The payloads the
/// mock answers with are short unmasked text, so they appear verbatim in the stream.
async fn read_until(stream: &mut TcpStream, seen: &mut Vec<u8>, needle: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut buf = [0u8; 2048];
    while !String::from_utf8_lossy(seen).contains(needle) {
        let n = tokio::time::timeout_at(deadline, stream.read(&mut buf))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "no {needle:?} arrived; read so far: {:?}",
                    String::from_utf8_lossy(seen)
                )
            })
            .expect("read");
        assert!(
            n > 0,
            "closed before {needle:?}; read so far: {:?}",
            String::from_utf8_lossy(seen)
        );
        seen.extend_from_slice(&buf[..n]);
    }
}

/// Send `first`, then — while the model answers it — `second` and `third` in one write, and
/// return `(prompt, event data)` for every `websocket_text_message` call.
async fn prompts_for_three_messages(batching: bool) -> Vec<(String, serde_json::Value)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("websocket_text_message")
            .and_event_data_contains("text", "first")
            .respond_with_actions(serde_json::json!([
                { "type": "send_websocket_text", "text": "got first" }
            ]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_event("websocket_text_message")
            .respond_with_actions_from_event(|event| {
                let text = event["text"].as_str().unwrap_or_default().to_string();
                serde_json::json!([{ "type": "send_websocket_text", "text": format!("got {text}") }])
            })
            .expect_at_least(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "websocket".to_string(),
        port: Some(0),
        instruction: Some("Acknowledge every message.".to_string()),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "websocket_handshake",
                "handler": {"type": "static", "actions": [{"type": "accept_websocket"}]}
            }),
            serde_json::json!({
                "event_pattern": "websocket_connection_opened",
                "handler": {"type": "static", "actions": []}
            }),
        ]),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create websocket server");
    let port = wait_for_port(&state, id).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    stream
        .write_all(
            format!(
                "GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                 Sec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("write handshake");
    let mut seen = Vec::new();
    read_until(&mut stream, &mut seen, "\r\n\r\n").await;
    assert!(
        String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 101"),
        "handshake refused: {:?}",
        String::from_utf8_lossy(&seen)
    );

    stream.write_all(&text_frame("first")).await.expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let text_calls = |calls: Vec<crate::helpers::mock_config::MockCallRecord>| {
        calls
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some("websocket_text_message"))
            .collect::<Vec<_>>()
    };
    while text_calls(mock.recorded_calls().await).is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the first message never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut both = text_frame("second");
    both.extend(text_frame("third"));
    stream.write_all(&both).await.expect("write");
    read_until(&mut stream, &mut seen, "got third").await;

    let prompts = text_calls(mock.recorded_calls().await)
        .into_iter()
        .map(|c| (c.context.prompt.clone(), c.context.event_data.clone()))
        .collect();
    let _ = state.remove_server(id).await;
    prompts
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_messages_sent_during_a_call_are_answered_together() {
    // === Control: batching off. Every queued message is its own call. ===
    let separate = prompts_for_three_messages(false).await;
    assert_eq!(
        separate.len(),
        3,
        "CONTROL FAILED: with batching off each message must be its own model call, or the \
         two-call result below proves nothing. Got {} calls: {:#?}",
        separate.len(),
        separate.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );

    // === The claim: the two messages queued during the slow call come back as one. ===
    let batched = prompts_for_three_messages(true).await;
    assert_eq!(
        batched.len(),
        2,
        "the two messages sent during the first call must be answered in one follow-up call; \
         got {} calls: {:#?}",
        batched.len(),
        batched.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    let (prompt, current) = &batched[1];
    assert_eq!(
        current["text"], "third",
        "the newest message is the batch's trigger"
    );
    let trigger_at = prompt
        .rfind("Event ID: websocket_text_message")
        .expect("trigger");
    let before = &prompt[..trigger_at];
    assert!(
        before.contains("(1) websocket_text_message {") && before.contains(r#""text":"second""#),
        "the earlier message must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

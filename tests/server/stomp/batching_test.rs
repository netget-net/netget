//! STOMP frames sent while the model is answering are answered together, and every frame still
//! gets exactly one `RECEIPT`.
//!
//! The peer is `async-stomp`, the client the rest of this suite uses. It sends `SEND first`
//! (answered slowly), then `SEND second` and `SEND third` during that call, each carrying a
//! `receipt`. The mock answers a send with a `RECEIPT` for the trigger's own receipt id, so in
//! the batch the model writes `r-3` and Rust owes `r-2` — the case that would duplicate or lose
//! a receipt if the per-frame bookkeeping were wrong.
//!
//! Control and claim are one test: with batching off the three sends must be three model
//! calls, or the two-call result proves nothing.
//!
//! LLM budget: 4 calls with batching off, 3 with it on.

use std::collections::HashMap;
use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use async_stomp::client::{ClientTransport, Connector};
use async_stomp::{FromServer, Message, ToServer};
use futures::{SinkExt, StreamExt};
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
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

async fn send(conn: &mut ClientTransport, body: &str, receipt: &str) {
    conn.send(Message::from(ToServer::Send {
        destination: "/queue/batch".to_string(),
        transaction: None,
        headers: Some(vec![("receipt".to_string(), receipt.to_string())]),
        body: Some(body.as_bytes().to_vec()),
    }))
    .await
    .expect("async-stomp could not send SEND");
}

/// Run the exchange; return the `stomp_send` prompts the model saw (prompt, trigger data) and
/// every receipt id the client received before the DISCONNECT receipt, in arrival order.
async fn three_sends(batching: bool) -> (Vec<(String, serde_json::Value)>, Vec<String>) {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("stomp_connect")
            .respond_with_actions(serde_json::json!([
                {"type": "send_stomp_connected", "version": "1.2", "session": "s-1"}
            ]))
            .expect_calls(1)
            .and()
            // The first send is answered slowly, so the next two arrive during the call.
            .on_event("stomp_send")
            .and_event_data_contains("body", "first")
            .respond_with_actions(serde_json::json!([]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_event("stomp_send")
            .respond_with_actions_from_event(|e| {
                let receipt = e["headers"]["receipt"].as_str().unwrap_or_default();
                serde_json::json!([{"type": "send_stomp_receipt", "receipt_id": receipt}])
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
        protocol: "stomp".to_string(),
        port: Some(0),
        instruction: Some("Accept every login; acknowledge what is published.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create stomp server");
    let port = wait_for_port(&state, id).await;

    let mut conn: ClientTransport = Connector::builder()
        .server(format!("127.0.0.1:{port}"))
        .virtualhost("localhost")
        .connect()
        .await
        .expect("async-stomp handshake");

    send(&mut conn, "first", "r-1").await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !mock
        .recorded_calls()
        .await
        .iter()
        .any(|c| c.context.event_type.as_deref() == Some("stomp_send"))
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the first SEND never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    send(&mut conn, "second", "r-2").await;
    send(&mut conn, "third", "r-3").await;
    conn.send(Message::from(ToServer::Disconnect {
        receipt: Some("r-bye".to_string()),
    }))
    .await
    .expect("async-stomp could not send DISCONNECT");

    let mut receipts = Vec::new();
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(30), conn.next())
            .await
            .expect("timed out waiting for receipts")
            .expect("the server closed before the DISCONNECT receipt")
            .expect("async-stomp could not decode a frame");
        match frame.content {
            FromServer::Receipt { receipt_id } if receipt_id == "r-bye" => break,
            FromServer::Receipt { receipt_id } => receipts.push(receipt_id),
            other => panic!("expected only RECEIPT frames, got {other:?}"),
        }
    }

    let prompts = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("stomp_send"))
        .map(|c| (c.context.prompt.clone(), c.context.event_data.clone()))
        .collect();
    let _ = state.remove_server(id).await;
    (prompts, receipts)
}

fn assert_each_receipt_once(receipts: &[String], mode: &str) {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for r in receipts {
        *counts.entry(r.as_str()).or_default() += 1;
    }
    for id in ["r-1", "r-2", "r-3"] {
        assert_eq!(
            counts.get(id).copied().unwrap_or(0),
            1,
            "{mode}: receipt {id} must arrive exactly once; got {receipts:?}"
        );
    }
    assert_eq!(
        receipts.len(),
        3,
        "{mode}: unexpected receipts {receipts:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sends_during_a_call_are_answered_together_with_one_receipt_each() {
    // === Control: batching off. Every SEND is its own call. ===
    let (separate, receipts) = three_sends(false).await;
    assert_eq!(
        separate.len(),
        3,
        "CONTROL FAILED: with batching off each SEND must be its own model call, or the \
         two-call result below proves nothing. Got {:#?}",
        separate.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    assert_each_receipt_once(&receipts, "batching off");

    // === The claim: the two SENDs that arrived during the slow call are one call. ===
    let (batched, receipts) = three_sends(true).await;
    assert_eq!(
        batched.len(),
        2,
        "the two SENDs sent during the first call must be answered in one follow-up call; \
         got {:#?}",
        batched.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    let (prompt, current) = &batched[1];
    assert_eq!(current["body"], "third", "the newest frame is the trigger");
    let trigger_at = prompt
        .rfind("Event ID: stomp_send")
        .expect("trigger in prompt");
    assert!(
        prompt[..trigger_at].contains(r#""body":"second""#),
        "the earlier SEND must be listed above the trigger:\n{prompt}"
    );
    // The model wrote r-3 itself; Rust still owed r-2 and must not repeat r-3.
    assert_each_receipt_once(&receipts, "batching on");
}

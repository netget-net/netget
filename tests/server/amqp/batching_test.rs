//! Publishes that arrive while the model is answering are answered together, and the
//! deliveries the model makes for them reach the consumer in order.
//!
//! The peer is `lapin`, the client the rest of this suite uses. It declares a queue, consumes
//! it, publishes `first` (answered slowly), and publishes `second` and `third` during that
//! call. Basic.Publish owes nothing on the wire, so what a batch can get wrong is what the
//! model is shown and what it delivers: the batched call has to list `second` above the
//! trigger `third`, and the two deliveries it answers with have to reach the consumer after
//! `first`, in order.
//!
//! Control and claim are one test: with batching off the three publishes must be three model
//! calls, or the two-call result proves nothing.
//!
//! LLM budget: 6 calls with batching off, 5 with it on.

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use futures::StreamExt;
use lapin::options::{BasicConsumeOptions, BasicPublishOptions, QueueDeclareOptions};
use lapin::types::FieldTable;
use lapin::{BasicProperties, Connection, ConnectionProperties};
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use serde_json::json;
use tokio::sync::mpsc;

const QUEUE: &str = "netget-batch-queue";
const CONSUMER_TAG: &str = "netget-batch-consumer";

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

fn deliver(body: &str) -> serde_json::Value {
    json!({
        "type": "amqp_basic_deliver",
        "consumer_tag": CONSUMER_TAG,
        "routing_key": QUEUE,
        "body": body,
        "content_type": "text/plain"
    })
}

/// Run the exchange; return the (prompt, trigger data) of every publish call and the bodies
/// the consumer received, in order.
async fn three_publishes(batching: bool) -> (Vec<(String, serde_json::Value)>, Vec<String>) {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("amqp_connection_open")
            .respond_with_actions(json!([{"type": "amqp_connection_open_ok"}]))
            .expect_calls(1)
            .and()
            .on_event("amqp_queue_declare")
            .respond_with_actions_from_event(|e| {
                json!([{"type": "amqp_queue_declare_ok", "queue": e["queue"],
                        "message_count": 0, "consumer_count": 0}])
            })
            .expect_calls(1)
            .and()
            .on_event("amqp_basic_consume")
            .respond_with_actions_from_event(
                |e| json!([{"type": "amqp_basic_consume_ok", "consumer_tag": e["consumer_tag"]}]),
            )
            .expect_calls(1)
            .and()
            // The first publish is answered slowly, so the next two arrive during the call.
            .on_event("amqp_basic_publish")
            .and_event_data_contains("body", "first")
            .respond_with_actions(json!([deliver("first")]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            // A batched call answers every publish it lists, in arrival order.
            .on_event("amqp_basic_publish")
            .and_prompt_containing("answers all 2 together")
            .respond_with_actions(json!([deliver("second"), deliver("third")]))
            .expect_at_least(0)
            .and()
            .on_event("amqp_basic_publish")
            .respond_with_actions_from_event(|e| json!([deliver(e["body"].as_str().unwrap_or(""))]))
            .expect_at_least(0)
            .and()
            .on_any()
            .respond_with_actions(json!([]))
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
        protocol: "amqp".to_string(),
        port: Some(0),
        instruction: Some("Accept everyone and deliver every message to the consumer.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create amqp server");
    let port = wait_for_port(&state, id).await;

    let conn = tokio::time::timeout(
        Duration::from_secs(20),
        Connection::connect(
            &format!("amqp://127.0.0.1:{port}/%2f"),
            ConnectionProperties::default(),
        ),
    )
    .await
    .expect("handshake within 20s")
    .expect("lapin handshake");
    let channel = conn.create_channel().await.expect("channel.open");
    channel
        .queue_declare(
            QUEUE.into(),
            QueueDeclareOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("queue.declare");
    let mut consumer = channel
        .basic_consume(
            QUEUE.into(),
            CONSUMER_TAG.into(),
            BasicConsumeOptions {
                no_ack: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .expect("basic.consume");

    let publish = |body: &'static str| {
        let channel = channel.clone();
        async move {
            channel
                .basic_publish(
                    "".into(),
                    QUEUE.into(),
                    BasicPublishOptions::default(),
                    body.as_bytes(),
                    BasicProperties::default(),
                )
                .await
                .expect("basic.publish");
        }
    };

    publish("first").await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !mock
        .recorded_calls()
        .await
        .iter()
        .any(|c| c.context.event_type.as_deref() == Some("amqp_basic_publish"))
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the first publish never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    publish("second").await;
    publish("third").await;

    let mut bodies = Vec::new();
    while bodies.len() < 3 {
        let delivery = tokio::time::timeout(Duration::from_secs(30), consumer.next())
            .await
            .unwrap_or_else(|_| panic!("only {bodies:?} were delivered within 30s"))
            .expect("consumer stream ended")
            .expect("malformed delivery");
        bodies.push(String::from_utf8_lossy(&delivery.data).into_owned());
    }

    let prompts = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("amqp_basic_publish"))
        .map(|c| (c.context.prompt.clone(), c.context.event_data.clone()))
        .collect();
    let _ = conn.close(200, "test finished".into()).await;
    let _ = state.remove_server(id).await;
    (prompts, bodies)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publishes_during_a_call_are_answered_together_and_delivered_in_order() {
    // === Control: batching off. Every publish is its own call. ===
    let (separate, bodies) = three_publishes(false).await;
    assert_eq!(
        separate.len(),
        3,
        "CONTROL FAILED: with batching off each publish must be its own model call, or the \
         two-call result below proves nothing. Got {:#?}",
        separate.iter().map(|(_, d)| &d["body"]).collect::<Vec<_>>()
    );
    assert_eq!(bodies, ["first", "second", "third"]);

    // === The claim: the two publishes sent during the slow call are one call. ===
    let (batched, bodies) = three_publishes(true).await;
    assert_eq!(
        batched.len(),
        2,
        "the two publishes sent during the first call must be answered in one follow-up \
         call; got {:#?}",
        batched.iter().map(|(_, d)| &d["body"]).collect::<Vec<_>>()
    );
    let (prompt, current) = &batched[1];
    assert_eq!(
        current["body"], "third",
        "the newest publish is the trigger"
    );
    let trigger_at = prompt
        .rfind("Event ID: amqp_basic_publish")
        .expect("trigger in prompt");
    assert!(
        prompt[..trigger_at].contains(r#""body":"second""#),
        "the earlier publish must be listed above the trigger:\n{prompt}"
    );
    assert_eq!(
        bodies,
        ["first", "second", "third"],
        "the batch's deliveries must reach the consumer after the first, in order"
    );
}

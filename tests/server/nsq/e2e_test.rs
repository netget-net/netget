//! NSQ end to end with a mocked model, over a raw socket.
//!
//! `real_client_test.rs` is the evidence that go-nsq accepts what this server writes. This file
//! pins the exact frames and covers what `to_nsq` and `nsq_tail` never do: MPUB, a consumer
//! whose RDY count is smaller than what the model delivers (the rest wait and follow each FIN),
//! REQ and a redelivery with its attempts raised, TOUCH and FIN of unknown ids (non-fatal, as in
//! nsqd), NOP, CLS, and IDENTIFY with and without feature negotiation. The commands NetGet
//! answers itself cost no model call (`expect_calls`).
//!
//! LLM budget: 9 calls (open_server, PUB, MPUB, SUB, RDY, three FINs, one REQ).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nsq --test server -- nsq::e2e --test-threads=100

use super::common::Peer;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use netget::server::nsq::wire::{self, Command};

#[tokio::test]
async fn an_nsq_session_against_a_mocked_model() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via nsq. A broker.")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("via nsq")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "nsq",
                    "instruction": "A broker"
                }]))
                .expect_calls(1)
                .and()
                // One rule for both publishes, answering OK only for exactly what was sent, so
                // a wrong summary shows up as a refusal on the wire.
                .on_event("nsq_publish")
                .respond_with_actions_from_event(|e| {
                    let bodies: Vec<&str> = e["messages"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|m| m.as_str()).collect())
                        .unwrap_or_default();
                    let expected = match e["command"].as_str() {
                        Some("PUB") => bodies == ["order 1"] && e["total_bytes"] == 7,
                        Some("MPUB") => {
                            bodies == ["a", "bb", "ccc"]
                                && e["message_count"] == 3
                                && e["total_bytes"] == 6
                        }
                        _ => false,
                    };
                    if expected && e["topic"] == "orders" {
                        serde_json::json!([{"type": "send_nsq_ok"}])
                    } else {
                        serde_json::json!([{"type": "send_nsq_error", "code": "E_PUB_FAILED",
                                            "message": "unexpected publish"}])
                    }
                })
                .expect_calls(2)
                .and()
                .on_event("nsq_subscribe")
                .and_event_data_contains("channel", "workers")
                .respond_with_actions(serde_json::json!([{"type": "send_nsq_ok"}]))
                .expect_calls(1)
                .and()
                .on_event("nsq_ready")
                .and_event_data_contains("topic", "jobs")
                .respond_with_actions_from_event(|e| {
                    // The model is told how much room there is (a wrong figure delivers
                    // nothing, and the test sees no messages); this answer then ignores it on
                    // purpose, so NetGet's own limit is what the test sees.
                    if e["can_deliver"] != 2 {
                        return serde_json::json!([]);
                    }
                    serde_json::json!([{"type": "deliver_nsq_messages", "messages": [
                        {"body": "job a"}, {"body": "job b"}, {"body": "job c"}
                    ]}])
                })
                .expect_calls(1)
                .and()
                .on_event("nsq_requeue")
                .respond_with_actions_from_event(|e| {
                    let body = e["body"].as_str().unwrap_or("").to_string();
                    let attempts = e["attempts"].as_u64().unwrap_or(1) + 1;
                    serde_json::json!([{"type": "deliver_nsq_messages",
                                        "messages": [{"body": body, "attempts": attempts}]}])
                })
                .expect_calls(1)
                .and()
                .on_event("nsq_finish")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(3)
                .and()
        });

    let server = start_netget_server(config).await?;

    // A publisher: IDENTIFY without negotiation answers a plain OK.
    let mut publisher = Peer::connect(server.port).await;
    publisher
        .identify(serde_json::json!({"client_id": "pub"}))
        .await;
    publisher.expect_response(b"OK", 10).await;
    publisher
        .command(&Command::Pub {
            topic: "orders".into(),
            body: b"order 1".to_vec(),
        })
        .await;
    publisher.expect_response(b"OK", 30).await;
    publisher
        .command(&Command::Mpub {
            topic: "orders".into(),
            messages: vec![b"a".to_vec(), b"bb".to_vec(), b"ccc".to_vec()],
        })
        .await;
    publisher.expect_response(b"OK", 30).await;
    publisher.command(&Command::Nop).await;
    // CLS on a connection that never subscribed is refused and closes it, as in nsqd.
    publisher.command(&Command::Cls).await;
    assert_eq!(
        publisher.expect_error(10).await,
        "E_INVALID cannot CLS in current state"
    );
    assert!(publisher.rest(10).await.is_empty());

    // A consumer with feature negotiation and RDY 2.
    let mut consumer = Peer::connect(server.port).await;
    consumer
        .identify(serde_json::json!({"feature_negotiation": true, "user_agent": "e2e/1"}))
        .await;
    let reply = consumer.frame(10).await;
    assert_eq!(reply.frame_type, wire::FRAME_RESPONSE);
    let negotiated: serde_json::Value = serde_json::from_slice(&reply.data).unwrap();
    assert_eq!(negotiated["max_rdy_count"], 2500);
    assert_eq!(negotiated["tls_v1"], false);

    consumer
        .command(&Command::Sub {
            topic: "jobs".into(),
            channel: "workers".into(),
        })
        .await;
    consumer.expect_response(b"OK", 30).await;
    consumer.command(&Command::Rdy(2)).await;
    let a = consumer.expect_message(30).await;
    let b = consumer.expect_message(30).await;
    assert_eq!((a.body.as_slice(), a.attempts), (&b"job a"[..], 1));
    assert_eq!((b.body.as_slice(), b.attempts), (&b"job b"[..], 1));
    assert_ne!(a.id, b.id);
    assert!(a.id.iter().all(|c| c.is_ascii_hexdigit()), "{:?}", a.id);
    assert!(
        a.timestamp_ns > 1_600_000_000_000_000_000,
        "nanoseconds since the epoch: {}",
        a.timestamp_ns
    );

    // Two in flight with RDY 2: the third waits. Unknown ids are refused without closing.
    consumer
        .command(&Command::Touch("ffffffffffffffff".into()))
        .await;
    assert_eq!(
        consumer.expect_error(10).await,
        "E_TOUCH_FAILED TOUCH ffffffffffffffff failed ID not in flight"
    );
    consumer
        .command(&Command::Fin("ffffffffffffffff".into()))
        .await;
    assert_eq!(
        consumer.expect_error(10).await,
        "E_FIN_FAILED FIN ffffffffffffffff failed ID not in flight"
    );
    let id = |m: &wire::Message| String::from_utf8(m.id.to_vec()).unwrap();
    consumer.command(&Command::Touch(id(&a))).await;

    // FIN a: job c follows at once, from NetGet's queue.
    consumer.command(&Command::Fin(id(&a))).await;
    let c = consumer.expect_message(30).await;
    assert_eq!(c.body, b"job c");

    // REQ b: the model redelivers it with attempts 2, under a new id.
    consumer
        .command(&Command::Req {
            id: id(&b),
            timeout_ms: 0,
        })
        .await;
    let b2 = consumer.expect_message(30).await;
    assert_eq!((b2.body.as_slice(), b2.attempts), (&b"job b"[..], 2));
    assert_ne!(b2.id, b.id);

    consumer.command(&Command::Fin(id(&c))).await;
    consumer.command(&Command::Fin(id(&b2))).await;
    consumer.command(&Command::Cls).await;
    consumer.expect_response(b"CLOSE_WAIT", 30).await;
    // RDY after CLS is ignored: no event, no messages.
    consumer.command(&Command::Rdy(5)).await;
    consumer.command(&Command::Nop).await;
    consumer.quiet_for(2).await;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

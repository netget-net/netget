//! E2E tests for the AMQP 0-9-1 broker.
//!
//! Driven by `lapin`, a real AMQP client. `lapin` is the wrong library for the *server*
//! side — it is a client and cannot implement a broker — but it is exactly the right one
//! for the test side: if it completes a handshake, declares a queue, publishes and
//! receives the delivery, the broker's framing is right at every layer.
//!
//! The load-bearing assertion is the last one in
//! `test_amqp_publish_is_delivered_to_consumer`: the body the mock told the broker to
//! deliver has to come back out of the consumer stream. Everything before it is setup
//! that would fail the test on its own if the wire format were wrong.


use crate::server::helpers::*;
use futures::StreamExt;
use lapin::options::{BasicConsumeOptions, BasicPublishOptions, QueueDeclareOptions};
use lapin::types::FieldTable;
use lapin::{BasicProperties, Connection, ConnectionProperties};
use serde_json::json;
use std::time::Duration;

const QUEUE: &str = "netget-e2e-queue";
const CONSUMER_TAG: &str = "netget-e2e-consumer";
const BODY: &str = "hello from lapin";

fn amqp_uri(port: u16) -> String {
    format!("amqp://127.0.0.1:{}/%2f", port)
}

/// Connect with a bounded wait so a broker that never answers fails the test instead of
/// hanging the suite.
async fn connect(port: u16) -> Result<Connection, String> {
    match tokio::time::timeout(
        Duration::from_secs(20),
        Connection::connect(&amqp_uri(port), ConnectionProperties::default()),
    )
    .await
    {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("the AMQP handshake did not finish within 20s".to_string()),
    }
}

/// A real client completes the handshake, declares a queue, consumes, publishes, and
/// receives back exactly the body the mocked model asked the broker to deliver.
#[tokio::test]
async fn test_amqp_publish_is_delivered_to_consumer() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Start an AMQP broker on port 0 that accepts every client and forwards published \
         messages to the attached consumer",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_instruction_containing("AMQP broker")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "amqp",
                "instruction": "Accept every connection, confirm queue declarations, accept \
                                consumers, and forward every published message to the consumer"
            }]))
            .expect_calls(1)
            .and()
            // One decision per connection: let the client in.
            .on_event("amqp_connection_open")
            .respond_with_actions(json!([{"type": "amqp_connection_open_ok"}]))
            .expect_calls(1)
            .and()
            // The queue name has to be echoed back or lapin rejects the declare-ok.
            .on_event("amqp_queue_declare")
            .respond_with_actions_from_event(|event| {
                json!([{
                    "type": "amqp_queue_declare_ok",
                    "queue": event["queue"],
                    "message_count": 0,
                    "consumer_count": 0
                }])
            })
            .expect_calls(1)
            .and()
            // The consumer tag has to be echoed back or lapin never matches deliveries.
            .on_event("amqp_basic_consume")
            .respond_with_actions_from_event(|event| {
                json!([{
                    "type": "amqp_basic_consume_ok",
                    "consumer_tag": event["consumer_tag"]
                }])
            })
            .expect_calls(1)
            .and()
            // Nothing is routed by the broker: this action is the whole delivery path.
            .on_event("amqp_basic_publish")
            .respond_with_actions_from_event(|event| {
                json!([{
                    "type": "amqp_basic_deliver",
                    "consumer_tag": event["active_consumers"][0]["consumer_tag"],
                    "routing_key": event["routing_key"],
                    "body": event["body"],
                    "content_type": "text/plain"
                }])
            })
            .expect_calls(1)
            .and()
    });

    let test_state = start_netget_server(config).await?;

    let conn = connect(test_state.port)
        .await
        .map_err(|e| format!("AMQP handshake failed: {}", e))?;
    println!("✓ handshake complete (Start/Tune/Open all accepted by lapin)");

    let channel = conn
        .create_channel()
        .await
        .map_err(|e| format!("channel.open failed: {}", e))?;

    let queue = channel
        .queue_declare(
            QUEUE.into(),
            QueueDeclareOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(|e| format!("queue.declare failed: {}", e))?;
    assert_eq!(
        queue.name().as_str(),
        QUEUE,
        "the broker confirmed a different queue name than the client declared"
    );
    assert_eq!(queue.message_count(), 0);

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
        .map_err(|e| format!("basic.consume failed: {}", e))?;
    assert_eq!(
        consumer.tag().as_str(),
        CONSUMER_TAG,
        "the broker confirmed a different consumer tag than the client asked for"
    );

    let _confirm = channel
        .basic_publish(
            "".into(),
            QUEUE.into(),
            BasicPublishOptions::default(),
            BODY.as_bytes(),
            BasicProperties::default(),
        )
        .await
        .map_err(|e| format!("basic.publish failed: {}", e))?;

    let delivery = match tokio::time::timeout(Duration::from_secs(20), consumer.next()).await {
        Ok(Some(Ok(delivery))) => delivery,
        Ok(Some(Err(e))) => return Err(format!("the delivery was malformed: {}", e).into()),
        Ok(None) => return Err("the consumer stream ended before a delivery arrived".into()),
        Err(_) => return Err("no AMQP delivery arrived within 20s".into()),
    };

    // The assertion that separates a working broker from a listening socket.
    assert_eq!(
        String::from_utf8_lossy(&delivery.data),
        BODY,
        "the consumer received a different body than the publisher sent"
    );
    assert_eq!(delivery.routing_key.as_str(), QUEUE);
    assert_eq!(
        delivery
            .properties
            .content_type()
            .as_ref()
            .map(|s| s.to_string()),
        Some("text/plain".to_string()),
        "content-type from the deliver action did not reach the consumer"
    );
    println!("✓ consumer received the published body through Basic.Deliver");

    // Exercises Connection.Close -> Close-Ok.
    let _ = conn.close(200, "test finished".into()).await;

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

/// A handler that answers `amqp_connection_open` with nothing usable must not open the
/// broker. This is the fail-closed default: silence is a refusal, not an acceptance.
#[tokio::test]
async fn test_amqp_connection_refused_when_handler_makes_no_decision() -> E2EResult<()> {
    let config = NetGetConfig::new("Start an AMQP broker on port 0 with no connection policy")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("AMQP broker")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "amqp",
                    "instruction": "Observe connections without deciding anything"
                }]))
                .expect_calls(1)
                .and()
                // A valid action that is not a decision about this connection.
                .on_event("amqp_connection_open")
                .respond_with_actions(json!([{
                    "type": "show_message",
                    "message": "a client is connecting"
                }]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;

    match connect(test_state.port).await {
        Ok(_) => {
            return Err(
                "the broker accepted a connection although its handler made no decision".into(),
            )
        }
        Err(e) => {
            assert!(
                e.contains("no decision"),
                "expected the fail-closed refusal, got: {}",
                e
            );
            println!("✓ connection refused with: {}", e);
        }
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

/// An explicit refusal reaches the client with the model's own reply code and text, and
/// is textually distinct from the silence path above.
#[tokio::test]
async fn test_amqp_connection_refused_by_handler() -> E2EResult<()> {
    let config = NetGetConfig::new("Start an AMQP broker on port 0 that rejects unknown users")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("AMQP broker")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "amqp",
                    "instruction": "Refuse every connection"
                }]))
                .expect_calls(1)
                .and()
                .on_event("amqp_connection_open")
                .respond_with_actions(json!([{
                    "type": "amqp_connection_close",
                    "reply_code": 403,
                    "reply_text": "ACCESS_REFUSED - denied by policy"
                }]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;

    match connect(test_state.port).await {
        Ok(_) => return Err("the broker accepted a connection its handler refused".into()),
        Err(e) => {
            assert!(
                e.contains("denied by policy"),
                "the handler's own reply text did not reach the client, got: {}",
                e
            );
            println!("✓ handler refusal surfaced to the client: {}", e);
        }
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

/// A method the broker does not implement produces a channel error rather than a hang.
#[tokio::test]
async fn test_amqp_unimplemented_method_closes_the_channel() -> E2EResult<()> {
    let config = NetGetConfig::new("Start an AMQP broker on port 0 that accepts every client")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("AMQP broker")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "amqp",
                    "instruction": "Accept every connection"
                }]))
                .expect_calls(1)
                .and()
                .on_event("amqp_connection_open")
                .respond_with_actions(json!([{"type": "amqp_connection_open_ok"}]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;

    let conn = connect(test_state.port)
        .await
        .map_err(|e| format!("AMQP handshake failed: {}", e))?;
    let channel = conn
        .create_channel()
        .await
        .map_err(|e| format!("channel.open failed: {}", e))?;

    // Basic.Get is deliberately outside the implemented subset.
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        channel.basic_get(QUEUE.into(), lapin::options::BasicGetOptions::default()),
    )
    .await;

    match result {
        Ok(Ok(_)) => return Err("basic.get was answered although it is not implemented".into()),
        Ok(Err(e)) => {
            let message = e.to_string();
            assert!(
                message.contains("NOT_IMPLEMENTED") || message.contains("basic.get"),
                "expected a NOT_IMPLEMENTED channel error, got: {}",
                message
            );
            println!("✓ unimplemented method reported as: {}", message);
        }
        Err(_) => {
            return Err(
                "basic.get neither succeeded nor failed within 20s (the broker hung)".into(),
            )
        }
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

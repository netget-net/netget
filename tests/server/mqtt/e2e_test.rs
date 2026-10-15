//! E2E tests for the MQTT broker.
//!
//! `test_mqtt_subscribe_and_receive_a_published_message` is the evidence behind the
//! protocol's Beta rating: a real rumqttc client completes CONNECT -> SUBSCRIBE ->
//! SUBACK -> PUBLISH and then receives the broker's own PUBLISH back, with topic and
//! payload asserted. It is not `#[ignore]`d and it cannot skip - rumqttc is a
//! dev-dependency, so it either compiles and runs or the suite does not build.

use crate::server::helpers::*;
use std::time::Duration;

/// Test that MQTT broker starts successfully
#[tokio::test]
async fn test_mqtt_broker_starts() -> E2EResult<()> {
    let config = NetGetConfig::new("Start an MQTT broker on port 0")
        .with_log_level("off")
        .with_mock(|mock| {
            mock.on_instruction_containing("MQTT broker")
                .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "MQTT", "instruction": "MQTT broker"}]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;

    println!("✓ MQTT broker started on port {}", test_state.port);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

/// Every keyword `MqttProtocol::keywords()` advertises resolves to MQTT.
///
/// This asks the registry directly. The version this replaced spawned NetGet with no
/// `.with_mock()`, so the LLM call always failed, no server was ever started, and the
/// harness returned `Expected exactly 1 server, got 0` - which contains neither
/// "unknown" nor "Unknown", so the assertion passed for *any* prompt, including one
/// naming no protocol at all. Its `else` branch additionally did
/// `panic!("Expected error for placeholder MQTT broker")`, i.e. it would have failed
/// had the broker worked. The broker has not been a placeholder for a long time.
#[test]
fn test_mqtt_keyword_detection() {
    use ::netget::protocol::server_registry::registry;

    let registry = registry();
    let mqtt = registry
        .get("MQTT")
        .expect("MQTT is compiled in under #![cfg(feature = \"mqtt\")]");

    // Assert against what the protocol itself advertises, so a keyword added to
    // actions.rs without a resolver entry fails here rather than silently never matching.
    for keyword in mqtt.keywords() {
        let prompt = format!("Start a server using {keyword} on port 1883");
        assert_eq!(
            registry.parse_from_str(&prompt).as_deref(),
            Some("MQTT"),
            "keyword {keyword:?} advertised by MqttProtocol::keywords() does not resolve to MQTT"
        );
    }

    // The names the LLM and the startup path use to refer to it.
    for name in ["mqtt", "MQTT", "ETH>IP>TCP>MQTT"] {
        assert_eq!(
            registry.parse_from_str(name).as_deref(),
            Some("MQTT"),
            "{name:?} should resolve to MQTT"
        );
    }
}

// ============================================================================
// MQTT BROKER TESTS
// ============================================================================

#[tokio::test]
async fn test_mqtt_basic_connect() -> E2EResult<()> {
    use rumqttc::{AsyncClient, Event, MqttOptions, Packet};

    let config =
        NetGetConfig::new("Start an MQTT broker on port 0. Accept all client connections.")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_instruction_containing("MQTT broker")
                    .and_instruction_containing("Accept all client connections")
                    .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "MQTT", "instruction": "MQTT broker accepting connections"}]))
                    .expect_calls(1)
                    .and()
                    // The handler must actually run and accept. This rule used to be absent,
                    // so the test passed on the CONNECT fail-open default (CONNACK return code
                    // 0 whenever the handler produced nothing, including when it could not run
                    // at all) - i.e. it asserted that a broker with a dead backend lets clients
                    // in. A refusal is now the correct answer in that case, so the acceptance
                    // this test is about has to be asked for.
                    .on_event("mqtt_connect")
                    .respond_with_actions(serde_json::json!([
                        {"type": "mqtt_connack", "return_code": 0, "session_present": false}
                    ]))
                    .expect_calls(1)
                    .and()
            });

    let test_state = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create MQTT client
    let mut mqttoptions = MqttOptions::new("test_client", "127.0.0.1", test_state.port);
    mqttoptions.set_keep_alive(Duration::from_secs(5));

    let (_client, mut eventloop) = AsyncClient::new(mqttoptions, 10);

    // Try to connect and receive CONNACK
    let mut connected = false;
    for _ in 0..10 {
        match tokio::time::timeout(Duration::from_secs(2), eventloop.poll()).await {
            Ok(Ok(Event::Incoming(Packet::ConnAck(_)))) => {
                println!("✓ Received CONNACK from MQTT broker");
                connected = true;
                break;
            }
            Ok(Ok(event)) => {
                println!("MQTT event: {:?}", event);
            }
            Ok(Err(e)) => {
                eprintln!("MQTT error: {}", e);
                break;
            }
            Err(_) => {
                eprintln!("Timeout waiting for CONNACK");
                break;
            }
        }
    }

    assert!(connected, "Should receive CONNACK from broker");

    println!("✓ MQTT client connected successfully");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

/// A real rumqttc client subscribes, publishes, and receives the broker's delivery.
///
/// This replaces four tests that sat commented out behind
/// `#[ignore = "MQTT broker not yet implemented"]` and
/// `#[ignore = "Pub/sub not yet implemented"]`. Both markers were stale twice over: the block
/// was inside `/* … */`, so nothing compiled it and `--include-ignored` could never have run
/// it, and the broker *is* implemented — `mod.rs` handles CONNECT, PUBLISH, SUBSCRIBE and
/// UNSUBSCRIBE and `actions.rs` declares `mqtt_connack`, `mqtt_suback`, `mqtt_puback`,
/// `mqtt_pubrec`, `mqtt_unsuback` and `mqtt_publish` as sync verbs.
///
/// Every rule below is checked against this protocol's own `actions.rs`, not a neighbouring
/// suite. Two details matter and are the usual way a mock like this silently never matches:
///
///  * **`mqtt_suback` must echo `packet_id` from the event.** rumqttc blocks until a SUBACK
///    carrying the packet id it chose arrives, so a hardcoded id stalls the subscribe forever.
///    Hence `respond_with_actions_from_event`, the same reason the UDP-style protocols need it.
///  * **The event `mqtt_publish` and the action `mqtt_publish` share a name and are opposite
///    directions.** The event is the client's PUBLISH arriving at the broker; the action is the
///    broker sending one out. Answering the event with the action is what forwards the message.
#[tokio::test]
async fn test_mqtt_subscribe_and_receive_a_published_message() -> E2EResult<()> {
    use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};

    const TOPIC: &str = "netget/e2e";
    const BODY: &str = "delivered-by-netget";

    let config = NetGetConfig::new(
        "Start an MQTT broker on port 0. Accept all client connections, grant every \
         subscription, and forward published messages back to subscribers.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_instruction_containing("MQTT broker")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "MQTT",
                "instruction": "MQTT broker: accept, grant subscriptions, forward publishes"
            }]))
            .expect_calls(1)
            .and()
            // Accepting has to be asked for: a CONNECT the backend cannot answer is refused,
            // so an absent rule here would test a broker that turns clients away.
            .on_event("mqtt_connect")
            .respond_with_actions(serde_json::json!([
                {"type": "mqtt_connack", "return_code": 0, "session_present": false}
            ]))
            .expect_at_least(1)
            .and()
            // packet_id MUST come from the event; rumqttc waits for its own id.
            .on_event("mqtt_subscribe")
            .respond_with_actions_from_event(|event| {
                serde_json::json!([{
                    "type": "mqtt_suback",
                    "packet_id": event["packet_id"].as_u64().unwrap_or(0),
                    "granted_qos": [0]
                }])
            })
            .expect_at_least(1)
            .and()
            // The client's PUBLISH arriving; answered with a broker-originated PUBLISH.
            .on_event("mqtt_publish")
            .respond_with_actions(serde_json::json!([{
                "type": "mqtt_publish",
                "topic": TOPIC,
                "payload": BODY,
                "qos": 0,
                "retain": false
            }]))
            .expect_at_least(1)
            .and()
    });

    let test_state = start_netget_server(config).await?;

    let mut opts = MqttOptions::new("netget_pubsub_client", "127.0.0.1", test_state.port);
    opts.set_keep_alive(Duration::from_secs(5));
    let (client, mut eventloop) = AsyncClient::new(opts, 10);

    // One client both subscribes and publishes, so the broker's delivery comes back on the
    // connection this loop is already driving — no second eventloop to keep alive.
    let mut connected = false;
    let mut subscribed = false;
    let mut published = false;
    let mut delivered: Option<(String, Vec<u8>)> = None;

    // One overall budget rather than 40 individual 5s waits: the failure path (nothing is
    // ever delivered) otherwise takes 90 seconds to report, which is long enough that a real
    // regression reads as a hang.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        let budget = deadline - tokio::time::Instant::now();
        match tokio::time::timeout(budget, eventloop.poll()).await {
            Ok(Ok(Event::Incoming(Packet::ConnAck(_)))) => {
                connected = true;
                client.subscribe(TOPIC, QoS::AtMostOnce).await?;
            }
            Ok(Ok(Event::Incoming(Packet::SubAck(_)))) => {
                subscribed = true;
                client
                    .publish(TOPIC, QoS::AtMostOnce, false, b"from-the-client".to_vec())
                    .await?;
            }
            Ok(Ok(Event::Outgoing(rumqttc::Outgoing::Publish(_)))) => {
                published = true;
            }
            Ok(Ok(Event::Incoming(Packet::Publish(p)))) => {
                delivered = Some((p.topic.clone(), p.payload.to_vec()));
                break;
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("rumqttc error: {e}").into()),
            Err(_) => break,
        }
    }

    assert!(connected, "rumqttc never received a CONNACK");
    assert!(
        subscribed,
        "rumqttc never received a SUBACK — check that mqtt_suback echoed packet_id"
    );
    assert!(published, "rumqttc never sent its PUBLISH");

    let (topic, payload) = delivered.ok_or(
        "the broker never delivered a PUBLISH to the subscriber; the mqtt_publish event was \
         answered with an mqtt_publish action, so the forward is what failed",
    )?;
    assert_eq!(topic, TOPIC, "delivered on the wrong topic");
    assert_eq!(
        String::from_utf8_lossy(&payload),
        BODY,
        "the delivered payload is not the one the broker was told to send"
    );

    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;
    test_state.stop().await?;
    Ok(())
}

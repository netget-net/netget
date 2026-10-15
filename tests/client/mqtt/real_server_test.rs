//! The MQTT client against **Eclipse Mosquitto** — the evidence its maturity rating rests on.
//!
//! NetGet's MQTT client is built on `rumqttc`; the broker here is `mosquitto`, a C
//! implementation that shares no code with it, and the peers on the other side of the broker
//! are Mosquitto's own `mosquitto_sub` and `mosquitto_pub`. Nothing on the wire was written by
//! this repository except NetGet itself.
//!
//! Both tests assert **condition 4 of the client bar** — the client acts on the model's answer,
//! asserted on the wire — from the far side of a real broker: a payload the mocked model chose
//! is read back by `mosquitto_sub`, and a message published by `mosquitto_pub` reaches the model
//! as an event whose fields are then quoted back onto the broker, so the assertion can only pass
//! if NetGet parsed Mosquitto's `PUBLISH` and put the model's reply into a `PUBLISH` Mosquitto
//! accepted and routed.
//!
//! **No test here skips.** A missing `mosquitto`, `mosquitto_sub` or `mosquitto_pub` fails with
//! the install command, because a skip-when-missing gate is a silent pass.
//!
//! LLM calls: 7 across the file (3 + 4).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mqtt --test client -- mqtt::real_server_test --test-threads=100


use crate::helpers::real_server::{InstallHint, RealServer, ToolProcess};
use crate::helpers::*;
use serde_json::json;
use std::process::Command;
use std::time::Duration;

const MOSQUITTO: InstallHint = InstallHint {
    brew: "mosquitto",
    apt: "mosquitto",
};
const MOSQUITTO_CLIENTS: InstallHint = InstallHint {
    brew: "mosquitto",
    apt: "mosquitto-clients",
};

/// A throwaway Mosquitto on a probed loopback port, anonymous, no persistence.
///
/// `listener 0` would mean a unix socket to Mosquitto, not "pick a port", so the probe-port
/// path is the only option; readiness is Mosquitto's own "running" line, which it prints only
/// after every listener is bound.
async fn start_mosquitto() -> E2EResult<RealServer> {
    RealServer::builder("mosquitto", MOSQUITTO)
        .config_file(
            "mosquitto.conf",
            "listener {port} 127.0.0.1\n\
             allow_anonymous true\n\
             persistence false\n\
             log_dest stderr\n\
             log_type all\n\
             connection_messages true\n",
        )
        .args(["-c", "{dir}/mosquitto.conf"])
        .ready_when_log_matches(r"mosquitto version \S+ running")
        .start()
        .await
}

/// `mosquitto_sub` on `topic`, ready once Mosquitto has sent it a SUBACK — so nothing
/// published after this returns can be missed.
///
/// Readiness comes from the **broker's** log (`log_type all` prints `Sending SUBACK to <id>`),
/// not from `mosquitto_sub -d`: with stdout on a pipe, `mosquitto_sub` block-buffers its debug
/// lines, while the message lines it exists to print are flushed one by one.
async fn subscribe(
    broker: &RealServer,
    id: &str,
    topic: &str,
    count: u32,
    qos: u8,
) -> E2EResult<ToolProcess> {
    let mut cmd = Command::new("mosquitto_sub");
    cmd.args([
        "-h",
        "127.0.0.1",
        "-p",
        &broker.port.to_string(),
        "-i",
        id,
        "-t",
        topic,
        "-q",
        &qos.to_string(),
        "-C",
        &count.to_string(),
        "-v",
    ]);
    let sub = ToolProcess::spawn(cmd, "mosquitto_sub", MOSQUITTO_CLIENTS)?;
    broker
        .wait_for_log(&format!("Sending SUBACK to {id}"), Duration::from_secs(20))
        .await?;
    Ok(sub)
}

/// `mosquitto_pub` one message and wait for it to exit (QoS ≥ 1 exits only after the broker
/// acknowledged it).
async fn publish(
    broker: &RealServer,
    topic: &str,
    payload: &str,
    qos: u8,
    retain: bool,
) -> E2EResult<()> {
    let mut cmd = Command::new("mosquitto_pub");
    cmd.args([
        "-h",
        "127.0.0.1",
        "-p",
        &broker.port.to_string(),
        "-t",
        topic,
        "-m",
        payload,
        "-q",
        &qos.to_string(),
    ]);
    if retain {
        cmd.arg("-r");
    }
    crate::helpers::real_server::run_tool(cmd, "mosquitto_pub", MOSQUITTO_CLIENTS).await?;
    Ok(())
}

/// The model publishes on connect, and answers a message `mosquitto_pub` sent it.
///
/// 1. `mosquitto_sub` subscribes to `netget/out` before NetGet exists.
/// 2. NetGet connects with `client_id` `netget-e2e-mqtt`; Mosquitto's connection log must name
///    it, which proves Mosquitto parsed NetGet's `CONNECT`.
/// 3. On `mqtt_connected` the mocked model subscribes to `netget/in` and publishes
///    `hello from the model` to `netget/out`. Both requests leave on one connection in that
///    order, and Mosquitto handles a connection's packets in order — so when `mosquitto_sub`
///    prints the greeting, NetGet's subscription is already in Mosquitto's table.
/// 4. `mosquitto_pub` publishes `ping from mosquitto_pub` to `netget/in`. The model's rule
///    matches only that payload and replies with a publish that quotes it.
/// 5. `mosquitto_sub` prints the quote.
///
/// LLM calls: 3 (startup, mqtt_connected, mqtt_message_received).
#[tokio::test]
async fn mqtt_client_publishes_and_answers_through_mosquitto() -> E2EResult<()> {
    let broker = start_mosquitto().await?;
    let result = publishes_and_answers(&broker).await;
    broker.with_log(result)
}

async fn publishes_and_answers(broker: &RealServer) -> E2EResult<()> {
    let sub = subscribe(broker, "e2e-watch-out", "netget/out", 2, 1).await?;

    let addr = broker.addr();
    let config = NetGetConfig::new(format!(
        "Connect to the MQTT broker at {addr}. MQTT-REAL-BROKER-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("MQTT-REAL-BROKER-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "MQTT",
                "remote_addr": addr,
                "instruction": "Greet netget/out, listen on netget/in, and answer each message.",
                "startup_params": {"client_id": "netget-e2e-mqtt"}
            }]))
            .expect_calls(1)
            .and()
            .on_event("mqtt_connected")
            .respond_with_actions(json!([
                {"type": "subscribe", "topics": ["netget/in"], "qos": 1},
                {"type": "publish", "topic": "netget/out", "payload": "hello from the model", "qos": 1}
            ]))
            .expect_calls(1)
            .and()
            .on_event("mqtt_message_received")
            .and_event_data_contains("topic", "netget/in")
            .and_event_data_contains("payload", "ping from mosquitto_pub")
            .respond_with_actions_from_event(|event| {
                json!([{
                    "type": "publish",
                    "topic": "netget/out",
                    "payload": format!(
                        "the model saw: {}",
                        event["payload"].as_str().unwrap_or("")
                    ),
                    "qos": 1
                }])
            })
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;

    // The model's first publish, read back through the real broker.
    sub.wait_for_line("the model's greeting", Duration::from_secs(30), |l| {
        l == "netget/out hello from the model"
    })
    .await?;

    // Mosquitto parsed NetGet's CONNECT, including the client id the startup parameter set.
    assert!(
        broker.log().contains("New client connected from 127.0.0.1"),
        "mosquitto never logged NetGet's connection"
    );
    assert!(
        broker.log().contains(" as netget-e2e-mqtt "),
        "mosquitto did not see the client_id NetGet was started with"
    );
    // The model's subscribe action, as Mosquitto recorded it in its own subscription table.
    assert!(
        broker.log().contains("netget-e2e-mqtt 1 netget/in"),
        "mosquitto has no QoS 1 subscription to netget/in from NetGet"
    );

    publish(broker, "netget/in", "ping from mosquitto_pub", 1, false).await?;

    // The model's reply to an event built from Mosquitto's PUBLISH, read back through Mosquitto.
    sub.wait_for_line("the model's reply", Duration::from_secs(30), |l| {
        l == "netget/out the model saw: ping from mosquitto_pub"
    })
    .await?;

    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    client.stop().await?;
    Ok(())
}

/// Wildcards, QoS and retained messages, each observed from both sides.
///
/// A retained message is published to `sensors/room1/temp` before NetGet connects. The model
/// subscribes to `sensors/#` at QoS 1 on connect, so Mosquitto delivers the retained message at
/// once with the retain flag set; then `mosquitto_pub` sends a live message to
/// `sensors/room2/humidity` at QoS 2, which Mosquitto downgrades to the subscription's QoS 1.
///
/// The model's rule answers every `mqtt_message_received` by publishing, at QoS 1, a line built
/// **from the event's own fields** — topic, payload, qos, retain. `mosquitto_sub` must print
/// exactly those lines, so the assertion checks that NetGet decoded Mosquitto's `PUBLISH`
/// (topic, payload, the retain bit, the granted QoS) and that the model's reply went back out.
///
/// LLM calls: 4 (startup, mqtt_connected, two mqtt_message_received).
#[tokio::test]
async fn mqtt_client_sees_wildcards_qos_and_retained_messages_from_mosquitto() -> E2EResult<()> {
    let broker = start_mosquitto().await?;
    let result = wildcards_qos_and_retained(&broker).await;
    broker.with_log(result)
}

async fn wildcards_qos_and_retained(broker: &RealServer) -> E2EResult<()> {
    publish(broker, "sensors/room1/temp", "21.5C", 1, true).await?;
    let sub = subscribe(broker, "e2e-watch-ack", "netget/ack", 2, 1).await?;

    let addr = broker.addr();
    let config = NetGetConfig::new(format!(
        "Watch every sensor on the MQTT broker at {addr}. MQTT-WILDCARD-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("MQTT-WILDCARD-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "MQTT",
                "remote_addr": addr,
                "instruction": "Subscribe to sensors/# and acknowledge every reading on netget/ack."
            }]))
            .expect_calls(1)
            .and()
            .on_event("mqtt_connected")
            .respond_with_actions(json!([
                {"type": "subscribe", "topics": ["sensors/#"], "qos": 1}
            ]))
            .expect_calls(1)
            .and()
            .on_event("mqtt_message_received")
            .respond_with_actions_from_event(|event| {
                json!([{
                    "type": "publish",
                    "topic": "netget/ack",
                    "payload": format!(
                        "topic={} payload={} qos={} retain={}",
                        event["topic"].as_str().unwrap_or("?"),
                        event["payload"].as_str().unwrap_or("?"),
                        event["qos"],
                        event["retain"]
                    ),
                    "qos": 1
                }])
            })
            .expect_calls(2)
            .and()
    });

    let client = start_netget_client(config).await?;

    // The retained message, delivered on SUBSCRIBE because of the wildcard match.
    sub.wait_for_line(
        "the acknowledgement of the retained reading",
        Duration::from_secs(30),
        |l| l == "netget/ack topic=sensors/room1/temp payload=21.5C qos=1 retain=true",
    )
    .await?;

    // A live message published at QoS 2, granted at the subscription's QoS 1, not retained.
    publish(broker, "sensors/room2/humidity", "40%", 2, false).await?;
    sub.wait_for_line(
        "the acknowledgement of the live reading",
        Duration::from_secs(30),
        |l| l == "netget/ack topic=sensors/room2/humidity payload=40% qos=1 retain=false",
    )
    .await?;

    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    client.stop().await?;
    Ok(())
}

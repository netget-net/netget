//! MQTT broker driven by the real **mosquitto** command-line clients.
//!
//! The peer here is deliberately not a Rust crate. `src/server/mqtt/mod.rs` is a
//! hand-written MQTT 3.1.1 control-packet codec, and `mosquitto_pub` /
//! `mosquitto_sub` are Eclipse Mosquitto's C clients built on libmosquitto — a
//! separate implementation by a separate project in a separate language. Nothing
//! this server links against appears anywhere in that binary, so a session it
//! completes is independent evidence rather than one codec agreeing with itself.
//!
//! What the test drives is a whole broker session, not a handshake:
//!
//! ```text
//!   mosquitto_sub  CONNECT  -> CONNACK    (the model chose return code 0)
//!                  SUBSCRIBE-> SUBACK     (granted QoS echoed against its packet id)
//!   mosquitto_pub  CONNECT  -> CONNACK
//!                  PUBLISH  -> (broker-originated PUBLISH to the subscriber)
//!   mosquitto_sub  prints the payload on stdout
//! ```
//!
//! The final assertion is on what `mosquitto_sub` *printed*, which is the point: a
//! raw socket can be told any bytes arrived, but libmosquitto only prints a payload
//! it successfully parsed out of a PUBLISH whose remaining-length, topic length and
//! flags it accepted.
//!
//! This test is **not** `#[ignore]`d and does **not** skip when mosquitto is
//! missing — see `require_binary`.

use crate::server::helpers::*;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

const TOPIC: &str = "netget/real-client";
const BODY: &str = "payload-from-netget-broker";
const SUB_CLIENT_ID: &str = "netget-real-sub";
const PUB_CLIENT_ID: &str = "netget-real-pub";

/// Fail — never skip — when the third-party client is absent.
///
/// A `SKIP: not installed` that returns `Ok(())` is a silent pass on every machine
/// that lacks the binary, which is precisely how a maturity rating outlives the
/// evidence that justified it. MQTT's rating rests on this test, so a runner
/// without mosquitto must say so out loud.
async fn require_binary(bin: &str, version_arg: &str) -> E2EResult<()> {
    match Command::new(bin).arg(version_arg).output().await {
        // mosquitto_pub --help and mosquitto_sub --help exit non-zero on some
        // builds while still proving the binary runs, so the check is "it
        // executed and said something", not "it exited 0".
        Ok(out) if !out.stdout.is_empty() || !out.stderr.is_empty() => {
            let banner = if out.stdout.is_empty() {
                String::from_utf8_lossy(&out.stderr).to_string()
            } else {
                String::from_utf8_lossy(&out.stdout).to_string()
            };
            println!(
                "[real-client] {bin}: {}",
                banner.lines().next().unwrap_or("")
            );
            Ok(())
        }
        Ok(_) => Err(format!(
            "`{bin} {version_arg}` produced no output. This test's whole point is driving the \
             real mosquitto client against NetGet's broker; skipping it would leave MQTT's \
             maturity rating resting on nothing."
        )
        .into()),
        Err(e) => Err(format!(
            "{bin} is not available ({e}). This test's whole point is driving the real \
             mosquitto client against NetGet's broker, and skipping it would leave MQTT's \
             maturity rating resting on nothing."
        )
        .into()),
    }
}

#[tokio::test]
async fn test_mqtt_pubsub_session_against_mosquitto_clients() -> E2EResult<()> {
    require_binary("mosquitto_sub", "--help").await?;
    require_binary("mosquitto_pub", "--help").await?;

    let config = NetGetConfig::new(
        "Start an MQTT broker on port {AVAILABLE_PORT}. Accept every client, grant every \
         subscription, and forward published messages to the subscriber.",
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
            // Two CONNECTs reach this rule: the subscriber's and the publisher's.
            // A CONNECT the backend cannot answer is refused, so without this rule
            // the test would be measuring a broker that turns mosquitto away.
            .on_event("mqtt_connect")
            .respond_with_actions(serde_json::json!([
                {"type": "mqtt_connack", "return_code": 0, "session_present": false}
            ]))
            .expect_at_least(2)
            .and()
            // packet_id MUST come from the event. mosquitto_sub blocks until it sees
            // a SUBACK carrying the id it chose; a hardcoded id would hang the test
            // rather than fail it.
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
            // The publisher's PUBLISH arriving. The answer is a broker-originated
            // PUBLISH addressed to the *other* connection by client id -- this
            // server keeps no subscription table, so naming the recipient is the
            // model's job and `to_client_id` is what routes it.
            .on_event("mqtt_publish")
            .and_event_data_contains("topic", TOPIC)
            .respond_with_actions_from_event(|event| {
                serde_json::json!([{
                    "type": "mqtt_publish",
                    "topic": event["topic"].as_str().unwrap_or(TOPIC),
                    "payload": event["payload"].as_str().unwrap_or(BODY),
                    "qos": 0,
                    "retain": false,
                    "to_client_id": SUB_CLIENT_ID
                }])
            })
            .expect_at_least(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("[real-client] NetGet MQTT broker on 127.0.0.1:{port}");

    // -- the subscriber, long-running -------------------------------------------------
    //
    // `-v` prints "<topic> <payload>" for each message, so the single printed line is
    // evidence about both halves of the PUBLISH libmosquitto decoded, not just the
    // body. `-C 1` makes it exit after one message, so the process itself is an
    // assertion that a message was delivered.
    let mut sub = Command::new("mosquitto_sub")
        .args([
            "-v",
            "-V",
            "mqttv311",
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-i",
            SUB_CLIENT_ID,
            "-t",
            TOPIC,
            "-q",
            "0",
            "-C",
            "1",
            "-W",
            "40",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("failed to spawn mosquitto_sub: {e}"))?;

    let sub_stdout = sub
        .stdout
        .take()
        .ok_or("mosquitto_sub stdout was not piped")?;
    let mut sub_lines = BufReader::new(sub_stdout).lines();
    let mut transcript: Vec<String> = Vec::new();

    // Wait for the SUBACK to have gone out before publishing, on a real condition
    // rather than a sleep. The server's own log is the condition: mosquitto's
    // `-d` narration is not used, because its wording is a libmosquitto
    // implementation detail and the payload line below is the assertion that
    // matters. A publish that raced ahead of the SUBACK would be delivered to a
    // client that had not yet subscribed.
    server.wait_for_log("MQTT -> SUBACK", 40).await?;
    println!("[real-client] NetGet answered libmosquitto's SUBSCRIBE with a SUBACK");

    // -- the publisher, one-shot -------------------------------------------------------
    let pub_out = tokio::time::timeout(
        Duration::from_secs(30),
        Command::new("mosquitto_pub")
            .args([
                "-V",
                "mqttv311",
                "-h",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-i",
                PUB_CLIENT_ID,
                "-t",
                TOPIC,
                "-q",
                "0",
                "-m",
                BODY,
            ])
            .output(),
    )
    .await
    .map_err(|_| "mosquitto_pub did not finish within 30s")?
    .map_err(|e| format!("failed to run mosquitto_pub: {e}"))?;

    assert!(
        pub_out.status.success(),
        "mosquitto_pub exited {} against NetGet's broker. stderr: {}",
        pub_out.status,
        String::from_utf8_lossy(&pub_out.stderr)
    );
    println!("[real-client] mosquitto_pub completed CONNECT/CONNACK and PUBLISH");

    // -- the delivery ------------------------------------------------------------------
    //
    // libmosquitto prints this line only after parsing a PUBLISH it accepted:
    // remaining length, topic length, flags and all. Under `-v` the line is
    // "<topic> <payload>", so it carries both halves of the packet the broker built
    // — evidence a raw socket cannot produce.
    let expected_line = format!("{TOPIC} {BODY}");
    let delivered = tokio::time::timeout(Duration::from_secs(40), async {
        while let Ok(Some(line)) = sub_lines.next_line().await {
            println!("[mosquitto_sub] {line}");
            let hit = line.trim() == expected_line;
            transcript.push(line);
            if hit {
                return true;
            }
        }
        false
    })
    .await
    .map_err(|_| {
        format!(
            "mosquitto_sub never printed the message NetGet's broker published within 40s. \
             Expected the line {expected_line:?}. Transcript:\n{}",
            transcript.join("\n")
        )
    })?;

    assert!(
        delivered,
        "mosquitto_sub exited without printing {expected_line:?}. The broker-originated PUBLISH \
         either never arrived, carried the wrong topic, or libmosquitto rejected its framing. \
         Transcript:\n{}",
        transcript.join("\n")
    );
    println!("[real-client] mosquitto_sub parsed and printed the broker's PUBLISH topic+payload");

    let sub_status = tokio::time::timeout(Duration::from_secs(20), sub.wait())
        .await
        .map_err(|_| "mosquitto_sub did not exit after receiving its one message")?
        .map_err(|e| format!("waiting for mosquitto_sub failed: {e}"))?;
    assert!(
        sub_status.success(),
        "mosquitto_sub exited {sub_status} after receiving the message"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

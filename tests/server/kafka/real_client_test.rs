//! Kafka broker driven by the real **`kcat`** binary (librdkafka).
//!
//! The peer is not a Rust crate. `src/server/kafka/mod.rs` frames with
//! `kafka-protocol`; `kcat` is a C program built on librdkafka, the reference
//! non-JVM Kafka client, which shares no code with anything NetGet links against.
//! The existing e2e suite builds requests and decodes responses with
//! `kafka-protocol`'s own client-side codecs — that proves the crate round-trips
//! through itself, not that a real Kafka client accepts what this broker writes.
//! This test is the part that was missing.
//!
//! What is driven is a produce and a fetch, on one broker, with the record body
//! librdkafka *decoded and printed* as the assertion:
//!
//! ```text
//!   kcat -P   ApiVersions -> Metadata -> Produce            (record accepted at an offset)
//!   kcat -C   ApiVersions -> Metadata -> Fetch              (record batch decoded, body printed)
//! ```
//!
//! Decoding the fetch is the strong part: a Kafka v2 record batch carries a CRC, a
//! length-prefixed varint body, an attributes word and per-record offset deltas, and
//! librdkafka checks all of them. `kafka-protocol` writing a batch its own reader
//! accepts says nothing about whether librdkafka will.
//!
//! This test is **not** `#[ignore]`d and does **not** skip when kcat is missing —
//! see `require_kcat`.

use crate::server::helpers::*;
use serde_json::json;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const TOPIC: &str = "orders";
const KEY: &str = "order-1";
const VALUE: &str = "{\"item\":\"laptop\",\"price\":999}";

/// Fail — never skip — when `kcat` is absent.
///
/// A skip that returns `Ok(())` is a silent pass on any machine without librdkafka's
/// CLI. Kafka's maturity rating is being changed on the strength of this test, so a
/// runner without the binary has to say so rather than report green.
async fn require_kcat() -> E2EResult<()> {
    match Command::new("kcat").arg("-V").output().await {
        Ok(out) => {
            let banner = String::from_utf8_lossy(&out.stdout).to_string()
                + &String::from_utf8_lossy(&out.stderr);
            if banner.contains("kcat") || banner.contains("librdkafka") {
                println!(
                    "[real-client] {}",
                    banner.lines().next().unwrap_or("kcat present")
                );
                Ok(())
            } else {
                Err(format!(
                    "`kcat -V` ran but did not identify itself. This test's whole point is \
                     driving the real librdkafka client against NetGet's broker; skipping would \
                     leave Kafka's maturity rating resting on nothing. Output was: {banner}"
                )
                .into())
            }
        }
        Err(e) => Err(format!(
            "kcat is not available ({e}). This test's whole point is driving the real librdkafka \
             client against NetGet's Kafka broker, and skipping it would leave Kafka's maturity \
             rating resting on nothing."
        )
        .into()),
    }
}

/// One `kcat` invocation, bounded, returning `(stdout, stderr, success)`.
///
/// librdkafka retries a broker it cannot parse rather than failing fast, so an
/// unbounded run against a broken broker hangs instead of failing. Every call site
/// also passes `-m` to bound librdkafka's own metadata wait.
///
/// `stdin` is fed on the producer path rather than naming a file argument: in
/// produce mode kcat sends each **file** as one whole message, so `-K` never gets a
/// chance to split a key off it and the record arrives keyless with the delimiter
/// still embedded in its value. Line splitting and key splitting only happen on
/// stdin.
async fn kcat(args: &[&str], stdin: Option<&str>, what: &str) -> E2EResult<(String, String, bool)> {
    let mut cmd = Command::new("kcat");
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn kcat {what}: {e}"))?;

    if let Some(body) = stdin {
        let mut pipe = child.stdin.take().ok_or("kcat stdin was not piped")?;
        pipe.write_all(body.as_bytes())
            .await
            .map_err(|e| format!("failed writing to kcat {what} stdin: {e}"))?;
        pipe.shutdown()
            .await
            .map_err(|e| format!("failed closing kcat {what} stdin: {e}"))?;
        drop(pipe);
    }

    let out = tokio::time::timeout(Duration::from_secs(90), child.wait_with_output())
        .await
        .map_err(|_| format!("kcat {what} did not finish within 90s"))?
        .map_err(|e| format!("failed to run kcat {what}: {e}"))?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    println!("[kcat {what}] status={} stdout={stdout:?}", out.status);
    if !stderr.trim().is_empty() {
        println!("[kcat {what}] stderr:\n{stderr}");
    }
    Ok((stdout, stderr, out.status.success()))
}

#[tokio::test]
async fn test_kafka_produce_and_fetch_against_kcat() -> E2EResult<()> {
    require_kcat().await?;

    // The fetch answers with whatever the produce delivered, so the assertion at the
    // end is a genuine round trip rather than two independent constants.
    let captured: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_produce = captured.clone();
    let captured_fetch = captured.clone();

    let config = NetGetConfig::new(
        "Listen on port {AVAILABLE_PORT} via Kafka. Accept produces to 'orders' and return them.",
    )
    .with_log_level("debug")
    .with_mock(move |mock| {
        let captured_produce = captured_produce.clone();
        let captured_fetch = captured_fetch.clone();
        mock.on_instruction_containing("via Kafka")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "KAFKA",
                "instruction": "Kafka broker for the 'orders' topic"
            }]))
            .expect_calls(1)
            .and()
            // Metadata. `brokers` is deliberately omitted so the server advertises
            // itself: librdkafka connects to the address it is told about, and a
            // fabricated one would send it somewhere that does not exist.
            //
            // librdkafka refreshes metadata on its own schedule and each kcat run is
            // a fresh client, so this fires an unpredictable number of times.
            .on_event("kafka_metadata_request")
            .respond_with_actions_from_event(|event| {
                let topic = event
                    .get("requested_topics")
                    .and_then(|t| t.as_array())
                    .and_then(|t| t.first())
                    .and_then(|t| t.as_str())
                    .unwrap_or(TOPIC)
                    .to_string();
                json!([{
                    "type": "metadata_response",
                    "topics": [{
                        "name": topic,
                        "partitions": [{"partition": 0, "leader": 0, "replicas": [0]}]
                    }]
                }])
            })
            .expect_at_least(1)
            .and()
            .on_event("kafka_produce_request")
            .respond_with_actions_from_event(move |event| {
                let records = event
                    .get("records")
                    .and_then(|r| r.as_array())
                    .cloned()
                    .unwrap_or_default();
                *captured_produce.lock().unwrap() = records;
                json!([{
                    "type": "produce_response",
                    "topic": event.get("topic").cloned().unwrap_or(json!(TOPIC)),
                    "partition": event.get("partition").cloned().unwrap_or(json!(0)),
                    "offset": 0,
                    "error_code": 0
                }])
            })
            .expect_at_least(1)
            .and()
            .on_event("kafka_fetch_request")
            .respond_with_actions_from_event(move |event| {
                let base = event
                    .get("fetch_offset")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let records: Vec<serde_json::Value> = captured_fetch
                    .lock()
                    .unwrap()
                    .iter()
                    .enumerate()
                    .map(|(i, r)| {
                        json!({
                            "offset": base + i as i64,
                            "key": r.get("key").cloned().unwrap_or(serde_json::Value::Null),
                            "value": r.get("value").cloned().unwrap_or(serde_json::Value::Null),
                        })
                    })
                    .collect();
                json!([{
                    "type": "fetch_response",
                    "topic": event.get("topic").cloned().unwrap_or(json!(TOPIC)),
                    "partition": event.get("partition").cloned().unwrap_or(json!(0)),
                    "records": records
                }])
            })
            // librdkafka keeps fetching until it hits the end of the partition, so
            // more than one Fetch is normal.
            .expect_at_least(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let broker = format!("127.0.0.1:{}", server.port);
    println!("[real-client] NetGet Kafka broker at {broker}");

    // -- produce -----------------------------------------------------------------------
    //
    // `-K :` makes kcat split "key:value" out of the line it reads on stdin, so the
    // record carries both and the fetch can assert both came back.
    let record_line = format!("{KEY}:{VALUE}\n");

    let (_stdout, stderr, ok) = kcat(
        &[
            "-b",
            &broker,
            "-t",
            TOPIC,
            "-p",
            "0",
            "-P",
            "-K",
            ":",
            "-m",
            "20",
            "-X",
            "message.timeout.ms=20000",
        ],
        Some(&record_line),
        "produce",
    )
    .await?;
    assert!(
        ok,
        "kcat failed to produce to NetGet's broker -- librdkafka rejected the ApiVersions, \
         Metadata or Produce response. stderr:\n{stderr}"
    );
    println!("[real-client] librdkafka accepted NetGet's Metadata and Produce responses");

    // The broker stores nothing: what comes back on fetch is what the model captured
    // off the produce, so an empty capture means librdkafka's record batch never
    // decoded and the fetch assertion below would be vacuous.
    {
        let got = captured.lock().unwrap();
        assert!(
            !got.is_empty(),
            "NetGet decoded no records out of librdkafka's Produce request, so the fetch below \
             would assert on nothing. The v2 record-batch decoder did not accept what \
             librdkafka wrote."
        );
        let first = &got[0];
        assert_eq!(
            first.get("value").and_then(|v| v.as_str()),
            Some(VALUE),
            "NetGet decoded a different record value out of librdkafka's batch: {first}"
        );
        assert_eq!(
            first.get("key").and_then(|v| v.as_str()),
            Some(KEY),
            "NetGet decoded a different record key out of librdkafka's batch: {first}"
        );
    }
    println!("[real-client] NetGet decoded librdkafka's v2 record batch: key and value intact");

    // -- fetch -------------------------------------------------------------------------
    //
    // `-o 0` is an absolute offset, which keeps librdkafka off ListOffsets -- an API
    // key this broker does not implement. `-e` exits at end of partition and `-c 1`
    // caps the run.
    let (stdout, stderr, ok) = kcat(
        &[
            "-b", &broker, "-t", TOPIC, "-p", "0", "-C", "-o", "0", "-c", "1", "-e", "-K", ":",
            "-m", "20",
        ],
        None,
        "consume",
    )
    .await?;
    assert!(
        ok,
        "kcat failed to consume from NetGet's broker -- librdkafka rejected the Fetch response. \
         stderr:\n{stderr}"
    );
    assert!(
        stdout.contains(VALUE),
        "librdkafka did not print the record body NetGet served, so it did not decode the v2 \
         record batch this broker encoded.\n  expected to contain: {VALUE}\n  stdout: {stdout:?}\n\
         stderr:\n{stderr}"
    );
    assert!(
        stdout.contains(KEY),
        "librdkafka printed a record body but not the key, so the batch's key encoding is \
         wrong.\n  stdout: {stdout:?}"
    );
    println!("[real-client] librdkafka decoded and printed NetGet's record batch");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

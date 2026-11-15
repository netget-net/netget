//! A Produce v0–2 request may carry legacy (magic 0/1) messages, and a legacy message flagged
//! compressed holds a message set. `kafka-protocol` decodes one by recursing once per nested
//! wrapper with no depth bound — and without inflating anything: it reads the wrapper's value
//! as if it were already a message set. So a request of nested "compressed" wrappers, each
//! 34 bytes with a correct CRC-32, is a stack overflow: a `SIGSEGV`, not a panic, and the
//! whole broker process goes.
//!
//! The broker refuses a compressed legacy wrapper before the decoder is reached, answering the
//! partition UNSUPPORTED_COMPRESSION_TYPE (76). This test sends the fuzz corpus's own depth
//! bomb (`fuzz/corpus/kafka_request/produce_v2_legacy_nesting_bomb`, 20 000 levels), expects
//! that answer, and checks the broker still answers afterwards; an uncompressed legacy message
//! on the same connection is the control, decoded and delivered to the handler.
//!
//! Without the refusal (the `LegacyCompressed` arm in `declared_records` removed) the test
//! binary dies with a stack overflow on the bomb.

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::server::kafka::kafka_protocol::messages::ProduceResponse;
use netget::server::kafka::kafka_protocol::protocol::Decodable;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[{'type':'produce_response','topic':e['topic'],'partition':e['partition'],'offset':5}] if t=='kafka_produce_request' else []
print(json.dumps({'actions':a}))"#;

async fn broker() -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "kafka".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":HANDLER}}),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create kafka broker");
    let port = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the Kafka broker never bound");
    (state, id, port)
}

/// CRC-32 (IEEE), what a legacy message carries over everything after its CRC field.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// One uncompressed magic-1 message carrying `value`.
fn legacy_message(value: &[u8]) -> Vec<u8> {
    let mut tail = vec![1u8, 0];
    tail.extend(0i64.to_be_bytes());
    tail.extend((-1i32).to_be_bytes());
    tail.extend((value.len() as i32).to_be_bytes());
    tail.extend_from_slice(value);
    let mut out = 0i64.to_be_bytes().to_vec();
    out.extend(((4 + tail.len()) as i32).to_be_bytes());
    out.extend(crc32_ieee(&tail).to_be_bytes());
    out.extend(tail);
    out
}

/// A Produce v2 request message (no size prefix) with one partition carrying `records`.
fn produce_v2(correlation_id: i32, records: &[u8]) -> Vec<u8> {
    let mut req = 0i16.to_be_bytes().to_vec();
    req.extend(2i16.to_be_bytes());
    req.extend(correlation_id.to_be_bytes());
    req.extend(4i16.to_be_bytes());
    req.extend(b"test");
    req.extend((-1i16).to_be_bytes());
    req.extend(1000i32.to_be_bytes());
    req.extend(1i32.to_be_bytes());
    req.extend(1i16.to_be_bytes());
    req.extend(b"t");
    req.extend(1i32.to_be_bytes());
    req.extend(0i32.to_be_bytes());
    req.extend((records.len() as i32).to_be_bytes());
    req.extend_from_slice(records);
    req
}

/// Send one request message and decode the Produce v2 response: (partition error, base offset).
async fn produce(c: &mut TcpStream, message: &[u8], correlation_id: i32) -> (i16, i64) {
    let mut frame = (message.len() as i32).to_be_bytes().to_vec();
    frame.extend_from_slice(message);
    c.write_all(&frame).await.unwrap();
    let mut size = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(20), c.read_exact(&mut size))
        .await
        .expect("the broker did not answer")
        .expect("the broker closed the connection");
    let mut body = vec![0u8; i32::from_be_bytes(size) as usize];
    c.read_exact(&mut body).await.unwrap();
    assert_eq!(&body[..4], &correlation_id.to_be_bytes());
    let response = ProduceResponse::decode(&mut std::io::Cursor::new(&body[4..]), 2).unwrap();
    let p = &response.responses[0].partition_responses[0];
    (p.error_code, p.base_offset)
}

#[tokio::test]
async fn a_nested_legacy_message_set_is_refused_before_the_decoder_recurses() {
    let (state, id, port) = broker().await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    // Control: an uncompressed legacy message is decoded and reaches the handler.
    assert_eq!(
        produce(&mut c, &produce_v2(1, &legacy_message(b"legacy-value")), 1).await,
        (0, 5)
    );
    let produced: Vec<serde_json::Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == "kafka_produce_request")
        .collect();
    assert_eq!(
        produced[0]["request"]["records"][0]["value"], "legacy-value",
        "{produced:#?}"
    );

    // The depth bomb, exactly as the fuzz corpus carries it.
    let bomb = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/corpus/kafka_request/produce_v2_legacy_nesting_bomb"
    ))
    .unwrap();
    assert!(bomb.len() > 600_000);
    assert_eq!(produce(&mut c, &bomb, 7).await, (76, -1));

    // One level is refused the same way: a compressed legacy wrapper is never decoded.
    let mut wrapper = legacy_message(&legacy_message(b"inner"));
    wrapper[17] = 1; // attributes: gzip
    let crc = crc32_ieee(&wrapper[16..]);
    wrapper[12..16].copy_from_slice(&crc.to_be_bytes());
    assert_eq!(produce(&mut c, &produce_v2(9, &wrapper), 9).await, (76, -1));

    // Still answering on the same connection.
    assert_eq!(
        produce(&mut c, &produce_v2(11, &legacy_message(b"after")), 11).await,
        (0, 5)
    );
}

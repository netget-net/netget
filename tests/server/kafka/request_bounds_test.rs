//! The broker's per-request bounds, each on both sides of its number:
//!
//! | bound | taken | refused |
//! |---|---|---|
//! | `MAX_PARTITIONS` (1024, inclusive) | partition 1024 | 1025 and -1: UNKNOWN_TOPIC_OR_PARTITION (3), handler not asked |
//! | `MAX_UNITS_PER_REQUEST` (64) | 64 partitions in one Produce, each asked | the 65th: UNKNOWN_SERVER_ERROR (-1), not asked |
//! | `MAX_RECORDS_PER_FETCH` (1000) | an answer of 1000 records, all sent | 1001: the first 1000 sent |
//! | `MIN_REQUEST_BYTES` (8) | an 8-byte ApiVersions v99 is answered UNSUPPORTED_VERSION | a 7-byte request: the connection is closed |
//!
//! The handler is a script; what it was asked is read from the access log.
//!
//! `MAX_FETCH_PAYLOAD_BYTES` (8 MiB of key and value bytes per Fetch answer) has no test here:
//! a script's stdout and a static rule are each bounded at 8 MiB of JSON first, so neither can
//! carry an answer that reaches it.

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::server::kafka::kafka_protocol::messages::fetch_request::{FetchPartition, FetchTopic};
use netget::server::kafka::kafka_protocol::messages::{
    ApiKey, BrokerId, FetchRequest, FetchResponse, ProduceResponse, RequestHeader, ResponseHeader,
};
use netget::server::kafka::kafka_protocol::protocol::{Decodable, Encodable, StrBytes};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='kafka_produce_request':
  a=[{'type':'produce_response','topic':e['topic'],'partition':e['partition'],'offset':5}]
elif t=='kafka_fetch_request' and e['topic'].startswith('count'):
  recs=[{'key':'k','value':'v'} for _ in range(int(e['topic'][5:]))]
  a=[{'type':'fetch_response','topic':e['topic'],'partition':e['partition'],'records':recs}]
print(json.dumps({'actions':a}))"#;

const MIB: usize = 1024 * 1024;

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

/// The partitions the handler was asked about for `event_type`, in order.
async fn asked(state: &AppState, id: ServerId, event_type: &str) -> Vec<i64> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|v| v["event_type"] == event_type)
        .map(|v| v["request"]["partition"].as_i64().unwrap_or(i64::MIN))
        .collect()
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

/// One uncompressed magic-1 message carrying `value`, as a one-message message set.
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

/// A Produce v2 request message (no size prefix) for topic `t`, one legacy message in each of
/// `partitions`.
fn produce_v2(correlation_id: i32, partitions: &[i32]) -> Vec<u8> {
    let records = legacy_message(b"bounded");
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
    req.extend((partitions.len() as i32).to_be_bytes());
    for p in partitions {
        req.extend(p.to_be_bytes());
        req.extend((records.len() as i32).to_be_bytes());
        req.extend_from_slice(&records);
    }
    req
}

/// Write one size-prefixed request message and read the response body after its size prefix.
async fn exchange(c: &mut TcpStream, message: &[u8]) -> Vec<u8> {
    let mut frame = (message.len() as i32).to_be_bytes().to_vec();
    frame.extend_from_slice(message);
    c.write_all(&frame).await.unwrap();
    let mut size = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(60), c.read_exact(&mut size))
        .await
        .expect("the broker did not answer")
        .expect("the broker closed the connection");
    let mut body = vec![0u8; i32::from_be_bytes(size) as usize];
    c.read_exact(&mut body).await.unwrap();
    body
}

/// Produce v2 to `partitions`; (partition, error code) per partition answered.
async fn produce(c: &mut TcpStream, correlation_id: i32, partitions: &[i32]) -> Vec<(i32, i16)> {
    let body = exchange(c, &produce_v2(correlation_id, partitions)).await;
    assert_eq!(&body[..4], &correlation_id.to_be_bytes());
    let response = ProduceResponse::decode(&mut std::io::Cursor::new(&body[4..]), 2).unwrap();
    response.responses[0]
        .partition_responses
        .iter()
        .map(|p| (p.index, p.error_code))
        .collect()
}

type Decompressor = fn(
    &mut bytes::Bytes,
    netget::server::kafka::kafka_protocol::records::Compression,
) -> anyhow::Result<std::io::Cursor<bytes::Bytes>>;

/// Fetch v11 of `topic` partition 0 from offset 0; the records the broker sent.
async fn fetch(
    c: &mut TcpStream,
    correlation_id: i32,
    topic: &str,
) -> Vec<netget::server::kafka::kafka_protocol::records::Record> {
    let mut message = Vec::new();
    RequestHeader::default()
        .with_request_api_key(ApiKey::Fetch as i16)
        .with_request_api_version(11)
        .with_correlation_id(correlation_id)
        .encode(&mut message, ApiKey::Fetch.request_header_version(11))
        .unwrap();
    FetchRequest::default()
        .with_replica_id(BrokerId(-1))
        .with_max_wait_ms(0)
        .with_max_bytes(64 * MIB as i32)
        .with_topics(vec![FetchTopic::default()
            .with_topic(StrBytes::from_string(topic.to_string()).into())
            .with_partitions(vec![FetchPartition::default()
                .with_partition(0)
                .with_fetch_offset(0)
                .with_partition_max_bytes(64 * MIB as i32)])])
        .encode(&mut message, 11)
        .unwrap();
    let body = exchange(c, &message).await;
    let mut cursor = std::io::Cursor::new(body.as_slice());
    let header =
        ResponseHeader::decode(&mut cursor, ApiKey::Fetch.response_header_version(11)).unwrap();
    assert_eq!(header.correlation_id, correlation_id);
    let response = FetchResponse::decode(&mut cursor, 11).unwrap();
    let partition = &response.responses[0].partitions[0];
    assert_eq!(partition.error_code, 0, "{topic}: the fetch was refused");
    let raw = partition.records.clone().unwrap_or_default();
    let mut cursor = std::io::Cursor::new(raw);
    let mut records = Vec::new();
    while cursor.position() < cursor.get_ref().len() as u64 {
        records.extend(
            netget::server::kafka::kafka_protocol::records::RecordBatchDecoder::decode_with_custom_compression::<
                _,
                Decompressor,
            >(&mut cursor, None)
            .expect("the broker's record batch must decode"),
        );
    }
    records
}

#[tokio::test]
async fn partition_indices_are_bounded_at_1024() {
    let (state, id, port) = broker().await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert_eq!(
        produce(&mut c, 1, &[1024, 1025, -1]).await,
        vec![(1024, 0), (1025, 3), (-1, 3)]
    );
    assert_eq!(
        asked(&state, id, "kafka_produce_request").await,
        vec![1024],
        "only the partition inside the bound may reach the handler"
    );
    state.remove_server(id).await;
}

#[tokio::test]
async fn one_request_reaches_the_handler_for_at_most_64_partitions() {
    let (state, id, port) = broker().await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    let exactly: Vec<i32> = (0..64).collect();
    let answered = produce(&mut c, 1, &exactly).await;
    assert!(
        answered.iter().all(|&(_, e)| e == 0),
        "64 partitions are inside the bound: {answered:?}"
    );
    assert_eq!(asked(&state, id, "kafka_produce_request").await.len(), 64);

    let one_more: Vec<i32> = (100..165).collect();
    let answered = produce(&mut c, 2, &one_more).await;
    assert_eq!(answered.len(), 65);
    assert!(answered[..64].iter().all(|&(_, e)| e == 0), "{answered:?}");
    assert_eq!(
        answered[64],
        (164, -1),
        "the 65th unit is UNKNOWN_SERVER_ERROR"
    );
    let asked_now = asked(&state, id, "kafka_produce_request").await;
    assert_eq!(
        asked_now.len(),
        128,
        "the 65th unit must not reach the handler"
    );
    assert!(!asked_now.contains(&164));
    state.remove_server(id).await;
}

#[tokio::test]
async fn a_fetch_answer_is_cut_at_1000_records() {
    let (state, id, port) = broker().await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert_eq!(fetch(&mut c, 1, "count1000").await.len(), 1000);
    assert_eq!(fetch(&mut c, 2, "count1001").await.len(), 1000);
    state.remove_server(id).await;
}

#[tokio::test]
async fn a_request_shorter_than_its_fixed_header_closes_the_connection() {
    let (state, id, port) = broker().await;

    // Control: ApiVersions at a version this broker does not implement is answered from the
    // 8-byte fixed header alone (UNSUPPORTED_VERSION and the table, at v0).
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut eight = 18i16.to_be_bytes().to_vec();
    eight.extend(99i16.to_be_bytes());
    eight.extend(7i32.to_be_bytes());
    let body = exchange(&mut c, &eight).await;
    assert_eq!(&body[..4], &7i32.to_be_bytes());

    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut frame = 7i32.to_be_bytes().to_vec();
    frame.extend_from_slice(&eight[..7]);
    c.write_all(&frame).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(10), c.read(&mut buf))
        .await
        .expect("a 7-byte request must close the connection, not hold it")
        .unwrap_or(0);
    assert_eq!(n, 0, "a 7-byte request must get no answer");
    state.remove_server(id).await;
}

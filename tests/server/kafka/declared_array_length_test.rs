//! An 18-byte unauthenticated request must not take the broker down.
//!
//! `kafka-protocol` pre-allocated every array from the peer-supplied count
//! (`Vec::with_capacity(n)` with no look at the bytes remaining), so a Metadata request
//! whose topics array declares 0x7fffffff entries asked for ~144 GiB before reading its
//! first (absent) element. That is an allocator failure, which aborts the whole process:
//! not a panic, so nothing caught it and the broker stayed "Running" in no one's memory.
//! The netget-kafka-protocol fork carries the bound; this test drives the bytes at a real broker.
//!
//! The same lever existed one layer down, in the record batch every Produce request carries
//! and every Fetch response hands the client: a batch's `record_count` and a record's header
//! count were reserved as declared, and a snappy batch zero-filled whatever length its
//! header named. The second half of this file decodes each of those through
//! `RecordBatchDecoder`, with a well-formed batch as the control that proves the hand-built
//! framing and CRC are right — so each hostile case fails on its count, not on a checksum.
//! Unpatched, the record-count and header-count cases abort the test binary with
//! "memory allocation of … bytes failed" rather than failing.
//!
//! The model is a closed port and is never reached: the decode fails before any event.
//!
//! Run with:
//!   cargo test --no-default-features --features kafka --test server -- kafka::declared_array_length

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..200 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Kafka broker #{} never bound a port", id.as_u32());
}

/// size=14, api_key=3 (Metadata), api_version=1, correlation_id=0, client_id=null,
/// topics array length = 0x7fffffff.
const HOSTILE_METADATA: [u8; 18] = [
    0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x7f, 0xff,
    0xff, 0xff,
];

#[tokio::test]
async fn a_request_declaring_two_billion_topics_leaves_the_broker_running() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "kafka".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create kafka broker");
    let port = wait_for_port(&state, server_id).await;

    let mut hostile = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    hostile.write_all(&HOSTILE_METADATA).await.unwrap();
    // The broker answers or closes; either way it must not hang and must not die.
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), hostile.read_to_end(&mut sink)).await;

    // Still here: a fresh connection is accepted and a well-formed ApiVersions request is
    // answered (api_key 18 v0 has an empty body).
    let mut probe = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("the broker must still accept connections");
    let api_versions: [u8; 14] = [
        0x00, 0x00, 0x00, 0x0a, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0xff, 0xff,
    ];
    probe.write_all(&api_versions).await.unwrap();
    let mut head = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(10), probe.read_exact(&mut head))
        .await
        .expect("the broker must still answer")
        .expect("a response frame");
    assert_eq!(
        &head[4..8],
        &[0, 0, 0, 0x2a],
        "the reply must carry the probe's correlation id"
    );
}

/// CRC-32C (Castagnoli), bitwise. RecordBatch v2 checksums everything from `attributes` to
/// the end of the batch with it, and the decoder refuses a batch whose CRC is wrong before
/// it reads a count — so a hostile batch must carry a correct one to reach the bound.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A zigzag varint, the encoding of every length inside a v2 record.
fn varint(n: i32) -> Vec<u8> {
    let mut v = ((n << 1) ^ (n >> 31)) as u32;
    let mut out = Vec::new();
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
    out
}

/// A v2 record: its varint length, then `body` (attributes onward).
fn record(body: &[u8]) -> Vec<u8> {
    let mut out = varint(body.len() as i32);
    out.extend_from_slice(body);
    out
}

/// A RecordBatch v2 with a correct length and CRC, declaring `record_count` and carrying
/// `records` (already compressed, if `attributes` names a codec).
fn record_batch(attributes: i16, record_count: i32, records: &[u8]) -> bytes::Bytes {
    let mut checked = Vec::new();
    checked.extend_from_slice(&attributes.to_be_bytes());
    checked.extend_from_slice(&0i32.to_be_bytes()); // last offset delta
    checked.extend_from_slice(&0i64.to_be_bytes()); // first timestamp
    checked.extend_from_slice(&0i64.to_be_bytes()); // max timestamp
    checked.extend_from_slice(&(-1i64).to_be_bytes()); // producer id
    checked.extend_from_slice(&(-1i16).to_be_bytes()); // producer epoch
    checked.extend_from_slice(&(-1i32).to_be_bytes()); // base sequence
    checked.extend_from_slice(&record_count.to_be_bytes());
    checked.extend_from_slice(records);

    let mut batch = Vec::new();
    batch.extend_from_slice(&0i64.to_be_bytes()); // base offset
    batch.extend_from_slice(&((4 + 1 + 4 + checked.len()) as i32).to_be_bytes());
    batch.extend_from_slice(&0i32.to_be_bytes()); // partition leader epoch
    batch.push(2); // magic
    batch.extend_from_slice(&crc32c(&checked).to_be_bytes());
    batch.extend_from_slice(&checked);
    bytes::Bytes::from(batch)
}

type Decompressor = fn(
    &mut bytes::Bytes,
    netget::server::kafka::kafka_protocol::records::Compression,
) -> anyhow::Result<std::io::Cursor<bytes::Bytes>>;

fn decode_batch(
    batch: bytes::Bytes,
) -> anyhow::Result<Vec<netget::server::kafka::kafka_protocol::records::Record>> {
    let mut cursor = std::io::Cursor::new(batch);
    netget::server::kafka::kafka_protocol::records::RecordBatchDecoder::decode_with_custom_compression::<
        _,
        Decompressor,
    >(&mut cursor, None)
}

/// attributes 0, timestamp delta 0, offset delta 0, key null (-1).
const RECORD_PREFIX: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// Decoding `batch` must fail cleanly, and not on the checksum — a CRC failure would mean
/// the decoder never reached the count under test.
fn assert_refused(what: &str, batch: bytes::Bytes) -> String {
    let len = batch.len();
    let err = decode_batch(batch).expect_err(what);
    let text = format!("{err:#}");
    assert!(
        !text.contains("Cyclic redundancy"),
        "{what}: the {len}-byte batch failed its CRC, so the bound was never exercised: {text}"
    );
    text
}

#[test]
fn the_hand_built_record_batch_framing_decodes_when_well_formed() {
    assert_eq!(crc32c(b"123456789"), 0xE306_9283, "CRC-32C check value");

    let mut body = RECORD_PREFIX.to_vec();
    body.extend(varint(5));
    body.extend_from_slice(b"hello");
    body.extend(varint(0)); // no headers
    let records = decode_batch(record_batch(0, 1, &record(&body)))
        .expect("the control batch must decode, or the hostile cases prove nothing");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].value.as_deref(), Some(&b"hello"[..]));
}

#[test]
fn a_record_batch_declaring_two_billion_records_is_an_error_not_an_abort() {
    let batch = record_batch(0, i32::MAX, &[]);
    assert!(batch.len() < 64, "the lever is a ~61-byte batch");
    assert_refused(
        "a batch declaring 0x7fffffff records and carrying none",
        batch,
    );
}

#[test]
fn a_record_declaring_two_billion_headers_is_an_error_not_an_abort() {
    let mut body = RECORD_PREFIX.to_vec();
    body.extend(varint(-1)); // value null
    body.extend(varint(i32::MAX)); // header count
    assert_refused(
        "a record declaring 0x7fffffff headers and carrying none",
        record_batch(0, 1, &record(&body)),
    );
}

#[test]
fn record_key_and_header_key_lengths_beyond_the_record_are_errors() {
    let mut key = vec![0x00, 0x00, 0x00];
    key.extend(varint(i32::MAX)); // key length
    assert_refused(
        "a record key declaring 2 GiB",
        record_batch(0, 1, &record(&key)),
    );

    let mut header_key = RECORD_PREFIX.to_vec();
    header_key.extend(varint(-1)); // value null
    header_key.extend(varint(1)); // one header
    header_key.extend(varint(i32::MAX)); // its key length
    assert_refused(
        "a header key declaring 2 GiB",
        record_batch(0, 1, &record(&header_key)),
    );
}

#[test]
fn a_snappy_batch_whose_header_declares_four_gib_is_refused_before_zero_filling() {
    // attributes 2 = snappy. A raw snappy block is a varint uncompressed length and then
    // elements; this one declares u32::MAX and carries none.
    let batch = record_batch(2, 1, &[0xff, 0xff, 0xff, 0xff, 0x0f]);
    let text = assert_refused("a snappy block declaring 4 GiB", batch);
    assert!(
        text.contains("Snappy header declares"),
        "the vendored bound must refuse it before allocating; unpatched, the decoder \
         zero-fills 4 GiB and only then fails: {text}"
    );
}

/// The same record-count lever, sent to a running broker inside a Produce request: the
/// broker must answer CORRUPT_MESSAGE (2) for the partition and stay up.
#[tokio::test]
async fn a_produce_request_whose_batch_declares_two_billion_records_is_corrupt_message() {
    use netget::server::kafka::kafka_protocol::messages::produce_request::{
        PartitionProduceData, TopicProduceData,
    };
    use netget::server::kafka::kafka_protocol::messages::{
        ApiKey, ProduceRequest, ProduceResponse, RequestHeader, ResponseHeader,
    };
    use netget::server::kafka::kafka_protocol::protocol::{Decodable, Encodable, StrBytes};

    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "kafka".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create kafka broker");
    let port = wait_for_port(&state, server_id).await;

    const VERSION: i16 = 7;
    let mut frame = Vec::new();
    RequestHeader::default()
        .with_request_api_key(ApiKey::Produce as i16)
        .with_request_api_version(VERSION)
        .with_correlation_id(0x2b)
        .encode(&mut frame, ApiKey::Produce.request_header_version(VERSION))
        .unwrap();
    ProduceRequest::default()
        .with_acks(1)
        .with_timeout_ms(5_000)
        .with_topic_data(vec![TopicProduceData::default()
            .with_name(StrBytes::from_static_str("orders").into())
            .with_partition_data(vec![PartitionProduceData::default()
                .with_index(0)
                .with_records(Some(record_batch(0, i32::MAX, &[])))])])
        .encode(&mut frame, VERSION)
        .unwrap();

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(&(frame.len() as i32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&frame).await.unwrap();

    let mut size = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut size))
        .await
        .expect("the broker must answer the produce")
        .expect("a response frame");
    let mut body = vec![0u8; i32::from_be_bytes(size) as usize];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .expect("the broker must finish the response")
        .expect("a response body");

    let mut cursor = std::io::Cursor::new(&body[..]);
    let header = ResponseHeader::decode(
        &mut cursor,
        ApiKey::Produce.response_header_version(VERSION),
    )
    .unwrap();
    assert_eq!(header.correlation_id, 0x2b);
    let response = ProduceResponse::decode(&mut cursor, VERSION).unwrap();
    assert_eq!(
        response.responses[0].partition_responses[0].error_code, 2,
        "a batch that cannot be decoded is CORRUPT_MESSAGE"
    );
}

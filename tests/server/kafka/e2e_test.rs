//! Kafka broker E2E tests
//!
//! # How these tests avoid asserting NetGet against itself
//!
//! There is no usable pure-Rust Kafka client in this workspace (`rdkafka` was removed
//! because it aborts in malloc, and adding a dev-dependency would mean editing
//! `Cargo.toml`). So the "client" here is built from `kafka-protocol`'s **client-side**
//! codecs — the request encoders and response decoders generated from Apache Kafka's
//! own message schemas — reached through `netget::server::kafka::kafka_protocol`.
//!
//! That is the opposite direction from the broker: the broker decodes requests and
//! encodes responses, these tests encode requests and decode responses. Nothing here
//! calls a function `src/server/kafka/` wrote. What is being validated is NetGet's
//! framing, version negotiation, dispatch, event emission and action handling; the
//! schemas themselves are taken as given.
//!
//! Every test asserts the correlation id is echoed, because that is the one thing a
//! client cannot recover from getting wrong.
//!
//! LLM call budget: 3 (test A: startup + 2 metadata) + 4 (test B: startup + produce +
//! fetch + offset commit) = 7.

use crate::helpers::{start_netget_server, wait_for_server_startup, E2EResult, NetGetConfig};
use bytes::Bytes;
use netget::server::kafka::kafka_protocol::messages::{
    ApiKey, ApiVersionsResponse, FetchRequest, FetchResponse, MetadataRequest, MetadataResponse,
    OffsetCommitRequest, OffsetCommitResponse, ProduceRequest, ProduceResponse, RequestHeader,
    ResponseHeader,
};
use netget::server::kafka::kafka_protocol::protocol::{Decodable, Encodable, StrBytes};
use netget::server::kafka::kafka_protocol::records::{
    Compression, Record, RecordBatchDecoder, RecordBatchEncoder, RecordEncodeOptions, TimestampType,
};
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Compressor/decompressor type parameters. `None` selects `kafka-protocol`'s built-in
/// codecs; the types still have to be nameable.
type Decompressor = fn(&mut Bytes, Compression) -> anyhow::Result<std::io::Cursor<Bytes>>;
type Compressor = fn(&mut bytes::BytesMut, &mut Vec<u8>, Compression) -> anyhow::Result<()>;

/// Encode `header + body` exactly as a Kafka client would, choosing the request header
/// version from the (api_key, api_version) pair rather than assuming one.
fn encode_request<B: Encodable>(
    api_key: ApiKey,
    api_version: i16,
    correlation_id: i32,
    body: &B,
) -> Vec<u8> {
    let mut buf = Vec::new();
    RequestHeader::default()
        .with_request_api_key(api_key as i16)
        .with_request_api_version(api_version)
        .with_correlation_id(correlation_id)
        .with_client_id(Some(StrBytes::from_string("netget-e2e".to_string())))
        .encode(&mut buf, api_key.request_header_version(api_version))
        .expect("request header must encode");
    body.encode(&mut buf, api_version)
        .expect("request body must encode");
    buf
}

async fn send_frame(stream: &mut TcpStream, body: &[u8]) -> E2EResult<()> {
    let size = i32::try_from(body.len()).expect("request fits in i32");
    tokio::time::timeout(IO_TIMEOUT, stream.write_all(&size.to_be_bytes())).await??;
    tokio::time::timeout(IO_TIMEOUT, stream.write_all(body)).await??;
    Ok(())
}

async fn read_frame(stream: &mut TcpStream) -> E2EResult<Vec<u8>> {
    let mut size = [0u8; 4];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut size)).await??;
    let n = i32::from_be_bytes(size);
    assert!(
        n > 0 && n < 10_000_000,
        "broker announced an implausible response size of {n} bytes"
    );
    let mut buf = vec![0u8; n as usize];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut buf)).await??;
    Ok(buf)
}

/// Split a response frame into its header and body, decoding both at the versions the
/// request implies. A wrong response-header version desynchronises the body, so this
/// doubles as an assertion that the broker picked the same one.
fn decode_response<R: Decodable>(api_key: ApiKey, api_version: i16, bytes: &[u8]) -> (i32, R) {
    let mut cursor = std::io::Cursor::new(bytes);
    let header = ResponseHeader::decode(&mut cursor, api_key.response_header_version(api_version))
        .expect("response header must decode");
    let body = R::decode(&mut cursor, api_version).expect("response body must decode");
    (header.correlation_id, body)
}

async fn roundtrip<B: Encodable, R: Decodable>(
    stream: &mut TcpStream,
    api_key: ApiKey,
    api_version: i16,
    correlation_id: i32,
    body: &B,
) -> E2EResult<R> {
    let request = encode_request(api_key, api_version, correlation_id, body);
    send_frame(stream, &request).await?;
    let response = read_frame(stream).await?;

    // The pcap oracle. `kafka-protocol` is an independent codec, but it is told which
    // api key and version to decode at — `decode_response` is handed them by the
    // caller — so it cannot notice a response header written at the wrong version, or
    // a size prefix that disagrees with the frame. Wireshark's `kafka` dissector
    // derives all of that from the request it saw on the same stream, which is why
    // both directions go in here, size prefixes included.
    {
        let framed = |b: &[u8]| {
            let mut v = (b.len() as u32).to_be_bytes().to_vec();
            v.extend_from_slice(b);
            v
        };
        crate::helpers::pcap_oracle::PcapOracle::tcp("kafka")
            // Wireshark 4.2's dissector knows Produce to v8, Fetch to v11, Metadata to v9 and
            // OffsetCommit to v8, and says so as a warning on any ApiVersions response
            // advertising more. The broker advertises Produce 11, Fetch 16, Metadata 12 and
            // OffsetCommit 9, which Apache Kafka's Java client and franz-go complete at
            // (flexible_versions_test.rs); the warning is a statement about the dissector's
            // table, not about these bytes. Every request this suite sends stays inside it.
            .allow_expert_containing(" version. Supports v0-")
            .to_server(&framed(&request))
            .from_server(&framed(&response))
            .assert_clean();
    }

    let (echoed, decoded) = decode_response::<R>(api_key, api_version, &response);
    assert_eq!(
        echoed, correlation_id,
        "broker must echo the correlation id for {api_key:?} v{api_version}"
    );
    Ok(decoded)
}

async fn connect(port: u16) -> E2EResult<TcpStream> {
    Ok(tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(format!("127.0.0.1:{port}"))).await??)
}

/// ApiVersions negotiation, Metadata, and the refusal paths that must not answer with a
/// plausible-looking body.
#[tokio::test]
async fn test_kafka_api_versions_and_metadata() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Listen on port {AVAILABLE_PORT} via Kafka. One topic 'orders' with one partition.",
    )
    .with_mock(|mock| {
        mock
            // Metadata: the model owns the topic list. It deliberately does not name a
            // broker, so the broker list has to come from the server's own address.
            .on_event("kafka_metadata_request")
            .respond_with_actions(json!([{
                "type": "metadata_response",
                "topics": [
                    {"name": "orders", "partitions": [{"partition": 0, "leader": 7, "replicas": [7]}]}
                ]
            }]))
            .expect_calls(2)
            .and()
            // Server startup (the user command).
            .on_any()
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "KAFKA",
                "instruction": "Kafka broker with a single topic 'orders'",
                "startup_params": {"cluster_id": "netget-test", "broker_id": 7}
            }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    wait_for_server_startup(&server, Duration::from_secs(20), "KAFKA").await?;
    let port = server.port;

    let mut stream = connect(port).await?;

    // ---- 1. ApiVersions at a version the broker implements ---------------------
    let api_versions: ApiVersionsResponse = roundtrip(
        &mut stream,
        ApiKey::ApiVersions,
        3,
        1001,
        &netget::server::kafka::kafka_protocol::messages::ApiVersionsRequest::default()
            .with_client_software_name(StrBytes::from_string("netget-e2e".to_string()))
            .with_client_software_version(StrBytes::from_string("0".to_string())),
    )
    .await?;

    assert_eq!(
        api_versions.error_code, 0,
        "ApiVersions v3 is supported and must not carry an error"
    );
    let advertised: Vec<(i16, i16, i16)> = api_versions
        .api_keys
        .iter()
        .map(|a| (a.api_key, a.min_version, a.max_version))
        .collect();
    assert!(
        advertised.contains(&(ApiKey::ApiVersions as i16, 0, 3)),
        "ApiVersions must advertise itself, got {advertised:?}"
    );
    assert!(
        advertised.contains(&(ApiKey::Metadata as i16, 0, 12)),
        "Metadata range missing from {advertised:?}"
    );
    assert!(
        advertised.contains(&(ApiKey::Produce as i16, 0, 11)),
        "Produce range missing from {advertised:?}"
    );
    assert!(
        advertised.contains(&(ApiKey::Fetch as i16, 0, 16)),
        "Fetch range missing from {advertised:?}"
    );
    assert!(
        advertised.contains(&(ApiKey::OffsetCommit as i16, 0, 9)),
        "OffsetCommit range missing from {advertised:?}"
    );
    assert!(
        !advertised
            .iter()
            .any(|(k, _, _)| *k == ApiKey::ListOffsets as i16),
        "ListOffsets is not implemented and must not be advertised: {advertised:?}"
    );

    // ---- 2. ApiVersions at a version the broker does not implement --------------
    // Kafka's negotiation rule: reply UNSUPPORTED_VERSION *and the table*, encoded at
    // v0, so the client can step down. Encoding the reply at the requested version
    // would leave the client unable to parse the very message telling it what to do.
    {
        let mut buf = Vec::new();
        RequestHeader::default()
            .with_request_api_key(ApiKey::ApiVersions as i16)
            .with_request_api_version(9)
            .with_correlation_id(1002)
            .with_client_id(Some(StrBytes::from_string("netget-e2e".to_string())))
            .encode(&mut buf, 1)
            .expect("header encodes");
        send_frame(&mut stream, &buf).await?;
        let response = read_frame(&mut stream).await?;
        let (echoed, body) =
            decode_response::<ApiVersionsResponse>(ApiKey::ApiVersions, 0, &response);
        assert_eq!(echoed, 1002, "correlation id must survive the error path");
        assert_eq!(
            body.error_code, 35,
            "an unsupported ApiVersions version must return UNSUPPORTED_VERSION"
        );
        assert!(
            !body.api_keys.is_empty(),
            "the error reply must still carry the supported-API table or the client cannot negotiate"
        );
    }

    // ---- 3. Metadata for a topic the model knows about --------------------------
    let metadata: MetadataResponse = roundtrip(
        &mut stream,
        ApiKey::Metadata,
        8,
        1003,
        &MetadataRequest::default().with_topics(Some(vec![
            netget::server::kafka::kafka_protocol::messages::metadata_request::MetadataRequestTopic::default()
                .with_name(Some(StrBytes::from_string("orders".to_string()).into())),
        ])),
    )
    .await?;

    assert_eq!(
        metadata.cluster_id.as_ref().map(|c| c.to_string()),
        Some("netget-test".to_string()),
        "cluster_id from startup_params must reach the wire at Metadata v8"
    );
    assert_eq!(
        metadata.controller_id.0, 7,
        "controller_id must be broker_id"
    );
    assert_eq!(
        metadata.brokers.len(),
        1,
        "a model that names no broker must still leave the client one to talk to"
    );
    let broker = &metadata.brokers[0];
    assert_eq!(broker.node_id.0, 7);
    assert_eq!(
        broker.port as u16, port,
        "the advertised broker must point back at this server, not a guess"
    );
    assert_eq!(broker.host.to_string(), "127.0.0.1");

    assert_eq!(metadata.topics.len(), 1);
    let topic = &metadata.topics[0];
    assert_eq!(
        topic.name.as_ref().map(|n| n.to_string()),
        Some("orders".to_string())
    );
    assert_eq!(topic.error_code, 0);
    assert_eq!(topic.partitions.len(), 1);
    assert_eq!(topic.partitions[0].partition_index, 0);
    assert_eq!(
        topic.partitions[0].leader_id.0, 7,
        "partition leadership must point at the advertised broker"
    );

    // ---- 4. Metadata for a topic the model did not describe ---------------------
    let metadata: MetadataResponse = roundtrip(
        &mut stream,
        ApiKey::Metadata,
        8,
        1004,
        &MetadataRequest::default().with_topics(Some(vec![
            netget::server::kafka::kafka_protocol::messages::metadata_request::MetadataRequestTopic::default()
                .with_name(Some(StrBytes::from_string("ghost".to_string()).into())),
        ])),
    )
    .await?;
    let ghost = metadata
        .topics
        .iter()
        .find(|t| t.name.as_ref().map(|n| n.to_string()) == Some("ghost".to_string()))
        .expect("the requested topic must appear in the reply");
    assert_eq!(
        ghost.error_code, 3,
        "a topic the model did not describe must be UNKNOWN_TOPIC_OR_PARTITION, not silently absent"
    );
    drop(stream);

    // ---- 5. An API key the broker does not implement ----------------------------
    // The connection must close rather than emit a body no client can parse.
    {
        let mut stream = connect(port).await?;
        let mut buf = Vec::new();
        RequestHeader::default()
            .with_request_api_key(ApiKey::ListOffsets as i16)
            .with_request_api_version(1)
            .with_correlation_id(1005)
            .with_client_id(Some(StrBytes::from_string("netget-e2e".to_string())))
            .encode(&mut buf, ApiKey::ListOffsets.request_header_version(1))
            .expect("header encodes");
        buf.extend_from_slice(&[0, 0, 0, 0]);
        send_frame(&mut stream, &buf).await?;

        let mut sink = [0u8; 8];
        let n = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut sink)).await??;
        assert_eq!(
            n, 0,
            "an unimplemented API key must close the connection, not answer with {n} bytes"
        );
    }

    // ---- 6. Hostile length prefixes ---------------------------------------------
    for prefix in [0i32, 3, -1, i32::MIN, i32::MAX] {
        let mut stream = connect(port).await?;
        tokio::time::timeout(IO_TIMEOUT, stream.write_all(&prefix.to_be_bytes())).await??;
        let mut sink = [0u8; 8];
        let n = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut sink)).await??;
        assert_eq!(
            n, 0,
            "size prefix {prefix} must close the connection cleanly"
        );
    }

    // ---- 7. The broker survived all of it ----------------------------------------
    let mut stream = connect(port).await?;
    let api_versions: ApiVersionsResponse = roundtrip(
        &mut stream,
        ApiKey::ApiVersions,
        0,
        1006,
        &netget::server::kafka::kafka_protocol::messages::ApiVersionsRequest::default(),
    )
    .await?;
    assert_eq!(api_versions.error_code, 0);
    assert!(!api_versions.api_keys.is_empty());
    drop(stream);

    tokio::time::sleep(Duration::from_millis(200)).await;
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Produce a real record batch, then fetch it back, then commit an offset.
///
/// The produce and fetch mocks share one `Arc<Mutex<_>>`: the produce mock records the
/// records NetGet decoded off the wire, and the fetch mock hands exactly those back. So
/// the assertion at the end — that the fetched key and value equal the bytes this test
/// originally encoded — only holds if NetGet's produce-side record-batch decoding and
/// its fetch-side record-batch encoding are both right and agree with each other.
#[tokio::test]
async fn test_kafka_produce_fetch_roundtrip() -> E2EResult<()> {
    const KEY: &str = "order-1";
    const VALUE: &str = "{\"item\":\"laptop\",\"price\":999}";

    let captured: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_produce = captured.clone();
    let captured_fetch = captured.clone();

    let config = NetGetConfig::new(
        "Listen on port {AVAILABLE_PORT} via Kafka. Accept produces to 'orders' and return them.",
    )
    .with_mock(move |mock| {
        let captured_produce = captured_produce.clone();
        let captured_fetch = captured_fetch.clone();
        mock.on_event("kafka_produce_request")
            .respond_with_actions_from_event(move |event| {
                let records = event
                    .get("records")
                    .and_then(|r| r.as_array())
                    .cloned()
                    .unwrap_or_default();
                *captured_produce.lock().unwrap() = records;
                json!([{
                    "type": "produce_response",
                    "topic": event.get("topic").cloned().unwrap_or(json!("orders")),
                    "partition": event.get("partition").cloned().unwrap_or(json!(0)),
                    "offset": 42,
                    "error_code": 0
                }])
            })
            .expect_calls(1)
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
                    "topic": event.get("topic").cloned().unwrap_or(json!("orders")),
                    "partition": event.get("partition").cloned().unwrap_or(json!(0)),
                    "records": records
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("kafka_offset_commit_request")
            .respond_with_actions_from_event(move |event| {
                json!([{
                    "type": "offset_commit_response",
                    "topic": event.get("topic").cloned().unwrap_or(json!("orders")),
                    "partition": event.get("partition").cloned().unwrap_or(json!(0)),
                    "error_code": 0
                }])
            })
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "KAFKA",
                "instruction": "Kafka broker for the 'orders' topic"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    wait_for_server_startup(&server, Duration::from_secs(20), "KAFKA").await?;
    let mut stream = connect(server.port).await?;

    // ---- Produce -----------------------------------------------------------------
    let batch = {
        let records = vec![Record {
            transactional: false,
            control: false,
            partition_leader_epoch: 0,
            producer_id: -1,
            producer_epoch: -1,
            timestamp_type: TimestampType::Creation,
            offset: 0,
            sequence: 0,
            timestamp: 1_700_000_000_000,
            key: Some(Bytes::from_static(KEY.as_bytes())),
            value: Some(Bytes::from_static(VALUE.as_bytes())),
            headers: Default::default(),
        }];
        let mut buf = Vec::new();
        RecordBatchEncoder::encode_with_custom_compression::<_, _, Compressor>(
            &mut buf,
            &records,
            &RecordEncodeOptions {
                version: 2,
                compression: Compression::None,
            },
            None,
        )
        .expect("test record batch must encode");
        Bytes::from(buf)
    };

    use netget::server::kafka::kafka_protocol::messages::produce_request::{
        PartitionProduceData, TopicProduceData,
    };
    let produce: ProduceResponse = roundtrip(
        &mut stream,
        ApiKey::Produce,
        7,
        2001,
        &ProduceRequest::default()
            .with_acks(1)
            .with_timeout_ms(5_000)
            .with_topic_data(vec![TopicProduceData::default()
                .with_name(StrBytes::from_string("orders".to_string()).into())
                .with_partition_data(vec![PartitionProduceData::default()
                    .with_index(0)
                    .with_records(Some(batch))])]),
    )
    .await?;

    assert_eq!(produce.responses.len(), 1);
    let produced = &produce.responses[0].partition_responses[0];
    assert_eq!(
        produced.error_code, 0,
        "the model accepted the batch, so the producer must see success"
    );
    assert_eq!(
        produced.base_offset, 42,
        "the base offset must be the one the model assigned, not one Rust invented"
    );

    // The event the broker raised must have carried the decoded record, not raw bytes.
    {
        let seen = captured.lock().unwrap();
        assert_eq!(seen.len(), 1, "one produced record must reach the model");
        assert_eq!(seen[0]["key"].as_str(), Some(KEY));
        assert_eq!(seen[0]["value"].as_str(), Some(VALUE));
        assert_eq!(
            seen[0]["value_encoding"].as_str(),
            Some("utf8"),
            "printable payloads must be presented as text, never base64"
        );
    }

    // ---- Fetch it back ------------------------------------------------------------
    use netget::server::kafka::kafka_protocol::messages::fetch_request::{
        FetchPartition, FetchTopic,
    };
    use netget::server::kafka::kafka_protocol::messages::BrokerId;
    let fetch: FetchResponse = roundtrip(
        &mut stream,
        ApiKey::Fetch,
        11,
        2002,
        &FetchRequest::default()
            .with_replica_id(BrokerId(-1))
            .with_max_wait_ms(100)
            .with_min_bytes(1)
            .with_max_bytes(1024 * 1024)
            .with_topics(vec![FetchTopic::default()
                .with_topic(StrBytes::from_string("orders".to_string()).into())
                .with_partitions(vec![FetchPartition::default()
                    .with_partition(0)
                    .with_fetch_offset(42)
                    .with_partition_max_bytes(1024 * 1024)])]),
    )
    .await?;

    assert_eq!(fetch.responses.len(), 1);
    let partition = &fetch.responses[0].partitions[0];
    assert_eq!(partition.error_code, 0);
    assert_eq!(
        partition.high_watermark, 43,
        "one record starting at offset 42 means a high watermark of 43"
    );

    let raw = partition
        .records
        .as_ref()
        .expect("fetch must carry a record set");
    let mut cursor = std::io::Cursor::new(raw.clone());
    let fetched =
        RecordBatchDecoder::decode_with_custom_compression::<_, Decompressor>(&mut cursor, None)
            .expect("the broker's record batch must decode with kafka-protocol's own decoder");

    assert_eq!(fetched.len(), 1, "exactly one record was produced");
    assert_eq!(
        fetched[0].offset, 42,
        "the fetched record must sit at the offset the consumer asked from"
    );
    assert_eq!(
        fetched[0].key.as_ref().map(|k| k.as_ref().to_vec()),
        Some(KEY.as_bytes().to_vec()),
        "the key must survive produce-decode -> event -> fetch-encode unchanged"
    );
    assert_eq!(
        fetched[0].value.as_ref().map(|v| v.as_ref().to_vec()),
        Some(VALUE.as_bytes().to_vec()),
        "the value must survive produce-decode -> event -> fetch-encode unchanged"
    );

    // ---- Commit an offset ---------------------------------------------------------
    use netget::server::kafka::kafka_protocol::messages::offset_commit_request::{
        OffsetCommitRequestPartition, OffsetCommitRequestTopic,
    };
    let commit: OffsetCommitResponse = roundtrip(
        &mut stream,
        ApiKey::OffsetCommit,
        2,
        2003,
        &OffsetCommitRequest::default()
            .with_group_id(StrBytes::from_string("orders-consumers".to_string()).into())
            .with_generation_id_or_member_epoch(-1)
            .with_topics(vec![OffsetCommitRequestTopic::default()
                .with_name(StrBytes::from_string("orders".to_string()).into())
                .with_partitions(vec![OffsetCommitRequestPartition::default()
                    .with_partition_index(0)
                    .with_committed_offset(43)])]),
    )
    .await?;

    assert_eq!(commit.topics.len(), 1);
    assert_eq!(commit.topics[0].partitions[0].error_code, 0);
    assert_eq!(commit.topics[0].partitions[0].partition_index, 0);

    drop(stream);
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

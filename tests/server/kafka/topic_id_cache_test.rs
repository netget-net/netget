//! The broker's topic-id table: what a Metadata answer can make it remember.
//!
//! Every topic a Metadata v10+ answer describes is remembered by id, so a later Fetch v13+
//! or Metadata v12 naming it by id alone can be answered. The names come from the model (or
//! a handler), so the table is bounded twice: a name over Kafka's own 249-byte limit is not
//! described and not remembered, and past `MAX_KNOWN_TOPIC_IDS` the oldest id is forgotten —
//! one, not the whole table.

use netget::cli::management::ServerForm;
use netget::server::kafka::{topic_id, TopicIds, MAX_KNOWN_TOPIC_IDS, MAX_TOPIC_NAME_LEN};
use netget::state::app_state::AppState;
use serde_json::json;
use std::time::Duration;
use tokio::sync::mpsc;

#[test]
fn a_name_over_kafkas_limit_is_not_remembered() {
    let table = TopicIds::default();
    let at = "a".repeat(MAX_TOPIC_NAME_LEN);
    let past = "b".repeat(MAX_TOPIC_NAME_LEN + 1);
    assert_eq!(table.report(&at), Some(topic_id(&at)));
    assert_eq!(table.report(&past), None);
    assert_eq!(table.len(), 1);
    assert_eq!(table.name(&topic_id(&at)), Some(at));
    assert_eq!(table.name(&topic_id(&past)), None);
}

#[test]
fn past_the_cap_the_oldest_id_is_forgotten_one_at_a_time() {
    let table = TopicIds::default();
    let name = |i: usize| format!("topic-{i}");
    for i in 0..MAX_KNOWN_TOPIC_IDS {
        table.report(&name(i)).unwrap();
    }
    assert_eq!(table.len(), MAX_KNOWN_TOPIC_IDS);
    // Reporting a known name again is not a new entry and evicts nothing.
    table.report(&name(0)).unwrap();
    assert_eq!(table.len(), MAX_KNOWN_TOPIC_IDS);

    table.report("one more").unwrap();
    assert_eq!(table.len(), MAX_KNOWN_TOPIC_IDS, "still at the cap");
    assert_eq!(table.name(&topic_id(&name(0))), None, "the oldest went");
    assert_eq!(
        table.name(&topic_id(&name(1))),
        Some(name(1)),
        "and only the oldest: the rest are still answerable"
    );
    assert_eq!(
        table.name(&topic_id(&name(MAX_KNOWN_TOPIC_IDS - 1))),
        Some(name(MAX_KNOWN_TOPIC_IDS - 1))
    );
    assert_eq!(table.name(&topic_id("one more")), Some("one more".into()));
}

/// A broker whose handler describes every requested topic, whatever its name.
async fn broker() -> (AppState, netget::state::ServerId, u16) {
    let handler = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='kafka_metadata_request':
  a=[{'type':'metadata_response','topics':[{'name':n,'partitions':[{'partition':0,'leader':0,'replicas':[0]}]} for n in e['requested_topics']]}]
elif t=='kafka_fetch_request':
  a=[{'type':'fetch_response','topic':e['topic'],'partition':e['partition'],'records':[]}]
else:
  a=[]
print(json.dumps({'actions':a}))"#;
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "kafka".to_string(),
        host: Some("127.0.0.1".into()),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![json!({
            "event_pattern": "*",
            "handler": {"type": "script", "language": "python", "code": handler}
        })]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create kafka broker");
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the broker never bound");
    (state, id, port)
}

/// Send one request frame and read one response frame's body (after the length prefix).
async fn exchange(stream: &mut tokio::net::TcpStream, body: Vec<u8>) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut frame = (body.len() as i32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    stream.write_all(&frame).await.unwrap();
    let mut len = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut len))
        .await
        .expect("the broker answered")
        .unwrap();
    let mut reply = vec![0u8; i32::from_be_bytes(len) as usize];
    stream.read_exact(&mut reply).await.unwrap();
    reply
}

#[tokio::test]
async fn a_metadata_answer_naming_an_overlong_topic_does_not_describe_or_remember_it() {
    use netget::server::kafka::kafka_protocol::messages::{
        fetch_request::{FetchPartition, FetchTopic},
        metadata_request::MetadataRequestTopic,
        ApiKey, FetchRequest, FetchResponse, MetadataRequest, MetadataResponse, RequestHeader,
        ResponseHeader,
    };
    use netget::server::kafka::kafka_protocol::protocol::{Decodable, Encodable, StrBytes};

    let at = "a".repeat(MAX_TOPIC_NAME_LEN);
    let past = "b".repeat(MAX_TOPIC_NAME_LEN + 1);
    let (state, id, port) = broker().await;
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();

    let mut body = Vec::new();
    RequestHeader::default()
        .with_request_api_key(ApiKey::Metadata as i16)
        .with_request_api_version(12)
        .with_correlation_id(1)
        .encode(&mut body, ApiKey::Metadata.request_header_version(12))
        .unwrap();
    MetadataRequest::default()
        .with_topics(Some(
            [&at, &past]
                .into_iter()
                .map(|n| {
                    MetadataRequestTopic::default()
                        .with_name(Some(StrBytes::from_string(n.clone()).into()))
                })
                .collect(),
        ))
        .encode(&mut body, 12)
        .unwrap();
    let reply = exchange(&mut stream, body).await;
    let mut cursor = std::io::Cursor::new(reply.as_slice());
    let header =
        ResponseHeader::decode(&mut cursor, ApiKey::Metadata.response_header_version(12)).unwrap();
    assert_eq!(header.correlation_id, 1);
    let response = MetadataResponse::decode(&mut cursor, 12).unwrap();
    let topic = |name: &str| {
        response
            .topics
            .iter()
            .find(|t| t.name.as_ref().map(|n| n.to_string()).as_deref() == Some(name))
            .unwrap_or_else(|| panic!("topic of {} bytes is in the answer", name.len()))
    };
    assert_eq!(topic(&at).error_code, 0, "a 249-byte name is described");
    assert_eq!(topic(&at).topic_id, topic_id(&at));
    assert_eq!(
        topic(&past).error_code,
        3,
        "a 250-byte name is UNKNOWN_TOPIC_OR_PARTITION, not described"
    );
    assert!(topic(&past).topic_id.is_nil(), "and gets no id");

    // Asked for by the id its name would have, the overlong topic is unknown: never stored.
    let mut body = Vec::new();
    RequestHeader::default()
        .with_request_api_key(ApiKey::Fetch as i16)
        .with_request_api_version(16)
        .with_correlation_id(2)
        .encode(&mut body, ApiKey::Fetch.request_header_version(16))
        .unwrap();
    FetchRequest::default()
        .with_max_wait_ms(0)
        .with_max_bytes(1 << 20)
        .with_topics(vec![FetchTopic::default()
            .with_topic_id(topic_id(&past))
            .with_partitions(vec![FetchPartition::default()
                .with_partition(0)
                .with_partition_max_bytes(1 << 20)])])
        .encode(&mut body, 16)
        .unwrap();
    let reply = exchange(&mut stream, body).await;
    let mut cursor = std::io::Cursor::new(reply.as_slice());
    ResponseHeader::decode(&mut cursor, ApiKey::Fetch.response_header_version(16)).unwrap();
    let response = FetchResponse::decode(&mut cursor, 16).unwrap();
    assert_eq!(response.responses[0].topic_id, topic_id(&past));
    assert_eq!(
        response.responses[0].partitions[0].error_code, 100,
        "UNKNOWN_TOPIC_ID"
    );
    state.remove_server(id).await;
}

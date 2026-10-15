//! The broker at the newest versions it advertises — Produce 11, Fetch 16, Metadata 12,
//! OffsetCommit 9, all *flexible* (compact strings and arrays, tagged fields), and Fetch v13+
//! naming topics by id — against independent clients that negotiate them:
//!
//! - **Apache Kafka's own Java client** (kafka-clients 3.9.1): Metadata v12, Produce v11,
//!   Fetch v16 by topic id.
//! - **franz-go** (Go, written from the protocol spec, not from the Java client): the same
//!   newest versions through a different implementation.
//! - **kcat** (librdkafka 2.3) still completes, now with Metadata v12 — the one flexible
//!   version it speaks — and its own Produce/Fetch ceilings.
//!
//! Each client produces a record and then consumes one. The handler answers every fetch with
//! a record whose value names the Fetch version the request came in at, so what the client
//! prints proves it decoded a response encoded at that version. The versions each client
//! negotiated are read back from the broker's own events.
//!
//! Every peer is required. `NETGET_KAFKA_PEERS` names the directory
//! `tests/server/kafka/install_peers.py` filled; the tests fail rather than skip without it.

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

/// Metadata names one partition led by this broker; produce answers offset 41; a fetch from
/// offset 0 answers one record naming the Fetch version it came in at, a later fetch nothing.
fn handler() -> String {
    r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='kafka_metadata_request':
  a=[{'type':'metadata_response','topics':[{'name':n,'partitions':[{'partition':0,'leader':0,'replicas':[0]}]} for n in (e['requested_topics'] or ['versions'])]}]
elif t=='kafka_produce_request':
  a=[{'type':'produce_response','topic':e['topic'],'partition':e['partition'],'offset':41,'error_code':0}]
elif t=='kafka_fetch_request':
  recs=[{'offset':0,'key':'netget-key','value':'served at fetch v%d' % e['api_version']}] if e['fetch_offset']==0 else []
  a=[{'type':'fetch_response','topic':e['topic'],'partition':e['partition'],'records':recs}]
else:
  a=[]
print(json.dumps({'actions':a}))"#
        .to_string()
}

async fn broker() -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "kafka".to_string(),
        host: Some("127.0.0.1".into()),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![json!({
            "event_pattern": "*",
            "handler": {"type": "script", "language": "python", "code": handler()}
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

/// The highest version each API was used at, from the broker's own events.
async fn versions(state: &AppState, id: ServerId) -> std::collections::BTreeMap<String, i64> {
    let mut out = std::collections::BTreeMap::new();
    for e in state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
    {
        let v = serde_json::to_value(&e).unwrap();
        if let Some(n) = v["request"]["api_version"].as_i64() {
            let entry = out
                .entry(v["event_type"].as_str().unwrap_or("").to_string())
                .or_insert(n);
            *entry = (*entry).max(n);
        }
    }
    out
}

fn peers() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("NETGET_KAFKA_PEERS").expect(
        "NETGET_KAFKA_PEERS is required: run python3 tests/server/kafka/install_peers.py <dir> \
         and export what it prints",
    ))
}

async fn run(mut command: tokio::process::Command, what: &str) -> String {
    let out = tokio::time::timeout(Duration::from_secs(90), command.kill_on_drop(true).output())
        .await
        .unwrap_or_else(|_| panic!("{what} did not finish"))
        .unwrap_or_else(|e| panic!("{what} could not run: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "{what} failed:\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

fn assert_round_trip(stdout: &str, fetch_version: i64, what: &str) {
    assert!(
        stdout.contains("PRODUCED partition=0 offset=41"),
        "{what}: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "CONSUMED offset=0 key=netget-key value=served at fetch v{fetch_version}"
        )),
        "{what}: {stdout}"
    );
}

#[tokio::test]
async fn apache_kafkas_java_client_at_the_newest_versions() {
    let (state, id, port) = broker().await;
    let dir = peers();
    let classpath = format!(
        "{}:{}",
        dir.join("kafka-clients-3.9.1.jar").display(),
        dir.join("slf4j-api-1.7.36.jar").display()
    );
    let mut java = tokio::process::Command::new("java");
    java.args([
        "-cp",
        &classpath,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/server/kafka/peer/JavaPeer.java"
        ),
        &format!("127.0.0.1:{port}"),
        "versions",
    ]);
    let stdout = run(java, "the Java client").await;
    let used = versions(&state, id).await;
    assert_eq!(used.get("kafka_metadata_request"), Some(&12), "{used:?}");
    assert_eq!(used.get("kafka_produce_request"), Some(&11), "{used:?}");
    assert_eq!(used.get("kafka_fetch_request"), Some(&16), "{used:?}");
    assert_round_trip(&stdout, 16, "Java");
    let produced = state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .into_iter()
        .map(|e| serde_json::to_value(&e).unwrap())
        .find(|e| e["event_type"] == "kafka_produce_request")
        .unwrap();
    assert_eq!(produced["request"]["first_key"], "java-key", "{produced}");
    state.remove_server(id).await;
}

#[tokio::test]
async fn franz_go_at_the_newest_versions() {
    let (state, id, port) = broker().await;
    let mut franz = tokio::process::Command::new(peers().join("franz-peer"));
    franz.args([&format!("127.0.0.1:{port}"), "versions"]);
    let stdout = run(franz, "franz-go").await;
    let used = versions(&state, id).await;
    assert_eq!(used.get("kafka_metadata_request"), Some(&12), "{used:?}");
    assert_eq!(used.get("kafka_produce_request"), Some(&11), "{used:?}");
    assert_eq!(used.get("kafka_fetch_request"), Some(&16), "{used:?}");
    assert_round_trip(&stdout, 16, "franz-go");
    state.remove_server(id).await;
}

/// A Fetch v13+ naming a topic id this broker never reported gets UNKNOWN_TOPIC_ID, and the
/// handler is not asked; the ids it does report are the name's, stable across servers.
#[tokio::test]
async fn unknown_topic_ids_are_refused_and_known_ones_are_stable() {
    use netget::server::kafka::kafka_protocol::messages::{
        fetch_request::{FetchPartition, FetchTopic},
        ApiKey, FetchRequest, FetchResponse, RequestHeader, ResponseHeader,
    };
    use netget::server::kafka::kafka_protocol::protocol::{Decodable, Encodable};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    assert_eq!(
        netget::server::kafka::topic_id("versions"),
        netget::server::kafka::topic_id("versions")
    );
    assert_ne!(
        netget::server::kafka::topic_id("versions"),
        netget::server::kafka::topic_id("version")
    );
    assert_ne!(netget::server::kafka::topic_id(""), uuid::Uuid::nil());

    let (state, id, port) = broker().await;
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let stranger = uuid::Uuid::from_u128(0x1234);
    let mut body = Vec::new();
    RequestHeader::default()
        .with_request_api_key(ApiKey::Fetch as i16)
        .with_request_api_version(16)
        .with_correlation_id(7)
        .encode(&mut body, ApiKey::Fetch.request_header_version(16))
        .unwrap();
    FetchRequest::default()
        .with_max_wait_ms(0)
        .with_max_bytes(1 << 20)
        .with_topics(vec![FetchTopic::default()
            .with_topic_id(stranger)
            .with_partitions(vec![FetchPartition::default()
                .with_partition(0)
                .with_partition_max_bytes(1 << 20)])])
        .encode(&mut body, 16)
        .unwrap();
    let mut frame = (body.len() as i32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    stream.write_all(&frame).await.unwrap();
    let mut len = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut len))
        .await
        .unwrap()
        .unwrap();
    let mut reply = vec![0u8; i32::from_be_bytes(len) as usize];
    stream.read_exact(&mut reply).await.unwrap();
    let mut cursor = std::io::Cursor::new(reply.as_slice());
    let header =
        ResponseHeader::decode(&mut cursor, ApiKey::Fetch.response_header_version(16)).unwrap();
    assert_eq!(header.correlation_id, 7);
    let response = FetchResponse::decode(&mut cursor, 16).unwrap();
    assert_eq!(response.responses[0].topic_id, stranger);
    assert_eq!(
        response.responses[0].partitions[0].error_code, 100,
        "UNKNOWN_TOPIC_ID"
    );
    assert!(
        !versions(&state, id)
            .await
            .contains_key("kafka_fetch_request"),
        "the handler was asked"
    );
    state.remove_server(id).await;
}

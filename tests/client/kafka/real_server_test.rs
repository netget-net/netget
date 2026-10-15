//! NetGet's Kafka client against **Apache Kafka 3.9.1**, a real single-node KRaft broker run
//! from the official release in a temp dir of its own — not NetGet's broker.
//!
//! `kcat` seeds a record into `inbox`. NetGet's client polls `inbox` (Fetch v16: the topic by
//! the id Kafka's Metadata v12 reported), and a script handler answers the records it receives
//! by producing `"netget saw: <value>"` to `outbox` (Produce v11) and committing `inbox`'s
//! offset for group `netget-test` (OffsetCommit v9). Then the broker is asked, with tools that
//! are not NetGet:
//!
//! - `kcat` consumes `outbox` and must print the derived record, and
//! - Kafka's own `kafka-consumer-groups.sh` must show the committed offset.
//!
//! That is the client acting on the model's answer, asserted from the broker's side. The
//! versions are read from the client's own events. The broker and kcat are required:
//! `NETGET_KAFKA_PEERS` names the directory `tests/server/kafka/install_peers.py` filled.

use crate::helpers::real_server::{InstallHint, RealServer};
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

const KAFKA: InstallHint = InstallHint {
    brew: "kafka",
    apt:
        "(no package; python3 tests/server/kafka/install_peers.py <dir> fetches Apache Kafka 3.9.1)",
};

fn home() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("NETGET_KAFKA_PEERS").expect(
        "NETGET_KAFKA_PEERS is required: run python3 tests/server/kafka/install_peers.py <dir>",
    ))
    .join("kafka_2.13-3.9.1")
}

async fn kafka() -> RealServer {
    let conf = "process.roles=broker,controller
node.id=1
controller.quorum.voters=1@127.0.0.1:{port1}
listeners=PLAINTEXT://127.0.0.1:{port},CONTROLLER://127.0.0.1:{port1}
advertised.listeners=PLAINTEXT://127.0.0.1:{port}
controller.listener.names=CONTROLLER
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
log.dirs={dir}/data
num.partitions=1
offsets.topic.replication.factor=1
offsets.topic.num.partitions=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
group.initial.rebalance.delay.ms=0
";
    let bin = home().join("bin");
    RealServer::builder(bin.join("kafka-server-start.sh").to_str().unwrap(), KAFKA)
        .config_file("server.properties", conf)
        .extra_ports(1)
        .env("KAFKA_HEAP_OPTS", "-Xmx512M -Xms256M")
        .setup_command(
            bin.join("kafka-storage.sh").to_str().unwrap(),
            KAFKA,
            [
                "format",
                "-t",
                "MkU3OEVBNTcwNTJENDM2Qg",
                "-c",
                "{dir}/server.properties",
            ],
        )
        .args(["{dir}/server.properties"])
        .ready_when_log_matches("Kafka Server started")
        .startup_timeout(Duration::from_secs(90))
        .start()
        .await
        .unwrap_or_else(|e| panic!("Apache Kafka: {e}"))
}

async fn kcat(args: &[&str], stdin: Option<&str>) -> String {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("kcat")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("kcat is required (apt install kcat / brew install kcat)");
    let mut input = child.stdin.take().unwrap();
    if let Some(s) = stdin {
        input.write_all(s.as_bytes()).await.unwrap();
    }
    drop(input);
    let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .expect("kcat did not finish")
        .unwrap();
    assert!(
        out.status.success(),
        "kcat {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Kafka's own consumer-groups tool, which also makes the broker create its offsets topic.
async fn consumer_groups(broker: &str) -> String {
    let out = tokio::time::timeout(
        Duration::from_secs(90),
        tokio::process::Command::new(home().join("bin/kafka-consumer-groups.sh"))
            .args([
                "--bootstrap-server",
                broker,
                "--describe",
                "--group",
                "netget-test",
            ])
            .env("KAFKA_HEAP_OPTS", "-Xmx256M")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("kafka-consumer-groups.sh did not finish")
    .expect("kafka-consumer-groups.sh could not run");
    String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr)
}

const RELAY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='kafka_records_received' and e['topic']=='inbox':
  for r in e['records']:
    a.append({'type':'produce_message','topic':'outbox','partition':0,'key':'relay','value':'netget saw: '+r['value']})
  a.append({'type':'commit_offset','topic':'inbox','partition':0,'offset':e['next_offset'],'group_id':'netget-test'})
print(json.dumps({'actions':a}))"#;

async fn events(state: &AppState, id: ClientId, kind: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .into_iter()
        .filter(|e| e.event_type == kind)
        .map(|e| e.request)
        .collect()
}

#[tokio::test]
async fn netget_consumes_relays_and_commits_on_apache_kafka() {
    let broker = kafka().await;
    let addr = broker.addr();
    kcat(
        &["-b", &addr, "-t", "inbox", "-P", "-K", ":"],
        Some("seed:ping from kcat\n"),
    )
    .await;
    // Kafka creates a topic on a Metadata request, never on a Produce: ask for `outbox` so
    // the relay has somewhere to write.
    kcat(&["-b", &addr, "-L", "-t", "outbox"], None).await;
    // Creates the offsets topic, so the commit below has a coordinator to land on.
    consumer_groups(&addr).await;

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "kafka".into(),
        remote_addr: Some(addr.clone()),
        instruction: Some(String::new()),
        startup_params: Some(json!({"topics": ["inbox"], "start_offset": 0, "poll_interval_ms": 200})),
        event_handlers: Some(vec![json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":RELAY}})]),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .unwrap_or_else(|e| panic!("the Kafka client could not start: {e:#}"));

    let delivered = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let d = events(&state, id, "kafka_message_delivered").await;
            if !d.is_empty() {
                break d;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no delivery\n{}", broker.log()));
    assert_eq!(delivered[0]["delivered"], true, "{}", delivered[0]);
    assert_eq!(
        delivered[0]["api_version"], 11,
        "Produce version: {}",
        delivered[0]
    );
    let received = events(&state, id, "kafka_records_received").await;
    assert_eq!(
        received[0]["records"][0]["value"], "ping from kcat",
        "{}",
        received[0]
    );
    assert_eq!(
        received[0]["api_version"], 16,
        "Fetch version: {}",
        received[0]
    );

    // What the broker now holds, read by tools that are not NetGet.
    let relayed = kcat(
        &[
            "-b",
            &addr,
            "-t",
            "outbox",
            "-C",
            "-e",
            "-o",
            "beginning",
            "-f",
            "%k=%s\n",
        ],
        None,
    )
    .await;
    assert_eq!(relayed.trim(), "relay=netget saw: ping from kcat");
    let mut groups = String::new();
    for _ in 0..20 {
        groups = consumer_groups(&addr).await;
        if groups.lines().any(|l| {
            l.split_whitespace().take(4).collect::<Vec<_>>() == ["netget-test", "inbox", "0", "1"]
        }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        groups.lines().any(|l| {
            l.split_whitespace().take(4).collect::<Vec<_>>() == ["netget-test", "inbox", "0", "1"]
        }),
        "the commit never reached the broker:\n{groups}"
    );
    state.remove_client(id).await;
}

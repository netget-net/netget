//! Three NetGet Redis servers, each started with the same `cluster_nodes` topology, form a fake
//! Redis Cluster — and three cluster clients that share no code with NetGet navigate it:
//!
//! * **`redis-cli -c`** (the C client) follows `-MOVED` from whichever node it reached first;
//! * **`redis-cli --cluster check`** reads every node's `CLUSTER NODES` and checks that the
//!   nodes agree and all 16384 slots are covered;
//! * **redis-rs's `ClusterClient`** (`cluster-async`) reads `CLUSTER SLOTS`, routes each key to
//!   the node that owns its slot, and — after the model moves a slot — follows the `MOVED` its
//!   stale map earns and refreshes.
//!
//! Every reply a node's handler writes names the node, so "the right node answered" is read
//! off the value itself. The model's side runs through the real executor: slots move and
//! migrate by `redis_cluster_set_slot`, dispatched exactly as a model's async action is.
//!
//! No LLM calls: a python handler per node plays the model. redis-cli is required; the test
//! fails rather than skips without it.

use netget::cli::management::ServerForm;
use netget::client::redis::resp::{encode_command, read_reply};
use netget::state::app_state::AppState;
use netget::state::ServerId;
use netget::utils::redis_keys::key_hash_slot;
use serde_json::{json, Value};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Each node answers a read with a value naming itself.
fn handler(port: u16) -> String {
    format!(
        r#"import json,sys
i=json.load(sys.stdin); e=i['event']; c=e.get('command','').split(' '); n=c[0].upper()
if n=='GET':
  a=[{{'type':'redis_bulk_string','value':'value of '+c[1]+' from {port}'}}]
elif n=='DBSIZE':
  a=[{{'type':'redis_integer','value':0}}]
elif n=='INFO':
  a=[{{'type':'redis_bulk_string','value':'# Server\r\nredis_version:7.4.0\r\n# Cluster\r\ncluster_enabled:1\r\n'}}]
else:
  a=[{{'type':'redis_simple_string','value':'OK'}}]
print(json.dumps({{'actions':a}}))"#
    )
}

fn topology(ports: [u16; 3], me: usize) -> Value {
    let ranges = ["0-5460", "5461-10922", "10923-16383"];
    Value::Array(
        (0..3)
            .map(|i| {
                json!({
                    "host": "127.0.0.1",
                    "port": ports[i],
                    "slots": [ranges[i]],
                    "myself": i == me,
                })
            })
            .collect(),
    )
}

/// Three free loopback ports. Probed, then released for the servers to bind: the same narrow
/// race `tests/helpers/real_server.rs` documents, and a bind failure fails the test loudly.
async fn free_ports() -> [u16; 3] {
    let mut ports = [0u16; 3];
    let mut held = Vec::new();
    for p in &mut ports {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        *p = l.local_addr().unwrap().port();
        held.push(l);
    }
    ports
}

async fn cluster() -> (AppState, [ServerId; 3], [u16; 3]) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let ports = free_ports().await;
    let mut ids = Vec::new();
    for (i, port) in ports.iter().enumerate() {
        let (tx, _) = mpsc::unbounded_channel();
        let id = ServerForm {
            protocol: "redis".into(),
            port: Some(*port),
            host: Some("127.0.0.1".into()),
            instruction: Some("Cluster node".into()),
            startup_params: Some(json!({"cluster_nodes": topology(ports, i)})),
            event_handlers: Some(vec![json!({
                "event_pattern":"*",
                "handler":{"type":"script","language":"python","code":handler(*port)}
            })]),
            ..Default::default()
        }
        .create(&state, tx)
        .await
        .expect("cluster node");
        ids.push(id);
    }
    for id in &ids {
        for _ in 0..1500 {
            if state
                .get_server(*id)
                .await
                .and_then(|s| s.local_addr)
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    (state, [ids[0], ids[1], ids[2]], ports)
}

async fn cli(port: u16, args: &[&str]) -> String {
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new("redis-cli")
            .args(["-h", "127.0.0.1", "-p", &port.to_string()])
            .args(args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("redis-cli did not finish")
    .expect("redis-cli is required: apt install redis-tools / brew install valkey");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .trim_end()
    .to_string()
}

/// One raw connection, commands in order, every reply's JSON value.
async fn raw(port: u16, commands: &[&[&str]]) -> Vec<Value> {
    let (r, mut w) = TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap()
        .into_split();
    let mut reader = BufReader::new(r);
    let mut replies = Vec::new();
    for c in commands {
        let args: Vec<Vec<u8>> = c.iter().map(|a| a.as_bytes().to_vec()).collect();
        w.write_all(&encode_command(&args)).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(30), read_reply(&mut reader))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        replies.push(reply.value);
    }
    replies
}

async fn set_slot(state: &AppState, id: ServerId, action: Value) {
    let registry = netget::protocol::server_registry::registry();
    let protocol = registry.resolve("redis").unwrap();
    let result = netget::llm::actions::executor::execute_actions(
        vec![action],
        state,
        Some(protocol.as_ref()),
        Some(id),
        None,
    )
    .await
    .unwrap();
    assert!(result.failures.is_empty(), "{:?}", result.failures);
}

#[tokio::test]
async fn real_cluster_clients_navigate_three_netget_nodes() {
    let (state, ids, ports) = cluster().await;
    let [a, b, c] = ports;
    let foo_slot = key_hash_slot(b"foo"); // 12182, owned by c
    let bar_slot = key_hash_slot(b"bar"); // 5061, owned by a

    // The introspection a client starts from.
    assert_eq!(cli(a, &["CLUSTER", "KEYSLOT", "foo"]).await, "12182");
    let info = cli(b, &["CLUSTER", "INFO"]).await;
    assert!(info.contains("cluster_state:ok"), "{info}");
    assert!(info.contains("cluster_known_nodes:3"), "{info}");
    let nodes = cli(a, &["CLUSTER", "NODES"]).await;
    assert_eq!(nodes.lines().count(), 3, "{nodes}");
    assert!(
        nodes.contains(&format!(
            "127.0.0.1:{a}@{} myself,master",
            u32::from(a) + 10000
        )),
        "{nodes}"
    );

    // Without -c a node only says where the key lives; with -c redis-cli goes there.
    let moved = cli(a, &["GET", "foo"]).await;
    assert!(
        moved.contains(&format!("MOVED {foo_slot} 127.0.0.1:{c}")),
        "{moved}"
    );
    assert_eq!(
        cli(a, &["-c", "GET", "foo"]).await,
        format!("value of foo from {c}")
    );
    assert_eq!(
        cli(c, &["-c", "GET", "{user1000}.following"]).await,
        format!(
            "value of {{user1000}}.following from {}",
            owner_port(ports, b"{user1000}.following")
        )
    );
    let cross = cli(a, &["MGET", "foo", "bar"]).await;
    assert!(
        cross.contains("CROSSSLOT Keys in request don't hash to the same slot"),
        "{cross}"
    );

    // redis-cli's own cluster checker: consistent views, full coverage.
    let check = cli(a, &["--cluster", "check", &format!("127.0.0.1:{a}")]).await;
    assert!(
        check.contains("[OK] All nodes agree about slots configuration."),
        "{check}"
    );
    assert!(check.contains("[OK] All 16384 slots covered."), "{check}");

    // redis-rs's cluster client: CLUSTER SLOTS, then each key straight to its owner.
    let client =
        redis::cluster::ClusterClient::new(vec![format!("redis://127.0.0.1:{a}/")]).unwrap();
    let mut conn = client
        .get_async_connection()
        .await
        .expect("cluster connection");
    for key in ["foo", "bar", "hello", "{user1000}.followers", "zebra"] {
        let value: String = redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(
            value,
            format!("value of {key} from {}", owner_port(ports, key.as_bytes()))
        );
    }
    let ok: String = redis::cmd("SET")
        .arg("foo")
        .arg("x")
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(ok, "OK");

    // The model moves foo's slot from c to b, on every node. Both clients now hold a stale
    // map; each is sent to c, told MOVED, and must end up at b.
    for id in ids {
        set_slot(
            &state,
            id,
            json!({"type":"redis_cluster_set_slot","slots": foo_slot.to_string(),
                   "state":"node","node": format!("127.0.0.1:{b}")}),
        )
        .await;
    }
    let value: String = redis::cmd("GET")
        .arg("foo")
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(value, format!("value of foo from {b}"));
    assert_eq!(
        cli(a, &["-c", "GET", "foo"]).await,
        format!("value of foo from {b}")
    );

    // The model migrates bar's slot from a to b: a answers ASK, b serves it only after ASKING.
    set_slot(
        &state,
        ids[0],
        json!({"type":"redis_cluster_set_slot","slots": bar_slot.to_string(),
               "state":"migrating","node": format!("127.0.0.1:{b}")}),
    )
    .await;
    set_slot(
        &state,
        ids[1],
        json!({"type":"redis_cluster_set_slot","slots": bar_slot.to_string(),
               "state":"importing","node": format!("127.0.0.1:{a}")}),
    )
    .await;
    assert_eq!(
        raw(a, &[&["GET", "bar"]]).await,
        vec![json!({"error": format!("ASK {bar_slot} 127.0.0.1:{b}")})]
    );
    assert_eq!(
        raw(
            b,
            &[
                &["GET", "bar"],
                &["ASKING"],
                &["GET", "bar"],
                &["GET", "bar"]
            ]
        )
        .await,
        vec![
            json!({"error": format!("MOVED {bar_slot} 127.0.0.1:{a}")}),
            json!("OK"),
            json!(format!("value of bar from {b}")),
            // ASKING holds for one command only.
            json!({"error": format!("MOVED {bar_slot} 127.0.0.1:{a}")}),
        ]
    );
    assert_eq!(
        cli(a, &["-c", "GET", "bar"]).await,
        format!("value of bar from {b}")
    );
    let nodes = cli(a, &["CLUSTER", "NODES"]).await;
    assert!(nodes.contains(&format!("[{bar_slot}->-")), "{nodes}");
}

/// The port of the node the topology assigns `key`'s slot to.
fn owner_port(ports: [u16; 3], key: &[u8]) -> u16 {
    match key_hash_slot(key) {
        0..=5460 => ports[0],
        5461..=10922 => ports[1],
        _ => ports[2],
    }
}

#[tokio::test]
async fn a_bad_topology_refuses_to_start() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    for nodes in [
        json!([{"host":"127.0.0.1","port":7000,"slots":["0-100"]}]),
        json!([{"myself":true,"slots":["0-100"]},{"host":"127.0.0.1","port":7001,"slots":["50-60"]}]),
        json!([{"myself":true,"slots":["0-16384"]}]),
        json!([{"myself":true,"host":"bad host\r\n","slots":["0-1"]}]),
    ] {
        let (tx, _) = mpsc::unbounded_channel();
        let id = ServerForm {
            protocol: "redis".into(),
            port: Some(0),
            host: Some("127.0.0.1".into()),
            startup_params: Some(json!({ "cluster_nodes": nodes })),
            ..Default::default()
        }
        .create(&state, tx)
        .await;
        let failed = match id {
            Err(_) => true,
            Ok(id) => {
                let mut status = None;
                for _ in 0..500 {
                    status = state
                        .get_server(id)
                        .await
                        .map(|s| format!("{:?}", s.status));
                    if status.as_deref().is_some_and(|s| s.contains("Error")) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                status.is_some_and(|s| s.contains("Error"))
            }
        };
        assert!(failed, "topology {nodes} should have refused to start");
    }
}

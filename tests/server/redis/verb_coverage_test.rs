//! The verbs Rust answers itself that `pubsub_test.rs` and `cluster_test.rs` leave to raw
//! sockets, each driven by two independent clients.
//!
//! Counting what the suite's clients send against what the server implements: `SUBSCRIBE`,
//! `PSUBSCRIBE`, `PUBLISH`, `PUBSUB NUMSUB|NUMPAT|CHANNELS`, `HELLO` and cluster
//! `MOVED`/`ASK`/`SLOTS`/`NODES` already had redis-cli and redis-rs. Sharded pub/sub
//! (`SSUBSCRIBE`, `SPUBLISH`, `SUNSUBSCRIBE`, `PUBSUB SHARDCHANNELS|SHARDNUMSUB`), `UNSUBSCRIBE`
//! and `PUNSUBSCRIBE`, `RESET`, subscribed-mode `PING`, and cluster `KEYSLOT`, `MYID`,
//! `SHARDS`, `INFO`, `-CROSSSLOT` and `-CLUSTERDOWN` were asserted only from raw sockets in this
//! repository's own RESP reader. Here:
//!
//! | verb | redis-cli | redis-rs | redis-py |
//! |---|---|---|---|
//! | `SSUBSCRIBE` / `SPUBLISH` / `smessage` | yes | yes (RESP3 push) | yes |
//! | `SUNSUBSCRIBE` | — | yes | yes |
//! | `PUBSUB SHARDCHANNELS` / `SHARDNUMSUB` | yes | yes | — |
//! | `UNSUBSCRIBE` / `PUNSUBSCRIBE` | — | yes | yes |
//! | `RESET` | yes | yes | yes |
//! | subscribed-mode `PING` | — | — | yes |
//! | `CLUSTER KEYSLOT` / `MYID` / `SHARDS` / `INFO` | yes | yes | — |
//! | `-CROSSSLOT` / `-CLUSTERDOWN` | yes | yes | — |
//!
//! redis-cli cannot unsubscribe (a subscribing redis-cli reads messages until it is killed) and
//! redis-rs 0.27's `PubSub` has no `ping`, so those rows rest on redis-py and the other client,
//! plus the exact shapes in `pubsub_bounds_test.rs` and `pcap_oracle_test.rs`.
//!
//! redis-cli and redis-py 5 (`NETGET_REDIS_PYTHON`, default `python3`) are required; the tests
//! fail rather than skip without them. No LLM calls: `pubsub_test.rs`'s python handler accepts
//! every subscription and delivers every publish.

use super::pubsub_test::{cli, pubsub_server, Cli, HANDLER};
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::utils::redis_keys::key_hash_slot;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

/// The next RESP3 push of `kind`, skipping any other.
async fn push_of(
    rx: &mut mpsc::UnboundedReceiver<redis::PushInfo>,
    kind: redis::PushKind,
) -> Vec<String> {
    let push = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let push = rx.recv().await.expect("push channel closed");
            if push.kind == kind {
                break push;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {kind:?} push within 20s"));
    push.data
        .iter()
        .map(|v| redis::from_redis_value(v).unwrap())
        .collect()
}

#[tokio::test]
async fn sharded_pubsub_unsubscribe_and_reset_through_redis_cli_and_redis_rs() {
    let (_state, port) = pubsub_server(HANDLER).await;

    // redis-cli: a sharded subscriber, introspected and published to by redis-cli.
    let sub = Cli::spawn(port, &["SSUBSCRIBE", "orders"]);
    sub.wait_for_line("ssubscribe", 20).await;
    let mut shard_channels = Vec::new();
    for _ in 0..200 {
        shard_channels = cli(port, &["PUBSUB", "SHARDCHANNELS"]).await;
        if shard_channels == ["orders"] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(shard_channels, ["orders"]);
    assert_eq!(
        cli(port, &["PUBSUB", "SHARDNUMSUB", "orders"]).await,
        ["orders", "1"]
    );
    assert_eq!(
        cli(port, &["SPUBLISH", "orders", "from redis-cli"]).await,
        ["1"]
    );
    sub.wait_for_line("from redis-cli", 20).await;
    let lines = sub.lines();
    let at = lines
        .iter()
        .position(|l| l == "smessage")
        .unwrap_or_else(|| {
            panic!(
                "no smessage frame; redis-cli printed:\n{}",
                lines.join("\n")
            )
        });
    assert_eq!(&lines[at..at + 3], ["smessage", "orders", "from redis-cli"]);
    assert_eq!(cli(port, &["RESET"]).await, ["RESET"]);

    // redis-rs, RESP3: a sharded subscription on a multiplexed connection, its confirmation and
    // messages as pushes; SPUBLISH from a second connection; SUNSUBSCRIBE.
    let url = format!("redis://127.0.0.1:{port}/");
    let client3 = redis::Client::open(format!("{url}?protocol=resp3").as_str()).unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let config = redis::AsyncConnectionConfig::new().set_push_sender(tx);
    let mut con = client3
        .get_multiplexed_async_connection_with_config(&config)
        .await
        .expect("resp3 connection");
    redis::cmd("SSUBSCRIBE")
        .arg("rs.orders")
        .exec_async(&mut con)
        .await
        .expect("SSUBSCRIBE");
    assert_eq!(
        push_of(&mut rx, redis::PushKind::SSubscribe).await,
        ["rs.orders", "1"]
    );
    let client = redis::Client::open(url.as_str()).unwrap();
    let mut plain = client.get_multiplexed_async_connection().await.unwrap();
    let mut shard_channels: Vec<String> = redis::cmd("PUBSUB")
        .arg("SHARDCHANNELS")
        .query_async(&mut plain)
        .await
        .unwrap();
    shard_channels.sort();
    // The redis-cli subscriber above still holds `orders`.
    assert_eq!(shard_channels, ["orders", "rs.orders"]);
    let numsub: Vec<String> = redis::cmd("PUBSUB")
        .arg("SHARDNUMSUB")
        .arg("rs.orders")
        .query_async(&mut plain)
        .await
        .unwrap();
    assert_eq!(numsub, ["rs.orders", "1"]);
    let delivered: i64 = redis::cmd("SPUBLISH")
        .arg("rs.orders")
        .arg("from redis-rs")
        .query_async(&mut plain)
        .await
        .unwrap();
    assert_eq!(delivered, 1);
    assert_eq!(
        push_of(&mut rx, redis::PushKind::SMessage).await,
        ["rs.orders", "from redis-rs"]
    );
    redis::cmd("SUNSUBSCRIBE")
        .arg("rs.orders")
        .exec_async(&mut con)
        .await
        .expect("SUNSUBSCRIBE");
    assert_eq!(
        push_of(&mut rx, redis::PushKind::SUnsubscribe).await,
        ["rs.orders", "0"]
    );

    // redis-rs, RESP2: UNSUBSCRIBE and PUNSUBSCRIBE on the dedicated PubSub connection, each
    // checked from the server's own count.
    let mut pubsub = client.get_async_pubsub().await.expect("pubsub connection");
    pubsub.subscribe("rs.u").await.expect("subscribe");
    pubsub.psubscribe("rs.p.*").await.expect("psubscribe");
    let numsub: Vec<String> = redis::cmd("PUBSUB")
        .arg("NUMSUB")
        .arg("rs.u")
        .query_async(&mut plain)
        .await
        .unwrap();
    assert_eq!(numsub, ["rs.u", "1"]);
    pubsub.unsubscribe("rs.u").await.expect("unsubscribe");
    pubsub.punsubscribe("rs.p.*").await.expect("punsubscribe");
    let numsub: Vec<String> = redis::cmd("PUBSUB")
        .arg("NUMSUB")
        .arg("rs.u")
        .query_async(&mut plain)
        .await
        .unwrap();
    assert_eq!(
        numsub,
        ["rs.u", "0"],
        "UNSUBSCRIBE left the subscription registered"
    );
    let numpat: i64 = redis::cmd("PUBSUB")
        .arg("NUMPAT")
        .query_async(&mut plain)
        .await
        .unwrap();
    assert_eq!(numpat, 0, "PUNSUBSCRIBE left the pattern registered");

    let reset: String = redis::cmd("RESET").query_async(&mut plain).await.unwrap();
    assert_eq!(reset, "RESET");
}

/// redis-py's own pub/sub state machine: it tracks what it holds from the confirmations it
/// reads, so a wrong count or a wrong frame type surfaces as a wrong message here.
const REDIS_PY_PUBSUB: &str = r#"import json,sys,redis
port=int(sys.argv[1])
r=redis.Redis(host='127.0.0.1',port=port,decode_responses=True,socket_timeout=20)
p=r.pubsub()
seen=[]
def take(n):
    for _ in range(n):
        m=None
        for _ in range(200):
            m=p.get_message(timeout=0.1)
            if m: break
        seen.append(None if m is None else [m['type'],m['channel'],m['data']])
p.subscribe('py.news'); take(1)
p.psubscribe('py.alerts.*'); take(1)
p.ping(); take(1)
r.publish('py.news','hello py'); take(1)
p.unsubscribe('py.news'); take(1)
p.punsubscribe('py.alerts.*'); take(1)
p.ssubscribe('py.orders'); take(1)
r.spublish('py.orders','sharded py'); take(1)
p.sunsubscribe('py.orders'); take(1)
out={'seen':seen,'numsub':r.pubsub_numsub('py.news'),'numpat':r.pubsub_numpat(),'reset':r.execute_command('RESET')}
print(json.dumps(out))"#;

#[tokio::test]
async fn redis_py_unsubscribes_pings_while_subscribed_and_uses_sharded_pubsub() {
    let python = std::env::var("NETGET_REDIS_PYTHON").unwrap_or_else(|_| "python3".into());
    let probe = std::process::Command::new(&python)
        .args([
            "-c",
            "import redis,sys; sys.exit(0 if int(redis.__version__.split('.')[0])>=5 else 1)",
        ])
        .output();
    assert!(
        probe.is_ok_and(|o| o.status.success()),
        "{python} with redis-py 5 is required: pip install 'redis>=5,<6' (or set NETGET_REDIS_PYTHON)"
    );
    let (_state, port) = pubsub_server(HANDLER).await;
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(&python)
            .args(["-c", REDIS_PY_PUBSUB, &port.to_string()])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("redis-py did not finish")
    .unwrap();
    assert!(
        out.status.success(),
        "redis-py failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        r["seen"],
        json!([
            ["subscribe", "py.news", 1],
            ["psubscribe", "py.alerts.*", 2],
            // Subscribed-mode PING is `["pong", ""]`, which redis-py reads as a pong message.
            ["pong", null, ""],
            ["message", "py.news", "hello py"],
            ["unsubscribe", "py.news", 1],
            ["punsubscribe", "py.alerts.*", 0],
            ["ssubscribe", "py.orders", 1],
            ["smessage", "py.orders", "sharded py"],
            ["sunsubscribe", "py.orders", 0]
        ]),
        "{r}"
    );
    assert_eq!(r["numsub"], json!([["py.news", 0]]), "{r}");
    assert_eq!(r["numpat"], 0, "{r}");
    assert_eq!(r["reset"], "RESET", "{r}");
}

/// A cluster node serving slots 0-15000, a second node owning 15001-16000, and 16001-16383
/// owned by nobody.
async fn cluster_node() -> (AppState, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let topology = json!([
        {"host": "127.0.0.1", "slots": ["0-15000"], "myself": true},
        {"host": "127.0.0.1", "port": 7001, "slots": ["15001-16000"]}
    ]);
    let id = ServerForm {
        protocol: "redis".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Cluster node".into()),
        startup_params: Some(json!({ "cluster_nodes": topology })),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":HANDLER}}),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create cluster node");
    let port = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the cluster node never bound");
    (state, port)
}

/// The first `k<n>` whose slot satisfies `want`.
fn key_where(want: impl Fn(u16) -> bool) -> String {
    (0..100_000)
        .map(|n| format!("k{n}"))
        .find(|k| want(key_hash_slot(k.as_bytes())))
        .expect("a key in the wanted slot range")
}

/// One redis-cli command, stdout and stderr together: an error reply is not a failed run.
async fn cli_any(port: u16, args: &[&str]) -> String {
    let out = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new("redis-cli")
            .args(["-h", "127.0.0.1", "-p", &port.to_string()])
            .args(args)
            .stdin(std::process::Stdio::null())
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
}

#[tokio::test]
async fn cluster_introspection_and_refusals_through_redis_cli_and_redis_rs() {
    let (_state, port) = cluster_node().await;
    let local_a = key_where(|s| s <= 15000);
    let local_b = key_where(|s| s <= 15000 && s != key_hash_slot(local_a.as_bytes()));
    let unowned = key_where(|s| s > 16000);
    let slot_a = key_hash_slot(local_a.as_bytes()).to_string();

    // redis-cli, without -c: it prints what the node said rather than following it.
    assert_eq!(
        cli(port, &["CLUSTER", "KEYSLOT", &local_a]).await,
        [slot_a.as_str()]
    );
    let myid = cli(port, &["CLUSTER", "MYID"]).await;
    assert!(
        myid.len() == 1 && myid[0].len() == 40,
        "CLUSTER MYID: {myid:?}"
    );
    let info = cli(port, &["CLUSTER", "INFO"]).await;
    assert!(
        info.iter().any(|l| l == "cluster_state:fail")
            && info.iter().any(|l| l == "cluster_slots_assigned:16001"),
        "a cluster with unowned slots is not ok: {info:?}"
    );
    let shards = cli(port, &["CLUSTER", "SHARDS"]).await;
    assert!(
        shards.iter().any(|l| l == "slots") && shards.iter().any(|l| l == &myid[0]),
        "CLUSTER SHARDS names this node's slots and id: {shards:?}"
    );
    let crossslot = cli_any(port, &["MSET", &local_a, "1", &local_b, "2"]).await;
    assert!(
        crossslot.contains("CROSSSLOT"),
        "two keys in different slots: {crossslot:?}"
    );
    let down = cli_any(port, &["GET", &unowned]).await;
    assert!(
        down.contains("CLUSTERDOWN"),
        "a key in an unowned slot: {down:?}"
    );

    // redis-rs, on a plain (not cluster-aware) connection, so each reply is the node's own.
    let client = redis::Client::open(format!("redis://127.0.0.1:{port}/").as_str()).unwrap();
    let mut con = client.get_multiplexed_async_connection().await.unwrap();
    let slot: i64 = redis::cmd("CLUSTER")
        .arg("KEYSLOT")
        .arg(&local_a)
        .query_async(&mut con)
        .await
        .unwrap();
    assert_eq!(slot.to_string(), slot_a);
    let id: String = redis::cmd("CLUSTER")
        .arg("MYID")
        .query_async(&mut con)
        .await
        .unwrap();
    assert_eq!(id, myid[0]);
    let info: String = redis::cmd("CLUSTER")
        .arg("INFO")
        .query_async(&mut con)
        .await
        .unwrap();
    assert!(info.contains("cluster_known_nodes:2"), "{info}");
    let shards: Vec<redis::Value> = redis::cmd("CLUSTER")
        .arg("SHARDS")
        .query_async(&mut con)
        .await
        .unwrap();
    assert_eq!(shards.len(), 2, "one shard per master: {shards:?}");
    let err = redis::cmd("MSET")
        .arg(&local_a)
        .arg(1)
        .arg(&local_b)
        .arg(2)
        .query_async::<()>(&mut con)
        .await
        .expect_err("CROSSSLOT");
    assert_eq!(err.code(), Some("CROSSSLOT"), "{err:?}");
    let err = redis::cmd("GET")
        .arg(&unowned)
        .query_async::<Option<String>>(&mut con)
        .await
        .expect_err("CLUSTERDOWN");
    assert_eq!(err.code(), Some("CLUSTERDOWN"), "{err:?}");
}

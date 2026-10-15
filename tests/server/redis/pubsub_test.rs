//! Pub/sub against two clients that implement it independently: **redis-cli** (the C client;
//! `valkey-cli` on Homebrew) in RESP2 and with `-3`, and **redis-rs** — its RESP2 `PubSub`
//! connection and its RESP3 multiplexed connection with a push sender.
//!
//! What is proved, each from a real subscriber's side of the wire:
//!
//! * a message one real client publishes reaches another real client subscribed to the
//!   channel, and one subscribed to a matching pattern (`pmessage`, with the pattern);
//! * a message the **model** publishes (`redis_publish_message`, answering a command) reaches a
//!   real subscriber;
//! * the model's policy holds: a refused subscription is refused to redis-rs, a withheld
//!   publish is answered with the model's own count and never delivered;
//! * the PUBLISH reply is the number of deliveries, counted as Redis counts them.
//!
//! No LLM calls: a python handler plays the model, deciding policy from the event it is given.
//! redis-cli is required; the tests fail rather than skip without it.

use futures::StreamExt;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use serde_json::json;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

/// The model, as a script. Policy: a channel starting `forbidden` is refused with NOPERM; a
/// publish to `withheld` is answered 42 and not delivered; everything else is allowed.
/// `NG.ANNOUNCE <channel> <message>` makes the model publish a message of its own.
pub const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='redis_subscribe':
  if any(c.startswith('forbidden') for c in e['channels']):
    a=[{'type':'redis_error','message':'NOPERM this user has no permissions to access one of the channels used as arguments'}]
  else:
    a=[{'type':'redis_accept_subscription'}]
elif t=='redis_publish':
  if e['channel']=='withheld':
    a=[{'type':'redis_integer','value':42}]
  else:
    a=[{'type':'redis_deliver_message'}]
else:
  c=e['command'].split(' ')
  n=c[0].upper()
  if n=='NG.ANNOUNCE':
    a=[{'type':'redis_publish_message','channel':c[1],'message':' '.join(c[2:])},{'type':'redis_simple_string','value':'OK'}]
  elif n=='PING':
    a=[{'type':'redis_simple_string','value':'PONG'}]
  else:
    a=[{'type':'redis_simple_string','value':'OK'}]
print(json.dumps({'actions':a}))"#;

pub async fn pubsub_server(handler: &str) -> (AppState, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "redis".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Answer pub/sub test commands".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":handler}}),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the Redis server never bound");
    (state, port)
}

/// A long-running `redis-cli` (a subscriber), every line it prints collected as it prints it.
pub struct Cli {
    child: tokio::process::Child,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Cli {
    pub fn spawn(port: u16, args: &[&str]) -> Cli {
        let mut child = tokio::process::Command::new("redis-cli")
            .args(["-h", "127.0.0.1", "-p", &port.to_string()])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("redis-cli is required: apt install redis-tools / brew install valkey");
        let lines = Arc::new(Mutex::new(Vec::new()));
        let stdout = child.stdout.take().unwrap();
        let sink = lines.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                sink.lock().unwrap().push(line);
            }
        });
        Cli { child, lines }
    }

    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }

    /// Wait until the printed lines contain `needle` as a whole line.
    pub async fn wait_for_line(&self, needle: &str, secs: u64) {
        self.wait_until(|l| l == needle, needle, secs).await
    }

    /// Wait until some printed line contains `needle`.
    pub async fn wait_for_line_containing(&self, needle: &str, secs: u64) {
        self.wait_until(|l| l.contains(needle), needle, secs).await
    }

    async fn wait_until(&self, pred: impl Fn(&str) -> bool, needle: &str, secs: u64) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        while tokio::time::Instant::now() < deadline {
            if self.lines().iter().any(|l| pred(l)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!(
            "redis-cli never printed {needle:?}; it printed:\n{}",
            self.lines().join("\n")
        );
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// One `redis-cli` command, raw output (it is not a tty), trimmed lines.
pub async fn cli(port: u16, args: &[&str]) -> Vec<String> {
    let out = tokio::time::timeout(
        Duration::from_secs(30),
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
    assert!(
        out.status.success(),
        "redis-cli {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim_end().to_string())
        .collect()
}

/// Poll `PUBSUB NUMSUB <channel>` until it reports `n` subscribers.
pub async fn wait_numsub(port: u16, channel: &str, n: usize) {
    let want = n.to_string();
    for _ in 0..600 {
        let out = cli(port, &["PUBSUB", "NUMSUB", channel]).await;
        if out == vec![channel.to_string(), want.clone()] {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("PUBSUB NUMSUB {channel} never reached {n}");
}

#[tokio::test]
async fn redis_cli_subscribers_receive_what_redis_cli_and_the_model_publish() {
    let (_state, port) = pubsub_server(HANDLER).await;

    // The model refuses this one; redis-cli prints its error and nothing is registered.
    let refused = Cli::spawn(port, &["SUBSCRIBE", "forbidden.room"]);
    refused
        .wait_for_line_containing("NOPERM this user has no permissions", 20)
        .await;
    assert!(
        !refused.lines().iter().any(|l| l == "subscribe"),
        "a refused subscription was confirmed:\n{}",
        refused.lines().join("\n")
    );

    // RESP2 channel subscriber, RESP3 channel subscriber, RESP2 pattern subscriber.
    let resp2 = Cli::spawn(port, &["SUBSCRIBE", "news", "withheld"]);
    let resp3 = Cli::spawn(port, &["-3", "SUBSCRIBE", "news"]);
    let pattern = Cli::spawn(port, &["PSUBSCRIBE", "news*"]);
    wait_numsub(port, "news", 2).await;
    wait_numsub(port, "withheld", 1).await;
    for _ in 0..600 {
        if cli(port, &["PUBSUB", "NUMPAT"]).await == vec!["1".to_string()] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(cli(port, &["PUBSUB", "NUMPAT"]).await, vec!["1"]);
    assert_eq!(
        cli(port, &["PUBSUB", "CHANNELS"]).await,
        vec!["news", "withheld"]
    );
    assert_eq!(cli(port, &["PUBSUB", "CHANNELS", "n*"]).await, vec!["news"]);

    // A real client publishes: two channel subscribers and one pattern subscriber, so three
    // deliveries — the count Redis would answer.
    assert_eq!(
        cli(port, &["PUBLISH", "news", "from redis-cli"]).await,
        vec!["3"]
    );
    resp2.wait_for_line("from redis-cli", 20).await;
    resp3.wait_for_line("from redis-cli", 20).await;
    pattern.wait_for_line("from redis-cli", 20).await;

    // The subscriber's own confirmation came first, then the message, in Redis's shape.
    let lines = resp2.lines();
    let at = lines.iter().position(|l| l == "from redis-cli").unwrap();
    assert_eq!(
        &lines[..3],
        &["subscribe", "news", "1"],
        "first confirmation:\n{}",
        lines.join("\n")
    );
    assert_eq!(&lines[at - 2..=at], &["message", "news", "from redis-cli"]);
    let plines = pattern.lines();
    let at = plines.iter().position(|l| l == "from redis-cli").unwrap();
    assert_eq!(
        &plines[at - 3..=at],
        &["pmessage", "news*", "news", "from redis-cli"],
        "pattern subscriber printed:\n{}",
        plines.join("\n")
    );

    // The model publishes a message of its own while answering a command.
    assert_eq!(
        cli(port, &["NG.ANNOUNCE", "news", "from", "the", "model"]).await,
        vec!["OK"]
    );
    resp2.wait_for_line("from the model", 20).await;
    resp3.wait_for_line("from the model", 20).await;
    pattern.wait_for_line("from the model", 20).await;

    // Withheld by the model: answered with its own count, never delivered. The marker sent
    // after it on the same subscriber proves the withheld one would have arrived first.
    assert_eq!(
        cli(port, &["PUBLISH", "withheld", "secret"]).await,
        vec!["42"]
    );
    assert_eq!(cli(port, &["PUBLISH", "news", "marker"]).await, vec!["3"]);
    resp2.wait_for_line("marker", 20).await;
    assert!(
        !resp2.lines().iter().any(|l| l == "secret"),
        "a publish the model withheld was delivered:\n{}",
        resp2.lines().join("\n")
    );
}

#[tokio::test]
async fn redis_rs_pubsub_on_resp2_and_resp3() {
    let (_state, port) = pubsub_server(HANDLER).await;
    let url = format!("redis://127.0.0.1:{port}/");
    let client = redis::Client::open(url.as_str()).unwrap();

    // RESP2: the dedicated PubSub connection.
    let mut pubsub = client.get_async_pubsub().await.expect("pubsub connection");
    pubsub.subscribe("rs.news").await.expect("subscribe");
    pubsub.psubscribe("rs.alerts.*").await.expect("psubscribe");

    // A refused subscription is not registered. (redis-rs 0.27's PubSub reports an error
    // reply to SUBSCRIBE as success — it maps the reply value away — so the refusal itself is
    // read by redis-cli in the test above.)
    let mut refused = client.get_async_pubsub().await.unwrap();
    let _ = refused.subscribe("forbidden.room").await;
    wait_numsub(port, "forbidden.room", 0).await;

    let mut publisher = client.get_multiplexed_async_connection().await.unwrap();
    let delivered: i64 = redis::cmd("PUBLISH")
        .arg("rs.news")
        .arg("hello rs")
        .query_async(&mut publisher)
        .await
        .unwrap();
    assert_eq!(delivered, 1);
    let delivered: i64 = redis::cmd("PUBLISH")
        .arg("rs.alerts.fire")
        .arg("hot")
        .query_async(&mut publisher)
        .await
        .unwrap();
    assert_eq!(delivered, 1);

    let mut stream = pubsub.on_message();
    let first = tokio::time::timeout(Duration::from_secs(20), stream.next())
        .await
        .expect("no message")
        .expect("stream ended");
    assert_eq!(first.get_channel_name(), "rs.news");
    assert_eq!(first.get_payload::<String>().unwrap(), "hello rs");
    assert!(!first.from_pattern());
    let second = tokio::time::timeout(Duration::from_secs(20), stream.next())
        .await
        .expect("no pattern message")
        .expect("stream ended");
    assert_eq!(second.get_channel_name(), "rs.alerts.fire");
    assert_eq!(second.get_pattern::<String>().unwrap(), "rs.alerts.*");
    assert_eq!(second.get_payload::<String>().unwrap(), "hot");
    drop(stream);

    // RESP3: pushes on a multiplexed connection, which can still run commands while subscribed.
    let client3 = redis::Client::open(format!("{url}?protocol=resp3").as_str()).unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let config = redis::AsyncConnectionConfig::new().set_push_sender(tx);
    let mut con = client3
        .get_multiplexed_async_connection_with_config(&config)
        .await
        .expect("resp3 connection");
    con.subscribe("rs3.news").await.expect("resp3 subscribe");
    let pong: String = redis::cmd("PING").query_async(&mut con).await.unwrap();
    assert_eq!(
        pong, "PONG",
        "RESP3 runs ordinary commands while subscribed"
    );
    let delivered: i64 = redis::cmd("PUBLISH")
        .arg("rs3.news")
        .arg("pushed")
        .query_async(&mut publisher)
        .await
        .unwrap();
    assert_eq!(delivered, 1);
    let message = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let push = rx.recv().await.expect("push channel closed");
            if push.kind == redis::PushKind::Message {
                break push;
            }
        }
    })
    .await
    .expect("no RESP3 push");
    let data: Vec<String> = message
        .data
        .iter()
        .map(|v| redis::from_redis_value(v).unwrap())
        .collect();
    assert_eq!(data, vec!["rs3.news", "pushed"]);
}

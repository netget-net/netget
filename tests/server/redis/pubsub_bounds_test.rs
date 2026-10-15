//! Pub/sub mechanics and every bound the hub declares, driven from raw sockets so each reply
//! is read exactly as the server framed it. Zero LLM calls: static handlers stand in for the
//! model except in the fail-closed test, where the model is deliberately unreachable.
//!
//! Each bound here was checked by mutation — raising or removing it makes its test fail:
//! `MAX_CHANNEL_BYTES`, `MAX_MESSAGE_BYTES`, `MAX_SUBSCRIPTIONS_PER_CONNECTION`,
//! `MAX_PATTERNS_PER_SERVER`, `MAX_SUBSCRIPTIONS_PER_SERVER` and
//! `SUBSCRIBER_OUTPUT_LIMIT_BYTES` (the slow-consumer disconnect).

use netget::cli::management::ServerForm;
use netget::client::redis::resp::{encode_command, read_reply, Reply};
use netget::server::redis::pubsub::{
    MAX_CHANNEL_BYTES, MAX_MESSAGE_BYTES, MAX_PATTERNS_PER_SERVER,
    MAX_SUBSCRIPTIONS_PER_CONNECTION, MAX_SUBSCRIPTIONS_PER_SERVER,
};
use netget::state::app_state::AppState;
use netget::state::ServerId;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `redis_subscribe` accepted, `redis_publish` delivered, every command answered OK.
fn allowing_handlers() -> Vec<Value> {
    vec![
        json!({"event_pattern":"redis_subscribe","handler":{"type":"static","actions":[{"type":"redis_accept_subscription"}]}}),
        json!({"event_pattern":"redis_publish","handler":{"type":"static","actions":[{"type":"redis_deliver_message"}]}}),
        json!({"event_pattern":"redis_command","handler":{"type":"static","actions":[{"type":"redis_simple_string","value":"OK"}]}}),
    ]
}

async fn server(handlers: Vec<Value>) -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "redis".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Pub/sub bounds".into()),
        event_handlers: Some(handlers),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    for _ in 0..1500 {
        if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
            return (state, id, a.port());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the Redis server never bound");
}

struct Raw {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Raw {
    async fn connect(port: u16) -> Raw {
        let (r, w) = TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap()
            .into_split();
        Raw {
            reader: BufReader::new(r),
            writer: w,
        }
    }

    async fn send(&mut self, args: &[&[u8]]) {
        let args: Vec<Vec<u8>> = args.iter().map(|a| a.to_vec()).collect();
        self.writer.write_all(&encode_command(&args)).await.unwrap();
    }

    async fn send_all(&mut self, verb: &str, names: &[String]) {
        let mut args: Vec<&[u8]> = vec![verb.as_bytes()];
        args.extend(names.iter().map(|n| n.as_bytes()));
        self.send(&args).await;
    }

    async fn read(&mut self) -> Reply {
        tokio::time::timeout(Duration::from_secs(30), read_reply(&mut self.reader))
            .await
            .expect("no reply within 30s")
            .expect("read error")
            .expect("connection closed")
    }

    async fn call(&mut self, args: &[&[u8]]) -> Reply {
        self.send(args).await;
        self.read().await
    }

    /// Read `n` replies and return them.
    async fn read_n(&mut self, n: usize) -> Vec<Reply> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.read().await);
        }
        out
    }
}

fn error_text(reply: &Reply) -> String {
    reply.value["error"].as_str().unwrap_or("").to_string()
}

fn names(prefix: &str, n: usize) -> Vec<String> {
    (0..n).map(|i| format!("{prefix}{i}")).collect()
}

#[tokio::test]
async fn a_subscribed_resp2_connection_takes_only_the_pubsub_family() {
    let (_state, _id, port) = server(allowing_handlers()).await;
    let mut c = Raw::connect(port).await;

    // Nothing held: one confirmation, null channel, count 0 — Redis's own answer.
    let none = c.call(&[b"UNSUBSCRIBE"]).await;
    assert_eq!(none.value, json!(["unsubscribe", null, 0]));

    assert_eq!(
        c.call(&[b"SUBSCRIBE", b"a"]).await.value,
        json!(["subscribe", "a", 1])
    );
    let refused = c.call(&[b"GET", b"k"]).await;
    assert_eq!(
        error_text(&refused),
        "ERR Can't execute 'get': only (P|S)SUBSCRIBE / (P|S)UNSUBSCRIBE / PING / QUIT / RESET are allowed in this context"
    );
    assert_eq!(c.call(&[b"PING"]).await.value, json!(["pong", ""]));
    assert_eq!(c.call(&[b"PING", b"x"]).await.value, json!(["pong", "x"]));
    // A pattern counts toward the same total as channels.
    assert_eq!(
        c.call(&[b"PSUBSCRIBE", b"p*"]).await.value,
        json!(["psubscribe", "p*", 2])
    );
    // A shard channel is counted on its own.
    assert_eq!(
        c.call(&[b"SSUBSCRIBE", b"s"]).await.value,
        json!(["ssubscribe", "s", 1])
    );
    c.send(&[b"UNSUBSCRIBE"]).await;
    assert_eq!(c.read().await.value, json!(["unsubscribe", "a", 1]));
    // Still subscribed (a pattern and a shard channel), so still restricted.
    assert!(error_text(&c.call(&[b"GET", b"k"]).await).starts_with("ERR Can't execute"));
    // RESET drops everything without confirmations and leaves an ordinary connection.
    assert_eq!(c.call(&[b"RESET"]).await.value, json!("RESET"));
    assert_eq!(c.call(&[b"GET", b"k"]).await.value, json!("OK"));
}

#[tokio::test]
async fn channel_names_and_messages_are_bounded() {
    let (_state, _id, port) = server(allowing_handlers()).await;
    let mut c = Raw::connect(port).await;

    let long = "c".repeat(MAX_CHANNEL_BYTES + 1);
    let refused = c.call(&[b"SUBSCRIBE", long.as_bytes()]).await;
    assert_eq!(
        error_text(&refused),
        format!("ERR channel name longer than {MAX_CHANNEL_BYTES} bytes")
    );
    let fits = "c".repeat(MAX_CHANNEL_BYTES);
    assert_eq!(
        c.call(&[b"SUBSCRIBE", fits.as_bytes()]).await.value,
        json!(["subscribe", fits, 1])
    );

    let mut p = Raw::connect(port).await;
    let big = vec![b'm'; MAX_MESSAGE_BYTES + 1];
    let refused = p.call(&[b"PUBLISH", fits.as_bytes(), &big]).await;
    assert_eq!(
        error_text(&refused),
        format!("ERR message longer than {MAX_MESSAGE_BYTES} bytes")
    );
    let ok = vec![b'm'; MAX_MESSAGE_BYTES];
    assert_eq!(
        p.call(&[b"PUBLISH", fits.as_bytes(), &ok]).await.value,
        json!(1)
    );
    let delivered = c.read().await;
    assert_eq!(delivered.value[0], json!("message"));
    assert_eq!(
        delivered.value[2].as_str().map(str::len),
        Some(MAX_MESSAGE_BYTES)
    );
}

#[tokio::test]
async fn per_connection_and_distinct_pattern_caps_refuse_the_whole_command() {
    let (_state, _id, port) = server(allowing_handlers()).await;

    let mut a = Raw::connect(port).await;
    a.send_all("SUBSCRIBE", &names("ch", MAX_SUBSCRIPTIONS_PER_CONNECTION))
        .await;
    let confirmations = a.read_n(MAX_SUBSCRIPTIONS_PER_CONNECTION).await;
    assert_eq!(
        confirmations.last().unwrap().value[2],
        json!(MAX_SUBSCRIPTIONS_PER_CONNECTION)
    );
    let over = a.call(&[b"SUBSCRIBE", b"one-more"]).await;
    assert_eq!(
        error_text(&over),
        format!(
            "ERR max subscriptions per connection reached ({MAX_SUBSCRIPTIONS_PER_CONNECTION})"
        )
    );
    // Re-subscribing to a held channel adds nothing, so it is not over the cap.
    assert_eq!(
        a.call(&[b"SUBSCRIBE", b"ch0"]).await.value,
        json!(["subscribe", "ch0", MAX_SUBSCRIPTIONS_PER_CONNECTION])
    );

    // Distinct patterns across the server: one connection fills the cap, a second may share
    // those patterns but not add one. All or nothing: the refused command subscribed to none.
    let mut b = Raw::connect(port).await;
    b.send_all("PSUBSCRIBE", &names("pat", MAX_PATTERNS_PER_SERVER))
        .await;
    b.read_n(MAX_PATTERNS_PER_SERVER).await;
    let mut c = Raw::connect(port).await;
    let over = c.call(&[b"PSUBSCRIBE", b"pat0", b"brand-new"]).await;
    assert_eq!(
        error_text(&over),
        format!("ERR max distinct patterns per server reached ({MAX_PATTERNS_PER_SERVER})")
    );
    assert_eq!(
        c.call(&[b"PSUBSCRIBE", b"pat0"]).await.value,
        json!(["psubscribe", "pat0", 1]),
        "the refused command must not have subscribed to pat0"
    );
}

#[tokio::test]
async fn the_server_wide_subscription_cap_holds() {
    let (_state, _id, port) = server(allowing_handlers()).await;
    let per = MAX_SUBSCRIPTIONS_PER_CONNECTION;
    let mut held = Vec::new();
    for i in 0..MAX_SUBSCRIPTIONS_PER_SERVER / per {
        let mut c = Raw::connect(port).await;
        c.send_all("SUBSCRIBE", &names(&format!("c{i}-"), per))
            .await;
        c.read_n(per).await;
        held.push(c);
    }
    let mut last = Raw::connect(port).await;
    let over = last.call(&[b"SUBSCRIBE", b"one-too-many"]).await;
    assert_eq!(
        error_text(&over),
        format!("ERR max subscriptions per server reached ({MAX_SUBSCRIPTIONS_PER_SERVER})")
    );
    // Closing a connection returns its subscriptions to the pool.
    drop(held.pop());
    let mut retry = Raw::connect(port).await;
    for _ in 0..600 {
        let reply = retry.call(&[b"SUBSCRIBE", b"one-too-many"]).await;
        if reply.value == json!(["subscribe", "one-too-many", 1]) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("a closed connection's subscriptions were never released");
}

#[tokio::test]
async fn a_subscriber_that_stops_reading_is_disconnected() {
    let (_state, _id, port) = server(allowing_handlers()).await;
    let mut slow = Raw::connect(port).await;
    assert_eq!(
        slow.call(&[b"SUBSCRIBE", b"firehose"]).await.value,
        json!(["subscribe", "firehose", 1])
    );
    // The subscriber now reads nothing. Its kernel buffers fill, then its queue: past the
    // output limit it is dropped, and publishes stop counting it.
    let mut publisher = Raw::connect(port).await;
    let message = vec![b'x'; MAX_MESSAGE_BYTES];
    let mut dropped_after = None;
    for i in 0..128 {
        let n = publisher
            .call(&[b"PUBLISH", b"firehose", &message])
            .await
            .value;
        if n == json!(0) {
            dropped_after = Some(i);
            break;
        }
        assert_eq!(n, json!(1));
    }
    let dropped_after =
        dropped_after.expect("128 MiB queued and the slow subscriber was never dropped");
    assert!(
        dropped_after >= 8,
        "dropped after only {dropped_after} MiB — the limit is 8 MiB of queued messages"
    );
    assert_eq!(
        publisher
            .call(&[b"PUBSUB", b"NUMSUB", b"firehose"])
            .await
            .value,
        json!(["firehose", 0])
    );
    // And its socket is closed: reading drains what the kernel held, then ends.
    let drained = tokio::time::timeout(Duration::from_secs(60), async {
        let mut buf = vec![0u8; 1 << 20];
        loop {
            match tokio::io::AsyncReadExt::read(&mut slow.reader, &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(
        drained.is_ok(),
        "the slow subscriber's connection was never closed"
    );
}

#[tokio::test]
async fn subscribe_and_publish_fail_closed_when_the_model_cannot_answer() {
    // Subscriptions are accepted by a static rule; nothing answers a publish, so it goes to a
    // model that is unreachable.
    let (state, id, port) = server(vec![json!({
        "event_pattern":"redis_subscribe",
        "handler":{"type":"static","actions":[{"type":"redis_accept_subscription"}]}
    })])
    .await;
    let mut sub = Raw::connect(port).await;
    assert_eq!(
        sub.call(&[b"SUBSCRIBE", b"room"]).await.value,
        json!(["subscribe", "room", 1])
    );
    let mut p = Raw::connect(port).await;
    let failed = p.call(&[b"PUBLISH", b"room", b"must not arrive"]).await;
    assert_eq!(
        failed.reply_type, "error",
        "a failed model call is an error, got {failed:?}"
    );
    assert!(error_text(&failed).starts_with("ERR ") || error_text(&failed).starts_with("LOADING "));

    // The model publishes through the async action path; that is the first thing the
    // subscriber sees, so the failed publish delivered nothing.
    let registry = netget::protocol::server_registry::registry();
    let protocol = registry.resolve("redis").expect("redis registered");
    let result = netget::llm::actions::executor::execute_actions(
        vec![json!({"type":"redis_publish_message","channel":"room","message":"marker"})],
        &state,
        Some(protocol.as_ref()),
        Some(id),
        None,
    )
    .await
    .unwrap();
    assert!(result.failures.is_empty(), "{:?}", result.failures);
    let first = sub.read().await;
    assert_eq!(first.value, json!(["message", "room", "marker"]));

    // A subscription the model cannot rule on is refused, not granted.
    let (_state2, _id2, port2) = server(vec![]).await;
    let mut c = Raw::connect(port2).await;
    let refused = c.call(&[b"SUBSCRIBE", b"room"]).await;
    assert_eq!(refused.reply_type, "error");
    assert_eq!(
        c.call(&[b"PUBSUB", b"NUMSUB", b"room"]).await.value,
        json!(["room", 0])
    );

    // The async cluster action refuses on a standalone server rather than pretending.
    let result = netget::llm::actions::executor::execute_actions(
        vec![json!({"type":"redis_cluster_set_slot","slots":"1","state":"stable"})],
        &state,
        Some(protocol.as_ref()),
        Some(id),
        None,
    )
    .await
    .unwrap();
    assert_eq!(result.failures.len(), 1);
}

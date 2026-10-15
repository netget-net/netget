//! Pub/sub on the client: what this connection is subscribed to, telling a delivered message
//! from an ordinary reply, and publishing while subscribed.
//!
//! # Telling a message from a reply
//!
//! On RESP3 a message is a push (`>`), unambiguous. On RESP2 it is an ordinary array whose first
//! element is `message`, `pmessage` or `smessage` — which an `LRANGE` reply could also be. So an
//! array is read as pub/sub traffic only while the connection is *engaged*: from the moment a
//! `(P|S)SUBSCRIBE` is written until a confirmation reports that nothing is left. That is the
//! same rule every Redis client library applies, for the same reason.
//!
//! # Publishing while subscribed
//!
//! A RESP2 connection holding a subscription may send nothing but the pub/sub family, `PING`,
//! `QUIT` and `RESET`; Redis refuses a `PUBLISH` there. So `redis_publish` on such a connection
//! opens a second, short-lived connection to the same server, publishes, reads the receiver
//! count and closes — what redis-rs, redis-py and Jedis all require of their users. On RESP3, or
//! when not subscribed, it publishes on the connection itself and the `:N` reply is an ordinary
//! `redis_response_received`.
use super::resp::{self, Reply};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// How long the side connection a subscribed RESP2 client publishes over may take, end to end.
pub const SIDE_PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);

/// The pub/sub family: commands whose replies are confirmations rather than ordinary replies.
const SUBSCRIBE_FAMILY: &[&str] = &[
    "SUBSCRIBE",
    "PSUBSCRIBE",
    "SSUBSCRIBE",
    "UNSUBSCRIBE",
    "PUNSUBSCRIBE",
    "SUNSUBSCRIBE",
];

#[derive(Default)]
struct Subscriptions {
    channels: BTreeSet<String>,
    patterns: BTreeSet<String>,
    shard: BTreeSet<String>,
}

/// Connection-wide state the read loop and the write path share.
pub struct Session {
    /// The server, for the side connection.
    pub remote_addr: String,
    resp3: AtomicBool,
    engaged: AtomicBool,
    subs: Mutex<Subscriptions>,
}

/// What one reply turned out to be.
#[derive(Debug, PartialEq)]
pub enum Classified {
    /// A delivered message: `kind` is `message`, `pmessage` or `smessage`.
    Message {
        kind: String,
        pattern: Option<String>,
        channel: String,
        message: String,
    },
    /// A (un)subscribe confirmation.
    Subscription {
        kind: String,
        channel: Option<String>,
        count: i64,
    },
    /// Anything else.
    Reply,
}

impl Session {
    pub fn new(remote_addr: String) -> Self {
        Session {
            remote_addr,
            resp3: AtomicBool::new(false),
            engaged: AtomicBool::new(false),
            subs: Mutex::new(Subscriptions::default()),
        }
    }

    fn subs(&self) -> std::sync::MutexGuard<'_, Subscriptions> {
        self.subs.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn is_resp3(&self) -> bool {
        self.resp3.load(Ordering::Relaxed)
    }

    pub fn set_resp3(&self, on: bool) {
        self.resp3.store(on, Ordering::Relaxed);
    }

    /// A RESP2 connection in subscribed mode, which cannot publish on itself.
    pub fn subscribed_resp2(&self) -> bool {
        !self.is_resp3() && self.engaged.load(Ordering::Relaxed)
    }

    /// Note a command about to be written.
    pub fn note_sent(&self, args: &[Vec<u8>]) {
        let name = args
            .first()
            .map(|n| String::from_utf8_lossy(n).to_ascii_uppercase())
            .unwrap_or_default();
        if SUBSCRIBE_FAMILY.contains(&name.as_str()) {
            self.engaged.store(true, Ordering::Relaxed);
        }
    }

    /// The `UNSUBSCRIBE`-family commands that drop every subscription held.
    pub fn unsubscribe_all_commands(&self) -> Vec<Vec<Vec<u8>>> {
        let subs = self.subs();
        let mut out = Vec::new();
        if !subs.channels.is_empty() {
            out.push(vec![b"UNSUBSCRIBE".to_vec()]);
        }
        if !subs.patterns.is_empty() {
            out.push(vec![b"PUNSUBSCRIBE".to_vec()]);
        }
        if !subs.shard.is_empty() {
            out.push(vec![b"SUNSUBSCRIBE".to_vec()]);
        }
        out
    }

    /// What this connection holds, for the model.
    pub fn snapshot(&self) -> Value {
        let subs = self.subs();
        json!({
            "channels": subs.channels.iter().collect::<Vec<_>>(),
            "patterns": subs.patterns.iter().collect::<Vec<_>>(),
            "shard_channels": subs.shard.iter().collect::<Vec<_>>(),
        })
    }

    /// Read a reply as pub/sub traffic where it is one, updating the subscription state from
    /// confirmations. Also notices a `HELLO` reply and records the version it agreed.
    pub fn classify(&self, reply: &Reply) -> Classified {
        if let Some(proto) = hello_proto(reply) {
            self.set_resp3(proto == 3);
            return Classified::Reply;
        }
        let pubsub_shaped = match reply.reply_type {
            "push" => true,
            "array" => self.engaged.load(Ordering::Relaxed),
            _ => false,
        };
        if !pubsub_shaped {
            return Classified::Reply;
        }
        let Some(items) = reply.value.as_array() else {
            return Classified::Reply;
        };
        let text = |v: &Value| v.as_str().map(str::to_string);
        let kind = items.first().and_then(text).unwrap_or_default();
        match (kind.as_str(), items.len()) {
            ("message" | "smessage", 3) => Classified::Message {
                kind,
                pattern: None,
                channel: text(&items[1]).unwrap_or_default(),
                message: text(&items[2]).unwrap_or_default(),
            },
            ("pmessage", 4) => Classified::Message {
                kind,
                pattern: text(&items[1]),
                channel: text(&items[2]).unwrap_or_default(),
                message: text(&items[3]).unwrap_or_default(),
            },
            (
                "subscribe" | "psubscribe" | "ssubscribe" | "unsubscribe" | "punsubscribe"
                | "sunsubscribe",
                3,
            ) => {
                let channel = text(&items[1]);
                let count = items[2].as_i64().unwrap_or(0);
                let mut subs = self.subs();
                if let Some(name) = &channel {
                    let set = match kind.as_str() {
                        "subscribe" | "unsubscribe" => &mut subs.channels,
                        "psubscribe" | "punsubscribe" => &mut subs.patterns,
                        _ => &mut subs.shard,
                    };
                    if kind.ends_with("unsubscribe") {
                        set.remove(name);
                    } else {
                        set.insert(name.clone());
                    }
                }
                if kind.ends_with("unsubscribe")
                    && count == 0
                    && subs.channels.is_empty()
                    && subs.patterns.is_empty()
                    && subs.shard.is_empty()
                {
                    self.engaged.store(false, Ordering::Relaxed);
                }
                Classified::Subscription {
                    kind,
                    channel,
                    count,
                }
            }
            _ => Classified::Reply,
        }
    }
}

/// The protocol version a `HELLO` reply agreed: a RESP3 map, or the RESP2 flat array, carrying
/// both `server` and `proto`.
fn hello_proto(reply: &Reply) -> Option<i64> {
    match &reply.value {
        Value::Object(map) if map.contains_key("server") => map.get("proto")?.as_i64(),
        Value::Array(items) if reply.reply_type == "array" => {
            let at = |key: &str| items.iter().position(|v| v.as_str() == Some(key));
            at("server")?;
            items.get(at("proto")? + 1)?.as_i64()
        }
        _ => None,
    }
}

/// `PUBLISH` (or `SPUBLISH`) over a fresh connection, for a RESP2 connection in subscribed mode.
/// Returns the receiver count the server answered.
pub async fn publish_on_side_connection(addr: &str, args: &[Vec<u8>]) -> Result<i64> {
    let work = async {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("side connection to {addr}"))?;
        let (read_half, mut write_half) = tokio::io::split(stream);
        write_half.write_all(&resp::encode_command(args)).await?;
        write_half.flush().await?;
        let mut reader = BufReader::new(read_half);
        let reply = resp::read_reply(&mut reader)
            .await?
            .context("the server closed the side connection without answering")?;
        let _ = write_half.shutdown().await;
        match (reply.reply_type, reply.value.as_i64()) {
            ("integer", Some(n)) => Ok(n),
            _ => bail!("the server answered the publish with {}", reply.response),
        }
    };
    tokio::time::timeout(SIDE_PUBLISH_TIMEOUT, work)
        .await
        .context("the side connection's publish timed out")?
}

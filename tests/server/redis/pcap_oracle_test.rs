//! Every reply shape the Redis server writes on its success paths, read by an independent
//! dissector.
//!
//! The two real clients (redis-rs, redis-cli) read these bytes too, but a client library shows
//! the test only what it parsed, and a lenient parser can agree with a wrong length prefix or a
//! missing CRLF. Wireshark's `resp` dissector reads the raw bytes: `assert_clean` fails on any
//! Warn-level expert info (malformed length, a frame that does not end where its prefix says)
//! and on the dissector not engaging at all, and the field checks below assert what it *read*
//! — the integer, the bulk length, the array length, the error text — so a reply that parses
//! as some other well-formed RESP value also fails.
//!
//! Covered, each on the connection that provoked it:
//!
//! - the six RESP2 reply verbs the model answers with, including a bulk string carrying CRLF
//!   (which only its length prefix can delimit), an empty bulk string, the nil bulk string, a
//!   negative integer and an array mixing every element mapping;
//! - what Rust writes on its own: the `HELLO 2` reply, `PUBSUB` introspection, the
//!   subscription confirmation, a delivered `message`, subscribed-mode `PING`, the
//!   `UNSUBSCRIBE` confirmation and `+RESET`;
//! - cluster mode: `CLUSTER SLOTS`, `SHARDS`, `NODES`, `INFO`, `KEYSLOT`, `MYID` and a `-MOVED`
//!   redirection.
//!
//! Not covered: RESP3. Wireshark 4.6's `resp` dissector knows the RESP2 types only, so a RESP3
//! map or push reads as malformed whatever the server wrote; RESP3's evidence is the two
//! independent RESP3 parsers in `resp3_test.rs` (hiredis via redis-cli `-3`, redis-py's
//! `_RESP3Parser`).
//!
//! `tshark` and `python3` are required; the tests fail rather than skip without them. No LLM
//! calls: a python handler answers every event.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!       --test server -- server::redis::pcap_oracle --test-threads=8

use std::time::Duration;

use crate::helpers::pcap_oracle::PcapOracle;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::utils::resp::{scan_resp2_frame, RespLimits, RespScan};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// One reply per command for the model-answered verbs; every subscription accepted and every
/// publish delivered.
const HANDLER: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
if t=='redis_subscribe':
  a=[{'type':'redis_accept_subscription'}]
elif t=='redis_publish':
  a=[{'type':'redis_deliver_message'}]
else:
  n=e['command'].split(' ')[0].upper()
  A={'NG.SIMPLE':{'type':'redis_simple_string','value':'OK'},
     'NG.BULK':{'type':'redis_bulk_string','value':'line one\r\nline two'},
     'NG.EMPTY':{'type':'redis_bulk_string','value':''},
     'NG.NIL':{'type':'redis_null'},
     'NG.INT':{'type':'redis_integer','value':-42},
     'NG.ARRAY':{'type':'redis_array','values':['k1',42,True,None,{'a':1}]},
     'NG.EMPTYARRAY':{'type':'redis_array','values':[]},
     'NG.ERR':{'type':'redis_error','message':'WRONGTYPE Operation against a key holding the wrong kind of value'}}
  a=[A.get(n,{'type':'redis_error','message':'ERR unknown command'})]
print(json.dumps({'actions':a}))"#;

async fn server(startup_params: Option<serde_json::Value>) -> (AppState, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "redis".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Answer pcap oracle test commands".into()),
        startup_params,
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":HANDLER}}),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create redis server");
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

/// A raw connection that hands back each reply's exact bytes.
struct Conn {
    stream: TcpStream,
    pending: Vec<u8>,
}

impl Conn {
    async fn open(port: u16) -> Conn {
        Conn {
            stream: TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect"),
            pending: Vec::new(),
        }
    }

    /// Send one command; return the request bytes and the next `replies` frames.
    async fn call(&mut self, argv: &[&str], replies: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut req = format!("*{}\r\n", argv.len()).into_bytes();
        for a in argv {
            req.extend_from_slice(format!("${}\r\n{a}\r\n", a.len()).as_bytes());
        }
        self.stream.write_all(&req).await.expect("write command");
        let mut frames = Vec::new();
        for _ in 0..replies {
            frames.push(self.next_frame().await);
        }
        (req, frames)
    }

    /// The next whole RESP2 frame the server wrote.
    async fn next_frame(&mut self) -> Vec<u8> {
        let limits = RespLimits::with_max_bulk_len(1 << 20);
        loop {
            if let RespScan::Complete { consumed } = scan_resp2_frame(&self.pending, &limits) {
                return self.pending.drain(..consumed).collect();
            }
            let mut buf = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(20), self.stream.read(&mut buf))
                .await
                .expect("a reply within 20s")
                .expect("read reply");
            assert!(
                n > 0,
                "the server closed with {:?} unparsed",
                String::from_utf8_lossy(&self.pending)
            );
            self.pending.extend_from_slice(&buf[..n]);
        }
    }
}

/// The dissector's verdict on one exchange, and the values it read for `field` in the server's
/// direction, in order.
fn dissect(req: &[u8], replies: &[Vec<u8>], field: &str) -> Vec<String> {
    let build = || {
        let mut oracle = PcapOracle::tcp("redis");
        // A delivered pub/sub message answers no request on its own connection.
        if !req.is_empty() {
            oracle = oracle.to_server(req);
        }
        for r in replies {
            oracle = oracle.from_server(r);
        }
        oracle
    };
    build().assert_clean();
    let rows = build()
        .fields(&["tcp.dstport", field])
        .unwrap_or_else(|e| panic!("tshark could not read {field}: {e}"));
    // The first packet is the client's SYN, so its destination is the server's port; the
    // server's packets are the ones going anywhere else.
    let server_port = rows
        .iter()
        .filter_map(|r| r.first())
        .find(|p| !p.is_empty())
        .cloned()
        .unwrap_or_default();
    rows.into_iter()
        .filter(|r| r.first().is_some_and(|p| p != &server_port))
        .filter_map(|r| r.get(1).cloned())
        .filter(|v| !v.is_empty())
        .flat_map(|v| v.split(',').map(str::to_string).collect::<Vec<_>>())
        .collect()
}

/// What the dissector read for `field` from the reply to one command on `conn`.
async fn read(conn: &mut Conn, argv: &[&str], replies: usize, field: &str) -> Vec<String> {
    let (req, frames) = conn.call(argv, replies).await;
    let values = dissect(&req, &frames, field);
    println!(
        "{:?} -> {:?}: {field} = {values:?}",
        argv,
        frames
            .iter()
            .map(|f| String::from_utf8_lossy(f).to_string())
            .collect::<Vec<_>>()
    );
    values
}

#[tokio::test]
async fn every_resp2_reply_the_server_writes_is_well_formed_resp_to_wireshark() {
    let (_state, port) = server(None).await;
    let mut c = Conn::open(port).await;

    // The model's reply verbs.
    assert_eq!(read(&mut c, &["NG.SIMPLE"], 1, "resp.string").await, ["OK"]);
    // Eighteen bytes, CRLF inside: only the length prefix can delimit it, and the dissector
    // must find the frame ending exactly where the prefix says.
    assert_eq!(
        read(&mut c, &["NG.BULK"], 1, "resp.bulk_string.length").await,
        ["18"]
    );
    assert_eq!(
        read(&mut c, &["NG.EMPTY"], 1, "resp.bulk_string.length").await,
        ["0"]
    );
    assert_eq!(
        read(&mut c, &["NG.NIL"], 1, "resp.bulk_string.length").await,
        ["-1"]
    );
    assert_eq!(read(&mut c, &["NG.INT"], 1, "resp.integer").await, ["-42"]);
    // `["k1", 42, true, null, {"a":1}]`: five elements, the integer a RESP integer.
    assert_eq!(
        read(&mut c, &["NG.ARRAY"], 1, "resp.array.length").await,
        ["5"]
    );
    let (req, frames) = c.call(&["NG.ARRAY"], 1).await;
    assert_eq!(dissect(&req, &frames, "resp.integer"), ["42"]);
    assert_eq!(
        dissect(&req, &frames, "resp.bulk_string.length"),
        ["2", "1", "-1", "7"],
        "k1, \"1\" for true, nil, and the object's JSON text"
    );
    assert_eq!(
        read(&mut c, &["NG.EMPTYARRAY"], 1, "resp.array.length").await,
        ["0"]
    );
    let errors = read(&mut c, &["NG.ERR"], 1, "resp.error").await;
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("WRONGTYPE"), "{errors:?}");

    // What Rust answers itself. HELLO 2: a flat array of seven key/value pairs.
    assert_eq!(
        read(&mut c, &["HELLO", "2"], 1, "resp.array.length").await,
        ["14", "0"],
        "fourteen entries, the last (`modules`) an empty array"
    );
    assert_eq!(
        read(&mut c, &["PUBSUB", "NUMPAT"], 1, "resp.integer").await,
        ["0"]
    );

    // Pub/sub: a subscriber, then a publisher on a second connection.
    let mut sub = Conn::open(port).await;
    assert_eq!(
        read(&mut sub, &["SUBSCRIBE", "news", "sport"], 2, "resp.integer").await,
        ["1", "2"],
        "one confirmation per channel, each with the running count"
    );
    assert_eq!(
        read(&mut c, &["PUBSUB", "CHANNELS"], 1, "resp.array.length").await,
        ["2"]
    );
    assert_eq!(
        read(&mut c, &["PUBSUB", "NUMSUB", "news"], 1, "resp.integer").await,
        ["1"]
    );
    assert_eq!(
        read(&mut c, &["PUBLISH", "news", "hello"], 1, "resp.integer").await,
        ["1"],
        "the publisher is told one subscriber received it"
    );
    let delivered = sub.next_frame().await;
    assert_eq!(
        dissect(b"", &[delivered.clone()], "resp.bulk_string.length"),
        ["7", "4", "5"],
        "message, news, hello: got {:?}",
        String::from_utf8_lossy(&delivered)
    );
    // Subscribed-mode PING is `["pong", ""]`, not `+PONG`.
    assert_eq!(
        read(&mut sub, &["PING"], 1, "resp.bulk_string.length").await,
        ["4", "0"]
    );
    assert_eq!(
        read(&mut sub, &["UNSUBSCRIBE", "news"], 1, "resp.integer").await,
        ["1"]
    );
    assert_eq!(
        read(&mut sub, &["RESET"], 1, "resp.string").await,
        ["RESET"]
    );
}

#[tokio::test]
async fn cluster_replies_are_well_formed_resp_to_wireshark() {
    // This node serves the lower half of the slots; the upper half belongs to a node that is
    // never contacted, so a key there is answered with a redirection.
    let topology = json!([
        {"host": "127.0.0.1", "slots": ["0-8191"], "myself": true},
        {"host": "127.0.0.1", "port": 7001, "slots": ["8192-16383"]}
    ]);
    let (_state, port) = server(Some(json!({ "cluster_nodes": topology }))).await;
    let mut c = Conn::open(port).await;

    // Two ranges, each [start, end, [host, port, id]].
    assert_eq!(
        read(&mut c, &["CLUSTER", "SLOTS"], 1, "resp.integer").await,
        ["0", "8191", &port.to_string(), "8192", "16383", "7001"]
    );
    assert!(
        !read(&mut c, &["CLUSTER", "SHARDS"], 1, "resp.array.length")
            .await
            .is_empty()
    );
    let nodes = read(&mut c, &["CLUSTER", "NODES"], 1, "resp.bulk_string.length").await;
    assert_eq!(
        nodes.len(),
        1,
        "CLUSTER NODES is one bulk string: {nodes:?}"
    );
    let info = read(&mut c, &["CLUSTER", "INFO"], 1, "resp.bulk_string.length").await;
    assert_eq!(info.len(), 1, "CLUSTER INFO is one bulk string: {info:?}");
    // `foo` hashes to slot 12182, on the other node.
    assert_eq!(
        read(&mut c, &["CLUSTER", "KEYSLOT", "foo"], 1, "resp.integer").await,
        ["12182"]
    );
    assert_eq!(
        read(&mut c, &["CLUSTER", "MYID"], 1, "resp.bulk_string.length").await,
        ["40"]
    );
    let moved = read(&mut c, &["GET", "foo"], 1, "resp.error").await;
    assert_eq!(moved, ["MOVED 12182 127.0.0.1:7001"]);
}

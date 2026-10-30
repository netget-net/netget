//! Real JSON-RPC framing: modern Events and legacy Channels share the answer tools.
#![cfg(feature = "mcp-stdio")]

use clap::Parser;
use netget::cli::Args;
use netget::events::journal::{
    EventJournal, ACCESS_RECORDED, EVENT_HISTORY_LIMIT, INTERCEPT_PENDING, LLM_PENDING,
};
use netget::mcp_stdio::{stdio, tools::NetGetMcpService};
use netget::settings::Settings;
use serde_json::{json, Map, Value};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{
    AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, ReadHalf,
    WriteHalf,
};
use tokio::net::TcpStream;

struct Wire {
    reader: Lines<BufReader<ReadHalf<DuplexStream>>>,
    writer: WriteHalf<DuplexStream>,
    pending: VecDeque<Value>,
    next_id: u64,
    modern: bool,
}
impl Wire {
    async fn connect(
        modern: bool,
    ) -> (
        Self,
        netget::state::app_state::AppState,
        tokio::task::JoinHandle<()>,
    ) {
        let service = NetGetMcpService::new(
            &Args::parse_from(["netget", "--llm-agent"]),
            Settings::default(),
        )
        .await
        .unwrap();
        let state = service.app_state();
        let (server, client) = tokio::io::duplex(1 << 20);
        let (read, write) = tokio::io::split(server);
        let task = tokio::spawn(async move {
            stdio::serve(service, read, write).await.unwrap();
        });
        let (read, writer) = tokio::io::split(client);
        let mut wire = Self {
            reader: BufReader::new(read).lines(),
            writer,
            pending: VecDeque::new(),
            next_id: 1,
            modern,
        };
        if !modern {
            let init = wire.rpc("initialize", json!({"protocolVersion":"2025-06-18","clientInfo":{"name":"test","version":"1"},"capabilities":{}})).await;
            assert!(
                init["result"]["capabilities"]["extensions"]["io.modelcontextprotocol/events"]
                    .is_object()
            );
            assert!(init["result"]["capabilities"]["experimental"]["claude/channel"].is_object());
            wire.write(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
                .await;
            // A round trip ensures the initialized notification has been handled.
            wire.rpc("ping", json!({})).await;
        }
        (wire, state, task)
    }
    async fn write(&mut self, value: Value) {
        self.writer
            .write_all(format!("{value}\n").as_bytes())
            .await
            .unwrap();
    }
    async fn send(&mut self, method: &str, mut params: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        if self.modern {
            params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientInfo":{"name":"events-test","version":"1"},
                "io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/events":{}}}});
        }
        self.write(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await;
        id
    }
    async fn matching(&mut self, predicate: impl Fn(&Value) -> bool) -> Value {
        if let Some(index) = self.pending.iter().position(&predicate) {
            return self.pending.remove(index).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                let line = self
                    .reader
                    .next_line()
                    .await
                    .unwrap()
                    .expect("server disconnected");
                let message: Value = serde_json::from_str(&line).unwrap();
                if predicate(&message) {
                    return message;
                }
                self.pending.push_back(message);
            }
        })
        .await
        .expect("matching JSON-RPC message")
    }
    async fn rpc(&mut self, method: &str, params: Value) -> Value {
        let id = self.send(method, params).await;
        self.matching(|m| m["id"] == id).await
    }
    async fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let response = self
            .rpc("tools/call", json!({"name":name,"arguments":arguments}))
            .await;
        assert!(response.get("error").is_none(), "{response}");
        assert_ne!(response["result"]["isError"], true, "{response}");
        response["result"].clone()
    }
    async fn notification(&mut self, method: &str, subscription: Value) -> Value {
        self.matching(|m| {
            m["method"] == method
                && (subscription.is_null()
                    || m["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"]
                        == subscription)
        })
        .await["params"]
            .clone()
    }
}

#[tokio::test]
async fn modern_discovery_catalog_and_tools_without_initialize() {
    let (mut wire, _, task) = Wire::connect(true).await;
    let discover = wire.rpc("server/discover", json!({})).await;
    assert_eq!(discover["result"]["resultType"], "complete");
    assert_eq!(
        discover["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "netget"
    );
    assert!(
        discover["result"]["capabilities"]["extensions"]["io.modelcontextprotocol/events"]
            .is_object()
    );
    assert!(discover["result"]["capabilities"]["experimental"]["claude/channel"].is_object());
    let catalog = wire.rpc("events/list", json!({})).await;
    let events = catalog["result"]["events"].as_array().unwrap();
    assert_eq!(events.len(), 3);
    for event in events {
        assert_eq!(event["delivery"], json!(["poll", "push"]));
    }
    let tools = wire.rpc("tools/list", json!({})).await;
    assert_eq!(tools["result"]["resultType"], "complete");
    assert!(tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "answer_llm_request"));
    drop(wire);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn polling_bootstraps_filters_batches_and_matches_stream_replay() {
    let (mut wire, state, task) = Wire::connect(true).await;
    state
        .event_journal
        .publish(LLM_PENDING, json!({"request_id":0}));
    let bootstrap = wire.rpc("events/poll", json!({"name":LLM_PENDING})).await;
    assert_eq!(bootstrap["result"]["events"], json!([]));
    let cursor = bootstrap["result"]["cursor"].clone();
    for id in 1..=4 {
        state
            .event_journal
            .publish(LLM_PENDING, json!({"request_id":id,"server_id":id%2}));
    }
    let poll = wire
        .rpc(
            "events/poll",
            json!({"name":LLM_PENDING,"cursor":cursor,"arguments":{"server_id":1},"maxEvents":1}),
        )
        .await;
    assert_eq!(poll["result"]["events"][0]["data"]["request_id"], 1);
    assert_eq!(poll["result"]["hasMore"], true);
    assert!(poll["result"]["events"][0].get("cursor").is_none());
    let poll2=wire.rpc("events/poll",json!({"name":LLM_PENDING,"cursor":poll["result"]["cursor"],"arguments":{"server_id":1}})).await;
    assert_eq!(poll2["result"]["events"][0]["data"]["request_id"], 3);
    assert_eq!(poll2["result"]["hasMore"], false);
    let stream = wire
        .send(
            "events/stream",
            json!({"name":LLM_PENDING,"cursor":cursor,"arguments":{"server_id":1}}),
        )
        .await;
    let active = wire
        .notification("notifications/events/active", json!(stream))
        .await;
    assert_eq!(active["cursor"], cursor);
    for expected in [1, 3] {
        let e = wire
            .notification("notifications/events/event", json!(stream))
            .await;
        assert_eq!(e["data"]["request_id"], expected);
    }
    drop(wire);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn stream_notification_drives_real_tcp_answer_without_polling() {
    tcp_answer(true).await;
    tcp_answer(false).await;
}

async fn tcp_answer(modern: bool) {
    let (mut wire, _, task) = Wire::connect(modern).await;
    let stream = if modern {
        let id = wire
            .send("events/stream", json!({"name":LLM_PENDING}))
            .await;
        wire.notification("notifications/events/active", json!(id))
            .await;
        Some(id)
    } else {
        None
    };
    wire.tool(
        "start_server",
        json!({"protocol":"tcp","port":0,"instruction":"Answer the peer."}),
    )
    .await;
    let listing = wire.tool("list_servers", json!({})).await;
    let text = listing["content"][0]["text"].as_str().unwrap();
    let port: u16 = text
        .split("on port ")
        .nth(1)
        .unwrap()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap();
    let mut peer = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    peer.write_all(b"hello push").await.unwrap();
    let event = if let Some(id) = stream {
        wire.notification("notifications/events/event", json!(id))
            .await
    } else {
        let channel = wire
            .notification("notifications/claude/channel", Value::Null)
            .await;
        serde_json::from_str(channel["content"].as_str().unwrap()).unwrap()
    };
    let request = wire
        .tool("get_next_llm_request", json!({"wait_seconds":0}))
        .await["structuredContent"]
        .clone();
    assert_eq!(request["request_id"], event["data"]["request_id"]);
    wire.tool("answer_llm_request",json!({"request_id":request["request_id"],"claim_token":request["claim_token"],"actions":[{"type":"send_tcp_data","data":"push answer"}]})).await;
    let mut bytes = [0; 11];
    tokio::time::timeout(Duration::from_secs(10), peer.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"push answer");
    wire.tool("stop_all", json!({})).await;
    drop(peer);
    drop(wire);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn channels_deliver_manual_intercepts_and_existing_tools_resolve_them() {
    let (mut wire, _, task) = Wire::connect(false).await;
    wire.tool(
        "start_server",
        json!({"protocol":"tcp","port":0,
        "event_handlers":[{"event_pattern":"*","handler":{"type":"manual","timeout_secs":60}}]}),
    )
    .await;
    let listing = wire.tool("list_servers", json!({})).await;
    let text = listing["content"][0]["text"].as_str().unwrap();
    let port: u16 = text
        .split("on port ")
        .nth(1)
        .unwrap()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap();
    let mut peer = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    peer.write_all(b"manual question").await.unwrap();
    let message = wire
        .notification("notifications/claude/channel", Value::Null)
        .await;
    let occurrence: Value = serde_json::from_str(message["content"].as_str().unwrap()).unwrap();
    assert_eq!(occurrence["name"], INTERCEPT_PENDING);
    wire.tool("answer_intercept",json!({"intercept_id":occurrence["data"]["intercept_id"],"actions":[{"type":"send_tcp_data","data":"manual answer"}]})).await;
    let mut bytes = [0; 13];
    tokio::time::timeout(Duration::from_secs(10), peer.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"manual answer");
    wire.tool("stop_all", json!({})).await;
    drop(peer);
    drop(wire);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn concurrent_streams_cancel_independently_and_eof_is_prompt() {
    let (mut wire, state, task) = Wire::connect(true).await;
    let first = wire
        .send("events/stream", json!({"name":LLM_PENDING}))
        .await;
    let second = wire
        .send("events/stream", json!({"name":INTERCEPT_PENDING}))
        .await;
    wire.notification("notifications/events/active", json!(first))
        .await;
    wire.notification("notifications/events/active", json!(second))
        .await;
    wire.write(
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":first}}),
    )
    .await;
    wire.rpc("ping", json!({})).await;
    state
        .event_journal
        .publish(LLM_PENDING, json!({"request_id":1}));
    state
        .event_journal
        .publish(INTERCEPT_PENDING, json!({"intercept_id":2}));
    let delivered = wire
        .notification("notifications/events/event", json!(second))
        .await;
    assert_eq!(delivered["data"]["intercept_id"], 2);
    assert!(!wire
        .pending
        .iter()
        .any(|m| m["method"] == "notifications/events/event"
            && m["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"] == first));
    assert_eq!(
        wire.rpc("tools/list", json!({})).await["result"]["resultType"],
        "complete"
    );
    drop(wire);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn quiet_stream_heartbeats_carry_cursor_and_subscription() {
    let (mut wire, _, task) = Wire::connect(true).await;
    let stream = wire
        .send("events/stream", json!({"name":ACCESS_RECORDED}))
        .await;
    let active = wire
        .notification("notifications/events/active", json!(stream))
        .await;
    let heartbeat = wire
        .notification("notifications/events/heartbeat", json!(stream))
        .await;
    assert_eq!(heartbeat["cursor"], active["cursor"]);
    drop(wire);
    task.await.unwrap();
}

#[tokio::test]
async fn invalid_requests_fail_without_opening_streams_or_webhooks() {
    let (mut wire, _, task) = Wire::connect(true).await;
    for (method, params, code) in [
        ("events/poll", json!({"name":"absent"}), -32023),
        (
            "events/poll",
            json!({"name":LLM_PENDING,"arguments":{"server_id":"1"}}),
            -32602,
        ),
        (
            "events/poll",
            json!({"name":LLM_PENDING,"arguments":{"typo":1}}),
            -32602,
        ),
        (
            "events/poll",
            json!({"name":LLM_PENDING,"maxEvents":0}),
            -32602,
        ),
        (
            "events/stream",
            json!({"name":LLM_PENDING,"maxEvents":1}),
            -32602,
        ),
        (
            "events/stream",
            json!({"name":LLM_PENDING,"cursor":"bad"}),
            -32602,
        ),
        ("events/list", json!({"cursor":"bad"}), -32602),
        ("events/subscribe", json!({}), -32026),
        ("events/unsubscribe", json!({}), -32026),
    ] {
        assert_eq!(
            wire.rpc(method, params).await["error"]["code"],
            code,
            "{method}"
        );
    }
    let id = wire.next_id;
    wire.next_id += 1;
    wire.write(json!({"jsonrpc":"2.0","id":id,"method":"events/list","params":{}}))
        .await;
    assert_eq!(
        wire.matching(|m| m["id"] == id).await["error"]["code"],
        -32602
    );
    drop(wire);
    task.await.unwrap();
}

#[tokio::test]
async fn stream_cap_releases_on_cancellation_and_string_ids_are_preserved() {
    let (mut wire, _, task) = Wire::connect(true).await;
    let mut first = 0;
    for index in 0..64 {
        let id = wire
            .send("events/stream", json!({"name":LLM_PENDING}))
            .await;
        if index == 0 {
            first = id;
        }
        wire.notification("notifications/events/active", json!(id))
            .await;
    }
    let denied = wire.rpc("events/stream", json!({"name":LLM_PENDING})).await;
    assert_eq!(denied["error"]["code"], -32025);
    wire.write(
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":first}}),
    )
    .await;
    // NetGet sends the optional final frame; it also proves the slot was released.
    let final_frame = wire.matching(|m| m["id"] == first).await;
    assert_eq!(
        final_frame["result"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
        first
    );
    wire.write(
        json!({"jsonrpc":"2.0","id":"string-stream","method":"events/stream",
        "params":{"name":LLM_PENDING,"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},
            "io.modelcontextprotocol/clientCapabilities":{}}}}),
    )
    .await;
    wire.notification("notifications/events/active", json!("string-stream"))
        .await;
    drop(wire);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn access_log_publication_covers_both_server_and_client_owners() {
    let (mut wire, state, task) = Wire::connect(true).await;
    let bootstrap = wire
        .rpc("events/poll", json!({"name":ACCESS_RECORDED}))
        .await;
    use netget::state::AccessLogOwner;
    for owner in [AccessLogOwner::Server(3), AccessLogOwner::Client(4)] {
        state
            .record_access_log(
                owner,
                "tcp",
                Some(5),
                "fixture",
                json!({"secret":"not-in-notification"}),
                vec![],
            )
            .await;
    }
    let poll = wire
        .rpc(
            "events/poll",
            json!({"name":ACCESS_RECORDED,"cursor":bootstrap["result"]["cursor"]}),
        )
        .await;
    let events = poll["result"]["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["data"]["server_id"], 3);
    assert_eq!(events[1]["data"]["client_id"], 4);
    assert!(!poll.to_string().contains("not-in-notification"));
    drop(wire);
    task.await.unwrap();
}

#[tokio::test]
async fn modern_version_errors_preserve_the_connection_for_retry() {
    let (mut wire, _, task) = Wire::connect(true).await;
    wire.write(
        json!({"jsonrpc":"2.0","id":100,"method":"events/list","params":{"_meta":{
        "io.modelcontextprotocol/protocolVersion":"2099-01-01"}}}),
    )
    .await;
    let error = wire.matching(|m| m["id"] == 100).await;
    assert_eq!(error["error"]["code"], -32022);
    assert_eq!(error["error"]["data"]["supported"], json!(["2026-07-28"]));
    assert!(wire.rpc("events/list", json!({})).await["result"]["events"].is_array());
    drop(wire);
    task.await.unwrap();
}

#[tokio::test]
async fn modern_channels_are_opted_in_scoped_and_share_ids_with_events() {
    let (mut wire, state, task) = Wire::connect(true).await;
    let meta = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"channels-test","version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{"experimental":{"claude/channel":{}}}});
    wire.write(json!({"jsonrpc":"2.0","id":"ordinary","method":"ping","params":{"_meta":meta}}))
        .await;
    wire.matching(|m| m["id"] == "ordinary").await;
    state
        .event_journal
        .publish(LLM_PENDING, json!({"request_id":1}));
    wire.rpc("ping", json!({})).await;
    assert!(!wire
        .pending
        .iter()
        .any(|m| m["method"] == "notifications/claude/channel"));
    let unrequested = wire
        .send("subscriptions/listen", json!({"notifications":{}}))
        .await;
    wire.notification(
        "notifications/subscriptions/acknowledged",
        json!(unrequested),
    )
    .await;
    wire.matching(|m| m["id"] == unrequested).await;
    wire.write(
        json!({"jsonrpc":"2.0","id":"channels","method":"subscriptions/listen",
        "params":{"notifications":{},"_meta":meta}}),
    )
    .await;
    wire.notification(
        "notifications/subscriptions/acknowledged",
        json!("channels"),
    )
    .await;
    let stream = wire
        .send("events/stream", json!({"name":LLM_PENDING}))
        .await;
    wire.notification("notifications/events/active", json!(stream))
        .await;
    state
        .event_journal
        .publish(LLM_PENDING, json!({"request_id":42}));
    let occurrence = wire
        .notification("notifications/events/event", json!(stream))
        .await;
    let channel = wire
        .notification("notifications/claude/channel", json!("channels"))
        .await;
    let content: Value = serde_json::from_str(channel["content"].as_str().unwrap()).unwrap();
    assert_eq!(occurrence["eventId"], content["eventId"]);
    assert_eq!(content["data"]["request_id"], 42);
    wire.write(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"channels"}})).await;
    wire.matching(|m| m["id"] == "channels").await;
    drop(wire);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn ring_retention_restart_and_age_bounds_signal_gaps() {
    let journal = EventJournal::default();
    let cursor = journal.current_cursor();
    for id in 0..=EVENT_HISTORY_LIMIT {
        journal.publish(LLM_PENDING, json!({"request_id":id}));
    }
    let replay = journal
        .read(LLM_PENDING, &Map::new(), Some(&cursor), None, 2000)
        .unwrap();
    assert!(replay.truncated);
    assert_eq!(replay.events.len(), EVENT_HISTORY_LIMIT);
    assert_eq!(replay.events[0]["data"]["request_id"], 1);
    let fresh = EventJournal::default()
        .read(LLM_PENDING, &Map::new(), Some(&cursor), None, 100)
        .unwrap();
    assert!(fresh.truncated);
    assert!(fresh.events.is_empty());
    std::thread::sleep(Duration::from_millis(3));
    let aged = journal
        .read(LLM_PENDING, &Map::new(), Some(&cursor), Some(0), 100)
        .unwrap();
    assert!(aged.truncated);
    assert!(aged.events.is_empty());
}

#[test]
fn observation_does_not_claim_queue_work_and_uses_one_id_across_deliveries() {
    let events = Arc::new(EventJournal::default());
    let cursor = events.current_cursor();
    let queue = netget::llm::agent_queue::LlmRequestQueue::with_events(None, events.clone());
    let (id, _rx) = queue.submit("agent".into(), vec![], vec![]);
    let first = events
        .read(LLM_PENDING, &Map::new(), Some(&cursor), None, 100)
        .unwrap();
    let second = events
        .read(LLM_PENDING, &Map::new(), Some(&cursor), None, 100)
        .unwrap();
    assert_eq!(first.events, second.events);
    assert_eq!(first.events[0]["data"]["request_id"], id);
    assert!(!queue.get(id).unwrap().claimed);
    assert_eq!(queue.claim_next().unwrap().id, id);
}

#[tokio::test]
async fn binary_accepts_modern_stdio_and_exits_with_an_open_stream_on_eof() {
    use std::process::Stdio;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_netget"))
        .args(["--mcp", "--llm-agent"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
    let meta = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"binary-test","version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{}});
    for (id, method, params) in [
        (1, "server/discover", json!({"_meta":meta})),
        (2, "events/stream", json!({"name":LLM_PENDING,"_meta":meta})),
    ] {
        input
            .write_all(
                format!(
                    "{}\n",
                    json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut discovered = false;
        let mut active = false;
        while !discovered || !active {
            let line = output
                .next_line()
                .await
                .unwrap()
                .expect("binary stdout ended");
            let message: Value = serde_json::from_str(&line).unwrap();
            if message["id"] == 1 {
                assert_eq!(message["result"]["resultType"], "complete");
                discovered = true;
            }
            if message["method"] == "notifications/events/active" {
                active = true;
            }
        }
    })
    .await
    .unwrap();
    drop(input);
    assert!(tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .unwrap()
        .unwrap()
        .success());
}

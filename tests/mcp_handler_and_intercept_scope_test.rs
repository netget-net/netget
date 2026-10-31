//! The MCP surface holds handlers and parked requests to the right instance, and shows its
//! caller only what is meant for it. Each case was reproduced by hand against the installed
//! `netget --mcp` on 31 October 2026:
//!
//! - **A static handler is scoped to the server's own protocol.** A redis server started
//!   with `send_http_response` as its `*` catch-all used to start and then answer every
//!   command `ERR no response produced`; an unknown name was refused with a list of every
//!   protocol's actions. Both `start_server` and `update_server` now refuse a foreign action
//!   and list redis's alone.
//! - **No control sentinel reaches a tool result.** `start_server`'s output carried the
//!   dashboard's `__UPDATE_UI__` repaint request.
//! - **A parked request offers the event's own answers.** `redis_subscribe` declares four;
//!   `list_intercepts` offered all of redis's actions, and `answer_intercept` accepted them.
//! - **A parked request dies with its connection.** A `redis-cli` SUBSCRIBE parked, the client
//!   was killed, and the request stayed listed; `answer_intercept` then said "Answered" and
//!   the server counted bytes written into the closed connection.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio \
//!       --test mcp_handler_and_intercept_scope_test

#![cfg(feature = "mcp-stdio")]

use std::time::Duration;

use clap::Parser;
use netget::cli::Args;
use netget::mcp_stdio::tools::NetGetMcpService;
use netget::settings::Settings;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::{serve_client, RoleClient, ServiceExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

type Client = rmcp::service::RunningService<RoleClient, ()>;

async fn connect() -> Client {
    let args = Args::parse_from(["netget"]);
    let service = NetGetMcpService::new(&args, Settings::default())
        .await
        .expect("service creation");
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(server) = service.serve(server_io).await {
            let _ = server.waiting().await;
        }
    });
    serve_client((), client_io).await.expect("client handshake")
}

async fn call(client: &Client, name: &'static str, args: serde_json::Value) -> CallToolResult {
    let mut params = CallToolRequestParams::new(name);
    params.arguments = args.as_object().cloned();
    client.call_tool(params).await.expect("call tool")
}

fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
        .collect()
}

fn number_after(text: &str, marker: &str) -> u64 {
    let idx = text
        .find(marker)
        .unwrap_or_else(|| panic!("marker {marker:?} not found in: {text}"));
    text[idx + marker.len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("no number after {marker:?} in: {text}"))
}

fn wildcard_static(actions: serde_json::Value) -> serde_json::Value {
    serde_json::json!([{"event_pattern": "*", "handler": {"type": "static", "actions": actions}}])
}

/// RESP2 array of bulk strings.
fn resp_command(args: &[&str]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        out.extend_from_slice(format!("${}\r\n{}\r\n", arg.len(), arg).as_bytes());
    }
    out
}

/// The ids in a `list_intercepts` result.
async fn listed_intercepts(client: &Client) -> (Vec<u64>, String) {
    let text = text_of(&call(client, "list_intercepts", serde_json::json!({})).await);
    let mut ids = Vec::new();
    let mut rest = text.as_str();
    while let Some(idx) = rest.find("intercept_id ") {
        rest = &rest[idx + "intercept_id ".len()..];
        if let Ok(id) = rest
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
        {
            ids.push(id);
        }
    }
    (ids, text)
}

#[tokio::test]
async fn a_static_handler_is_validated_against_the_servers_own_protocol() {
    let client = connect().await;

    // A foreign action as the catch-all: refused at start, nothing registered.
    let refused = call(
        &client,
        "start_server",
        serde_json::json!({
            "protocol": "redis",
            "port": 0,
            "event_handlers": wildcard_static(
                serde_json::json!([{"type": "send_http_response", "status": 200, "body": "hi"}])
            ),
        }),
    )
    .await;
    let text = text_of(&refused);
    assert_eq!(
        refused.is_error,
        Some(true),
        "a redis server must not start with an HTTP catch-all: {text}"
    );
    assert!(text.contains("send_http_response"), "{text}");
    assert!(text.contains("Valid actions for Redis"), "{text}");
    let listed = text_of(&call(&client, "list_servers", serde_json::json!({})).await);
    assert!(
        !listed.contains("Server #"),
        "a refused start registers nothing: {listed}"
    );

    // A typo: the list is redis's, not the build's.
    let typo = call(
        &client,
        "start_server",
        serde_json::json!({
            "protocol": "redis",
            "port": 0,
            "event_handlers": wildcard_static(
                serde_json::json!([{"type": "send_redis_simple_string", "value": "OK"}])
            ),
        }),
    )
    .await;
    let typo_text = text_of(&typo);
    assert_eq!(typo.is_error, Some(true), "{typo_text}");
    assert!(typo_text.contains("redis_simple_string"), "{typo_text}");
    assert!(
        !typo_text.contains("send_tcp_data") && !typo_text.contains("send_dns_a_response"),
        "other protocols' actions are not offered to a redis server: {typo_text}"
    );

    // The update path is held to the same rule, and leaves the running server untouched.
    let started = call(
        &client,
        "start_server",
        serde_json::json!({
            "protocol": "redis",
            "port": 0,
            "event_handlers": wildcard_static(
                serde_json::json!([{"type": "redis_simple_string", "value": "OK"}])
            ),
        }),
    )
    .await;
    let started_text = text_of(&started);
    assert_ne!(started.is_error, Some(true), "{started_text}");
    let server_id = number_after(&started_text, "Server #");
    let update = call(
        &client,
        "update_server",
        serde_json::json!({
            "server_id": server_id,
            "event_handlers": wildcard_static(
                serde_json::json!([{"type": "send_http_response", "status": 200, "body": "hi"}])
            ),
        }),
    )
    .await;
    let update_text = text_of(&update);
    assert_eq!(update.is_error, Some(true), "{update_text}");
    assert!(update_text.contains("send_http_response"), "{update_text}");

    client.cancel().await.expect("shutdown");
}

/// Start a redis server whose every command parks for an answer; returns (id, port, text).
async fn start_manual_redis(client: &Client) -> (u64, u16, String) {
    let started = call(
        client,
        "start_server",
        serde_json::json!({
            "protocol": "redis",
            "port": 0,
            "event_handlers": [
                {"event_pattern": "*", "handler": {"type": "manual", "timeout_secs": 120}}
            ]
        }),
    )
    .await;
    let text = text_of(&started);
    assert_ne!(started.is_error, Some(true), "{text}");
    let server_id = number_after(&text, "Server #");
    let listed = text_of(&call(client, "list_servers", serde_json::json!({})).await);
    let port = number_after(&listed, "on port ") as u16;
    (server_id, port, text)
}

/// Connect a peer, SUBSCRIBE, and wait for the request to park; returns (peer, id, listing).
async fn park_a_subscribe(client: &Client, port: u16) -> (TcpStream, u64, String) {
    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("peer connects");
    peer.write_all(&resp_command(&["SUBSCRIBE", "news"]))
        .await
        .expect("peer writes");
    for _ in 0..300 {
        let (ids, text) = listed_intercepts(client).await;
        if let Some(id) = ids.first() {
            return (peer, *id, text);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the SUBSCRIBE never parked for an answer");
}

#[tokio::test]
async fn start_server_output_carries_no_control_sentinels() {
    let client = connect().await;
    let (_, _, started_text) = start_manual_redis(&client).await;
    assert!(
        !started_text.contains("__"),
        "status-channel control sentinels must not reach a tool result: {started_text}"
    );
    client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn a_parked_request_offers_and_accepts_only_its_events_answers() {
    let client = connect().await;
    let (_, port, _) = start_manual_redis(&client).await;
    let (_peer, intercept, listing) = park_a_subscribe(&client, port).await;

    assert!(listing.contains("redis_subscribe"), "{listing}");
    for offered in [
        "redis_accept_subscription(",
        "redis_error(",
        "redis_publish_message(",
        "close_this_connection(",
    ] {
        assert!(
            listing.contains(offered),
            "redis_subscribe's declared answer {offered} is offered: {listing}"
        );
    }
    for not_offered in ["redis_bulk_string(", "redis_simple_string(", "redis_array("] {
        assert!(
            !listing.contains(not_offered),
            "{not_offered} is a redis action but not an answer redis_subscribe declares: \
             {listing}"
        );
    }

    // answer_intercept holds an answer to the same list.
    let wrong = call(
        &client,
        "answer_intercept",
        serde_json::json!({
            "intercept_id": intercept,
            "actions": [{"type": "redis_bulk_string", "value": "x"}]
        }),
    )
    .await;
    let wrong_text = text_of(&wrong);
    assert_eq!(wrong.is_error, Some(true), "{wrong_text}");
    assert!(
        wrong_text.contains("redis_accept_subscription"),
        "the refusal lists the event's answers: {wrong_text}"
    );
    client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn a_parked_request_dies_with_its_connection() {
    let client = connect().await;
    let (server_id, port, _) = start_manual_redis(&client).await;
    let (peer, intercept, _) = park_a_subscribe(&client, port).await;

    // The peer hangs up while its SUBSCRIBE is parked.
    drop(peer);
    let mut gone = false;
    for _ in 0..200 {
        let (ids, _) = listed_intercepts(&client).await;
        if !ids.contains(&intercept) {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        gone,
        "a request whose peer hung up must leave list_intercepts"
    );
    let late = call(
        &client,
        "answer_intercept",
        serde_json::json!({
            "intercept_id": intercept,
            "actions": [{"type": "redis_accept_subscription"}]
        }),
    )
    .await;
    assert_eq!(
        late.is_error,
        Some(true),
        "answering a request whose peer is gone must be an error, not \"Answered\": {}",
        text_of(&late)
    );

    // The connection is closed and nothing was written to it.
    let status = text_of(
        &call(
            &client,
            "server_status",
            serde_json::json!({"server_id": server_id}),
        )
        .await,
    );
    assert!(
        !status.contains("(Active)"),
        "the hung-up connection is not reported live: {status}"
    );
    assert!(
        !status.contains("(Closed)") || status.contains(" / 0 out"),
        "nothing was written into the closed connection: {status}"
    );

    client.cancel().await.expect("shutdown");
}

/// Pipelined commands that arrive while one is parked are still answered, in order, once it
/// is: watching the socket for a hang-up must not lose bytes.
#[tokio::test]
async fn commands_pipelined_behind_a_parked_one_are_still_answered() {
    let client = connect().await;
    let started = call(
        &client,
        "start_server",
        serde_json::json!({
            "protocol": "redis",
            "port": 0,
            "event_handlers": [
                {"event_pattern": "*", "handler": {"type": "manual", "timeout_secs": 120}}
            ]
        }),
    )
    .await;
    assert_ne!(started.is_error, Some(true), "{}", text_of(&started));
    let listed = text_of(&call(&client, "list_servers", serde_json::json!({})).await);
    let port = number_after(&listed, "on port ") as u16;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("peer connects");
    peer.write_all(&resp_command(&["GET", "a"]))
        .await
        .expect("first command");

    let mut answered = Vec::new();
    for expected in ["first", "second"] {
        let mut next = None;
        for _ in 0..300 {
            let (ids, _) = listed_intercepts(&client).await;
            if let Some(id) = ids.into_iter().find(|id| !answered.contains(id)) {
                next = Some(id);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let id = next.unwrap_or_else(|| panic!("the {expected} command parks"));
        if expected == "first" {
            // The second command arrives while the first is parked.
            peer.write_all(&resp_command(&["GET", "b"]))
                .await
                .expect("second command");
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let ok = call(
            &client,
            "answer_intercept",
            serde_json::json!({
                "intercept_id": id,
                "actions": [{"type": "redis_bulk_string", "value": expected}]
            }),
        )
        .await;
        assert_ne!(ok.is_error, Some(true), "{}", text_of(&ok));
        answered.push(id);
    }

    let want = b"$5\r\nfirst\r\n$6\r\nsecond\r\n";
    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while got.len() < want.len() && tokio::time::Instant::now() < deadline {
        let mut buf = [0u8; 256];
        match tokio::time::timeout(Duration::from_secs(10), peer.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
            Ok(Err(e)) => panic!("peer read failed: {e}"),
        }
    }
    assert_eq!(
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(want),
        "both answers, in order"
    );

    client.cancel().await.expect("shutdown");
}

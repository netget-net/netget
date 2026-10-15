//! The MCP surface for requests parked by a `manual` event handler: `list_intercepts`,
//! `answer_intercept` and `fail_intercept` — the dashboard's intercept modal, headless.
//!
//! Everything is asserted from the **peer's** side of a real TCP connection, because a tool
//! result is text and says "answered" whatever reached the wire. Three answers, three
//! different things on the wire:
//!
//! 1. a composed action → the peer reads exactly those bytes;
//! 2. an empty array → the peer reads nothing, and the connection carries on (its next line
//!    parks a new request) — "acknowledge, say nothing" is an answer, not a timeout;
//! 3. `fail_intercept` → the peer gets TCP's fail-closed form, a half-close (EOF).
//!
//! No model is involved anywhere: `*` → manual means every event waits for the caller, and the
//! caller here is the test.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,tcp \
//!       --test mcp_intercept_test -- --test-threads=100

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

/// Start a TCP server whose every event parks for a human; returns (server id, port).
async fn start_manual_tcp_server(client: &Client) -> (u64, u16) {
    let started = call(
        client,
        "start_server",
        serde_json::json!({
            "protocol": "tcp",
            "port": 0,
            "event_handlers": [
                {"event_pattern": "*", "handler": {"type": "manual", "timeout_secs": 60}}
            ]
        }),
    )
    .await;
    let text = text_of(&started);
    assert_ne!(started.is_error, Some(true), "start_server failed: {text}");
    let server_id = number_after(&text, "Server #");
    let listed = text_of(&call(client, "list_servers", serde_json::json!({})).await);
    let port = number_after(&listed, "on port ") as u16;
    (server_id, port)
}

/// Poll `list_intercepts` until an intercept id not in `seen` appears; return (id, text).
async fn next_intercept(client: &Client, seen: &[u64]) -> (u64, String) {
    for _ in 0..300 {
        let text = text_of(&call(client, "list_intercepts", serde_json::json!({})).await);
        let mut rest = text.as_str();
        while let Some(idx) = rest.find("intercept_id ") {
            rest = &rest[idx + "intercept_id ".len()..];
            let id: u64 = rest
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse()
                .unwrap_or(0);
            if id != 0 && !seen.contains(&id) {
                return (id, text.clone());
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no new intercept appeared (seen: {seen:?})");
}

async fn read_some(peer: &mut TcpStream, within: Duration) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 1024];
    match tokio::time::timeout(within, peer.read(&mut buf)).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        Ok(Err(e)) => panic!("peer read failed: {e}"),
        Err(_) => None,
    }
}

#[tokio::test]
async fn answering_parked_requests_over_mcp_reaches_the_wire() {
    let client = connect().await;
    let (server_id, port) = start_manual_tcp_server(&client).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("peer connects");

    // ---- 1. a composed answer -------------------------------------------------------------
    peer.write_all(b"hello\n").await.expect("peer writes");
    let (first, listing) = next_intercept(&client, &[]).await;
    assert!(
        listing.contains(&format!("server #{server_id}")),
        "the listing names the owning server: {listing}"
    );
    assert!(
        listing.contains("tcp_data_received"),
        "event type: {listing}"
    );
    assert!(
        listing.contains("hello"),
        "the event data is shown: {listing}"
    );
    assert!(
        listing.contains("send_tcp_data(data*"),
        "the answerable actions are listed with their parameters: {listing}"
    );
    let remaining = number_after(&listing, "Fails closed in**: ");
    assert!(
        (50..=60).contains(&remaining),
        "seconds until fail-closed counts down from the handler's 60: {listing}"
    );

    // An action the event cannot be answered with is refused and the request keeps waiting.
    let refused = call(
        &client,
        "answer_intercept",
        serde_json::json!({"intercept_id": first, "actions": [{"type": "send_udp_response", "data": "x"}]}),
    )
    .await;
    let refused_text = text_of(&refused);
    assert_eq!(refused.is_error, Some(true), "{refused_text}");
    assert!(
        refused_text.contains("still waiting") && refused_text.contains("send_tcp_data"),
        "the refusal says the request still waits and lists what is accepted: {refused_text}"
    );
    let still = text_of(&call(&client, "list_intercepts", serde_json::json!({})).await);
    assert!(
        still.contains(&format!("intercept_id {first}")),
        "a refused answer must not consume the request: {still}"
    );

    let answered = call(
        &client,
        "answer_intercept",
        serde_json::json!({
            "intercept_id": first,
            "actions": [{"type": "send_tcp_data", "data": "hi from mcp\n"}]
        }),
    )
    .await;
    assert_ne!(answered.is_error, Some(true), "{}", text_of(&answered));
    let got = read_some(&mut peer, Duration::from_secs(10))
        .await
        .expect("the composed answer reaches the peer");
    assert_eq!(got, b"hi from mcp\n", "exact bytes on the wire");

    // ---- 2. an empty answer: nothing on the wire, connection carries on -------------------
    peer.write_all(b"again\n").await.expect("peer writes");
    let (second, _) = next_intercept(&client, &[first]).await;
    let nothing = call(
        &client,
        "answer_intercept",
        serde_json::json!({"intercept_id": second, "actions": []}),
    )
    .await;
    let nothing_text = text_of(&nothing);
    assert_ne!(nothing.is_error, Some(true), "{nothing_text}");
    assert!(nothing_text.contains("with nothing"), "{nothing_text}");
    assert!(
        read_some(&mut peer, Duration::from_millis(700))
            .await
            .is_none(),
        "answering with nothing writes nothing and does not close the connection"
    );
    // The connection is alive: its next line is a fresh request.
    peer.write_all(b"third\n").await.expect("peer writes");
    let (third, _) = next_intercept(&client, &[first, second]).await;

    // ---- 3. fail closed: TCP's fail-closed form is a half-close ---------------------------
    let failed = call(
        &client,
        "fail_intercept",
        serde_json::json!({"intercept_id": third}),
    )
    .await;
    assert_ne!(failed.is_error, Some(true), "{}", text_of(&failed));
    let eof = read_some(&mut peer, Duration::from_secs(10))
        .await
        .expect("the peer observes the refusal");
    assert!(
        eof.is_empty(),
        "fail-closed on TCP is a half-close (EOF), got {:?}",
        String::from_utf8_lossy(&eof)
    );

    // Gone: a second refusal or an answer both say so.
    let again = call(
        &client,
        "fail_intercept",
        serde_json::json!({"intercept_id": third}),
    )
    .await;
    assert_eq!(again.is_error, Some(true), "{}", text_of(&again));
    let late = call(
        &client,
        "answer_intercept",
        serde_json::json!({"intercept_id": third, "actions": []}),
    )
    .await;
    assert_eq!(late.is_error, Some(true), "{}", text_of(&late));

    client.cancel().await.expect("shutdown");
}

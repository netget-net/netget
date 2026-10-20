//! `send_to_client`, `send_to_peer` and `disconnect_peer` over MCP — the dashboard's
//! `[ send ]`, `[ message ]` and `[ disconnect ]`, headless.
//!
//! Each is asserted where the bytes land, not from the tool's text:
//!
//! - `send_to_client`: a NetGet TCP client started over MCP sends a line on demand. The NetGet
//!   TCP server it is connected to (a static echo handler, no model) records the line it
//!   received in its access log, and echoes it back — which the client records in *its* access
//!   log, so the round trip is proven from both ends.
//! - `send_to_peer`: a raw `TcpStream` connected to a NetGet TCP server reads the pushed line
//!   before it has said anything.
//! - `disconnect_peer`: the same raw peer reads EOF.
//!
//! Plus the refusals: an action outside the target's set is refused with the accepted names; a
//! client with no command channel (here: disconnected) and a connection with no peer handle
//! both fail immediately rather than waiting out a timeout.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,tcp \
//!       --test mcp_client_send_test -- --test-threads=100

#![cfg(feature = "mcp-stdio")]

use std::time::{Duration, Instant};

use clap::Parser;
use netget::cli::Args;
use netget::mcp_stdio::tools::NetGetMcpService;
use netget::settings::Settings;
use netget::state::app_state::AppState;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::{serve_client, RoleClient, ServiceExt};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

type Client = rmcp::service::RunningService<RoleClient, ()>;

async fn connect() -> (Client, AppState) {
    let args = Args::parse_from(["netget"]);
    let service = NetGetMcpService::new(&args, Settings::default())
        .await
        .expect("service creation");
    let app_state = service.app_state();
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(server) = service.serve(server_io).await {
            let _ = server.waiting().await;
        }
    });
    (
        serve_client((), client_io).await.expect("client handshake"),
        app_state,
    )
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

/// Start a TCP server with the given handlers; returns (server id, bound port).
async fn start_tcp_server(client: &Client, handlers: serde_json::Value) -> (u64, u16) {
    let started = call(
        client,
        "start_server",
        serde_json::json!({"protocol": "tcp", "port": 0, "event_handlers": handlers}),
    )
    .await;
    let text = text_of(&started);
    assert_ne!(started.is_error, Some(true), "start_server failed: {text}");
    let server_id = number_after(&text, "Server #");
    let status = text_of(
        &call(
            client,
            "server_status",
            serde_json::json!({"server_id": server_id}),
        )
        .await,
    );
    let port = number_after(&status, "**Port**: ") as u16;
    (server_id, port)
}

/// Poll the access log until `pred` holds for some entry.
async fn wait_for_log(
    state: &AppState,
    what: &str,
    pred: impl Fn(&netget::state::app_state::AccessLogEntry) -> bool,
) -> netget::state::app_state::AccessLogEntry {
    for _ in 0..300 {
        if let Some(entry) = state.list_access_logs(None).await.into_iter().find(&pred) {
            return entry;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "no access-log entry for {what}; log: {:#?}",
        state.list_access_logs(None).await
    );
}

#[tokio::test]
async fn send_to_client_puts_the_action_on_the_wire() {
    let (client, state) = connect().await;

    // Echo server: a static handler, no model.
    let (server_id, port) = start_tcp_server(
        &client,
        serde_json::json!([{
            "event_pattern": "tcp_data_received",
            "handler": {"type": "static", "actions": [
                {"type": "send_tcp_data", "data": "{{event.data}}"}
            ]}
        }]),
    )
    .await;

    // A client that says nothing on its own: every event is answered with no actions.
    let started = call(
        &client,
        "start_client",
        serde_json::json!({
            "protocol": "tcp",
            "remote_addr": format!("127.0.0.1:{port}"),
            "event_handlers": [
                {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
            ]
        }),
    )
    .await;
    let started_text = text_of(&started);
    assert_ne!(started.is_error, Some(true), "{started_text}");
    let client_id = number_after(&started_text, "Client #");

    // An action outside the client's set is refused, naming what is accepted.
    let refused = call(
        &client,
        "send_to_client",
        serde_json::json!({"client_id": client_id, "action": {"type": "send_http_request"}}),
    )
    .await;
    let refused_text = text_of(&refused);
    assert_eq!(refused.is_error, Some(true), "{refused_text}");
    assert!(
        refused_text.contains("send_tcp_data"),
        "the refusal lists the accepted actions: {refused_text}"
    );

    let sent = call(
        &client,
        "send_to_client",
        serde_json::json!({
            "client_id": client_id,
            "action": {"type": "send_tcp_data", "data": "ping from mcp\n"}
        }),
    )
    .await;
    let sent_text = text_of(&sent);
    assert_ne!(sent.is_error, Some(true), "{sent_text}");
    assert!(sent_text.contains("sent 14 byte(s)"), "{sent_text}");

    // The server received exactly that line…
    wait_for_log(&state, "the server's tcp_data_received", |e| {
        e.server_id == Some(server_id as u32)
            && e.event_type == "tcp_data_received"
            && e.request.get("data").and_then(|d| d.as_str()) == Some("ping from mcp\n")
    })
    .await;
    // …and its echo came back to the client.
    wait_for_log(&state, "the client's echoed tcp_data_received", |e| {
        e.client_id == Some(client_id as u32)
            && e.event_type == "tcp_data_received"
            && e.request.get("data").and_then(|d| d.as_str()) == Some("ping from mcp\n")
    })
    .await;

    // A client with no command channel fails at once instead of waiting out the timeout.
    assert!(
        state
            .disconnect_client(netget::state::ClientId::new(client_id as u32))
            .await
    );
    let began = Instant::now();
    let dead = call(
        &client,
        "send_to_client",
        serde_json::json!({
            "client_id": client_id,
            "action": {"type": "send_tcp_data", "data": "x"},
            "timeout_secs": 60
        }),
    )
    .await;
    let dead_text = text_of(&dead);
    assert_eq!(dead.is_error, Some(true), "{dead_text}");
    assert!(
        dead_text.contains("does not accept injected actions"),
        "{dead_text}"
    );
    assert!(
        began.elapsed() < Duration::from_secs(5),
        "a client without a command channel must fail fast, took {:?}",
        began.elapsed()
    );

    let missing = call(
        &client,
        "send_to_client",
        serde_json::json!({"client_id": 999_999, "action": {"type": "send_tcp_data", "data": "x"}}),
    )
    .await;
    assert_eq!(missing.is_error, Some(true), "{}", text_of(&missing));

    client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn send_to_peer_and_disconnect_peer_reach_the_peer() {
    let (client, _state) = connect().await;

    // Silent server: every event answered with nothing, so anything the peer reads was pushed.
    let (server_id, port) = start_tcp_server(
        &client,
        serde_json::json!([
            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
        ]),
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("peer connects");

    // server_status lists the connection and says it accepts send_to_peer.
    let mut connection_id = None;
    for _ in 0..300 {
        let status = text_of(
            &call(
                &client,
                "server_status",
                serde_json::json!({"server_id": server_id}),
            )
            .await,
        );
        if status.contains("accepts send_to_peer") {
            connection_id = Some(number_after(&status, "connection_id **"));
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let connection_id = connection_id.expect("server_status lists the live connection");

    let refused = call(
        &client,
        "send_to_peer",
        serde_json::json!({
            "server_id": server_id, "connection_id": connection_id,
            "action": {"type": "send_dns_a_response"}
        }),
    )
    .await;
    let refused_text = text_of(&refused);
    assert_eq!(refused.is_error, Some(true), "{refused_text}");
    assert!(refused_text.contains("send_tcp_data"), "{refused_text}");

    let no_handle = call(
        &client,
        "send_to_peer",
        serde_json::json!({
            "server_id": server_id, "connection_id": 424_242,
            "action": {"type": "send_tcp_data", "data": "x"}
        }),
    )
    .await;
    let no_handle_text = text_of(&no_handle);
    assert_eq!(no_handle.is_error, Some(true), "{no_handle_text}");
    assert!(
        no_handle_text.contains("does not accept injected actions"),
        "{no_handle_text}"
    );

    let pushed = call(
        &client,
        "send_to_peer",
        serde_json::json!({
            "server_id": server_id, "connection_id": connection_id,
            "action": {"type": "send_tcp_data", "data": "pushed\n"}
        }),
    )
    .await;
    assert_ne!(pushed.is_error, Some(true), "{}", text_of(&pushed));
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(10), peer.read(&mut buf))
        .await
        .expect("the pushed line arrives")
        .expect("read");
    assert_eq!(&buf[..n], b"pushed\n");

    let hung_up = call(
        &client,
        "disconnect_peer",
        serde_json::json!({"server_id": server_id, "connection_id": connection_id}),
    )
    .await;
    assert_ne!(hung_up.is_error, Some(true), "{}", text_of(&hung_up));
    let n = tokio::time::timeout(Duration::from_secs(10), peer.read(&mut buf))
        .await
        .expect("the hang-up arrives")
        .expect("read");
    assert_eq!(n, 0, "disconnect_peer half-closes: the peer reads EOF");

    client.cancel().await.expect("shutdown");
}

/// `send_to_peer` on a server whose protocol only answers requests says so in the protocol's
/// own terms, rather than suggesting a peer handle might turn up.
#[tokio::test]
async fn send_to_peer_on_a_request_only_protocol_names_the_protocols_reason() {
    let (client, _state) = connect().await;
    let started = call(
        &client,
        "start_server",
        serde_json::json!({
            "protocol": "http", "port": 0,
            "event_handlers": [
                {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
            ]
        }),
    )
    .await;
    let text = text_of(&started);
    assert_ne!(started.is_error, Some(true), "start_server failed: {text}");
    let server_id = number_after(&text, "Server #");

    let refused = call(
        &client,
        "send_to_peer",
        serde_json::json!({
            "server_id": server_id, "connection_id": 1,
            "action": {"type": "send_http_response", "status": 200, "body": "hi"}
        }),
    )
    .await;
    let refused_text = text_of(&refused);
    assert_eq!(refused.is_error, Some(true), "{refused_text}");
    let reason = netget::protocol::server_registry::registry()
        .request_only_reason("HTTP")
        .expect("HTTP declares request_only");
    assert!(refused_text.contains(reason), "{refused_text}");
    assert!(!refused_text.contains("peer handle"), "{refused_text}");
}

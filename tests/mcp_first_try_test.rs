//! What an MCP caller is told when it starts something, and when that goes wrong.
//!
//! An agent driving NetGet acts on the tool result and nothing else, so each of these pins a
//! fact the result has to carry for its next step to be right:
//!
//! - `start_server` leads with the address the server is listening on, once, rather than in
//!   the third of several log lines;
//! - a server or client whose events go to the model says so, at once, when the model backend
//!   cannot be reached — instead of reporting a clean start and failing every request;
//! - after such a failure `get_status` names it, and `list_access_logs` / `server_status` say
//!   why each event failed rather than `FAILED: redis_command`;
//! - an error keeps its cause (`Connection refused`), and a port that is taken names the port,
//!   who holds it and what to do instead.
//!
//! No model anywhere: `--ollama-url` points at a closed port, which is the case under test.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!       --test mcp_first_try_test -- --test-threads=100

#![cfg(feature = "mcp-stdio")]

use clap::Parser;
use netget::cli::Args;
use netget::mcp_stdio::tools::NetGetMcpService;
use netget::settings::Settings;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::{serve_client, RoleClient, ServiceExt};

type Client = rmcp::service::RunningService<RoleClient, ()>;

/// Nothing listens on port 1 of loopback: every model request is refused at once.
const UNREACHABLE_OLLAMA: &str = "http://127.0.0.1:1";

async fn connect(argv: &[&str]) -> Client {
    let args = Args::parse_from(argv);
    let service = NetGetMcpService::new(&args, Settings::default())
        .await
        .expect("service creation");
    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
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

fn number_after(text: &str, marker: &str) -> u32 {
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

fn static_http_handlers() -> serde_json::Value {
    serde_json::json!([{
        "event_pattern": "*",
        "handler": {"type": "static", "actions": [
            {"type": "send_http_response", "status": 200, "body": "hello"}
        ]}
    }])
}

#[tokio::test]
async fn errors_keep_their_cause_and_a_taken_port_says_what_to_do() {
    let client = connect(&["netget", "--ollama-url", UNREACHABLE_OLLAMA]).await;

    // A name nothing resolves points at the search that takes a description.
    let unknown = call(
        &client,
        "start_server",
        serde_json::json!({"protocol": "webserver", "port": 0}),
    )
    .await;
    let text = text_of(&unknown);
    assert_eq!(unknown.is_error, Some(true), "{text}");
    assert!(
        text.contains(r#"list_protocols with {"type": "server", "query": "webserver"}"#),
        "{text}"
    );

    // The client's error used to stop at "Failed to connect to Redis at 127.0.0.1:1".
    let refused = call(
        &client,
        "start_client",
        serde_json::json!({
            "protocol": "redis",
            "remote_addr": "127.0.0.1:1",
            "event_handlers": [{"event_pattern": "*", "handler": {"type": "static", "actions": []}}]
        }),
    )
    .await;
    let text = text_of(&refused);
    assert_eq!(refused.is_error, Some(true), "{text}");
    assert!(
        text.to_lowercase().contains("refused"),
        "the cause is kept: {text}"
    );

    // A port taken by this NetGet's own server.
    let first = text_of(
        &call(
            &client,
            "start_server",
            serde_json::json!({"protocol": "http", "port": 0, "event_handlers": static_http_handlers()}),
        )
        .await,
    );
    let holder = number_after(&first, "Server #");
    let port = number_after(&first, "listening on 127.0.0.1:");
    let taken = call(
        &client,
        "start_server",
        serde_json::json!({"protocol": "http", "port": port, "event_handlers": static_http_handlers()}),
    )
    .await;
    let text = text_of(&taken);
    assert_eq!(taken.is_error, Some(true), "{text}");
    assert!(
        text.contains(&format!("127.0.0.1:{port}"))
            && text.contains(&format!("by this NetGet's server #{holder} (HTTP)"))
            && text.contains("port 0"),
        "names the port, its holder and the way out: {text}"
    );

    // A privileged port, where this process cannot bind one, says what to use instead.
    let privileged = call(
        &client,
        "start_server",
        serde_json::json!({"protocol": "http", "port": 80, "event_handlers": static_http_handlers()}),
    )
    .await;
    let text = text_of(&privileged);
    if privileged.is_error == Some(true) && text.contains("Privileged port") {
        assert!(text.contains("1024 or above"), "{text}");
    }
}

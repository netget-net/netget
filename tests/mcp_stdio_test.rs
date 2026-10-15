//! MCP STDIO server smoke tests
//!
//! These tests exercise the MCP server end-to-end over an in-process duplex
//! transport (no real stdin/stdout, no Ollama). They verify that the JSON-RPC
//! handshake, tool discovery, and non-LLM tool calls work.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,tcp --test mcp_stdio_test -- --test-threads=100

#![cfg(feature = "mcp-stdio")]

use netget::cli::Args;
use netget::mcp_stdio::tools::NetGetMcpService;
use netget::settings::Settings;

use clap::Parser;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::{serve_client, RoleClient, ServiceExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Build an in-process client connected to a NetGet MCP server started with `argv`.
async fn connect_args(argv: &[&str]) -> rmcp::service::RunningService<RoleClient, ()> {
    let args = Args::parse_from(argv);
    let service = NetGetMcpService::new(&args, Settings::default())
        .await
        .expect("service creation");

    let (server_io, client_io) = tokio::io::duplex(64 * 1024);

    // Serve the NetGet MCP server on one end of the duplex.
    tokio::spawn(async move {
        if let Ok(server) = service.serve(server_io).await {
            let _ = server.waiting().await;
        }
    });

    // The unit type `()` is a no-capability MCP client handler.
    serve_client((), client_io).await.expect("client handshake")
}

/// Build an in-process client connected to a fresh default NetGet MCP server.
async fn connect() -> rmcp::service::RunningService<RoleClient, ()> {
    connect_args(&["netget"]).await
}

/// Call a tool with JSON arguments and return the result.
async fn call(
    client: &rmcp::service::RunningService<RoleClient, ()>,
    name: &'static str,
    args: serde_json::Value,
) -> CallToolResult {
    let mut params = CallToolRequestParams::new(name);
    params.arguments = args.as_object().cloned();
    client.call_tool(params).await.expect("call tool")
}

/// Concatenate the text content of a tool result.
fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
        .collect()
}

/// Parse the digits following `marker` in `text` (e.g. "port " → 54321).
fn parse_number_after(text: &str, marker: &str) -> u64 {
    let idx = text
        .find(marker)
        .unwrap_or_else(|| panic!("marker {:?} not found in: {}", marker, text));
    text[idx + marker.len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("no number after {:?} in: {}", marker, text))
}

#[tokio::test]
async fn initialize_and_list_tools() {
    let client = connect().await;

    // The handshake populated server info.
    let info = client.peer_info().expect("server info");
    assert_eq!(info.server_info.name, "netget");

    // Core management tools must be advertised.
    let tools = client.list_all_tools().await.expect("list tools");
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    for expected in [
        "list_protocols",
        "start_server",
        "stop_server",
        "get_status",
        "list_access_logs",
        "get_access_log",
    ] {
        assert!(
            names.contains(&expected),
            "expected tool '{}' in {:?}",
            expected,
            names
        );
    }

    client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn call_list_protocols_returns_tcp() {
    let client = connect().await;

    let mut params = CallToolRequestParams::new("list_protocols");
    params.arguments = serde_json::json!({ "type": "server" }).as_object().cloned();

    let result = client.call_tool(params).await.expect("call list_protocols");

    assert_ne!(result.is_error, Some(true), "tool reported an error");

    // The rendered markdown should mention the TCP protocol that is compiled in.
    let text = result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
        .collect::<String>()
        .to_lowercase();
    assert!(text.contains("tcp"), "expected tcp in output: {}", text);

    client.cancel().await.expect("shutdown");
}

/// In `--llm-agent` mode the agent-queue tools are advertised.
#[tokio::test]
async fn agent_mode_exposes_queue_tools() {
    let client = connect_args(&["netget", "--llm-agent"]).await;

    let tools = client.list_all_tools().await.expect("list tools");
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    for expected in [
        "get_next_llm_request",
        "answer_llm_request",
        "list_llm_requests",
    ] {
        assert!(
            names.contains(&expected),
            "expected tool '{}' in {:?}",
            expected,
            names
        );
    }

    // get_status should report the agent backend.
    let status = call(&client, "get_status", serde_json::json!({})).await;
    assert!(
        text_of(&status).to_lowercase().contains("agent"),
        "expected agent backend in status: {}",
        text_of(&status)
    );

    client.cancel().await.expect("shutdown");
}

/// End-to-end: a real TCP server queues its LLM request, the MCP agent fetches it
/// and answers, and the answer drives the socket response.
#[tokio::test]
async fn agent_answers_tcp_request_end_to_end() {
    let client = connect_args(&["netget", "--llm-agent"]).await;

    // Start a TCP server on an OS-assigned port.
    let started = call(
        &client,
        "start_server",
        serde_json::json!({ "protocol": "tcp", "port": 0 }),
    )
    .await;
    assert_ne!(started.is_error, Some(true), "start_server errored");

    // Discover the bound port.
    let servers = call(&client, "list_servers", serde_json::json!({})).await;
    let port = parse_number_after(&text_of(&servers), "port ") as u16;
    assert!(port > 0, "expected a bound port, got {}", port);

    // Connect a real client and send a line — this triggers tcp_data_received,
    // which enqueues an LLM request the agent must answer.
    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    sock.write_all(b"PING\n").await.expect("tcp write");

    // Long-poll for the queued request.
    let next = call(
        &client,
        "get_next_llm_request",
        serde_json::json!({ "wait_seconds": 5 }),
    )
    .await;
    let next_text = text_of(&next);
    assert!(
        !next_text.contains("(no pending requests)"),
        "expected a queued request, got: {}",
        next_text
    );
    let request_id = parse_number_after(&next_text, "request #");

    // Answer it with a send_tcp_data action (one of the actions offered for this
    // event) so the server writes "PONG" back on the wire.
    let answered = call(
        &client,
        "answer_llm_request",
        serde_json::json!({
            "request_id": request_id,
            "actions": [
                { "type": "send_tcp_data", "data": "PONG\n" }
            ]
        }),
    )
    .await;
    assert_ne!(
        answered.is_error,
        Some(true),
        "answer_llm_request errored: {}",
        text_of(&answered)
    );

    // The socket should receive the agent's answer.
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), sock.read(&mut buf))
        .await
        .expect("socket read timed out")
        .expect("socket read");
    let received = String::from_utf8_lossy(&buf[..n]);
    assert!(
        received.contains("PONG"),
        "expected PONG on the wire, got: {:?}",
        received
    );

    client.cancel().await.expect("shutdown");
}

/// A queued request that is never answered errors out after the configured timeout,
/// after which it can no longer be answered.
#[tokio::test]
async fn agent_request_times_out() {
    let client = connect_args(&["netget", "--llm-agent", "--llm-agent-timeout", "1"]).await;

    call(
        &client,
        "start_server",
        serde_json::json!({ "protocol": "tcp", "port": 0 }),
    )
    .await;
    let servers = call(&client, "list_servers", serde_json::json!({})).await;
    let port = parse_number_after(&text_of(&servers), "port ") as u16;

    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    sock.write_all(b"PING\n").await.expect("tcp write");

    // Claim the request but do not answer it.
    let next = call(
        &client,
        "get_next_llm_request",
        serde_json::json!({ "wait_seconds": 5 }),
    )
    .await;
    let request_id = parse_number_after(&text_of(&next), "request #");

    // Wait past the 1s answer timeout; the backend expires the request.
    tokio::time::sleep(std::time::Duration::from_millis(1600)).await;

    // Answering an expired request must now fail.
    let answered = call(
        &client,
        "answer_llm_request",
        serde_json::json!({ "request_id": request_id, "actions": [] }),
    )
    .await;
    assert_eq!(
        answered.is_error,
        Some(true),
        "expected answering an expired request to fail, got: {}",
        text_of(&answered)
    );

    client.cancel().await.expect("shutdown");
}

/// `get_protocol_docs` must describe the MCP surface, not the internal TUI LLM's
/// `open_server`/`open_client` actions or its `base_stack` parameter.
#[tokio::test]
async fn protocol_docs_describe_the_mcp_surface() {
    let client = connect().await;

    let docs = call(
        &client,
        "get_protocol_docs",
        serde_json::json!({ "protocol": "tcp" }),
    )
    .await;
    assert_ne!(docs.is_error, Some(true), "get_protocol_docs errored");
    let text = text_of(&docs);

    for forbidden in ["open_server", "open_client", "base_stack"] {
        assert!(
            !text.contains(forbidden),
            "MCP docs must not mention '{}':\n{}",
            forbidden,
            text
        );
    }

    // The tool arguments an MCP caller actually has.
    for expected in [
        "start_server",
        "`event_handlers`",
        "`startup_params`",
        "`instruction`",
        "privilege required",
        "maturity",
    ] {
        assert!(
            text.contains(expected),
            "expected '{}' in MCP docs:\n{}",
            expected,
            text
        );
    }

    // A declared default is printed beside its parameter, and it is the number the server
    // falls back to — tcp's idle bound is 900 seconds (`IDLE_BETWEEN_MESSAGES_TIMEOUT`).
    let idle = text
        .lines()
        .find(|l| l.starts_with("- `idle_timeout_secs`"))
        .unwrap_or_else(|| panic!("tcp declares idle_timeout_secs:\n{text}"));
    assert!(
        idle.contains("default: `900`"),
        "the default must be shown beside the parameter: {idle}"
    );
    // tcp has no well-known port, so an omitted port is an OS-assigned one.
    assert!(
        text.contains("has no well-known port"),
        "tcp's port line must say it has no well-known port:\n{text}"
    );

    // redis does have one, and its docs name it whether or not it is free right now.
    if true {
        let redis = call(
            &client,
            "get_protocol_docs",
            serde_json::json!({ "protocol": "redis" }),
        )
        .await;
        let redis = text_of(&redis);
        let port_line = redis
            .lines()
            .find(|l| l.starts_with("- `port`"))
            .unwrap_or_else(|| panic!("redis docs have a port line:\n{redis}"));
        assert!(
            port_line.contains("6379"),
            "the port line must name redis's well-known port: {port_line}"
        );
    }

    // Event ids with their field names, which handlers are written against.
    assert!(
        text.contains("tcp_data_received"),
        "expected tcp event ids in docs:\n{}",
        text
    );
    assert!(
        text.contains("`encoding`"),
        "expected event field names in docs:\n{}",
        text
    );
    // Action names with parameter schemas.
    assert!(
        text.contains("send_tcp_data"),
        "expected action names in docs:\n{}",
        text
    );

    // What the server writes when the model cannot answer, and whether it keeps connections.
    assert!(
        text.contains("when the model cannot answer**: answers"),
        "expected failure_mode in docs:\n{}",
        text
    );
    assert!(
        text.contains("connection-oriented"),
        "expected connectionless in docs:\n{}",
        text
    );
    // Async actions are invocable over MCP (send_to_peer / send_to_client), so they are
    // rendered like the response actions: a heading, parameters and an example — not a bare
    // list of names. tcp's server-level close_connection and its client's disconnect.
    for rendered in [
        "#### `close_connection`",
        "#### `disconnect`",
        "send_to_client",
    ] {
        assert!(
            text.contains(rendered),
            "expected '{}' in MCP docs:\n{}",
            rendered,
            text
        );
    }
    assert!(
        !text.contains("no MCP tool"),
        "docs must not claim async actions are unreachable over MCP:\n{}",
        text
    );

    // Unknown protocols still report what is available.
    let missing = call(
        &client,
        "get_protocol_docs",
        serde_json::json!({ "protocol": "definitely_not_a_protocol" }),
    )
    .await;
    assert_eq!(missing.is_error, Some(true));
    assert!(text_of(&missing).contains("not found"));

    client.cancel().await.expect("shutdown");
}

/// `send_first` must actually reach the protocol: a TCP server started with it speaks first, the
/// same server without it does not, and a `send_first` server whose greeting failed closes the
/// connection because the greeting was owed.
#[tokio::test]
async fn send_first_produces_a_greeting_banner() {
    let client = connect().await;

    let banner_handler = serde_json::json!([{
        "event_pattern": "tcp_connection_opened",
        "handler": {
            "type": "static",
            "actions": [{ "type": "send_tcp_data", "data": "220 banner\r\n" }]
        }
    }]);

    let started = call(
        &client,
        "start_server",
        serde_json::json!({
            "protocol": "tcp",
            "port": 0,
            "send_first": true,
            "event_handlers": banner_handler,
        }),
    )
    .await;
    assert_ne!(
        started.is_error,
        Some(true),
        "start_server errored: {}",
        text_of(&started)
    );
    let port = parse_number_after(&text_of(&started), "listening on 127.0.0.1:") as u16;
    assert!(port > 0, "expected a bound port in: {}", text_of(&started));

    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), sock.read(&mut buf))
        .await
        .expect("no banner within 5s — send_first was ignored")
        .expect("socket read");
    assert!(
        String::from_utf8_lossy(&buf[..n]).contains("220 banner"),
        "unexpected banner: {:?}",
        String::from_utf8_lossy(&buf[..n])
    );

    // Control: without send_first no connect event is raised, so the server waits for the
    // client.
    let started = call(
        &client,
        "start_server",
        serde_json::json!({
            "protocol": "tcp",
            "port": 0,
            "event_handlers": banner_handler,
        }),
    )
    .await;
    let port = parse_number_after(&text_of(&started), "listening on 127.0.0.1:") as u16;
    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let mut buf = vec![0u8; 64];
    let quiet =
        tokio::time::timeout(std::time::Duration::from_millis(1500), sock.read(&mut buf)).await;
    assert!(
        quiet.is_err(),
        "server sent data without send_first: {:?}",
        quiet.map(|r| r.map(|n| String::from_utf8_lossy(&buf[..n]).to_string()))
    );

    // The peer is OWED a greeting under send_first. A connect event that fails (a manual rule
    // nobody answers within its 1s timeout fails closed, the same path as a backend failure)
    // closes a send_first server's connection; without send_first there is no connect event,
    // so the connection stays open and quiet.
    let unanswered = serde_json::json!([{
        "event_pattern": "tcp_connection_opened",
        "handler": {"type": "manual", "timeout_secs": 1}
    }]);
    for send_first in [true, false] {
        let started = call(
            &client,
            "start_server",
            serde_json::json!({
                "protocol": "tcp",
                "port": 0,
                "send_first": send_first,
                "event_handlers": unanswered,
            }),
        )
        .await;
        let port = parse_number_after(&text_of(&started), "listening on 127.0.0.1:") as u16;
        let mut sock = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        let mut buf = vec![0u8; 64];
        let read =
            tokio::time::timeout(std::time::Duration::from_secs(5), sock.read(&mut buf)).await;
        if send_first {
            assert!(
                matches!(read, Ok(Ok(0))),
                "a send_first server whose greeting failed must close (EOF), got {read:?}"
            );
        } else {
            assert!(
                read.is_err(),
                "without send_first no connect event is raised, so the connection must stay \
                 open and quiet, got {read:?}"
            );
        }
    }

    client.cancel().await.expect("shutdown");
}

/// A malformed `scheduled_tasks` entry is reported to the caller rather than
/// silently dropped.
#[tokio::test]
async fn scheduled_tasks_are_validated() {
    let client = connect().await;

    let result = call(
        &client,
        "start_server",
        serde_json::json!({
            "protocol": "tcp",
            "port": 0,
            "scheduled_tasks": [{ "not_a_task": true }],
        }),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    assert!(
        text_of(&result).contains("scheduled_tasks"),
        "expected a scheduled_tasks error, got: {}",
        text_of(&result)
    );

    client.cancel().await.expect("shutdown");
}

/// The client control surface: start_client / list_clients / client_status /
/// stop_client, driven against a NetGet TCP server started in the same session.
#[tokio::test]
async fn client_tools_manage_a_real_connection() {
    let client = connect().await;

    // The tools are advertised.
    let tools = client.list_all_tools().await.expect("list tools");
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    for expected in [
        "start_client",
        "stop_client",
        "list_clients",
        "client_status",
    ] {
        assert!(
            names.contains(&expected),
            "expected tool '{}' in {:?}",
            expected,
            names
        );
    }

    // The client half of list_protocols carries maturity and a description.
    let protocols = call(
        &client,
        "list_protocols",
        serde_json::json!({ "type": "client" }),
    )
    .await;
    let text = text_of(&protocols);
    assert!(
        text.to_lowercase().contains("tcp"),
        "expected tcp client in: {}",
        text
    );
    assert!(
        text.contains("Experimental") || text.contains("Beta") || text.contains("Stable"),
        "expected maturity on client protocols in: {}",
        text
    );

    assert!(
        text_of(&call(&client, "list_clients", serde_json::json!({})).await).contains("No clients")
    );

    // Something to connect to. The `*` -> static-with-no-actions rule is load-bearing,
    // not decoration: without it the server's `tcp_connected` event goes to whatever LLM
    // endpoint this process was started with, and when that call fails the TCP server
    // fails closed by half-closing — so the client reads EOF and moves itself to
    // `Disconnected` before `client_status` is asked. That is correct product behaviour
    // and it raced this test under load. `tests/empty_static_handler_test.rs` measures
    // that an empty static handler suppresses the model call outright, which is what makes
    // the `Connected` assertion below deterministic rather than lucky.
    let no_model = serde_json::json!([
        {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
    ]);
    let started = call(
        &client,
        "start_server",
        serde_json::json!({
            "protocol": "tcp",
            "port": 0,
            "event_handlers": no_model,
        }),
    )
    .await;
    let port = parse_number_after(&text_of(&started), "listening on 127.0.0.1:") as u16;

    // Lowercase protocol names must resolve against the client registry's own casing.
    let connected = call(
        &client,
        "start_client",
        serde_json::json!({
            "protocol": "tcp",
            "remote_addr": format!("127.0.0.1:{}", port),
            "instruction": "no-op",
            "event_handlers": no_model,
        }),
    )
    .await;
    assert_ne!(
        connected.is_error,
        Some(true),
        "start_client errored: {}",
        text_of(&connected)
    );
    let client_id = parse_number_after(&text_of(&connected), "Client #");

    let listed = text_of(&call(&client, "list_clients", serde_json::json!({})).await);
    assert!(
        listed.contains(&format!("Client #{}", client_id)),
        "expected the new client in: {}",
        listed
    );

    let status = text_of(
        &call(
            &client,
            "client_status",
            serde_json::json!({ "client_id": client_id }),
        )
        .await,
    );
    // The whole rendered line, not the bare word: `Disconnected` contains `Connected`, so
    // a substring check here passed on a client that had already read EOF and given up.
    assert!(
        status.contains("- **Status**: Connected\n"),
        "expected a connected client: {}",
        status
    );

    let stopped = call(
        &client,
        "stop_client",
        serde_json::json!({ "client_id": client_id }),
    )
    .await;
    assert_ne!(stopped.is_error, Some(true));

    let missing = call(
        &client,
        "client_status",
        serde_json::json!({ "client_id": client_id }),
    )
    .await;
    assert_eq!(missing.is_error, Some(true), "client should be gone");

    client.cancel().await.expect("shutdown");
}

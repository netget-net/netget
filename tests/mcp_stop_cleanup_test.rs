//! Regression test: stopping a server over MCP must take its scheduled tasks with it.
//!
//! The MCP `stop_server` / `stop_all` tools called `AppState::remove_server()`, which
//! at the time only dropped the map entry — the scheduled-task cleanup lived in the
//! TUI's stop path (`cleanup_server_tasks`) and nowhere else. Server- and
//! connection-scoped tasks therefore outlived the server that owned them and kept
//! firing on their interval, each tick producing an LLM prompt for a server that no
//! longer existed.
//!
//! `remove_server` now owns the whole teardown, so no caller can forget half of it.
//! `tests/server_stop_cleans_scheduled_tasks_test.rs` asserts that from the state API;
//! these tests assert it from the other end — through the actual MCP tool surface, so
//! a future rewrite of `stop_server`/`stop_all` that stops routing through
//! `remove_server` is caught here rather than in production.
//!
//! No Ollama and no real stdio: the tools are driven over an in-process duplex
//! transport, and a bare TCP listener on port 0 is the only network resource used.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,tcp \
//!       --test mcp_stop_cleanup_test -- --test-threads=100

#![cfg(feature = "mcp-stdio")]

use netget::cli::Args;
use netget::mcp_stdio::tools::NetGetMcpService;
use netget::server::connection::ConnectionId;
use netget::settings::Settings;
use netget::state::app_state::AppState;
use netget::state::task::{ScheduledTask, TaskId, TaskScope};
use netget::state::ServerId;

use clap::Parser;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::{serve_client, RoleClient, ServiceExt};

/// An in-process MCP client plus a handle on the very `AppState` the tools mutate
/// (`AppState` is an `Arc`, so this is the live state, not a snapshot).
async fn connect() -> (rmcp::service::RunningService<RoleClient, ()>, AppState) {
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

    let client = serve_client((), client_io).await.expect("client handshake");
    (client, app_state)
}

async fn call(
    client: &rmcp::service::RunningService<RoleClient, ()>,
    name: &'static str,
    args: serde_json::Value,
) -> CallToolResult {
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

/// Start a TCP server on an OS-assigned port carrying one recurring server-scoped
/// task named `task_id`, and return its `ServerId`.
///
/// The interval is deliberately long: the point is that the task is *registered*,
/// not that it runs.
async fn start_server_with_task(
    client: &rmcp::service::RunningService<RoleClient, ()>,
    task_id: &str,
) -> ServerId {
    let started = call(
        client,
        "start_server",
        serde_json::json!({
            "protocol": "tcp",
            "port": 0,
            "scheduled_tasks": [{
                "task_id": task_id,
                "recurring": true,
                "interval_secs": 3600,
                "instruction": "never mind, this must not outlive the server"
            }]
        }),
    )
    .await;
    let text = text_of(&started);
    assert_ne!(
        started.is_error,
        Some(true),
        "start_server errored: {}",
        text
    );

    ServerId::new(parse_number_after(&text, "Server #") as u32)
}

async fn task_names(state: &AppState) -> Vec<String> {
    let mut names: Vec<String> = state
        .get_all_tasks()
        .await
        .into_iter()
        .map(|t| t.name)
        .collect();
    names.sort();
    names
}

/// Attach a connection-scoped task, as the LLM's `schedule_task` action does at
/// runtime. A connection cannot outlive its server, so neither may its tasks.
async fn add_connection_task(state: &AppState, name: &str, server_id: ServerId) {
    state
        .add_task(
            ScheduledTask::new_recurring(
                TaskId::new(0),
                name.to_string(),
                TaskScope::Connection(server_id, ConnectionId::new(7)),
                3600,
                None,
                "tick".to_string(),
                None,
            )
            .unwrap(),
        )
        .await;
}

#[tokio::test]
async fn mcp_stop_server_cancels_that_servers_scheduled_tasks() {
    let (client, state) = connect().await;

    let server_id = start_server_with_task(&client, "doomed-task").await;
    add_connection_task(&state, "doomed-connection-task", server_id).await;

    assert_eq!(
        task_names(&state).await,
        vec![
            "doomed-connection-task".to_string(),
            "doomed-task".to_string()
        ],
        "start_server should have registered the scheduled task"
    );

    let stopped = call(
        &client,
        "stop_server",
        serde_json::json!({ "server_id": server_id.as_u32() }),
    )
    .await;
    assert_ne!(stopped.is_error, Some(true), "stop_server errored");

    assert!(
        state.get_server(server_id).await.is_none(),
        "the server itself must be gone"
    );
    assert!(
        state.get_all_tasks().await.is_empty(),
        "stopping a server over MCP must cancel its server- AND connection-scoped \
         scheduled tasks; leftovers: {:?}",
        task_names(&state).await
    );
    // The name → id mapping has to go too, or the name can never be reused.
    assert!(state.get_task("doomed-task").await.is_none());
    assert!(state.get_task("doomed-connection-task").await.is_none());

    client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn mcp_stop_server_leaves_other_servers_tasks_alone() {
    let (client, state) = connect().await;

    let doomed = start_server_with_task(&client, "doomed-task").await;
    let survivor = start_server_with_task(&client, "surviving-task").await;

    // A global task belongs to no server and must survive any stop.
    state
        .add_task(
            ScheduledTask::new_recurring(
                TaskId::new(0),
                "global-task".to_string(),
                TaskScope::Global,
                3600,
                None,
                "tick".to_string(),
                None,
            )
            .unwrap(),
        )
        .await;

    let stopped = call(
        &client,
        "stop_server",
        serde_json::json!({ "server_id": doomed.as_u32() }),
    )
    .await;
    assert_ne!(stopped.is_error, Some(true), "stop_server errored");

    assert_eq!(
        task_names(&state).await,
        vec!["global-task".to_string(), "surviving-task".to_string()],
        "stopping one server must not touch another server's tasks or global tasks"
    );
    assert!(state.get_server(survivor).await.is_some());

    // Cleaning up the survivor takes its task with it, and leaves the global one.
    let stopped = call(
        &client,
        "stop_server",
        serde_json::json!({ "server_id": survivor.as_u32() }),
    )
    .await;
    assert_ne!(stopped.is_error, Some(true), "stop_server errored");
    assert_eq!(task_names(&state).await, vec!["global-task".to_string()]);

    client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn mcp_stop_all_cancels_every_servers_scheduled_tasks() {
    let (client, state) = connect().await;

    let first = start_server_with_task(&client, "first-task").await;
    let second = start_server_with_task(&client, "second-task").await;
    add_connection_task(&state, "second-connection-task", second).await;

    assert_eq!(state.get_all_tasks().await.len(), 3);

    let stopped = call(&client, "stop_all", serde_json::json!({})).await;
    let text = text_of(&stopped);
    assert_ne!(stopped.is_error, Some(true), "stop_all errored: {}", text);
    assert!(
        text.contains("Stopped 2 server(s)"),
        "unexpected stop_all result: {}",
        text
    );

    assert!(state.get_server(first).await.is_none());
    assert!(state.get_server(second).await.is_none());
    assert!(
        state.get_all_tasks().await.is_empty(),
        "stop_all must cancel every stopped server's scheduled tasks; leftovers: {:?}",
        task_names(&state).await
    );

    client.cancel().await.expect("shutdown");
}

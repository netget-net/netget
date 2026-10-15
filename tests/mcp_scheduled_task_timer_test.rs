//! Regression test: a task scheduled through the MCP path must actually fire.
//!
//! `schedule_task` and `start_server`'s `scheduled_tasks` array both create tasks over
//! the MCP tool surface, but MCP mode had no timer to execute them — `execute_due_tasks`
//! was driven only by the TUI event loop and the non-interactive runner, so a task
//! created over MCP sat at `Scheduled` forever and its instruction never ran. (IMPROVEMENTS
//! item 5; the `--mcp` docs listed "Scheduled tasks never fire" as a known limitation.)
//!
//! `spawn_task_ticker` (in `src/mcp_stdio/tools.rs`) restores the 1s
//! `execute_due_tasks_public` cadence for both transports. This test proves it end to end
//! through the real MCP tools: `start_server` registers a recurring server-scoped task whose
//! instruction the mocked LLM answers with `set_memory`, and the server's memory is asserted
//! to change within a bounded time. If the ticker is removed the memory never changes and the
//! `verify_calls()` at the end sees zero LLM calls instead of at least one.
//!
//! No real Ollama and no real stdio: the tools are driven over an in-process duplex
//! transport, and the LLM is the in-process mock Ollama server.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,tcp \
//!       --test mcp_scheduled_task_timer_test -- --test-threads=100

#![cfg(feature = "mcp-stdio")]
// `mod helpers` compiles the whole shared E2E harness into this binary; this file uses a
// small slice of it (the mock LLM server). Same situation as `tests/feedback_loop_test.rs`.
#![allow(dead_code, unused_imports)]

mod helpers;

use std::time::Duration;

use helpers::mock_builder::MockLlmBuilder;
use helpers::mock_ollama::MockOllamaServer;
use helpers::E2EResult;

use clap::Parser;
use netget::cli::Args;
use netget::mcp_stdio::tools::NetGetMcpService;
use netget::settings::Settings;
use netget::state::app_state::AppState;
use netget::state::ServerId;

use rmcp::model::CallToolRequestParams;
use rmcp::{serve_client, RoleClient, ServiceExt};

/// The value the scheduled task's mocked LLM writes into server memory. Distinctive so the
/// assertion proves *this* action ran, not some incidental memory write.
const MARKER: &str = "scheduled-task-fired-via-mcp-ticker";

/// Bring up an in-process MCP client wired to the given mock-LLM base URL, plus a handle on
/// the very `AppState` the tools mutate (`AppState` is an `Arc`, so this is the live state).
async fn connect(ollama_url: &str) -> (rmcp::service::RunningService<RoleClient, ()>, AppState) {
    // Point NetGet's own LLM client at the mock, pin a model so `ensure_model_selected`
    // never reaches out to `/api/tags`, and drop scripting so the task's action set is the
    // plain action vocabulary the mock answers against.
    let args = Args::parse_from([
        "netget",
        "--ollama-url",
        ollama_url,
        "--model",
        "mock-model",
        "--no-scripts",
    ]);
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
) -> rmcp::model::CallToolResult {
    let mut params = CallToolRequestParams::new(name);
    params.arguments = args.as_object().cloned();
    client.call_tool(params).await.expect("call tool")
}

fn text_of(result: &rmcp::model::CallToolResult) -> String {
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

#[tokio::test]
async fn scheduled_task_created_over_mcp_actually_fires() -> E2EResult<()> {
    // The mock answers the scheduled task's LLM call with a `set_memory` action. The task
    // recurs on a 1s interval, so it may fire several times before we observe the effect —
    // hence `expect_at_least(1)` rather than an exact count.
    let mock_config = MockLlmBuilder::new()
        .on_any()
        .respond_with_actions(serde_json::json!([
            { "type": "set_memory", "value": MARKER }
        ]))
        .expect_at_least(1)
        .and()
        .build();

    let mock = MockOllamaServer::start(mock_config).await?;
    let (client, state) = connect(&mock.base_url()).await;

    // Register the task the only way an MCP caller can: through `start_server`'s
    // `scheduled_tasks` array. This is server-scoped, so its firing targets this server's
    // memory. A short interval keeps the test fast.
    let started = call(
        &client,
        "start_server",
        serde_json::json!({
            "protocol": "tcp",
            "port": 0,
            "scheduled_tasks": [{
                "task_id": "mcp-ticker-probe",
                "recurring": true,
                "interval_secs": 1,
                "instruction": "set the server memory using the set_memory action"
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
    let server_id = ServerId::new(parse_number_after(&text, "Server #") as u32);

    // Before any tick, the task is registered but has not run: memory is still empty.
    assert!(
        state
            .get_memory(server_id)
            .await
            .unwrap_or_default()
            .is_empty(),
        "memory must start empty; the task must not have fired synchronously"
    );

    // Poll for the observable effect. The first fire is ~1s out (recurring `next_execution`
    // is `now + interval_secs`); allow generous headroom for the LLM round trip. If the
    // ticker is missing this loop times out with memory still empty.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if state.get_memory(server_id).await.as_deref() == Some(MARKER) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the scheduled task never fired over MCP: server memory was never set to the \
             marker. This is the defect the MCP task ticker exists to fix."
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Stop the server so the recurring task cannot keep firing while we verify, and so its
    // teardown path (which cancels the scheduled task) is exercised too.
    let stopped = call(
        &client,
        "stop_server",
        serde_json::json!({ "server_id": server_id.as_u32() }),
    )
    .await;
    assert_ne!(stopped.is_error, Some(true), "stop_server errored");

    // The LLM must genuinely have been called — asserts the fire was a real round trip and
    // not an artifact of some other write.
    mock.verify_calls().await?;

    client.cancel().await.expect("shutdown");
    Ok(())
}

//! MCP mode must apply the same startup configuration as every other entry point.
//!
//! `--mcp` / `--mcp-http` return from `cli::run()` before the TUI's and the
//! non-interactive runner's configuration blocks, and `create_shared_state` used
//! to build a bare `AppState::new()`. Every flag below was therefore accepted on
//! the command line and silently ignored — including `--llm-max-concurrent`,
//! which is the one knob that could have worked around the limiter dropping
//! overlapping network requests. Since MCP is the primary headless surface,
//! these assertions are what keep the headless mode configurable at all.
//!
//! No Ollama and no real stdio: the service is constructed and its `AppState`
//! inspected directly.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,tcp \
//!       --test mcp_startup_config_test -- --test-threads=100

#![cfg(feature = "mcp-stdio")]

use clap::Parser;
use netget::cli::Args;
use netget::llm::{DEFAULT_MAX_QUEUED, DEFAULT_QUEUE_TIMEOUT_SECS};
use netget::mcp_stdio::tools::NetGetMcpService;
use netget::settings::Settings;
use netget::state::app_state::{AppState, EventHandlerMode, ScriptingMode, WebSearchMode};

/// Build the MCP service the way `run_mcp_stdio` does and hand back the state
/// its tools mutate.
async fn mcp_state(argv: &[&str]) -> AppState {
    let args = Args::parse_from(argv);
    let service = NetGetMcpService::new(&args, Settings::default())
        .await
        .expect("service creation");
    service.app_state()
}

#[cfg(unix)]
#[tokio::test]
async fn agent_notification_pipe_refuses_existing_files_and_symlinks() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("important-file");
    let link = temp.path().join("link");
    std::fs::write(&file, "keep this content").unwrap();
    symlink(&file, &link).unwrap();
    for path in [&file, &link, &temp.path().to_path_buf()] {
        let args = Args::parse_from([
            "netget",
            "--mcp",
            "--llm-agent",
            "--llm-agent-pipe",
            path.to_str().unwrap(),
        ]);
        let result = NetGetMcpService::new(&args, Settings::default()).await;
        let error = match result {
            Ok(_) => panic!("a non-FIFO notification path must fail startup"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("must be a FIFO"), "{error:#}");
    }
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "keep this content");
}

#[cfg(unix)]
#[tokio::test]
async fn agent_notification_pipe_creates_and_reuses_a_real_fifo() {
    use std::os::unix::fs::FileTypeExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("notifications");
    let args = Args::parse_from([
        "netget",
        "--mcp",
        "--llm-agent",
        "--llm-agent-pipe",
        path.to_str().unwrap(),
    ]);
    for _ in 0..2 {
        NetGetMcpService::new(&args, Settings::default())
            .await
            .expect("FIFO startup");
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_fifo());
    }
}

#[tokio::test]
async fn mcp_honours_llm_max_concurrent() {
    let state = mcp_state(&["netget", "--mcp", "--llm-max-concurrent", "7"]).await;
    let config = state.get_rate_limiter().await.get_config().await;
    assert_eq!(
        config.max_concurrent, 7,
        "--llm-max-concurrent must reach the rate limiter under --mcp"
    );
}

#[tokio::test]
async fn mcp_honours_llm_queue_bounds() {
    let state = mcp_state(&[
        "netget",
        "--mcp",
        "--llm-queue-timeout",
        "9",
        "--llm-max-queued",
        "3",
    ])
    .await;
    let config = state.get_rate_limiter().await.get_config().await;
    assert_eq!(config.queue_timeout_secs, 9);
    assert_eq!(config.max_queued, 3);
}

#[tokio::test]
async fn mcp_honours_token_limit_and_window() {
    let state = mcp_state(&[
        "netget",
        "--mcp",
        "--llm-token-limit",
        "5000",
        "--llm-token-window",
        "30",
    ])
    .await;
    let config = state.get_rate_limiter().await.get_config().await;
    assert_eq!(config.token_limit, Some(5000));
    assert_eq!(config.token_window_secs, 30);
}

/// With no flags MCP must land on the same shipped default as everything else —
/// sequential, but with a bounded queue rather than a drop.
#[tokio::test]
async fn mcp_defaults_match_the_shipped_rate_limiter_defaults() {
    let state = mcp_state(&["netget", "--mcp"]).await;
    let config = state.get_rate_limiter().await.get_config().await;
    assert_eq!(config.max_concurrent, 1);
    assert_eq!(config.queue_timeout_secs, DEFAULT_QUEUE_TIMEOUT_SECS);
    assert_eq!(config.max_queued, DEFAULT_MAX_QUEUED);
}

#[tokio::test]
async fn mcp_honours_no_scripts() {
    let state = mcp_state(&["netget", "--mcp", "--no-scripts"]).await;
    assert_eq!(
        state.get_selected_scripting_mode().await,
        ScriptingMode::Off,
        "--no-scripts must reach AppState under --mcp"
    );
}

#[tokio::test]
async fn mcp_honours_scripting_env() {
    let state = mcp_state(&["netget", "--mcp", "--env", "off"]).await;
    assert_eq!(
        state.get_selected_scripting_mode().await,
        ScriptingMode::Off
    );
}

#[tokio::test]
async fn mcp_honours_event_handler_mode() {
    let state = mcp_state(&["netget", "--mcp", "--handler", "static"]).await;
    assert_eq!(
        state.get_event_handler_mode().await,
        EventHandlerMode::Static,
        "--handler must reach AppState under --mcp"
    );
}

#[tokio::test]
async fn mcp_honours_include_disabled_protocols() {
    let state = mcp_state(&["netget", "--mcp", "--include-disabled-protocols"]).await;
    assert!(
        state.get_include_disabled_protocols().await,
        "--include-disabled-protocols must reach AppState under --mcp"
    );

    let default_state = mcp_state(&["netget", "--mcp"]).await;
    assert!(!default_state.get_include_disabled_protocols().await);
}

/// ASK needs a terminal to prompt on, which MCP does not have; the
/// non-interactive runner degrades it to OFF and MCP must do the same rather
/// than leaving a mode that can only hang.
#[tokio::test]
async fn mcp_never_selects_ask_web_search_mode() {
    let state = mcp_state(&["netget", "--mcp"]).await;
    assert_ne!(state.get_web_search_mode().await, WebSearchMode::Ask);
}

#[tokio::test]
async fn background_ticker_stops_when_the_last_service_clone_is_dropped() {
    use netget::state::task::{ScheduledTask, TaskId, TaskScope, TaskStatus};
    use netget::state::ServerId;
    use std::time::Duration;
    let args = Args::parse_from(["netget", "--mcp", "--llm-agent"]);
    let service = NetGetMcpService::new(&args, Settings::default())
        .await
        .unwrap();
    let state = service.app_state();
    let last_owner = service.clone();
    drop(service);
    let task = |name: &str| {
        ScheduledTask::new_one_shot(
            TaskId::new(0),
            name.into(),
            TaskScope::Server(ServerId::new(u32::MAX)),
            0,
            "unused: owner does not exist".into(),
            None,
        )
        .unwrap()
    };
    state.add_task(task("live-owner")).await;
    // The owner does not exist, so a tick fails the task and removes it: either outcome
    // shows the ticker ran.
    tokio::time::timeout(Duration::from_secs(3), async {
        while state
            .get_task("live-owner")
            .await
            .is_some_and(|t| t.status == TaskStatus::Scheduled)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a retained service clone must keep its ticker running");
    drop(last_owner);
    state.add_task(task("no-owner")).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        state.get_task("no-owner").await.unwrap().status,
        TaskStatus::Scheduled,
        "retaining AppState alone must not retain the MCP background loops"
    );
}

#[tokio::test]
async fn closing_service_cancels_its_execution_but_preserves_other_owners_and_definitions() {
    use netget::state::task::{ScheduledTask, TaskId, TaskScope, TaskStatus};
    use std::time::Duration;
    let args = Args::parse_from(["netget", "--mcp", "--llm-agent"]);
    let service = NetGetMcpService::new(&args, Settings::default())
        .await
        .unwrap();
    let state = service.app_state();
    let make_task = |name: &str| {
        ScheduledTask::new_one_shot(
            TaskId::new(0),
            name.into(),
            TaskScope::Global,
            0,
            "wait for local agent answer".into(),
            None,
        )
        .unwrap()
    };
    let external = state.add_task(make_task("external-owner")).await;
    state
        .update_task_status(external, TaskStatus::Executing)
        .await;
    let (release, gate) = tokio::sync::oneshot::channel();
    let (done, completed) = tokio::sync::oneshot::channel();
    assert!(
        state
            .spawn_scheduled_task(external, async {
                let _ = gate.await;
                let _ = done.send(());
            })
            .await
    );
    state.add_task(make_task("mcp-owner")).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while state.get_task("mcp-owner").await.unwrap().status == TaskStatus::Scheduled {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    drop(service);
    tokio::time::timeout(Duration::from_secs(2), async {
        while state.get_task("mcp-owner").await.unwrap().status == TaskStatus::Executing {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("closing service must cancel its already launched execution");
    assert_eq!(
        state.get_task("mcp-owner").await.unwrap().status,
        TaskStatus::Failed("execution owner closed".into())
    );
    release
        .send(())
        .expect("an externally owned task must still be alive");
    completed.await.unwrap();
    assert!(state.get_task("external-owner").await.is_some());
}

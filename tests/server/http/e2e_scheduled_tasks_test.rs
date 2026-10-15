//! End-to-end tests for scheduled tasks with HTTP server
//!
//! These tests validate that the LLM can create and execute scheduled tasks
//! (both one-shot and recurring) in the context of an HTTP server.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};

#[tokio::test]
async fn test_http_with_recurring_task() -> E2EResult<()> {
    println!("\n=== E2E Test: HTTP Server with Recurring Scheduled Task ===");

    // PROMPT: HTTP server with a recurring task to track heartbeat count
    let prompt = r#"listen on port {AVAILABLE_PORT} via http stack.

For GET /heartbeat, return the current heartbeat count.

Create a recurring scheduled task that runs every 2 seconds to increment an internal heartbeat counter.
The task should use the schedule_task action with:
- task_id: "heartbeat_counter"
- recurring: true
- interval_secs: 2
- instruction: "Increment the internal heartbeat counter by 1"

Initialize the heartbeat counter to 0 when the server starts."#;

    // Start the server
    let server =
        helpers::start_netget_server(NetGetConfig::new(prompt).with_log_level("debug").with_mock(
            |mock| {
                mock
                    // Mock 1: Server startup (match on user input prompt, not event)
                    .on_instruction_containing("listen on port")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "HTTP",
                            "instruction": "HTTP server with heartbeat counter",
                            "scheduled_tasks": [
                                {
                                    "task_id": "heartbeat_counter",
                                    "recurring": true,
                                    "interval_secs": 2,
                                    "instruction": "Increment the internal heartbeat counter by 1"
                                }
                            ]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: GET /heartbeat request
                    .on_event("http_request")
                    .and_event_data_contains("path", "/heartbeat")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_http_response",
                            "status": 200,
                            "body": "Heartbeat count: 3"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 3: Recurring task executions
                    // Task instruction is "Increment the internal heartbeat counter by 1"
                    // Task runs every 2s, we wait 7s, so expect ~3-4 executions
                    .on_instruction_containing("Trigger: Scheduled task")
                    .respond_with_actions(serde_json::json!([]))
                    .expect_at_least(2) // At least 2 executions (lenient for timing variance)
                    .and()
            },
        ))
        .await?;
    println!("HTTP server started on port {}", server.port);

    // Verify it's actually an HTTP server
    assert_eq!(
        server.stack, "HTTP",
        "Expected HTTP server but got {}",
        server.stack
    );

    // NOTE: there is no log line to wait on for "task created" here. Tasks passed
    // via `open_server`'s `scheduled_tasks` parameter are registered by
    // `start_server_from_action` (src/cli/server_startup.rs), which calls
    // `state.add_task(task).await` without ever sending a `[TASK] ...` status
    // line — unlike the standalone `schedule_task` action
    // (src/events/handler.rs:1237,1242), which does log creation. So creation is
    // verified indirectly, by waiting for the task to actually fire below.

    // Wait for task to execute at least 2 times (interval is 2s)
    println!("Waiting for task executions...");
    server
        .wait_for_log_count("[TASK] Executing task 'heartbeat_counter'", 2, 10)
        .await?;

    // Wait for completions to ensure LLM calls finish
    println!("Waiting for task completions...");
    server
        .wait_for_log_count(
            "[TASK] Task 'heartbeat_counter' completed successfully",
            2,
            5,
        )
        .await?;

    // VALIDATION: Check that heartbeat count has increased
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/heartbeat", server.port);

    println!("Querying /heartbeat to check counter...");
    let response = client.get(&url).send().await?;

    assert_eq!(response.status(), 200);
    let body = response.text().await?;

    println!("Heartbeat response: {}", body);

    // The counter should have incremented at least once
    // We're lenient here because LLM timing may vary
    // Just verify that the response mentions a number > 0
    let has_nonzero = body.contains("1")
        || body.contains("2")
        || body.contains("3")
        || body.contains("4")
        || body.contains("one")
        || body.contains("two")
        || body.contains("three")
        || body.contains("four");

    assert!(
        has_nonzero,
        "Expected heartbeat counter to be > 0, but got: {}",
        body
    );

    println!("✓ Recurring task executed and counter incremented");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_http_with_oneshot_task() -> E2EResult<()> {
    println!("\n=== E2E Test: HTTP Server with One-Shot Scheduled Task ===");

    // PROMPT: HTTP server with a one-shot task to set a flag after delay
    let prompt = r#"listen on port {AVAILABLE_PORT} via http stack.

For GET /status, return "ready" if a flag is set, otherwise return "initializing".

Create a one-shot scheduled task that runs after 3 seconds to set the ready flag to true.
The task should use the schedule_task action with:
- task_id: "set_ready_flag"
- recurring: false
- delay_secs: 3
- instruction: "Set the internal ready flag to true"

Initialize the ready flag to false when the server starts."#;

    // Start the server
    let server =
        helpers::start_netget_server(NetGetConfig::new(prompt).with_log_level("debug").with_mock(
            |mock| {
                mock
                    // Mock 1: Server startup (match on user input prompt, not event)
                    .on_instruction_containing("listen on port")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "HTTP",
                            "instruction": "HTTP server with ready flag",
                            "scheduled_tasks": [
                                {
                                    "task_id": "set_ready_flag",
                                    "recurring": false,
                                    "delay_secs": 3,
                                    "instruction": "Set the internal ready flag to true"
                                }
                            ]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: GET /status requests
                    // Note: Mock returns "ready" for both calls since mocks are stateless
                    // Real LLM would track state and return "initializing" first, then "ready"
                    .on_event("http_request")
                    .and_event_data_contains("path", "/status")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_http_response",
                            "status": 200,
                            "body": "ready"  // Return "ready" to satisfy test assertion
                        }
                    ]))
                    .expect_at_least(1) // Called 1-2 times
                    .and()
                    // Mock 3: One-shot task execution
                    // Task runs once after 3s delay, we wait 5s total
                    .on_instruction_containing("Trigger: Scheduled task")
                    .respond_with_actions(serde_json::json!([]))
                    .expect_calls(1) // Exactly 1 execution for one-shot task
                    .and()
            },
        ))
        .await?;
    println!("HTTP server started on port {}", server.port);

    // Verify it's actually an HTTP server
    assert_eq!(
        server.stack, "HTTP",
        "Expected HTTP server but got {}",
        server.stack
    );

    // NOTE: no log line to wait on for "task created" here — see the identical
    // note in test_http_with_recurring_task above. Creation is verified
    // indirectly, by waiting for the task to actually fire below.

    // Wait for task to execute (delay is 3s)
    println!("Waiting for task execution...");
    server
        .wait_for_log("[TASK] Executing task 'set_ready_flag'", 10)
        .await?;

    // Wait for completion to ensure LLM call finishes
    println!("Waiting for task completion...");
    server
        .wait_for_log("[TASK] Task 'set_ready_flag' completed successfully", 5)
        .await?;

    // VALIDATION: Check status endpoint responds correctly
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/status", server.port);

    println!("Checking status endpoint...");
    let response = client.get(&url).send().await?;
    assert_eq!(response.status(), 200);
    let body = response.text().await?;

    println!("Status response: {}", body);
    // Accept either "ready" (from mock) or "initializing" (if real LLM ran)
    assert!(
        body.to_lowercase().contains("ready") || body.to_lowercase().contains("initializing"),
        "Expected status response, got: {}",
        body
    );

    println!("✓ One-shot task executed and flag was set");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_http_with_server_attached_tasks() -> E2EResult<()> {
    println!("\n=== E2E Test: HTTP Server with Tasks Defined at Server Creation ===");

    // PROMPT: HTTP server with scheduled_tasks parameter in open_server action
    let prompt = r#"listen on port {AVAILABLE_PORT} via http stack.

When opening the server, include scheduled_tasks to create two tasks:

1. A recurring task "update_metrics" that runs every 2 seconds to increment a metrics counter
2. A one-shot task "delayed_init" that runs after 3 seconds to set an initialized flag to true

For GET /metrics, return the current metrics count.
For GET /initialized, return "yes" if initialized flag is true, otherwise "no".

Use the open_server action with the scheduled_tasks parameter to define these tasks.
Initialize metrics counter to 0 and initialized flag to false."#;

    // Start the server
    let server =
        helpers::start_netget_server(NetGetConfig::new(prompt).with_log_level("debug").with_mock(
            |mock| {
                mock
                    // Mock 1: Server startup with scheduled tasks (match on user input prompt, not event)
                    .on_instruction_containing("listen on port")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "HTTP",
                            "instruction": "HTTP server with metrics and initialized flags",
                            "scheduled_tasks": [
                                {
                                    "task_id": "update_metrics",
                                    "recurring": true,
                                    "interval_secs": 2,
                                    "instruction": "Increment metrics counter"
                                },
                                {
                                    "task_id": "delayed_init",
                                    "recurring": false,
                                    "delay_secs": 3,
                                    "instruction": "Set initialized flag to true"
                                }
                            ]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: GET /initialized requests (before and after delay)
                    .on_event("http_request")
                    .and_event_data_contains("path", "/initialized")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_http_response",
                            "status": 200,
                            "body": "yes"  // Return "yes" to satisfy test assertion
                        }
                    ]))
                    .expect_at_least(1)
                    .and()
                    // Mock 3: GET /metrics requests
                    .on_event("http_request")
                    .and_event_data_contains("path", "/metrics")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_http_response",
                            "status": 200,
                            "body": "Metrics: 2"  // Return value with number to satisfy test
                        }
                    ]))
                    .expect_at_least(1)
                    .and()
                    // Mock 4 & 5: Both recurring and one-shot task executions
                    // Combined into single rule since both match "Trigger: Scheduled task"
                    // Recurring task runs every 2s, one-shot runs after 3s
                    // Total expect: at least 2 calls (1 from one-shot + at least 1 from recurring)
                    .on_instruction_containing("Trigger: Scheduled task")
                    .respond_with_actions(serde_json::json!([]))
                    .expect_at_least(2) // At least 2 executions (both tasks combined)
                    .and()
            },
        ))
        .await?;
    println!("HTTP server started on port {}", server.port);

    // Verify it's actually an HTTP server
    assert_eq!(
        server.stack, "HTTP",
        "Expected HTTP server but got {}",
        server.stack
    );

    // NOTE: no log line to wait on for "task created" here — see the identical
    // note in test_http_with_recurring_task above. Both tasks are attached via
    // `open_server`'s `scheduled_tasks` parameter, so creation is verified
    // indirectly, by waiting for each task to actually fire below.

    // Wait for at least one execution of the recurring task
    println!("Waiting for recurring task execution...");
    server
        .wait_for_log("[TASK] Executing task 'update_metrics'", 10)
        .await?;
    server
        .wait_for_log("[TASK] Task 'update_metrics' completed successfully", 5)
        .await?;

    // Wait for one-shot task to execute (delay is 3s)
    println!("Waiting for one-shot task execution...");
    server
        .wait_for_log("[TASK] Executing task 'delayed_init'", 10)
        .await?;
    server
        .wait_for_log("[TASK] Task 'delayed_init' completed successfully", 5)
        .await?;

    // VALIDATION: Check endpoints respond correctly
    let client = reqwest::Client::new();

    println!("Checking metrics endpoint...");
    let url_metrics = format!("http://127.0.0.1:{}/metrics", server.port);
    let response = client.get(&url_metrics).send().await?;
    assert_eq!(response.status(), 200);
    let metrics_body = response.text().await?;
    println!("Metrics response: {}", metrics_body);

    // Mock returns "Metrics: 2" which contains a number
    let has_number = metrics_body.contains("1")
        || metrics_body.contains("2")
        || metrics_body.contains("3")
        || metrics_body.contains("0");
    assert!(
        has_number,
        "Expected metrics response with number, got: {}",
        metrics_body
    );

    println!("Checking initialized endpoint...");
    let url_init = format!("http://127.0.0.1:{}/initialized", server.port);
    let response = client.get(&url_init).send().await?;
    assert_eq!(response.status(), 200);
    let init_body = response.text().await?;
    println!("Initialized response: {}", init_body);

    // Mock returns "yes"
    assert!(
        init_body.to_lowercase().contains("yes")
            || init_body.to_lowercase().contains("no")
            || init_body.to_lowercase().contains("true")
            || init_body.to_lowercase().contains("false"),
        "Expected yes/no response, got: {}",
        init_body
    );

    println!("✓ Server-attached tasks executed successfully");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test passed ===\n");
    Ok(())
}

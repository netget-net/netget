//! Scheduled tasks: what each scope is offered, what its prompt says, and that its actions
//! run where they can actually take effect.
//!
//! Three defects are pinned here.
//!
//! 1. **The set offered and the set validated must be one list.** `execute_single_task` once
//!    handed `ConversationHandler` an empty list while the prompt advertised a real one, so
//!    every action a task returned was "unknown". `PromptBuilder::task_action_set` is now
//!    computed once and both halves use it; these tests read the advertised names back out
//!    of the rendered prompt and compare.
//! 2. **A task is not a network event and not an operator command.** Server- and
//!    connection-scoped tasks rendered `network_request/main` ("You are being invoked in
//!    response to a network event"), client and global tasks `user_input/main` ("You are an
//!    API that interprets user commands"). Every scope now renders `scheduled_task/main`, and
//!    its Required Format example is an action the task was actually offered.
//! 3. **A protocol action must run inside the instance.** A client-scoped task's protocol
//!    actions were executed with no protocol in context, so each failed as "unknown action
//!    type and no protocol in context" — and the task was still reported "completed
//!    successfully", because the executor records failures rather than returning them. A
//!    server-scoped `send_tcp_data` produced bytes no connection wrote. Protocol actions now
//!    go through `send_to_client` / `send_to_peer`, and a failed action fails the task.
//!
//! Run with:
//!   ./cargo-isolated.sh test --test scheduled_task_actions_test -- --test-threads=32

#![allow(dead_code, unused_imports)]

mod helpers;

use std::collections::BTreeSet;
use std::time::Duration;

use helpers::mock_builder::MockLlmBuilder;
use helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::{ClientForm, ServerForm};
use netget::llm::PromptBuilder;
use netget::state::app_state::{AppState, ScriptingMode};
use netget::state::server::{ServerInstance, ServerStatus};
use netget::state::{ClientId, ScheduledTask, ServerId, TaskId, TaskScope};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Extract the action names the prompt advertises: the shared actions partial renders each
/// as a numbered heading, `## <n>. <action_name>`.
fn advertised_action_names(prompt: &str) -> BTreeSet<String> {
    prompt
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("## ")?;
            let (index, name) = rest.split_once(". ")?;
            if index.parse::<u32>().is_err() {
                return None;
            }
            let name = name.trim();
            if name.is_empty() || name.contains(' ') {
                None
            } else {
                Some(name.to_string())
            }
        })
        .collect()
}

/// The `type` of the Required Format example under `# Response Format`.
fn response_format_example_type(prompt: &str) -> String {
    let section = &prompt[prompt
        .find("# Response Format")
        .expect("task prompt has a Response Format section")..];
    let start = section.find("{\"actions\": [").expect("an actions example");
    let line = section[start..].lines().next().unwrap();
    let value: serde_json::Value = serde_json::from_str(line).expect("example is JSON");
    value["actions"][0]["type"]
        .as_str()
        .expect("example action has a type")
        .to_string()
}

/// What every task prompt must say, and must not.
fn assert_task_preamble(prompt: &str, scope_label: &str) {
    assert!(
        prompt.contains("A scheduled task has fired"),
        "task preamble missing:\n{prompt}"
    );
    assert!(
        prompt.contains(&format!("**Scope:** {scope_label}")),
        "scope {scope_label:?} not stated:\n{prompt}"
    );
    // The network-request template's framing. (Action descriptions such as open_server's
    // legitimately mention network events; the task's own framing must not claim one.)
    for phrase in [
        "in response to a network event",
        "You are handling a network event",
        "Your response completes this event",
    ] {
        assert!(
            !prompt.contains(phrase),
            "a task prompt must not say {phrase:?}:\n{prompt}"
        );
    }
    assert!(
        !prompt.contains("interprets user commands"),
        "a task prompt must not use the user-input preamble:\n{prompt}"
    );
    assert!(prompt.contains("\n\nTrigger: Scheduled task '"));
}

/// Render a task's prompt the way `execute_single_task` does, and check the invariants that
/// hold for every scope. Returns the prompt and the offered names.
async fn render(
    state: &AppState,
    task: &ScheduledTask,
    scope_label: &str,
) -> (String, BTreeSet<String>) {
    let set = PromptBuilder::task_action_set(state, task).await;
    let prompt = PromptBuilder::build_task_execution_prompt(state, task, &set).await;
    let offered: BTreeSet<String> = set.actions.iter().map(|a| a.name.clone()).collect();

    assert_task_preamble(&prompt, scope_label);
    assert!(!offered.is_empty());
    assert_eq!(
        offered,
        advertised_action_names(&prompt),
        "the prompt must advertise exactly the actions the task is validated against"
    );
    let example = response_format_example_type(&prompt);
    assert!(
        offered.contains(&example),
        "the Required Format example uses `{example}`, which this task is not offered"
    );
    (prompt, offered)
}

async fn plain_state() -> AppState {
    let state = AppState::new();
    state
        .set_scripting_env(netget::scripting::ScriptingEnvironment {
            python: None,
            javascript: None,
            go: None,
            perl: None,
        })
        .await;
    state.set_selected_scripting_mode(ScriptingMode::Off).await;
    state
}

#[tokio::test]
async fn global_task_prompt_offers_operator_actions_and_no_untargeted_ones() {
    let state = plain_state().await;
    let task = ScheduledTask::new_one_shot(
        TaskId::new(1),
        "startup".to_string(),
        TaskScope::Global,
        5,
        "Open a TCP server on an available port".to_string(),
        None,
    )
    .unwrap();

    let (prompt, offered) = render(&state, &task, "global").await;
    for name in [
        "open_server",
        "close_server",
        "open_client",
        "schedule_task",
        "show_message",
    ] {
        assert!(offered.contains(name), "global task must be offered {name}");
    }
    // With no instance in scope these fall through to "the first server".
    for name in [
        "set_memory",
        "append_memory",
        "append_to_log",
        "update_instruction",
    ] {
        assert!(
            !offered.contains(name),
            "global task must not be offered {name}"
        );
    }
    assert!(prompt.contains("No servers are running."));
}

#[tokio::test]
async fn server_task_prompt_without_live_peers_offers_no_protocol_actions() {
    let state = plain_state().await;
    let mut server = ServerInstance::new(
        ServerId::new(1),
        9999,
        "Tcp".to_string(),
        "Echo everything".to_string(),
    );
    server.status = ServerStatus::Running;
    server.memory = "line one\nline two".to_string();
    let server_id = state.add_server(server).await;

    let task = ScheduledTask::new_recurring(
        TaskId::new(1),
        "heartbeat".to_string(),
        TaskScope::Server(server_id),
        60,
        None,
        "Log a heartbeat message".to_string(),
        None,
    )
    .unwrap();

    let (prompt, offered) = render(&state, &task, &format!("server #{}", server_id.as_u32())).await;
    assert!(offered.contains("set_memory"));
    assert!(offered.contains("append_to_log"));
    assert!(
        !offered.contains("send_tcp_data"),
        "no connection can run a protocol action, so none may be offered"
    );
    assert!(prompt.contains("No protocol actions are offered"));
    assert!(
        prompt.contains("Echo everything"),
        "instance instruction shown"
    );
    assert!(
        prompt.contains("```text\nline one\nline two\n```"),
        "multi-line memory is fenced:\n{prompt}"
    );
}

#[tokio::test]
async fn client_task_prompt_without_command_channel_offers_no_protocol_actions() {
    let state = plain_state().await;
    let client_id = state
        .add_client(netget::state::client::ClientInstance::new(
            ClientId::new(1),
            "127.0.0.1:9".to_string(),
            "tcp".to_string(),
            "Say hello".to_string(),
        ))
        .await;
    let task = ScheduledTask::new_one_shot(
        TaskId::new(1),
        "ping".to_string(),
        TaskScope::Client(client_id),
        5,
        "Send a ping".to_string(),
        None,
    )
    .unwrap();

    let (prompt, offered) = render(&state, &task, &format!("client #{}", client_id.as_u32())).await;
    assert!(offered.contains("set_memory"));
    assert!(
        !offered.contains("append_to_log"),
        "append_to_log writes to a server's log, never a client's"
    );
    assert!(!offered.contains("send_tcp_data"));
    assert!(prompt.contains("No protocol actions are offered"));
}

// ---------------------------------------------------------------------------------------------
// End to end: the model answers the task, and the answer reaches the wire.
// ---------------------------------------------------------------------------------------------

async fn mock_state(base_url: &str) -> (AppState, netget::llm::OllamaClient) {
    let state = AppState::new_with_options(false, base_url.to_string());
    let llm = netget::llm::OllamaClient::new(base_url.to_string());
    state.set_llm_client(llm.clone()).await;
    state.set_ollama_model(Some("mock-model".to_string())).await;
    state.set_selected_scripting_mode(ScriptingMode::Off).await;
    (state, llm)
}

/// Every event of an instance answered with nothing, so the only model call is the task's.
fn silent_routing() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "event_pattern": "*",
        "handler": {"type": "static", "actions": []}
    })]
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..300 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("client #{} never registered a command handle", id.as_u32());
}

/// Fire every due task once, the way the 1s ticker does.
async fn fire(
    state: &AppState,
    llm: &netget::llm::OllamaClient,
) -> mpsc::UnboundedReceiver<String> {
    let (tx, rx) = mpsc::unbounded_channel();
    netget::cli::execute_due_tasks_public(state, llm, &tx).await;
    rx
}

/// Drain status lines until one contains `needle`, or panic.
async fn wait_for_status(rx: &mut mpsc::UnboundedReceiver<String>, needle: &str) -> Vec<String> {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(line)) => {
                let hit = line.contains(needle);
                seen.push(line);
                if hit {
                    return seen;
                }
            }
            _ => panic!("no status line containing {needle:?}; saw {seen:#?}"),
        }
    }
}

/// A TCP client connected to a plain local listener, with a one-shot task due now.
async fn client_with_task(
    state: &AppState,
    llm: &netget::llm::OllamaClient,
    task_name: &str,
) -> (tokio::net::TcpStream, ClientId) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "tcp".to_string(),
        remote_addr: Some(addr.to_string()),
        instruction: Some("A TCP client.".to_string()),
        event_handlers: Some(silent_routing()),
        ..Default::default()
    }
    .create(state, llm.clone(), tx)
    .await
    .expect("create tcp client");
    let (peer, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client connects")
        .unwrap();
    wait_for_client_handle(state, client_id).await;

    state
        .add_task(
            ScheduledTask::new_one_shot(
                TaskId::new(0),
                task_name.to_string(),
                TaskScope::Client(client_id),
                0,
                "Send the word probe to the server.".to_string(),
                None,
            )
            .unwrap(),
        )
        .await;
    (peer, client_id)
}

#[tokio::test]
async fn client_task_protocol_action_reaches_the_wire() -> helpers::E2EResult<()> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_instruction_containing("client-wire-probe")
            .respond_with_actions(serde_json::json!([
                {"type": "send_tcp_data", "data": "probe-from-task\n"}
            ]))
            .expect_calls(1)
            .and()
            .build(),
    )
    .await?;
    let (state, llm) = mock_state(&mock.base_url()).await;
    let (mut peer, _client_id) = client_with_task(&state, &llm, "client-wire-probe").await;

    let mut rx = fire(&state, &llm).await;

    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut buf))
        .await
        .expect("the task's send_tcp_data never reached the listener")?;
    assert_eq!(&buf[..n], b"probe-from-task\n");

    let seen = wait_for_status(&mut rx, "completed").await;
    assert!(
        !seen.iter().any(|l| l.contains("failed")),
        "a task whose action went out must not report failure: {seen:#?}"
    );
    assert!(
        state.get_task("client-wire-probe").await.is_none(),
        "a completed one-shot task is removed"
    );
    mock.verify_calls().await?;
    Ok(())
}

#[tokio::test]
async fn a_failing_task_action_fails_the_task() -> helpers::E2EResult<()> {
    // `zz` is not hex: the client's own executor refuses the action, so nothing is sent and
    // the task must say it failed rather than "completed successfully". (The TCP client reads
    // hex from `data_hex`.)
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_instruction_containing("client-reject-probe")
            .respond_with_actions(serde_json::json!([
                {"type": "send_tcp_data", "data_hex": "zz"}
            ]))
            .expect_calls(1)
            .and()
            .build(),
    )
    .await?;
    let (state, llm) = mock_state(&mock.base_url()).await;
    let (_peer, _client_id) = client_with_task(&state, &llm, "client-reject-probe").await;

    let mut rx = fire(&state, &llm).await;
    let seen = wait_for_status(&mut rx, "failed").await;
    assert!(
        !seen.iter().any(|l| l.contains("completed")),
        "a task whose only action failed must not report completion: {seen:#?}"
    );

    let task = state
        .get_task("client-reject-probe")
        .await
        .expect("a failed task stays scheduled for its retry");
    assert_eq!(task.failure_count, 1);
    let error = task
        .last_error
        .expect("the failure is recorded on the task");
    assert!(
        error.contains("send_tcp_data") && error.contains("1 of 1"),
        "the recorded error names the failed action: {error}"
    );
    mock.verify_calls().await?;
    Ok(())
}

#[tokio::test]
async fn connection_task_protocol_action_reaches_its_peer() -> helpers::E2EResult<()> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_instruction_containing("conn-wire-probe")
            .respond_with_actions(serde_json::json!([
                {"type": "send_tcp_data", "data": "hello-from-task\n"}
            ]))
            .expect_calls(1)
            .and()
            .build(),
    )
    .await?;
    let (state, llm) = mock_state(&mock.base_url()).await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "tcp".to_string(),
        port: Some(0),
        instruction: Some("A TCP server.".to_string()),
        event_handlers: Some(silent_routing()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create tcp server");

    let mut port = 0;
    for _ in 0..100 {
        if let Some(s) = state.get_server(server_id).await {
            port = s.local_addr.map(|a| a.port()).unwrap_or(s.port);
            if port != 0 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let mut peer = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;

    // The connection, once it has registered a peer handle.
    let mut conn = None;
    for _ in 0..300 {
        if let Some(s) = state.get_server(server_id).await {
            for id in s.connections.keys() {
                if state.has_peer_handle(server_id, id.as_u32()).await {
                    conn = Some(*id);
                }
            }
        }
        if conn.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let conn = conn.expect("the TCP connection registers a peer handle");

    let task = ScheduledTask::new_one_shot(
        TaskId::new(0),
        "conn-wire-probe".to_string(),
        TaskScope::Connection(server_id, conn),
        0,
        "Greet this peer.".to_string(),
        None,
    )
    .unwrap();
    let (prompt, offered) = render(
        &state,
        &task,
        &format!("connection {} on server #{}", conn, server_id.as_u32()),
    )
    .await;
    assert!(
        offered.contains("send_tcp_data"),
        "a live peer's actions are offered"
    );
    assert_eq!(response_format_example_type(&prompt), "send_tcp_data");
    state.add_task(task).await;

    let mut rx = fire(&state, &llm).await;
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(30), peer.read(&mut buf))
        .await
        .expect("the task's send_tcp_data never reached the peer")?;
    assert_eq!(&buf[..n], b"hello-from-task\n");
    wait_for_status(&mut rx, "completed").await;
    mock.verify_calls().await?;

    let _ = peer.shutdown().await;
    Ok(())
}

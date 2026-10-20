//! What a feedback answer is allowed to do, and that it actually does it.
//!
//! A feedback batch belongs to one instance and runs unattended off a timer. Its answer used
//! to be executed with the whole operator vocabulary: `update_server` fell through to the
//! plain executor's "must be handled by caller" arm and vanished with no failure recorded,
//! `close_all_servers` really ran, and `update_client_instruction` with any client id rewrote
//! the *server's* instruction. These tests drive `feedback::apply_feedback_actions` directly,
//! in process, against instances registered in an `AppState`.
//!
//! ```bash
//! ./cargo-isolated.sh test --test feedback_actions_test
//! ```

use netget::llm::feedback::{apply_feedback_actions, get_feedback_actions, FeedbackTarget};
use netget::llm::OllamaClient;
use netget::state::app_state::AppState;
use netget::state::client::ClientInstance;
use netget::state::server::ServerInstance;
use netget::state::{ClientId, ServerId};
use serde_json::json;
use tokio::sync::mpsc;

async fn tcp_server(state: &AppState, instruction: &str) -> ServerId {
    let mut instance = ServerInstance::new(
        ServerId::new(0),
        0,
        "tcp".to_string(),
        instruction.to_string(),
    );
    instance.feedback_instructions = Some("adjust when peers complain".into());
    state.add_server(instance).await
}

/// No model is ever called by these actions; the client exists only to satisfy the signature.
fn unused_llm() -> OllamaClient {
    OllamaClient::new("http://127.0.0.1:9")
}

fn drain(rx: &mut mpsc::UnboundedReceiver<String>) -> Vec<String> {
    let mut lines = Vec::new();
    while let Ok(line) = rx.try_recv() {
        lines.push(line);
    }
    lines
}

#[tokio::test]
async fn update_server_from_feedback_changes_handlers_and_history_in_place() {
    let state = AppState::new();
    let sid = tcp_server(&state, "echo").await;
    let (tx, mut rx) = mpsc::unbounded_channel();

    let outcome = apply_feedback_actions(
        &state,
        &unused_llm(),
        &tx,
        FeedbackTarget::Server(sid),
        vec![json!({
            "type": "update_server",
            "server_id": sid.as_u32(),
            "event_handlers": [{
                "event_pattern": "tcp_data_received",
                "handler": {"type": "static", "actions": []}
            }],
            "history": 5
        })],
    )
    .await;

    assert!(
        outcome.failures.is_empty(),
        "{:?} / {:?}",
        outcome,
        drain(&mut rx)
    );
    let server = state.get_server(sid).await.expect("server still exists");
    let handlers = server
        .event_handler_config
        .expect("event_handlers must have been applied");
    assert_eq!(handlers.handlers.len(), 1);
    assert_eq!(server.history_entries, 5, "history must have been applied");
}

#[tokio::test]
async fn update_server_without_an_id_targets_this_server() {
    let state = AppState::new();
    let sid = tcp_server(&state, "echo").await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let outcome = apply_feedback_actions(
        &state,
        &unused_llm(),
        &tx,
        FeedbackTarget::Server(sid),
        vec![json!({"type": "update_server", "history": 0})],
    )
    .await;

    assert!(outcome.failures.is_empty(), "{outcome:?}");
    assert_eq!(state.get_server(sid).await.unwrap().history_entries, 0);
}

#[tokio::test]
async fn actions_outside_the_feedback_set_are_refused_and_recorded() {
    let state = AppState::new();
    let other = tcp_server(&state, "the other server").await;
    let sid = tcp_server(&state, "echo").await;
    let (tx, mut rx) = mpsc::unbounded_channel();

    let outcome = apply_feedback_actions(
        &state,
        &unused_llm(),
        &tx,
        FeedbackTarget::Server(sid),
        vec![
            json!({"type": "close_all_servers"}),
            json!({"type": "close_server", "server_id": other.as_u32()}),
            json!({"type": "create_database", "name": "x"}),
        ],
    )
    .await;

    assert_eq!(outcome.failures.len(), 3, "{outcome:?}");
    assert!(outcome.applied.is_empty(), "{outcome:?}");
    assert!(state.get_server(sid).await.is_some(), "server was closed");
    assert!(state.get_server(other).await.is_some(), "server was closed");

    let lines = drain(&mut rx);
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("[WARN] Feedback adjustment for server #")
                && l.contains("close_all_servers")),
        "the refusal must be reported: {lines:?}"
    );
}

#[tokio::test]
async fn foreign_ids_and_restarting_fields_touch_nothing() {
    let state = AppState::new();
    let other = tcp_server(&state, "the other server").await;
    let sid = tcp_server(&state, "echo").await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let outcome = apply_feedback_actions(
        &state,
        &unused_llm(),
        &tx,
        FeedbackTarget::Server(sid),
        vec![
            // Used to rewrite the SERVER's instruction, whatever client id it named.
            json!({"type": "update_client_instruction", "client_id": 2, "instruction": "hijacked"}),
            json!({"type": "update_server", "server_id": other.as_u32(), "instruction": "hijacked"}),
            json!({"type": "update_server", "server_id": sid.as_u32(), "port": 1, "instruction": "hijacked"}),
            json!({"type": "schedule_task", "task_id": "t", "recurring": false,
                   "server_id": other.as_u32(), "instruction": "x"}),
        ],
    )
    .await;

    assert_eq!(outcome.failures.len(), 4, "{outcome:?}");
    assert_eq!(state.get_server(sid).await.unwrap().instruction, "echo");
    assert_eq!(
        state.get_server(other).await.unwrap().instruction,
        "the other server"
    );
    assert!(state.get_task("t").await.is_none());
}

#[tokio::test]
async fn update_instruction_replaces_the_target_not_the_first_server() {
    let state = AppState::new();
    let first = tcp_server(&state, "first").await;
    let sid = tcp_server(&state, "second").await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let outcome = apply_feedback_actions(
        &state,
        &unused_llm(),
        &tx,
        FeedbackTarget::Server(sid),
        vec![
            json!({"type": "update_instruction", "instruction": "second, and say goodbye"}),
            json!({"type": "schedule_task", "task_id": "recheck", "recurring": false,
                   "delay_secs": 600, "instruction": "recheck"}),
        ],
    )
    .await;

    assert!(outcome.failures.is_empty(), "{outcome:?}");
    assert_eq!(
        state.get_server(sid).await.unwrap().instruction,
        "second, and say goodbye"
    );
    assert_eq!(state.get_server(first).await.unwrap().instruction, "first");
    let task = state.get_task("recheck").await.expect("task scheduled");
    assert!(
        matches!(task.scope, netget::state::task::TaskScope::Server(s) if s == sid),
        "the task must belong to the server the feedback is about: {:?}",
        task.scope
    );
}

#[tokio::test]
async fn client_feedback_is_scoped_to_the_client() {
    let state = AppState::new();
    let sid = tcp_server(&state, "a server").await;
    let cid = state
        .add_client(ClientInstance::new(
            ClientId::new(0),
            "127.0.0.1:9".to_string(),
            "tcp".to_string(),
            "poll".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let names: Vec<String> = get_feedback_actions(FeedbackTarget::Client(cid))
        .into_iter()
        .map(|a| a.name)
        .collect();
    assert!(names.contains(&"update_client".to_string()), "{names:?}");
    assert!(!names.contains(&"update_server".to_string()), "{names:?}");
    assert!(!names.contains(&"append_to_log".to_string()), "{names:?}");

    let outcome = apply_feedback_actions(
        &state,
        &unused_llm(),
        &tx,
        FeedbackTarget::Client(cid),
        vec![
            json!({"type": "update_instruction", "instruction": "poll slower"}),
            json!({"type": "set_memory", "value": "backoff: 2x"}),
            json!({"type": "update_server", "server_id": sid.as_u32(), "instruction": "x"}),
        ],
    )
    .await;

    assert_eq!(outcome.failures.len(), 1, "{outcome:?}");
    let client = state.get_client(cid).await.unwrap();
    assert_eq!(client.instruction, "poll slower");
    assert_eq!(client.memory, "backoff: 2x");
    let server = state.get_server(sid).await.unwrap();
    assert_eq!(server.instruction, "a server");
    assert!(server.memory.is_empty());
}

/// The client feedback prompt is about the client: it shows the client and offers
/// `update_client` pinned to its id, and lists no other instance.
#[tokio::test]
async fn the_client_feedback_prompt_shows_the_client() {
    let state = AppState::new();
    tcp_server(&state, "an unrelated server").await;
    let mut client = ClientInstance::new(
        ClientId::new(0),
        "127.0.0.1:6379".to_string(),
        "redis".to_string(),
        "poll the queue\nand report its length".to_string(),
    );
    client.memory = "polls: 3\n```odd fence```".to_string();
    let cid = state.add_client(client).await;

    let prompt = netget::llm::PromptBuilder::build_feedback_system_prompt(
        &state,
        None,
        Some(cid),
        "slow down if the server complains",
        "poll the queue\nand report its length",
        "polls: 3\n```odd fence```",
        &[json!({"issue": "rate_limited"})],
        get_feedback_actions(FeedbackTarget::Client(cid)),
    )
    .await;

    let id = cid.as_u32();
    assert!(
        prompt.contains(&format!(
            "**client #{id}**: redis, connected to 127.0.0.1:6379"
        )),
        "{prompt}"
    );
    assert!(prompt.contains("poll the queue\nand report its length"));
    assert_eq!(
        prompt.matches("and report its length").count(),
        1,
        "{prompt}"
    );
    assert!(
        prompt.contains("````text\npolls: 3\n```odd fence```\n````"),
        "{prompt}"
    );
    assert!(
        prompt.contains(&format!("`update_client` with `client_id` {id}")),
        "{prompt}"
    );
    assert!(
        prompt.contains(&format!("Must be {id}, this client's id.")),
        "{prompt}"
    );
    assert!(prompt.contains("slow down if the server complains"));
    assert!(prompt.contains("rate_limited"));
    for absent in [
        "an unrelated server",
        "No servers currently running",
        "Running Servers",
        "update_server",
        "update_client_instruction",
        "open_client",
        "reconnect_client",
        "close_all",
        "sent to the peer",
        "System Capabilities",
    ] {
        assert!(!prompt.contains(absent), "{absent} in:\n{prompt}");
    }
}

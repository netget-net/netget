//! The `provide_feedback` loop, end to end.
//!
//! `feedback_instructions` is a documented `open_server`/`open_client` parameter, and
//! setting it makes `call_llm` and `call_llm_for_client` advertise a `provide_feedback`
//! tool. Calling that tool pushed an entry onto `ServerInstance::feedback_buffer` — and
//! that was the end of it. Nothing ever read the buffer, and `call_llm_for_feedback`, which
//! knows how to turn a batch of entries into adjustment actions, had **zero callers**. The
//! documented behaviour ("feedback is accumulated and debounced, then the LLM adjusts the
//! server") was fiction, and a tool whose output goes nowhere is worse than no tool: the
//! model cannot tell that its report was discarded.
//!
//! `src/llm/feedback.rs` is the missing drain, polled from the same 1s timer that runs due
//! scheduled tasks. These tests pin both halves:
//!
//! * `take_due_feedback` — the debounce contract, without an LLM.
//! * the E2E — a real TCP peer triggers a network event, the model answers with
//!   `provide_feedback`, and the *second* LLM call is the feedback call, whose
//!   `update_instruction` lands on the server the feedback came from. Before the drain
//!   existed the second call never happened at all, which is exactly what
//!   `verify_mocks()` now enforces.
//!
//! ```bash
//! ./cargo-isolated.sh test --no-default-features --features tcp \
//!     --test feedback_loop_test -- --test-threads=100
//! ```

// `mod helpers` compiles the whole shared E2E harness into this binary; this file uses a
// small slice of it. Same situation as `tests/server.rs`.
#![allow(dead_code, unused_imports)]

mod helpers;

use std::time::Duration;

use helpers::{E2EResult, NetGetConfig};
use netget::state::app_state::AppState;
use netget::state::server::ServerInstance;
use netget::state::ServerId;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// A server with `feedback_instructions` set — the only condition under which
/// `provide_feedback` is advertised, and therefore the only one where a buffer can fill.
async fn server_with_feedback_instructions(state: &AppState) -> ServerId {
    let mut instance = ServerInstance::new(
        ServerId::new(0),
        0,
        "tcp".to_string(),
        "echo whatever arrives".to_string(),
    );
    instance.feedback_instructions = Some("tighten the instruction if peers complain".into());
    state.add_server(instance).await
}

/// The debounce contract, stated directly.
///
/// Draining and stamping happen under one write lock, so two ticks can never take the same
/// entries — that is what makes the 1s timer safe to poll from. The leading edge matters
/// too: the *first* entry after a quiet period must be due immediately rather than waiting
/// out a window, or a low-traffic server's feedback would sit unread indefinitely.
#[tokio::test]
async fn test_take_due_feedback_drains_once_then_debounces() {
    let state = AppState::new();
    let server_id = server_with_feedback_instructions(&state).await;

    // Nothing buffered: nothing due.
    assert!(
        state
            .take_due_feedback(Duration::from_secs(30))
            .await
            .is_empty(),
        "an empty buffer must never produce a batch, or every tick would call the LLM"
    );

    state
        .add_server_feedback(
            server_id,
            serde_json::json!({"observation": "peer hung up"}),
        )
        .await
        .expect("feedback_instructions is set, so this must be accepted");
    state
        .add_server_feedback(
            server_id,
            serde_json::json!({"observation": "peer hung up again"}),
        )
        .await
        .expect("feedback_instructions is set, so this must be accepted");

    // Leading edge: due at once, and both entries arrive in one batch rather than two.
    let due = state.take_due_feedback(Duration::from_secs(30)).await;
    assert_eq!(due.len(), 1, "one instance had feedback, so one batch");
    assert_eq!(due[0].server_id, Some(server_id));
    assert_eq!(
        due[0].entries.len(),
        2,
        "a burst must coalesce into one call"
    );
    assert_eq!(
        due[0].instructions, "tighten the instruction if peers complain",
        "the batch must carry the instance's feedback_instructions"
    );

    // The buffer was emptied by the take, so an immediate re-poll finds nothing. This is
    // the property that stops one batch being processed twice.
    assert!(
        state
            .take_due_feedback(Duration::from_secs(30))
            .await
            .is_empty(),
        "take must empty the buffer"
    );

    // New feedback inside the debounce window accumulates instead of firing again.
    state
        .add_server_feedback(server_id, serde_json::json!({"observation": "third"}))
        .await
        .expect("feedback_instructions is set, so this must be accepted");
    assert!(
        state
            .take_due_feedback(Duration::from_secs(30))
            .await
            .is_empty(),
        "within the debounce window a new entry must wait, not trigger a second LLM call"
    );

    // Once the window has passed it becomes due — with the entry that was held back.
    let due = state.take_due_feedback(Duration::from_millis(0)).await;
    assert_eq!(due.len(), 1, "the held-back entry must not be lost");
    assert_eq!(due[0].entries.len(), 1);
}

/// Feedback for a server without `feedback_instructions` is refused at the door, so a
/// buffer can never fill for an instance that has no way to process it.
#[tokio::test]
async fn test_feedback_without_instructions_is_refused() {
    let state = AppState::new();
    let instance = ServerInstance::new(ServerId::new(0), 0, "tcp".to_string(), "x".to_string());
    let server_id = state.add_server(instance).await;

    assert!(
        state
            .add_server_feedback(server_id, serde_json::json!({"observation": "ignored"}))
            .await
            .is_err(),
        "without feedback_instructions there is nothing to process, so accumulating would leak"
    );
    assert!(state
        .take_due_feedback(Duration::from_secs(0))
        .await
        .is_empty());
}

/// The whole loop against a real TCP peer.
///
/// Three LLM calls are expected and all three are asserted by `verify_mocks()`:
///   1. startup — opens the server *with* `feedback_instructions`
///   2. the `tcp_data_received` event — answers the peer and calls `provide_feedback`
///   3. the feedback call — matched on its fixed user message, answers with
///      `update_instruction`
///
/// Call 3 is the one that did not exist. Its `expect_calls(1)` is the regression guard: with
/// the drain removed the mock verification fails with "expected 1, got 0" rather than the
/// test quietly passing.
#[tokio::test]
async fn test_provide_feedback_reaches_the_llm_and_adjusts_the_server() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via tcp and greet every peer";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        // Matched on the fixed user message `call_llm_for_feedback` sends. The mock
        // harness extracts only the user turn, not the system prompt, so the feedback
        // template's own text is not visible to `on_prompt_containing`; and the harness
        // classifies this turn as `RequestKind::Unknown`, so there is no event id to key
        // on either. Declared first because rules are matched in declaration order.
        mock.on_instruction_containing("Analyze the accumulated feedback")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "update_instruction",
                    "instruction": "greet every peer, and say goodbye before closing"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("via tcp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TCP",
                    "instruction": "greet every peer",
                    "feedback_instructions": "if a peer complains, tighten the instruction"
                }
            ]))
            .expect_calls(1)
            .and()
            .on_event("tcp_data_received")
            .respond_with_actions(serde_json::json!([
                {"type": "send_tcp_data", "data": "hello\n", "encoding": "utf8"},
                {
                    "type": "provide_feedback",
                    "feedback": {"observation": "the peer expected a goodbye message"}
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;

    // A real peer, so the event is raised the way production raises it.
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    stream.write_all(b"hi\n").await?;
    stream.flush().await?;

    // The drain is polled on the 1s task timer; allow several ticks plus the LLM round trip.
    server
        .wait_for_pattern(
            "Feedback updated the instruction for server",
            Duration::from_secs(30),
        )
        .await
        .map_err(|e| {
            format!(
                "the feedback batch never reached the LLM, or its adjustment was never \
                 applied - this is the defect the drain exists to fix: {e}"
            )
        })?;

    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

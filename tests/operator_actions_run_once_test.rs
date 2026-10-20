//! An operator command's actions each run once.
//!
//! `handle_interpret_with_actions` runs the common actions itself and hands the rest to
//! `execute_actions`. Anything given to both runs twice, and `show_message` is the one the
//! operator can see: it was printed twice for every command that used it. The control is that
//! the message is printed at all, which proves the command and its answer got through.

#[allow(dead_code)]
mod helpers;

use helpers::mock_builder::MockLlmBuilder;
use helpers::mock_ollama::MockOllamaServer;
use netget::events::EventHandler;
use netget::state::app_state::AppState;
use tokio::sync::mpsc;

#[tokio::test]
async fn a_show_message_from_one_command_is_shown_once() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_instruction_containing("say that the room is ready")
            .respond_with_actions(serde_json::json!([
                {"type": "show_message", "message": "the room is ready"}
            ]))
            .expect_calls(1)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    let llm = netget::llm::OllamaClient::new(mock.base_url());
    state.set_llm_client(llm.clone()).await;
    state.set_ollama_model(Some("mock-model".to_string())).await;

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    EventHandler::new(state.clone(), llm)
        .handle_interpret_with_actions("say that the room is ready".to_string(), tx, None)
        .await
        .expect("operator command");

    let mut status = Vec::new();
    while let Ok(line) = rx.try_recv() {
        status.push(line);
    }
    // Lines that display the message: not the `→ show_message (…)` summary of the model's
    // answer, and not the TRACE echo of it.
    let shown = status
        .iter()
        .filter(|line| {
            line.ends_with("the room is ready")
                && !line.contains('→')
                && !line.starts_with("[TRACE]")
        })
        .count();
    assert!(
        shown > 0,
        "CONTROL FAILED: the message never reached the operator:\n{status:#?}"
    );
    assert_eq!(shown, 1, "show_message printed {shown} times:\n{status:#?}");

    mock.verify_calls().await.expect("mock expectations");
}

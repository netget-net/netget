//! The Git client reports what an operation produced back to the model.
//!
//! `git_operation_completed` and `git_operation_error` were declared in
//! `get_event_types()` and **raised by nothing**, so the model got exactly one turn — the
//! connected event — and then went deaf. `src/client/git/CLAUDE.md` documented the loop
//! ("Each action triggers an event … LLM responds to events with follow-up actions") the
//! whole time, and `tests/client/git/e2e_test.rs` even mocked
//! `git_operation_completed` — but both of its tests are `#[ignore]`d for reaching GitHub,
//! so nothing ever noticed that the rule could not match.
//!
//! Everything here is local: a `git2`-initialised repository in a temp dir and an
//! in-process mock model. Nothing touches the network.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features git \
//!       --test client -- git::operation_events --test-threads=100


use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::ClientId;
use tokio::sync::mpsc;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use crate::helpers::E2EResult;

/// Commit subject written into the test repository. The assertion that this string reaches
/// the model is the whole point: `git_log` used to report "2 line(s)" and throw the log
/// away, so a client told to "show me the last commits" could never show one.
const COMMIT_SUBJECT: &str = "netget-operation-events-marker";

/// Build a repository with exactly one commit whose subject is [`COMMIT_SUBJECT`].
fn repo_with_one_commit(path: &std::path::Path) {
    let repo = git2::Repository::init(path).expect("git init");
    std::fs::write(path.join("README.md"), b"hello\n").unwrap();

    let mut index = repo.index().unwrap();
    index.add_path(std::path::Path::new("README.md")).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();

    let sig =
        git2::Signature::new("NetGet Test", "test@localhost", &git2::Time::new(0, 0)).unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, COMMIT_SUBJECT, &tree, &[])
        .unwrap();
}

async fn wait_for_status(state: &AppState, id: ClientId, want: &str) -> bool {
    for _ in 0..600 {
        let status = state
            .with_client_mut(id, |client| client.status.clone())
            .await;
        if let Some(status) = status {
            if format!("{status:?}").contains(want) {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    false
}

/// clone-substitute → log → the model reads the log → disconnect.
///
/// Three model calls, and the middle one is the one that could not happen before: it is
/// matched on `operation=git_log` *and* on the commit subject appearing in `output`, so a
/// rule that fired without the log text would report zero calls and fail verification.
#[tokio::test]
async fn a_git_operation_reports_its_output_back_to_the_model() -> E2EResult<()> {
    let temp = tempfile::tempdir()?;
    let repo_path = temp.path().join("repo");
    std::fs::create_dir_all(&repo_path)?;
    repo_with_one_commit(&repo_path);

    let mock_config = MockLlmBuilder::new()
        // The connected event: ask for the log.
        .on_event("git_connected")
        .respond_with_actions(serde_json::json!([{
            "type": "git_log",
            "max_count": 5
        }]))
        .expect_calls(1)
        .and()
        // The follow-up. Matching on `output` is what makes this test about the payload
        // rather than merely about an event id.
        .on_event("git_operation_completed")
        .and_event_data_contains("operation", "git_log")
        .and_event_data_contains("output", COMMIT_SUBJECT)
        .respond_with_actions(serde_json::json!([{ "type": "disconnect" }]))
        .expect_calls(1)
        .and()
        .build();

    let mock = MockOllamaServer::start(mock_config).await?;
    let llm = netget::llm::OllamaClient::new(mock.base_url());

    let state = AppState::new_with_options(false, mock.base_url());
    state.set_llm_client(llm.clone()).await;

    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "git".to_string(),
        remote_addr: Some(repo_path.display().to_string()),
        // The Git client confines every path it touches to `allowed_root`, so a test
        // repository in a tempdir has to declare that tempdir. See
        // `src/client/git/sandbox.rs`; the default root is a NetGet-owned workspace.
        startup_params: Some(serde_json::json!({
            "allowed_root": temp.path().display().to_string()
        })),
        instruction: Some("Show me the most recent commits, then disconnect.".to_string()),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create git client");

    // The `disconnect` the model answers with is the end of the chain, so waiting for the
    // status is waiting for the whole exchange — no fixed sleep.
    assert!(
        wait_for_status(&state, client_id, "Disconnected").await,
        "the model's disconnect never took effect; the follow-up chain did not complete"
    );

    mock.wait_for_expectations(30).await;
    mock.verify_calls().await?;

    // Belt and braces: the recorded call history must actually contain the commit subject,
    // so this cannot pass on a rule that matched something else.
    let calls = mock.recorded_calls().await;
    assert!(
        calls
            .iter()
            .any(|call| call.context.prompt.contains(COMMIT_SUBJECT)),
        "no model call carried the commit log; the prompts were {:#?}",
        calls.iter().map(|c| &c.context.prompt).collect::<Vec<_>>()
    );

    Ok(())
}

/// A failing operation is reported too, through `git_operation_error`.
///
/// `git_checkout` of a branch that does not exist fails inside git2, which used to be
/// logged and dropped. The model now hears about it and can decide what to do — here,
/// give up.
#[tokio::test]
async fn a_failing_git_operation_reports_the_error_back_to_the_model() -> E2EResult<()> {
    let temp = tempfile::tempdir()?;
    let repo_path = temp.path().join("repo");
    std::fs::create_dir_all(&repo_path)?;
    repo_with_one_commit(&repo_path);

    let mock_config = MockLlmBuilder::new()
        .on_event("git_connected")
        .respond_with_actions(serde_json::json!([{
            "type": "git_checkout",
            "target": "no-such-branch"
        }]))
        .expect_calls(1)
        .and()
        .on_event("git_operation_error")
        .and_event_data_contains("operation", "git_checkout")
        .respond_with_actions(serde_json::json!([{ "type": "disconnect" }]))
        .expect_calls(1)
        .and()
        .build();

    let mock = MockOllamaServer::start(mock_config).await?;
    let llm = netget::llm::OllamaClient::new(mock.base_url());

    let state = AppState::new_with_options(false, mock.base_url());
    state.set_llm_client(llm.clone()).await;

    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "git".to_string(),
        remote_addr: Some(repo_path.display().to_string()),
        // The Git client confines every path it touches to `allowed_root`, so a test
        // repository in a tempdir has to declare that tempdir. See
        // `src/client/git/sandbox.rs`; the default root is a NetGet-owned workspace.
        startup_params: Some(serde_json::json!({
            "allowed_root": temp.path().display().to_string()
        })),
        instruction: Some("Check out the release branch.".to_string()),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create git client");

    assert!(
        wait_for_status(&state, client_id, "Disconnected").await,
        "the model was never told the checkout failed"
    );

    mock.wait_for_expectations(30).await;
    mock.verify_calls().await?;

    Ok(())
}

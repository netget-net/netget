//! The dashboard's `[ send ]` path on a Git client: `AppState::send_to_client` injects an
//! action from outside the client's own task and it runs against the session's repository.
//!
//! Everything is local - a `git2`-initialised repository in a temp dir - so nothing touches
//! the network at all, and the client's LLM points at an unreachable URL so zero LLM calls
//! happen. The connected-event call fails and the loop must tolerate that; verifying it does
//! is part of the point.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features git --test client -- git::command_channel --test-threads=100


use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "Git client #{} never registered a command handle",
        id.as_u32()
    );
}

async fn wait_for_log_containing(state: &AppState, owner: AccessLogOwner, needle: &str) {
    for _ in 0..1_000 {
        for entry in state.list_access_logs_for(Some(owner), None).await {
            if serde_json::to_string(&entry)
                .unwrap_or_default()
                .contains(needle)
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

#[tokio::test]
async fn injected_git_action_runs_against_the_session_repository() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // A real repository with one untracked file, so `git_status` has something to report.
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    std::fs::create_dir_all(&repo_path).unwrap();
    git2::Repository::init(&repo_path).expect("git init");
    std::fs::write(repo_path.join("dashboard-marker.txt"), b"hello").unwrap();

    let client_id = ClientForm {
        protocol: "git".to_string(),
        remote_addr: Some(repo_path.display().to_string()),
        // The Git client confines every path it touches to `allowed_root`, so a test
        // repository in a tempdir has to declare that tempdir. See
        // `src/client/git/sandbox.rs`; the default root is a NetGet-owned workspace.
        startup_params: Some(serde_json::json!({
            "allowed_root": temp.path().display().to_string()
        })),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create git client");

    // Regression guard for "register the channel BEFORE the connected-event LLM call":
    // the handle must exist without anything having answered that call.
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "git_status"}),
            Duration::from_secs(20),
        )
        .await
        .expect("send_to_client git_status");

    // Deliberately `Executed`, never `Sent`: git2 owns whatever sockets a Git operation
    // uses and reports no byte counts, so a number here would be invented. The detail
    // carries the real result instead - and the fact that it names the file proves the
    // action ran against the repository `remote_addr` pointed at, not a no-op.
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("dashboard-marker.txt"),
                "git_status should report the untracked file, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // An unknown verb is refused, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "definitely_not_a_git_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected disconnect ends the command loop and takes the handle with it.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "client should be Disconnected with no command handle; status={:?} has_handle={}",
        state.get_client(client_id).await.map(|c| c.status),
        state.has_client_handle(client_id).await
    );
}

/// A verb needing an open repository on a client that has none reports the reason instead
/// of succeeding silently. Before the session was shared, that branch was an `if let
/// Some(path)` with no `else` - the operation simply did not happen and nothing said so.
#[tokio::test]
async fn injected_git_action_without_a_repository_reports_why() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // A path that is not a repository: nothing to open, nothing cloned.
    let temp = tempfile::tempdir().expect("tempdir");
    let not_a_repo = temp.path().join("not-a-repo");
    std::fs::create_dir_all(&not_a_repo).unwrap();

    let client_id = ClientForm {
        protocol: "git".to_string(),
        remote_addr: Some(not_a_repo.display().to_string()),
        // Inside the sandbox, so the refusal under test is "no repository is open",
        // not "that path is outside allowed_root".
        startup_params: Some(serde_json::json!({
            "allowed_root": temp.path().display().to_string()
        })),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create git client");

    wait_for_client_handle(&state, client_id).await;

    let err = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "git_status"}),
            Duration::from_secs(20),
        )
        .await
        .expect_err("git_status without a repository must not report success");
    let text = err.to_string();
    assert!(
        text.contains("open repository"),
        "the error should name the missing repository, got {text:?}"
    );
}

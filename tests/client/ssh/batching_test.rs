//! Does the SSH client answer command output that finished during a model call together, when
//! it batches?
//!
//! The client runs up to 16 operations at once and asks the model about each result as it
//! finishes, in handlers that run side by side. With batching on, output that finishes while a
//! handler is asking the model is held and answered in one call when that call ends, through
//! `call_llm_for_client_batch`. SFTP results and failures are never held.
//!
//! The peer is OpenSSH's `sshd`, run unprivileged by `real_server_test::start_sshd` (the test
//! fails, never skips, without it). On connect the model starts three commands at once:
//! `echo first`, `sleep 0.5; echo second` and `sleep 1; echo third`. The mock answers
//! `first`'s output slowly (1.5 s), so `second` and `third` finish during that call. Batching
//! off is the control, in the same test as the claim: three output calls, or a two-call result
//! would prove nothing.
//!
//! Run with:
//!   ./cargo-isolated.sh test --test client -- client::ssh::batching_test --test-threads=16

use std::time::Duration;

use super::real_server_test::{current_user, start_sshd};
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use crate::helpers::real_server::RealServer;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use serde_json::json;
use tokio::sync::mpsc;

const OUTPUT_EVENT: &str = "ssh_output_received";

/// One session: returns the (output, prompt) of every output event the model was asked about.
async fn session(server: &RealServer, batching: bool) -> Vec<(String, String)> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("ssh_connected")
            .respond_with_actions(json!([
                {"type": "execute_command", "command": "echo first"},
                {"type": "execute_command", "command": "sleep 0.5; echo second"},
                {"type": "execute_command", "command": "sleep 1; echo third"},
            ]))
            .expect_calls(1)
            .and()
            .on_event(OUTPUT_EVENT)
            .and_event_data_contains("output", "first")
            .respond_with_actions(json!([]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_any()
            .respond_with_actions(json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    let llm = netget::llm::OllamaClient::new(mock.base_url());
    state.set_llm_client(llm.clone()).await;

    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "ssh".to_string(),
        remote_addr: Some(server.addr()),
        instruction: Some("Run the commands and note their output.".to_string()),
        startup_params: Some(json!({
            "username": current_user(),
            "private_key_path": server.dir().join("user_key").display().to_string(),
        })),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, llm, tx)
    .await
    .expect("create client");

    let output_calls = |calls: Vec<crate::helpers::mock_config::MockCallRecord>| {
        calls
            .into_iter()
            .filter(|c| c.context.event_type.as_deref() == Some(OUTPUT_EVENT))
            .map(|c| {
                (
                    c.context.event_data["output"]
                        .as_str()
                        .unwrap_or_default()
                        .trim()
                        .to_string(),
                    c.context.prompt.clone(),
                )
            })
            .collect::<Vec<_>>()
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let calls = output_calls(mock.recorded_calls().await);
        if calls.iter().any(|(o, _)| o == "third") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "`third` never reached the model; calls: {:?}",
            calls.iter().map(|(o, _)| o).collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Room for a stray extra call to show up before counting.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let calls = output_calls(mock.recorded_calls().await);
    let _ = state.remove_client(id).await;
    calls
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_client_answers_output_that_finished_during_a_call_together() {
    let server = start_sshd().await.expect("sshd");

    let separate = session(&server, false).await;
    let outputs: Vec<&str> = separate.iter().map(|(o, _)| o.as_str()).collect();
    assert_eq!(
        outputs,
        vec!["first", "second", "third"],
        "CONTROL FAILED: with batching off each command's output must be its own model call"
    );

    let batched = session(&server, true).await;
    let outputs: Vec<&str> = batched.iter().map(|(o, _)| o.as_str()).collect();
    assert_eq!(
        outputs,
        vec!["first", "third"],
        "the two outputs that finished during the first call must be one model call, \
         triggered by the newest"
    );
    let prompt = &batched[1].1;
    let trigger_at = prompt.rfind("Event: ssh_output_received").expect("trigger");
    let before = &prompt[..trigger_at];
    let listed = before
        .find("(1) ssh_output_received")
        .expect("the earlier output must be listed as arrived and not yet answered");
    assert!(
        before[listed..].contains("second"),
        "the listed output must be `second`'s:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

//! The login is one decision, and the model is offered only its two answers.
//!
//! Told "act as a Neo4j graph database that accepts any login", llama3.1:8b refused the login
//! on 14 of 120 replayed draws while the prompt also offered the memory, log and close actions
//! every other network event carries — one draw answered with `set_memory` alone — and on none
//! of 120 with only `accept_bolt_login` and `reject_bolt_login` on offer
//! (`eval-results/2026-11-13-structural-cases/`). `bolt_authenticate` is declared
//! `EventType::decision_only`, so `call_llm` offers nothing beside its own actions and the
//! prompt leaves out the section explaining memory.
//!
//! This reads the prompt the mock model received for the login and checks it holds exactly
//! those two answers. The control is in the same test: the query on the same connection is not
//! a decision event and is still offered memory, so the absence on the login is the
//! declaration's doing and not a prompt that never offers memory to anyone.
//!
//! LLM calls: 2 — the login and one query.

use super::common::*;
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use serde_json::json;
use tokio::sync::mpsc;

/// The action headings the prompt lists, `## N. name`, in order.
fn offered_actions(prompt: &str) -> Vec<String> {
    let section = prompt
        .split("# Available Actions")
        .nth(1)
        .and_then(|rest| rest.split("\n# ").next())
        .unwrap_or_default();
    section
        .lines()
        .filter_map(|line| line.strip_prefix("## "))
        .filter_map(|heading| {
            heading
                .split_once(". ")
                .map(|(_, name)| name.trim().to_string())
        })
        .collect()
}

#[tokio::test]
async fn the_login_prompt_offers_only_accept_and_reject() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("bolt_authenticate")
            .respond_with_actions(json!([{"type": "accept_bolt_login"}]))
            .expect_calls(1)
            .and()
            .on_event("bolt_query")
            .respond_with_actions(json!([{
                "type": "send_bolt_records", "fields": ["movies"], "records": [[42]]
            }]))
            .expect_calls(1)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "bolt".to_string(),
        port: Some(0),
        instruction: Some(
            "Act as a Neo4j graph database that accepts any login. It holds exactly 42 Movie \
             nodes and nothing else."
                .to_string(),
        ),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create bolt server");
    let port = wait_for_port(&state, id).await;

    let mut peer = Peer::connect_and_login(port).await;
    peer.send_all(&[run("MATCH (m:Movie) RETURN count(m) AS movies"), pull(-1)])
        .await;
    assert_success(&peer.recv().await);
    assert_eq!(
        record_values(&peer.recv().await),
        [netget::server::bolt::packstream::Value::Int(42)]
    );

    mock.wait_for_expectations(30).await;
    mock.verify_calls().await.expect("mock expectations");

    let calls = mock.recorded_calls().await;
    let prompt_of = |event: &str| {
        calls
            .iter()
            .find(|c| c.context.event_type.as_deref() == Some(event))
            .map(|c| c.context.prompt.clone())
            .unwrap_or_else(|| panic!("no call for {event} was recorded"))
    };
    let login = prompt_of("bolt_authenticate");
    let query = prompt_of("bolt_query");

    // Control first: a query is not a decision event, so memory is on offer there. Without
    // this, a prompt that offered memory to nobody would pass the assertions below.
    let query_actions = offered_actions(&query);
    assert!(
        query_actions.iter().any(|a| a == "set_memory")
            && query.contains("## Understanding Memory"),
        "the query prompt should still offer memory; it offered {query_actions:?}"
    );

    assert_eq!(
        offered_actions(&login),
        ["accept_bolt_login", "reject_bolt_login"],
        "the login prompt offers more than its two answers:\n{login}"
    );
    for absent in [
        "## Understanding Memory",
        "Maintain state if needed",
        "You can update memory",
    ] {
        assert!(
            !login.contains(absent),
            "the login prompt still explains memory ({absent:?}):\n{login}"
        );
    }
}

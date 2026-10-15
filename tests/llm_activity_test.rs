//! Live work follows the actual generation future, including failures and aborts.

use std::{sync::Arc, time::Duration};

use netget::llm::{
    BridgeReply, ConversationHandler, LlmBridge, OllamaClient, RateLimiter, RateLimiterConfig,
    RequestSource,
};
use netget::state::app_state::{AppState, ConversationSource, WebSearchMode};
use netget::state::ServerId;

fn reply() -> BridgeReply {
    BridgeReply {
        content: Some(r#"{"actions":[{"type":"show_message","message":"done"}]}"#.into()),
        tool_calls: vec![],
        prompt_tokens: 1,
        completion_tokens: 1,
        reasoning: None,
    }
}

fn conversation(
    state: &AppState,
    client: OllamaClient,
    source: ConversationSource,
) -> ConversationHandler {
    let mut handler = ConversationHandler::new(
        "test".into(),
        Arc::new(client),
        "test-model".into(),
        RateLimiter::new(RateLimiterConfig::default()),
        RequestSource::User,
    )
    .with_tracking(state.clone(), source, "request under test".into());
    handler.add_user_message("answer".into());
    handler
}

#[tokio::test]
async fn concurrent_generations_clear_individually_on_success_and_cancellation() {
    let state = AppState::new();
    let (bridge, mut requests) = LlmBridge::new();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5));
    let mut handles = Vec::new();
    let mut pending = Vec::new();
    for source in [
        ConversationSource::User,
        ConversationSource::Network {
            server_id: ServerId::new(7),
            connection_id: Some(netget::server::connection::ConnectionId::new(9)),
        },
    ] {
        let mut handler = conversation(&state, client.clone(), source.clone());
        handles.push(tokio::spawn(async move {
            handler
                .generate_with_tools_and_retry(
                    None,
                    WebSearchMode::Off,
                    vec![netget::llm::actions::common::show_message_action()],
                )
                .await
        }));
        pending.push(
            tokio::time::timeout(Duration::from_secs(5), requests.recv())
                .await
                .unwrap()
                .unwrap(),
        );
        assert!(state
            .llm_activity
            .snapshot()
            .iter()
            .any(|work| work.source == source));
    }
    let snapshot = netget::tui::projection::build_snapshot(&state).await;
    assert_eq!(snapshot.active_conversations, 2);
    assert_eq!(snapshot.llm_activity.len(), 2);

    pending.remove(0).reply.send(Ok(reply())).unwrap();
    handles.remove(0).await.unwrap().unwrap();
    assert_eq!(state.llm_activity.snapshot().len(), 1);

    let cancelled = handles.remove(0);
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    assert!(
        state.llm_activity.snapshot().is_empty(),
        "UI snapshots must not keep work alive"
    );
    assert_eq!(
        snapshot.llm_activity.len(),
        2,
        "the old snapshot is still held"
    );
}

#[tokio::test]
async fn failed_generation_clears_even_while_the_handler_is_kept_for_retry() {
    let state = AppState::new();
    let (bridge, mut requests) = LlmBridge::new();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5));
    let mut handler = conversation(&state, client, ConversationSource::User);
    let observer = state.clone();
    let host = tokio::spawn(async move {
        let mut calls = 0;
        while let Some(request) = requests.recv().await {
            calls += 1;
            assert_eq!(observer.llm_activity.snapshot().len(), 1);
            drop(request);
        }
        calls
    });
    assert!(handler
        .generate_with_tools_and_retry(
            None,
            WebSearchMode::Off,
            vec![netget::llm::actions::common::show_message_action()]
        )
        .await
        .is_err());
    assert!(state.llm_activity.snapshot().is_empty());
    drop(handler);
    assert!(host.await.unwrap() > 0);
}

#[tokio::test]
async fn legacy_script_tracking_does_not_show_as_model_generation() {
    let state = AppState::new();
    state
        .register_conversation(
            "script-test".into(),
            ConversationSource::Network {
                server_id: ServerId::new(1),
                connection_id: None,
            },
            "SCRIPT test".into(),
        )
        .await;
    let snapshot = netget::tui::projection::build_snapshot(&state).await;
    assert!(snapshot.llm_activity.is_empty());
    assert_eq!(snapshot.active_conversations, 0);
}

#[tokio::test]
async fn private_generations_keep_sensitive_details_out_of_ui_snapshots() {
    let state = AppState::new();
    let (bridge, mut requests) = LlmBridge::new();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5));
    let mut handler =
        conversation(&state, client, ConversationSource::User).with_private_payloads(true);
    let task = tokio::spawn(async move {
        handler
            .generate_with_tools_and_retry(
                None,
                WebSearchMode::Off,
                vec![netget::llm::actions::common::show_message_action()],
            )
            .await
    });
    let request = tokio::time::timeout(Duration::from_secs(5), requests.recv())
        .await
        .unwrap()
        .unwrap();
    let activity = state.llm_activity.snapshot();
    assert_eq!(activity.len(), 1);
    assert_eq!(activity[0].details, netget::utils::redact::REDACTED);
    request.reply.send(Ok(reply())).unwrap();
    task.await.unwrap().unwrap();
    assert!(state.llm_activity.snapshot().is_empty());
}

#[tokio::test]
async fn client_calls_are_attributed_to_the_client() {
    let state = AppState::new();
    state.set_ollama_model(Some("test-model".into())).await;
    let (bridge, mut requests) = LlmBridge::new();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5));
    let worker_state = state.clone();
    let task = tokio::spawn(async move {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        netget::llm::action_helper::call_llm_for_client(
            &client,
            &worker_state,
            "client-42".into(),
            "answer",
            "",
            None,
            &netget::client::tcp::actions::TcpClientProtocol::new(),
            &tx,
        )
        .await
    });
    let request = tokio::time::timeout(Duration::from_secs(5), requests.recv())
        .await
        .unwrap()
        .unwrap();
    let activity = state.llm_activity.snapshot();
    assert_eq!(activity.len(), 1);
    assert_eq!(
        activity[0].source,
        ConversationSource::Client {
            client_id: netget::state::ClientId::new(42)
        }
    );
    request.reply.send(Ok(reply())).unwrap();
    task.await.unwrap().unwrap();
    assert!(state.llm_activity.snapshot().is_empty());
}

//! The bridge LLM backend: requests go to whoever drains the bridge, answers come back as
//! the model's.
//!
//! This is the backend the browser build runs on (`crates/netget-web` drains the bridge into
//! the page's JavaScript), but nothing about it is browser-specific, so the mapping from a
//! `ConversationHandler` round-trip to a `BridgeRequest` and from a `BridgeReply` back to
//! parsed actions is pinned here, natively, through the same public API the scheduled-task
//! runner uses. The wasm bundle's own end-to-end check is `web/test/smoke.mjs`.

use std::sync::Arc;
use std::time::Duration;

use netget::llm::{
    ActionDefinition, BridgeReply, BridgeRequestKind, ConversationHandler, LlmBridge, OllamaClient,
    Parameter, RateLimiter, RateLimiterConfig, RequestSource,
};
use netget::state::app_state::WebSearchMode;
use serde_json::json;

fn send_tcp_data() -> ActionDefinition {
    ActionDefinition {
        name: "send_tcp_data".to_string(),
        description: "Send data to the peer".to_string(),
        parameters: vec![Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "Payload".to_string(),
            required: true,
        }],
        example: json!({"type": "send_tcp_data", "data": "hi"}),
        log_template: None,
    }
}

fn conversation(client: OllamaClient) -> ConversationHandler {
    let mut conversation = ConversationHandler::new(
        "system prompt under test".to_string(),
        Arc::new(client),
        "page-model".to_string(),
        RateLimiter::new(RateLimiterConfig::default()),
        RequestSource::Network,
    );
    conversation.add_user_message("hello from the peer".to_string());
    conversation
}

#[tokio::test]
async fn an_unadvertised_tool_is_rejected_before_execution_and_its_draft_is_discarded() {
    let (bridge, mut rx) = LlmBridge::new();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5));
    let host = tokio::spawn(async move {
        let first = rx.recv().await.unwrap();
        first
            .reply
            .send(Ok(BridgeReply {
                content: Some(
                    json!({
                        "tools": [{"type": "read_file", "path": "/must-not-be-read"}],
                        "actions": [{"type": "send_tcp_data", "data": "draft greeting"}]
                    })
                    .to_string(),
                ),
                ..Default::default()
            }))
            .unwrap();
        let second = rx.recv().await.unwrap();
        let correction = &second.messages.last().unwrap().content;
        assert!(correction.contains("read_file"), "{correction}");
        assert!(correction.contains("Available Actions"), "{correction}");
        assert!(!second
            .messages
            .iter()
            .any(|m| m.content.contains("Tool Results")));
        second
            .reply
            .send(Ok(BridgeReply {
                content: Some(
                    json!({"actions": [
                        {"type": "send_tcp_data", "data": "final greeting"}
                    ]})
                    .to_string(),
                ),
                ..Default::default()
            }))
            .unwrap();
    });
    let actions = conversation(client)
        .generate_with_tools_and_retry(None, WebSearchMode::Off, vec![send_tcp_data()])
        .await
        .unwrap();
    host.await.unwrap();
    assert_eq!(
        actions,
        vec![json!({"type": "send_tcp_data", "data": "final greeting"})]
    );
}

/// Operator conversations retain tools, but an intermediate action is not a commitment.
#[tokio::test]
async fn a_tool_rounds_actions_are_replaced_by_the_final_response() {
    let (bridge, mut rx) = LlmBridge::new();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5));
    let host = tokio::spawn(async move {
        for (round, tools) in [
            json!([{"type": "generate_random", "data_type": "uuid"}]),
            json!([]),
        ]
        .into_iter()
        .enumerate()
        {
            let request = rx.recv().await.unwrap();
            if round == 1 {
                let prompt = request
                    .messages
                    .iter()
                    .map(|m| m.content.as_str())
                    .collect::<String>();
                assert!(prompt.contains("generate_random"));
                assert!(prompt.contains("have not been executed"));
            }
            request
                .reply
                .send(Ok(BridgeReply {
                    content: Some(
                        json!({
                            "tools": tools,
                            "actions": [{"type": "send_tcp_data", "data": "one greeting"}]
                        })
                        .to_string(),
                    ),
                    ..Default::default()
                }))
                .unwrap();
        }
    });
    let mut handler = ConversationHandler::new(
        "Use a tool if needed, then return the final actions.".into(),
        Arc::new(client),
        "page-model".into(),
        RateLimiter::new(RateLimiterConfig::default()),
        RequestSource::User,
    );
    handler.add_user_message("greet the peer".into());
    let mut available = netget::llm::actions::get_all_tool_actions(WebSearchMode::Off);
    available.push(send_tcp_data());
    let actions = handler
        .generate_with_tools_and_retry(None, WebSearchMode::Off, available)
        .await
        .unwrap();
    host.await.unwrap();
    assert_eq!(
        actions,
        vec![json!({"type": "send_tcp_data", "data": "one greeting"})]
    );
}

#[tokio::test]
async fn exhausting_tool_rounds_fails_without_committing_draft_actions() {
    let (bridge, mut rx) = LlmBridge::new();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5));
    let state = netget::state::app_state::AppState::new();
    let observed_state = state.clone();
    let host = tokio::spawn(async move {
        for _ in 0..5 {
            let request = rx.recv().await.unwrap();
            assert_eq!(observed_state.get_active_conversations().await.len(), 1);
            request
                .reply
                .send(Ok(BridgeReply {
                    content: Some(
                        json!({
                            "tools": [{"type": "generate_random", "data_type": "uuid"}],
                            "actions": [{"type": "send_tcp_data", "data": "draft"}]
                        })
                        .to_string(),
                    ),
                    ..Default::default()
                }))
                .unwrap();
        }
    });
    let mut available = netget::llm::actions::get_all_tool_actions(WebSearchMode::Off);
    available.push(send_tcp_data());
    let error = conversation(client)
        .with_tracking(
            state.clone(),
            netget::state::app_state::ConversationSource::User,
            "unfinished tool loop".into(),
        )
        .generate_with_tools_and_retry(None, WebSearchMode::Off, available)
        .await
        .expect_err("an unfinished tool loop cannot commit its drafts");
    host.await.unwrap();
    assert!(
        error.to_string().contains("Tool iteration limit"),
        "{error:#}"
    );
    assert!(state
        .get_active_conversations()
        .await
        .iter()
        .all(|conversation| conversation.end_time.is_some()));
}

#[tokio::test]
async fn malformed_tool_entries_cannot_commit_the_other_actions() {
    for malformed in [json!(null), json!({}), json!({"type": 7})] {
        let (bridge, mut rx) = LlmBridge::new();
        let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5));
        let host = tokio::spawn(async move {
            for _ in 0..2 {
                let request = rx.recv().await.unwrap();
                request
                    .reply
                    .send(Ok(BridgeReply {
                        content: Some(
                            json!({
                                "tools": [malformed],
                                "actions": [{"type": "send_tcp_data", "data": "draft"}]
                            })
                            .to_string(),
                        ),
                        ..Default::default()
                    }))
                    .unwrap();
            }
        });
        let result = conversation(client)
            .generate_with_tools_and_retry(None, WebSearchMode::Off, vec![send_tcp_data()])
            .await;
        host.await.unwrap();
        assert!(
            result.is_err(),
            "malformed tool returned actions: {result:?}"
        );
    }
}

#[tokio::test]
async fn repeated_tool_failure_cannot_finish_successfully_without_a_final_response() {
    let (bridge, mut rx) = LlmBridge::new();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5));
    let missing = tempfile::tempdir().unwrap();
    let missing = missing.path().join("does-not-exist");
    let host = tokio::spawn(async move {
        for _ in 0..2 {
            let request = rx.recv().await.unwrap();
            request
                .reply
                .send(Ok(BridgeReply {
                    content: Some(
                        json!({
                            "tools": [{"type": "read_file", "path": missing}],
                            "actions": [{"type": "send_tcp_data", "data": "draft"}]
                        })
                        .to_string(),
                    ),
                    ..Default::default()
                }))
                .unwrap();
        }
    });
    let mut available = netget::llm::actions::get_all_tool_actions(WebSearchMode::Off);
    available.push(send_tcp_data());
    let error = conversation(client)
        .generate_with_tools_and_retry(None, WebSearchMode::Off, available)
        .await
        .expect_err("tool failures cannot commit drafts");
    host.await.unwrap();
    assert!(
        error
            .to_string()
            .contains("without a final action response"),
        "{error:#}"
    );
}

#[tokio::test]
async fn unresolved_drafts_exhausting_retries_are_not_a_successful_empty_response() {
    let (bridge, mut rx) = LlmBridge::new();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5));
    let host = tokio::spawn(async move {
        for _ in 0..5 {
            rx.recv()
                .await
                .unwrap()
                .reply
                .send(Ok(BridgeReply {
                    content: Some(
                        json!({"actions": [{
                            "type": "send_tcp_data", "data": "{{tools[0].result}}"
                        }]})
                        .to_string(),
                    ),
                    ..Default::default()
                }))
                .unwrap();
        }
    });
    let error = conversation(client)
        .generate_with_tools_and_retry(None, WebSearchMode::Off, vec![send_tcp_data()])
        .await
        .expect_err("rejected drafts are not a final answer");
    host.await.unwrap();
    assert!(
        error
            .to_string()
            .contains("without a final action response"),
        "{error:#}"
    );
}

#[tokio::test]
async fn a_generate_request_carries_the_whole_prompt_and_its_text_answer_is_parsed_as_actions() {
    let (bridge, mut rx) = LlmBridge::new();
    bridge.set_models(vec!["page-model".to_string()]);
    let client = OllamaClient::new_bridge(bridge.clone(), Duration::from_secs(5));
    assert_eq!(client.backend_type(), "bridge");
    assert_eq!(client.list_models().await.unwrap(), vec!["page-model"]);

    // The host: check the request is the full prompt, then answer with an action envelope.
    let host = tokio::spawn(async move {
        let req = rx.recv().await.expect("the bridge delivers the request");
        assert_eq!(req.kind, BridgeRequestKind::Generate);
        assert_eq!(req.model, "page-model");
        assert!(req.event.is_none());
        assert!(serde_json::to_value(&req).unwrap().get("event").is_none());
        assert!(
            req.tools.is_empty(),
            "the generate path embeds actions in the prompt"
        );
        let prompt: String = req.messages.iter().map(|m| m.content.as_str()).collect();
        assert!(
            prompt.contains("system prompt under test"),
            "system prompt missing"
        );
        assert!(prompt.contains("hello from the peer"), "user turn missing");
        // The actions the prompt describes also travel as data, example included, so a
        // person answering by hand gets a form rather than prose to transcribe.
        assert_eq!(req.actions.len(), 1, "{:?}", req.actions);
        assert_eq!(req.actions[0]["name"], "send_tcp_data");
        assert_eq!(req.actions[0]["example"]["data"], "hi");
        assert_eq!(req.actions[0]["parameters"][0]["name"], "data");
        assert_eq!(req.actions[0]["parameters"][0]["required"], true);
        assert_eq!(req.actions[0]["schema"]["required"][0], "data");
        req.reply
            .send(Ok(BridgeReply {
                content: Some(
                    r#"{"actions":[{"type":"send_tcp_data","data":"HELLO FROM THE PEER"}]}"#
                        .to_string(),
                ),
                tool_calls: vec![],
                prompt_tokens: 3,
                completion_tokens: 2,
                reasoning: None,
            }))
            .expect("the client is waiting");
    });

    let actions = conversation(client)
        .generate_with_tools_and_retry(None, WebSearchMode::Off, vec![send_tcp_data()])
        .await
        .expect("the host's answer parses as actions");
    host.await.unwrap();

    assert_eq!(actions.len(), 1, "{actions:?}");
    assert_eq!(actions[0]["type"], "send_tcp_data");
    assert_eq!(actions[0]["data"], "HELLO FROM THE PEER");
}

#[tokio::test]
async fn a_chat_request_with_native_tools_maps_the_hosts_tool_calls_to_actions() {
    let (bridge, mut rx) = LlmBridge::new();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5));

    let host = tokio::spawn(async move {
        let req = rx.recv().await.expect("the bridge delivers the request");
        assert_eq!(req.kind, BridgeRequestKind::Chat);
        assert_eq!(
            req.tools.len(),
            1,
            "the tool schema travels with a chat request"
        );
        assert_eq!(req.tools[0]["function"]["name"], "send_tcp_data");
        assert_eq!(req.actions[0]["name"], "send_tcp_data");
        assert_eq!(req.messages[0].role, "system");
        req.reply
            .send(Ok(BridgeReply {
                content: None,
                tool_calls: vec![netget::llm::bridge::BridgeToolCall {
                    id: None,
                    name: "send_tcp_data".to_string(),
                    arguments: json!({"data": "from a tool call"}),
                }],
                prompt_tokens: 0,
                completion_tokens: 0,
                reasoning: None,
            }))
            .expect("the client is waiting");
    });

    let actions = conversation(client)
        .with_native_tools(&[send_tcp_data()])
        .generate_with_tools_and_retry(None, WebSearchMode::Off, vec![send_tcp_data()])
        .await
        .expect("a tool call is an action");
    host.await.unwrap();

    assert_eq!(actions.len(), 1, "{actions:?}");
    assert_eq!(actions[0]["type"], "send_tcp_data");
    assert_eq!(actions[0]["data"], "from a tool call");
}

#[tokio::test]
async fn a_request_the_host_drops_fails_the_call_rather_than_hanging() {
    let (bridge, mut rx) = LlmBridge::new();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5));

    // Drop every request unanswered; the conversation retries once, then gives up.
    let host = tokio::spawn(async move {
        let mut seen = 0;
        while let Some(req) = rx.recv().await {
            seen += 1;
            drop(req);
        }
        seen
    });

    let err = conversation(client)
        .generate_with_tools_and_retry(None, WebSearchMode::Off, vec![send_tcp_data()])
        .await
        .expect_err("no answer is a failure");
    let text = format!("{err:#}");
    assert!(
        text.contains("dropped"),
        "the error names the cause: {text}"
    );
    drop(host);
}

#[tokio::test]
async fn an_error_from_the_host_is_the_models_error_not_a_transport_fault() {
    let (bridge, mut rx) = LlmBridge::new();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5));
    let breaker = client.circuit_breaker().clone();

    let host = tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            let _ = req.reply.send(Err("the visitor refused".to_string()));
        }
    });

    let err = conversation(client)
        .generate_with_tools_and_retry(None, WebSearchMode::Off, vec![send_tcp_data()])
        .await
        .expect_err("a refusal is a failure");
    let text = format!("{err:#}");
    assert!(text.contains("the visitor refused"), "{text}");
    // A slow or unwilling host is not a backend outage: the breaker must stay closed so
    // the next request is still attempted.
    assert_eq!(breaker.status().consecutive_failures, 0);
    drop(host);
}

#[tokio::test]
async fn an_empty_action_list_is_an_answer_not_a_failure() {
    // The page's "answer with nothing" sends exactly this. It must be taken as the model's
    // answer on the first request — not rejected and retried, not failed.
    let (bridge, mut rx) = LlmBridge::new();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5));

    let host = tokio::spawn(async move {
        let mut seen = 0;
        while let Some(req) = rx.recv().await {
            seen += 1;
            let _ = req.reply.send(Ok(BridgeReply {
                content: Some(r#"{"actions":[]}"#.to_string()),
                ..Default::default()
            }));
        }
        seen
    });

    let actions = conversation(client)
        .generate_with_tools_and_retry(None, WebSearchMode::Off, vec![send_tcp_data()])
        .await
        .expect("an empty action list is a valid answer");
    assert!(actions.is_empty(), "{actions:?}");
    // The conversation (and with it the client and the bridge sender) is gone, so the host
    // loop has ended and its count is final.
    assert_eq!(host.await.unwrap(), 1, "answered once, never retried");
}

/// Every `[REASONING] ` line waiting on a status channel, in order, each checked to be one the
/// dashboard files as the model's reasoning (`route_status_line` is what the dashboard's own
/// drain calls on every status line).
fn reasoning_lines(rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> Vec<String> {
    use netget::tui::chat::{route_status_line, EntryKind, Routed};
    let mut lines = Vec::new();
    while let Ok(line) = rx.try_recv() {
        if let Some(rest) = line.strip_prefix("[REASONING] ") {
            assert_eq!(
                route_status_line(&line),
                Routed::Chat(EntryKind::Reasoning, rest.to_string()),
                "the dashboard does not file {line:?} as reasoning"
            );
            lines.push(rest.to_string());
        }
    }
    lines
}

/// The page sends a thinking model's `<think>` text as the reply's `reasoning`, and the answer
/// that followed it as `content`. The reasoning reaches the dashboard's stream; only the
/// content is parsed.
#[tokio::test]
async fn a_hosts_reasoning_reaches_the_dashboard_and_only_its_content_is_parsed() {
    let (bridge, mut rx) = LlmBridge::new();
    let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(5)).with_status_tx(status_tx);

    // The host answers the first request with no reasoning (the control: nothing is forwarded
    // that the host did not send) and the second with an answer and the thinking behind it.
    let host = tokio::spawn(async move {
        let first = rx.recv().await.expect("first request");
        first
            .reply
            .send(Ok(BridgeReply {
                content: Some(
                    r#"{"actions":[{"type":"send_tcp_data","data":"first"}]}"#.to_string(),
                ),
                ..Default::default()
            }))
            .expect("the client is waiting");
        let second = rx.recv().await.expect("second request");
        second
            .reply
            .send(Ok(BridgeReply {
                content: Some(
                    r#"{"actions":[{"type":"send_tcp_data","data":"HELLO BACK"}]}"#.to_string(),
                ),
                reasoning: Some(
                    "The peer said hello, so I greet it.\nA greeting in capitals reads as friendly here."
                        .to_string(),
                ),
                ..Default::default()
            }))
            .expect("the client is waiting");
    });

    let client = Arc::new(client);
    let ask = |client: Arc<OllamaClient>| async move {
        let mut conversation = ConversationHandler::new(
            "system prompt under test".to_string(),
            client,
            "page-model".to_string(),
            RateLimiter::new(RateLimiterConfig::default()),
            RequestSource::Network,
        );
        conversation.add_user_message("hello from the peer".to_string());
        conversation
            .generate_with_tools_and_retry(None, WebSearchMode::Off, vec![send_tcp_data()])
            .await
            .expect("the host's answer parses as actions")
    };

    let first = ask(client.clone()).await;
    assert_eq!(first[0]["data"], "first");
    assert_eq!(
        reasoning_lines(&mut status_rx),
        Vec::<String>::new(),
        "reasoning was forwarded for a reply that carried none"
    );

    let second = ask(client.clone()).await;
    host.await.unwrap();
    assert_eq!(second.len(), 1, "{second:?}");
    assert_eq!(second[0]["type"], "send_tcp_data");
    assert_eq!(second[0]["data"], "HELLO BACK");
    assert!(
        second[0].get("reasoning").is_none(),
        "the reasoning leaked into the action: {second:?}"
    );
    assert_eq!(
        reasoning_lines(&mut status_rx),
        vec![
            "The peer said hello, so I greet it.".to_string(),
            "A greeting in capitals reads as friendly here.".to_string(),
        ]
    );
}

/// The browser's shape of the same thing: a server's network event is answered through the
/// bridge with reasoning, and the reasoning arrives on the server's status channel — the one
/// the dashboard drains — while the answer reaches the peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_network_events_reasoning_reaches_the_status_channel_the_dashboard_drains() {
    use netget::cli::management::ServerForm;
    use netget::state::app_state::AppState;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (bridge, mut rx) = LlmBridge::new();
    bridge.set_models(vec!["page-model".to_string()]);
    let state = AppState::new_with_options(false, "browser://model".to_string());
    state.set_ollama_model(Some("page-model".to_string())).await;
    state
        .set_llm_client(OllamaClient::new_bridge(bridge, Duration::from_secs(30)))
        .await;
    let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "tcp".to_string(),
        port: Some(0),
        instruction: Some("Answer whatever arrives.".to_string()),
        ..Default::default()
    }
    .create(&state, status_tx)
    .await
    .expect("create tcp server");

    let mut port = None;
    for _ in 0..200 {
        if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
            port = Some(addr.port());
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let port = port.expect("the tcp server binds a port");
    let mut peer = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(b"hello\n").await.expect("write");

    let req = tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .expect("the event reaches the bridge")
        .expect("the bridge delivers the request");
    req.reply
        .send(Ok(BridgeReply {
            content: Some(
                json!({"actions": [{"type": "send_tcp_data", "data": "hello yourself\n"}]})
                    .to_string(),
            ),
            reasoning: Some("A hello deserves one back.".to_string()),
            ..Default::default()
        }))
        .expect("the server is waiting");

    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !String::from_utf8_lossy(&got).contains("hello yourself") {
        let n = tokio::time::timeout_at(deadline, peer.read(&mut buf))
            .await
            .expect("the answer arrives")
            .expect("read");
        assert!(n > 0, "closed before the answer");
        got.extend_from_slice(&buf[..n]);
    }
    // The reasoning was forwarded before the answer was executed, so it is waiting now.
    let lines = reasoning_lines(&mut status_rx);
    assert_eq!(lines, vec!["A hello deserves one back.".to_string()]);
    let _ = state.remove_server(id).await;
}

/// The path that matters for the demo page: a real TCP server, a real peer, and the request
/// the page receives for the network event. It has no native tool schemas — the network-event
/// path deliberately sends none — so `actions` is the only structured description of what the
/// visitor may answer with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_network_event_request_offers_the_events_actions_with_their_examples() {
    use netget::cli::management::ServerForm;
    use netget::state::app_state::AppState;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (bridge, mut rx) = LlmBridge::new();
    bridge.set_models(vec!["page-model".to_string()]);
    let state = AppState::new_with_options(false, "browser://model".to_string());
    state.set_ollama_model(Some("page-model".to_string())).await;
    state
        .set_llm_client(OllamaClient::new_bridge(bridge, Duration::from_secs(30)))
        .await;
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "tcp".to_string(),
        port: Some(0),
        instruction: Some("Answer whatever arrives.".to_string()),
        ..Default::default()
    }
    .create(&state, status_tx)
    .await
    .expect("create tcp server");

    let mut port = None;
    for _ in 0..200 {
        if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
            port = Some(addr.port());
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let port = port.expect("the tcp server binds a port");

    let mut peer = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(b"hello\n").await.expect("write");

    let req = tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .expect("the event reaches the bridge")
        .expect("the bridge delivers the request");
    assert_eq!(req.kind, BridgeRequestKind::Generate);
    assert!(req.tools.is_empty(), "network events carry no native tools");

    let names: Vec<&str> = req
        .actions
        .iter()
        .filter_map(|a| a["name"].as_str())
        .collect();
    for expected in ["send_tcp_data", "wait_for_more", "close_this_connection"] {
        assert!(
            names.contains(&expected),
            "the event's own action {expected} is offered: {names:?}"
        );
    }
    // Exactly the list the prompt describes: every offered name appears in the prompt.
    let prompt: String = req.messages.iter().map(|m| m.content.as_str()).collect();
    for name in &names {
        assert!(
            prompt.contains(name),
            "{name} is offered but not in the prompt"
        );
    }
    for action in &req.actions {
        assert!(
            action["example"].is_object(),
            "every offered action carries an example: {action}"
        );
        assert_eq!(action["example"]["type"], action["name"], "{action}");
    }
    let send = req
        .actions
        .iter()
        .find(|a| a["name"] == "send_tcp_data")
        .unwrap();
    assert_eq!(send["generic"], false);
    assert_eq!(send["tool"], false);
    let encoding = send["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "encoding")
        .expect("send_tcp_data declares encoding");
    assert_eq!(encoding["choices"], json!(["utf8", "hex"]));
    let set_memory = req.actions.iter().find(|a| a["name"] == "set_memory");
    assert_eq!(set_memory.map(|a| a["generic"].clone()), Some(json!(true)));

    // Answer with the action's own example, as the page's composer does before any edit,
    // and the example's bytes reach the peer.
    let example = send["example"].clone();
    let expected = example["data"].as_str().unwrap().to_string();
    req.reply
        .send(Ok(BridgeReply {
            content: Some(json!({ "actions": [example] }).to_string()),
            ..Default::default()
        }))
        .expect("the server is waiting");

    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !String::from_utf8_lossy(&got).contains(&expected) {
        let n = tokio::time::timeout_at(deadline, peer.read(&mut buf))
            .await
            .expect("the example's bytes arrive")
            .expect("read");
        assert!(
            n > 0,
            "closed before the answer: {:?}",
            String::from_utf8_lossy(&got)
        );
        got.extend_from_slice(&buf[..n]);
    }
    let _ = state.remove_server(id).await;
}

#[tokio::test]
async fn structured_event_context_survives_retries_and_distinguishes_repeated_commands() {
    use netget::protocol::{Event, EventType};
    use netget::server::connection::ConnectionId;
    use netget::state::ServerId;
    static EVENT: std::sync::LazyLock<EventType> = std::sync::LazyLock::new(|| {
        EventType::new(
            "test_message",
            "A peer sent a line",
            json!({"type": "send_tcp_data", "data": "ok"}),
        )
    });
    let event = Event::new(&EVENT, json!({"message": "north <&>"}));
    let (bridge, mut rx) = LlmBridge::new();
    let client = OllamaClient::new_bridge(bridge, Duration::from_secs(10));
    let host = tokio::spawn(async move {
        let mut tokens = Vec::new();
        let mut requests = Vec::new();
        for round in 0..3 {
            let req = rx.recv().await.expect("event request");
            let event = req.event.as_ref().expect("structured event metadata");
            assert_eq!(event.server_id, 7);
            assert_eq!(event.connection_id, Some(11));
            assert_eq!(event.protocol, "tcp");
            assert_eq!(event.event_type, "test_message");
            assert_eq!(event.data, json!({"message": "north <&>"}));
            tokens.push(event.token.clone());
            requests.push(req.id);
            req.reply
                .send(Ok(BridgeReply {
                    // Force a formatting retry; it remains the same network event.
                    content: Some(if round == 0 {
                        "{".to_string()
                    } else {
                        json!({"actions": [{"type": "send_tcp_data", "data": "ok"}]}).to_string()
                    }),
                    ..Default::default()
                }))
                .unwrap();
        }
        assert_ne!(requests[0], requests[1], "each model call has its own id");
        assert_eq!(
            tokens[0], tokens[1],
            "a retry must not reapply a host's event side effect"
        );
        assert_ne!(
            tokens[1], tokens[2],
            "an identical later command is a new event"
        );
    });
    for _ in 0..2 {
        let actions = conversation(client.clone())
            .with_bridge_event(ServerId::new(7), Some(ConnectionId::new(11)), "tcp", &event)
            .generate_with_tools_and_retry(None, WebSearchMode::Off, vec![send_tcp_data()])
            .await
            .unwrap();
        assert_eq!(actions[0]["data"], "ok");
    }
    host.await.unwrap();
}

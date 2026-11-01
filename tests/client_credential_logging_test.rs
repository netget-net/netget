//! Credential actions and structured server input retain their intended values
//! while incidental model/script diagnostics hide credentials, including malformed output.
use netget::{
    client::llm_budget::call_llm_for_client,
    llm::{
        actions::{
            client_trait::{Client, ClientActionResult},
            protocol_trait::Protocol,
            ActionDefinition, Parameter, StartupExamples,
        },
        rate_limiter::{RateLimiter, RateLimiterConfig},
        ConversationHandler, OllamaClient, RequestSource,
    },
    protocol::{ConnectContext, Event, EventType},
    scripting::{EventHandler, EventHandlerConfig, EventHandlerType, EventPattern},
    state::{app_state::WebSearchMode, AccessLogOwner, AppState, ClientId, ClientInstance},
};
use serde_json::{json, Value};
use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;
use tracing::instrument::WithSubscriber;
const PASSWORD: &str = "fixture-password-do-not-log-73";
const ORDINARY: &str = "ordinary-visible-marker-86";
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}
fn subscriber(capture: Capture) -> impl tracing::Subscriber + Send + Sync {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .without_time()
        .with_ansi(false)
        .with_writer(move || capture.clone())
        .finish()
}
fn background_capture() -> Capture {
    static BACKGROUND: std::sync::LazyLock<Capture> = std::sync::LazyLock::new(|| {
        let capture = Capture::default();
        tracing::subscriber::set_global_default(subscriber(capture.clone())).unwrap();
        capture
    });
    BACKGROUND.clone()
}
#[derive(Clone)]
struct TestProtocol {
    credential: bool,
}
fn action(credential: bool) -> ActionDefinition {
    let name = if credential {
        "credential_login"
    } else {
        "ordinary_action"
    };
    ActionDefinition {
        name: name.into(),
        description: "Test typed action".into(),
        parameters: vec![Parameter {
            name: if credential { "password" } else { "value" }.into(),
            type_hint: "string".into(),
            description: "value".into(),
            required: true,
        }],
        example: json!({"type":name}),
        log_template: None,
    }
}
impl Protocol for TestProtocol {
    fn protocol_name(&self) -> &'static str {
        "Test"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Test"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["test"]
    }
    fn description(&self) -> &'static str {
        "test"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn example_prompt(&self) -> &'static str {
        "test"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![action(self.credential)]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn metadata(&self) -> netget::protocol::metadata::ProtocolMetadataV2 {
        netget::protocol::metadata::ProtocolMetadataV2::builder().build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(json!({}), json!({}), json!({}))
    }
}
impl Client for TestProtocol {
    fn connect(
        &self,
        _: ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async { anyhow::bail!("test does not connect") })
    }
    fn execute_action(&self, value: Value) -> anyhow::Result<ClientActionResult> {
        Ok(ClientActionResult::SendData(
            value[if self.credential { "password" } else { "value" }]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
        ))
    }
}
async fn instance(state: &AppState, handler: Option<EventHandlerType>) -> ClientId {
    let mut client = ClientInstance::new(
        ClientId::new(0),
        "127.0.0.1:1".into(),
        "test".into(),
        "test".into(),
    );
    if let Some(handler) = handler {
        let mut config = EventHandlerConfig::new();
        config.add_handler(EventHandler::new(EventPattern::wildcard(), handler));
        client.event_handler_config = Some(config);
    }
    state.add_client(client).await
}
fn event() -> Event {
    static EVENT: std::sync::LazyLock<EventType> =
        std::sync::LazyLock::new(|| EventType::new("test_connected", "ready", json!({})));
    Event::new(&EVENT, json!({"ready":true}))
}
async fn routed(
    state: &AppState,
    client: &OllamaClient,
    id: ClientId,
    credential: bool,
    tx: &mpsc::UnboundedSender<String>,
) -> anyhow::Result<Vec<Value>> {
    Ok(call_llm_for_client(
        client,
        state,
        id.to_string(),
        if credential { "credential" } else { "ordinary" },
        "",
        Some(&event()),
        &TestProtocol { credential },
        tx,
    )
    .await?
    .actions)
}
async fn mock(mode: &str, openai: bool) -> (u16, tokio::task::JoinHandle<()>) {
    use axum::{extract::State, response::IntoResponse, routing::post, Json, Router};
    async fn reply(
        State((mode, openai)): State<(String, bool)>,
        Json(request): Json<Value>,
    ) -> axum::response::Response {
        let credential = request.to_string().contains("credential_login");
        let narrowed = request.to_string().contains("narrowed-followup");
        let (name, field, value) = if narrowed {
            ("ordinary_action", "value", PASSWORD)
        } else if credential {
            ("credential_login", "password", PASSWORD)
        } else if request.to_string().contains(PASSWORD) {
            ("ordinary_action", "value", PASSWORD)
        } else {
            ("ordinary_action", "value", ORDINARY)
        };
        let mut args = json!({});
        args[field] = json!(value);
        if mode == "reflected_note" {
            args["note"] = json!(PASSWORD);
            args["nested"] = json!({"text":PASSWORD});
        }
        let mut returned = args.clone();
        returned["type"] = json!(name);
        if mode == "error" {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(if openai {
                    json!({"error":{"message":value}})
                } else {
                    json!({"error":value})
                }),
            )
                .into_response();
        }
        let content = match mode.as_str() {
            "malformed" => format!("{{\"actions\":[{{\"password\":\"{value}\""),
            "plain" => format!("unstructured secret {value}"),
            "malformed_common" => {
                json!({"actions":[{"type":"show_message","message":null,"password":PASSWORD}]})
                    .to_string()
            }
            "unknown" => json!({"actions":[{"type":PASSWORD,"password":PASSWORD}]}).to_string(),
            "diagnostics" if !request.to_string().contains("Tool execution results") => {
                json!({"actions":[returned, {"type":"read_file","path":PASSWORD},
                    {"type":"show_message","message":PASSWORD}]})
                .to_string()
            }
            "diagnostics" => {
                // The tool round contains draft actions. Explicitly offer the display
                // action again in the final response whose actions are committed.
                json!({"actions":[returned, {"type":"show_message","message":PASSWORD}]})
                    .to_string()
            }
            _ => json!({"actions":[returned]}).to_string(),
        };
        if openai {
            let message = if mode == "native" || mode == "followup_native" {
                json!({"role":"assistant","tool_calls":[{"id":"1","type":"function","function":{"name":name,"arguments":args.to_string()}}],"reasoning_content":value})
            } else {
                json!({"role":"assistant","content":content,"reasoning_content":value})
            };
            Json(json!({"choices":[{"message":message}],"usage":{"prompt_tokens":1,"completion_tokens":1}})).into_response()
        } else {
            let message = if mode == "native" || mode == "followup_native" {
                json!({"role":"assistant","tool_calls":[{"function":{"name":name,"arguments":args}}],"thinking":value})
            } else {
                json!({"role":"assistant","content":content,"thinking":value})
            };
            Json(json!({"model":"test-model","message":message,"response":content,"thinking":value,"done":true})).into_response()
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new()
        .route("/api/generate", post(reply))
        .route("/api/chat", post(reply))
        .route("/v1/chat/completions", post(reply))
        .with_state((mode.into(), openai));
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (port, task)
}
fn drain(rx: &mut mpsc::UnboundedReceiver<String>) -> String {
    let mut lines = Vec::new();
    while let Ok(line) = rx.try_recv() {
        lines.push(line)
    }
    lines.join("\n")
}
fn assert_hidden(logs: &str, status: &str) {
    assert!(
        !logs.contains(PASSWORD),
        "file logs exposed fixture credential: {}",
        logs.lines()
            .filter(|line| line.contains(PASSWORD))
            .map(|line| line.replace(PASSWORD, "<fixture credential>"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        !status.contains(PASSWORD),
        "status exposed fixture credential"
    );
}
#[tokio::test]
async fn static_and_script_actions_execute_original_password_but_store_redacted_copies() {
    let background = background_capture();

    let capture = Capture::default();
    let observed = capture.clone();
    async move {
        let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
        let client = OllamaClient::new("http://127.0.0.1:1");
        let (tx, _) = mpsc::unbounded_channel();
        let a = json!({"type":"credential_login","password":PASSWORD,"username":"alice","note":PASSWORD,"nested":{"text":PASSWORD}});
        for handler in [
            EventHandlerType::static_response(vec![a.clone()]),
            EventHandlerType::script(
                "python",
                format!(
                    "import json,sys\nsys.stderr.write({:?})\njson.dump({{\"actions\":[{}]}},sys.stdout)",
                    PASSWORD, a
                ),
            ),
            EventHandlerType::script_resident(
                "python",
                format!("import sys\ndef handle(event_type,event,message):\n sys.stderr.write({:?}+'\\n')\n return {{'actions':[{}]}}", PASSWORD, a),
                None,
            ),
        ] {
            let id = instance(&state, Some(handler)).await;
            let actions = routed(&state, &client, id, true, &tx).await.unwrap();
            assert_eq!(actions, vec![a.clone()]);
            assert_eq!(
                TestProtocol { credential: true }
                    .execute_action(actions[0].clone())
                    .unwrap()
                    .get_all_data(),
                vec![PASSWORD.as_bytes().to_vec()]
            );
            let logs = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await;
            assert_eq!(logs.len(), 1);
            assert_eq!(logs[0].response[0], json!({"type":"credential_login"}));
            assert!(!serde_json::to_string(&logs).unwrap().contains(PASSWORD));
            netget::scripting::ResidentScriptManager::shutdown_client(id.as_u32()).await;
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while !background.text().contains("resident script client #") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("resident stderr must reach the background log oracle");
        assert!(!background.text().contains(PASSWORD), "resident stderr exposed credential");
        assert!(background.text().contains("<redacted>"));
        assert!(
            !observed.text().contains(PASSWORD),
            "script code/stdout exposed a credential at TRACE"
        );
    }
    .with_subscriber(subscriber(capture))
    .await;
}
#[tokio::test]
async fn concurrent_credential_and_ordinary_requests_keep_privacy_local_to_the_request() {
    let capture = Capture::default();
    let observed = capture.clone();
    async move {
        let (port, peer) = mock("valid", false).await;
        let url = format!("http://127.0.0.1:{port}");
        let (tx, mut rx) = mpsc::unbounded_channel();
        let client = OllamaClient::new(&url).with_status_tx(tx.clone());
        let state = AppState::new_with_options(false, url);
        state.set_ollama_model(Some("test-model".into())).await;
        let secret_id = instance(&state, None).await;
        let ordinary_id = instance(&state, None).await;
        let (secret, ordinary) = tokio::join!(
            routed(&state, &client, secret_id, true, &tx),
            routed(&state, &client, ordinary_id, false, &tx)
        );
        assert_eq!(secret.unwrap()[0]["password"], PASSWORD);
        assert_eq!(ordinary.unwrap()[0]["value"], ORDINARY);
        let logs = state
            .list_access_logs_for(Some(AccessLogOwner::Client(secret_id.as_u32())), None)
            .await;
        assert_eq!(logs[0].response[0], json!({"type":"credential_login"}));
        let ordinary_logs = state
            .list_access_logs_for(Some(AccessLogOwner::Client(ordinary_id.as_u32())), None)
            .await;
        assert_eq!(ordinary_logs[0].response[0]["value"], ORDINARY);
        assert_hidden(&observed.text(), &drain(&mut rx));
        assert!(
            observed.text().contains(ORDINARY),
            "control proves ordinary payload logging remained enabled"
        );
        peer.abort();
        let _ = peer.await;
    }
    .with_subscriber(subscriber(capture))
    .await;
}
#[tokio::test]
async fn private_access_logs_hide_note_copies_and_unknown_or_malformed_action_names() {
    for openai in [false, true] {
        let (port, peer) = mock("reflected_note", openai).await;
        let url = format!("http://127.0.0.1:{port}");
        let client = if openai {
            OllamaClient::new_openai(url.clone(), "fixture-api-key")
        } else {
            OllamaClient::new(&url)
        };
        let state = AppState::new_with_options(false, url);
        state.set_ollama_model(Some("test-model".into())).await;
        let (tx, _) = mpsc::unbounded_channel();
        let id = instance(&state, None).await;
        let actions = routed(&state, &client, id, true, &tx).await.unwrap();
        assert_eq!(actions[0]["password"], PASSWORD);
        assert_eq!(actions[0]["note"], PASSWORD);
        assert_eq!(actions[0]["nested"]["text"], PASSWORD);
        let logs = state
            .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
            .await;
        assert_eq!(logs[0].response, vec![json!({"type":"credential_login"})]);
        assert!(!serde_json::to_string(&logs).unwrap().contains(PASSWORD));
        for action in [
            json!({"type":PASSWORD,"note":PASSWORD}),
            json!({"type":{"nested":PASSWORD},"note":PASSWORD}),
            json!({"note":PASSWORD}),
        ] {
            let id = instance(
                &state,
                Some(EventHandlerType::static_response(vec![action.clone()])),
            )
            .await;
            assert_eq!(
                routed(&state, &client, id, true, &tx).await.unwrap(),
                vec![action]
            );
            let logs = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await;
            assert_eq!(logs[0].response, vec![json!({})]);
            assert!(!serde_json::to_string(&logs).unwrap().contains(PASSWORD));
        }
        peer.abort();
        let _ = peer.await;
    }
}
#[tokio::test]
async fn native_tool_arguments_and_reasoning_are_private_on_ollama_and_openai() {
    for openai in [false, true] {
        let capture = Capture::default();
        let observed = capture.clone();
        async move {
            let (port, peer) = mock("native", openai).await;
            let (tx, mut rx) = mpsc::unbounded_channel();
            let url = format!("http://127.0.0.1:{port}");
            let client = if openai {
                OllamaClient::new_openai(url, "fixture-api-key")
            } else {
                OllamaClient::new(url)
            }
            .with_status_tx(tx.clone());
            let offered = vec![
                action(true),
                netget::llm::actions::common::notify_operator_action(),
            ];
            let mut conversation = ConversationHandler::new(
                "credential request".into(),
                Arc::new(client),
                "test-model".into(),
                RateLimiter::new(RateLimiterConfig::default()),
                RequestSource::Network,
            )
            .with_native_tools(&offered)
            .with_status_tx(tx);
            conversation.add_user_message("login".into());
            let actions = conversation
                .generate_with_tools_and_retry(None, WebSearchMode::Off, offered)
                .await
                .unwrap();
            assert_eq!(actions[0]["password"], PASSWORD);
            assert_hidden(&observed.text(), &drain(&mut rx));
            peer.abort();
            let _ = peer.await;
        }
        .with_subscriber(subscriber(capture))
        .await;
    }
}
#[tokio::test]
async fn malformed_plain_text_and_reflected_backend_errors_never_expose_credentials() {
    for native in [false, true] {
        for openai in [false, true] {
            for mode in ["malformed", "plain", "malformed_common", "unknown", "error"] {
                let capture = Capture::default();
                let observed = capture.clone();
                async move {
                    let (port, peer) = mock(mode, openai).await;
                    let (tx, mut rx) = mpsc::unbounded_channel();
                    let url = format!("http://127.0.0.1:{port}");
                    let client = if openai {
                        OllamaClient::new_openai(url, "fixture-api-key")
                    } else {
                        OllamaClient::new(url)
                    }
                    .with_status_tx(tx.clone());
                    let offered = vec![
                        action(true),
                        netget::llm::actions::common::notify_operator_action(),
                    ];
                    let mut conversation = ConversationHandler::new(
                        "credential request".into(),
                        Arc::new(client),
                        "test-model".into(),
                        RateLimiter::new(RateLimiterConfig::default()),
                        RequestSource::Network,
                    )
                    .with_status_tx(tx);
                    if native {
                        conversation = conversation.with_native_tools(&offered);
                    }
                    conversation.add_user_message("login".into());
                    let e = tokio::time::timeout(
                        Duration::from_secs(5),
                        conversation.generate_with_tools_and_retry(
                            None,
                            WebSearchMode::Off,
                            offered,
                        ),
                    )
                    .await
                    .unwrap()
                    .expect_err("peer reply must fail");
                    assert!(!format!("{e:#}").contains(PASSWORD));
                    assert_hidden(&observed.text(), &drain(&mut rx));
                    peer.abort();
                    let _ = peer.await;
                }
                .with_subscriber(subscriber(capture))
                .await;
            }
        }
    }
}

#[tokio::test]
async fn narrowed_followups_keep_credential_history_private_on_both_backends() {
    for native in [false, true] {
        for openai in [false, true] {
            let capture = Capture::default();
            let observed = capture.clone();
            async move {
                let (port, peer) = mock(
                    if native {
                        "followup_native"
                    } else {
                        "followup_prompt"
                    },
                    openai,
                )
                .await;
                let (tx, mut rx) = mpsc::unbounded_channel();
                let url = format!("http://127.0.0.1:{port}");
                let client = if openai {
                    OllamaClient::new_openai(url, "fixture-api-key")
                } else {
                    OllamaClient::new(url)
                }
                .with_status_tx(tx.clone());
                let credentials = vec![action(true)];
                let mut conversation = ConversationHandler::new(
                    "Offer credential_login for login, then ordinary_action for the follow-up"
                        .into(),
                    Arc::new(client),
                    "test-model".into(),
                    RateLimiter::new(RateLimiterConfig::default()),
                    RequestSource::Network,
                )
                .with_status_tx(tx);
                if native {
                    conversation = conversation.with_native_tools(&credentials);
                }
                conversation.add_user_message("login".into());
                let first = conversation
                    .generate_with_tools_and_retry(None, WebSearchMode::Off, credentials)
                    .await
                    .unwrap();
                assert_eq!(first[0]["password"], PASSWORD);

                let narrowed = vec![action(false)];
                if native {
                    conversation = conversation.with_native_tools(&narrowed);
                }
                conversation.add_user_message("narrowed-followup".into());
                let next = conversation
                    .generate_with_tools_and_retry(None, WebSearchMode::Off, narrowed)
                    .await
                    .unwrap();
                assert_eq!(next[0]["type"], "ordinary_action");
                assert_eq!(next[0]["value"], PASSWORD);
                assert_eq!(
                    TestProtocol { credential: false }
                        .execute_action(next[0].clone(),)
                        .unwrap()
                        .get_all_data(),
                    vec![PASSWORD.as_bytes().to_vec()]
                );
                assert_hidden(&observed.text(), &drain(&mut rx));
                peer.abort();
                let _ = peer.await;
            }
            .with_subscriber(subscriber(capture))
            .await;
        }
    }
}

#[tokio::test]
async fn tool_and_action_diagnostics_hide_credentials_without_changing_display_actions() {
    for openai in [false, true] {
        let capture = Capture::default();
        let observed = capture.clone();
        async move {
            let (port, peer) = mock("diagnostics", openai).await;
            let (tx, mut rx) = mpsc::unbounded_channel();
            let url = format!("http://127.0.0.1:{port}");
            let client = if openai {
                OllamaClient::new_openai(url, "fixture-api-key")
            } else {
                OllamaClient::new(url)
            }
            .with_status_tx(tx.clone());
            let offered = vec![
                action(true),
                netget::llm::actions::common::notify_operator_action(),
                netget::llm::actions::tools::read_file_action(),
            ];
            let mut conversation = ConversationHandler::new(
                "Offer credential_login, read_file and show_message".into(),
                Arc::new(client),
                "test-model".into(),
                RateLimiter::new(RateLimiterConfig::default()),
                RequestSource::Network,
            )
            .with_status_tx(tx);
            conversation.add_user_message("login".into());
            let actions = conversation
                .generate_with_tools_and_retry(None, WebSearchMode::Off, offered)
                .await
                .unwrap();
            assert_eq!(actions[0]["password"], PASSWORD);
            assert!(
                actions
                    .iter()
                    // Answered under the former name, executed under the current one.
                    .any(|a| a["type"] == "notify_operator" && a["message"] == PASSWORD),
                "intentional display action must preserve its original value"
            );
            assert_hidden(&observed.text(), &drain(&mut rx));
            peer.abort();
            let _ = peer.await;
        }
        .with_subscriber(subscriber(capture))
        .await;
    }
}

impl netget::llm::actions::protocol_trait::Server for TestProtocol {
    fn spawn(
        &self,
        _: netget::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async { anyhow::bail!("test does not bind") })
    }
    fn execute_action(
        &self,
        value: Value,
    ) -> anyhow::Result<netget::llm::actions::protocol_trait::ActionResult> {
        Ok(netget::llm::actions::protocol_trait::ActionResult::Output(
            value["value"].as_str().unwrap().as_bytes().to_vec(),
        ))
    }
}
async fn server_instance(
    state: &AppState,
    handler: Option<EventHandlerType>,
) -> netget::state::ServerId {
    let mut server = netget::state::ServerInstance::new(
        netget::state::ServerId::new(0),
        0,
        "Test".into(),
        "test".into(),
    );
    if let Some(handler) = handler {
        let mut config = EventHandlerConfig::new();
        config.add_handler(EventHandler::new(EventPattern::wildcard(), handler));
        server.event_handler_config = Some(config);
    }
    state.add_server(server).await
}
fn server_event(private: bool) -> Event {
    static EVENT: std::sync::LazyLock<EventType> = std::sync::LazyLock::new(|| {
        EventType::new("typed_login", "Typed chosen handler input", json!({}))
            .with_actions(vec![action(false)])
    });
    Event::new(
        &EVENT,
        if private {
            json!({"request":{"username":"alice","password":PASSWORD}})
        } else {
            json!({"request":{"value":ORDINARY}})
        },
    )
}
async fn server_mock(
    mode: &str,
    requests: Arc<Mutex<Vec<Value>>>,
) -> (u16, tokio::task::JoinHandle<()>) {
    use axum::{extract::State, response::IntoResponse, routing::post, Json, Router};
    async fn reply(
        State((mode, requests)): State<(String, Arc<Mutex<Vec<Value>>>)>,
        Json(request): Json<Value>,
    ) -> axum::response::Response {
        let private = request.to_string().contains(PASSWORD);
        requests.lock().unwrap().push(request);
        let value = if private { PASSWORD } else { ORDINARY };
        if mode == "error" {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(json!({"error":value})),
            )
                .into_response();
        }
        let content = match mode.as_str() {
            "malformed" => format!("{{\"actions\":[{{\"value\":\"{value}\""),
            "plain" => format!("unstructured reflected {value}"),
            _ => json!({"actions":[{"type":"ordinary_action","value":value}]}).to_string(),
        };
        Json(json!({"model":"test-model","response":content,"done":true})).into_response()
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new()
        .route("/api/generate", post(reply))
        .with_state((mode.to_owned(), requests));
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (port, task)
}
#[test]
fn structured_request_credential_scan_is_iterative_bounded_and_local() {
    use netget::utils::{json_budget::drop_iteratively, redact::contains_credentials};
    for key in ["password", "SHARED-SECRET", "nested_access_token", "Cookie"] {
        assert!(contains_credentials(&json!({"request":[{key:"value"}]})));
    }
    assert!(!contains_credentials(
        &json!({"password":null,"value":"ordinary"})
    ));
    assert!(!contains_credentials(
        &json!({"request":{"value":"ordinary"}})
    ));
    let mut deep = Value::Null;
    for _ in 0..10000 {
        deep = Value::Array(vec![deep]);
    }
    assert!(contains_credentials(&deep));
    drop_iteratively(deep);
    assert!(contains_credentials(&json!(vec![0; 4097])));
    assert!(contains_credentials(&json!({"value":"x".repeat(256*1024)})));
}
#[tokio::test]
async fn server_request_privacy_hides_malformed_model_output_and_backend_errors() {
    for mode in ["malformed", "plain", "error"] {
        let capture = Capture::default();
        let observed = capture.clone();
        async move {
            let requests = Arc::new(Mutex::new(vec![]));
            let (port, peer) = server_mock(mode, requests.clone()).await;
            let url = format!("http://127.0.0.1:{port}");
            let (tx, mut rx) = mpsc::unbounded_channel();
            let client = OllamaClient::new(&url).with_status_tx(tx);
            let state = AppState::new_with_options(false, url);
            state.set_ollama_model(Some("test-model".into())).await;
            let id = server_instance(&state, None).await;
            let e = netget::llm::action_helper::call_llm(
                &client,
                &state,
                id,
                None,
                &server_event(true),
                &TestProtocol { credential: false },
            )
            .await
            .err()
            .expect("invalid response must fail closed");
            assert!(!format!("{e:#}").contains(PASSWORD));
            assert_hidden(&observed.text(), &drain(&mut rx));
            assert!(
                requests
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|r| r.to_string().contains(PASSWORD)),
                "chosen model must receive intended typed credential input"
            );
            let logs = state
                .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
                .await;
            assert_eq!(logs[0].request["request"]["password"], PASSWORD);
            assert!(!serde_json::to_string(&logs[0].response)
                .unwrap()
                .contains(PASSWORD));
            state.remove_server(id).await;
            peer.abort();
            let _ = peer.await;
        }
        .with_subscriber(subscriber(capture))
        .await;
    }
}
#[tokio::test]
async fn server_private_and_ordinary_model_requests_preserve_actions_and_local_logging() {
    let capture = Capture::default();
    let observed = capture.clone();
    async move {
        let requests = Arc::new(Mutex::new(vec![]));
        let (port, peer) = server_mock("valid", requests).await;
        let url = format!("http://127.0.0.1:{port}");
        let (tx, mut rx) = mpsc::unbounded_channel();
        let client = OllamaClient::new(&url).with_status_tx(tx);
        let state = AppState::new_with_options(false, url);
        state.set_ollama_model(Some("test-model".into())).await;
        let private = server_instance(&state, None).await;
        let ordinary = server_instance(&state, None).await;
        let p = server_event(true);
        let o = server_event(false);
        let protocol = TestProtocol { credential: false };
        let (a, b) = tokio::join!(
            netget::llm::action_helper::call_llm(&client, &state, private, None, &p, &protocol),
            netget::llm::action_helper::call_llm(&client, &state, ordinary, None, &o, &protocol)
        );
        assert_eq!(
            a.unwrap().protocol_results[0].get_all_output(),
            vec![PASSWORD.as_bytes().to_vec()]
        );
        assert_eq!(
            b.unwrap().protocol_results[0].get_all_output(),
            vec![ORDINARY.as_bytes().to_vec()]
        );
        assert_hidden(&observed.text(), &drain(&mut rx));
        assert!(
            observed.text().contains(ORDINARY),
            "ordinary model payload remains visible"
        );
        state.remove_server(private).await;
        state.remove_server(ordinary).await;
        peer.abort();
        let _ = peer.await;
    }
    .with_subscriber(subscriber(capture))
    .await;
}
#[tokio::test]
async fn server_scripts_receive_intended_credentials_while_stderr_and_errors_stay_private() {
    let background = background_capture();
    let capture = Capture::default();
    let observed = capture.clone();
    async move {
        let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
        for resident in [false, true] {
            for fail in [false, true] {
                let handler = if resident {
                    let verdict = if fail { "raise Exception(value)" }
                        else { "return {'actions':[{'type':'ordinary_action','value':value}]}" };
                    EventHandlerType::script_resident("python", format!(
                        "import sys\ndef handle(event_type,event,message):\n value=event['request']['password']\n sys.stderr.write(value+'\\n')\n {verdict}"), None)
                } else {
                    let verdict = if fail { "raise Exception(v)" }
                        else { "print(json.dumps({'actions':[{'type':'ordinary_action','value':v}]}))" };
                    EventHandlerType::script("python", format!(
                        "import json,sys\ne=json.load(sys.stdin)['event']\nv=e['request']['password']\nsys.stderr.write(v)\n{verdict}"))
                };
                let id = server_instance(&state, Some(handler)).await;
                let event = server_event(true);
                let result = netget::llm::event_handler_executor::try_execute_event_handler(
                    &state, id, None, event.id(), &event.to_prompt_description(),
                    Some(event.data.clone()), Some(&TestProtocol { credential:false }),
                ).await.unwrap();
                match result {
                    netget::llm::event_handler_executor::EventHandlerResult::Handled(r) if !fail => {
                        assert_eq!(r.protocol_results[0].get_all_output(), vec![PASSWORD.as_bytes().to_vec()]);
                    }
                    netget::llm::event_handler_executor::EventHandlerResult::FallbackToLlm {..} if fail => {},
                    _ => panic!("unexpected handler result resident={resident} fail={fail}"),
                }
                state.remove_server(id).await;
            }
        }
        assert!(!observed.text().contains(PASSWORD));
        assert!(!background.text().contains(PASSWORD));
        let code = format!("import json,sys\njson.load(sys.stdin)\nsys.stderr.write({ORDINARY:?})\nprint('{{\"actions\":[]}}')");
        let id = server_instance(&state, Some(EventHandlerType::script("python",code))).await;
        let event = server_event(false);
        netget::llm::event_handler_executor::try_execute_event_handler(
            &state,id,None,event.id(),&event.to_prompt_description(),Some(event.data.clone()),
            Some(&TestProtocol {credential:false}),
        ).await.unwrap();
        assert!(observed.text().contains(ORDINARY), "ordinary stderr control remains visible");
        state.remove_server(id).await;
    }.with_subscriber(subscriber(capture)).await;
}

#[tokio::test]
async fn constructed_server_actions_and_handler_events_preflight_before_copy_or_drop() {
    fn deep() -> Value {
        let mut value = Value::Null;
        for _ in 0..10000 {
            value = Value::Array(vec![value]);
        }
        value
    }
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    assert!(netget::llm::actions::executor::execute_actions(
        vec![deep()],
        &state,
        None,
        None,
        None
    )
    .await
    .is_err());
    let id = server_instance(&state, None).await;
    assert!(
        netget::llm::event_handler_executor::try_execute_event_handler(
            &state,
            id,
            None,
            "test",
            "test",
            Some(deep()),
            None
        )
        .await
        .is_err()
    );
    let value = deep();
    let mut event = server_event(false);
    event.data = value;
    assert!(netget::llm::action_helper::call_llm(
        &OllamaClient::new("http://127.0.0.1:1"),
        &state,
        id,
        None,
        &event,
        &TestProtocol { credential: false }
    )
    .await
    .is_err());
    netget::utils::json_budget::drop_iteratively(event.data);
    state.remove_server(id).await;
    assert!(!netget::utils::json_budget::within_values_budget(
        [&json!("a"), &json!("b")],
        64,
        1,
        8
    ));
}

fn client_input_event(private: bool, authorization: bool) -> Event {
    static EVENT: std::sync::LazyLock<EventType> = std::sync::LazyLock::new(|| {
        EventType::new("test_connected", "Typed client input", json!({}))
    });
    Event::new(
        &EVENT,
        if private {
            if authorization {
                json!({"metadata":{"authorization":PASSWORD}})
            } else {
                json!({"request":{"password":PASSWORD}})
            }
        } else {
            json!({"request":{"value":ORDINARY}})
        },
    )
}

async fn client_with_input(
    state: &AppState,
    client: &OllamaClient,
    id: ClientId,
    input: &Event,
    tx: &mpsc::UnboundedSender<String>,
    direct: bool,
) -> anyhow::Result<netget::llm::ClientLlmResult> {
    let protocol = TestProtocol { credential: false };
    if direct {
        netget::llm::action_helper::call_llm_for_client(
            client,
            state,
            id.to_string(),
            "test",
            "",
            Some(input),
            &protocol,
            tx,
        )
        .await
    } else {
        call_llm_for_client(
            client,
            state,
            id.to_string(),
            "test",
            "",
            Some(input),
            &protocol,
            tx,
        )
        .await
    }
}

#[tokio::test]
async fn nested_client_input_hides_model_reflections_on_routed_and_direct_entries() {
    for openai in [false, true] {
        for direct in [false, true] {
            for authorization in [false, true] {
                for mode in ["malformed", "plain", "error", "valid"] {
                    let capture = Capture::default();
                    let observed = capture.clone();
                    async move {
                        let (port, peer) = mock(mode,openai).await;
                        let url = format!("http://127.0.0.1:{port}");
                        let (tx,mut rx) = mpsc::unbounded_channel();
                        let client = if openai {OllamaClient::new_openai(url.clone(),"fixture-api-key")}
                            else {OllamaClient::new(&url)}.with_status_tx(tx.clone());
                        let state = AppState::new_with_options(false,url);
                        state.set_ollama_model(Some("test-model".into())).await;
                        let id = instance(&state,None).await;
                        let input = client_input_event(true,authorization);
                        let result = client_with_input(&state,&client,id,&input,&tx,direct).await;
                        if mode == "valid" {
                            let actions = result.unwrap_or_else(|error| panic!("mode={mode} openai={openai} direct={direct} authorization={authorization}: {error}")).actions;
                            assert_eq!(actions[0]["value"],PASSWORD,"original typed input must reach model and action");
                            assert!(matches!(TestProtocol{credential:false}.execute_action(actions[0].clone()).unwrap(),ClientActionResult::SendData(bytes) if bytes == PASSWORD.as_bytes()));
                            if !direct {
                                let access = state.list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())),None).await;
                                assert_eq!(access[0].request,input.data,"intentional typed handler input is retained");
                                assert_eq!(access[0].response,vec![json!({"type":"ordinary_action"})]);
                            }
                        } else {
                            let error = result.err().expect("invalid private response must fail");
                            assert!(!format!("{error:#}").contains(PASSWORD));
                        }
                        assert_hidden(&observed.text(),&drain(&mut rx));
                        let ordinary = client_input_event(false,authorization);
                        let result = client_with_input(&state,&client,id,&ordinary,&tx,direct).await;
                        if mode == "valid" {
                            assert_eq!(result.unwrap().actions[0]["value"],ORDINARY);
                            assert!(observed.text().contains(ORDINARY),"ordinary control retains payload diagnostics");
                            if !direct {
                                let access = state.list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())),None).await;
                                assert_eq!(access[0].request,ordinary.data);
                                assert_eq!(access[0].response[0]["value"],ORDINARY);
                            }
                        } else if mode == "error" {
                            assert!(format!("{:#}",result.err().unwrap()).contains(ORDINARY),"ordinary backend error context retained");
                        }
                        peer.abort(); let _ = peer.await;
                        state.remove_client(id).await;
                    }.with_subscriber(subscriber(capture)).await;
                }
            }
        }
    }
}

#[tokio::test]
async fn nested_client_input_privacy_reaches_direct_static_and_script_handlers() {
    let background = background_capture();
    let capture = Capture::default();
    let observed = capture.clone();
    async move {
        let state = AppState::new_with_options(false,"http://127.0.0.1:1".into());
        for routed in [false,true] {
            for resident in [false,true] {
                for fail in [false,true] {
                    let handler = if resident {
                        let verdict = if fail {"raise Exception(value)"} else {"return {'actions':[{'type':'ordinary_action','value':value}]}"};
                        EventHandlerType::script_resident("python",format!("import sys\ndef handle(event_type,event,message):\n value=event['request']['password']\n sys.stderr.write(value+'\\n')\n {verdict}"),None)
                    } else {
                        let verdict = if fail {"raise Exception(value)"} else {"print(json.dumps({'actions':[{'type':'ordinary_action','value':value}]}))"};
                        EventHandlerType::script("python",format!("import json,sys\ne=json.load(sys.stdin)['event']\nvalue=e['request']['password']\nsys.stderr.write(value)\n{verdict}"))
                    };
                    let id = instance(&state,Some(handler)).await;
                    let input = client_input_event(true,false);
                    if routed {
                        let (tx,mut rx) = mpsc::unbounded_channel();
                        let result = client_with_input(&state,&OllamaClient::new("http://127.0.0.1:1"),id,&input,&tx,false).await;
                        if fail { assert!(result.is_err()); }
                        else { assert_eq!(result.unwrap().actions[0]["value"],PASSWORD); }
                        assert_hidden(&observed.text(),&drain(&mut rx));
                    } else {
                        let result = netget::llm::event_handler_executor::try_execute_client_event_handler(&state,id,input.id(),&input.to_prompt_description(),Some(input.data.clone())).await.unwrap();
                        match result {
                            netget::llm::event_handler_executor::ClientEventHandlerResult::Handled {actions} if !fail => assert_eq!(actions[0]["value"],PASSWORD),
                            netget::llm::event_handler_executor::ClientEventHandlerResult::FallbackToLlm {..} if fail => {},
                            _ => panic!("unexpected script result routed={routed} resident={resident} fail={fail}"),
                        }
                    }
                    assert!(!observed.text().contains(PASSWORD));
                    assert!(!background.text().contains(PASSWORD));
                    state.remove_client(id).await;
                }
            }
        }
        for direct in [false,true] {
            let input = client_input_event(true,false);
            let id = instance(&state,Some(EventHandlerType::static_response(vec![json!({"type":"ordinary_action","value":"{{event.request.password}}"})]))).await;
            if direct {
                let result = netget::llm::event_handler_executor::try_execute_client_event_handler(&state,id,input.id(),&input.to_prompt_description(),Some(input.data.clone())).await.unwrap();
                match result {netget::llm::event_handler_executor::ClientEventHandlerResult::Handled{actions} => assert_eq!(actions[0]["value"],PASSWORD),_=>panic!("static handler must handle")}
            } else {
                let (tx,mut rx)=mpsc::unbounded_channel();
                assert_eq!(client_with_input(&state,&OllamaClient::new("http://127.0.0.1:1"),id,&input,&tx,false).await.unwrap().actions[0]["value"],PASSWORD);
                assert_hidden(&observed.text(),&drain(&mut rx));
            }
            state.remove_client(id).await;
        }
        let handler = EventHandlerType::script("python",format!("import json,sys\ne=json.load(sys.stdin)['event']\nsys.stderr.write(e['request']['value'])\nprint('{{\"actions\":[]}}')"));
        let id = instance(&state,Some(handler)).await;
        let input = client_input_event(false,false);
        netget::llm::event_handler_executor::try_execute_client_event_handler(&state,id,input.id(),&input.to_prompt_description(),Some(input.data.clone())).await.unwrap();
        assert!(observed.text().contains(ORDINARY),"ordinary script stderr remains visible");
        state.remove_client(id).await;
    }.with_subscriber(subscriber(capture)).await;
}

#[tokio::test]
async fn constructed_client_events_preflight_before_routing_copy_or_recursive_drop() {
    fn deep() -> Value {
        let mut value = Value::Null;
        for _ in 0..10_000 {
            value = Value::Array(vec![value]);
        }
        value
    }
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let id = instance(&state, None).await;
    for external_private in [false, true] {
        assert!(
            netget::llm::event_handler_executor::try_execute_client_event_handler_with_privacy(
                &state,
                id,
                "test",
                "test",
                Some(deep()),
                external_private
            )
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("budget")
        );
    }
    assert!(
        netget::llm::event_handler_executor::try_execute_client_event_handler(
            &state,
            id,
            "test",
            "test",
            Some(deep())
        )
        .await
        .is_err()
    );
    let mut input = client_input_event(false, false);
    input.data = deep();
    let (tx, _rx) = mpsc::unbounded_channel();
    for direct in [false, true] {
        let error = client_with_input(
            &state,
            &OllamaClient::new("http://127.0.0.1:1"),
            id,
            &input,
            &tx,
            direct,
        )
        .await
        .err()
        .unwrap();
        assert!(error.to_string().contains("budget"));
    }
    assert_eq!(
        state.get_client_llm_calls(id).await,
        0,
        "invalid constructed input must not debit model budget"
    );
    netget::utils::json_budget::drop_iteratively(input.data);
    state.remove_client(id).await;
}

#[tokio::test]
async fn private_errors_preserve_numeric_overload_category_without_secret_context() {
    use netget::llm::rate_limiter::RateLimitError;
    use netget::utils::{redact::hide_error_details, wire_failure::WireFailure};
    for category in [
        RateLimitError::QueueFull { max_queued: 1 },
        RateLimitError::QueueTimeout { waited_secs: 1 },
        RateLimitError::TokenLimit {
            limit: 10,
            window_secs: 60,
        },
    ] {
        let error = hide_error_details(anyhow::Error::new(category).context(PASSWORD));
        assert_eq!(error.downcast_ref::<RateLimitError>(), Some(&category));
        assert_eq!(WireFailure::classify(&error), WireFailure::Overloaded);
        assert_eq!(error.chain().count(), 1, "untyped context must be removed");
        assert!(!format!("{error:#}").contains(PASSWORD));
    }
    let error = hide_error_details(anyhow::anyhow!(PASSWORD).context("backend context"));
    assert_eq!(WireFailure::classify(&error), WireFailure::Unavailable);
    assert!(!format!("{error:#}").contains(PASSWORD));
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state.set_ollama_model(Some("test-model".into())).await;
    state
        .configure_rate_limiter(RateLimiterConfig {
            max_concurrent: 1,
            max_queued: 1,
            queue_timeout_secs: 30,
            ..Default::default()
        })
        .await
        .unwrap();
    let limiter = state.get_rate_limiter().await;
    let held = limiter
        .acquire_permit(RequestSource::Network)
        .await
        .unwrap();
    let queued = {
        let limiter = limiter.clone();
        tokio::spawn(async move { limiter.acquire_permit(RequestSource::Network).await })
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if limiter.get_stats().await.currently_queued == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let server = server_instance(&state, None).await;
    let input = server_event(true);
    let error = netget::llm::action_helper::call_llm(
        &OllamaClient::new("http://127.0.0.1:1"),
        &state,
        server,
        None,
        &input,
        &TestProtocol { credential: false },
    )
    .await
    .err()
    .unwrap();
    assert_eq!(WireFailure::classify(&error), WireFailure::Overloaded);
    assert_eq!(
        error.downcast_ref::<RateLimitError>(),
        Some(&RateLimitError::QueueFull { max_queued: 1 })
    );
    assert_eq!(error.chain().count(), 1);
    assert!(!format!("{error:#}").contains(PASSWORD));
    let client = instance(&state, None).await;
    let input = client_input_event(true, false);
    let (tx, mut rx) = mpsc::unbounded_channel();
    for direct in [false, true] {
        let error = client_with_input(
            &state,
            &OllamaClient::new("http://127.0.0.1:1"),
            client,
            &input,
            &tx,
            direct,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(WireFailure::classify(&error), WireFailure::Overloaded);
        assert_eq!(error.chain().count(), 1);
        assert!(!format!("{error:#}").contains(PASSWORD));
    }
    assert!(!drain(&mut rx).contains(PASSWORD));
    drop(held);
    let permit = tokio::time::timeout(Duration::from_secs(3), queued)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(permit);
    assert_eq!(limiter.get_stats().await.currently_queued, 0);
    state.remove_client(client).await;
    state.remove_server(server).await;
}

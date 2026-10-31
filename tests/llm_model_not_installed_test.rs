//! A model the endpoint does not have is said to be missing, in plain words, everywhere.
//!
//! Reproduced 31 October 2026 on the installed `netget --mcp`: the saved settings named
//! `qwen3.5:0.8b-q8_0`, which the local Ollama did not have. `get_status` reported it as the
//! model anyway, and every request failed in ~40 ms with the access-log error
//! "✗  LLM failed to generate valid response after retries." — no retry had happened, and the
//! real cause (Ollama's 404, model not found) was visible nowhere.
//!
//! The mock here behaves like an Ollama with two models installed: `/api/tags` lists them and a
//! request naming any other is answered 404 `model "…" not found`, as Ollama answers it.
//!
//! - **Startup**: a saved model the endpoint lacks is replaced by an installed one, and
//!   `get_status` shows the model actually used plus a note naming the missing one and the
//!   endpoint.
//! - **`set_model`** refuses a model the endpoint does not list, naming it, the endpoint and
//!   what is installed.
//! - **A request** that meets the backend's model-not-found is made once — not retried as if
//!   the model had answered badly — and its access-log entry, `get_status` and the log say
//!   "not installed" with the model and the endpoint, never "after retries". The peer gets no
//!   error text.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,mcp-http,sqlite,terminal-snapshot \
//!       --test llm_model_not_installed_test

#![cfg(feature = "mcp-stdio")]
#![allow(dead_code, unused_imports)]

mod helpers;

use std::time::Duration;

use helpers::mock_builder::MockLlmBuilder;
use helpers::mock_ollama::MockOllamaServer;
use helpers::E2EResult;

use clap::Parser;
use netget::cli::Args;
use netget::mcp_stdio::tools::NetGetMcpService;
use netget::settings::Settings;
use netget::state::app_state::AppState;

use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::{serve_client, RoleClient, ServiceExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MISSING: &str = "qwen3.5:0.8b-q8_0";
const INSTALLED: [&str; 2] = ["gemma3:1b", "llama3.1:8b"];

/// An MCP service whose saved settings name `MISSING`, pointed at `ollama_url`.
async fn connect(ollama_url: &str) -> (rmcp::service::RunningService<RoleClient, ()>, AppState) {
    let args = Args::parse_from(["netget", "--ollama-url", ollama_url, "--no-scripts"]);
    let mut settings = Settings::default();
    settings.model = Some(MISSING.to_string());
    let service = NetGetMcpService::new(&args, settings)
        .await
        .expect("service creation");
    let app_state = service.app_state();

    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(server) = service.serve(server_io).await {
            let _ = server.waiting().await;
        }
    });
    let client = serve_client((), client_io).await.expect("client handshake");
    (client, app_state)
}

async fn call(
    client: &rmcp::service::RunningService<RoleClient, ()>,
    name: &'static str,
    args: serde_json::Value,
) -> CallToolResult {
    let mut params = CallToolRequestParams::new(name);
    params.arguments = args.as_object().cloned();
    client.call_tool(params).await.expect("call tool")
}

fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
        .collect()
}

fn parse_number_after(text: &str, marker: &str) -> u64 {
    let idx = text
        .find(marker)
        .unwrap_or_else(|| panic!("marker {:?} not found in: {}", marker, text));
    text[idx + marker.len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("no number after {:?} in: {}", marker, text))
}

/// The line of `get_status` starting with `- **<label>**:`.
fn status_line<'a>(status: &'a str, label: &str) -> Option<&'a str> {
    let prefix = format!("- **{}**: ", label);
    status
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
}

/// Model requests (`/api/generate` + `/api/chat`) that reached the mock, 404s included.
fn model_requests(mock: &MockOllamaServer) -> usize {
    mock.recorded_request_fields().len()
}

/// Send one line to a TCP server and read until it closes or answers.
async fn exchange(port: u16, line: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    sock.write_all(line.as_bytes()).await.expect("write");
    let mut received = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match tokio::time::timeout(Duration::from_secs(15), sock.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                received.extend_from_slice(&buf[..n]);
                if received.ends_with(b"\n") {
                    break;
                }
            }
        }
    }
    String::from_utf8_lossy(&received).into_owned()
}

/// The newest access-log entry for `event`, waiting up to 15 s for it to appear.
async fn wait_for_entry(state: &AppState, event: &str, after: usize) -> Vec<serde_json::Value> {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let entries: Vec<_> = state
            .list_access_logs(None)
            .await
            .into_iter()
            .filter(|e| e.event_type == event)
            .collect();
        if entries.len() > after {
            let newest = entries.into_iter().max_by_key(|e| e.id).expect("an entry");
            return newest.response;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no access-log entry for {event} within 15 s"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn a_model_the_endpoint_does_not_have_is_reported_as_not_installed() -> E2EResult<()> {
    // Only the request with an installed model reaches a rule; the 404s are answered before
    // rule matching, exactly as real Ollama never runs a model it does not have.
    let mock_config = MockLlmBuilder::new()
        .on_event("tcp_data_received")
        .respond_with_actions(serde_json::json!([
            { "type": "send_tcp_data", "data": "pong\n" }
        ]))
        .expect_calls(1)
        .and()
        .build();
    let mock = MockOllamaServer::start(mock_config).await?;
    mock.set_installed_models(&INSTALLED);
    let url = mock.base_url();
    let (client, state) = connect(&url).await;

    // --- Startup: the saved model is checked, and an installed one is what gets used. ---
    let status = text_of(&call(&client, "get_status", serde_json::json!({})).await);
    let model = status_line(&status, "Model").expect("a Model line");
    assert!(
        INSTALLED.contains(&model),
        "get_status must show the model actually used, an installed one; got {model:?} in:\n{status}"
    );
    assert_eq!(state.get_ollama_model().await.as_deref(), Some(model));
    let note = status_line(&status, "Model note").unwrap_or_else(|| {
        panic!("get_status must say the configured model was replaced:\n{status}")
    });
    for needle in [MISSING, "not installed", url.as_str()] {
        assert!(note.contains(needle), "note lacks {needle:?}: {note}");
    }
    let check = status_line(&status, "Model check").expect("a Model check line");
    assert!(check.starts_with("installed at"), "{check}");

    // --- set_model refuses what the endpoint does not list. ---
    let refused = call(
        &client,
        "set_model",
        serde_json::json!({ "model": MISSING }),
    )
    .await;
    assert_eq!(refused.is_error, Some(true), "{}", text_of(&refused));
    let refused = text_of(&refused);
    for needle in [
        MISSING,
        "not installed",
        url.as_str(),
        INSTALLED[0],
        INSTALLED[1],
    ] {
        assert!(
            refused.contains(needle),
            "refusal lacks {needle:?}: {refused}"
        );
    }
    assert_eq!(
        state.get_ollama_model().await.as_deref(),
        Some(model),
        "a refused set_model must leave the model alone"
    );
    // An untagged name resolves to `:latest`; a listed name is accepted.
    let accepted = call(
        &client,
        "set_model",
        serde_json::json!({ "model": INSTALLED[1] }),
    )
    .await;
    assert_ne!(accepted.is_error, Some(true), "{}", text_of(&accepted));

    // --- A request meets the backend's model-not-found. ---
    // The model disappears after startup (or was pinned some other way): the request is the
    // first to find out.
    state.set_ollama_model(Some(MISSING.to_string())).await;
    let status = text_of(&call(&client, "get_status", serde_json::json!({})).await);
    let check = status_line(&status, "Model check").expect("a Model check line");
    assert!(
        check.starts_with("NOT INSTALLED") && check.contains(MISSING) && check.contains(&url),
        "get_status must check the model it reports:\n{status}"
    );

    let started = call(
        &client,
        "start_server",
        serde_json::json!({
            "protocol": "tcp",
            "port": 0,
            "instruction": "Answer every line with pong.",
        }),
    )
    .await;
    assert_ne!(started.is_error, Some(true), "{}", text_of(&started));
    let port = parse_number_after(&text_of(&started), "listening on 127.0.0.1:") as u16;

    let before = model_requests(&mock);
    let peer_saw = exchange(port, "ping\n").await;
    let failed = wait_for_entry(&state, "tcp_data_received", 0).await;
    // Give a retry, if there were one, time to land before counting.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        model_requests(&mock) - before,
        1,
        "a model-not-found is not a bad answer: exactly one request, no retries"
    );

    let error = failed[0]["error"].as_str().unwrap_or_default().to_string();
    for needle in [MISSING, "not installed", url.as_str()] {
        assert!(
            error.contains(needle),
            "access-log failure lacks {needle:?}: {failed:?}"
        );
    }
    assert!(
        !error.contains("after retries"),
        "nothing was retried, so nothing may say so: {error}"
    );
    // Fail closed on the wire: the peer gets no diagnosis.
    assert!(
        !peer_saw.contains(MISSING) && !peer_saw.contains("not installed"),
        "the peer must not see the backend error: {peer_saw:?}"
    );

    let status = text_of(&call(&client, "get_status", serde_json::json!({})).await);
    let last = status_line(&status, "Last LLM backend failure")
        .unwrap_or_else(|| panic!("get_status must show the request's failure:\n{status}"));
    assert!(
        last.contains(MISSING) && last.contains("not installed") && last.contains(&url),
        "{last}"
    );

    // --- Control: the same request against an installed model is answered, once. ---
    let fixed = call(
        &client,
        "set_model",
        serde_json::json!({ "model": INSTALLED[0] }),
    )
    .await;
    assert_ne!(fixed.is_error, Some(true), "{}", text_of(&fixed));
    let before = model_requests(&mock);
    let answer = exchange(port, "ping\n").await;
    assert_eq!(answer, "pong\n", "the installed model answers");
    assert_eq!(model_requests(&mock) - before, 1);
    let status = text_of(&call(&client, "get_status", serde_json::json!({})).await);
    assert!(
        status_line(&status, "Last LLM backend failure").is_none(),
        "a request the backend answered clears the failure:\n{status}"
    );

    mock.wait_for_expectations(30).await;
    mock.verify_calls().await?;
    client.cancel().await.expect("shutdown");
    Ok(())
}

/// With no model configured, the first request's auto-selection is stored: it is the model
/// later requests use and the one `get_status` names, and the endpoint is asked once.
#[tokio::test]
async fn an_auto_selected_model_is_recorded_as_the_model_in_use() -> E2EResult<()> {
    let mock = MockOllamaServer::start(MockLlmBuilder::new().build()).await?;
    mock.set_installed_models(&INSTALLED);
    let state = AppState::new_with_options(false, mock.base_url());
    assert_eq!(state.get_ollama_model().await, None);

    let chosen = netget::llm::model_selection::ensure_state_model(&state).await?;
    assert!(INSTALLED.contains(&chosen.as_str()), "{chosen}");
    assert_eq!(
        state.get_ollama_model().await.as_deref(),
        Some(chosen.as_str()),
        "the auto-selected model must be the model in use, not re-chosen per request"
    );
    let notice = state.model_health().notice.unwrap_or_default();
    assert!(
        notice.contains(&chosen) && notice.contains(&mock.base_url()),
        "{notice}"
    );

    let again = netget::llm::model_selection::ensure_state_model(&state).await?;
    assert_eq!(again, chosen);
    assert_eq!(mock.tags_request_count(), 1, "chosen once, then reused");
    Ok(())
}

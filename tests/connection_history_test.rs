//! Does the model see what already happened on a connection?
//!
//! Every network event used to reach the model alone. A telnet peer typing `hi` and then
//! `what did i say` got an answer from a prompt holding only the second line, so the model
//! could not know — and said so, or made something up. `src/state/exchange_history.rs` now
//! records each exchange on a connection and the server's LLM path renders it ahead of the
//! current event.
//!
//! The end-to-end test drives a real telnet server through two lines and reads the prompt the
//! mock model received for the second. It holds a control in the same test: the same exchange
//! with history switched off must produce a prompt *without* the first line, otherwise the
//! positive half would pass on a prompt that happened to contain "hi" for some other reason.
//! It also checks the mock read the *current* event's data, not the earlier one rendered above
//! it — the mock finds an event by its trigger labels, and history must not look like one.
//!
//! The remaining tests pin the bounds on [`ExchangeHistory`] directly: the entry limit, the
//! prompt budget, and that credentials are not repeated.

mod helpers;

use std::time::Duration;

use helpers::mock_builder::MockLlmBuilder;
use helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::exchange_history::{ExchangeHistory, HISTORY_PROMPT_BUDGET_CHARS};
use netget::state::ServerId;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

/// Read lines until one contains `needle`, or fail after the deadline.
async fn read_until<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R, needle: &str) -> String {
    let mut seen = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let mut line = String::new();
        let read = tokio::time::timeout_at(deadline, reader.read_line(&mut line))
            .await
            .unwrap_or_else(|_| {
                panic!("no line containing {needle:?} arrived; read so far: {seen:?}")
            })
            .expect("read");
        assert!(
            read > 0,
            "connection closed before {needle:?}; read so far: {seen:?}"
        );
        seen.push_str(&line);
        if line.contains(needle) {
            return seen;
        }
    }
}

/// Start a telnet server answering `you said <line>`, send `hi` then `what did i say`, and
/// return the full prompt the model received for the second line together with the event
/// data the mock extracted from it.
async fn second_prompt(history_entries: Option<u16>) -> (String, serde_json::Value) {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("telnet_message_received")
            .respond_with_actions_from_event(|event| {
                let message = event["message"].as_str().unwrap_or_default().to_string();
                serde_json::json!([{ "type": "send_telnet_line", "line": format!("you said {message}") }])
            })
            .expect_at_least(2)
            .and()
            // The connect greeting, if the server asks for one: answer with nothing.
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
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
        protocol: "telnet".to_string(),
        port: Some(0),
        instruction: Some("Repeat back what the peer says.".to_string()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create telnet server");
    if let Some(entries) = history_entries {
        state
            .set_server_conversation_settings(id, entries, false)
            .await;
    }
    let port = wait_for_port(&state, id).await;

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write_half.write_all(b"hi\r\n").await.expect("write hi");
    read_until(&mut reader, "you said hi").await;
    write_half
        .write_all(b"what did i say\r\n")
        .await
        .expect("write second line");
    read_until(&mut reader, "you said what did i say").await;

    let calls = mock.recorded_calls().await;
    let call = calls
        .iter()
        .find(|c| {
            c.context.prompt.contains("what did i say")
                && c.context.event_type.as_deref() == Some("telnet_message_received")
                && c.context.event_data["message"] == "what did i say"
        })
        .unwrap_or_else(|| {
            panic!(
                "no recorded call carried the second line as its current event. Calls: {:#?}",
                calls
                    .iter()
                    .map(|c| (&c.context.event_type, &c.context.event_data))
                    .collect::<Vec<_>>()
            )
        });
    let result = (call.context.prompt.clone(), call.context.event_data.clone());
    let _ = state.remove_server(id).await;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_model_sees_earlier_lines_on_the_same_connection() {
    // === Control: history off. The second prompt must not carry the first line. ===
    let (without, _) = second_prompt(Some(0)).await;
    assert!(
        !without.contains("Earlier on this connection"),
        "CONTROL FAILED: with history off the prompt must hold no history block, or the \
         assertions below cannot tell history from coincidence:\n{without}"
    );
    assert!(
        !without.contains("you said hi"),
        "CONTROL FAILED: with history off nothing in the prompt should repeat the first \
         answer:\n{without}"
    );

    // === The claim: telnet's declared default shows the first exchange. ===
    let (with, event_data) = second_prompt(None).await;
    let history_at = with
        .find("Earlier on this connection")
        .unwrap_or_else(|| panic!("no history block in the second prompt:\n{with}"));
    let trigger_at = with
        .rfind("Event ID: telnet_message_received")
        .expect("the current event's trigger");
    assert!(
        history_at < trigger_at,
        "history must come before the event being answered, so the event is the last thing \
         the model reads:\n{with}"
    );
    let history = &with[history_at..trigger_at];
    assert!(
        history.contains(r#""message":"hi""#),
        "the first line the peer sent is missing from the history:\n{history}"
    );
    assert!(
        history.contains("you said hi"),
        "what answered the first line is missing from the history:\n{history}"
    );
    assert!(
        !history
            .lines()
            .any(|l| l.trim_start().starts_with("Event ID:")
                || l.trim_start().starts_with("Event:")
                || l.contains("Context data:")),
        "the history block must not look like a trigger — the prompt's reader and the mock both \
         find the current event by those labels:\n{history}"
    );
    assert_eq!(
        event_data["message"], "what did i say",
        "the mock must read the current event's data, not the earlier exchange above it"
    );
}

#[test]
fn history_keeps_at_most_the_entry_limit() {
    let mut history = ExchangeHistory::new();
    for i in 0..100 {
        history.record(
            "telnet_message_received",
            &serde_json::json!({ "message": format!("line {i}") }),
            &[serde_json::json!({ "type": "send_telnet_line", "line": "ok" })],
            40,
        );
    }
    assert_eq!(history.len(), 40, "kept more entries than the limit");
    assert_eq!(history.recorded(), 100);

    let rendered = history.render(40).expect("something to render");
    assert!(
        !rendered.contains("\"line 59\""),
        "an entry older than the limit was rendered"
    );
    assert!(
        rendered.contains("\"line 99\""),
        "the newest entry is missing"
    );
    assert!(
        rendered.contains("earlier not shown"),
        "the block must say that older entries were dropped:\n{rendered}"
    );
}

#[test]
fn history_stays_within_the_prompt_budget() {
    let mut history = ExchangeHistory::new();
    let long = "x".repeat(2_000);
    for _ in 0..40 {
        history.record(
            "tcp_data_received",
            &serde_json::json!({ "data": long }),
            &[serde_json::json!({ "type": "send_tcp_data", "data": long })],
            40,
        );
    }
    let rendered = history.render(40).expect("something to render");
    // The header line is the only thing allowed past the entry budget.
    let header = rendered.lines().next().unwrap_or_default().len() + 1;
    assert!(
        rendered.len() <= HISTORY_PROMPT_BUDGET_CHARS + header,
        "rendered history is {} bytes, over the {}-byte budget",
        rendered.len(),
        HISTORY_PROMPT_BUDGET_CHARS
    );
    assert!(
        rendered.contains("(cut)"),
        "a long entry must be cut and say so"
    );
}

#[test]
fn history_does_not_repeat_credentials() {
    let mut history = ExchangeHistory::new();
    history.record(
        "ssh_auth",
        &serde_json::json!({ "username": "ada", "password": "hunter2" }),
        &[serde_json::json!({ "type": "ssh_auth_decision", "allow": true })],
        40,
    );
    history.record(
        "telnet_message_received",
        &serde_json::json!({ "message": "ls" }),
        &[serde_json::json!({ "type": "send_telnet_line", "line": "file.txt" })],
        40,
    );
    let rendered = history.render(40).expect("something to render");
    assert!(
        !rendered.contains("hunter2"),
        "a password reached the history:\n{rendered}"
    );
    assert!(
        rendered.contains("carried credentials"),
        "the credential-bearing exchange must still be marked as having happened:\n{rendered}"
    );
    assert!(
        rendered.contains("file.txt"),
        "the ordinary exchange is missing:\n{rendered}"
    );
}

#[test]
fn history_off_records_nothing() {
    let mut history = ExchangeHistory::new();
    history.record(
        "telnet_message_received",
        &serde_json::json!({ "message": "hi" }),
        &[],
        0,
    );
    assert!(history.is_empty());
    assert!(history.render(0).is_none());
}

/// An instance's history and batching come from the protocol's declaration, can be overridden
/// at start and in place, and a request the protocol cannot honour is refused without touching
/// the running instance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn history_and_batching_overrides_apply_and_refuse_cleanly() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");
    let state = AppState::new_with_options(false, mock.base_url());
    let (tx, _rx) = mpsc::unbounded_channel();

    // Declared default: telnet shows 40 earlier entries and cannot batch.
    let declared = ServerForm {
        protocol: "telnet".to_string(),
        port: Some(0),
        instruction: Some("x".to_string()),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create with defaults");
    assert_eq!(
        state.server_conversation_settings(declared).await,
        Some((netget::protocol::metadata::SESSION_HISTORY_ENTRIES, false))
    );

    // Overridden at start.
    let overridden = ServerForm {
        protocol: "telnet".to_string(),
        port: Some(0),
        instruction: Some("x".to_string()),
        history: Some(5),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create with history 5");
    assert_eq!(
        state.server_conversation_settings(overridden).await,
        Some((5, false))
    );

    // Batching on a protocol that cannot batch is refused at start, naming the reason.
    let refused = ServerForm {
        protocol: "telnet".to_string(),
        port: Some(0),
        instruction: Some("x".to_string()),
        batching: Some(true),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect_err("batching on telnet must be refused while telnet cannot batch");
    assert!(
        refused.to_string().contains("cannot batch"),
        "the refusal must say why: {refused}"
    );

    // Hot update: in place, same id, no restart.
    let outcome = netget::cli::management::update_server(
        &state,
        overridden,
        ServerForm {
            history: Some(0),
            ..Default::default()
        },
        tx.clone(),
    )
    .await
    .expect("update history");
    assert!(
        !outcome.restarted,
        "a history change must not restart the server"
    );
    assert_eq!(
        state.server_conversation_settings(overridden).await,
        Some((0, false))
    );

    // A refused update leaves the instance exactly as it was.
    netget::cli::management::update_server(
        &state,
        overridden,
        ServerForm {
            history: Some(7),
            batching: Some(true),
            ..Default::default()
        },
        tx.clone(),
    )
    .await
    .expect_err("batching on telnet must be refused on update too");
    assert_eq!(
        state.server_conversation_settings(overridden).await,
        Some((0, false)),
        "a refused update changed the instance"
    );

    // The model's own open_client / update_server actions accept the fields.
    let action: netget::llm::actions::common::CommonAction = serde_json::from_value(
        serde_json::json!({"type": "update_server", "server_id": 1, "history": 12, "batching": false}),
    )
    .expect("update_server with history/batching parses");
    match action {
        netget::llm::actions::common::CommonAction::UpdateServer {
            history, batching, ..
        } => {
            assert_eq!(history, Some(12));
            assert_eq!(batching, Some(false));
        }
        other => panic!("parsed as {other:?}"),
    }

    let _ = state.remove_server(declared).await;
    let _ = state.remove_server(overridden).await;
}

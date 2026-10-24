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
use helpers::mock_config::MockGate;
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

/// Wait until the peer has acknowledged every byte written on `stream`.
///
/// TCP acknowledges bytes once they are in the receiving socket's buffer, so after this the
/// server can read them without waiting for anything. A completed write does not promise that:
/// macOS hands loopback traffic to an input thread, and under load a line written a moment ago
/// can still be on its way when the server looks — which a test of "what had arrived" would
/// then misread as the server failing to take it.
///
/// Where the platform cannot say (neither Linux nor macOS), this returns at once.
async fn wait_until_acknowledged(stream: &tokio::net::tcp::OwnedWriteHalf) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match unacknowledged_bytes(stream) {
            None | Some(0) => return,
            Some(n) => assert!(
                tokio::time::Instant::now() < deadline,
                "{n} written bytes were never acknowledged by the server"
            ),
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Bytes written on `stream` that the peer has not acknowledged yet, where the OS will say.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn unacknowledged_bytes(stream: &tokio::net::tcp::OwnedWriteHalf) -> Option<usize> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_ref().as_raw_fd();
    let mut n: libc::c_int = 0;
    // Linux: TIOCOUTQ (SIOCOUTQ) on a TCP socket is everything not yet acknowledged, sent or not.
    #[cfg(target_os = "linux")]
    // SAFETY: `fd` is a live socket owned by `stream`; `n` is a valid `c_int` to write into.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut n) };
    // macOS: SO_NWRITE is the send buffer's byte count, and TCP keeps data there until it is
    // acknowledged.
    #[cfg(target_vendor = "apple")]
    let rc = {
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: as above; `len` holds the size of `n`.
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NWRITE,
                (&mut n as *mut libc::c_int).cast(),
                &mut len,
            )
        }
    };
    (rc == 0).then_some(n.max(0) as usize)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn unacknowledged_bytes(_stream: &tokio::net::tcp::OwnedWriteHalf) -> Option<usize> {
    None
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

    // Declared default: telnet shows 40 earlier entries and batches.
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
        Some((netget::protocol::metadata::SESSION_HISTORY_ENTRIES, true))
    );

    // Overridden at start.
    let overridden = ServerForm {
        protocol: "telnet".to_string(),
        port: Some(0),
        instruction: Some("x".to_string()),
        history: Some(5),
        batching: Some(false),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create with history 5, batching off");
    assert_eq!(
        state.server_conversation_settings(overridden).await,
        Some((5, false))
    );

    // Batching on a protocol that cannot batch is refused at start, naming the reason. HTTP
    // owes each request its own response, so it declares batching unsupported.
    let refused = ServerForm {
        protocol: "http".to_string(),
        port: Some(0),
        instruction: Some("x".to_string()),
        batching: Some(true),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect_err("batching on http must be refused");
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
            batching: Some(true),
            ..Default::default()
        },
        tx.clone(),
    )
    .await
    .expect("update history and batching");
    assert!(
        !outcome.restarted,
        "a history or batching change must not restart the server"
    );
    assert_eq!(
        state.server_conversation_settings(overridden).await,
        Some((0, true))
    );

    // A refused update leaves the instance exactly as it was.
    let http = ServerForm {
        protocol: "http".to_string(),
        port: Some(0),
        instruction: Some("x".to_string()),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create http");
    assert_eq!(
        state.server_conversation_settings(http).await,
        Some((0, false))
    );
    netget::cli::management::update_server(
        &state,
        http,
        ServerForm {
            history: Some(7),
            batching: Some(true),
            ..Default::default()
        },
        tx.clone(),
    )
    .await
    .expect_err("batching on http must be refused on update too");
    assert_eq!(
        state.server_conversation_settings(http).await,
        Some((0, false)),
        "a refused update changed the instance"
    );
    let _ = state.remove_server(http).await;

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

/// Send `first`, then — while the model is still answering it — `second` and `third`, and
/// return the prompts of every `telnet_message_received` call the model received.
///
/// `second` is the text of the second line, so a caller can make it long enough to end
/// exactly where one socket read does.
///
/// "While the model is still answering" is made true rather than likely: the answer to `first`
/// is held on a gate until both later lines have been written. It used to be a 1.5 s delay
/// started when the mock had seen *any* call — and every telnet connection raises
/// `telnet_connection_opened` before its first line is read, so under load the test could see
/// that call, write `second` and `third` before the server had read `first`, and the server
/// then correctly answered all three in one batch.
async fn prompts_for_three_lines(batching: bool, second: &str) -> Vec<(String, serde_json::Value)> {
    let first_answer = MockGate::new();
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            // The answer to the first line waits until the next two have been sent.
            .on_event("telnet_message_received")
            .and_event_data_contains("message", "first")
            .respond_with_actions(serde_json::json!([
                { "type": "send_telnet_line", "line": "got first" }
            ]))
            .held_until(&first_answer)
            .expect_calls(1)
            .and()
            .on_event("telnet_message_received")
            .respond_with_actions_from_event(|event| {
                let message = event["message"].as_str().unwrap_or_default().to_string();
                serde_json::json!([{ "type": "send_telnet_line", "line": format!("got {message}") }])
            })
            .expect_at_least(1)
            .and()
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
        instruction: Some("Acknowledge every line.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create telnet server");
    let port = wait_for_port(&state, id).await;

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write_half.write_all(b"first\r\n").await.expect("write");
    // Wait for the call answering `first` itself. The connect event's call comes earlier and
    // proves nothing about where the server is: it is made before the first line is read.
    // Once the call for `first` is recorded, that line's batch has been collected and the
    // server is waiting on the model, which cannot answer until the gate opens.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !mock.recorded_calls().await.iter().any(|c| {
        c.context.event_type.as_deref() == Some("telnet_message_received")
            && c.context.event_data["message"] == "first"
    }) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the first line never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Typed as two separate lines, both before the answer to `first` exists, and both in the
    // server's receive buffer before that answer is let go.
    write_half
        .write_all(format!("{second}\r\n").as_bytes())
        .await
        .expect("write");
    write_half.write_all(b"third\r\n").await.expect("write");
    write_half.flush().await.expect("flush");
    wait_until_acknowledged(&write_half).await;
    first_answer.release();
    read_until(&mut reader, "got third").await;

    let prompts = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("telnet_message_received"))
        .map(|c| (c.context.prompt.clone(), c.context.event_data.clone()))
        .collect();
    let _ = state.remove_server(id).await;
    prompts
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lines_typed_during_a_call_are_answered_together() {
    // === Control: batching off. Every line is its own call. ===
    let separate = prompts_for_three_lines(false, "second").await;
    assert_eq!(
        separate.len(),
        3,
        "CONTROL FAILED: with batching off each line must be its own model call, or the \
         two-call result below proves nothing. Got {} calls: {:#?}",
        separate.len(),
        separate.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );

    // === The claim: the two lines that arrived during the slow call come back as one. ===
    let batched = prompts_for_three_lines(true, "second").await;
    assert_eq!(
        batched.len(),
        2,
        "the two lines typed during the first call must be answered in one follow-up call; \
         got {} calls: {:#?}",
        batched.len(),
        batched.iter().map(|(_, d)| d).collect::<Vec<_>>()
    );
    let (prompt, current) = &batched[1];
    assert_eq!(
        current["message"], "third",
        "the newest line is the batch's trigger"
    );
    let trigger_at = prompt
        .rfind("Event ID: telnet_message_received")
        .expect("trigger");
    let before = &prompt[..trigger_at];
    assert!(
        before.contains(r#"(1) telnet_message_received {"message":"second"}"#),
        "the earlier line must be listed as arrived and not yet answered:\n{prompt}"
    );
    assert!(
        before.contains("answers all 2 together"),
        "the model must be told it answers both:\n{prompt}"
    );
}

/// A line that arrived during the call but is still in the kernel's receive buffer has arrived.
///
/// The second line is sized so that it and its CRLF fill exactly one socket read, so after the
/// first call the server's read returns that line and nothing more: `third` is not in the
/// reader's own buffer, only in the kernel's. Batching has to read the socket to find it — a
/// reader that took only what it had already buffered would answer `third` in a call of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_line_still_in_the_kernel_buffer_joins_the_batch() {
    use netget::server::telnet::READ_CHUNK_BYTES;
    let second = format!(
        "second{}",
        "-".repeat(READ_CHUNK_BYTES - "second\r\n".len())
    );
    assert_eq!(second.len() + 2, READ_CHUNK_BYTES);

    let separate = prompts_for_three_lines(false, &second).await;
    assert_eq!(
        separate.len(),
        3,
        "CONTROL FAILED: with batching off each line must be its own model call; got {}",
        separate.len()
    );

    let batched = prompts_for_three_lines(true, &second).await;
    assert_eq!(
        batched.len(),
        2,
        "the line still in the kernel buffer must join the batch, not wait for a call of its \
         own; got {} calls: {:#?}",
        batched.len(),
        batched
            .iter()
            .map(|(_, d)| d["message"]
                .as_str()
                .unwrap_or_default()
                .chars()
                .take(12)
                .collect::<String>())
            .collect::<Vec<_>>()
    );
    let (prompt, current) = &batched[1];
    assert_eq!(
        current["message"], "third",
        "the newest line is the batch's trigger"
    );
    assert!(
        prompt.contains("answers all 2 together"),
        "the model must be told it answers both"
    );
}

/// TCP: `first`, then two separate writes while the model answers it. Returns the `data` of
/// every `tcp_data_received` the model was asked about.
async fn tcp_payloads_for_three_writes(batching: bool) -> Vec<String> {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("tcp_data_received")
            .and_event_data_contains("data", "first")
            .respond_with_actions(serde_json::json!([
                { "type": "send_tcp_data", "data": "ok first\n", "encoding": "utf8" }
            ]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            .on_event("tcp_data_received")
            .respond_with_actions_from_event(|event| {
                let data = event["data"].as_str().unwrap_or_default().to_string();
                serde_json::json!([{ "type": "send_tcp_data", "data": format!("ok {data}\n"), "encoding": "utf8" }])
            })
            .expect_at_least(1)
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
        protocol: "tcp".to_string(),
        port: Some(0),
        instruction: Some("Acknowledge everything.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create tcp server");
    let port = wait_for_port(&state, id).await;

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write_half.write_all(b"first").await.expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.call_count().await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "first never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Two reads the server sees separately, both during the slow first call.
    write_half.write_all(b"second").await.expect("write");
    tokio::time::sleep(Duration::from_millis(200)).await;
    write_half.write_all(b"third").await.expect("write");
    read_until(&mut reader, "third").await;

    let payloads = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("tcp_data_received"))
        .map(|c| {
            c.context.event_data["data"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    let _ = state.remove_server(id).await;
    payloads
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_batching_joins_or_separates_what_arrived_during_a_call() {
    let separate = tcp_payloads_for_three_writes(false).await;
    assert_eq!(
        separate,
        vec!["first", "second", "third"],
        "with batching off each read that arrived during the call is answered on its own"
    );
    let batched = tcp_payloads_for_three_writes(true).await;
    assert_eq!(
        batched,
        vec!["first", "secondthird"],
        "with batching on everything that arrived during the call is the next call's payload"
    );
}

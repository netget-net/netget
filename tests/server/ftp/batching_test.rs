//! Pipelined FTP commands sent while the model is answering are answered together when the
//! instance asks for batching, and every command still gets its own completion reply, in order.
//!
//! Batching is off by default for FTP, because a client matches replies to commands by
//! position alone. With it on, a batch is written only when the handler gave exactly one
//! completion reply per command; anything else is refused with `421` and closed rather than
//! risking a client reading one command's reply as another's.
//!
//! A raw socket (as in `one_reply_test.rs`) sends `USER anonymous`, answered slowly, then
//! pipelines two more commands during that call. Control and claims are one test: with
//! batching off the three commands must be three model calls.
//!
//! LLM budget: 4 calls (batching off), 3 (on), 3 (on, mismatched answer).

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use serde_json::json;
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

fn reply(code: u16, message: &str) -> serde_json::Value {
    json!({"type": "send_ftp_response", "code": code, "message": message})
}

/// Send `USER anonymous`, then `pipelined` while it is being answered. Return the commands
/// each `ftp_command` call was triggered by (greeting excluded) and every line the server
/// wrote after the greeting until it closed or went quiet.
async fn session(batching: bool, pipelined: &str) -> (Vec<(String, String)>, Vec<String>) {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("ftp_command")
            .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
            .respond_with_actions(json!([reply(220, "ready")]))
            .expect_calls(1)
            .and()
            .on_event("ftp_command")
            .and_event_data_contains("command", "USER")
            .respond_with_actions(json!([reply(331, "send password")]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            // A batched call answers each command it lists, in order.
            .on_event("ftp_command")
            .and_prompt_containing("answers all 2 together")
            .and_event_data_contains("command", "PWD")
            .respond_with_actions(json!([reply(230, "logged in"), reply(257, "\"/\" is cwd")]))
            .expect_at_least(0)
            .and()
            // ...or, here, answers two commands with one reply: unmatchable.
            .on_event("ftp_command")
            .and_prompt_containing("answers all 2 together")
            .and_event_data_contains("command", "SYST")
            .respond_with_actions(json!([reply(230, "logged in")]))
            .expect_at_least(0)
            .and()
            .on_event("ftp_command")
            .and_event_data_contains("command", "PASS")
            .respond_with_actions(json!([reply(230, "logged in")]))
            .expect_at_least(0)
            .and()
            .on_event("ftp_command")
            .and_event_data_contains("command", "PWD")
            .respond_with_actions(json!([reply(257, "\"/\" is cwd")]))
            .expect_at_least(0)
            .and()
            .on_event("ftp_command")
            .and_event_data_contains("command", "SYST")
            .respond_with_actions(json!([reply(215, "UNIX Type: L8")]))
            .expect_at_least(0)
            .and()
            .on_any()
            .respond_with_actions(json!([]))
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
        protocol: "ftp".to_string(),
        port: Some(0),
        instruction: Some("Let anyone log in anonymously.".to_string()),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create ftp server");
    let port = wait_for_port(&state, id).await;

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut greeting = String::new();
    tokio::time::timeout(Duration::from_secs(30), reader.read_line(&mut greeting))
        .await
        .expect("greeting within 30s")
        .expect("read greeting");
    assert_eq!(greeting, "220 ready\r\n");

    write_half
        .write_all(b"USER anonymous\r\n")
        .await
        .expect("USER");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !mock.recorded_calls().await.iter().any(|c| {
        c.context.event_data["command"]
            .as_str()
            .is_some_and(|c| c.starts_with("USER"))
    }) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "USER never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    write_half
        .write_all(pipelined.as_bytes())
        .await
        .expect("pipelined");

    // Three replies are owed; read until three arrive, the server closes, or it goes quiet.
    let mut lines = Vec::new();
    while lines.len() < 3 {
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
            Ok(Ok(n)) if n > 0 => lines.push(line),
            _ => break,
        }
    }

    let calls = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("ftp_command"))
        .filter(|c| c.context.event_data["command"] != "CONNECTION_ESTABLISHED")
        .map(|c| {
            (
                c.context.event_data["command"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                c.context.prompt.clone(),
            )
        })
        .collect();
    let _ = state.remove_server(id).await;
    (calls, lines)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipelined_commands_are_answered_together_with_one_reply_each() {
    let wanted = [
        "331 send password\r\n",
        "230 logged in\r\n",
        "257 \"/\" is cwd\r\n",
    ];

    // === Control: batching off (the default). Every command is its own call. ===
    let (calls, lines) = session(false, "PASS x\r\nPWD\r\n").await;
    let triggers: Vec<&str> = calls.iter().map(|(c, _)| c.as_str()).collect();
    assert_eq!(
        triggers,
        ["USER anonymous", "PASS x", "PWD"],
        "CONTROL FAILED: with batching off each command must be its own model call"
    );
    assert_eq!(lines, wanted);

    // === The claim: PASS and PWD, pipelined during USER's call, are one call, and each
    // still gets its own reply, in order. ===
    let (calls, lines) = session(true, "PASS x\r\nPWD\r\n").await;
    let triggers: Vec<&str> = calls.iter().map(|(c, _)| c.as_str()).collect();
    assert_eq!(
        triggers,
        ["USER anonymous", "PWD"],
        "PASS and PWD must be answered in one call triggered by the newest, PWD"
    );
    let prompt = &calls[1].1;
    let trigger_at = prompt.rfind("Event ID: ftp_command").expect("trigger");
    assert!(
        prompt[..trigger_at].contains(r#""command":"PASS x""#),
        "PASS must be listed above the trigger:\n{prompt}"
    );
    assert_eq!(lines, wanted, "one reply per command, in command order");

    // === A batch answered with fewer completion replies than commands cannot be matched to
    // them: nothing of it is written, and the connection is refused with 421. ===
    let (calls, lines) = session(true, "PASS x\r\nSYST\r\n").await;
    assert_eq!(calls.len(), 2, "PASS and SYST are one call");
    assert_eq!(
        lines.len(),
        2,
        "USER's reply and the refusal, then EOF: {lines:?}"
    );
    assert_eq!(lines[0], "331 send password\r\n");
    assert!(
        lines[1].starts_with("421 "),
        "a mismatched batch must be refused, not written: {lines:?}"
    );
}

//! Shell lines typed while the model is answering are answered together, and their output
//! reaches the terminal in order.
//!
//! The client is `ssh2` (libssh2), as in the rest of this suite, on an interactive shell
//! channel. It types `first` (answered slowly), then `second` and `third` as two separate
//! packets during that call. russh delivers channel data one `Handler::data` call at a time,
//! so batching depends on the shell's model calls running off the handler (`ShellWorker`);
//! this test is what shows they do.
//!
//! Control and claim are one test: with batching off the three lines must be three model
//! calls, or the two-call result proves nothing.
//!
//! LLM budget: 3 calls with batching off, 2 with it on (the login is a static rule).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use serde_json::json;
use tokio::sync::mpsc;

fn output(text: &str) -> serde_json::Value {
    json!({"type": "ssh_shell_response", "response": text})
}

/// Type the three lines; return (trigger command, prompt) per shell call and the transcript.
async fn three_lines(batching: bool) -> (Vec<(String, String)>, String) {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("ssh_shell_command")
            .and_event_data_contains("command", "first")
            .respond_with_actions(json!([output("got first\n")]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            // A batched call answers each line it lists, in order.
            .on_event("ssh_shell_command")
            .and_prompt_containing("answers all 2 together")
            .respond_with_actions(json!([output("got second\n"), output("got third\n")]))
            .expect_at_least(0)
            .and()
            .on_event("ssh_shell_command")
            .respond_with_actions_from_event(|e| {
                let command = e["command"].as_str().unwrap_or_default().trim().to_string();
                json!([output(&format!("got {command}\n"))])
            })
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
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let id = ServerForm {
        protocol: "ssh".to_string(),
        port: Some(0),
        instruction: Some("Act as a Linux shell.".to_string()),
        event_handlers: Some(vec![json!({
            "event_pattern": "ssh_auth",
            "handler": {"type": "static", "actions": [{"type": "ssh_auth_decision", "allowed": true}]},
        })]),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create ssh server");
    let mut port = 0;
    for _ in 0..200 {
        if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
            port = addr.port();
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_ne!(port, 0, "SSH server never bound a port");

    // The client runs on a blocking thread; it reports when `first` has been typed and waits
    // for the go-ahead (the model has the first call) before typing the rest.
    let (typed_tx, typed_rx) = std::sync::mpsc::channel::<()>();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let client = tokio::task::spawn_blocking(move || -> String {
        let tcp = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let mut session = ssh2::Session::new().expect("libssh2 session");
        session.set_tcp_stream(tcp);
        session.set_timeout(30_000);
        session.handshake().expect("SSH handshake");
        session
            .userauth_password("operator", "anything")
            .expect("the static rule accepts every password");
        let mut channel = session.channel_session().expect("session channel");
        channel.shell().expect("shell");
        channel.write_all(b"first\n").expect("type first");
        typed_tx.send(()).expect("report");
        go_rx.recv().expect("go-ahead");
        // Two packets, so each is its own line event. No `flush()` anywhere: ssh2's
        // `Write::flush` is libssh2's `channel_flush`, which discards unread *incoming* data
        // (the echo of what was typed) and refunds it as a window adjustment that can push
        // russh 0.45's `recipient_window_size` past u32 - a debug-build overflow panic that
        // drops the session.
        channel.write_all(b"second\n").expect("type second");
        std::thread::sleep(Duration::from_millis(100));
        channel.write_all(b"third\n").expect("type third");

        let mut transcript = String::new();
        let mut buf = [0u8; 16 * 1024];
        while !transcript.contains("got third") {
            match channel.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => transcript.push_str(&String::from_utf8_lossy(&buf[..n])),
            }
        }
        transcript
    });

    tokio::task::spawn_blocking(move || typed_rx.recv().expect("first typed"))
        .await
        .expect("wait");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !mock
        .recorded_calls()
        .await
        .iter()
        .any(|c| c.context.event_type.as_deref() == Some("ssh_shell_command"))
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the first line never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    go_tx.send(()).expect("go");
    let transcript = client.await.expect("client task");

    let calls = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("ssh_shell_command"))
        .map(|c| {
            (
                c.context.event_data["command"]
                    .as_str()
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                c.context.prompt.clone(),
            )
        })
        .collect();
    let _ = state.remove_server(id).await;
    (calls, transcript)
}

fn assert_in_order(transcript: &str, mode: &str) {
    let at = |s: &str| {
        transcript
            .find(s)
            .unwrap_or_else(|| panic!("{mode}: {s:?} missing from {transcript:?}"))
    };
    assert!(
        at("got first") < at("got second") && at("got second") < at("got third"),
        "{mode}: output out of order: {transcript:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lines_typed_during_a_call_are_answered_together_in_order() {
    // === Control: batching off. Every line is its own call. ===
    let (calls, transcript) = three_lines(false).await;
    let triggers: Vec<&str> = calls.iter().map(|(c, _)| c.as_str()).collect();
    assert_eq!(
        triggers,
        ["first", "second", "third"],
        "CONTROL FAILED: with batching off each line must be its own model call"
    );
    assert_in_order(&transcript, "batching off");

    // === The claim: second and third, typed during the first call, are one call. ===
    let (calls, transcript) = three_lines(true).await;
    let triggers: Vec<&str> = calls.iter().map(|(c, _)| c.as_str()).collect();
    assert_eq!(
        triggers,
        ["first", "third"],
        "the two lines typed during the first call must be answered in one call"
    );
    let prompt = &calls[1].1;
    let trigger_at = prompt
        .rfind("Event ID: ssh_shell_command")
        .expect("trigger");
    let listed = &prompt[..trigger_at];
    let block = &listed[listed.rfind("answers all 2 together").expect("batch block")..];
    assert!(
        block.contains("(1) ssh_shell_command") && block.contains("second"),
        "the earlier line must be listed above the trigger:\n{prompt}"
    );
    assert_in_order(&transcript, "batching on");
}

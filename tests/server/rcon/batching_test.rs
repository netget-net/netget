//! Pipelined RCON commands sent while the model is answering are answered together when the
//! instance asks for batching, and each output still goes back under its own request id.
//!
//! Batching is off by default for RCON: `rcon_response` names no command, so a batch can only
//! be matched to its commands by position. With it on, a batch is answered only when the
//! handler gave exactly one response per command; any other count closes the connection, the
//! same way a failed command does, rather than misattributing output.
//!
//! Raw packets, as in `wire_test.rs`: log in with a Rust-checked password, send command 10
//! (answered slowly), then pipeline 11 and 12 during that call. Control and claims are one
//! test: with batching off the three commands must be three model calls.
//!
//! LLM budget: 3 calls (off), 2 (on), 2 (on, mismatched answer).

use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

fn packet(id: i32, kind: i32, body: &str) -> Vec<u8> {
    let mut out = ((body.len() + 10) as i32).to_le_bytes().to_vec();
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(body.as_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

/// The next packet as (id, type, body), or `None` once the server has closed.
async fn read(s: &mut TcpStream) -> Option<(i32, i32, String)> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut size = [0u8; 4];
        s.read_exact(&mut size).await.ok()?;
        let mut rest = vec![0u8; i32::from_le_bytes(size) as usize];
        s.read_exact(&mut rest).await.ok()?;
        let id = i32::from_le_bytes(rest[0..4].try_into().unwrap());
        let kind = i32::from_le_bytes(rest[4..8].try_into().unwrap());
        Some((
            id,
            kind,
            String::from_utf8(rest[8..rest.len() - 2].to_vec()).unwrap(),
        ))
    })
    .await
    .unwrap_or(None)
}

fn response(output: &str) -> serde_json::Value {
    json!({"type": "rcon_response", "output": output})
}

/// Log in, send `first` as id 10, then `pipelined` as ids 11 and 12 during its call. Return
/// the command each model call was triggered by, its prompt, and every packet the server sent
/// after the login until it closed or three arrived.
async fn session(
    batching: bool,
    pipelined: [&str; 2],
) -> (Vec<(String, String)>, Vec<(i32, i32, String)>) {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("rcon_command")
            .and_event_data_contains("command", "first")
            .respond_with_actions(json!([response("ran: first")]))
            .after_delay(Duration::from_millis(1500))
            .expect_calls(1)
            .and()
            // A batched call answers each command it lists, in order.
            .on_event("rcon_command")
            .and_prompt_containing("answers all 2 together")
            .and_event_data_contains("command", "third")
            .respond_with_actions(json!([response("ran: second"), response("ran: third")]))
            .expect_at_least(0)
            .and()
            // ...or, here, answers two commands with one response: unmatchable.
            .on_event("rcon_command")
            .and_prompt_containing("answers all 2 together")
            .and_event_data_contains("command", "odd")
            .respond_with_actions(json!([response("ran: which?")]))
            .expect_at_least(0)
            .and()
            .on_event("rcon_command")
            .respond_with_actions_from_event(|e| {
                json!([response(&format!(
                    "ran: {}",
                    e["command"].as_str().unwrap_or("")
                ))])
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
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "rcon".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Answer as a game server console".into()),
        startup_params: Some(json!({"password": "pw", "dialect": "minecraft"})),
        batching: Some(batching),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create rcon server");
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("rcon bound a port");

    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(&packet(1, 3, "pw")).await.unwrap();
    assert_eq!(read(&mut s).await, Some((1, 2, String::new())), "logged in");

    s.write_all(&packet(10, 2, "first")).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while mock.call_count().await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the first command never reached the model"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut rest = packet(11, 2, pipelined[0]);
    rest.extend(packet(12, 2, pipelined[1]));
    s.write_all(&rest).await.unwrap();

    let mut packets = Vec::new();
    while packets.len() < 3 {
        match read(&mut s).await {
            Some(p) => packets.push(p),
            None => break,
        }
    }

    let calls = mock
        .recorded_calls()
        .await
        .into_iter()
        .filter(|c| c.context.event_type.as_deref() == Some("rcon_command"))
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
    state.remove_server(id).await;
    (calls, packets)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipelined_commands_are_answered_together_under_their_own_ids() {
    let wanted = vec![
        (10, 0, "ran: first".to_string()),
        (11, 0, "ran: second".to_string()),
        (12, 0, "ran: third".to_string()),
    ];

    // === Control: batching off (the default). Every command is its own call. ===
    let (calls, packets) = session(false, ["second", "third"]).await;
    let triggers: Vec<&str> = calls.iter().map(|(c, _)| c.as_str()).collect();
    assert_eq!(
        triggers,
        ["first", "second", "third"],
        "CONTROL FAILED: with batching off each command must be its own model call"
    );
    assert_eq!(packets, wanted);

    // === The claim: 11 and 12, pipelined during 10's call, are one call, and each output
    // goes back under its own request id. ===
    let (calls, packets) = session(true, ["second", "third"]).await;
    let triggers: Vec<&str> = calls.iter().map(|(c, _)| c.as_str()).collect();
    assert_eq!(
        triggers,
        ["first", "third"],
        "11 and 12 must be answered in one call triggered by the newest"
    );
    let prompt = &calls[1].1;
    let trigger_at = prompt.rfind("Event ID: rcon_command").expect("trigger");
    assert!(
        prompt[..trigger_at].contains(r#""command":"second""#),
        "command 11 must be listed above the trigger:\n{prompt}"
    );
    assert_eq!(
        packets, wanted,
        "each output under its own request id, in order"
    );

    // === One response for two commands cannot be matched: nothing is sent for either and
    // the connection closes. ===
    let (calls, packets) = session(true, ["even", "odd"]).await;
    assert_eq!(calls.len(), 2, "11 and 12 are one call");
    assert_eq!(
        packets,
        vec![(10, 0, "ran: first".to_string())],
        "a mismatched batch must close the connection without output"
    );
}

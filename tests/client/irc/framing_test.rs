//! IRC message injection on the *client* side, asserted end to end on a real socket.
//!
//! This is the direction with the highest stakes in the whole family: what the client writes
//! lands in a channel other humans read, and the text comes from the model. An embedded `\r\n`
//! in a `send_privmsg` body does not make a longer message - IRC lines are CRLF-terminated, so
//! it forges a second command *from this client*. A model told only to chat could otherwise be
//! steered into `JOIN`, `NICK`, `MODE` or `QUIT` by anything that reaches its context, which on
//! a chat protocol is every stranger in the channel.
//!
//! The test injects through `AppState::send_to_client`, the same path the dashboard's
//! `[ send_privmsg ]` row uses and the same executor the LLM path runs, and then checks the
//! *server's* access log - the only place that can show whether a second command actually
//! crossed the wire.
//!
//! Zero LLM calls: the server answers through a `*` static handler and the client's LLM
//! endpoint is unreachable, exactly as `command_channel_test.rs` sets it up.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features irc --test client -- irc::framing --test-threads=100

use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ServerId};
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..1_000 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("IRC server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "IRC client #{} never registered a command handle",
        id.as_u32()
    );
}

async fn server_log(state: &AppState, id: ServerId) -> String {
    let mut all = String::new();
    for entry in state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
    {
        all.push_str(&serde_json::to_string(&entry).unwrap_or_default());
        all.push('\n');
    }
    all
}

async fn wait_for_server_log(state: &AppState, id: ServerId, needle: &str) {
    for _ in 0..1_000 {
        if server_log(state, id).await.contains(needle) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("the IRC server never logged {needle:?}");
}

#[tokio::test]
async fn crlf_in_a_client_message_cannot_forge_a_second_command() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "irc".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_irc_welcome", "nickname": "netget_user", "message": "static" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create irc server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "irc".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create irc client");

    wait_for_client_handle(&state, client_id).await;

    // Every field that reaches a line, each with the break that would end it early.
    for action in [
        serde_json::json!({"type": "send_privmsg", "target": "#netget",
                           "message": "hi\r\nJOIN #forged-privmsg"}),
        serde_json::json!({"type": "send_notice", "target": "#netget",
                           "message": "hi\r\nJOIN #forged-notice"}),
        serde_json::json!({"type": "send_raw", "command": "MODE #netget +m\r\nJOIN #forged-raw"}),
        serde_json::json!({"type": "part_channel", "channel": "#netget",
                           "message": "bye\r\nJOIN #forged-part"}),
        serde_json::json!({"type": "disconnect", "quit_message": "bye\r\nJOIN #forged-quit"}),
    ] {
        let outcome = state
            .send_to_client(client_id, action.clone(), Duration::from_secs(5))
            .await
            .expect("send_to_client");
        match outcome {
            ClientSendOutcome::Rejected { error } => assert!(
                error.contains("CR, LF or NUL"),
                "{action}: rejected for the wrong reason: {error}"
            ),
            other => panic!("{action} was not rejected: {other:?}"),
        }
    }

    // A word-position field with a space in it shifts every later parameter.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_privmsg", "target": "#a :spoof", "message": "x"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("must not contain a space")),
        "expected a space rejection, got {outcome:?}"
    );

    // A benign message on the same connection proves the client is still usable - a refusal
    // must not have left half a line on the socket or poisoned the write lock.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_privmsg", "target": "#netget", "message": "benign-marker"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "expected the benign message to be sent, got {outcome:?}"
    );
    wait_for_server_log(&state, server_id, "PRIVMSG #netget :benign-marker").await;

    // The only thing that actually settles it: no forged command ever reached the server.
    let log = server_log(&state, server_id).await;
    for forged in [
        "#forged-privmsg",
        "#forged-notice",
        "#forged-raw",
        "#forged-part",
        "#forged-quit",
    ] {
        assert!(
            !log.contains(forged),
            "a forged {forged} command crossed the wire"
        );
    }
}

#[tokio::test]
async fn an_over_long_client_message_is_truncated_to_one_valid_line() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "irc".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_irc_welcome", "nickname": "netget_user", "message": "static" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create irc server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "irc".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create irc client");

    wait_for_client_handle(&state, client_id).await;

    // Multi-byte, so the RFC 1459 cut at byte 510 lands mid-character unless it is done on a
    // char boundary - the byte-index-slicing panic this repo has hit before.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_privmsg", "target": "#netget",
                               "message": "é".repeat(2000)}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    match outcome {
        ClientSendOutcome::Sent { bytes_sent } => assert!(
            bytes_sent <= 512,
            "wrote {bytes_sent} bytes, over the RFC 1459 512-byte line limit"
        ),
        other => panic!("expected a truncated send, got {other:?}"),
    }

    // The connection survived it, which is what proves nothing malformed went out.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_privmsg", "target": "#netget", "message": "after-marker"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "expected the follow-up to be sent, got {outcome:?}"
    );
    wait_for_server_log(&state, server_id, "PRIVMSG #netget :after-marker").await;
}

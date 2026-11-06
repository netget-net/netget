//! The handshake hint, and the executor refusing only the part of an accept that is invalid.
//!
//! llama3.1:8b answered websocat's upgrade - which offers no subprotocol - with
//! `{"type": "accept_websocket", "subprotocol": "chat"}` (the action's example) five runs in five,
//! and the executor refused the whole action, so every one became the fail-closed 503. With
//! another instruction it refused the upgrade outright because "no subprotocols were offered".

use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::connection::ConnectionId;
use netget::server::websocket::actions::{
    handshake_answer_with, WebSocketProtocol, OPENED_ANSWER_WITH, TEXT_MESSAGE_ANSWER_WITH,
    WEBSOCKET_CONNECTION_OPENED_EVENT,
};
use netget::state::ServerId;
use serde_json::json;
use tokio::sync::mpsc;

fn executor(offered: &[&str]) -> WebSocketProtocol {
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    let (status_tx, _status_rx) = mpsc::unbounded_channel();
    WebSocketProtocol::for_connection(
        ServerId::new(1),
        ConnectionId::new(1),
        out_tx,
        status_tx,
        offered.iter().map(|s| s.to_string()).collect(),
    )
}

fn accepted_subprotocol(result: ActionResult) -> Option<String> {
    match result {
        ActionResult::Custom { name, data } => {
            assert_eq!(name, "accept_websocket");
            data["subprotocol"].as_str().map(str::to_string)
        }
        other => panic!("expected an accept, got {other:?}"),
    }
}

/// An accept naming a subprotocol the client never offered still accepts: RFC 6455 forbids
/// echoing the subprotocol, not opening the connection, so only the subprotocol is dropped.
#[test]
fn an_unoffered_subprotocol_is_dropped_and_the_accept_stands() {
    let result = executor(&[])
        .execute_action(json!({"type": "accept_websocket", "subprotocol": "chat"}))
        .expect("the accept must stand");
    assert_eq!(accepted_subprotocol(result), None);

    let result = executor(&["mqtt"])
        .execute_action(json!({"type": "accept_websocket", "subprotocol": "chat"}))
        .expect("the accept must stand");
    assert_eq!(accepted_subprotocol(result), None);
}

#[test]
fn an_offered_subprotocol_is_agreed() {
    let result = executor(&["superchat", "chat"])
        .execute_action(json!({"type": "accept_websocket", "subprotocol": "chat"}))
        .expect("an offered subprotocol is accepted");
    assert_eq!(accepted_subprotocol(result).as_deref(), Some("chat"));

    let result = executor(&["chat"])
        .execute_action(json!({"type": "accept_websocket"}))
        .expect("accepting without a subprotocol is always valid");
    assert_eq!(accepted_subprotocol(result), None);
}

#[test]
fn the_hint_says_whether_anything_was_offered() {
    let none = handshake_answer_with(&[]);
    assert!(
        none.starts_with("this client offered no subprotocol"),
        "{none}"
    );
    assert!(none.contains("never a reason to refuse"), "{none}");
    assert!(none.contains("Answer accept_websocket"), "{none}");

    let some = handshake_answer_with(&["chat".to_string(), "superchat".to_string()]);
    assert!(some.contains("(chat, superchat)"), "{some}");
    assert!(some.contains("reject_websocket only when"), "{some}");
    // Speaking first is decided here, in the accept: told to greet, the model answered the
    // handshake with the greeting and no accept when the greeting had nowhere else to go,
    // which is the fail-closed 503. Echoes and replies still wait for a message.
    for hint in [&none, &some] {
        assert!(
            hint.contains("put those exact words in accept_websocket's greeting"),
            "{hint}"
        );
        assert!(hint.contains("otherwise no greeting"), "{hint}");
        assert!(
            hint.contains("Echoes and replies are sent later, when messages arrive"),
            "{hint}"
        );
    }
}

/// Speaking first is the instruction's call: an echo server stays silent on connect.
#[test]
fn the_opened_and_message_hints_leave_the_words_to_the_instructions() {
    assert!(OPENED_ANSWER_WITH.starts_with("speak first only if"));
    assert!(OPENED_ANSWER_WITH.contains(r#"answer {"actions": []}: no action at all"#));
    assert!(OPENED_ANSWER_WITH.contains("never an empty message"));
    assert!(TEXT_MESSAGE_ANSWER_WITH.contains("to echo, its text is this message's 'text' field"));
    // No example the model reads on connect carries a plausible greeting.
    let mut texts: Vec<String> = WEBSOCKET_CONNECTION_OPENED_EVENT
        .actions
        .iter()
        .map(|a| a.example.to_string())
        .collect();
    texts.push(
        WEBSOCKET_CONNECTION_OPENED_EVENT
            .effective_response_example()
            .to_string(),
    );
    for text in texts {
        assert!(!text.contains("welcome"), "{text}");
    }
}

/// While the server speaks first, an empty text message is dropped rather than sent: it
/// carries nothing, and websocat reads a zero-length message as end of stream, so the echo the
/// eval's model sent after one was never shown. A reply to the client is not affected.
#[test]
fn an_empty_greeting_is_dropped_but_an_empty_reply_is_sent() {
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let (status_tx, _status_rx) = mpsc::unbounded_channel();
    let protocol = WebSocketProtocol::for_connection(
        ServerId::new(1),
        ConnectionId::new(1),
        out_tx,
        status_tx,
        Vec::new(),
    );

    protocol.set_speaking_first(true);
    protocol
        .execute_action(json!({"type": "send_websocket_text", "text": ""}))
        .expect("an empty greeting is accepted and dropped");
    assert!(
        out_rx.try_recv().is_err(),
        "an empty greeting must not be sent"
    );
    protocol
        .execute_action(json!({"type": "send_websocket_text", "text": "hi"}))
        .expect("a real greeting is sent");
    assert!(out_rx.try_recv().is_ok(), "a real greeting must be sent");

    protocol.set_speaking_first(false);
    protocol
        .execute_action(json!({"type": "send_websocket_text", "text": ""}))
        .expect("an empty reply is sent");
    assert!(
        out_rx.try_recv().is_ok(),
        "an empty reply must still be sent"
    );
}

/// The accept carries the server's first message: the words it was given, and nothing for an
/// empty one, which websocat would read as the end of the stream.
#[test]
fn an_accept_carries_its_greeting_and_an_empty_one_is_none() {
    let greeting = |accept: serde_json::Value| match executor(&[]).execute_action(accept) {
        Ok(ActionResult::Custom { data, .. }) => data["greeting"].as_str().map(str::to_string),
        other => panic!("expected an accept, got {other:?}"),
    };
    assert_eq!(
        greeting(json!({"type": "accept_websocket", "greeting": "Welcome to NetGet Eval"}))
            .as_deref(),
        Some("Welcome to NetGet Eval")
    );
    assert_eq!(
        greeting(json!({"type": "accept_websocket", "greeting": ""})),
        None
    );
    assert_eq!(greeting(json!({"type": "accept_websocket"})), None);
    assert!(executor(&[])
        .execute_action(json!({"type": "accept_websocket", "greeting": 42}))
        .is_err());
}

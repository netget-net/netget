//! `notify_operator` (formerly `show_message`): a note for the person running NetGet, which
//! must never be taken for a reply to the peer.
//!
//! Reproduced 31 October 2026 with llama3.1:8b: a telnet server told to be a BBS that greets
//! its users answered the connect event and the first line with `show_message`, offered beside
//! `send_telnet_line`, and the peer saw nothing. The action is now named for where it goes, and
//! an event that offers the protocol's own answers no longer offers it at all.
//!
//! The end-to-end half drives a real telnet server through the bridge backend, which hands the
//! test every request with the exact list of actions it offers — so "not offered" is read off
//! the request rather than inferred. The same session proves the other half of the contract:
//! a model that names the action anyway, under its former name, is executed rather than sent
//! round a retry, and the protocol answer beside it still reaches the peer.

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::llm::actions::common::{
    self, canonical_action_name, network_event_common_actions_for, CommonAction,
    LEGACY_NOTIFY_OPERATOR, NOTIFY_OPERATOR,
};
use netget::llm::{BridgeReply, BridgeRequest, LlmBridge, OllamaClient};
use netget::state::app_state::AppState;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn names(actions: &[netget::llm::ActionDefinition]) -> Vec<String> {
    actions.iter().map(|a| a.name.clone()).collect()
}

#[test]
fn the_former_name_is_parsed_as_the_current_action() {
    let parsed = CommonAction::from_json(&json!({"type": "show_message", "message": "hi"}))
        .expect("show_message still parses");
    assert!(
        matches!(parsed, CommonAction::NotifyOperator { ref message } if message == "hi"),
        "{parsed:?}"
    );
    assert_eq!(
        canonical_action_name(LEGACY_NOTIFY_OPERATOR),
        NOTIFY_OPERATOR
    );
    assert_eq!(canonical_action_name("send_tcp_data"), "send_tcp_data");

    // A model's answer is rewritten to the current name before it is validated or executed.
    let response = netget::llm::actions::ActionResponse::from_str(
        r#"{"actions":[{"type":"show_message","message":"hi"}]}"#,
    )
    .expect("parses");
    assert_eq!(response.actions[0]["type"], NOTIFY_OPERATOR);
    assert_eq!(response.actions[0]["message"], "hi");
}

#[test]
fn handlers_and_clients_written_against_the_former_name_keep_working() {
    // Static/script handler validation accepts both names.
    let accepted = netget::events::handler::common_action_names();
    assert!(accepted.contains(&NOTIFY_OPERATOR));
    assert!(accepted.contains(&LEGACY_NOTIFY_OPERATOR));

    // A client handler's `show_message` is still a common action the LLM layer runs itself,
    // not something handed to the protocol executor to reject.
    let (common_actions, protocol_actions) =
        netget::llm::action_helper::split_client_common_actions(vec![
            json!({"type": "show_message", "message": "old"}),
            json!({"type": "send_tcp_data", "data": "x"}),
        ]);
    assert_eq!(common_actions.len(), 1, "{common_actions:?}");
    assert_eq!(protocol_actions[0]["type"], "send_tcp_data");
}

#[test]
fn the_note_is_offered_only_where_there_is_no_wire_answer_to_mistake_it_for() {
    let with_answer = names(&network_event_common_actions_for(true, true));
    assert!(
        !with_answer.contains(&NOTIFY_OPERATOR.to_string()),
        "offered beside the protocol's answers: {with_answer:?}"
    );
    // Control: an informational event (nothing to answer) still offers it — the list is
    // narrowed, not emptied of the action everywhere.
    let informational = names(&network_event_common_actions_for(false, true));
    assert!(
        informational.contains(&NOTIFY_OPERATOR.to_string()),
        "{informational:?}"
    );
    // Its description says where the note goes.
    let description = common::notify_operator_action().description;
    assert!(description.contains("NOT sent"), "{description}");
}

async fn next_request(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<BridgeRequest>,
) -> BridgeRequest {
    tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .expect("a request reaches the bridge")
        .expect("the bridge delivers it")
}

fn offered(req: &BridgeRequest) -> Vec<String> {
    req.actions
        .iter()
        .filter_map(|a| a["name"].as_str().map(str::to_string))
        .collect()
}

fn answer(req: BridgeRequest, actions: serde_json::Value) {
    req.reply
        .send(Ok(BridgeReply {
            content: Some(json!({ "actions": actions }).to_string()),
            ..Default::default()
        }))
        .expect("the server is waiting");
}

async fn read_line_containing<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R, needle: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut seen = String::new();
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout_at(deadline, reader.read_line(&mut line))
            .await
            .unwrap_or_else(|_| panic!("{needle:?} never arrived; read {seen:?}"))
            .expect("read");
        assert!(n > 0, "closed before {needle:?}; read {seen:?}");
        seen.push_str(&line);
        if line.contains(needle) {
            return;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_telnet_event_does_not_offer_the_note_and_still_runs_the_former_name() {
    let (bridge, mut rx) = LlmBridge::new();
    bridge.set_models(vec!["page-model".to_string()]);
    let state = AppState::new_with_options(false, "browser://model".to_string());
    state.set_ollama_model(Some("page-model".to_string())).await;
    state
        .set_llm_client(OllamaClient::new_bridge(bridge, Duration::from_secs(30)))
        .await;
    let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "telnet".to_string(),
        port: Some(0),
        instruction: Some("You are a retro BBS called NightOwl. Greet users.".to_string()),
        ..Default::default()
    }
    .create(&state, status_tx)
    .await
    .expect("create telnet server");

    let mut port = None;
    for _ in 0..200 {
        if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
            port = Some(addr.port());
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let port = port.expect("the telnet server binds a port");
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // The connect event: the greeting must go through the protocol, and the note that was
    // taken for it is not on offer.
    let connect = next_request(&mut rx).await;
    let names = offered(&connect);
    assert!(
        names.iter().any(|n| n == "send_telnet_line"),
        "the protocol's answer is offered: {names:?}"
    );
    for hidden in [NOTIFY_OPERATOR, LEGACY_NOTIFY_OPERATOR] {
        assert!(
            !names.iter().any(|n| n == hidden),
            "{hidden} is offered beside the protocol's answers: {names:?}"
        );
    }
    // A model that uses it anyway, under the former name, is executed — not retried — and
    // the greeting beside it reaches the peer.
    answer(
        connect,
        json!([
            {"type": "show_message", "message": "operator-note-7f3a"},
            {"type": "send_telnet_line", "line": "Welcome to NightOwl"}
        ]),
    );
    read_line_containing(&mut reader, "Welcome to NightOwl").await;

    // The next request is the next event, not a retry of the connect answer.
    write_half
        .write_all(b"Hi, my name is Zed\r\n")
        .await
        .expect("write");
    let message = next_request(&mut rx).await;
    let prompt: String = message
        .messages
        .iter()
        .map(|m| m.content.as_str())
        .collect();
    assert!(
        prompt.contains("Hi, my name is Zed"),
        "the request after the greeting is the peer's line, not a retry"
    );
    assert!(!offered(&message).iter().any(|n| n == NOTIFY_OPERATOR));
    answer(
        message,
        json!([{"type": "send_telnet_line", "line": "Hello Zed"}]),
    );
    read_line_containing(&mut reader, "Hello Zed").await;

    // The note went to the operator's stream.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut statuses = Vec::new();
    while !statuses
        .iter()
        .any(|s: &String| s.contains("operator-note-7f3a"))
    {
        match tokio::time::timeout_at(deadline, status_rx.recv()).await {
            Ok(Some(line)) => statuses.push(line),
            _ => panic!("the operator note never reached the status stream: {statuses:#?}"),
        }
    }
    let _ = state.remove_server(id).await;
}

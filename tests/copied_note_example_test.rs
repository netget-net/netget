//! An answer to a network event that is nothing but a note-keeping action's example, copied
//! from the action list, is sent back once for an answer the peer receives.
//!
//! Measured with llama3.1:8b (November 2026): asked to answer an LDAP search, the model
//! repeated the prompt back, and NetGet read the reply's first JSON value — the example of
//! `set_memory`, the first action listed — as the whole answer. Nothing reached the peer, so
//! the search failed closed with the protocol's refusal default. Told once what it had sent, it
//! answered the search in 10 of 10 seeds.
//!
//! Only a copied example is sent back. A note the model wrote itself is a whole answer — a
//! collector that records a datagram and says nothing is answering correctly — and costs no
//! second call.
//!
//! The end-to-end test drives a telnet server through the bridge backend, which hands the test
//! every request, so the correction is read off the second request for the same event.

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::llm::actions::common::{append_connection_memory_action, set_memory_action};
use netget::llm::conversation::copied_note_example_answer;
use netget::llm::prompt::PromptBuilder;
use netget::llm::{ActionDefinition, BridgeReply, BridgeRequest, LlmBridge, OllamaClient};
use netget::state::app_state::AppState;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const CORRECTION: &str = "That answer is only the example of";

#[test]
fn only_an_answer_made_entirely_of_copied_note_examples_is_sent_back() {
    let offered: Vec<ActionDefinition> =
        vec![set_memory_action(), append_connection_memory_action()];
    let set_example = set_memory_action().example;
    let append_example = append_connection_memory_action().example;

    assert_eq!(
        copied_note_example_answer(&[set_example.clone()], &offered),
        Some(vec!["set_memory".to_string()])
    );
    assert_eq!(
        copied_note_example_answer(&[set_example.clone(), append_example.clone()], &offered),
        Some(vec![
            "set_memory".to_string(),
            "append_connection_memory".to_string()
        ])
    );
    assert_eq!(
        copied_note_example_answer(
            &[json!({"type": "set_memory", "value": "datagrams_seen: 3"})],
            &offered
        ),
        None,
        "a note the model wrote is a whole answer"
    );
    assert_eq!(
        copied_note_example_answer(
            &[
                set_example,
                json!({"type": "send_telnet_line", "line": "hi"})
            ],
            &offered
        ),
        None,
        "anything that reaches the peer makes it an answer"
    );
    assert_eq!(
        copied_note_example_answer(&[], &offered),
        None,
        "an empty answer is an explicit 'send nothing'"
    );

    let correction = PromptBuilder::build_copied_note_example_retry_prompt(
        &["set_memory".to_string()],
        &[
            "send_telnet_line".to_string(),
            "close_connection".to_string(),
        ],
    );
    assert!(correction.starts_with(CORRECTION), "{correction}");
    assert!(
        correction.contains("`set_memory`") && correction.contains("`send_telnet_line`"),
        "{correction}"
    );
    assert!(correction.contains(r#"{"actions": []}"#), "{correction}");
}

async fn next_request(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<BridgeRequest>,
) -> BridgeRequest {
    tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .expect("a request reaches the bridge")
        .expect("the bridge delivers it")
}

fn prompt_of(req: &BridgeRequest) -> String {
    req.messages.iter().map(|m| m.content.as_str()).collect()
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
async fn a_copied_note_example_is_sent_back_once_and_a_written_note_is_believed() {
    let (bridge, mut rx) = LlmBridge::new();
    bridge.set_models(vec!["page-model".to_string()]);
    let state = AppState::new_with_options(false, "browser://model".to_string());
    state.set_ollama_model(Some("page-model".to_string())).await;
    state
        .set_llm_client(OllamaClient::new_bridge(bridge, Duration::from_secs(30)))
        .await;
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();
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

    // The connect event, answered the way the echoed prompt was read: set_memory's example.
    let connect = next_request(&mut rx).await;
    assert!(
        !prompt_of(&connect).contains(CORRECTION),
        "a first answer is never a correction"
    );
    answer(connect, json!([set_memory_action().example]));

    // The same event comes back once, saying why, and the right answer then reaches the peer.
    let retry = next_request(&mut rx).await;
    let retry_prompt = prompt_of(&retry);
    assert!(
        retry_prompt.contains(CORRECTION) && retry_prompt.contains("send_telnet_line"),
        "the second request is the correction naming the wire answers: {retry_prompt}"
    );
    answer(
        retry,
        json!([{"type": "send_telnet_line", "line": "Welcome to NightOwl"}]),
    );
    read_line_containing(&mut reader, "Welcome to NightOwl").await;
    let memory = state.get_server(id).await.expect("server").memory;
    assert!(
        memory.is_empty(),
        "nothing from the copied example ran, its memory write included: {memory:?}"
    );

    // A note the model wrote itself is its whole answer: executed, no second request.
    write_half
        .write_all(b"my name is Zed\r\n")
        .await
        .expect("write");
    let line = next_request(&mut rx).await;
    answer(
        line,
        json!([{"type": "append_connection_memory", "value": "user_name: Zed"}]),
    );
    write_half.write_all(b"who am I?\r\n").await.expect("write");
    let next = next_request(&mut rx).await;
    let next_prompt = prompt_of(&next);
    assert!(
        next_prompt.contains("who am I?") && !next_prompt.contains(CORRECTION),
        "a written note is not sent back: {next_prompt}"
    );
    assert!(
        next_prompt.contains("Memory for this connection")
            && next_prompt.contains("user_name: Zed"),
        "the written note ran: the connection's memory holds it"
    );

    // A copied example given twice is believed the second time rather than sent round again.
    let copied = append_connection_memory_action().example;
    answer(next, json!([copied.clone()]));
    let again = next_request(&mut rx).await;
    assert!(prompt_of(&again).contains(CORRECTION));
    answer(again, json!([copied]));
    write_half.write_all(b"bye\r\n").await.expect("write");
    let last = next_request(&mut rx).await;
    let last_prompt = prompt_of(&last);
    assert!(
        last_prompt.contains("bye") && !last_prompt.contains(CORRECTION),
        "the second copy was believed: {last_prompt}"
    );
    answer(
        last,
        json!([{"type": "send_telnet_line", "line": "Goodbye"}]),
    );
    read_line_containing(&mut reader, "Goodbye").await;
    let _ = state.remove_server(id).await;
}

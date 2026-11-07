//! A client whose answer to a reply starts its instruction over is checked before it is sent.
//!
//! Measured with llama3.1:8b: a redis client told "Send PING, then GET mykey, then stop
//! sending commands." answered the reply to PING with PING and GET again, and the reply to
//! those with the same again (or with PING alone), with both commands listed as already sent
//! directly above the reply. `crate::client::restart_check` compares each answer to an event
//! with the client's opening — the wire actions of its first model answer — and when the
//! answer begins with the opening's first steps, verbatim, asks the model one yes/no question
//! before anything is sent.
//!
//! Driven through the bridge backend, so the test answers every model request itself, sees
//! which ones are asked, and reads what reached a local listener speaking just enough RESP.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::client::restart_check::{
    trigger_is_founded, RESTART_CHECK_EVENT, SEND_AGAIN, SKIP_REPEAT,
};
use netget::llm::{BridgeReply, BridgeRequest, LlmBridge, OllamaClient};
use netget::state::app_state::AppState;
use netget::state::ClientId;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedReceiver;

/// One RESP array command off the front of `buf`: its words and how many bytes it used.
fn parse_command(buf: &[u8]) -> Option<(Vec<String>, usize)> {
    let line_end = |from: usize| {
        buf[from..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| from + p)
    };
    let end = line_end(0)?;
    let count: usize = std::str::from_utf8(buf.get(1..end)?).ok()?.parse().ok()?;
    let mut at = end + 2;
    let mut words = Vec::new();
    for _ in 0..count {
        let end = line_end(at)?;
        let len: usize = std::str::from_utf8(&buf[at + 1..end]).ok()?.parse().ok()?;
        let start = end + 2;
        if buf.len() < start + len + 2 {
            return None;
        }
        words.push(String::from_utf8_lossy(&buf[start..start + len]).to_string());
        at = start + len + 2;
    }
    Some((words, at))
}

/// Accept one connection and answer PING and GET until it closes, recording each command.
async fn fake_redis(listener: tokio::net::TcpListener, seen: Arc<Mutex<Vec<String>>>) {
    let Ok((mut socket, _)) = listener.accept().await else {
        return;
    };
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = match socket.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        while let Some((words, used)) = parse_command(&buf) {
            buf.drain(..used);
            let reply: &[u8] = match words.first().map(|w| w.to_ascii_uppercase()).as_deref() {
                Some("PING") => b"+PONG\r\n",
                Some("GET") => b"$5\r\nhello\r\n",
                _ => b"+OK\r\n",
            };
            seen.lock().unwrap().push(words.join(" "));
            if socket.write_all(reply).await.is_err() {
                return;
            }
        }
    }
}

async fn next_request(rx: &mut UnboundedReceiver<BridgeRequest>) -> BridgeRequest {
    tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .expect("a request reaches the bridge")
        .expect("the bridge delivers it")
}

/// Whether another request arrives within `wait`.
async fn no_request_within(rx: &mut UnboundedReceiver<BridgeRequest>, wait: Duration) -> bool {
    tokio::time::timeout(wait, rx.recv()).await.is_err()
}

fn prompt_of(req: &BridgeRequest) -> String {
    req.messages
        .iter()
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The id of the event a request is about (`Event: <id>`), or `""` for the start call.
fn event_of(req: &BridgeRequest) -> String {
    prompt_of(req)
        .lines()
        .find_map(|l| l.strip_prefix("Event: "))
        .unwrap_or("")
        .trim()
        .to_string()
}

fn answer(req: BridgeRequest, actions: serde_json::Value) {
    req.reply
        .send(Ok(BridgeReply {
            content: Some(json!({ "actions": actions }).to_string()),
            ..Default::default()
        }))
        .expect("the client is waiting");
}

/// The request that asks again after a refused restart left nothing to send: the same event,
/// with the instruction saying which steps are done.
async fn asked_again(rx: &mut UnboundedReceiver<BridgeRequest>, done: &str) -> BridgeRequest {
    let again = next_request(rx).await;
    assert_eq!(event_of(&again), "redis_response_received");
    let prompt = prompt_of(&again);
    assert!(
        prompt.contains("Those lines or commands must not be sent again")
            && prompt.contains("execute_redis_command is still the way to send anything new")
            && prompt.contains(done),
        "asked again, told {done} is done and its action is not:\n{prompt}"
    );
    again
}

fn cmd(command: &str) -> serde_json::Value {
    json!({"type": "execute_redis_command", "command": command})
}

struct Session {
    state: AppState,
    rx: UnboundedReceiver<BridgeRequest>,
    seen: Arc<Mutex<Vec<String>>>,
    client_id: ClientId,
    server: tokio::task::JoinHandle<()>,
}

/// Start a redis client against the fake server and answer its connect event with `opening`.
async fn start(
    instruction: &str,
    opening: serde_json::Value,
    restart_check: Option<bool>,
) -> Session {
    let (bridge, mut rx) = LlmBridge::new();
    bridge.set_models(vec!["page-model".to_string()]);
    let state = AppState::new_with_options(false, "browser://model".to_string());
    state.set_ollama_model(Some("page-model".to_string())).await;
    let llm = OllamaClient::new_bridge(bridge, Duration::from_secs(30));
    state.set_llm_client(llm.clone()).await;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = tokio::spawn(fake_redis(listener, seen.clone()));

    let (tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();
    // The redis client answers its connect event inside `connect()`, so creation returns only
    // once that first model call has been answered: run it beside the test's bridge.
    let create = tokio::spawn({
        let state = state.clone();
        let instruction = instruction.to_string();
        async move {
            ClientForm {
                protocol: "redis".to_string(),
                remote_addr: Some(format!("127.0.0.1:{port}")),
                instruction: Some(instruction),
                batching: Some(false),
                restart_check,
                ..Default::default()
            }
            .create(&state, llm, tx)
            .await
        }
    });
    let connect = next_request(&mut rx).await;
    assert_eq!(event_of(&connect), "redis_connected");
    answer(connect, opening);
    let client_id = create.await.expect("joins").expect("create redis client");
    Session {
        state,
        rx,
        seen,
        client_id,
        server,
    }
}

impl Session {
    async fn wait_for_commands(&self, n: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while self.seen.lock().unwrap().len() < n {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the server got {:?}, not {n} commands",
                self.seen.lock().unwrap()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn commands(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    async fn finish(self) {
        self.server.abort();
        let _ = self.state.remove_client(self.client_id).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_that_starts_the_script_over_is_asked_about_and_not_sent() {
    let instruction = "Send PING, then GET mykey, then stop sending commands.";
    let mut s = start(instruction, json!([cmd("PING"), cmd("GET mykey")]), None).await;
    s.wait_for_commands(2).await;

    // The reply to PING, answered by starting the script over.
    let reply = next_request(&mut s.rx).await;
    assert_eq!(event_of(&reply), "redis_response_received");
    answer(reply, json!([cmd("PING"), cmd("GET mykey")]));

    // Before anything is sent, one yes/no question naming what would be repeated.
    let check = next_request(&mut s.rx).await;
    assert_eq!(event_of(&check), RESTART_CHECK_EVENT);
    let prompt = prompt_of(&check);
    assert!(prompt.contains(instruction), "{prompt}");
    assert!(
        prompt.contains("GET mykey") && prompt.contains("PONG"),
        "the question names the repeated actions and the message they answer:\n{prompt}"
    );
    let offered: Vec<&str> = check
        .actions
        .iter()
        .filter_map(|a| a["name"].as_str())
        .collect();
    assert_eq!(offered, vec![SKIP_REPEAT, SEND_AGAIN], "{offered:?}");
    answer(check, json!([{"type": SKIP_REPEAT}]));

    // The whole answer was the restart, so the model has not answered PONG yet: asked once
    // more, told which steps are done. Nothing is left, so it answers with nothing.
    let again = asked_again(&mut s.rx, "GET mykey").await;
    answer(again, json!([]));

    // The reply to GET is the next model request — no second PING went out to provoke one.
    let reply = next_request(&mut s.rx).await;
    assert_eq!(event_of(&reply), "redis_response_received");
    assert!(prompt_of(&reply).contains("hello"), "{}", prompt_of(&reply));
    // History records what was actually done on the PONG: nothing.
    let history = s
        .state
        .render_client_history(s.client_id)
        .await
        .expect("history");
    assert!(
        history.contains("PONG") && history.contains("you did: nothing"),
        "{history}"
    );
    // The restart measured most often after the first: the script's first step alone.
    answer(reply, json!([cmd("PING")]));
    let check = next_request(&mut s.rx).await;
    assert_eq!(event_of(&check), RESTART_CHECK_EVENT);
    assert!(
        prompt_of(&check).contains("hello"),
        "the question is about the reply to GET:\n{}",
        prompt_of(&check)
    );
    // Answered the way llama3.1:8b answers it: the action as a bare string.
    answer(check, json!([SKIP_REPEAT]));
    // Asked again, the model sends the opening's steps once more — the second one alone, as
    // llama3.1:8b did, and the first — and then something new: every opening action is
    // dropped unasked, the new step is sent. This is what keeps a conversation going.
    let again = asked_again(&mut s.rx, "PING").await;
    answer(
        again,
        json!([cmd("GET mykey"), cmd("PING"), cmd("GET next")]),
    );
    s.wait_for_commands(3).await;
    let reply = next_request(&mut s.rx).await;
    assert_eq!(event_of(&reply), "redis_response_received");
    answer(reply, json!([]));

    assert!(no_request_within(&mut s.rx, Duration::from_millis(500)).await);
    assert_eq!(s.commands(), vec!["PING", "GET mykey", "GET next"]);
    s.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_the_model_confirms_is_sent_and_what_follows_it_always_is() {
    let instruction = "Send PING. Each time the server answers PONG, send PING again.";
    let mut s = start(instruction, json!([cmd("PING")]), None).await;
    s.wait_for_commands(1).await;

    let reply = next_request(&mut s.rx).await;
    assert_eq!(event_of(&reply), "redis_response_received");
    answer(reply, json!([cmd("PING"), cmd("GET extra")]));
    let check = next_request(&mut s.rx).await;
    assert_eq!(event_of(&check), RESTART_CHECK_EVENT);
    answer(check, json!([{"type": SEND_AGAIN, "trigger": "PONG"}]));
    s.wait_for_commands(3).await;
    assert_eq!(s.commands(), vec!["PING", "PING", "GET extra"]);

    // Declined: the repeated opening is dropped, what came after it in the answer is not.
    let reply = next_request(&mut s.rx).await;
    answer(reply, json!([cmd("PING"), cmd("GET after")]));
    let check = next_request(&mut s.rx).await;
    assert_eq!(event_of(&check), RESTART_CHECK_EVENT);
    answer(check, json!([{"type": SKIP_REPEAT}]));
    s.wait_for_commands(4).await;
    assert_eq!(s.commands(), vec!["PING", "PING", "GET extra", "GET after"]);
    s.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_that_does_not_start_where_the_opening_did_is_not_asked_about() {
    let instruction = "Send PING, then GET mykey, then keep reading keys.";
    let mut s = start(instruction, json!([cmd("PING"), cmd("GET mykey")]), None).await;
    s.wait_for_commands(2).await;

    // A later step of the opening alone, a different command, and the opening's steps in
    // another order: none starts the script over, so each goes out with no question asked.
    let reply = next_request(&mut s.rx).await;
    answer(reply, json!([cmd("GET mykey")]));
    let reply = next_request(&mut s.rx).await;
    assert_eq!(event_of(&reply), "redis_response_received");
    answer(reply, json!([cmd("GET other")]));
    let reply = next_request(&mut s.rx).await;
    assert_eq!(event_of(&reply), "redis_response_received");
    answer(reply, json!([cmd("GET mykey"), cmd("PING")]));
    s.wait_for_commands(6).await;
    assert_eq!(
        s.commands(),
        vec![
            "PING",
            "GET mykey",
            "GET mykey",
            "GET other",
            "GET mykey",
            "PING"
        ]
    );
    s.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_the_check_off_a_restart_is_sent_unasked() {
    let instruction = "Send PING, then GET mykey, then stop sending commands.";
    let mut s = start(
        instruction,
        json!([cmd("PING"), cmd("GET mykey")]),
        Some(false),
    )
    .await;
    s.wait_for_commands(2).await;
    let reply = next_request(&mut s.rx).await;
    assert_eq!(event_of(&reply), "redis_response_received");
    answer(reply, json!([cmd("PING"), cmd("GET mykey")]));
    s.wait_for_commands(4).await;
    let next = next_request(&mut s.rx).await;
    assert_eq!(
        event_of(&next),
        "redis_response_received",
        "no check is asked with restart_check off"
    );
    answer(next, json!([]));
    s.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_instruction_is_a_new_opening() {
    let mut s = start("Send PING, then stop.", json!([cmd("PING")]), None).await;
    s.wait_for_commands(1).await;
    s.state
        .set_instruction_for_client(s.client_id, "Send PING again, once.".to_string())
        .await;
    // The first answer after the change opens the new instruction: PING again, unasked.
    let reply = next_request(&mut s.rx).await;
    answer(reply, json!([cmd("PING")]));
    s.wait_for_commands(2).await;
    // And it is the new opening: repeating it on the next reply is asked about.
    let reply = next_request(&mut s.rx).await;
    answer(reply, json!([cmd("PING")]));
    let check = next_request(&mut s.rx).await;
    assert_eq!(event_of(&check), RESTART_CHECK_EVENT);
    answer(check, json!([{"type": SKIP_REPEAT}]));
    let again = asked_again(&mut s.rx, "PING").await;
    answer(again, json!([]));
    assert!(no_request_within(&mut s.rx, Duration::from_millis(500)).await);
    assert_eq!(s.commands(), vec!["PING", "PING"]);
    s.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_again_with_a_trigger_the_message_does_not_carry_is_not_sent() {
    // The measured failure of a bare yes/no: "send again" to a PONG, for an instruction that
    // says to stop. The model names PING, which the instruction has and PONG does not.
    let instruction = "Send PING, then GET mykey, then stop sending commands.";
    let mut s = start(instruction, json!([cmd("PING"), cmd("GET mykey")]), None).await;
    s.wait_for_commands(2).await;
    let reply = next_request(&mut s.rx).await;
    answer(reply, json!([cmd("PING"), cmd("GET mykey")]));
    let check = next_request(&mut s.rx).await;
    assert_eq!(event_of(&check), RESTART_CHECK_EVENT);
    answer(check, json!([{"type": SEND_AGAIN, "trigger": "PING"}]));
    let again = asked_again(&mut s.rx, "GET mykey").await;
    answer(again, json!([]));
    let reply = next_request(&mut s.rx).await;
    assert_eq!(event_of(&reply), "redis_response_received");
    answer(reply, json!([]));
    assert!(no_request_within(&mut s.rx, Duration::from_millis(500)).await);
    assert_eq!(s.commands(), vec!["PING", "GET mykey"]);
    s.finish().await;
}

#[test]
fn a_trigger_is_founded_only_when_instruction_and_message_both_carry_it() {
    let instruction =
        "Send the command PING. Each time the server answers AGAIN, send PING again. \
                       When it answers DONE, disconnect.";
    let again = json!({"data": "AGAIN"});
    let done = json!({"data": "DONE"});
    assert!(trigger_is_founded("AGAIN", instruction, &again));
    assert!(
        trigger_is_founded("\"again\"", instruction, &again),
        "quoting and case"
    );
    assert!(
        !trigger_is_founded("AGAIN", instruction, &done),
        "not in the message"
    );
    assert!(!trigger_is_founded(
        "PONG",
        instruction,
        &json!({"response": "PONG"})
    ));
    assert!(!trigger_is_founded(
        "PING",
        instruction,
        &json!({"response": "PONG"})
    ));
    assert!(!trigger_is_founded("", instruction, &again), "empty");
    assert!(
        !trigger_is_founded("A", "A thing", &json!({"x": "A"})),
        "too short"
    );
    assert!(
        !trigger_is_founded("data", "send data", &again),
        "a field name is not something the server sent"
    );
    assert!(
        !trigger_is_founded("GAIN", instruction, &again),
        "whole words only"
    );
}

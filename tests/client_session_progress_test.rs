//! A client's model must see what it already did, framed as progress through its instruction.
//!
//! Reproduced 31 October 2026 with llama3.1:8b: a redis client told "Send PING, then GET
//! mykey, then stop sending commands." re-sent PING and GET on every reply — seven rounds
//! before it disconnected. Each reply is a new model call, and the call presented the
//! instruction bare beside the reply, with the history worded as a server's ("answered
//! with"), so the reply read as the cue to start the script again.
//!
//! Driven through the bridge backend so the test reads each request's whole prompt — the
//! system message with the instruction as well as the event — against a local listener that
//! speaks just enough RESP to answer PING and GET.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::llm::{BridgeReply, BridgeRequest, LlmBridge, OllamaClient};
use netget::state::app_state::AppState;
use netget::state::exchange_history::{ExchangeHistory, CLIENT_STARTED_EVENT};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One RESP command off the front of `buf`: its words and how many bytes it used.
fn parse_command(buf: &[u8]) -> Option<(Vec<String>, usize)> {
    let line_end = |from: usize| {
        buf[from..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| from + p)
    };
    if buf.first() != Some(&b'*') {
        let end = line_end(0)?;
        let words = String::from_utf8_lossy(&buf[..end])
            .split_whitespace()
            .map(str::to_string)
            .collect();
        return Some((words, end + 2));
    }
    let end = line_end(0)?;
    let count: usize = std::str::from_utf8(&buf[1..end]).ok()?.parse().ok()?;
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

async fn next_request(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<BridgeRequest>,
) -> BridgeRequest {
    tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .expect("a request reaches the bridge")
        .expect("the bridge delivers it")
}

/// The whole prompt: a network-side request reaches the bridge as one flattened message.
fn prompt_of(req: &BridgeRequest) -> String {
    req.messages
        .iter()
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn answer(req: BridgeRequest, actions: serde_json::Value) {
    req.reply
        .send(Ok(BridgeReply {
            content: Some(json!({ "actions": actions }).to_string()),
            ..Default::default()
        }))
        .expect("the client is waiting");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_reply_to_the_first_command_shows_what_the_client_already_sent() {
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

    let instruction = "Send PING, then GET mykey, then stop sending commands.";
    let (tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();
    // The redis client answers its connect event inside `connect()`, so creation returns only
    // once that first model call has been answered: run it beside the test's bridge.
    let create = tokio::spawn({
        let state = state.clone();
        let llm = llm.clone();
        let tx = tx.clone();
        async move {
            ClientForm {
                protocol: "redis".to_string(),
                remote_addr: Some(format!("127.0.0.1:{port}")),
                instruction: Some(instruction.to_string()),
                batching: Some(false),
                ..Default::default()
            }
            .create(&state, llm, tx)
            .await
        }
    });

    // The connect event: the instruction, and no history yet.
    let connect = next_request(&mut rx).await;
    let system = prompt_of(&connect);
    assert!(system.contains(instruction), "{system}");
    assert!(!system.contains("Earlier in this session"), "{system}");
    answer(
        connect,
        json!([
            {"type": "execute_redis_command", "command": "PING"},
            {"type": "execute_redis_command", "command": "GET mykey"}
        ]),
    );
    let client_id = create.await.expect("joins").expect("create redis client");

    // The reply to PING: the model is shown both commands as already sent.
    let first_reply = next_request(&mut rx).await;
    let user = prompt_of(&first_reply);
    assert!(
        user.contains("Event: redis_response_received"),
        "this is the first reply:\n{user}"
    );
    assert!(
        user.contains("Earlier in this session")
            && user.contains("do not send it again")
            && user.contains("not a new request on each event")
            && user.contains("#1 redis_connected"),
        "the session so far is shown as done:\n{user}"
    );
    let did = user
        .lines()
        .find(|l| l.trim_start().starts_with("you did:"))
        .unwrap_or_else(|| panic!("no `you did:` line:\n{user}"));
    assert!(
        did.contains("PING") && did.contains("GET mykey"),
        "both commands are listed as sent: {did}"
    );
    assert!(
        !user.contains("answered with:"),
        "a client's history is worded as what it did, not as answers it gave:\n{user}"
    );
    answer(first_reply, json!([]));

    let second_reply = next_request(&mut rx).await;
    answer(second_reply, json!([{"type": "disconnect"}]));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while seen.lock().unwrap().len() < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the server never got both commands"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(*seen.lock().unwrap(), vec!["PING", "GET mykey"]);

    // The call that starts a client with no event is recorded too (a client whose first
    // turn is not a connect event would otherwise begin every later prompt with no record).
    let protocol = netget::client::redis::actions::RedisClientProtocol;
    let call = tokio::spawn({
        let state = state.clone();
        let llm = llm.clone();
        let tx = tx.clone();
        async move {
            netget::client::llm_budget::call_llm_for_client(
                &llm,
                &state,
                client_id.to_string(),
                instruction,
                "",
                None,
                &protocol,
                &tx,
            )
            .await
        }
    });
    let start = next_request(&mut rx).await;
    answer(
        start,
        json!([{"type": "execute_redis_command", "command": "PING"}]),
    );
    call.await.expect("joins").expect("the call succeeds");
    let history = state
        .render_client_history(client_id)
        .await
        .expect("the client keeps history");
    assert!(
        history.contains(CLIENT_STARTED_EVENT)
            && history.contains("you did: execute_redis_command"),
        "{history}"
    );

    server.abort();
    let _ = state.remove_client(client_id).await;
}

#[test]
fn a_client_history_is_progress_and_a_server_history_is_answers() {
    let mut history = ExchangeHistory::new();
    history.record(
        CLIENT_STARTED_EVENT,
        &json!({}),
        &[json!({"type": "execute_redis_command", "command": "PING"})],
        40,
    );
    history.record(
        "redis_response_received",
        &json!({"response": "PONG"}),
        &[],
        40,
    );
    let client = history.render_for_client(40).expect("rendered");
    assert!(
        client.contains("you did: execute_redis_command {\"command\":\"PING\"}"),
        "{client}"
    );
    assert!(client.contains("you did: nothing"), "{client}");
    assert!(!client.contains("answered with"), "{client}");
    let server = history.render(40).expect("rendered");
    assert!(server.contains("answered with:"), "{server}");
    assert!(!server.contains("you did:"), "{server}");
}

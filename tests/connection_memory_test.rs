//! Memory about one peer stays with that peer's connection.
//!
//! Reproduced 31 October 2026 with llama3.1:8b: a telnet BBS appended `user_name: Zed` to the
//! server's memory — twice — so the next peer's events would have been answered as Zed's.
//! Server memory is one string every connection reads. Connection memory
//! (`set_connection_memory` / `append_connection_memory`) is shown with one connection's events
//! only and ends with it, and a `key: value` line replaces the earlier line with that key
//! instead of repeating it.
//!
//! The end-to-end test drives two telnet peers through the bridge backend, which hands the
//! test each request's full prompt. Its control is in the same test: the peer whose name was
//! written must see it on its next event, or the other peer's not seeing it would prove
//! nothing.

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::llm::actions::common::{append_memory_lines, memory_line_key};
use netget::llm::{BridgeReply, BridgeRequest, LlmBridge, OllamaClient};
use netget::server::connection::ConnectionId;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[test]
fn a_keyed_line_replaces_the_earlier_one_with_its_key() {
    assert_eq!(
        memory_line_key("user_name: Zed").as_deref(),
        Some("user_name")
    );
    assert_eq!(
        memory_line_key("conn-3 cwd: /home").as_deref(),
        Some("conn-3 cwd")
    );
    assert_eq!(
        memory_line_key("User_Name:Zed"),
        None,
        "no space after the colon"
    );
    assert_eq!(memory_line_key("see http://example.com"), None);
    assert_eq!(memory_line_key("meeting at 12:30"), None);
    assert_eq!(memory_line_key("a free-form note"), None);

    let once = append_memory_lines("", "user_name: Zed");
    let twice = append_memory_lines(&once, "user_name: Zed");
    assert_eq!(
        twice, "user_name: Zed",
        "appending the same fact twice keeps one line"
    );

    let changed = append_memory_lines("user_name: Zed\nlast_selected: 2", "user_name: Ada");
    assert_eq!(changed, "last_selected: 2\nuser_name: Ada");

    // Lines with no key are notes, and notes accumulate.
    let notes = append_memory_lines("a note", "a note");
    assert_eq!(notes, "a note\na note");
}

#[tokio::test]
async fn connection_memory_is_refused_where_there_is_no_connection() {
    // With no connection in context the only other place for the note is the server's shared
    // memory, which is exactly where it must not go.
    let state = AppState::new();
    let sid = state
        .add_server(netget::state::server::ServerInstance::new(
            ServerId::new(0),
            0,
            "Telnet".to_string(),
            String::new(),
        ))
        .await;
    let result = netget::llm::actions::executor::execute_actions(
        vec![json!({"type": "append_connection_memory", "value": "user_name: Zed"})],
        &state,
        None,
        Some(sid),
        None,
    )
    .await
    .expect("the batch runs");
    assert_eq!(result.failures.len(), 1, "refused, not redirected");
    assert_eq!(state.get_memory(sid).await.unwrap_or_default(), "");

    // Nor for a connection the server does not hold: nothing would ever clear the entry.
    let result = netget::llm::actions::executor::execute_actions_on_connection(
        vec![json!({"type": "set_connection_memory", "value": "user_name: Zed"})],
        &state,
        None,
        Some(sid),
        None,
        Some(ConnectionId::new(999)),
    )
    .await
    .expect("the batch runs");
    assert_eq!(result.failures.len(), 1);
    assert_eq!(
        state
            .get_connection_memory(sid, ConnectionId::new(999))
            .await,
        None
    );
}

#[tokio::test]
async fn shared_memory_appends_by_key_too() {
    let state = AppState::new();
    let sid = state
        .add_server(netget::state::server::ServerInstance::new(
            ServerId::new(0),
            0,
            "Telnet".to_string(),
            String::new(),
        ))
        .await;
    for _ in 0..2 {
        netget::llm::actions::executor::execute_actions(
            vec![json!({"type": "append_memory", "value": "visitors: 1"})],
            &state,
            None,
            Some(sid),
            None,
        )
        .await
        .expect("runs");
    }
    netget::llm::actions::executor::execute_actions(
        vec![json!({"type": "append_memory", "value": "visitors: 2"})],
        &state,
        None,
        Some(sid),
        None,
    )
    .await
    .expect("runs");
    assert_eq!(
        state.get_memory(sid).await.unwrap_or_default(),
        "visitors: 2"
    );
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

/// The live connection ids of the server, oldest first.
async fn connection_ids(state: &AppState, sid: ServerId) -> Vec<ConnectionId> {
    let mut ids: Vec<ConnectionId> = state
        .get_server(sid)
        .await
        .map(|s| s.connections.keys().copied().collect())
        .unwrap_or_default();
    ids.sort_by_key(|c| c.as_u32());
    ids
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_peers_name_is_not_read_out_to_the_next() {
    let (bridge, mut rx) = LlmBridge::new();
    bridge.set_models(vec!["page-model".to_string()]);
    let state = AppState::new_with_options(false, "browser://model".to_string());
    state.set_ollama_model(Some("page-model".to_string())).await;
    state
        .set_llm_client(OllamaClient::new_bridge(bridge, Duration::from_secs(30)))
        .await;
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();
    let sid = ServerForm {
        protocol: "telnet".to_string(),
        port: Some(0),
        instruction: Some("A BBS: ask for the user's name, then greet them by it.".to_string()),
        ..Default::default()
    }
    .create(&state, status_tx)
    .await
    .expect("create telnet server");
    let mut port = None;
    for _ in 0..200 {
        if let Some(addr) = state.get_server(sid).await.and_then(|s| s.local_addr) {
            port = Some(addr.port());
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let port = port.expect("the telnet server binds a port");

    // Peer A connects and gives its name; the model keeps it — twice, as the 8B model did.
    let a = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect A");
    let (a_read, mut a_write) = a.into_split();
    let mut a_read = BufReader::new(a_read);
    let connect_a = next_request(&mut rx).await;
    let names: Vec<String> = connect_a
        .actions
        .iter()
        .filter_map(|x| x["name"].as_str().map(str::to_string))
        .collect();
    for offered in ["set_connection_memory", "append_connection_memory"] {
        assert!(
            names.iter().any(|n| n == offered),
            "{offered} offered: {names:?}"
        );
    }
    answer(
        connect_a,
        json!([{"type": "send_telnet_line", "line": "Name?"}]),
    );
    read_line_containing(&mut a_read, "Name?").await;

    a_write
        .write_all(b"my name is Zed\r\n")
        .await
        .expect("write");
    let line_a = next_request(&mut rx).await;
    answer(
        line_a,
        json!([
            {"type": "append_connection_memory", "value": "user_name: Zed"},
            {"type": "append_connection_memory", "value": "user_name: Zed"},
            {"type": "send_telnet_line", "line": "Hello Zed"}
        ]),
    );
    read_line_containing(&mut a_read, "Hello Zed").await;
    let conn_a = connection_ids(&state, sid).await[0];
    assert_eq!(
        state.get_connection_memory(sid, conn_a).await.as_deref(),
        Some("user_name: Zed"),
        "kept once, on A's connection"
    );
    assert_eq!(
        state.get_memory(sid).await.unwrap_or_default(),
        "",
        "nothing went to the memory every peer reads"
    );

    // Peer B connects and asks who it is: nothing of A's reaches its prompts.
    let b = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect B");
    let (b_read, mut b_write) = b.into_split();
    let mut b_read = BufReader::new(b_read);
    let connect_b = next_request(&mut rx).await;
    assert!(
        !prompt_of(&connect_b).contains("Zed"),
        "B's connect event carries A's name:\n{}",
        prompt_of(&connect_b)
    );
    answer(
        connect_b,
        json!([{"type": "send_telnet_line", "line": "Name?"}]),
    );
    read_line_containing(&mut b_read, "Name?").await;
    b_write.write_all(b"who am i\r\n").await.expect("write");
    let line_b = next_request(&mut rx).await;
    assert!(
        !prompt_of(&line_b).contains("Zed"),
        "B's line carries A's name:\n{}",
        prompt_of(&line_b)
    );
    answer(
        line_b,
        json!([{"type": "send_telnet_line", "line": "a stranger"}]),
    );
    read_line_containing(&mut b_read, "a stranger").await;

    // Control: A's next event does carry it, so B's prompts lacking it means something.
    a_write
        .write_all(b"what is my name\r\n")
        .await
        .expect("write");
    let again_a = next_request(&mut rx).await;
    let prompt = prompt_of(&again_a);
    assert!(
        prompt.contains("Memory for this connection") && prompt.contains("user_name: Zed"),
        "A's own memory is shown with A's events:\n{prompt}"
    );
    answer(
        again_a,
        json!([{"type": "send_telnet_line", "line": "You are Zed"}]),
    );
    read_line_containing(&mut a_read, "You are Zed").await;

    // It ends with the connection.
    drop(a_write);
    drop(a_read);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while state.get_connection_memory(sid, conn_a).await.is_some() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "A's memory outlived A's connection"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = state.remove_server(sid).await;
}

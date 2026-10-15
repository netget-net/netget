//! ra_svn framing, from the wire, with zero LLM calls.
//!
//! Two halves, and both are needed. The first proves the server frames on **tuple structure**:
//! a message that ends without a newline is answered, and a counted string containing newlines
//! is read as data rather than as message boundaries. That is the defect this protocol shipped
//! with — `read_line` waiting for a newline a real `svn` client never sends — and
//! `real_client_test.rs` proves it against the actual client, but only where `svn` is
//! installed. This one holds everywhere.
//!
//! The second proves the bounds declared in `src/server/svn/wire.rs` actually fire: a depth
//! bomb and a string length the peer merely *claims*. A bound with no test is a comment. Both
//! were checked by removing them, and what happens then is worth knowing: the tests fail on
//! their own 20-second deadline waiting for a refusal that never comes, not on an assertion.
//! An unbounded parser has no failure to report — it goes on reading, and in the
//! declared-length case goes on to allocate the gigabyte it was promised.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features svn --test server -- svn::framing


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
            if s.port != 0 {
                return s.port;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

/// A server whose every event is answered by a static handler, so the LLM is never consulted
/// and the backend address above (port 1) is never reached.
async fn start_static_svn_server(state: &AppState, tx: mpsc::UnboundedSender<String>) -> u16 {
    let server_id = ServerForm {
        protocol: "svn".to_string(),
        port: Some(0),
        // Empty, not None: `ServerForm::create` substitutes a default instruction for `None`,
        // and any non-empty instruction makes the server consult the model.
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            serde_json::json!({
                "event_pattern": "svn_greeting",
                "handler": {
                    "type": "static",
                    "actions": [ { "type": "send_svn_greeting", "min_version": 2,
                                   "max_version": 2, "mechanisms": ["ANONYMOUS"] } ]
                }
            }),
            serde_json::json!({
                "event_pattern": "svn_client_capabilities",
                "handler": {
                    "type": "static",
                    "actions": [ { "type": "send_svn_auth_request",
                                   "mechanisms": ["ANONYMOUS"], "realm": "lab" } ]
                }
            }),
            serde_json::json!({
                "event_pattern": "svn_auth_response",
                "handler": {
                    "type": "static",
                    "actions": [
                        { "type": "send_svn_auth_success" },
                        { "type": "send_svn_repos_info",
                          "uuid": "0d1e2f30-4152-4364-8576-a7b8c9dae1f2",
                          "repository_root": "svn://127.0.0.1" }
                    ]
                }
            }),
            serde_json::json!({
                "event_pattern": "svn_command",
                "handler": {
                    "type": "static",
                    "actions": [ { "type": "send_svn_success", "data": "1" } ]
                }
            }),
        ]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create svn server");
    wait_for_port(state, server_id).await
}

async fn connect(
    port: u16,
) -> (
    BufReader<tokio::io::ReadHalf<tokio::net::TcpStream>>,
    tokio::io::WriteHalf<tokio::net::TcpStream>,
) {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (read_half, write_half) = tokio::io::split(stream);
    (BufReader::new(read_half), write_half)
}

async fn read_reply(
    reader: &mut BufReader<tokio::io::ReadHalf<tokio::net::TcpStream>>,
    what: &str,
) -> String {
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
        .unwrap_or_else(|e| panic!("read error waiting for {what}: {e}"));
    line
}

/// The real client's handshake shape, byte for byte in the ways that matter: the capability
/// tuple ends in a **space** with no newline, and the ANONYMOUS token is a counted string that
/// **contains** one. A line-framed reader stalls on the first and desynchronises on the second.
#[tokio::test]
async fn a_tuple_with_no_trailing_newline_and_a_newline_inside_a_string_is_framed() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let port = start_static_svn_server(&state, tx).await;
    let (mut reader, mut write_half) = connect(port).await;

    let greeting = read_reply(&mut reader, "greeting").await;
    assert!(greeting.contains("success"), "greeting was {greeting:?}");

    // No newline anywhere, and the trailing byte is a space — exactly what svn 1.14.5 sends.
    write_half
        .write_all(
            b"( 2 ( edit-pipeline svndiff1 ) 21:svn://127.0.0.1:1/lab 14:SVN/1.14.5 (x) ( ) ) ",
        )
        .await
        .unwrap();

    let auth_request = read_reply(&mut reader, "auth-request").await;
    assert!(
        auth_request.contains("ANONYMOUS") && auth_request.contains("3:lab"),
        "expected an auth-request tuple, got {auth_request:?}"
    );

    // A counted string carrying two newlines, still with nothing after the closing paren.
    write_half
        .write_all(b"( ANONYMOUS ( 5:a\nb\nc ) ) ")
        .await
        .unwrap();

    let auth_success = read_reply(&mut reader, "auth success").await;
    assert_eq!(auth_success, "( success ( ) )\n");
    let repos_info = read_reply(&mut reader, "repos-info").await;
    assert!(
        repos_info.contains("0d1e2f30-4152-4364-8576-a7b8c9dae1f2"),
        "expected repository info, got {repos_info:?}"
    );

    // And a command, which in a completed session is preceded by the trivial auth-request the
    // real client consumes before every response.
    write_half
        .write_all(b"( get-latest-rev ( ) ) ")
        .await
        .unwrap();
    let reply = read_reply(&mut reader, "command reply").await;
    assert_eq!(reply, "( success ( ( ) 0: ) ) ( success ( 1 ) )\n");
}

/// A peer that never completed the handshake gets exactly the bytes its handler produced: no
/// trivial auth-request prefix, because no client is waiting to consume one.
#[tokio::test]
async fn a_peer_that_skips_the_handshake_gets_an_unprefixed_reply() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let port = start_static_svn_server(&state, tx).await;
    let (mut reader, mut write_half) = connect(port).await;

    let _greeting = read_reply(&mut reader, "greeting").await;
    write_half
        .write_all(b"( get-latest-rev ( ) )\n")
        .await
        .unwrap();
    let reply = read_reply(&mut reader, "command reply").await;
    assert_eq!(reply, "( success ( 1 ) )\n");
}

/// `(` is one byte. Without [`netget::server::svn::wire::MAX_TUPLE_DEPTH`] this is a heap of
/// 65 000 nested `Vec`s for 64 KiB on the wire, pre-authentication — and a *recursive* parser
/// would take the whole process down with a SIGSEGV rather than a catchable panic.
#[tokio::test]
async fn a_depth_bomb_is_refused_in_svns_own_vocabulary() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let port = start_static_svn_server(&state, tx).await;
    let (mut reader, mut write_half) = connect(port).await;

    let _greeting = read_reply(&mut reader, "greeting").await;
    let bomb = vec![b'('; netget::server::svn::wire::MAX_TUPLE_DEPTH * 4];
    write_half.write_all(&bomb).await.unwrap();

    let refusal = read_reply(&mut reader, "refusal").await;
    assert!(
        refusal.contains("failure") && refusal.contains("210004"),
        "expected an ra_svn malformed-data failure, got {refusal:?}"
    );

    // And the connection ends, rather than leaving the allocation alive.
    let mut rest = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut rest))
        .await
        .expect("timed out waiting for EOF")
        .expect("read after refusal");
    assert_eq!(n, 0, "server kept the connection open, sent {rest:?}");
}

/// The length is bounded as **declared**, not as delivered: these are twelve bytes on the wire
/// claiming a gigabyte, and nothing may be allocated for them.
#[tokio::test]
async fn a_string_length_larger_than_the_cap_is_refused_before_it_is_read() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let port = start_static_svn_server(&state, tx).await;
    let (mut reader, mut write_half) = connect(port).await;

    let _greeting = read_reply(&mut reader, "greeting").await;
    write_half.write_all(b"( 1073741824:").await.unwrap();

    let refusal = read_reply(&mut reader, "refusal").await;
    assert!(
        refusal.contains("failure") && refusal.contains("210004"),
        "expected an ra_svn malformed-data failure, got {refusal:?}"
    );
}

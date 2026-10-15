//! Two things a Redis server must not let model output do: end a RESP frame early, and
//! outlive `stop_server`.
//!
//! Zero LLM calls throughout — a `*` static handler supplies the reply, and
//! `instruction: Some(String::new())` keeps `ServerForm::create` from substituting its default
//! instruction (any non-empty instruction makes `operator_wants_dynamic` true, so a server
//! built with `..Default::default()` consults the model whatever a comment claims).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features redis --test server -- redis::resp_framing --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Redis server #{} never bound a port", id.as_u32());
}

async fn start_with_handler(state: &AppState, action: serde_json::Value) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "redis".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [ action ] }
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create redis server");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

/// Send one RESP command and read one reply's worth of bytes.
async fn command(stream: &mut TcpStream, argv: &[&str]) -> Vec<u8> {
    let mut req = format!("*{}\r\n", argv.len()).into_bytes();
    for a in argv {
        req.extend_from_slice(format!("${}\r\n{}\r\n", a.len(), a).as_bytes());
    }
    stream.write_all(&req).await.expect("write command");

    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
        .await
        .expect("a reply within 10s")
        .expect("read reply");

    // The pcap oracle. This file asserts on the *content* of the reply, byte for
    // byte; Wireshark's `resp` dissector asserts it is a well-formed RESP frame at
    // all — the type byte, the length prefix agreeing with the payload, the CRLF
    // terminator. Both halves of the injection hazard this file exists for are
    // framing questions, so an independent RESP reader belongs in the loop.
    crate::helpers::pcap_oracle::PcapOracle::tcp("redis")
        .to_server(&req)
        .from_server(&buf[..n])
        .assert_clean();

    buf[..n].to_vec()
}

/// A RESP simple string is CRLF-terminated with **no length prefix**, so a newline inside the
/// payload ends the frame early and everything after it is parsed as the *next* reply. The
/// connection is then desynchronised permanently: every later command reads the previous
/// command's leftovers and the client cannot tell.
///
/// The payload here is model output (`redis_simple_string`'s `value`), so it is exactly as
/// trustworthy as any other generated text. `mod.rs` documents this hazard on its own
/// LLM-failure path and avoids it by sending a fixed category; the model-facing verbs had no
/// such guard.
#[tokio::test]
async fn crlf_in_a_model_supplied_simple_string_cannot_split_the_frame() {
    let state = new_state().await;
    let (_id, port) = start_with_handler(
        &state,
        serde_json::json!({
            "type": "redis_simple_string",
            "value": "OK\r\n+INJECTED\r\n:99"
        }),
    )
    .await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    let first = command(&mut stream, &["PING"]).await;

    // Exactly one frame: a leading '+', a single trailing CRLF, and no CRLF inside.
    assert_eq!(first.first(), Some(&b'+'), "expected a simple string reply");
    assert!(
        first.ends_with(b"\r\n"),
        "reply must be CRLF-terminated, got {:?}",
        String::from_utf8_lossy(&first)
    );
    let body = &first[1..first.len() - 2];
    assert!(
        !body.contains(&b'\r') && !body.contains(&b'\n'),
        "a CR/LF survived into the frame body, which splits the reply and desynchronises the \
         connection for good: {:?}",
        String::from_utf8_lossy(&first)
    );

    // Redis maps CR/LF to spaces rather than dropping the text, so the payload survives whole
    // - it is simply no longer able to end the frame.
    assert_eq!(
        first, b"+OK  +INJECTED  :99\r\n",
        "expected the CR and LF each replaced by one space, as Redis's own \
         `sdsmapchars(s, \"\\r\\n\", \"  \", 2)` does"
    );

    // The decisive check: the next command must get *its own* reply, not the tail of the
    // previous one. With the frame split at the first CRLF, this read returns "+INJECTED\r\n"
    // - so the body would start with "INJECTED" rather than "OK".
    let second = command(&mut stream, &["PING"]).await;
    assert_eq!(
        second, first,
        "the second command read a different frame from the first - the connection is \
         desynchronised, and every later reply is off by one"
    );
    assert!(
        second.starts_with(b"+OK"),
        "the second reply was the tail of the first: {:?}",
        String::from_utf8_lossy(&second)
    );
}

/// Same hazard on the error verb, which is the more likely one in practice: a model asked to
/// explain a refusal writes multi-line prose without thinking about framing.
#[tokio::test]
async fn crlf_in_a_model_supplied_error_cannot_split_the_frame() {
    let state = new_state().await;
    let (_id, port) = start_with_handler(
        &state,
        serde_json::json!({
            "type": "redis_error",
            "message": "ERR bad request\nreason: the key was not found\r\n+INJECTED"
        }),
    )
    .await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    let first = command(&mut stream, &["GET", "k"]).await;
    assert_eq!(first.first(), Some(&b'-'), "expected an error reply");
    let body = &first[1..first.len() - 2];
    assert!(
        !body.contains(&b'\r') && !body.contains(&b'\n'),
        "a CR/LF survived into the error frame: {:?}",
        String::from_utf8_lossy(&first)
    );
    // Redis maps CR/LF to spaces rather than dropping the text, so the message survives.
    let text = String::from_utf8_lossy(&first);
    assert!(
        text.contains("ERR bad request") && text.contains("the key was not found"),
        "the message itself should survive, only its newlines replaced: {text:?}"
    );

    let second = command(&mut stream, &["GET", "k"]).await;
    assert_eq!(
        second, first,
        "connection desynchronised after a multi-line error"
    );
}

/// `stop_server` has to stop the server, not just release the port. Registering only the
/// accept loop aborts the listener while every in-flight session keeps running — the socket is
/// gone from `netstat` but the peer is still being served.
#[tokio::test]
async fn stop_server_ends_an_in_flight_connection_not_just_the_listener() {
    let state = new_state().await;
    let (server_id, port) = start_with_handler(
        &state,
        serde_json::json!({ "type": "redis_simple_string", "value": "PONG" }),
    )
    .await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    // Prove the session is live and being served before stopping anything.
    let reply = command(&mut stream, &["PING"]).await;
    assert_eq!(reply, b"+PONG\r\n");

    // `remove_server` is what the dashboard's stop and MCP's `stop_server` both call; its
    // `teardown_server` aborts every handle registered for the server.
    state
        .remove_server(server_id)
        .await
        .expect("the server was registered");

    // The connection task is aborted, so the peer's read reaches EOF (or a reset). Before the
    // per-connection handle was registered, this read would block until the 10s timeout with
    // the session still happily alive.
    let mut buf = [0u8; 64];
    let ended = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf)).await;
    match ended {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!(
            "expected EOF after stop_server, got {n} bytes: {:?}",
            &buf[..n]
        ),
        Err(_) => panic!(
            "the connection outlived stop_server - only the accept loop was registered with \
             register_server_task, so the port was released while the session kept running"
        ),
    }
}

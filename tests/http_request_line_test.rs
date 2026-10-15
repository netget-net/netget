//! What a bare `GET /` (what typing into telnet produces) does to the HTTP
//! server, versus a well-formed HTTP/1.1 request.
//!
//! HTTP/1.x requires three tokens on the request line — `METHOD SP TARGET SP
//! VERSION` — followed by headers and a blank line. `GET /\r\n` has two, which
//! is an HTTP/0.9 simple request; hyper does not support HTTP/0.9 and answers
//! 400 from its own parser, before NetGet's service function runs. So no
//! event is raised, no handler fires and no LLM call happens: the 400 is not
//! NetGet declining to answer, it is the request never reaching NetGet.


use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use tokio::sync::mpsc;

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server never bound");
}

fn round_trip(port: u16, raw: &[u8]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(raw).expect("write");
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

/// Multi-threaded: the blocking socket reads below would otherwise starve the
/// server task on a current-thread runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bare_get_slash_is_rejected_by_the_parser_before_netget_sees_it() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // A static handler, so a request that *does* reach NetGet is answered
    // deterministically and the difference is unmistakable.
    let form = ServerForm {
        protocol: "http".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "http_request",
            "handler": {
                "type": "static",
                "actions": [{
                    "type": "send_http_response",
                    "status": 200,
                    "body": "hello-from-netget"
                }]
            }
        })]),
        ..Default::default()
    };
    let server_id = form.create(&state, tx).await.expect("create http server");
    let port = wait_for_port(&state, server_id).await;

    // (A) Exactly what `telnet host port` sends when you type `GET /` + Enter.
    let bare = round_trip(port, b"GET /\r\n");
    assert!(
        bare.contains("400"),
        "a bare 'GET /' should be rejected as a malformed request line, got: {bare:?}"
    );
    assert!(
        !bare.contains("hello-from-netget"),
        "the static handler must not have run: {bare:?}"
    );

    // (B) A well-formed HTTP/1.1 request: three tokens, headers, blank line.
    let full = round_trip(
        port,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(
        full.contains("hello-from-netget"),
        "a well-formed request should reach NetGet and be answered, got: {full:?}"
    );

    // The decisive evidence: only the well-formed request produced an event.
    // The malformed one never reached NetGet, so it left no trace at all.
    let entries = state
        .list_access_logs_for(Some(AccessLogOwner::Server(server_id.as_u32())), None)
        .await;
    assert_eq!(
        entries.len(),
        1,
        "exactly one request should have reached NetGet; entries: {entries:#?}"
    );
    assert_eq!(entries[0].event_type, "http_request");
}

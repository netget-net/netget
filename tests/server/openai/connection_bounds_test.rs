//! The read deadlines on a real, running OpenAI-compatible server, driven from a raw socket.
//!
//! This is a hyper server, so the two bounds are enforced in two different places and each
//! needs its own proof.
//!
//! **A peer that has connected and said nothing must eventually be let go of.** That one is a
//! `TcpStream::peek` *before* `serve_connection` is called: hyper owns every read afterwards
//! and keeps polling the connection while a request is being answered, so a deadline on its
//! reads would fire in the middle of a model round-trip — and on this server, where the answer
//! *is* model output, that round-trip is the normal case rather than the slow one. Remove the
//! peek in `src/server/openai/mod.rs` and the first test hangs until its own window expires.
//!
//! **An established keep-alive connection that goes silent must be let go of too**, and that
//! one is `watch_idle` over a `ConnectionActivity` the service holds busy for the whole of each
//! request. The second test drives `GET /v1/models` through a static routing rule — so no model
//! is involved — and then goes quiet on an otherwise healthy keep-alive connection. The two
//! bounds are set far apart and the wrong way round: a first-byte deadline applied to the whole
//! connection would keep this one for 60 seconds and time the assertion out.
//!
//! The values here are overrides, not the defaults. The shipped defaults are 30 seconds and 300
//! (argued beside `FIRST_BYTE_READ_TIMEOUT` and `IDLE_BETWEEN_REQUESTS_TIMEOUT`), and a test
//! that asserted them by waiting them out would be the slowest thing in the suite. That is why
//! both are declared startup parameters: what is asserted here is that each parameter is read
//! and applied to the bound it names; the *values* are argued where they are declared.
//!
//! The third test is not about a deadline: it checks that the connection-cap refusal this
//! server hands a peer over `MAX_CONNECTIONS` is a well-framed HTTP response. Its
//! `Content-Length` is written by hand in a byte-string literal, and a wrong one makes every
//! client hang waiting for a body that is not coming — which is a worse failure than the silent
//! close the refusal exists to replace.
//!
//! No mock backend: the LLM endpoint is a dead port. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features openai --test server -- \
//!       openai::connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The first-byte bound the first test drives, as `first_byte_timeout_secs`.
const SHORT_FIRST_BYTE: Duration = Duration::from_secs(6);

/// The idle bound the second test drives, as `idle_timeout_secs`.
const SHORT_IDLE: Duration = Duration::from_secs(3);

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
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("OpenAI server #{} never bound a port", id.as_u32());
}

/// A model-free OpenAI server: an empty instruction really is model-free, where `None` is
/// replaced by a default one and every event would consult the LLM.
async fn start_server(
    state: &AppState,
    startup_params: Option<serde_json::Value>,
    event_handlers: Option<Vec<serde_json::Value>>,
) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "openai".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params,
        event_handlers,
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create openai server");
    wait_for_port(state, server_id).await
}

#[tokio::test]
async fn a_peer_that_connects_and_sends_no_request_is_closed_at_the_first_byte_bound() {
    let state = new_state().await;
    let port = start_server(
        &state,
        Some(serde_json::json!({
            "first_byte_timeout_secs": SHORT_FIRST_BYTE.as_secs(),
        })),
        None,
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    // Generous against the declared bound so an ordinary scheduling delay under
    // --test-threads=100 is not mistaken for a missing deadline; what is asserted is that the
    // read ends at all, and that it ends on this bound rather than on the 300-second default.
    let read = tokio::time::timeout(
        SHORT_FIRST_BYTE + Duration::from_secs(45),
        peer.read_to_end(&mut sink),
    )
    .await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "a peer that connected and sent no request was still holding the socket, the connection \
         task and its AppState entry after {}s — either the peek-based first-byte bound is not \
         applied at all, or `first_byte_timeout_secs` was declared and never read",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        elapsed >= SHORT_FIRST_BYTE / 2,
        "closed after only {}ms — that is not the declared {}s bound, it is something else \
         tearing the connection down, and this test would then pass without the bound existing",
        elapsed.as_millis(),
        SHORT_FIRST_BYTE.as_secs()
    );
    assert!(
        sink.is_empty(),
        "the server wrote {} bytes to a peer that had sent no request; HTTP is \
         client-speaks-first",
        sink.len()
    );
}

#[tokio::test]
async fn once_a_request_has_been_answered_the_idle_bound_governs_not_the_first_byte_one() {
    let state = new_state().await;
    // The two bounds are set far apart and the wrong way round on purpose: if the first-byte
    // bound governed the whole connection, this one would live 60 seconds and the assertion
    // below would time out.
    let port = start_server(
        &state,
        Some(serde_json::json!({
            "first_byte_timeout_secs": 60,
            "idle_timeout_secs": SHORT_IDLE.as_secs(),
        })),
        Some(vec![serde_json::json!({
            "event_pattern": "openai_request",
            "handler": {
                "type": "static",
                "actions": [{
                    "type": "openai_models_response",
                    "models": ["gpt-4"]
                }]
            }
        })]),
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    // HTTP/1.1 without `Connection: close`, so the connection stays open after the answer —
    // which is the state this test is about.
    peer.write_all(b"GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .expect("write request");

    let mut reply = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(20), peer.read(&mut reply))
        .await
        .expect("the static handler did not answer /v1/models within 20s")
        .expect("read reply");
    let head = String::from_utf8_lossy(&reply[..n]);
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "the static rule did not answer with 200, so what follows is not the answered \
         keep-alive connection this test is about; got: {head}"
    );

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(45), peer.read_to_end(&mut sink)).await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "an answered keep-alive connection that then went quiet was never closed — \
         `idle_timeout_secs` was declared and is not being read, or nothing watches \
         ConnectionActivity"
    );
    read.unwrap().expect("read to EOF");
    assert!(
        elapsed >= SHORT_IDLE / 2,
        "closed after only {}ms, which is below the declared {}s idle bound",
        elapsed.as_millis(),
        SHORT_IDLE.as_secs()
    );
    assert!(
        elapsed < Duration::from_secs(40),
        "closed after {}s, which is the 60-second first-byte bound rather than the {}s idle one",
        elapsed.as_secs(),
        SHORT_IDLE.as_secs()
    );
}

#[test]
fn the_connection_cap_refusal_is_a_well_framed_http_response() {
    let refusal = std::str::from_utf8(netget::server::openai::CONNECTION_CAP_REFUSAL)
        .expect("the refusal must be valid UTF-8 to be a valid HTTP response");
    let (head, body) = refusal
        .split_once("\r\n\r\n")
        .expect("the refusal has no header/body separator, so no client can parse it");

    assert!(
        head.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "a peer over the cap must be told it is a server-side refusal it may retry; got: {head}"
    );
    assert!(
        head.contains("\r\nRetry-After: 5\r\n"),
        "without a Retry-After a client has no guidance on when to come back; got: {head}"
    );

    let declared: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .expect("the refusal declares no Content-Length")
        .trim()
        .parse()
        .expect("Content-Length is not a number");
    assert_eq!(
        declared,
        body.len(),
        "Content-Length says {declared} and the body is {} bytes. It is written by hand in a \
         byte-string literal in src/server/openai/mod.rs, and a wrong one is worse than the \
         silent close this refusal replaced: every client hangs waiting for a body that is \
         never coming, or discards the message as truncated",
        body.len()
    );
    let parsed: serde_json::Value = serde_json::from_str(body.trim())
        .expect("the refusal claims Content-Type: application/json and its body does not parse");
    assert!(
        parsed.get("error").is_some(),
        "an OpenAI SDK reads a refusal out of the `error` object; this body has none: {body}"
    );
}

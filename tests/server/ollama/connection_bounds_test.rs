//! The read deadlines on a real, running Ollama API server, driven from a raw socket.
//!
//! This is a hyper server, so the two bounds are enforced in two different places and each
//! needs its own proof.
//!
//! **A peer that has connected and said nothing must eventually be let go of.** That one is a
//! `TcpStream::peek` *before* `serve_connection` is called: hyper owns every read afterwards
//! and keeps polling the connection while a request is being answered, so a deadline on its
//! reads would fire in the middle of a model round-trip. Remove the peek in
//! `src/server/ollama/mod.rs` and the first test hangs until its own window expires.
//!
//! **An established keep-alive connection that goes silent must be let go of too**, and that
//! one is `watch_idle` over a `ConnectionActivity` the service holds busy for the whole of each
//! request. The second test drives `GET /api/tags` through a static routing rule — so no model
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
//!   ./cargo-isolated.sh test --no-default-features --features ollama --test server -- \
//!       ollama::connection_bounds --test-threads=100

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
    panic!("Ollama server #{} never bound a port", id.as_u32());
}

/// A model-free Ollama server: an empty instruction really is model-free, where `None` is
/// replaced by a default one and every event would consult the LLM.
async fn start_server(
    state: &AppState,
    startup_params: Option<serde_json::Value>,
    event_handlers: Option<Vec<serde_json::Value>>,
) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "ollama".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params,
        event_handlers,
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create ollama server");
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
            "event_pattern": "ollama_models_request",
            "handler": {
                "type": "static",
                "actions": [{
                    "type": "ollama_models_response",
                    "models": ["llama2"]
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
    peer.write_all(b"GET /api/tags HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .expect("write request");

    let mut reply = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(20), peer.read(&mut reply))
        .await
        .expect("the static handler did not answer /api/tags within 20s")
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
    let refusal = std::str::from_utf8(netget::server::ollama::CONNECTION_CAP_REFUSAL)
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
         byte-string literal in src/server/ollama/mod.rs, and a wrong one is worse than the \
         silent close this refusal replaced: every client hangs waiting for a body that is \
         never coming, or discards the message as truncated",
        body.len()
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(body.trim()).is_ok(),
        "the refusal claims Content-Type: application/json and its body does not parse: {body}"
    );
}

/// Hold the tail back until the 413 and EOF have arrived. This makes the unread-upload race
/// deterministic: the server must flush the refusal first, then keep its read half alive for
/// the sender, rather than dropping the socket while that sender is still writing.
#[tokio::test]
async fn a_body_refusal_is_flushed_before_the_upload_tail_is_drained() {
    let state = new_state().await;
    let port = start_server(&state, None, None).await;
    let cap = netget::server::ollama::MAX_REQUEST_BODY_BYTES;
    let tail = vec![b'A'; 1024 * 1024];
    for chunked in [false, true] {
        let peer = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (mut reader, mut writer) = peer.into_split();
        let framing = if chunked {
            format!(
                "Transfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                cap + 1 + tail.len()
            )
        } else {
            format!("Content-Length: {}\r\n\r\n", cap + 1 + tail.len())
        };
        tokio::time::timeout(Duration::from_secs(30), async {
            writer
                .write_all(
                    format!("POST /api/generate HTTP/1.1\r\nHost: localhost\r\n{framing}")
                        .as_bytes(),
                )
                .await
                .unwrap();
            writer.write_all(&vec![b'A'; cap + 1]).await.unwrap();
            let mut response = Vec::new();
            reader
                .read_to_end(&mut response)
                .await
                .expect("413 and EOF");
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with("HTTP/1.1 413"), "{response}");
            assert!(response.contains("request body too large"), "{response}");
            for chunk in tail.chunks(8192) {
                writer
                    .write_all(chunk)
                    .await
                    .expect("the refused upload tail must drain without RST");
                tokio::task::yield_now().await;
            }
            if chunked {
                writer.write_all(b"\r\n0\r\n\r\n").await.unwrap();
            }
            writer.shutdown().await.unwrap();
        })
        .await
        .expect("the refusal must not wait for the rest of the upload");
    }
    assert_eq!(
        state.access_log_total().await,
        0,
        "oversized requests never raise a model event"
    );
}

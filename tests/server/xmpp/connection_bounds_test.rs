//! The read deadlines on a real, running XMPP server, driven from a raw socket.
//!
//! **A peer that has connected and said nothing must eventually be let go of.** RFC 6120 §4.2
//! puts the opening stream header on the initiating entity, so a peer that has sent nothing has
//! begun no stream — and nothing else in the process closes that socket, which holds a task, an
//! `AppState` row and one of `MAX_CONNECTIONS` slots pre-authentication. Remove the deadline
//! around `read_half.read(&mut temp_buf)` in `src/server/xmpp/mod.rs` and the first test hangs
//! until its own window expires.
//!
//! **Once the server has answered, the *idle* bound governs.** The second test sends a stream
//! header, gets one back from a static routing rule — so no model is involved — and then goes
//! quiet, with the two bounds set far apart and the wrong way round: a read loop that never
//! switched would hold the connection for 60 seconds and time the assertion out. The switch is
//! `stream_opened`, which is set the moment this server writes its first byte, and that is the
//! honest definition of an established stream on a server whose opening tag *is* the answer to
//! the peer's first event.
//!
//! The values here are overrides, not the defaults. The shipped defaults are 30 seconds and 900
//! (argued beside `FIRST_BYTE_READ_TIMEOUT` and `IDLE_BETWEEN_STANZAS_TIMEOUT`), and a test that
//! asserted them by waiting them out would be the slowest thing in the suite. That is why both
//! are declared startup parameters: what is asserted here is that each parameter is read and
//! applied to the read it names; the *values* are argued where they are declared.
//!
//! No mock backend: the LLM endpoint is a dead port. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features xmpp --test server -- \
//!       xmpp::connection_bounds --test-threads=100

#![cfg(unix)]

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

/// What a client opens a stream with (RFC 6120 §4.2).
const CLIENT_STREAM_HEADER: &[u8] = b"<?xml version='1.0'?>\
<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' \
to='localhost' version='1.0'>";

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
    panic!("XMPP server #{} never bound a port", id.as_u32());
}

/// A model-free XMPP server: an empty instruction really is model-free, where `None` is
/// replaced by a default one and every event would consult the LLM.
async fn start_server(
    state: &AppState,
    startup_params: Option<serde_json::Value>,
    event_handlers: Option<Vec<serde_json::Value>>,
) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "xmpp".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params,
        event_handlers,
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create xmpp server");
    wait_for_port(state, server_id).await
}

#[tokio::test]
async fn a_peer_that_connects_and_opens_no_stream_is_closed_at_the_first_byte_bound() {
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
    // read ends at all, and that it ends on this bound rather than on the 900-second default.
    let read = tokio::time::timeout(
        SHORT_FIRST_BYTE + Duration::from_secs(45),
        peer.read_to_end(&mut sink),
    )
    .await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "a peer that connected and sent no stream header was still holding the socket, the \
         connection task and its AppState entry after {}s — either the first-byte deadline is \
         not applied at all, or `first_byte_timeout_secs` was declared and never read",
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
        "the server wrote {} bytes to a peer that had not opened a stream; RFC 6120 §4.2 puts \
         the first header on the initiating entity",
        sink.len()
    );
}

#[tokio::test]
async fn once_the_stream_is_open_the_idle_bound_governs_not_the_first_byte_one() {
    let state = new_state().await;
    // The two bounds are set far apart and the wrong way round on purpose: if the read loop
    // kept using the first-byte bound after answering, this connection would live 60 seconds
    // and the assertion below would time out.
    let port = start_server(
        &state,
        Some(serde_json::json!({
            "first_byte_timeout_secs": 60,
            "idle_timeout_secs": SHORT_IDLE.as_secs(),
        })),
        Some(vec![serde_json::json!({
            "event_pattern": "xmpp_data_received",
            "handler": {
                "type": "static",
                "actions": [{
                    "type": "send_stream_header",
                    "from": "localhost",
                    "stream_id": "bounds-test"
                }]
            }
        })]),
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(CLIENT_STREAM_HEADER)
        .await
        .expect("write stream header");

    let mut reply = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(20), peer.read(&mut reply))
        .await
        .expect("the static handler did not answer the stream header within 20s")
        .expect("read reply");
    let head = String::from_utf8_lossy(&reply[..n]);
    assert!(
        head.contains("<stream:stream"),
        "the static rule did not answer with a stream header, so `stream_opened` is still false \
         and what follows is not the post-answer state this test is about; got: {head}"
    );

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(45), peer.read_to_end(&mut sink)).await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "an open stream that then went quiet was never closed — `idle_timeout_secs` was \
         declared and is not being read"
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
        "closed after {}s, which is the 60-second first-byte bound rather than the {}s idle one \
         — the read loop never switched bounds",
        elapsed.as_secs(),
        SHORT_IDLE.as_secs()
    );
}

//! The read deadlines on a real, running Redis server, driven from a raw socket.
//!
//! Three claims, and the first two pull in opposite directions.
//!
//! **A peer that has connected and said nothing must eventually be let go of.** Nothing else in
//! the process will close that socket: it holds a task, an `AppState` row and one of
//! `MAX_CONNECTIONS` slots, pre-authentication, so the server has to give up first. Remove the
//! deadline around the read in `src/server/redis/mod.rs` and the first test hangs until its own
//! window expires.
//!
//! **But the default must not be short enough to drop the operator's own peer.** NetGet's Redis
//! client is a bare `TcpStream::connect` that sends nothing until an action says to, and a
//! client created from the dashboard's `[ + redis client ]` is routed `*` -> manual: it connects
//! and waits for a person to type into `[ send message ]`. At the 30 seconds this bound used to
//! carry, the server dropped that peer while the operator was still looking at it — the same
//! defect `src/server/tcp/mod.rs` had. The third test is the regression for it and is
//! deliberately slow: proving a peer survives *past* the old bound means waiting past it.
//!
//! **And the two bounds are different claims**, so the second test drives a command through and
//! then goes quiet, which must be governed by `idle_timeout_secs` rather than by the first-byte
//! one. Its command is answered by a static routing rule, so no model is involved.
//!
//! The values here are overrides, not the defaults. `FIRST_COMMAND_READ_TIMEOUT` is 300
//! seconds — the window a `manual` rule gives a human (`src/state/intercepts.rs`) — and a test
//! that asserted it by waiting it out would be the slowest thing in the suite. That is why both
//! bounds are declared startup parameters: what is asserted here is that each parameter is read
//! and applied to the read it names; the *values* are argued where they are declared.
//!
//! No mock backend: the LLM endpoint is a dead port. These tests assert on deadlines, not on
//! answers. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features redis --test server -- \
//!       redis::connection_bounds --test-threads=100

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

/// How long the third test holds a silent peer against the *default* first-byte bound.
///
/// Past the 30 seconds this bound used to be, by a margin that survives a 100-thread run, and
/// far inside the 300 it now is. A cheaper test cannot exist: the claim is about a number
/// larger than 30, so the wait has to be larger than 30 too.
const PAST_THE_OLD_BOUND: Duration = Duration::from_secs(40);

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
    panic!("Redis server #{} never bound a port", id.as_u32());
}

/// A model-free Redis server: an empty instruction really is model-free, where `None` is
/// replaced by a default one and every event would consult the LLM.
async fn start_server(
    state: &AppState,
    startup_params: Option<serde_json::Value>,
    event_handlers: Option<Vec<serde_json::Value>>,
) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "redis".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params,
        event_handlers,
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create redis server");
    wait_for_port(state, server_id).await
}

#[tokio::test]
async fn a_peer_that_connects_and_sends_no_command_is_closed_at_the_first_byte_bound() {
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
        "a peer that connected and sent no command was still holding the socket, the connection \
         task and its AppState entry after {}s — either the first-byte deadline is not applied \
         at all, or `first_byte_timeout_secs` was declared and never read and the 300-second \
         default is still in force",
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
}

#[tokio::test]
async fn once_a_command_has_been_answered_the_idle_bound_governs_not_the_first_byte_one() {
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
            "event_pattern": "redis_command",
            "handler": {
                "type": "static",
                "actions": [{"type": "redis_simple_string", "value": "PONG"}]
            }
        })]),
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(b"*1\r\n$4\r\nPING\r\n")
        .await
        .expect("write PING");

    let mut reply = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(20), peer.read(&mut reply))
        .await
        .expect("the static handler did not answer PING within 20s")
        .expect("read reply");
    assert_eq!(
        &reply[..n],
        b"+PONG\r\n",
        "the static rule did not answer, so what follows is not the post-answer state this \
         test is about"
    );

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(45), peer.read_to_end(&mut sink)).await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "an answered connection that then went quiet was never closed — `idle_timeout_secs` was \
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

#[tokio::test]
async fn the_default_leaves_a_silent_peer_alone_for_longer_than_a_person_takes() {
    let state = new_state().await;
    // No startup parameters at all: this is the shipped default, which is the whole point.
    let port = start_server(&state, None, None).await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    // A dashboard-created Redis client is exactly this peer: connected, answered with nothing,
    // and silent until a person uses [ send message ].
    let mut sink = Vec::new();
    match tokio::time::timeout(PAST_THE_OLD_BOUND, peer.read_to_end(&mut sink)).await {
        // Still open with nothing to read: the passing case.
        Err(_) => {}
        Ok(Ok(0)) => panic!(
            "the server hung up on a silent peer within {}s. The default first-byte bound was 30 \
             seconds and that is less than a person takes: NetGet's own Redis client opens a \
             socket and sends nothing until someone types into [ send message ], so the operator \
             watched their own client disappear. See FIRST_COMMAND_READ_TIMEOUT in \
             src/server/redis/mod.rs",
            PAST_THE_OLD_BOUND.as_secs()
        ),
        Ok(Ok(n)) => panic!(
            "a Redis server wrote {n} bytes to a peer that had sent no command; it must not \
             speak first"
        ),
        Ok(Err(e)) => panic!("read failed on a connection that should still be open: {e}"),
    }
}

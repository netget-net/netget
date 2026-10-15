//! The connection cap and the relay idle bound on a real, running SOCKS5 proxy, driven from the
//! wire. The idle tests are described where they start, below the cap test.
//!
//! `HANDSHAKE_TIMEOUT_SECS` is 30 seconds and it bounds *one* peer: a stranger who connects and
//! says nothing holds a socket, a task and an `AppState` row for half a minute, and nothing
//! bounded how many such strangers there could be at once. A proxy is the worst case for that
//! in this tree, because an *established* connection holds two sockets — the client's and the
//! one this server opened to the target on its behalf — so an uncapped accept loop lets a
//! stranger spend this process's descriptors two at a time.
//!
//! Three claims:
//!
//! 1. `MAX_CONNECTIONS` peers are admitted.
//! 2. The next one is refused with `05 FF` — RFC 1928 §3's method-selection reply carrying
//!    `NO ACCEPTABLE METHODS` — and then closed. That message is the only thing a SOCKS5 server
//!    may send without having read anything: it echoes nothing from the greeting, so unlike a
//!    reply carrying a request id it cannot be mis-matched against something the peer never
//!    sent, and §3 requires the client to close on `X'FF'`.
//! 3. Closing an admitted connection **frees exactly one slot**. A permit dropped before the
//!    connection ends un-caps the server silently; one never released wedges it shut after
//!    `MAX_CONNECTIONS` peers have ever connected.
//!
//! **How this was proved to fail without the cap**: replace the `accept_bounded` call in
//! `src/server/socks5/mod.rs` with a bare `listener.accept().await` (and drop the permit from
//! the connection task). The over-cap peer is then admitted, so it sends nothing and waits for
//! *our* greeting, and the test fails on the `05 FF` read timing out.
//!
//! The server is model-free: an empty instruction really is model-free, where `None` is
//! replaced by a default one. SOCKS5 is client-speaks-first, so a peer that says nothing
//! provokes no model call. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features socks5 --test server -- socks5::connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/socks5/mod.rs::MAX_CONNECTIONS`. Deliberately duplicated rather than imported:
/// if the constant moves, this test should be re-read rather than silently follow it.
const MAX_CONNECTIONS: usize = 256;

/// `src/server/socks5/mod.rs::CONNECTION_CAP_REFUSAL`, byte for byte: version 5, method 0xFF.
const CONNECTION_CAP_REFUSAL: &[u8] = &[0x05, 0xFF];

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
    panic!("SOCKS5 server #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "socks5".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create socks5 server");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

/// Wait until the accept loop has taken `n` connections out of the listen backlog. A
/// `connect()` succeeds as soon as the kernel queues it, so without this the over-cap peer
/// races the accept loop and the test measures scheduling rather than the cap.
///
/// This server registers the connection at the top of `handle_connection`, before its first
/// read, so the count reflects admitted peers rather than peers that have spoken.
async fn wait_for_admitted(state: &AppState, id: ServerId, n: usize) {
    for _ in 0..600 {
        if let Some(s) = state.get_server(id).await {
            if s.connections.len() >= n {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let seen = state
        .get_server(id)
        .await
        .map(|s| s.connections.len())
        .unwrap_or(0);
    panic!("the server admitted only {seen} of {n} connections");
}

#[tokio::test]
async fn the_connection_past_the_cap_gets_no_acceptable_methods_and_the_slot_comes_back() {
    let state = new_state().await;
    let (server_id, port) = start_server(&state).await;

    let mut held = Vec::with_capacity(MAX_CONNECTIONS);
    for i in 0..MAX_CONNECTIONS {
        held.push(
            TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap_or_else(|e| panic!("connection {i} of the cap failed: {e}")),
        );
    }
    wait_for_admitted(&state, server_id, MAX_CONNECTIONS).await;

    let mut over = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("the listener must still accept — a cap is not a closed socket");
    let mut refusal = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), over.read_to_end(&mut refusal))
        .await
        .expect(
            "the connection past the cap was neither answered nor closed — it was admitted and \
             is waiting for a greeting, so there is no cap",
        )
        .expect("read to EOF");
    assert_eq!(
        refusal, CONNECTION_CAP_REFUSAL,
        "a refused peer must get RFC 1928 §3's method-selection reply with X'FF' and nothing \
         else, then EOF. Got {refusal:02x?}"
    );

    drop(held.pop().expect("one held connection"));

    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect after freeing a slot");
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(300), candidate.read(&mut buf)).await {
            // Neither bytes nor EOF: SOCKS5 is client-speaks-first, so a connection still open
            // and still silent after the window is one that was admitted and is waiting for our
            // greeting. A refused peer gets two bytes and a close immediately instead.
            Err(_) => {
                admitted = true;
                break;
            }
            Ok(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    assert!(
        admitted,
        "the cap never freed its slot after an admitted connection ended — the permit is being \
         held past the life of the connection, which wedges the proxy shut"
    );
}

// ---------------------------------------------------------------------------------------------
// The relay idle bound
// ---------------------------------------------------------------------------------------------
//
// `HANDSHAKE_TIMEOUT_SECS` ends at the CONNECT reply. After it, `RELAY_IDLE_TIMEOUT` (3600s,
// declared as `idle_timeout_secs`) closes a tunnel that has moved nothing **in either
// direction**: a byte read from the client *or* the target resets one shared clock. Four tests:
// silent both ways is closed; traffic only upstream keeps it open; traffic only downstream keeps
// it open; a MITM chunk parked for a human keeps it open.
//
// Removing the `watch_idle` arm from the passthrough relay makes the first hang to its window.
// A per-direction clock would fail the second and third (the silent direction would expire).
// Removing the `busy()` guard from the MITM relay makes the fourth see its tunnel closed.

/// The relay idle bound these tests drive, as `idle_timeout_secs`.
const SHORT_IDLE: Duration = Duration::from_secs(2);

async fn start_proxy(
    state: &AppState,
    startup_params: serde_json::Value,
    event_handlers: Vec<serde_json::Value>,
) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "socks5".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(startup_params),
        event_handlers: Some(event_handlers),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create socks5 server");
    wait_for_port(state, server_id).await
}

/// A loopback target for the tunnel, and the one connection the proxy opens to it.
async fn target() -> (u16, tokio::task::JoinHandle<TcpStream>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind target");
    let port = listener.local_addr().expect("target addr").port();
    let accepted = tokio::spawn(async move { listener.accept().await.expect("accept").0 });
    (port, accepted)
}

/// Greet with no-auth, CONNECT to `127.0.0.1:target_port`, and return the established tunnel.
async fn open_tunnel(proxy_port: u16, target_port: u16) -> TcpStream {
    use tokio::io::AsyncWriteExt;

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect to proxy");
    client.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(20), client.read_exact(&mut method))
        .await
        .expect("no method selection within 20s")
        .expect("read method selection");
    assert_eq!(method, [5, 0], "the proxy did not select no-auth");
    let [hi, lo] = target_port.to_be_bytes();
    client
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, hi, lo])
        .await
        .expect("CONNECT");
    let mut reply = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(20), client.read_exact(&mut reply))
        .await
        .expect("no CONNECT reply within 20s")
        .expect("read CONNECT reply");
    assert_eq!(reply[1], 0, "the proxy refused the CONNECT: {reply:?}");
    client
}

/// Read until EOF and say how long it took, or `None` if it never came inside `window`.
async fn time_to_eof(stream: &mut TcpStream, window: Duration) -> Option<Duration> {
    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    match tokio::time::timeout(window, stream.read_to_end(&mut sink)).await {
        Ok(_) => Some(started.elapsed()),
        Err(_) => None,
    }
}

fn allow_all() -> serde_json::Value {
    serde_json::json!({
        "filter_mode": "allow_all",
        "idle_timeout_secs": SHORT_IDLE.as_secs(),
    })
}

#[tokio::test]
async fn a_tunnel_silent_both_ways_is_closed_at_the_idle_bound() {
    let state = new_state().await;
    let proxy = start_proxy(&state, allow_all(), vec![]).await;
    let (target_port, accepted) = target().await;
    let mut client = open_tunnel(proxy, target_port).await;
    let mut far_end = accepted.await.expect("target accepted");

    let elapsed = time_to_eof(&mut client, Duration::from_secs(45))
        .await
        .expect(
            "a tunnel that moved nothing either way was never closed — the relay has no idle bound",
        );
    assert!(
        elapsed >= SHORT_IDLE / 2 && elapsed < Duration::from_secs(40),
        "closed after {}ms, which is not the declared {}s idle bound",
        elapsed.as_millis(),
        SHORT_IDLE.as_secs()
    );
    assert!(
        time_to_eof(&mut far_end, Duration::from_secs(10))
            .await
            .is_some(),
        "the client's side closed but the proxy kept its socket to the target open"
    );
}

#[tokio::test]
async fn traffic_only_upstream_keeps_the_tunnel_open() {
    use tokio::io::AsyncWriteExt;

    let state = new_state().await;
    let proxy = start_proxy(&state, allow_all(), vec![]).await;
    let (target_port, accepted) = target().await;
    let mut client = open_tunnel(proxy, target_port).await;
    let mut far_end = accepted.await.expect("target accepted");

    // The client sends a byte every 500ms for four idle bounds; the target never answers. A
    // per-direction clock would expire the silent direction and close this tunnel.
    let ticks = (SHORT_IDLE * 4).as_millis() / 500;
    let mut got = [0u8; 1];
    for i in 0..ticks {
        tokio::time::sleep(Duration::from_millis(500)).await;
        client.write_all(&[i as u8]).await.unwrap_or_else(|e| {
            panic!("the proxy closed an upstream-busy tunnel at tick {i}: {e}")
        });
        tokio::time::timeout(Duration::from_secs(10), far_end.read_exact(&mut got))
            .await
            .unwrap_or_else(|_| panic!("byte {i} never reached the target"))
            .unwrap_or_else(|e| panic!("the target side was closed at tick {i}: {e}"));
        assert_eq!(got[0], i as u8, "the tunnel reordered or lost a byte");
    }

    // Now silent both ways: it must go.
    assert!(
        time_to_eof(&mut client, Duration::from_secs(45))
            .await
            .is_some(),
        "the tunnel was not closed once it went silent both ways"
    );
}

#[tokio::test]
async fn traffic_only_downstream_keeps_the_tunnel_open() {
    use tokio::io::AsyncWriteExt;

    let state = new_state().await;
    let proxy = start_proxy(&state, allow_all(), vec![]).await;
    let (target_port, accepted) = target().await;
    let mut client = open_tunnel(proxy, target_port).await;
    let mut far_end = accepted.await.expect("target accepted");

    // The target sends a byte every 500ms for four idle bounds; the client never writes — a
    // download.
    let ticks = (SHORT_IDLE * 4).as_millis() / 500;
    let mut got = [0u8; 1];
    for i in 0..ticks {
        tokio::time::sleep(Duration::from_millis(500)).await;
        far_end.write_all(&[i as u8]).await.unwrap_or_else(|e| {
            panic!("the proxy closed a downstream-busy tunnel at tick {i}: {e}")
        });
        tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut got))
            .await
            .unwrap_or_else(|_| panic!("byte {i} never reached the client"))
            .unwrap_or_else(|e| panic!("the client side was closed at tick {i}: {e}"));
        assert_eq!(got[0], i as u8, "the tunnel reordered or lost a byte");
    }
}

#[tokio::test]
async fn a_mitm_chunk_parked_for_a_human_keeps_the_tunnel_open() {
    use tokio::io::AsyncWriteExt;

    let state = new_state().await;
    let proxy = start_proxy(
        &state,
        serde_json::json!({
            "filter_mode": "allow_all",
            "mitm_by_default": true,
            "idle_timeout_secs": SHORT_IDLE.as_secs(),
        }),
        vec![serde_json::json!({
            "event_pattern": "socks5_data_to_target",
            "handler": {"type": "manual", "timeout_secs": 600}
        })],
    )
    .await;
    let (target_port, accepted) = target().await;
    let mut client = open_tunnel(proxy, target_port).await;
    let mut far_end = accepted.await.expect("target accepted");

    // The chunk is parked for a human; nothing moves either way while it is.
    client.write_all(b"hello").await.expect("write chunk");
    let closed = time_to_eof(&mut client, SHORT_IDLE * 4).await;
    assert!(
        closed.is_none(),
        "the proxy closed a MITM tunnel after {closed:?} while its chunk was parked for a human \
         — the idle clock is running against a decision"
    );
    let mut buf = [0u8; 16];
    let forwarded = tokio::time::timeout(Duration::from_millis(200), far_end.read(&mut buf)).await;
    assert!(
        forwarded.is_err(),
        "the target received {forwarded:?} before the parked chunk was decided"
    );

    // The human answers — four idle bounds after the chunk arrived. The chunk is forwarded, and
    // the answer itself is activity: the tunnel must get a fresh bound from here, not be closed
    // the moment the relay loop comes back and finds the clock long expired. The relay does not
    // poll the clock while the answer is outstanding, so this is the half of the claim that
    // `busy()` exists for.
    let intercept = state
        .list_intercepts()
        .await
        .into_iter()
        .find(|i| i.event_type == "socks5_data_to_target")
        .expect("the chunk is not parked as an intercept");
    state
        .resolve_intercept(
            intercept.id,
            vec![serde_json::json!({"type": "forward_socks5_data"})],
        )
        .await
        .expect("answer the parked chunk");
    let mut got = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(10), far_end.read_exact(&mut got))
        .await
        .expect("the answered chunk never reached the target")
        .expect("read the forwarded chunk");
    assert_eq!(
        &got, b"hello",
        "the answered chunk was not forwarded intact"
    );
    let after_answer = time_to_eof(&mut client, SHORT_IDLE / 2).await;
    assert!(
        after_answer.is_none(),
        "the tunnel was closed {after_answer:?} after its parked chunk was answered — the answer \
         did not count as activity, so the clock that ran out during the park closed it at once"
    );
}

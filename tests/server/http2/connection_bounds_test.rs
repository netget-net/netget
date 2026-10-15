//! HTTP/2's connection bounds, driven from the wire.
//!
//! `src/server/http2/h2_server.rs` declares four numbers and argues each beside itself:
//! `FIRST_BYTE_READ_TIMEOUT` (30s), `HANDSHAKE_TIMEOUT` (30s), `IDLE_BETWEEN_REQUESTS_TIMEOUT`
//! (300s) and `MAX_CONNECTIONS` (128). The two read bounds are declared startup parameters
//! (`first_byte_timeout_secs`, `idle_timeout_secs`), so these tests set them short; what is
//! asserted is that each is applied to the state it names, not the default values.
//!
//! Four claims, from the peer's side:
//!
//! * **A peer that connects and says nothing is closed at the first-byte bound.** A `peek` with
//!   a deadline before rustls or `h2` sees the socket. Remove it and the first test hangs until
//!   its own window expires: nothing else in the process closes that socket.
//! * **An established connection that carries no request is closed at the idle bound, with a
//!   GOAWAY.** An `h2` client completes the preface and one request, then goes quiet; the
//!   connection must end on the short idle bound and not on the long first-byte one. Remove the
//!   `watch_idle` arm and it lives forever.
//! * **A connection whose answer is parked for a human is not closed**, however far past the
//!   idle bound. Every stream's task holds `ConnectionActivity` busy, and this is what stops the
//!   second claim being satisfiable by a server that hangs up on everybody. Remove the `busy()`
//!   guard and the connection is closed under the parked request.
//! * **The connection past `MAX_CONNECTIONS` is refused with an HTTP/1.1 503, and closing one
//!   admitted connection frees exactly one slot.**
//!
//! No mock backend: the LLM endpoint is a dead port and every rule is static or manual. Loopback
//! only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features http2 --test server -- \
//!       http2::connection_bounds --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::server::ConnectionStatus;
use netget::state::ServerId;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The first-byte bound the first test drives.
const SHORT_FIRST_BYTE: Duration = Duration::from_secs(4);

/// The idle bound the second and third tests drive.
const SHORT_IDLE: Duration = Duration::from_secs(3);

/// `MAX_CONNECTIONS` exactly as `h2_server.rs` declares it. Copied on purpose: if it moves,
/// this file should be re-read rather than silently follow.
const MAX_CONNECTIONS: usize = 128;

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
    panic!("HTTP/2 server #{} never bound a port", id.as_u32());
}

/// A model-free HTTP/2 server: an empty instruction really is model-free, where `None` is
/// replaced by a default one and every event would consult the LLM.
async fn start_server(
    state: &AppState,
    startup_params: serde_json::Value,
    event_handlers: Vec<serde_json::Value>,
) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "http2".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(startup_params),
        event_handlers: Some(event_handlers),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create http2 server");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

async fn live_connections(state: &AppState, id: ServerId) -> usize {
    state
        .get_server(id)
        .await
        .map(|s| {
            s.connections
                .values()
                .filter(|c| !matches!(c.status, ConnectionStatus::Closed))
                .count()
        })
        .unwrap_or(0)
}

/// Complete the HTTP/2 preface over a fresh socket and send one GET. Returns the request handle
/// (kept alive by the caller so the client never closes the connection itself), the response
/// future, and the task driving the client connection — which ends when the server closes it.
async fn h2_get(
    port: u16,
) -> (
    h2::client::SendRequest<bytes::Bytes>,
    h2::client::ResponseFuture,
    tokio::task::JoinHandle<Result<(), h2::Error>>,
) {
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (client, connection) = h2::client::handshake(tcp)
        .await
        .expect("h2 client handshake");
    let driver = tokio::spawn(connection);
    let mut client = client.ready().await.expect("h2 client ready");
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:{port}/"))
        .body(())
        .expect("build request");
    let (response, _) = client.send_request(request, true).expect("send request");
    (client, response, driver)
}

#[tokio::test]
async fn a_peer_that_connects_and_says_nothing_is_closed_at_the_first_byte_bound() {
    let state = new_state().await;
    let (_, port) = start_server(
        &state,
        serde_json::json!({ "first_byte_timeout_secs": SHORT_FIRST_BYTE.as_secs() }),
        vec![],
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    // Generous against the declared bound so an ordinary scheduling delay under
    // --test-threads=100 is not mistaken for a missing deadline.
    let read = tokio::time::timeout(
        SHORT_FIRST_BYTE + Duration::from_secs(45),
        peer.read_to_end(&mut sink),
    )
    .await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "a peer that connected and sent no preface was still holding the socket after {}s — \
         the first-byte bound is not applied, or `first_byte_timeout_secs` is declared and never \
         read",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        elapsed >= SHORT_FIRST_BYTE / 2,
        "closed after only {}ms, which is not the declared {}s bound — something else is tearing \
         the connection down, and this test would then pass without the bound existing",
        elapsed.as_millis(),
        SHORT_FIRST_BYTE.as_secs()
    );
    assert!(
        sink.is_empty(),
        "the server wrote {} bytes to a peer that had sent nothing; HTTP/2 is client-speaks-first",
        sink.len()
    );
}

#[tokio::test]
async fn an_answered_connection_that_goes_quiet_is_closed_at_the_idle_bound() {
    let state = new_state().await;
    // The two bounds are set far apart and the wrong way round on purpose: if the first-byte
    // bound governed the whole connection, this one would live 60 seconds and the assertion
    // below would time out.
    let (_, port) = start_server(
        &state,
        serde_json::json!({
            "first_byte_timeout_secs": 60,
            "idle_timeout_secs": SHORT_IDLE.as_secs(),
        }),
        vec![serde_json::json!({
            "event_pattern": "http2_request",
            "handler": {
                "type": "static",
                "actions": [{"type": "send_http2_response", "status": 200, "body": "ok"}]
            }
        })],
    )
    .await;

    let (_client, response, driver) = h2_get(port).await;
    let response = tokio::time::timeout(Duration::from_secs(20), response)
        .await
        .expect("the static rule did not answer within 20s")
        .expect("response");
    assert_eq!(
        response.status(),
        200,
        "the static rule did not answer 200, so what follows is not the answered connection \
         this test is about"
    );

    let started = std::time::Instant::now();
    let ended = tokio::time::timeout(Duration::from_secs(45), driver).await;
    let elapsed = started.elapsed();
    assert!(
        ended.is_ok(),
        "an answered HTTP/2 connection that then carried no request was never closed — \
         `idle_timeout_secs` is not read, or nothing watches ConnectionActivity"
    );
    assert!(
        elapsed >= SHORT_IDLE / 2,
        "closed after only {}ms, below the declared {}s idle bound",
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

#[tokio::test]
async fn a_connection_whose_answer_is_parked_for_a_human_is_not_closed() {
    let state = new_state().await;
    let (server_id, port) = start_server(
        &state,
        serde_json::json!({
            "first_byte_timeout_secs": SHORT_IDLE.as_secs(),
            "idle_timeout_secs": SHORT_IDLE.as_secs(),
        }),
        vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {"type": "manual", "timeout_secs": 600}
        })],
    )
    .await;

    let (_client, response, driver) = h2_get(port).await;

    // The request is parked for a human, so the connection is silent on the wire and busy on
    // the server. Wait well past both bounds, but well inside the 600-second window the human
    // has to answer in.
    tokio::time::sleep(SHORT_IDLE * 4 + Duration::from_secs(8)).await;

    assert!(
        !driver.is_finished(),
        "the server closed an HTTP/2 connection whose request was parked for a human — the idle \
         watchdog is not honouring ConnectionActivity::busy"
    );
    assert_eq!(
        live_connections(&state, server_id).await,
        1,
        "the server no longer has a live connection for a peer whose answer is parked"
    );
    drop(response);
}

#[tokio::test]
async fn the_connection_past_the_cap_is_refused_with_a_503_and_a_slot_comes_back() {
    let state = new_state().await;
    let (server_id, port) = start_server(
        &state,
        serde_json::json!({ "first_byte_timeout_secs": 120 }),
        vec![],
    )
    .await;

    let mut admitted = Vec::with_capacity(MAX_CONNECTIONS);
    for _ in 0..MAX_CONNECTIONS {
        admitted.push(
            TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect under the cap"),
        );
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while live_connections(&state, server_id).await < MAX_CONNECTIONS {
        assert!(
            std::time::Instant::now() < deadline,
            "only {} of {MAX_CONNECTIONS} connections were admitted",
            live_connections(&state, server_id).await
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut refused = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect over the cap");
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), refused.read_to_end(&mut reply))
        .await
        .expect("the connection over the cap was neither refused nor closed within 20s")
        .expect("read refusal");
    let reply = String::from_utf8_lossy(&reply);
    assert!(
        reply.starts_with("HTTP/1.1 503 Service Unavailable\r\n") && reply.contains("Retry-After"),
        "the peer over the cap was not told it may retry; got: {reply:?}"
    );

    // Close one admitted connection: its task sees EOF at the peek, ends, and drops its permit.
    drop(admitted.pop());
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while live_connections(&state, server_id).await >= MAX_CONNECTIONS {
        assert!(
            std::time::Instant::now() < deadline,
            "closing an admitted connection never released its slot"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The row is marked closed a moment before the task ends and drops its permit, so a refusal
    // right at this point is the slot not yet being free rather than a leak: retry until the
    // deadline, and only a connection that is admitted — left waiting for its preface — ends it.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let _next = loop {
        let mut next = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect into the freed slot");
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_secs(2), next.read(&mut buf)).await {
            Err(_) => break next,
            Ok(read) => assert!(
                std::time::Instant::now() < deadline,
                "the connection into the freed slot was answered or closed ({read:?}) instead \
                 of admitted and left waiting for its preface"
            ),
        }
    };

    // And exactly one slot: the one after it is refused again.
    let mut over = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect over the cap again");
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), over.read_to_end(&mut reply))
        .await
        .expect("the second connection over the cap was not refused within 20s")
        .expect("read second refusal");
    assert!(
        String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 503"),
        "closing one connection freed more than one slot"
    );
}

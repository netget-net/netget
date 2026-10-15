//! Every bound SMB declares, driven from the wire, each at the bound and one past it.
//!
//! | Bound | Governs | Test |
//! |---|---|---|
//! | `FIRST_MESSAGE_READ_TIMEOUT` (30s, `first_byte_timeout_secs`) | silence before any admitted session | `the_read_deadlines_follow_their_startup_parameters`, `the_default_first_message_deadline_is_thirty_seconds` |
//! | `IDLE_BETWEEN_MESSAGES_TIMEOUT` (900s, `idle_timeout_secs`) | silence once a session is admitted | `the_read_deadlines_follow_their_startup_parameters` |
//! | `BODY_READ_TIMEOUT` (30s, `body_timeout_secs`) | a stall inside a frame whose length has been announced | `the_read_deadlines_follow_their_startup_parameters` |
//! | `MAX_CONNECTIONS` (256) | concurrent peers | `the_connection_cap_refuses_silently_and_every_close_returns_its_slot` |
//! | `MAX_SESSIONS_PER_CONNECTION` (16) | sessions on one connection, mid-NTLMSSP ones included | `sessions_opened_before_anyone_is_asked_are_capped_per_connection` |
//! | `MAX_TREES_PER_CONNECTION` (64) | tree connects on one connection | `tree_connects_are_capped_per_connection_and_a_disconnect_returns_a_slot` |
//! | `MAX_OPEN_FILES_PER_CONNECTION` (1024) | open handles on one connection | `open_handles_are_capped_per_connection_and_a_close_returns_a_slot` |
//! | `MAX_READ_SIZE` (1 MiB, `MaxReadSize`) | a READ's requested length | `read_and_output_buffer_lengths_past_the_negotiated_maxima_are_refused` |
//! | `MAX_TRANSACT_SIZE` (1 MiB, `MaxTransactSize`) | a QUERY_INFO or QUERY_DIRECTORY output buffer | `read_and_output_buffer_lengths_past_the_negotiated_maxima_are_refused` |
//! | `MAX_COMPOUND_REQUESTS` (32) | requests acted on per compound frame | `a_compound_past_the_request_cap_is_answered_without_being_acted_on` |
//! | `MAX_CREDIT_GRANT` (64) | **outbound**: credits one response grants | `credits_and_the_netbios_session_layer_are_bounded` |
//! | RFC 1002 session request, at most 256 bytes of names | the one frame read before SMB2 | `credits_and_the_netbios_session_layer_are_bounded` |
//! | `MAX_RESPONSE_FRAME_BYTES` (16 MiB - 1 - 2 MiB) | **outbound**: the bytes of one compound reply | `a_compound_whose_replies_would_overflow_a_frame_is_still_answered_in_one` |
//!
//! `MAX_MESSAGE_BYTES` and `MAX_WRITE_SIZE` are in `inbound_limit_test.rs`.
//!
//! Every bound here but the last is **inbound** — each counts or times something the peer
//! does — and each of those refusals is decided before the model: the tests that count model
//! calls assert the refused request cost none. `MAX_RESPONSE_FRAME_BYTES` governs what the
//! server *writes*: a Direct TCP header cannot announce more than 2^24 - 1 bytes.
//!
//! **Verified by removal**, one bound at a time, each restored afterwards:
//!
//! - `timeout(header_timeout, …)` around the transport-header read replaced by the bare read:
//!   the silent peer is never closed and the deadline test fails at its 20s window.
//! - the idle deadline collapsed onto the first-message one (`ctx.deadlines.first_message` in
//!   both arms): the admitted peer is closed at 1s and the "quiet for at least 4s" assertion
//!   fails.
//! - `read_body_exact`'s timeout removed: the stalled frame is never closed.
//! - the session-cap check in `session_cap_refusal` removed: the 17th NEGOTIATE leg is
//!   answered `STATUS_MORE_PROCESSING_REQUIRED`.
//! - the tree-cap check removed: the 65th TREE_CONNECT succeeds.
//! - the open-handle check removed: the 1025th CREATE succeeds.
//! - the MaxReadSize check removed (the length clamped instead, as it once was): the over-size
//!   READ reaches the model.
//! - each MaxTransactSize check removed: its over-size request reaches the model.
//! - the credit clamp removed (the request's CreditRequest granted as asked): 1000 is granted.
//! - the session request's 256-byte bound removed: the 257-byte request is answered.
//! - the compound cap removed: all 40 CREATEs reach the model.
//! - the response budget removed: `wire::frame`'s 24-bit assertion panics the connection task
//!   and the 17-READ compound gets no reply at all.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features smb --test server -- smb::bounds --test-threads=100


use std::time::{Duration, Instant};

use netget::cli::management::ServerForm;
use netget::server::smb::{
    MAX_COMPOUND_REQUESTS, MAX_CONNECTIONS, MAX_OPEN_FILES_PER_CONNECTION, MAX_READ_SIZE,
    MAX_RESPONSE_FRAME_BYTES, MAX_SESSIONS_PER_CONNECTION, MAX_TRANSACT_SIZE,
    MAX_TREES_PER_CONNECTION,
};
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::wire_util::{self as w, nbss, read_frame};
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;

/// A running SMB server whose model is a counting mock that admits every login.
struct Server {
    state: AppState,
    mock: MockOllamaServer,
    server_id: ServerId,
    port: u16,
}

impl Server {
    /// Start with `startup_params` and, optionally, `event_handlers` answering in front of the
    /// model.
    async fn start(
        startup_params: Option<serde_json::Value>,
        event_handlers: Option<Vec<serde_json::Value>>,
    ) -> Self {
        let mock = MockOllamaServer::start(
            MockLlmBuilder::new()
                .on_event("smb_operation")
                .and_event_data_contains("operation", "session_setup")
                .respond_with_actions(serde_json::json!([
                    {"type": "smb_auth_success", "username": "guest"}
                ]))
                .expect_at_least(0)
                .and()
                .on_any()
                .respond_with_actions(serde_json::json!([]))
                .expect_at_least(0)
                .build(),
        )
        .await
        .expect("mock ollama");
        let state = AppState::new_with_options(false, mock.base_url());
        state
            .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
            .await;
        let (tx, _rx) = mpsc::unbounded_channel();
        let server_id = ServerForm {
            protocol: "smb".to_string(),
            port: Some(0),
            host: Some("127.0.0.1".to_string()),
            instruction: Some("Admit every guest.".to_string()),
            startup_params,
            event_handlers,
            ..Default::default()
        }
        .create(&state, tx)
        .await
        .expect("create smb server");
        for _ in 0..300 {
            if let Some(s) = state.get_server(server_id).await {
                if let Some(addr) = s.local_addr {
                    return Self {
                        state,
                        mock,
                        server_id,
                        port: addr.port(),
                    };
                }
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("smb never bound a port");
    }

    async fn connect(&self) -> TcpStream {
        TcpStream::connect(("127.0.0.1", self.port))
            .await
            .expect("connect")
    }

    /// The model-call count once it has stopped moving.
    async fn settled_calls(&self) -> usize {
        let ceiling = Instant::now() + Duration::from_secs(10);
        let mut last = self.mock.call_count().await;
        let mut stable_since = Instant::now();
        while Instant::now() < ceiling {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let now = self.mock.call_count().await;
            if now != last {
                last = now;
                stable_since = Instant::now();
            } else if stable_since.elapsed() >= Duration::from_millis(600) {
                break;
            }
        }
        last
    }

    async fn stop(self) {
        let _ = self.state.remove_server(self.server_id).await;
    }
}

/// Send one framed request and read the one frame answering it.
async fn call(stream: &mut TcpStream, message: Vec<u8>) -> Vec<u8> {
    stream.write_all(&nbss(message)).await.expect("write");
    tokio::time::timeout(Duration::from_secs(30), read_frame(stream))
        .await
        .expect("no reply within 30s")
        .expect("read reply")
}

/// Read until the server closes, returning what it wrote first. Fails if it has not closed
/// within `secs`.
async fn read_until_closed(stream: &mut TcpStream, secs: u64, what: &str) -> Vec<u8> {
    let mut sink = Vec::new();
    match tokio::time::timeout(Duration::from_secs(secs), stream.read_to_end(&mut sink)).await {
        Ok(_) => sink,
        Err(_) => panic!("{what}: the server was still holding the connection after {secs}s"),
    }
}

/// NEGOTIATE then a one-step guest SESSION_SETUP (session 1). Costs one model call.
async fn log_in(stream: &mut TcpStream) {
    let neg = call(stream, w::negotiate(0)).await;
    assert_eq!(w::status(&neg), w::STATUS_SUCCESS, "NEGOTIATE");
    let setup = call(stream, w::session_setup(1)).await;
    assert_eq!(w::status(&setup), w::STATUS_SUCCESS, "SESSION_SETUP");
    assert_eq!(w::session_id(&setup), 1);
}

// ---------------------------------------------------------------------------------------------
// Read deadlines
// ---------------------------------------------------------------------------------------------

/// All three deadlines follow their startup parameters, which is the only way to test the idle
/// one: its default is fifteen minutes. Each is set to a different number so that one collapsing
/// onto another shows.
#[tokio::test]
async fn the_read_deadlines_follow_their_startup_parameters() {
    let server = Server::start(
        Some(serde_json::json!({
            "first_byte_timeout_secs": 1,
            "idle_timeout_secs": 5,
            "body_timeout_secs": 3,
        })),
        None,
    )
    .await;

    // Before any session: a peer that says nothing is closed at the first-message bound, and
    // closed without a byte — there is no request whose MessageId a reply could echo.
    let mut silent = server.connect().await;
    let started = Instant::now();
    let sink = read_until_closed(&mut silent, 20, "a silent peer").await;
    assert!(
        sink.is_empty(),
        "an idle close writes nothing; got {sink:02x?}"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(800),
        "closed after {:?}, before the configured 1s first-message bound",
        started.elapsed()
    );

    // Mid-frame: the transport header has announced 100 bytes and only 10 arrive. The body
    // bound (3s) governs, not the first-message one (1s).
    let mut stalled = server.connect().await;
    stalled.write_all(&w::nbss_header(100)).await.unwrap();
    stalled.write_all(&[0u8; 10]).await.unwrap();
    let started = Instant::now();
    let sink = read_until_closed(&mut stalled, 20, "a peer stalled mid-frame").await;
    assert!(
        sink.is_empty(),
        "a stalled frame gets no reply; got {sink:02x?}"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(2500),
        "a peer stalled inside an announced frame was closed after {:?} — that is not the \
         configured 3s body bound",
        started.elapsed()
    );

    // After a session is admitted: the idle bound (5s) governs, so the peer outlives the
    // first-message bound several times over and is then closed.
    let mut talker = server.connect().await;
    log_in(&mut talker).await;
    let answered = Instant::now();
    let sink = read_until_closed(&mut talker, 30, "a peer gone quiet in a session").await;
    let quiet_for = answered.elapsed();
    assert!(
        sink.is_empty(),
        "an idle close writes nothing; got {sink:02x?}"
    );
    assert!(
        quiet_for >= Duration::from_secs(4),
        "a peer holding an admitted session was closed after {quiet_for:?} of silence — that \
         is the first-message bound (1s), not the idle bound (5s)"
    );

    // A zero deadline would close every connection before it could speak: refused at startup.
    let (tx, _rx) = mpsc::unbounded_channel();
    let refused = ServerForm {
        protocol: "smb".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        instruction: Some(String::new()),
        startup_params: Some(serde_json::json!({ "idle_timeout_secs": 0 })),
        ..Default::default()
    }
    .create(&server.state, tx)
    .await;
    let failed = match refused {
        Err(e) => Some(e.to_string()),
        Ok(id) => {
            // Startup errors surface as the instance's status rather than as `Err`.
            let mut error = None;
            for _ in 0..100 {
                if let Some(s) = server.state.get_server(id).await {
                    if let netget::state::server::ServerStatus::Error(e) = s.status {
                        error = Some(e);
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            error
        }
    };
    let failed = failed.expect("idle_timeout_secs 0 must be refused");
    assert!(
        failed.contains("idle_timeout_secs"),
        "the refusal must name the parameter: {failed}"
    );

    server.stop().await;
}

/// The default first-message bound, with no startup parameter: the one default short enough
/// to wait out, which is what shows the defaults are actually wired in.
#[tokio::test]
async fn the_default_first_message_deadline_is_thirty_seconds() {
    let server = Server::start(None, None).await;
    let mut silent = server.connect().await;
    let started = Instant::now();
    let sink = read_until_closed(&mut silent, 75, "a silent peer at the default bound").await;
    assert!(
        sink.is_empty(),
        "an idle close writes nothing; got {sink:02x?}"
    );
    assert!(
        started.elapsed() >= Duration::from_secs(25),
        "closed after {:?}; the declared default is 30s",
        started.elapsed()
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------------------------
// MAX_CONNECTIONS
// ---------------------------------------------------------------------------------------------

async fn wait_for_admitted(server: &Server, n: usize) {
    for _ in 0..600 {
        if let Some(s) = server.state.get_server(server.server_id).await {
            let live = s
                .connections
                .values()
                .filter(|c| matches!(c.status, netget::state::server::ConnectionStatus::Active))
                .count();
            if live >= n {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the server never admitted {n} connections");
}

/// Connect until one is admitted, and return it held open. SMB2 is client-speaks-first, so an
/// admitted connection is one still open and silent after a short window; a refused one reads
/// EOF at once.
async fn connect_until_admitted(port: u16, what: &str) -> TcpStream {
    for _ in 0..100 {
        let mut candidate = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let mut buf = [0u8; 16];
        match tokio::time::timeout(Duration::from_millis(300), candidate.read(&mut buf)).await {
            Err(_) => return candidate,
            Ok(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    panic!("{what}: no connection was admitted — the slot never came back")
}

/// 256 peers are admitted, the 257th is closed without a byte, and a slot comes back both when
/// a peer hangs up **and** when the server closes a peer that keeps its own end open — the
/// modbus defect, where a server-side close left the permit held until the peer let go.
#[tokio::test]
async fn the_connection_cap_refuses_silently_and_every_close_returns_its_slot() {
    // Held peers say nothing; keep them inside the first-message bound for the whole test.
    let server = Server::start(
        Some(serde_json::json!({ "first_byte_timeout_secs": 300 })),
        None,
    )
    .await;

    let mut held = Vec::with_capacity(MAX_CONNECTIONS);
    for i in 0..MAX_CONNECTIONS {
        held.push(
            TcpStream::connect(("127.0.0.1", server.port))
                .await
                .unwrap_or_else(|e| panic!("connection {i} of the cap failed: {e}")),
        );
    }
    wait_for_admitted(&server, MAX_CONNECTIONS).await;

    let mut over = server.connect().await;
    let refusal = read_until_closed(&mut over, 20, "the 257th peer").await;
    assert!(
        refusal.is_empty(),
        "every SMB2 response echoes a MessageId, TreeId and SessionId from a request, and this \
         peer has sent none; the refusal must be a plain close. Got {refusal:02x?}"
    );

    // A held peer sends something that is not a Direct TCP session message, and then keeps
    // its end of the socket open. The server closes it; its slot must come back regardless.
    let mut bad = held.remove(0);
    bad.write_all(&[0x01, 0x00, 0x00, 0x04])
        .await
        .expect("write");
    let reply = read_until_closed(&mut bad, 15, "a framing error").await;
    assert!(
        reply.is_empty(),
        "a framing error has no answer; got {reply:02x?}"
    );
    // `bad` stays in scope: its end of the socket is still open.
    held.push(connect_until_admitted(server.port, "after a server-side close").await);

    // And the ordinary case: a peer hangs up.
    drop(held.pop());
    held.push(connect_until_admitted(server.port, "after a peer hung up").await);

    drop(bad);
    drop(held);
    server.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Per-connection tables
// ---------------------------------------------------------------------------------------------

/// The first leg of an NTLMSSP exchange opens a session before anyone is asked. Sixteen legs
/// open sixteen sessions; the seventeenth is refused. A leg that restarts an exchange already
/// in progress reuses its session, a one-step login at the cap is refused before the model, and
/// a failed exchange returns its slot. None of it costs a model call.
#[tokio::test]
async fn sessions_opened_before_anyone_is_asked_are_capped_per_connection() {
    let server = Server::start(None, None).await;
    let mut s = server.connect().await;
    let neg = call(&mut s, w::negotiate(0)).await;
    assert_eq!(w::status(&neg), w::STATUS_SUCCESS);
    let before = server.settled_calls().await;

    let mut mid = 1u64;
    let mut sessions = Vec::new();
    for i in 0..MAX_SESSIONS_PER_CONNECTION {
        let reply = call(
            &mut s,
            w::session_setup_with(mid, 0, &w::ntlmssp_negotiate()),
        )
        .await;
        mid += 1;
        assert_eq!(
            w::status(&reply),
            w::STATUS_MORE_PROCESSING_REQUIRED,
            "NEGOTIATE leg {i} of the cap must be answered with a CHALLENGE"
        );
        let sid = w::session_id(&reply);
        assert!(
            sid != 0 && !sessions.contains(&sid),
            "leg {i} opened session {sid}, already open or zero"
        );
        sessions.push(sid);
    }

    // One past the bound.
    let over = call(
        &mut s,
        w::session_setup_with(mid, 0, &w::ntlmssp_negotiate()),
    )
    .await;
    mid += 1;
    assert_eq!(
        w::status(&over),
        w::STATUS_INSUFFICIENT_RESOURCES,
        "NEGOTIATE leg {} opened a session past MAX_SESSIONS_PER_CONNECTION ({})",
        MAX_SESSIONS_PER_CONNECTION + 1,
        MAX_SESSIONS_PER_CONNECTION
    );

    // Restarting an exchange in progress is not a new session, so it is not refused.
    let restart = call(
        &mut s,
        w::session_setup_with(mid, sessions[0], &w::ntlmssp_negotiate()),
    )
    .await;
    mid += 1;
    assert_eq!(
        (w::status(&restart), w::session_id(&restart)),
        (w::STATUS_MORE_PROCESSING_REQUIRED, sessions[0]),
        "a NEGOTIATE leg naming a session mid-exchange restarts that exchange"
    );

    // A one-step guest login at the cap would allocate a session if admitted: refused before
    // the model is asked.
    let guest = call(&mut s, w::session_setup(mid)).await;
    mid += 1;
    assert_eq!(w::status(&guest), w::STATUS_INSUFFICIENT_RESOURCES);

    // A failed exchange forgets its session, and the slot comes back.
    let failed = call(
        &mut s,
        w::session_setup_with(mid, sessions[0], &w::ntlmssp_truncated_authenticate()),
    )
    .await;
    mid += 1;
    assert_eq!(w::status(&failed), w::STATUS_INVALID_PARAMETER);
    let again = call(
        &mut s,
        w::session_setup_with(mid, 0, &w::ntlmssp_negotiate()),
    )
    .await;
    assert_eq!(
        w::status(&again),
        w::STATUS_MORE_PROCESSING_REQUIRED,
        "the slot a failed exchange held must come back"
    );

    let after = server.settled_calls().await;
    assert_eq!(
        after - before,
        0,
        "nothing in this test is a decision for the model, yet it cost {} call(s)",
        after - before
    );

    // A fresh connection has a table of its own.
    let mut fresh = server.connect().await;
    call(&mut fresh, w::negotiate(0)).await;
    let first = call(
        &mut fresh,
        w::session_setup_with(1, 0, &w::ntlmssp_negotiate()),
    )
    .await;
    assert_eq!(w::status(&first), w::STATUS_MORE_PROCESSING_REQUIRED);

    server.stop().await;
}

/// TREE_CONNECT asks no one, so the tree table is bounded by this cap alone.
#[tokio::test]
async fn tree_connects_are_capped_per_connection_and_a_disconnect_returns_a_slot() {
    let server = Server::start(None, None).await;
    let mut s = server.connect().await;
    log_in(&mut s).await;
    let before = server.settled_calls().await;

    let mut mid = 2u64;
    let mut trees = Vec::new();
    for i in 0..MAX_TREES_PER_CONNECTION {
        let reply = call(
            &mut s,
            w::tree_connect(mid, 1, &format!(r"\\127.0.0.1\share{i}")),
        )
        .await;
        mid += 1;
        assert_eq!(w::status(&reply), w::STATUS_SUCCESS, "TREE_CONNECT {i}");
        trees.push(w::tree_id(&reply));
    }
    let over = call(&mut s, w::tree_connect(mid, 1, r"\\127.0.0.1\one_too_many")).await;
    mid += 1;
    assert_eq!(
        w::status(&over),
        w::STATUS_INSUFFICIENT_RESOURCES,
        "TREE_CONNECT {} succeeded past MAX_TREES_PER_CONNECTION ({})",
        MAX_TREES_PER_CONNECTION + 1,
        MAX_TREES_PER_CONNECTION
    );

    let gone = call(&mut s, w::simple(w::TREE_DISCONNECT, mid, trees[0], 1)).await;
    mid += 1;
    assert_eq!(w::status(&gone), w::STATUS_SUCCESS, "TREE_DISCONNECT");
    let back = call(&mut s, w::tree_connect(mid, 1, r"\\127.0.0.1\again")).await;
    mid += 1;
    assert_eq!(
        w::status(&back),
        w::STATUS_SUCCESS,
        "the slot a TREE_DISCONNECT freed must come back"
    );

    // LOGOFF drops every tree the session held.
    let logoff = call(&mut s, w::simple(w::LOGOFF, mid, 0, 1)).await;
    mid += 1;
    assert_eq!(w::status(&logoff), w::STATUS_SUCCESS, "LOGOFF");
    let relog = call(&mut s, w::session_setup(mid)).await;
    mid += 1;
    assert_eq!(w::status(&relog), w::STATUS_SUCCESS);
    let sid = w::session_id(&relog);
    for i in 0..MAX_TREES_PER_CONNECTION {
        let reply = call(
            &mut s,
            w::tree_connect(mid, sid, &format!(r"\\127.0.0.1\s{i}")),
        )
        .await;
        mid += 1;
        assert_eq!(
            w::status(&reply),
            w::STATUS_SUCCESS,
            "after LOGOFF every tree slot is free; TREE_CONNECT {i} was refused"
        );
    }

    let after = server.settled_calls().await;
    assert_eq!(
        after - before,
        1,
        "the second login is the only model decision after the first; {} calls",
        after - before
    );
    server.stop().await;
}

/// A static handler answering every CREATE is the case this bound exists for: no model stands
/// in front of the handle table, so without it a client that opens and never closes grows it
/// until the connection ends.
#[tokio::test]
async fn open_handles_are_capped_per_connection_and_a_close_returns_a_slot() {
    let server = Server::start(
        None,
        Some(vec![serde_json::json!({
            "event_pattern": "smb_operation",
            "handler": {
                "type": "static",
                "actions": [
                    {"type": "smb_auth_success", "username": "guest"},
                    {"type": "smb_create_file", "path": "/f", "size": 0}
                ]
            }
        })]),
    )
    .await;
    let mut s = server.connect().await;
    log_in(&mut s).await;
    let tree = call(&mut s, w::tree_connect(2, 1, r"\\127.0.0.1\share")).await;
    assert_eq!(w::status(&tree), w::STATUS_SUCCESS);

    // Pipelined: every CREATE written, then every reply read, in order.
    let first_mid = 3u64;
    let mut batch = Vec::new();
    for i in 0..MAX_OPEN_FILES_PER_CONNECTION as u64 {
        batch.extend(nbss(w::create(first_mid + i, 1, 1, &format!("f{i}"))));
    }
    s.write_all(&batch).await.expect("write CREATEs");
    let mut handles = Vec::new();
    for i in 0..MAX_OPEN_FILES_PER_CONNECTION as u64 {
        let reply = tokio::time::timeout(Duration::from_secs(60), read_frame(&mut s))
            .await
            .expect("CREATE reply")
            .expect("read");
        assert_eq!(
            (w::message_id(&reply), w::status(&reply)),
            (first_mid + i, w::STATUS_SUCCESS),
            "CREATE {i} of the cap"
        );
        handles.push(w::create_file_id(&reply));
    }
    let mut mid = first_mid + MAX_OPEN_FILES_PER_CONNECTION as u64;
    let over = call(&mut s, w::create(mid, 1, 1, "one_too_many")).await;
    mid += 1;
    assert_eq!(
        w::status(&over),
        w::STATUS_TOO_MANY_OPENED_FILES,
        "CREATE {} opened a handle past MAX_OPEN_FILES_PER_CONNECTION ({})",
        MAX_OPEN_FILES_PER_CONNECTION + 1,
        MAX_OPEN_FILES_PER_CONNECTION
    );

    let closed = call(&mut s, w::close(mid, 1, 1, &handles[0])).await;
    mid += 1;
    assert_eq!(w::status(&closed), w::STATUS_SUCCESS, "CLOSE");
    let back = call(&mut s, w::create(mid, 1, 1, "again")).await;
    assert_eq!(
        w::status(&back),
        w::STATUS_SUCCESS,
        "the slot a CLOSE freed must come back"
    );

    assert_eq!(
        server.settled_calls().await,
        0,
        "every answer here came from the static handler"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Compound frames
// ---------------------------------------------------------------------------------------------

/// One frame can link thousands of requests. The first `MAX_COMPOUND_REQUESTS` are acted on;
/// every one after is answered to its own MessageId without being acted on — here, without
/// the model being asked about it.
#[tokio::test]
async fn a_compound_past_the_request_cap_is_answered_without_being_acted_on() {
    let server = Server::start(None, None).await;
    let mut s = server.connect().await;
    log_in(&mut s).await;
    let tree = call(&mut s, w::tree_connect(2, 1, r"\\127.0.0.1\share")).await;
    assert_eq!(w::status(&tree), w::STATUS_SUCCESS);
    let before = server.settled_calls().await;

    let total = MAX_COMPOUND_REQUESTS + 8;
    let creates = (0..total as u64)
        .map(|i| w::create(100 + i, 1, 1, &format!("c{i}")))
        .collect();
    let reply = call(&mut s, w::compound(creates)).await;
    let replies = w::split_compound(&reply);
    assert_eq!(replies.len(), total, "one reply per request in the chain");
    for (i, r) in replies.iter().enumerate() {
        assert_eq!(
            w::message_id(r),
            100 + i as u64,
            "reply {i} names its request"
        );
        if i < MAX_COMPOUND_REQUESTS {
            // The model answers with no action: a refusal, but one the model made.
            assert_eq!(
                w::status(r),
                w::STATUS_ACCESS_DENIED,
                "CREATE {i} was acted on"
            );
        } else {
            assert_eq!(
                w::status(r),
                w::STATUS_INSUFFICIENT_RESOURCES,
                "CREATE {i} is past MAX_COMPOUND_REQUESTS ({MAX_COMPOUND_REQUESTS})"
            );
        }
    }
    let after = server.settled_calls().await;
    assert_eq!(
        after - before,
        MAX_COMPOUND_REQUESTS,
        "only the first {MAX_COMPOUND_REQUESTS} requests of the chain may reach the model"
    );
    server.stop().await;
}

/// A compound of READs can ask for more than one Direct TCP frame can carry (its length field
/// is 24 bits). The reply must still be one frame: READs whose data would take it past
/// `MAX_RESPONSE_FRAME_BYTES` are answered `STATUS_INSUFFICIENT_RESOURCES` instead.
#[tokio::test]
async fn a_compound_whose_replies_would_overflow_a_frame_is_still_answered_in_one() {
    use base64::Engine as _;
    let content =
        base64::engine::general_purpose::STANDARD.encode(vec![0x5Au8; MAX_READ_SIZE as usize]);
    let server = Server::start(
        None,
        Some(vec![serde_json::json!({
            "event_pattern": "smb_operation",
            "handler": {
                "type": "static",
                "actions": [
                    {"type": "smb_auth_success", "username": "guest"},
                    {"type": "smb_create_file", "path": "/big", "size": MAX_READ_SIZE},
                    {"type": "smb_read_file", "path": "/big", "content": content,
                     "encoding": "base64"}
                ]
            }
        })]),
    )
    .await;
    let mut s = server.connect().await;
    log_in(&mut s).await;
    let tree = call(&mut s, w::tree_connect(2, 1, r"\\127.0.0.1\share")).await;
    assert_eq!(w::status(&tree), w::STATUS_SUCCESS);
    let open = call(&mut s, w::create(3, 1, 1, "big")).await;
    assert_eq!(w::status(&open), w::STATUS_SUCCESS);
    let file = w::create_file_id(&open);

    let count = 17;
    let reads = (0..count as u64)
        .map(|i| w::read(10 + i, 1, 1, &file, 0, MAX_READ_SIZE))
        .collect();
    let reply = call(&mut s, w::compound(reads)).await;
    assert!(reply.len() <= 0x00FF_FFFF);
    let replies = w::split_compound(&reply);
    assert_eq!(replies.len(), count, "one reply per READ");
    let per_read = (64 + 16 + MAX_READ_SIZE as usize).div_ceil(8) * 8;
    let fit = MAX_RESPONSE_FRAME_BYTES / per_read;
    for (i, r) in replies.iter().enumerate() {
        assert_eq!(w::message_id(r), 10 + i as u64);
        if i < fit {
            assert_eq!(w::status(r), w::STATUS_SUCCESS, "READ {i} fits the frame");
            assert_eq!(w::read_payload(r).len(), MAX_READ_SIZE as usize);
        } else {
            assert_eq!(
                w::status(r),
                w::STATUS_INSUFFICIENT_RESOURCES,
                "READ {i} would take the reply past MAX_RESPONSE_FRAME_BYTES"
            );
        }
    }
    // The connection is still in step.
    let echo = call(&mut s, w::simple(w::ECHO, 99, 0, 1)).await;
    assert_eq!((w::command(&echo), w::message_id(&echo)), (w::ECHO, 99));
    server.stop().await;
}

// ---------------------------------------------------------------------------------------------
// MaxReadSize and MaxTransactSize
// ---------------------------------------------------------------------------------------------

/// NEGOTIATE advertises both maxima, a request at each is served, and one byte past either is
/// refused `STATUS_INVALID_PARAMETER` (MS-SMB2 3.3.5.12, 3.3.5.18, 3.3.5.20) before the model.
#[tokio::test]
async fn read_and_output_buffer_lengths_past_the_negotiated_maxima_are_refused() {
    let server = Server::start(
        None,
        Some(vec![serde_json::json!({
            "event_pattern": "smb_operation",
            "handler": {
                "type": "static",
                "actions": [
                    {"type": "smb_auth_success", "username": "guest"},
                    {"type": "smb_create_directory", "path": "/"},
                    {"type": "smb_list_directory", "path": "/", "files": []},
                    {"type": "smb_read_file", "path": "/", "content": "x"}
                ]
            }
        })]),
    )
    .await;
    let mut s = server.connect().await;
    let neg = call(&mut s, w::negotiate(0)).await;
    // MaxTransactSize, MaxReadSize at NEGOTIATE response body offsets 28 and 32.
    let body_u32 = |off: usize| u32::from_le_bytes(neg[64 + off..64 + off + 4].try_into().unwrap());
    assert_eq!(
        body_u32(28),
        MAX_TRANSACT_SIZE,
        "MaxTransactSize advertised"
    );
    assert_eq!(body_u32(32), MAX_READ_SIZE, "MaxReadSize advertised");
    let setup = call(&mut s, w::session_setup(1)).await;
    assert_eq!(w::status(&setup), w::STATUS_SUCCESS);
    call(&mut s, w::tree_connect(2, 1, r"\\127.0.0.1\share")).await;
    // The share root, opened as a directory: good for QUERY_DIRECTORY and QUERY_INFO.
    let root = call(&mut s, w::create_with(3, 1, 1, "", 1)).await;
    assert_eq!(w::status(&root), w::STATUS_SUCCESS);
    let dir = w::create_file_id(&root);

    let at = call(
        &mut s,
        w::with_output_buffer_length(
            w::query_directory(4, 1, 1, &dir, 37, "*"),
            MAX_TRANSACT_SIZE,
        ),
    )
    .await;
    assert_eq!(
        w::status(&at),
        w::STATUS_SUCCESS,
        "QUERY_DIRECTORY at MaxTransactSize"
    );
    let over = call(
        &mut s,
        w::with_output_buffer_length(
            w::query_directory(5, 1, 1, &dir, 37, "*"),
            MAX_TRANSACT_SIZE + 1,
        ),
    )
    .await;
    assert_eq!(
        w::status(&over),
        w::STATUS_INVALID_PARAMETER,
        "QUERY_DIRECTORY past MaxTransactSize"
    );

    let at = call(
        &mut s,
        w::with_output_buffer_length(w::query_info(6, 1, 1, &dir, 1, 4), MAX_TRANSACT_SIZE),
    )
    .await;
    assert_eq!(
        w::status(&at),
        w::STATUS_SUCCESS,
        "QUERY_INFO at MaxTransactSize"
    );
    let over = call(
        &mut s,
        w::with_output_buffer_length(w::query_info(7, 1, 1, &dir, 1, 4), MAX_TRANSACT_SIZE + 1),
    )
    .await;
    assert_eq!(
        w::status(&over),
        w::STATUS_INVALID_PARAMETER,
        "QUERY_INFO past MaxTransactSize"
    );

    // READ is checked against MaxReadSize before the handle is even looked at, so a directory
    // handle shows the order: at the bound it gets the directory's own refusal, past it the
    // length's.
    let at = call(&mut s, w::read(8, 1, 1, &dir, 0, MAX_READ_SIZE)).await;
    assert_eq!(
        w::status(&at),
        w::STATUS_INVALID_DEVICE_REQUEST,
        "a READ of exactly MaxReadSize passes the length check"
    );
    let over = call(&mut s, w::read(9, 1, 1, &dir, 0, MAX_READ_SIZE + 1)).await;
    assert_eq!(
        w::status(&over),
        w::STATUS_INVALID_PARAMETER,
        "a READ past MaxReadSize (MS-SMB2 3.3.5.12)"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------------------------
// The transport and credit bounds
// ---------------------------------------------------------------------------------------------

/// An ECHO asking for `credits` in its header's CreditRequest.
fn echo_requesting(message_id: u64, credits: u16) -> Vec<u8> {
    let mut m = w::simple(w::ECHO, message_id, 0, 0);
    m[14..16].copy_from_slice(&credits.to_le_bytes());
    m
}

fn credits_granted(reply: &[u8]) -> u16 {
    u16::from_le_bytes([reply[14], reply[15]])
}

/// `MAX_CREDIT_GRANT` (64) caps what one response grants, and at least one is always granted;
/// an RFC 1002 session request (a client that dialled 139) of at most 256 bytes of names is
/// answered positively and one longer closes the connection; a keep-alive is not answered; a
/// frame shorter than an SMB2 header, and a first frame that is SMB1, close the connection.
#[tokio::test]
async fn credits_and_the_netbios_session_layer_are_bounded() {
    use netget::server::smb::wire::MAX_CREDIT_GRANT;
    let server = Server::start(None, None).await;

    let mut s = server.connect().await;
    for (asked, granted) in [(0u16, 1u16), (8, 8), (MAX_CREDIT_GRANT, MAX_CREDIT_GRANT)] {
        let r = call(&mut s, echo_requesting(u64::from(asked), asked)).await;
        assert_eq!(credits_granted(&r), granted, "asked for {asked} credits");
    }
    let r = call(&mut s, echo_requesting(1000, 1000)).await;
    assert_eq!(
        credits_granted(&r),
        MAX_CREDIT_GRANT,
        "one response grants at most MAX_CREDIT_GRANT credits"
    );

    // A keep-alive (0x85) is read and not answered: the next reply is the ECHO's.
    s.write_all(&[0x85, 0, 0, 0]).await.unwrap();
    let r = call(&mut s, w::simple(w::ECHO, 7, 0, 0)).await;
    assert_eq!((w::command(&r), w::message_id(&r)), (w::ECHO, 7));

    // An RFC 1002 session request with 68 bytes of names (two encoded NetBIOS names) gets a
    // positive session response, and SMB2 follows on the same connection.
    let mut names = Vec::new();
    for _ in 0..2 {
        names.push(0x20u8);
        names.extend_from_slice(&[b'C', b'A'].repeat(16));
        names.push(0);
    }
    let mut request = vec![0x81, 0, 0, names.len() as u8];
    request.extend_from_slice(&names);
    let mut s = server.connect().await;
    s.write_all(&request).await.unwrap();
    let mut positive = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(20), s.read_exact(&mut positive))
        .await
        .expect("a positive session response")
        .unwrap();
    assert_eq!(positive, [0x82, 0, 0, 0]);
    let r = call(&mut s, w::simple(w::ECHO, 8, 0, 0)).await;
    assert_eq!(w::message_id(&r), 8);

    // One byte past 256 is not a session request this server reads.
    let mut s = server.connect().await;
    let mut request = vec![0x81, 0, 0x01, 0x01];
    request.extend_from_slice(&[b'A'; 257]);
    s.write_all(&request).await.unwrap();
    let sink = read_until_closed(&mut s, 20, "a 257-byte session request").await;
    assert!(
        sink.is_empty(),
        "no positive response past 256 bytes; got {sink:02x?}"
    );

    // A frame shorter than an SMB2 header, and an SMB1 NEGOTIATE, each close the connection.
    let mut s = server.connect().await;
    s.write_all(&nbss(vec![0xFE, b'S', b'M', b'B', 0, 0, 0, 0, 0, 0]))
        .await
        .unwrap();
    let sink = read_until_closed(&mut s, 20, "a 10-byte frame").await;
    assert!(sink.is_empty(), "got {sink:02x?}");
    let mut s = server.connect().await;
    let mut smb1 = b"\xFFSMBr".to_vec();
    smb1.resize(64, 0);
    s.write_all(&nbss(smb1)).await.unwrap();
    let sink = read_until_closed(&mut s, 20, "an SMB1 NEGOTIATE").await;
    assert!(sink.is_empty(), "SMB1 is not answered; got {sink:02x?}");

    assert_eq!(server.settled_calls().await, 0);
    server.stop().await;
}

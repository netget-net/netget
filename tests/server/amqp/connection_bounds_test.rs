//! The connection cap on a real, running AMQP broker, driven from the wire.
//!
//! `HANDSHAKE_TIMEOUT_SECS` (30s) and `IDLE_READ_TIMEOUT_SECS` (600s) bound how long *one* peer
//! holds a connection; neither says anything about how many such peers there may be, and until
//! September 2026 this accept loop admitted every connection offered to it. An AMQP connection
//! is four tasks and up to `MAX_OPEN_CHANNELS` channels each buffering toward `MAX_BODY_SIZE`,
//! so an unbounded number of them is an unbounded multiplier on a bound this broker already
//! took care to declare.
//!
//! Three claims:
//!
//! 1. `MAX_CONNECTIONS` peers are admitted.
//! 2. The next one is refused with a connection-level `Connection.Close` on channel 0 carrying
//!    reply code 320 `CONNECTION_FORCED`, and then closed. The expected frame is rebuilt here
//!    from AMQP 0-9-1's framing rules rather than imported from `codec.rs`, so this asserts
//!    against the spec and not against the encoder that produced it.
//! 3. Closing an admitted connection **frees exactly one slot**. A permit dropped before the
//!    connection ends un-caps the broker silently; one never released wedges it shut after
//!    `MAX_CONNECTIONS` peers have ever connected.
//!
//! **Why a frame rather than silence, tested here rather than argued once**: the method's
//! `class-id`/`method-id` fields are zero when the close answers no method (0-9-1 §1.4.2.9),
//! which is exactly a peer over the cap — so nothing in this refusal is fabricated, unlike an
//! IPP status or a MongoDB reply that would have to invent a request id. The test asserts those
//! two zero fields for that reason.
//!
//! **How this was proved to fail without the cap**: replace the `accept_bounded` call in
//! `src/server/amqp/mod.rs` with a bare `listener.accept().await` (and drop the permit from the
//! connection task). The over-cap peer is then admitted, sits waiting for a protocol header it
//! will never be asked for, and the test fails on the read timing out.
//!
//! The server is model-free: an empty instruction really is model-free, where `None` is
//! replaced by a default one. AMQP is client-speaks-first — the broker waits for the 8-byte
//! protocol header — so a peer that says nothing provokes no model call. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features amqp --test server -- amqp::connection_bounds --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/amqp/mod.rs::MAX_CONNECTIONS`. Deliberately duplicated rather than imported: if
/// the constant moves, this test should be re-read rather than silently follow it.
const MAX_CONNECTIONS: usize = 256;

/// `src/server/amqp/mod.rs::CONNECTION_CAP_REPLY_TEXT`, byte for byte.
const CAP_REPLY_TEXT: &str = "connection limit reached, try again later";

/// The refusal AMQP 0-9-1 says this is, rebuilt from the spec.
///
/// Frame (§4.2.3): type 1 (method), channel 0, a four-byte payload length, the payload, then
/// the `0xCE` frame-end octet. Method payload (§4.2.5): class 10 (connection), method 50
/// (close), then the arguments — `reply-code` (short), `reply-text` (short string: one length
/// octet then the bytes), `class-id` and `method-id`, the last two zero because this close
/// answers no method at all (§1.4.2.9).
fn expected_refusal() -> Vec<u8> {
    let mut args = Vec::new();
    args.extend_from_slice(&320u16.to_be_bytes()); // CONNECTION_FORCED
    args.push(CAP_REPLY_TEXT.len() as u8);
    args.extend_from_slice(CAP_REPLY_TEXT.as_bytes());
    args.extend_from_slice(&0u16.to_be_bytes()); // class-id: not in reply to a method
    args.extend_from_slice(&0u16.to_be_bytes()); // method-id: likewise

    let mut payload = Vec::new();
    payload.extend_from_slice(&10u16.to_be_bytes()); // class: connection
    payload.extend_from_slice(&50u16.to_be_bytes()); // method: close
    payload.extend_from_slice(&args);

    let mut frame = Vec::new();
    frame.push(1u8); // FRAME_METHOD
    frame.extend_from_slice(&0u16.to_be_bytes()); // channel 0
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame.push(0xCE); // FRAME_END
    frame
}

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
    panic!("AMQP broker #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "amqp".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create amqp broker");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

/// Wait until the accept loop has taken `n` connections out of the listen backlog. A
/// `connect()` succeeds as soon as the kernel queues it, so without this the over-cap peer
/// races the accept loop and the test measures scheduling rather than the cap.
///
/// This broker registers the connection at the top of `handle_connection`, before it reads the
/// protocol header, so the count reflects admitted peers rather than peers that have spoken.
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
    panic!("the broker admitted only {seen} of {n} connections");
}

#[tokio::test]
async fn the_connection_past_the_cap_gets_a_connection_close_and_the_slot_comes_back() {
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
             is waiting for a protocol header, so there is no cap",
        )
        .expect("read to EOF");
    assert_eq!(
        refusal,
        expected_refusal(),
        "a refused peer must get a Connection.Close on channel 0 with reply code 320 and \
         class-id/method-id zero, then EOF. Got {refusal:02x?}"
    );

    drop(held.pop().expect("one held connection"));

    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect after freeing a slot");
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(300), candidate.read(&mut buf)).await {
            // Neither bytes nor EOF: AMQP is client-speaks-first, so a connection still open and
            // still silent after the window is one that was admitted and is waiting for the
            // protocol header. A refused peer gets a Close frame and an immediate close.
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
         held past the life of the connection, which wedges the broker shut"
    );
}

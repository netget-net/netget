//! The connection cap on the LLMNR responder's TCP side, driven from the wire.
//!
//! LLMNR is a UDP-multicast protocol with a TCP listener beside it: RFC 4795 §2.4 requires
//! responders to support TCP queries, and it is the only transport on which a non-zero RCODE
//! may be returned. That listener is a real accept loop reachable by anyone who can open a
//! socket, and until September 2026 it admitted every connection offered to it.
//! `TCP_IDLE_TIMEOUT` (30s) bounds how long *one* silent querier holds a task and a descriptor;
//! thirty seconds multiplied by an unbounded arrival rate is not a bound.
//!
//! Three claims:
//!
//! 1. `MAX_CONNECTIONS` peers are admitted.
//! 2. The next one is closed **with nothing written**, and that is the right answer rather than
//!    a shortcut. LLMNR's only server message is a DNS response, and RFC 4795 §2.4 requires it
//!    to copy the query's ID and question section while §2.1 has the querier silently discard
//!    anything that does not match an outstanding query — so a fabricated response to a peer
//!    that has sent nothing would be dropped, leaving it to wait out its own timeout instead of
//!    the immediate EOF it gets here. Silence is also what this protocol does everywhere else:
//!    a responder that cannot answer simply says nothing.
//! 3. Closing an admitted connection **frees exactly one slot**. A permit dropped before the
//!    connection ends un-caps the responder silently; one never released wedges it shut after
//!    `MAX_CONNECTIONS` peers have ever connected.
//!
//! **Why there is no `wait_for_admitted` here, unlike the rest of this sweep.** This responder
//! registers a connection in `AppState` only when a query is *answered*, so a connected-but-
//! silent peer is invisible to the state it would poll. The ordering guarantee is the kernel's
//! instead: the listen backlog is FIFO and every one of the 256 `connect()` calls below has
//! returned before the 257th is even started, so the accept loop necessarily reaches them in
//! that order. Nothing here sleeps and hopes.
//!
//! Because the refusal is silence, "refused" and "admitted" are told apart by *time*: a refused
//! peer reads EOF at once, an admitted one is held for `TCP_IDLE_TIMEOUT`. The windows below
//! sit well inside that gap on both sides.
//!
//! **How this was proved to fail without the cap**: replace the `accept_bounded` call in
//! `src/server/llmnr/mod.rs` with a bare `listener.accept().await` (and drop the permit from
//! the connection task). The over-cap peer is then admitted and held for the full idle
//! deadline, and the test fails on "was neither answered nor closed".
//!
//! The server is model-free: an empty instruction really is model-free, where `None` is
//! replaced by a default one. No query is ever sent, so no model call is provoked. Multicast
//! joining is switched off so the test touches nothing but loopback.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features llmnr --test server -- llmnr::connection_bounds --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// `src/server/llmnr/mod.rs::MAX_CONNECTIONS`. Deliberately duplicated rather than imported: if
/// the constant moves, this test should be re-read rather than silently follow it.
const MAX_CONNECTIONS: usize = 256;

/// `src/server/llmnr/mod.rs::TCP_IDLE_TIMEOUT`, which is what the refusal has to beat for
/// "refused" and "admitted then evicted" to be distinguishable.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

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
    panic!("LLMNR responder #{} never bound a port", id.as_u32());
}

async fn start_server(state: &AppState) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "llmnr".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(serde_json::json!({ "join_multicast": false })),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create llmnr responder");
    let port = wait_for_port(state, server_id).await;
    (server_id, port)
}

/// Connect, waiting for the TCP listener to exist.
///
/// The responder binds UDP first and then takes the same port on TCP, so the TCP side may
/// appear a moment after the server reports its address.
async fn connect(port: u16) -> std::io::Result<TcpStream> {
    let mut last = None;
    for _ in 0..100 {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    Err(last.expect("at least one attempt"))
}

#[tokio::test]
async fn the_tcp_connection_past_the_cap_is_closed_without_a_fabricated_answer_and_the_slot_comes_back(
) {
    let state = new_state().await;
    let (_server_id, port) = start_server(&state).await;

    let mut held = Vec::with_capacity(MAX_CONNECTIONS);
    for i in 0..MAX_CONNECTIONS {
        held.push(
            connect(port)
                .await
                .unwrap_or_else(|e| panic!("connection {i} of the cap failed: {e}")),
        );
    }

    let mut over = connect(port)
        .await
        .expect("the listener must still accept — a cap is not a closed socket");
    let mut refusal = Vec::new();
    let started = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(10), over.read_to_end(&mut refusal))
        .await
        .expect(
            "the connection past the cap was neither answered nor closed — it was admitted, so \
             there is no cap",
        )
        .expect("read to EOF");
    assert!(
        refusal.is_empty(),
        "every LLMNR response echoes the query's ID and question, and a refused peer has sent \
         no query — so the refusal must be a plain close. Got {refusal:02x?}"
    );
    assert!(
        started.elapsed() < TCP_IDLE_TIMEOUT / 3,
        "the refusal took {:?}, which is close enough to TCP_IDLE_TIMEOUT that this peer may \
         simply have been admitted and then closed for saying nothing",
        started.elapsed()
    );

    drop(held.pop().expect("one held connection"));

    let mut admitted = false;
    for _ in 0..100 {
        let mut candidate = connect(port).await.expect("connect after freeing a slot");
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(300), candidate.read(&mut buf)).await {
            // Neither bytes nor EOF: LLMNR's TCP side waits for a length-prefixed query, so a
            // connection still open and still silent after the window is one that was admitted.
            // A refused peer, whose refusal is a bare close, returns `Ok(0)` at once.
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
         held past the life of the connection, which wedges the TCP side shut"
    );
}

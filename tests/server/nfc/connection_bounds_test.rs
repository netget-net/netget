//! The read deadlines on a real, running NFC virtual tag, driven from a raw socket.
//!
//! The peer here is a vpcd reader: `u16` big-endian length, then a payload that is either a
//! one-byte control code or a command APDU. Both tests speak that framing directly, which is
//! all a reader ever does.
//!
//! **A reader that has connected and sent no frame must eventually be let go of.** Nothing else
//! in the process closes that socket: it holds a task, an `AppState` row and one of
//! `MAX_CONNECTIONS` slots, and this server registers no peer channel, so there is not even an
//! operator who could be driving it. Remove the deadline around `read_half.read_u16()` in
//! `src/server/nfc/mod.rs` and the first test hangs until its own window expires.
//!
//! **Once a frame has been answered the *idle* bound governs, not the first-byte one.** The
//! second test sends the vpcd `ATR` control code, which the tag answers from its own state with
//! no model involved at all, and then goes quiet — with the two bounds set far apart and the
//! wrong way round, so a read loop that never switched would hold the connection for 60 seconds
//! and time the assertion out.
//!
//! The values here are overrides, not the defaults. The shipped defaults are 30 seconds and 300
//! (argued beside `FIRST_FRAME_READ_TIMEOUT` and `IDLE_BETWEEN_FRAMES_TIMEOUT`), and a test
//! that asserted them by waiting them out would be the slowest thing in the suite. That is why
//! both are declared startup parameters: what is asserted here is that each parameter is read
//! and applied to the read it names; the *values* are argued where they are declared.
//!
//! No mock backend: the LLM endpoint is a dead port, and the tag's startup configuration call
//! is explicitly non-fatal when it fails. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nfc --test server -- \
//!       nfc::connection_bounds --test-threads=100

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

/// vpcd control code: "give me the ATR". Answered from the tag's own state, no LLM.
const VPCD_CTRL_ATR: u8 = 0x04;

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
    panic!("NFC server #{} never bound a port", id.as_u32());
}

/// A model-free tag: an empty instruction really is model-free, where `None` is replaced by a
/// default one and every event would consult the LLM.
async fn start_server(state: &AppState, startup_params: serde_json::Value) -> u16 {
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "nfc".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        startup_params: Some(startup_params),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create nfc server");
    wait_for_port(state, server_id).await
}

#[tokio::test]
async fn a_reader_that_connects_and_sends_no_frame_is_closed_at_the_first_byte_bound() {
    let state = new_state().await;
    let port = start_server(
        &state,
        serde_json::json!({
            "first_byte_timeout_secs": SHORT_FIRST_BYTE.as_secs(),
        }),
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
        "a reader that connected and sent no frame was still holding the socket, the connection \
         task and its AppState entry after {}s — either the first-byte deadline is not applied \
         at all, or `first_byte_timeout_secs` was declared and never read",
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
        "the tag wrote {} bytes to a reader that had sent no frame; a card answers commands and \
         never speaks first",
        sink.len()
    );
}

#[tokio::test]
async fn a_reader_that_announces_a_frame_and_stalls_does_not_buy_the_longer_bound() {
    let state = new_state().await;
    // A two-byte length prefix and then nothing. If the read loop treated the prefix as
    // "established" it would apply the 60-second idle bound to the body read, and two bytes
    // would be all it takes to make the first-byte bound irrelevant.
    let port = start_server(
        &state,
        serde_json::json!({
            "first_byte_timeout_secs": SHORT_FIRST_BYTE.as_secs(),
            "idle_timeout_secs": 60,
        }),
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(&[0x00, 0x08]).await.expect("write length");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(45), peer.read_to_end(&mut sink)).await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "a reader that announced an 8-byte frame and then sent nothing held the connection for \
         {}s — the body read is not bounded at all",
        elapsed.as_secs()
    );
    read.unwrap().expect("read to EOF");
    assert!(
        elapsed < Duration::from_secs(40),
        "closed after {}s, which is the 60-second idle bound rather than the {}s first-byte one \
         — two bytes bought this peer the established-connection bound",
        elapsed.as_secs(),
        SHORT_FIRST_BYTE.as_secs()
    );
}

#[tokio::test]
async fn once_a_frame_has_been_answered_the_idle_bound_governs_not_the_first_byte_one() {
    let state = new_state().await;
    // The two bounds are set far apart and the wrong way round on purpose: if the read loop
    // kept using the first-byte bound after answering, this connection would live 60 seconds
    // and the assertion below would time out.
    let port = start_server(
        &state,
        serde_json::json!({
            "first_byte_timeout_secs": 60,
            "idle_timeout_secs": SHORT_IDLE.as_secs(),
        }),
    )
    .await;

    let mut peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    peer.write_all(&[0x00, 0x01, VPCD_CTRL_ATR])
        .await
        .expect("write ATR request");

    // Read the framed answer the way a reader does: the length prefix and the payload arrive
    // as two separate writes, so a single `read` sees only the prefix.
    let mut len = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(20), peer.read_exact(&mut len))
        .await
        .expect("the tag did not answer the ATR control code within 20s")
        .expect("read reply length");
    let atr_len = u16::from_be_bytes(len) as usize;
    assert!(
        atr_len > 0,
        "the tag answered the ATR request with an empty frame, so what follows is not the \
         post-answer state this test is about"
    );
    let mut atr = vec![0u8; atr_len];
    tokio::time::timeout(Duration::from_secs(20), peer.read_exact(&mut atr))
        .await
        .expect("the tag announced an ATR and never sent it")
        .expect("read ATR body");

    let started = std::time::Instant::now();
    let mut sink = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(45), peer.read_to_end(&mut sink)).await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "an answered reader that then went quiet was never closed — `idle_timeout_secs` was \
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

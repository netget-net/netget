//! What an NMDC client gets when the LLM backend fails: a `$Error` frame, not silence.
//!
//! The hub used to log `LLM call failed` and write nothing, then loop round to read again.
//! A DC client that has just sent `$ValidateNick` is blocked on the hub's answer, so the
//! login sat half-finished until the client's own timeout - the silent-failure pattern
//! CLAUDE.md calls out as worse than refusing.
//!
//! The reply carries a category and nothing else. NMDC has no numeric status codes, so the
//! two `WireFailure` classes are separated by frame shape: `Overloaded` is a hub chat notice
//! (transient - the session continues and a retry is sensible), `Unavailable` is `$Error`,
//! the protocol's own error command. Both texts are `&'static str` from `WireFailure`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dc --test server -- dc::llm_failure --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// An LLM endpoint that is not listening: every call fails with a transport error, which
/// `WireFailure::classify` reports as `Unavailable` (not an overload).
const DEAD_LLM: &str = "http://127.0.0.1:1";

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, DEAD_LLM.to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(DEAD_LLM.to_string()))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("DC server #{} never bound a port", id.as_u32());
}

/// Read one `|`-terminated NMDC command (terminator included).
async fn read_dc_command(stream: &mut TcpStream, secs: u64) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(secs), stream.read(&mut byte))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the hub neither answered nor closed within {secs}s - it went silent on \
                     LLM failure, which is the defect this test exists to catch (partial: \
                     {:?})",
                    String::from_utf8_lossy(&buf)
                )
            })
            .expect("read");
        assert_ne!(n, 0, "unexpected EOF while reading a DC command");
        buf.push(byte[0]);
        if byte[0] == b'|' {
            return String::from_utf8(buf).expect("utf8");
        }
    }
}

#[tokio::test]
async fn dc_answers_error_frame_when_llm_fails() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // No event_handlers: every command goes to the LLM, and the LLM is unreachable.
    let server_id = ServerForm {
        protocol: "dc".to_string(),
        port: Some(0),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create dc server");
    let port = wait_for_port(&state, server_id).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect");

    let lock = read_dc_command(&mut stream, 5).await;
    assert!(lock.starts_with("$Lock "), "expected $Lock, got {lock:?}");

    stream
        .write_all(b"$ValidateNick alice|")
        .await
        .expect("write");

    // Generous: the failure path runs through the retry/repair loop first.
    let reply = read_dc_command(&mut stream, 90).await;
    println!("DC failure reply: {reply:?}");

    assert!(
        reply.starts_with("$Error ") || reply.starts_with("<Hub> "),
        "expected an NMDC error frame or a hub notice, got {reply:?}"
    );
    assert!(reply.ends_with('|'), "NMDC frames end with `|`: {reply:?}");
    assert!(
        reply.contains("request could not be processed") || reply.contains("backend at capacity"),
        "the reply must carry a WireFailure category: {reply:?}"
    );

    // Nothing derived from the error may reach the peer.
    for leak in [
        "http://",
        "127.0.0.1:1",
        "ollama",
        "Ollama",
        "retries",
        ".rs:",
        "error sending request",
        "Connection refused",
    ] {
        assert!(
            !reply.contains(leak),
            "internal detail `{leak}` reached the wire: {reply:?}"
        );
    }
    // A forged second frame: the category text must contain no embedded terminator.
    assert_eq!(
        reply.matches('|').count(),
        1,
        "the failure frame must be a single NMDC command: {reply:?}"
    );

    // The session is still usable - the hub reported a failure, it did not hang up.
    stream.write_all(b"$Version 1,0091|").await.expect("write");
    let second = read_dc_command(&mut stream, 90).await;
    assert!(
        second.starts_with("$Error ") || second.starts_with("<Hub> "),
        "the hub should keep answering subsequent commands, got {second:?}"
    );

    state.remove_server(server_id).await;
}

//! The DC client's session against a loopback fake hub, with the in-process mock model
//! answering its events, plus the pure helpers the session relies on.
//!
//! What the hub tests pin, each from the hub's side of the wire:
//! - an action answered at `$Lock` goes out and the handshake (`$Key`, `$ValidateNick`,
//!   `$MyINFO`) still completes, rather than the session hanging on its own state mutex;
//! - a batch with one failing action still sends the actions after it;
//! - `|` and `$` in model-supplied text are escaped (`&#124;`, `&#36;`) and a private-message
//!   target that is not a valid nickname is refused, so the model cannot inject a command;
//! - malformed `$To:` frames do not kill the read loop (a later chat still reaches the model);
//! - `disconnect` writes `$Quit|`, closes the client's side and ends the read loop while the
//!   hub still holds its end open, and nothing after it in the batch is sent.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dc --test client -- dc::session_test --test-threads=100


use std::time::{Duration, Instant};

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ClientForm;
use netget::client::dc::{
    escape_nmdc_text, parse_private_message, reconnect_delay_secs, validate_nmdc_nickname,
    MAX_RECONNECT_DELAY_SECS,
};
use netget::state::app_state::AppState;
use netget::state::ClientId;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const LOCK: &[u8] = b"$Lock EXTENDEDPROTOCOLABCABCABCABCABCABC Pk=FakeHub|";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Read from the hub's socket into `seen` until `needle` appears, the peer closes, or the
/// deadline passes.
async fn read_until(stream: &mut TcpStream, seen: &mut Vec<u8>, needle: &[u8], secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if contains(seen, needle) {
            return true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => seen.extend_from_slice(&chunk[..n]),
            _ => return contains(seen, needle),
        }
    }
}

/// Read until the client closes its side (EOF). Returns false on timeout or reset.
async fn read_to_eof(stream: &mut TcpStream, seen: &mut Vec<u8>, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return true,
            Ok(Ok(n)) => seen.extend_from_slice(&chunk[..n]),
            _ => return false,
        }
    }
}

async fn state_for(mock: &MockOllamaServer) -> AppState {
    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    state
}

/// Create a DC client named `alice` pointed at `port`.
async fn create_client(state: &AppState, mock: &MockOllamaServer, port: u16) -> ClientId {
    let (tx, _rx) = mpsc::unbounded_channel();
    ClientForm {
        protocol: "dc".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("DC session test client".to_string()),
        startup_params: Some(json!({"nickname": "alice"})),
        ..Default::default()
    }
    .create(state, netget::llm::OllamaClient::new(mock.base_url()), tx)
    .await
    .expect("create dc client")
}

async fn accept(listener: &TcpListener) -> TcpStream {
    tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the DC client never connected to the fake hub")
        .expect("accept")
        .0
}

/// Send `$Lock` and wait for the client's whole handshake answer.
async fn lock_and_handshake(hub: &mut TcpStream, seen: &mut Vec<u8>) {
    hub.write_all(LOCK).await.unwrap();
    assert!(
        read_until(hub, seen, b"$MyINFO $ALL alice ", 15).await,
        "the client never completed its answer to $Lock; the hub saw: {:?}",
        String::from_utf8_lossy(seen)
    );
    assert!(
        contains(seen, b"$Key "),
        "no $Key: {:?}",
        String::from_utf8_lossy(seen)
    );
    assert!(
        contains(seen, b"$ValidateNick alice|"),
        "no $ValidateNick: {:?}",
        String::from_utf8_lossy(seen)
    );
}

#[tokio::test]
async fn an_action_answered_at_lock_goes_out_and_the_handshake_completes() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("dc_client_connected")
            .respond_with_actions(json!([{"type": "send_dc_chat", "message": "lock-marker"}]))
            .expect_calls(1)
            .build(),
    )
    .await
    .expect("mock ollama");
    let state = state_for(&mock).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let _client = create_client(&state, &mock, port).await;
    let mut hub = accept(&listener).await;
    let mut seen = Vec::new();

    lock_and_handshake(&mut hub, &mut seen).await;
    assert!(
        contains(&seen, b"<alice> lock-marker|"),
        "the model's answer to $Lock was not sent: {:?}",
        String::from_utf8_lossy(&seen)
    );

    mock.wait_for_expectations(10).await;
    mock.verify_calls().await.expect("mock expectations");
}

#[tokio::test]
async fn a_failing_action_does_not_drop_the_rest_and_model_text_is_escaped() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("dc_client_connected")
            .respond_with_actions(json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
            .on_event("dc_client_authenticated")
            .respond_with_actions(json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
            // Only the well-formed chat reaches the model: the malformed private messages
            // before it are parse errors, and a panic on either would have ended the read
            // loop before the chat was read at all.
            .on_event("dc_client_message_received")
            .respond_with_actions(json!([
                {"type": "send_dc_chat", "message": "before"},
                // Rejected by the protocol: no `message`.
                {"type": "send_dc_chat"},
                // Refused: the target is not a valid nickname.
                {"type": "send_dc_private_message", "target": "bad|nick", "message": "x"},
                {"type": "send_dc_private_message", "target": "bob", "message": "pm|$Kick bob"},
                {"type": "send_dc_chat", "message": "after|$ForceMove evil &#124;"}
            ]))
            .expect_calls(1)
            .build(),
    )
    .await
    .expect("mock ollama");
    let state = state_for(&mock).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let _client = create_client(&state, &mock, port).await;
    let mut hub = accept(&listener).await;
    let mut seen = Vec::new();
    lock_and_handshake(&mut hub, &mut seen).await;

    hub.write_all(
        "$Hello alice|$To: From: bob $<bob> hi|$To:\u{e9} From: bob $<bob> hi|<bob> go|".as_bytes(),
    )
    .await
    .unwrap();

    let after = b"<alice> after&#124;&#36;ForceMove evil &amp;#124;|";
    assert!(
        read_until(&mut hub, &mut seen, after, 15).await,
        "the last action of the batch never arrived escaped: {:?}",
        String::from_utf8_lossy(&seen)
    );
    assert!(
        contains(&seen, b"<alice> before|"),
        "{:?}",
        String::from_utf8_lossy(&seen)
    );
    assert!(
        contains(
            &seen,
            b"$To: bob From: alice $<alice> pm&#124;&#36;Kick bob|"
        ),
        "the private message was not sent escaped: {:?}",
        String::from_utf8_lossy(&seen)
    );
    for injected in [&b"|$Kick"[..], b"|$ForceMove", b"bad|nick"] {
        assert!(
            !contains(&seen, injected),
            "model text reached the wire as a command ({:?}): {:?}",
            String::from_utf8_lossy(injected),
            String::from_utf8_lossy(&seen)
        );
    }

    mock.wait_for_expectations(10).await;
    mock.verify_calls().await.expect("mock expectations");
}

#[tokio::test]
async fn disconnect_ends_the_session_while_the_hub_holds_the_connection_open() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("dc_client_connected")
            .respond_with_actions(json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
            .on_event("dc_client_authenticated")
            .respond_with_actions(json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
            .on_event("dc_client_message_received")
            .respond_with_actions(json!([
                {"type": "disconnect"},
                {"type": "send_dc_chat", "message": "must-not-send"}
            ]))
            .expect_calls(1)
            .build(),
    )
    .await
    .expect("mock ollama");
    let state = state_for(&mock).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let client = create_client(&state, &mock, port).await;
    let mut hub = accept(&listener).await;
    let mut seen = Vec::new();
    lock_and_handshake(&mut hub, &mut seen).await;

    hub.write_all(b"$Hello alice|<bob> bye|").await.unwrap();
    assert!(
        read_until(&mut hub, &mut seen, b"$Quit|", 15).await,
        "disconnect never wrote $Quit|: {:?}",
        String::from_utf8_lossy(&seen)
    );
    // The hub keeps its end open; the client must close its own.
    assert!(
        read_to_eof(&mut hub, &mut seen, 10).await,
        "the client sent $Quit| and kept the connection open"
    );
    assert!(
        !contains(&seen, b"must-not-send"),
        "an action after disconnect was sent: {:?}",
        String::from_utf8_lossy(&seen)
    );

    // The read loop ended by itself: it removes the client's command handle on exit.
    let deadline = Instant::now() + Duration::from_secs(10);
    while state.has_client_handle(client).await {
        assert!(
            Instant::now() < deadline,
            "the read loop kept running after disconnect"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    mock.wait_for_expectations(10).await;
    mock.verify_calls().await.expect("mock expectations");
}

#[tokio::test]
async fn a_nickname_with_a_delimiter_is_refused_before_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = mpsc::unbounded_channel();

    let error = ClientForm {
        protocol: "dc".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("DC session test client".to_string()),
        startup_params: Some(json!({"nickname": "ali|$MyINFO injected"})),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect_err("a nickname containing '|' must be refused");
    assert!(
        format!("{error:#}").contains("invalid NMDC nickname"),
        "{error:#}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_err(),
        "the client connected to the hub with a nickname it should have refused"
    );
}

#[test]
fn malformed_private_messages_are_errors_not_panics() {
    let parts = parse_private_message("$To: alice From: bob $<bob> hello there").unwrap();
    assert_eq!(parts.target, "alice");
    assert_eq!(parts.source, "bob");
    assert_eq!(parts.message, "hello there");

    for frame in [
        // " From:" sits before the end of "$To: ", so the target range is inverted.
        "$To: From: bob $<bob> hi",
        // The target range starts inside the two-byte 'é'.
        "$To:\u{e9} From: bob $<bob> hi",
        "$To: alice From: bob no body",
        "$To: alice",
        "$To:",
    ] {
        assert!(
            parse_private_message(frame).is_err(),
            "{frame:?} should be refused"
        );
    }

    // No prefix of a multi-byte frame panics.
    let full = "$To: \u{e5}lice From: b\u{f8}b $<b\u{f8}b> h\u{e9}llo";
    for (end, _) in full.char_indices() {
        let _ = parse_private_message(&full[..end]);
    }
}

#[test]
fn reconnect_delay_doubles_and_saturates_at_the_cap() {
    assert_eq!(reconnect_delay_secs(2, 0), 2);
    assert_eq!(reconnect_delay_secs(2, 1), 2);
    assert_eq!(reconnect_delay_secs(2, 2), 4);
    assert_eq!(reconnect_delay_secs(2, 5), 32);
    assert_eq!(reconnect_delay_secs(2, 6), MAX_RECONNECT_DELAY_SECS);
    // Exponents that overflow `2u64.pow`.
    for attempt in [64, 65, 1_000, u32::MAX] {
        assert_eq!(reconnect_delay_secs(2, attempt), MAX_RECONNECT_DELAY_SECS);
    }
    // A product that overflows on the first retry.
    assert_eq!(reconnect_delay_secs(u64::MAX, 2), MAX_RECONNECT_DELAY_SECS);
}

#[test]
fn nmdc_text_escaping_and_nickname_validation() {
    assert_eq!(escape_nmdc_text("a|b$c"), "a&#124;b&#36;c");
    assert_eq!(escape_nmdc_text("&#124;"), "&amp;#124;");
    assert_eq!(escape_nmdc_text("&#36;&amp;"), "&amp;#36;&amp;amp;");
    assert_eq!(escape_nmdc_text("AT&T & co"), "AT&T & co");
    assert_eq!(escape_nmdc_text("\u{e9}|"), "\u{e9}&#124;");

    for ok in ["alice", "\u{7528}\u{6237}\u{540d}", "[bot]x"] {
        assert!(validate_nmdc_nickname(ok).is_ok(), "{ok:?}");
    }
    for bad in ["", "ali|ce", "a$b", "a b", "<x>", "a\u{7}", "a\r\n"] {
        assert!(validate_nmdc_nickname(bad).is_err(), "{bad:?}");
    }
}

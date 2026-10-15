//! IRC line framing: the two ways an IRC implementation gets owned, both asserted directly.
//!
//! 1. **Message injection.** Every `send_irc_*` action interpolates model-supplied text into a
//!    CRLF-terminated line. A `message` containing `\r\n` therefore does not make a longer
//!    message - it forges a second command from the server. This is the same shape as the FTP
//!    reply-splitting defect (`src/server/ftp/actions.rs`), and it matters more here because
//!    the text is chat relayed to other humans.
//! 2. **Unbounded reads.** `AsyncBufReadExt::read_line` grows until it finds a newline, so an
//!    unauthenticated peer that streams bytes with no `\n` is a one-connection OOM.
//!
//! Zero LLM calls: the framing checks run the executor directly, and the read-bound check
//! never reaches an event because the line never completes.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features irc --test server -- irc::framing --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::IrcProtocol;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// The bytes an action put on the wire, or the error it refused with.
fn wire(action: serde_json::Value) -> Result<String, String> {
    match IrcProtocol::new().execute_action(action) {
        Ok(ActionResult::Output(bytes)) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        Ok(other) => Err(format!("expected Output, got {other:?}")),
        Err(e) => Err(e.to_string()),
    }
}

fn refused(action: serde_json::Value) -> String {
    match wire(action.clone()) {
        Ok(out) => panic!("action {action} was accepted and wrote {out:?}; expected a refusal"),
        Err(e) => e,
    }
}

#[test]
fn crlf_in_model_text_cannot_forge_a_second_message() {
    // The canonical attack: a chat body that closes its own PRIVMSG and starts a command.
    for action in [
        serde_json::json!({"type": "send_irc_privmsg", "source": "bot", "target": "#general",
                           "message": "hi\r\nPRIVMSG #ops :op me"}),
        serde_json::json!({"type": "send_irc_notice", "source": "bot", "target": "#general",
                           "message": "hi\r\nKILL alice"}),
        serde_json::json!({"type": "send_irc_welcome", "nickname": "alice",
                           "message": "hi\r\n:x 001 alice :welcome again"}),
        serde_json::json!({"type": "send_irc_numeric", "code": 332, "target": "alice",
                           "message": "topic\r\nPRIVMSG alice :forged"}),
        serde_json::json!({"type": "send_irc_message",
                           "message": "NOTICE * :a\r\nNOTICE * :b"}),
        serde_json::json!({"type": "send_irc_pong", "token": "x\r\nQUIT"}),
        serde_json::json!({"type": "send_irc_part", "nickname": "a", "channel": "#c",
                           "reason": "bye\r\nJOIN #ops"}),
    ] {
        let e = refused(action);
        assert!(
            e.contains("CR, LF or NUL"),
            "expected the CR/LF refusal, got {e:?}"
        );
    }

    // A bare LF is enough on its own - many ircds accept LF-terminated lines.
    let e = refused(
        serde_json::json!({"type": "send_irc_privmsg", "source": "bot",
                                       "target": "#g", "message": "hi\nJOIN #ops"}),
    );
    assert!(e.contains("CR, LF or NUL"), "got {e:?}");

    // RFC 1459 forbids NUL in a message outright.
    let e = refused(
        serde_json::json!({"type": "send_irc_privmsg", "source": "bot",
                                       "target": "#g", "message": "hi\0there"}),
    );
    assert!(e.contains("CR, LF or NUL"), "got {e:?}");
}

#[test]
fn a_space_in_a_word_parameter_cannot_shift_the_parameters_after_it() {
    // `target: "alice :spoofed"` would put the trailing-parameter marker in word position,
    // so the client parses a message the server never composed.
    let e = refused(
        serde_json::json!({"type": "send_irc_privmsg", "source": "bot",
                                       "target": "alice :spoofed", "message": "real"}),
    );
    assert!(e.contains("must not contain a space"), "got {e:?}");

    let e = refused(
        serde_json::json!({"type": "send_irc_privmsg", "source": "bot",
                                       "target": ":alice", "message": "real"}),
    );
    assert!(e.contains("must not start with ':'"), "got {e:?}");

    let e = refused(serde_json::json!({"type": "send_irc_join", "nickname": "a",
                                       "channel": "#c d"}));
    assert!(e.contains("must not contain a space"), "got {e:?}");

    let e = refused(serde_json::json!({"type": "send_irc_welcome", "nickname": ""}));
    assert!(e.contains("must not be empty"), "got {e:?}");
}

#[test]
fn a_numeric_is_three_digits_or_it_is_not_a_numeric() {
    // `{:03}` pads a small number and happily widens a large one, so 1234 would emit a
    // four-digit field the client reads as the start of the next parameter.
    for code in [0, 1000, 99999] {
        let e = refused(serde_json::json!({"type": "send_irc_numeric", "code": code,
                                           "target": "alice", "message": "x"}));
        assert!(
            e.contains("three-digit reply code"),
            "code {code}: got {e:?}"
        );
    }
    let out = wire(serde_json::json!({"type": "send_irc_numeric", "code": 1,
                                      "target": "alice", "message": "x"}))
    .expect("code 1 is valid and pads to 001");
    assert!(out.contains(" 001 alice "), "got {out:?}");
}

#[test]
fn an_over_long_line_is_truncated_to_512_bytes_on_a_char_boundary() {
    // RFC 1459 §2.3.1. A longer line is truncated or dropped by every real peer, so the tail
    // is lost either way; what must not happen is a malformed line or a panic.
    let long = "e".repeat(2000);
    let out = wire(
        serde_json::json!({"type": "send_irc_privmsg", "source": "bot",
                                      "target": "#general", "message": long}),
    )
    .expect("a long message is truncated, not refused");
    assert_eq!(out.len(), 512, "expected exactly the RFC 1459 limit");
    assert!(out.ends_with("\r\n"), "still one well-formed line: {out:?}");

    // The cut must land on a `char` boundary. Byte-index slicing guarded only by `len() > N`
    // panics on ordinary non-ASCII chat text, which is the defect this repo has hit before.
    let multibyte = "é".repeat(2000); // 2 bytes each, so byte 510 falls mid-character
    let out = wire(
        serde_json::json!({"type": "send_irc_privmsg", "source": "bot",
                                      "target": "#general", "message": multibyte}),
    )
    .expect("multi-byte text is truncated, not a panic");
    assert!(out.len() <= 512, "over the limit: {} bytes", out.len());
    assert!(out.ends_with("\r\n"));
    assert!(
        std::str::from_utf8(out.as_bytes()).is_ok(),
        "truncation split a character"
    );
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..1_000 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("IRC server #{} never bound a port", id.as_u32());
}

#[tokio::test]
async fn a_peer_that_never_sends_a_newline_is_cut_off_rather_than_buffered() {
    // `instruction: Some(String::new())` keeps `ServerForm::create` from substituting its
    // default instruction, which would make this server consult the model.
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "irc".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create irc server");
    let port = wait_for_port(&state, server_id).await;

    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    // 64 KiB with not one newline in it. Unbounded, this is buffered whole and the peer can
    // keep going until netget is out of memory.
    let chunk = vec![b'A'; 4096];
    let mut written = 0usize;
    for _ in 0..16 {
        if sock.write_all(&chunk).await.is_err() {
            break; // the server has already closed on us, which is the point
        }
        written += chunk.len();
    }
    let _ = sock.flush().await;

    let mut reply = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), sock.read_to_end(&mut reply)).await;
    assert!(
        read.is_ok(),
        "the server never closed the connection after {written} bytes with no newline"
    );

    let reply = String::from_utf8_lossy(&reply);
    assert!(
        reply.starts_with("ERROR :Closing link:"),
        "expected IRC's own ERROR before the close, got {reply:?}"
    );
    assert!(
        !reply.contains("http://") && !reply.contains("127.0.0.1"),
        "the peer must get a category, never an internal detail: {reply:?}"
    );
}

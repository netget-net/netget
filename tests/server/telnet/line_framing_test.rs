//! How the Telnet server frames what arrives on the wire.
//!
//! Both tests cover a defect that was reachable by any peer, with no authentication in front
//! of it, and both run on a **script** handler so nothing here depends on a model.
//!
//! 1. A real `telnet(1)` client opens by sending `IAC DO/WILL …` negotiation. Those bytes are
//!    not valid UTF-8, and the server used to read lines with `BufReader::read_line`, which
//!    validates UTF-8 over the whole line and returns `InvalidData` when it fails — so the
//!    first line the user typed arrived behind that junk, failed to decode, and the read loop
//!    closed the connection. `actions.rs` told the model those bytes "arrive as part of the
//!    first message"; they never did.
//! 2. `read_line` grows its `String` until a newline arrives, so a peer streaming bytes with
//!    no `\n` among them made the server buffer every one of them.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const IAC: u8 = 255;
const SE: u8 = 240;
const SB: u8 = 250;
const WILL: u8 = 251;
const DO: u8 = 253;

/// A telnet server that echoes back the exact `message` the handler was given, and no model
/// involved.
///
/// The echo is the point: a static reply would prove only that *something* arrived, whereas
/// quoting the message back asserts what the stripping left. `instruction: ""` is deliberate
/// — a non-empty instruction makes the server consult the model, so a test that wants zero
/// LLM calls has to say so explicitly.
fn echo_message_config() -> NetGetConfig {
    let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
print(json.dumps({"actions": [
    {"type": "send_telnet_line", "line": "[" + str(event.get("message", "")) + "]"}
]}))"#;

    NetGetConfig::new("listen on port {AVAILABLE_PORT} via telnet").with_mock(move |mock| {
        mock.on_instruction_containing("telnet")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Telnet",
                    "instruction": "",
                    "event_handlers": [{
                        "event_pattern": "telnet_message_received",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": script
                        }
                    }]
                }
            ]))
            .expect_calls(1)
            .and()
    })
}

/// Read until `needle` appears or the deadline passes, so the assertion waits on the
/// condition rather than on a fixed sleep.
async fn read_until<R>(reader: &mut R, needle: &str, secs: u64) -> String
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut buf = [0u8; 1024];
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        match tokio::time::timeout(remaining, reader.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                seen.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&seen).contains(needle) {
                    break;
                }
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }
    String::from_utf8_lossy(&seen).into_owned()
}

/// A real client's negotiation preamble must not cost it the connection, and must not reach
/// the handler as part of the line either.
#[tokio::test]
async fn iac_negotiation_is_stripped_and_the_line_still_arrives() -> E2EResult<()> {
    let server = helpers::start_netget_server(echo_message_config()).await?;

    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (mut read_half, mut write_half) = stream.into_split();

    // What `telnet(1)` actually opens with: three option negotiations, a subnegotiation
    // whose payload contains a byte that would otherwise read as a newline, and then the
    // line the user typed. `IAC DO 10` is the trap — option 10 (NAOCRD) *is* 0x0A, so a
    // reader that split on newlines before stripping IAC would cut the sequence in half.
    let mut preamble: Vec<u8> = vec![
        IAC, DO, 24, // TERMINAL-TYPE
        IAC, WILL, 31, // NAWS
        IAC, DO, 10, // NAOCRD — the option byte is 0x0A
    ];
    preamble.extend_from_slice(&[IAC, SB, 24, 0, b'x', b'\n', b'y', IAC, SE]);
    preamble.extend_from_slice(b"hello\r\n");

    write_half.write_all(&preamble).await?;
    write_half.flush().await?;

    let seen = read_until(&mut read_half, "]", 15).await;

    // The brackets are what make this decisive. Answering *at all* would only show the
    // connection survived; quoting the message back shows the handler was given `hello` and
    // nothing else — no replacement characters standing in for the preamble, and no `x`/`y`
    // from the subnegotiation payload, whose embedded 0x0A would have ended a line had the
    // stripping run after the newline split rather than before it.
    assert!(
        seen.contains("[hello]"),
        "the handler did not receive exactly `hello`. Before this framing, read_line \
         validated UTF-8 across the whole line, failed on the negotiation preamble, and the \
         read loop closed the connection. Saw: {seen:?}"
    );

    // The server does not answer negotiation, and must not echo any IAC byte back.
    assert!(
        !seen.as_bytes().contains(&IAC),
        "an IAC byte reached the wire in the reply: {seen:?}"
    );

    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A peer that never sends a newline must be refused rather than buffered forever.
#[tokio::test]
async fn a_line_with_no_newline_is_bounded_and_refused() -> E2EResult<()> {
    let server = helpers::start_netget_server(echo_message_config()).await?;

    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (mut read_half, mut write_half) = stream.into_split();

    // Comfortably past the 8 KiB cap, and not one newline in it. Written in chunks because
    // the server stops reading partway through and the socket then fills.
    let chunk = vec![b'A'; 4096];
    for _ in 0..8 {
        if write_half.write_all(&chunk).await.is_err() {
            break;
        }
    }
    let _ = write_half.flush().await;

    let seen = read_until(&mut read_half, "line too long", 15).await;
    assert!(
        seen.contains("[netget] line too long"),
        "a peer sending 32 KiB with no newline was not refused; the server buffered it \
         instead. Saw: {seen:?}"
    );
    assert!(
        !seen.contains("[AAA"),
        "an unterminated run of bytes was treated as a line and reached the handler: {seen:?}"
    );

    // The notice is a category, not a diagnosis: nothing about netget's internals goes to
    // the peer. `tests/wire_failure_test.rs` guards the same rule tree-wide.
    assert!(
        !seen.to_lowercase().contains("error"),
        "the refusal leaked something beyond the category: {seen:?}"
    );

    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

//! What an NNTP client gets when the LLM backend fails: a 4xx, never silence and never a 2xx.
//!
//! NNTP is strictly one response line per command, so a missing response does not merely delay
//! the client - it desynchronises the session, because the next command's reply is read as the
//! answer to this one. Both failure points are now answered:
//!
//! * the greeting, where RFC 3977 §5.1 defines `400 service temporarily unavailable` as a legal
//!   greeting, after which the server closes;
//! * any command, answered `403` ("internal fault or problem preventing action being taken"),
//!   which leaves the session usable.
//!
//! Every code here is 4xx. None of them can be confused with 200/201 (ready), 211 (group
//! selected), 220 (article follows) or 281 (authentication accepted).


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| {
            "No NNTP response within 20s - the server went silent on LLM failure, which is the \
             exact defect this test exists to catch"
        })??;
    if n == 0 {
        return Err("NNTP connection closed without a response".into());
    }
    Ok(line)
}

/// The greeting fails: `400`, then EOF.
#[tokio::test]
async fn test_nntp_answers_400_when_greeting_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via nntp. Serve comp.lang.rust";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via nntp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "nntp",
                    "instruction": "Serve comp.lang.rust"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `nntp_command_received`, so the GREETING event fails.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, _write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await?;
    println!("NNTP greeting: {}", greeting.trim());
    assert!(
        greeting.starts_with("400 "),
        "expected 400 (service temporarily unavailable) instead of a 200 that cannot be \
         honoured, got: {greeting}"
    );
    assert!(
        greeting.contains("netget"),
        "the text should name the source of the failure: {greeting}"
    );

    let mut trailing = String::new();
    let n = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut trailing))
        .await
        .map_err(|_| "the server did not close the connection after the 400 greeting")??;
    assert_eq!(n, 0, "expected EOF after 400, got: {trailing}");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A command fails after a good greeting: `403`, and the session stays open.
#[tokio::test]
async fn test_nntp_answers_403_when_command_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via nntp. Greet, then serve comp.lang.rust";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via nntp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "nntp",
                    "instruction": "Greet, then serve comp.lang.rust"
                }
            ]))
            .expect_calls(1)
            .and()
            // Only the greeting is answered. LIST is not.
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "GREETING")
            .respond_with_actions(serde_json::json!([
                {"type": "send_nntp_response", "code": 200, "text": "NetGet NNTP ready"}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await?;
    println!("NNTP greeting: {}", greeting.trim());
    assert!(
        greeting.starts_with("200 "),
        "expected the mocked 200 greeting, got: {greeting}"
    );

    write_half.write_all(b"LIST\r\n").await?;
    write_half.flush().await?;

    let reply = read_line(&mut reader).await?;
    println!("NNTP LIST reply: {}", reply.trim());
    assert!(
        reply.starts_with("403 "),
        "expected 403 (internal fault) for a command the backend could not answer, got: {reply}"
    );
    assert!(
        !reply.starts_with('2'),
        "a backend failure must never be reported as success: {reply}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The greeting comes back *empty*: `400`, then EOF.
///
/// This is the hole the two tests above do not cover. An answer with no actions in it is not an
/// error - `call_llm` returns `Ok` with no protocol results and no failures - so the greeting
/// branch used to write nothing at all and the connection sat in the read loop forever, with
/// the client blocked on a banner that was never coming. A zero-action static handler is the
/// cleanest way to produce that state; a manual "answer with nothing" and an empty model reply
/// arrive at the same place.
#[tokio::test]
async fn test_nntp_answers_400_when_greeting_answer_is_empty() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via nntp. Serve comp.lang.rust";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via nntp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "nntp",
                    "instruction": "Serve comp.lang.rust",
                    "event_handlers": [{
                        "event_pattern": "nntp_command_received",
                        "handler": { "type": "static", "actions": [] }
                    }]
                }
            ]))
            .expect_calls(1)
            .and()
        // Every event is answered by the zero-action static handler, so the LLM is
        // never consulted again - including for the greeting.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, _write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await?;
    println!("NNTP greeting: {}", greeting.trim());
    assert!(
        greeting.starts_with("400 "),
        "an answer with no greeting in it is a session that can never start; expected 400, \
         got: {greeting}"
    );
    assert!(
        !greeting.contains("403 netget: could not build"),
        "the reply must carry a category, not netget's internals: {greeting}"
    );

    let mut trailing = String::new();
    let n = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut trailing))
        .await
        .map_err(|_| "the server did not close the connection after the 400 greeting")??;
    assert_eq!(n, 0, "expected EOF after 400, got: {trailing}");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A command is answered with *no actions*: `403`, and the session stays open.
///
/// Same hole, per command, and worse there: NNTP is one response line per command, so a
/// command that draws no reply desynchronises everything after it - the client reads the next
/// command's answer as this one's. The script below greets normally and then deliberately
/// answers `[]`, which is exactly what a model returning an empty array, a manual "answer with
/// nothing" or a zero-action static rule produce. Zero LLM calls after startup.
#[tokio::test]
async fn test_nntp_answers_403_when_command_answer_is_empty() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via nntp. Greet, then serve comp.lang.rust";

    // Scripts are run raw (`python3 -c`) and speak JSON over stdin/stdout - there is no
    // `event`/`respond()` prelude, whatever the startup examples suggest.
    let script = r#"import sys, json
inp = json.load(sys.stdin)
cmd = inp.get('event', {}).get('command', '').upper()
if cmd == 'GREETING':
    print(json.dumps({'actions': [{'type': 'send_nntp_response', 'code': 200, 'text': 'NetGet NNTP ready'}]}))
else:
    print(json.dumps({'actions': []}))
"#;

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via nntp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "nntp",
                    "instruction": "Greet, then serve comp.lang.rust",
                    "event_handlers": [{
                        "event_pattern": "nntp_command_received",
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
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await?;
    println!("NNTP greeting: {}", greeting.trim());
    assert!(
        greeting.starts_with("200 "),
        "expected the script's 200 greeting, got: {greeting}"
    );

    write_half.write_all(b"LIST\r\n").await?;
    write_half.flush().await?;

    let reply = read_line(&mut reader).await?;
    println!("NNTP LIST reply: {}", reply.trim());
    assert!(
        reply.starts_with("403 "),
        "a command answered with no actions must still get a response line, or the session \
         desynchronises; got: {reply}"
    );
    assert!(
        !reply.starts_with('2'),
        "an empty answer must never be reported as success: {reply}"
    );

    // The session survives a 403, so a second command is still answered.
    write_half.write_all(b"QUIT\r\n").await?;
    write_half.flush().await?;
    let second = read_line(&mut reader).await?;
    println!("NNTP QUIT reply: {}", second.trim());
    assert!(
        second.starts_with("403 "),
        "the session must stay usable after a 403, got: {second}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

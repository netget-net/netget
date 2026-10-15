//! Two CQL requests the server used to answer by dropping the socket.
//!
//! Both took the `Err(e)` exit out of `handle_frame`, which set `closing = true` under a
//! comment reading "send error frame and close connection" and then sent nothing. A driver
//! blocks on the reply to every request it issues, so the vanishing socket surfaced as a
//! *transport* fault: the session died and neither end recorded why.
//!
//! 1. **EXECUTE naming a statement id the connection has not prepared.** Reachable in ordinary
//!    use — ids are a hash of the query text held per connection, so a driver executing on a
//!    pooled connection that never saw the PREPARE lands here, as does one reconnecting. CQL
//!    has an error for exactly this: UNPREPARED (0x2500), whose body carries the unknown id so
//!    the driver can re-PREPARE and retry. scylla does precisely that, which turns a dead
//!    session into a hiccup.
//!
//! 2. **A frame that cannot be parsed at all.** PROTOCOL_ERROR (0x000A) is what a real
//!    coordinator answers. The stream id lives at bytes 2..4 of the header and does not depend
//!    on the body parsing, so the reply reaches the right request even when nothing else about
//!    the frame could be understood.
//!
//! Frames are built and decoded against the native protocol v4 spec rather than through
//! `scylla`, for the reason `llm_failure_test.rs` gives: a driver cannot be got to the point
//! of issuing a deliberately-bogus statement id, and the assertion is about one opcode and one
//! four-byte code.


use crate::helpers::server::NetGetServer;
use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn frame(opcode: u8, stream_id: i16, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.push(0x04); // version 4, request direction
    f.push(0x00); // flags
    f.extend_from_slice(&stream_id.to_be_bytes());
    f.push(opcode);
    f.extend_from_slice(&(body.len() as u32).to_be_bytes());
    f.extend_from_slice(body);
    f
}

fn build_startup(stream_id: i16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_be_bytes());
    for s in ["CQL_VERSION", "3.0.0"] {
        body.extend_from_slice(&(s.len() as u16).to_be_bytes());
        body.extend_from_slice(s.as_bytes());
    }
    frame(0x01, stream_id, &body)
}

/// EXECUTE: `[short bytes] id`, `[short] consistency`, `[byte] flags`.
fn build_execute(stream_id: i16, statement_id: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(statement_id.len() as u16).to_be_bytes());
    body.extend_from_slice(statement_id);
    body.extend_from_slice(&0x0001u16.to_be_bytes()); // consistency ONE
    body.push(0x00); // no flags, so no bound values
    frame(0x0A, stream_id, &body)
}

struct Reply {
    stream_id: i16,
    opcode: u8,
    body: Vec<u8>,
}

async fn read_frame(stream: &mut TcpStream, what: &str) -> E2EResult<Reply> {
    let mut header = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(25), stream.read_exact(&mut header))
        .await
        .map_err(|_| {
            format!(
                "no CQL frame within 25s while waiting for {what} — the server closed the \
                 connection instead of answering, which is the defect this test exists to catch"
            )
        })??;
    assert_eq!(
        header[0] & 0x80,
        0x80,
        "the high bit marks a response frame: {header:02x?}"
    );
    let body_len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    let mut body = vec![0u8; body_len];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .map_err(|_| format!("the {what} header arrived but its body did not"))??;
    Ok(Reply {
        stream_id: i16::from_be_bytes([header[2], header[3]]),
        opcode: header[4],
        body,
    })
}

/// A server whose STARTUP is answered by a static handler, so the exchange costs no LLM call
/// and the mock needs only the one rule that starts it.
async fn cql_server() -> E2EResult<NetGetServer> {
    let prompt = "Start a Cassandra/CQL database server on port {AVAILABLE_PORT}.";
    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Cassandra")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "Cassandra",
                "instruction": "CQL server",
                "event_handlers": [{
                    "event_pattern": "cassandra_startup",
                    "handler": {
                        "type": "static",
                        "actions": [{"type": "cassandra_ready"}]
                    }
                }]
            }]))
            .expect_calls(1)
            .and()
    });
    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(server)
}

#[tokio::test]
async fn execute_with_an_unknown_statement_id_answers_unprepared() -> E2EResult<()> {
    let server = cql_server().await?;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;

    stream.write_all(&build_startup(1)).await?;
    stream.flush().await?;
    let ready = read_frame(&mut stream, "READY").await?;
    assert_eq!(
        ready.opcode, 0x02,
        "expected READY, got {:02x}",
        ready.opcode
    );

    // An id no PREPARE on this connection produced.
    const UNKNOWN_ID: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];
    const STREAM_ID: i16 = 0x0123;
    stream
        .write_all(&build_execute(STREAM_ID, UNKNOWN_ID))
        .await?;
    stream.flush().await?;

    let reply = read_frame(&mut stream, "the UNPREPARED error").await?;
    assert_eq!(
        reply.stream_id, STREAM_ID,
        "the frame must echo the stream id or the driver cannot correlate it"
    );
    assert_eq!(
        reply.opcode, 0x00,
        "expected opcode 0x00 (ERROR), got {:02x}",
        reply.opcode
    );

    let code = u32::from_be_bytes([reply.body[0], reply.body[1], reply.body[2], reply.body[3]]);
    assert_eq!(
        code, 0x2500,
        "expected UNPREPARED (0x2500) so the driver re-prepares; 0x{code:04X} leaves it with \
         no way to recover"
    );

    // `[int code][string message][short bytes id]` — a driver reads the trailing id
    // unconditionally, so omitting it is a framing fault rather than a shorter answer.
    let msg_len = u16::from_be_bytes([reply.body[4], reply.body[5]]) as usize;
    let mut at = 6 + msg_len;
    let id_len = u16::from_be_bytes([reply.body[at], reply.body[at + 1]]) as usize;
    at += 2;
    assert_eq!(
        &reply.body[at..at + id_len],
        UNKNOWN_ID,
        "the body must carry back the id the driver asked about, or it cannot tell which \
         statement to re-prepare"
    );
    assert_eq!(
        at + id_len,
        reply.body.len(),
        "nothing may follow the id: {:02x?}",
        reply.body
    );

    // The session survives: the whole point of UNPREPARED over a dropped socket.
    stream.write_all(&build_startup(2)).await?;
    stream.flush().await?;
    let after = read_frame(&mut stream, "a frame after the UNPREPARED error").await?;
    assert_eq!(after.stream_id, 2);

    server.verify_mocks().await?;
    Ok(())
}

#[tokio::test]
async fn an_unparseable_frame_answers_protocol_error() -> E2EResult<()> {
    let server = cql_server().await?;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;

    // A truncated EXECUTE: the declared body length is honest, so the frame is read whole,
    // but the statement-id length runs past its end. `parse_execute` rejects it.
    const STREAM_ID: i16 = 0x0456;
    let body = vec![0xFF, 0xFF, 0x01, 0x02];
    stream.write_all(&frame(0x0A, STREAM_ID, &body)).await?;
    stream.flush().await?;

    let reply = read_frame(&mut stream, "the PROTOCOL_ERROR").await?;
    assert_eq!(
        reply.stream_id, STREAM_ID,
        "the stream id comes from the header, which parses even when the body does not"
    );
    assert_eq!(
        reply.opcode, 0x00,
        "expected opcode 0x00 (ERROR), got {:02x}",
        reply.opcode
    );

    let code = u32::from_be_bytes([reply.body[0], reply.body[1], reply.body[2], reply.body[3]]);
    assert_eq!(code, 0x000A, "expected PROTOCOL_ERROR, got 0x{code:04X}");

    let msg_len = u16::from_be_bytes([reply.body[4], reply.body[5]]) as usize;
    let message = String::from_utf8_lossy(&reply.body[6..6 + msg_len]).to_string();
    assert!(
        message.contains("netget"),
        "the message should name its source: {message}"
    );
    // The peer gets a category, never the internal error text — no anyhow context, no
    // library message, no field names from our parser.
    assert!(
        !message.contains("truncated") && !message.contains("statement ID"),
        "the reply leaked our own parser's wording: {message}"
    );

    server.verify_mocks().await?;
    Ok(())
}

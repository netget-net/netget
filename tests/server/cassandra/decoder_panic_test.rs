//! Three CQL headers that panic `cassandra-protocol` 3.3.0's `Envelope::from_buffer`, sent to
//! the running server over its real socket.
//!
//! Each is a header bit the peer chooses on its very first frame, before STARTUP:
//!
//! 1. **The tracing flag on a frame whose direction bit says "response".** `from_buffer` then
//!    reads a 16-byte tracing id with `read_exact(..).unwrap()` (`frame.rs:187`); a zero-length
//!    body panics.
//! 2. **The warning flag with a negative `[string list]` count.** `Vec::with_capacity(len as
//!    usize)` on an `i16` (`types.rs:267`) — `-1` is `usize::MAX` elements, a `capacity
//!    overflow` panic.
//! 3. **The warning flag with a string longer than the body.** `cursor_next_value_ref` slices
//!    `[start..start + len]` before it checks the length (`types.rs:485`).
//!
//! A panic there is inside the connection task, so `tokio::spawn` swallows it: the server stays
//! `Running`, the peer's socket simply closes, and no reply ever says why. What the server must
//! do instead is what it does for any other unparseable frame — answer PROTOCOL_ERROR (0x000A)
//! on the frame's own stream id — and keep serving everyone else. The guard is
//! `netget::server::cassandra::parse_request_frame`, which refuses both header bits on a
//! request (neither means anything there) before the decoder runs.
//!
//! Every exchange here is answered without the model: STARTUP by a static rule, and the refused
//! frames by the protocol-error path, so the mock carries only the rule that starts the server.

use crate::helpers::server::NetGetServer;
use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A raw frame: version byte, flags, stream id, opcode, declared body length, body.
fn raw_frame(version: u8, flags: u8, stream_id: i16, opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut f = vec![version, flags];
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
    raw_frame(0x04, 0x00, stream_id, 0x01, &body)
}

struct Reply {
    stream_id: i16,
    opcode: u8,
    body: Vec<u8>,
}

async fn read_frame(stream: &mut TcpStream, what: &str) -> E2EResult<Reply> {
    let mut header = [0u8; 9];
    match tokio::time::timeout(Duration::from_secs(25), stream.read_exact(&mut header)).await {
        Err(_) => return Err(format!("no CQL frame within 25s while waiting for {what}").into()),
        Ok(Err(e)) => {
            return Err(format!(
                "the server closed the connection instead of answering {what} ({e}) — the \
                 connection task died inside the decoder, which is the defect this test exists \
                 to catch"
            )
            .into())
        }
        Ok(Ok(_)) => {}
    }
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

/// Send `frame` on a fresh connection and require PROTOCOL_ERROR on `stream_id`.
async fn expect_protocol_error(
    server: &NetGetServer,
    case: &str,
    frame: &[u8],
    stream_id: i16,
) -> E2EResult<()> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    stream.write_all(frame).await?;
    stream.flush().await?;
    let reply = read_frame(&mut stream, case).await?;
    assert_eq!(reply.stream_id, stream_id, "{case}: wrong stream id");
    assert_eq!(
        reply.opcode, 0x00,
        "{case}: expected ERROR, got {:02x}",
        reply.opcode
    );
    let code = u32::from_be_bytes([reply.body[0], reply.body[1], reply.body[2], reply.body[3]]);
    assert_eq!(
        code, 0x000A,
        "{case}: expected PROTOCOL_ERROR, got 0x{code:04X}"
    );
    let msg_len = u16::from_be_bytes([reply.body[4], reply.body[5]]) as usize;
    let message = String::from_utf8_lossy(&reply.body[6..6 + msg_len]).to_string();
    assert!(
        !message.contains("refused before decoding") && !message.contains("flag"),
        "{case}: the reply leaked the log's wording: {message}"
    );
    Ok(())
}

#[tokio::test]
async fn panicking_cql_headers_are_refused_and_the_server_keeps_serving() -> E2EResult<()> {
    let server = cql_server().await?;

    // 1. Version byte 0x84 = v4 with the response bit; flags 0x02 = tracing; no body.
    expect_protocol_error(
        &server,
        "a response frame with the tracing flag and no tracing id",
        &raw_frame(0x84, 0x02, 0x0071, 0x07, &[]),
        0x0071,
    )
    .await?;

    // 2. Flags 0x08 = warning; the string list's count is 0xFFFF = -1.
    expect_protocol_error(
        &server,
        "a warning list with a negative count",
        &raw_frame(0x04, 0x08, 0x0072, 0x01, &[0xFF, 0xFF]),
        0x0072,
    )
    .await?;

    // 3. One warning whose declared length (16) runs past the two bytes that follow.
    expect_protocol_error(
        &server,
        "a warning string longer than the body",
        &raw_frame(
            0x04,
            0x08,
            0x0073,
            0x01,
            &[0x00, 0x01, 0x00, 0x10, b'x', b'y'],
        ),
        0x0073,
    )
    .await?;

    // The server is still up and still answers an ordinary client.
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    stream.write_all(&build_startup(9)).await?;
    stream.flush().await?;
    let ready = read_frame(&mut stream, "READY after the refused frames").await?;
    assert_eq!(ready.stream_id, 9);
    assert_eq!(
        ready.opcode, 0x02,
        "expected READY, got {:02x}",
        ready.opcode
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

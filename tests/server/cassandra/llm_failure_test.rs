//! What a CQL client gets when the LLM backend fails: a native-protocol ERROR frame.
//!
//! All six of Cassandra's LLM entry points - STARTUP, OPTIONS, QUERY, PREPARE, EXECUTE and
//! AUTH_RESPONSE - propagated the error with `?`, which dropped the connection with nothing
//! written. A driver blocks on the response to every request it sends, so that read as a
//! network fault rather than a server error.
//!
//! ERROR is the protocol's own answer. It matters that it is not a RESULT frame: an empty
//! Rows result is a perfectly ordinary CQL answer meaning "no rows matched", so a failure that
//! produced one would be a statement about the data.
//!
//! 0x0000 is "Server error"; 0x1001 "Overloaded" is reserved for capacity exhaustion, which
//! every driver already treats as retryable. Deliberately *not* 0x0100 "Bad credentials" on
//! the AUTH_RESPONSE path - the credentials were never looked at, and saying they were bad
//! would stop a driver retrying with correct ones.
//!
//! The frame here is built and decoded against the native protocol v4 spec rather than with
//! the `scylla` driver, because a driver cannot be got as far as a session without answering
//! its whole startup conversation, and the assertion is about a specific opcode and a specific
//! four-byte code.

use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Native protocol v4 STARTUP: a request frame whose body is a [string map].
fn build_startup(stream_id: i16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_be_bytes()); // one entry
    for s in ["CQL_VERSION", "3.0.0"] {
        body.extend_from_slice(&(s.len() as u16).to_be_bytes());
        body.extend_from_slice(s.as_bytes());
    }

    let mut frame = Vec::new();
    frame.push(0x04); // version 4, request direction
    frame.push(0x00); // flags
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.push(0x01); // opcode STARTUP
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

#[tokio::test]
async fn test_cassandra_answers_error_frame_when_llm_fails() -> E2EResult<()> {
    let prompt = "Start a Cassandra/CQL database server on port {AVAILABLE_PORT}.";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Cassandra")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Cassandra",
                    "instruction": "CQL server"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `cassandra_startup`.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    const STREAM_ID: i16 = 0x0042;
    stream.write_all(&build_startup(STREAM_ID)).await?;
    stream.flush().await?;

    let mut header = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(25), stream.read_exact(&mut header))
        .await
        .map_err(|_| {
            "No CQL frame within 25s - the server went silent on LLM failure, which is the \
             exact defect this test exists to catch"
        })??;
    println!("CQL response header: {header:02x?}");

    assert_eq!(
        header[0] & 0x80,
        0x80,
        "the high bit marks a response frame: {header:02x?}"
    );
    assert_eq!(
        i16::from_be_bytes([header[2], header[3]]),
        STREAM_ID,
        "the frame must echo the stream id or the driver cannot correlate it: {header:02x?}"
    );
    assert_eq!(
        header[4], 0x00,
        "expected opcode 0x00 (ERROR). 0x02 (READY) or 0x08 (RESULT) here would tell the \
         client the request succeeded: {header:02x?}"
    );

    let body_len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    let mut body = vec![0u8; body_len];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .map_err(|_| "the ERROR frame header arrived but its body did not")??;

    let code = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let msg_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    let message = String::from_utf8_lossy(&body[6..6 + msg_len]).to_string();
    println!("CQL ERROR 0x{code:04X}: {message}");

    assert!(
        code == 0x0000 || code == 0x1001,
        "expected Server error (0x0000) or Overloaded (0x1001), got 0x{code:04X}"
    );
    assert_ne!(
        code, 0x0100,
        "0x0100 is Bad credentials, which misattributes our failure to the client"
    );
    assert!(
        message.contains("netget"),
        "the message should name the source of the failure: {message}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

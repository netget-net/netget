//! E2E tests for TCP protocol examples
//!
//! These tests verify that TCP protocol examples work correctly:
//! - StartupExamples (llm_mode, script_mode, static_mode) start servers
//! - EventType response_examples execute correctly
//! - Connection events trigger and respond properly

use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The `response_example` the TCP protocol actually ships for `event_id`.
///
/// These tests exist to prove the shipped literals work, so they must read them from the
/// registry rather than keep a copy. A copy is what let `tcp_data_received` drift: the test
/// carried `{"data": "48656c6c6f"}` while the protocol had gained an explicit
/// `"encoding": "hex"` field, so the test's version would have put the ten characters
/// `48656c6c6f` on the wire instead of the five bytes `Hello`.
fn shipped_response_example(event_id: &str) -> serde_json::Value {
    use netget::llm::actions::protocol_trait::Protocol;
    use netget::server::TcpProtocol;

    TcpProtocol::new()
        .get_event_types()
        .into_iter()
        .find(|e| e.id == event_id)
        .unwrap_or_else(|| panic!("TCP declares no event type '{event_id}'"))
        .response_example
}

/// The bytes a `send_tcp_data` action puts on the wire, per its `encoding` field.
///
/// Mirrors `src/server/tcp/actions.rs`: `"utf8"` (or absent) sends the string verbatim, `"hex"`
/// decodes it. Duplicating the rule here is deliberate — if the server's implementation and the
/// documented contract diverge again (they did once: the executor ignored `encoding` entirely
/// and an echo server could not echo), this is what notices.
fn expected_wire_bytes(response_example: &serde_json::Value) -> Vec<u8> {
    let data = response_example["data"]
        .as_str()
        .expect("send_tcp_data response_example must carry a string 'data'");
    match response_example.get("encoding").and_then(|e| e.as_str()) {
        None | Some("utf8") => data.as_bytes().to_vec(),
        Some("hex") => (0..data.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&data[i..i + 2], 16)
                    .expect("hex response_example must be valid hex")
            })
            .collect(),
        Some(other) => panic!("unknown encoding {other:?} in a shipped response_example"),
    }
}

/// Test TCP protocol response_example for tcp_connection_opened event
///
/// This test verifies that the tcp_connection_opened response_example
/// (sending a welcome banner) works correctly when triggered by a connection.
#[tokio::test]
async fn example_test_tcp_connection_opened() -> E2EResult<()> {
    println!("\n=== E2E Example Test: TCP tcp_connection_opened ===");

    // The response_example for tcp_connection_opened is:
    // {"type": "send_tcp_data", "data": "220 Welcome to server\r\n"}

    let config = NetGetConfig::new("Start a TCP server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Start a TCP server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TCP",
                    "instruction": "Send welcome banner on connection",
                    // `tcp_connection_opened` is raised only by `send_first` servers
                    // (src/server/tcp/mod.rs::send_greeting). Without this the event never
                    // fires and no banner is ever sent - which is what this test found the
                    // first time it was able to fail.
                    "startup_params": {"send_first": true}
                }]))
                .and()
                // Mock 2: Connection opened event.
                // The literal comes from the protocol, so this test fails if the shipped
                // example stops working rather than testing a stale copy of it.
                .on_event("tcp_connection_opened")
                .respond_with_actions(shipped_response_example("tcp_connection_opened"))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("TCP server started on port {}", port);

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Connect to trigger the tcp_connection_opened event
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
    println!("Connected to TCP server");

    // Try to read the welcome banner
    // Every outcome other than "the banner arrived" is a failure. The three non-success arms
    // used to print a "⚠ ... may be expected" note and fall through, which made this test
    // unable to fail for the thing it exists to check.
    let expected = expected_wire_bytes(&shipped_response_example("tcp_connection_opened"));
    let mut buf = vec![0u8; 1024];
    let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        Ok(Ok(_)) => panic!(
            "server closed the connection without sending the tcp_connection_opened \
             response_example"
        ),
        Ok(Err(e)) => panic!("read failed while waiting for the welcome banner: {e}"),
        Err(_) => panic!(
            "timed out after 5s waiting for the tcp_connection_opened response_example; the \
             banner was never sent"
        ),
    };
    assert_eq!(
        &buf[..n],
        expected.as_slice(),
        "wire bytes differ from the shipped response_example. got {:?}, want {:?}",
        String::from_utf8_lossy(&buf[..n]),
        String::from_utf8_lossy(&expected)
    );
    println!("✓ tcp_connection_opened response_example executed correctly");

    // Verify mock expectations
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

/// Test TCP protocol response_example for tcp_data_received event
///
/// This test verifies that the tcp_data_received response_example
/// (echo response) works correctly when data is sent.
#[tokio::test]
async fn example_test_tcp_data_received() -> E2EResult<()> {
    println!("\n=== E2E Example Test: TCP tcp_data_received ===");

    // The response_example for tcp_data_received is:
    // {"type": "send_tcp_data", "data": "48656c6c6f"} (hex for "Hello")

    let config = NetGetConfig::new("Start a TCP server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Start a TCP server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TCP",
                    "instruction": "Echo received data"
                }]))
                .and()
                // Mock 2: Connection opened (may trigger first)
                .on_event("tcp_connection_opened")
                .respond_with_actions(json!({
                    "type": "wait_for_more"
                }))
                .and()
                // Mock 3: Data received event.
                // Taken from the protocol; the hardcoded copy that used to live here had
                // already drifted (it omitted "encoding": "hex", so it would have sent the ten
                // characters 48656c6c6f rather than the five bytes Hello).
                .on_event("tcp_data_received")
                .respond_with_actions(shipped_response_example("tcp_data_received"))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("TCP server started on port {}", port);

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Connect and send data
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
    println!("Connected to TCP server");

    // Send test data
    stream.write_all(b"Test data").await?;
    stream.flush().await?;
    println!("Sent: Test data");

    // Read the response. All four arms used to be non-fatal - three printed
    // "⚠ ... may be expected in mock mode" and the success arm asserted nothing about the
    // payload - and then mock verification was itself skipped unless data had arrived. The
    // test passed whether the server echoed correctly, closed without data, errored, or timed
    // out; there was no outcome it could fail on.
    let expected = expected_wire_bytes(&shipped_response_example("tcp_data_received"));
    let mut buf = vec![0u8; 1024];
    let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        Ok(Ok(_)) => {
            panic!("server closed the connection without sending the tcp_data_received response")
        }
        Ok(Err(e)) => panic!("read failed while waiting for the echo: {e}"),
        Err(_) => panic!(
            "timed out after 5s waiting for the tcp_data_received response_example; nothing \
             was written back"
        ),
    };
    assert_eq!(
        &buf[..n],
        expected.as_slice(),
        "wire bytes differ from the shipped response_example. got {:?}, want {:?}. A mismatch \
         of exactly \"48656c6c6f\" vs \"Hello\" means the 'encoding' field was not honoured.",
        String::from_utf8_lossy(&buf[..n]),
        String::from_utf8_lossy(&expected)
    );
    println!("✓ tcp_data_received response_example executed correctly");

    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

/// Test TCP startup examples (llm_mode)
///
/// Verifies that the LLM mode startup example starts a server correctly.
#[tokio::test]
async fn example_test_tcp_startup_llm_mode() -> E2EResult<()> {
    println!("\n=== E2E Example Test: TCP Startup (LLM Mode) ===");

    // Use the LLM mode startup example format
    let config = NetGetConfig::new("Start a TCP server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("Start a TCP server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TCP",
                    "instruction": "Respond to each connection with a greeting",
                    "startup_params": {"send_first": true}
                }]))
                .and()
                .on_event("tcp_connection_opened")
                .respond_with_actions(json!({
                    "type": "send_tcp_data",
                    "data": "Hello from LLM mode!"
                }))
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;

    assert!(port > 0, "Server should have started on a port");
    println!(
        "✓ TCP server started successfully on port {} using LLM mode",
        port
    );

    // Verify by connecting
    let _stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
    println!("✓ Successfully connected to TCP server");

    server.verify_mocks().await?;
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}

/// Test TCP startup examples (static_mode)
///
/// Static handlers are the documented way to answer an event with no LLM round-trip, so this
/// asserts the whole path: the server starts, a connection triggers `tcp_connection_opened`,
/// the static action lands on the wire, and the LLM is consulted **exactly once** (for startup)
/// — that last part being the entire point of a static handler.
///
/// It used to assert none of it. Every branch printed a note and fell through: a server that
/// failed to start printed "⚠ Server did not start ... (static mode may have limitations)"
/// followed by "✓ Mock response format was correct", and a static handler that produced nothing
/// printed "⚠ No response from static handler (implementation may differ)". The test could not
/// fail, and "may have limitations" is not a test result.
#[tokio::test]
async fn example_test_tcp_startup_static_mode() -> E2EResult<()> {
    println!("\n=== E2E Example Test: TCP Startup (Static Mode) ===");

    const STATIC_BANNER: &str = "Static response\r\n";

    let config = NetGetConfig::new("Start a TCP server on port 0 with static handler")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("Start a TCP server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TCP",
                    "instruction": "Send static greeting on connection",
                    // See the note in example_test_tcp_connection_opened: without
                    // send_first the tcp_connection_opened event never fires, so the static
                    // handler below would never run.
                    "startup_params": {"send_first": true},
                    "event_handlers": [{
                        "event_pattern": "tcp_connection_opened",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_tcp_data",
                                "data": STATIC_BANNER
                            }]
                        }
                    }]
                }]))
                // Startup only. A static handler that fell through to the LLM would make this
                // 2 and fail, which is the regression worth guarding.
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    assert!(port > 0, "static-mode server must bind a real port");
    println!("✓ TCP server started on port {port} using static mode");

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await?;
    let mut buf = vec![0u8; 1024];
    let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        Ok(Ok(_)) => panic!("server closed the connection without running the static handler"),
        Ok(Err(e)) => panic!("read failed while waiting for the static handler output: {e}"),
        Err(_) => panic!(
            "timed out after 5s waiting for the static handler; the tcp_connection_opened \
             event_handler declared at startup never produced any bytes"
        ),
    };
    let response = String::from_utf8_lossy(&buf[..n]);
    assert_eq!(
        response, STATIC_BANNER,
        "static handler must put its declared action on the wire verbatim"
    );
    println!("✓ Static handler executed correctly");

    server.verify_mocks().await?;
    server.stop().await?;

    println!("=== Test completed ===\n");
    Ok(())
}

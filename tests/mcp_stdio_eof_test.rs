//! A caller that writes its requests and closes stdin must still get every answer.
//!
//! rmcp's serve loop stops the moment its input ends, and a tool call still being handled at that
//! moment has its response dropped. `netget --mcp` wraps its stdio transport in
//! `mcp_stdio::drain::DrainOnEof`, which reports the end of input only once every request it
//! received has been answered. This drives both transports over in-memory pipes with the same
//! bytes a shell pipeline sends: `initialize`, `initialized`, one `tools/call`, then EOF.
//!
//! The runtime is single-threaded on purpose. There the loop sees the end of input before the
//! spawned tool handler has run at all, so the unwrapped transport loses the answer every time
//! (the control) rather than only when a race goes the wrong way, and the wrapped one keeps it
//! because waiting for the answer is what lets the handler run.

#![cfg(feature = "mcp-stdio")]

use clap::Parser;
use netget::cli::Args;
use netget::mcp_stdio::drain::drain_on_eof_transport;
use netget::mcp_stdio::tools::NetGetMcpService;
use netget::settings::Settings;
use rmcp::transport::async_rw::AsyncRwTransport;
use rmcp::ServiceExt;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const REQUESTS: &str = concat!(
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"eof-test","version":"1"}}}"#,
    "\n",
    r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    "\n",
    r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_protocols","arguments":{}}}"#,
    "\n",
);

/// Serve one session over pipes, send `REQUESTS`, close the input, and return every line the
/// server wrote before it stopped.
async fn run_session(drain: bool) -> Vec<serde_json::Value> {
    let args = Args::parse_from(["netget"]);
    let service = NetGetMcpService::new(&args, Settings::default())
        .await
        .expect("service creation");

    let (mut to_server, server_in): (DuplexStream, DuplexStream) = tokio::io::duplex(1 << 20);
    let (server_out, mut from_server): (DuplexStream, DuplexStream) = tokio::io::duplex(1 << 20);

    let server = tokio::spawn(async move {
        if drain {
            if let Ok(running) = service
                .serve(drain_on_eof_transport(server_in, server_out))
                .await
            {
                let _ = running.waiting().await;
            }
        } else if let Ok(running) = service
            .serve(AsyncRwTransport::new_server(server_in, server_out))
            .await
        {
            let _ = running.waiting().await;
        }
    });

    to_server
        .write_all(REQUESTS.as_bytes())
        .await
        .expect("write requests");
    // EOF, exactly what `printf ... | netget --mcp` does after its last line.
    drop(to_server);

    let mut output = String::new();
    tokio::time::timeout(
        Duration::from_secs(60),
        from_server.read_to_string(&mut output),
    )
    .await
    .expect("the server must stop once its input has ended")
    .expect("read server output");
    server.await.expect("server task");

    output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}")))
        .collect()
}

fn answered(lines: &[serde_json::Value], id: u64) -> bool {
    lines
        .iter()
        .any(|l| l.get("id").and_then(|v| v.as_u64()) == Some(id))
}

#[tokio::test(flavor = "current_thread")]
async fn a_request_in_flight_when_stdin_closes_is_still_answered() {
    // Control: rmcp's transport as it comes. If this ever answers request 2, rmcp has started
    // draining by itself and the wrapper below is no longer what makes the second assertion pass.
    let unwrapped = run_session(false).await;
    assert!(
        answered(&unwrapped, 1),
        "control: initialize is answered during the handshake either way: {unwrapped:?}"
    );
    assert!(
        !answered(&unwrapped, 2),
        "CONTROL: the unwrapped transport answered the tools/call it was expected to drop, so \
         this test no longer shows what DrainOnEof fixes: {unwrapped:?}"
    );

    let wrapped = run_session(true).await;
    assert!(
        answered(&wrapped, 1),
        "initialize must be answered: {wrapped:?}"
    );
    let reply = wrapped
        .iter()
        .find(|l| l.get("id").and_then(|v| v.as_u64()) == Some(2))
        .unwrap_or_else(|| {
            panic!("the tools/call received before stdin closed was never answered: {wrapped:?}")
        });
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("Server Protocols"),
        "the answer must be list_protocols' own result, got: {reply}"
    );
}

//! A `{"type":"llm","instruction":"…"}` event handler must actually reach the model.
//!
//! `src/llm/event_handler_executor.rs` parsed the instruction, logged it, and dropped it
//! behind a `// TODO`, while the MCP `start_server` / `start_client` tool schemas
//! advertised the handler shape. An MCP caller could therefore configure a per-event
//! instruction, receive no error, and silently get the server-wide instruction instead.
//!
//! This test asserts against the prompt the mock actually received, not merely that a
//! call happened: rule 1 matches only if the per-event instruction is present in the
//! prompt, and rule 2 (a catch-all for the same event, `expect_calls(0)`) fires if it is
//! not. A regression fails both expectations.
//!
//! ```bash
//! ./cargo-isolated.sh test --no-default-features --features tcp \
//!   --test event_handler_llm_instruction_test -- --test-threads=100
//! ```

mod helpers;

use crate::helpers::{E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Distinctive enough that it can only have come from the handler configuration.
const HANDLER_INSTRUCTION: &str =
    "PER-EVENT-HANDLER-INSTRUCTION-9f3a: reply with the single word HANDLED";

/// Deliberately different from the handler instruction, so a prompt carrying only this
/// one proves the per-event instruction was dropped.
const SERVER_INSTRUCTION: &str = "SERVER-WIDE-INSTRUCTION-0000: reply with IGNORED";

#[tokio::test]
async fn llm_event_handler_instruction_reaches_the_model() -> E2EResult<()> {
    let prompt = "start a tcp listener for the handler-instruction test";

    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // 1. User command → open a TCP server whose tcp_data_received event is
            //    handled by an explicit LLM handler carrying its own instruction.
            .on_instruction_containing("handler-instruction test")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "protocol": "tcp",
                    "instruction": SERVER_INSTRUCTION,
                    "event_handlers": [
                        {
                            "event_pattern": "tcp_data_received",
                            "handler": {
                                "type": "llm",
                                "instruction": HANDLER_INSTRUCTION
                            }
                        }
                    ]
                }
            ]))
            .expect_calls(1)
            .and()
            // 2. The network event: matches ONLY if the handler instruction is in the
            //    prompt the model received.
            .on_prompt_containing(HANDLER_INSTRUCTION)
            .respond_with_actions(serde_json::json!([
                { "type": "send_tcp_data", "data": "HANDLED", "encoding": "utf8" }
            ]))
            .expect_calls(1)
            .and()
            // 3. Catch-all for the same event, placed after 2 (first match wins). It
            //    fires only when the instruction was dropped — the pre-fix behaviour.
            .on_event("tcp_data_received")
            .respond_with_actions(serde_json::json!([
                { "type": "send_tcp_data", "data": "INSTRUCTION-WAS-DROPPED", "encoding": "utf8" }
            ]))
            .expect_calls(0)
            .and()
    }))
    .await?;

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    stream.write_all(b"PING\r\n").await?;
    stream.flush().await?;

    let mut buffer = vec![0u8; 1024];
    let n = match tokio::time::timeout(Duration::from_secs(15), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => n,
        Ok(Ok(_)) => return Err("connection closed without a response".into()),
        Ok(Err(e)) => return Err(format!("read error: {e}").into()),
        Err(_) => return Err("timed out waiting for the server response".into()),
    };
    let response = String::from_utf8_lossy(&buffer[..n]).to_string();

    assert!(
        response.contains("HANDLED"),
        "the per-event handler's rule must have answered, got: {response}"
    );
    assert!(
        !response.contains("INSTRUCTION-WAS-DROPPED"),
        "the catch-all answered, so the handler instruction never reached the prompt: {response}"
    );

    // The real assertion: rule 2 (prompt contains the handler instruction) was hit
    // exactly once and rule 3 (catch-all) never.
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

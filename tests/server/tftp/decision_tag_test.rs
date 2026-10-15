//! TFTP tags every terminal outcome with a `decision=` token, and the two that matter most
//! are the ones that look identical from outside.
//!
//! A backend outage and a handler that deliberately refuses the transfer both put an ERROR
//! packet (opcode 5, code 0) on the wire. Nothing in those bytes says which happened - the
//! refusal's message is whatever the handler chose and the outage's is a fixed category
//! string, and a client parses neither. So the log is the only place the distinction can
//! live, which is exactly why it has to be there.
//!
//! Both tests drive a real UDP socket and assert the wire bytes *and* the log line, because
//! either half alone proves nothing: a tag with no packet behind it is a claim about
//! something that did not happen, and a packet with no tag is the defect this pass exists to
//! remove.
//!
//! See `src/server/tftp/CLAUDE.md`, "Failure behaviour".

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

fn build_rrq_packet(filename: &str, mode: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&1u16.to_be_bytes()); // Opcode RRQ
    packet.extend_from_slice(filename.as_bytes());
    packet.push(0);
    packet.extend_from_slice(mode.as_bytes());
    packet.push(0);
    packet
}

/// Decode an ERROR packet the way a client does, so "the server sent something" is not what
/// gets asserted.
fn expect_error_packet(packet: &[u8]) -> (u16, String) {
    assert!(
        packet.len() >= 5,
        "ERROR packet is shorter than opcode+code+NUL: {} bytes",
        packet.len()
    );
    let opcode = u16::from_be_bytes([packet[0], packet[1]]);
    assert_eq!(
        opcode, 5,
        "expected opcode 5 (ERROR), got {opcode} - the server answered in the wrong vocabulary"
    );
    let error_code = u16::from_be_bytes([packet[2], packet[3]]);
    assert_eq!(
        *packet.last().unwrap(),
        0,
        "ERROR message must be NUL-terminated"
    );
    (
        error_code,
        String::from_utf8_lossy(&packet[4..packet.len() - 1]).to_string(),
    )
}

/// The backend fails on the read request. The client gets ERROR, and the log says the server
/// was the one that could not answer.
#[tokio::test]
async fn test_tftp_backend_failure_is_tagged_fail_closed() -> E2EResult<()> {
    let config = NetGetConfig::new_no_scripts(
        "listen on port {AVAILABLE_PORT} via tftp. Serve file kernel.img",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("via tftp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TFTP",
                    "instruction": "Serve file kernel.img"
                }
            ]))
            .expect_calls(1)
            .and()
            // Not JSON and not an action: the retry/repair loop exhausts and `call_llm`
            // returns Err, which is the backend-failure path.
            .on_event("tftp_read_request")
            .respond_with_raw("the backend is having a bad day and this is not an action")
            .expect_at_least(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client
        .send_to(
            &build_rrq_packet("kernel.img", "octet"),
            format!("127.0.0.1:{}", server.port),
        )
        .await?;

    let mut buffer = vec![0u8; 516];
    let (n, _) = timeout(REPLY_TIMEOUT, client.recv_from(&mut buffer))
        .await
        .map_err(|_| {
            "no TFTP reply within 30s - the server went silent on backend failure, which is \
             worse than failing: a transfer that simply stops looks like a corrupt image"
        })??;

    let (code, message) = expect_error_packet(&buffer[..n]);
    assert_eq!(code, 0, "a backend failure is reported as 'not defined'");
    assert!(
        message == "Internal error: LLM backend failure"
            || message == "Server overloaded, retry later",
        "the peer gets one of the two fixed categories and never the error text, got: \
         {message:?}"
    );

    server
        .wait_for_any(
            &[
                "decision=fail_closed_llm_error",
                "decision=fail_closed_llm_overloaded",
            ],
            30,
        )
        .await;

    let lines = server.get_output().await;
    assert!(
        lines.iter().any(|l| l.contains("decision=fail_closed_llm")),
        "a backend failure must be greppable as decision=fail_closed_llm_*, or it is \
         indistinguishable from the handler refusing the transfer - both send the same ERROR \
         packet. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=model_reject")),
        "the backend failed; no model refused anything. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The handler refuses the transfer with `send_tftp_error`. Same opcode on the wire as the
/// test above, opposite meaning, and only the log says so.
#[tokio::test]
async fn test_tftp_handler_refusal_is_tagged_model_reject() -> E2EResult<()> {
    let config =
        NetGetConfig::new_no_scripts("listen on port {AVAILABLE_PORT} via tftp. Refuse every file")
            .with_mock(|mock| {
                mock.on_instruction_containing("via tftp")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "TFTP",
                            "instruction": "Refuse every file"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("tftp_read_request")
                    .respond_with_actions(serde_json::json!([{
                        "type": "send_tftp_error",
                        "error_code": 2,
                        "error_message": "Access violation"
                    }]))
                    .expect_calls(1)
                    .and()
            });

    let server = start_netget_server(config).await?;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client
        .send_to(
            &build_rrq_packet("secret.bin", "octet"),
            format!("127.0.0.1:{}", server.port),
        )
        .await?;

    let mut buffer = vec![0u8; 516];
    let (n, _) = timeout(REPLY_TIMEOUT, client.recv_from(&mut buffer))
        .await
        .map_err(|_| "no TFTP reply within 30s")??;

    let (code, message) = expect_error_packet(&buffer[..n]);
    assert_eq!(
        code, 2,
        "the handler's own error code must reach the client"
    );
    assert_eq!(message, "Access violation");

    server.wait_for_any(&["decision=model_reject"], 30).await;

    let lines = server.get_output().await;
    assert!(
        lines.iter().any(|l| l.contains("decision=model_reject")),
        "a deliberate refusal must be tagged distinctly from a backend failure; the ERROR \
         packet on the wire is the same shape for both. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=fail_closed")),
        "the handler answered; nothing failed closed. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

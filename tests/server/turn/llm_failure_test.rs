//! Regression test: when the LLM backend *errors* on a TURN control request, the client gets a
//! STUN error response carrying a category only — never netget's internal error text.
//!
//! Two failure modes are pinned at once, because fixing one used to cause the other:
//!
//! 1. **Silence.** The LLM-error branch used to return with nothing written, so a STUN client
//!    retransmitted for the whole Rc/Rm schedule (~39s) before giving up. An operator policy
//!    *is* configured here, so this is a genuine backend failure, not the deliberate
//!    no-policy fail-closed silence that `static_default_test.rs` pins.
//! 2. **Leaking.** The ERROR-CODE reason phrase must be `WireFailure`'s static category text.
//!    Nothing derived from the error — backend URL, model name, file path, anyhow chain —
//!    may appear in it.
//!
//! Nothing is granted either way: the reserved relay socket is still dropped.
//!
//! The failure is injected by giving the mock **no rule for `turn_allocate_request`**; an
//! unmatched request is answered with HTTP 500, which is exactly the shape of a backend error.

#![cfg(unix)]

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

const MAGIC_COOKIE: u32 = 0x2112_A442;
const ALLOCATE_REQUEST: u16 = 0x0003;
/// Allocate error response: method 3, class 3 (RFC 8489 section 5).
const ALLOCATE_ERROR_RESPONSE: u16 = 0x0113;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_ERROR_CODE: u16 = 0x0009;

fn allocate_request(tid: &[u8; 12]) -> Vec<u8> {
    let mut attrs = Vec::new();
    attrs.extend_from_slice(&ATTR_REQUESTED_TRANSPORT.to_be_bytes());
    attrs.extend_from_slice(&4u16.to_be_bytes());
    attrs.extend_from_slice(&[17, 0, 0, 0]);

    let mut msg = Vec::with_capacity(20 + attrs.len());
    msg.extend_from_slice(&ALLOCATE_REQUEST.to_be_bytes());
    msg.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(tid);
    msg.extend_from_slice(&attrs);
    msg
}

/// Pull (code, reason) out of the first ERROR-CODE attribute.
fn error_code_attribute(packet: &[u8]) -> Option<(u16, String)> {
    let mut offset = 20;
    while offset + 4 <= packet.len() {
        let attr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let len = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
        let value_start = offset + 4;
        if value_start + len > packet.len() {
            return None;
        }
        if attr_type == ATTR_ERROR_CODE && len >= 4 {
            let value = &packet[value_start..value_start + len];
            let code = value[2] as u16 * 100 + value[3] as u16;
            let reason = String::from_utf8_lossy(&value[4..]).to_string();
            return Some((code, reason));
        }
        offset = value_start + len + ((4 - len % 4) % 4);
    }
    None
}

#[tokio::test]
async fn test_turn_answers_the_client_with_a_category_when_the_llm_errors() -> E2EResult<()> {
    let config = NetGetConfig::new_no_scripts(
        "Start a TURN relay server on port {AVAILABLE_PORT} that grants allocations",
    )
    .with_mock(|mock| {
        mock
            // A NON-EMPTY instruction: operator policy IS configured, so the control path
            // really does consult the LLM (unlike static_default_test.rs).
            .on_instruction_containing("server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "TURN",
                    "instruction": "Grant every allocation request."
                }
            ]))
            .expect_calls(1)
            .and()
        // Deliberately NO rule for turn_allocate_request: the mock answers HTTP 500 and
        // netget sees a backend error.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.connect(format!("127.0.0.1:{}", server.port)).await?;
    let tid = [0x2au8; 12];
    client.send(&allocate_request(&tid)).await?;

    let mut buf = [0u8; 2048];
    // Generous: the LLM path retries before giving up. Still far below the ~39s a STUN
    // client would spend retransmitting into silence.
    let n =
        match timeout(Duration::from_secs(20), client.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(format!("recv error: {e}").into()),
            Err(_) => return Err(
                "no reply at all: an LLM backend error must not leave the client retransmitting"
                    .into(),
            ),
        };
    let packet = &buf[..n];

    assert!(n >= 20, "runt STUN packet ({n} bytes)");
    let msg_type = u16::from_be_bytes([packet[0], packet[1]]);
    assert_eq!(
        msg_type, ALLOCATE_ERROR_RESPONSE,
        "expected an Allocate error response (0x0113), got 0x{msg_type:04x}"
    );
    assert_eq!(
        &packet[8..20],
        &tid,
        "error response must echo the request's transaction ID or the client discards it"
    );

    let (code, reason) =
        error_code_attribute(packet).ok_or("error response carries no ERROR-CODE attribute")?;
    assert!(
        code == 500 || code == 508,
        "expected 500 Server Error (or 508 when the backend is saturated), got {code}"
    );

    // The category text, and nothing else. These are the things that actually leaked.
    assert!(
        reason == "request could not be processed" || reason == "backend at capacity, retry later",
        "ERROR-CODE reason must be a WireFailure category, got {reason:?}"
    );
    for forbidden in [
        "http://",
        "127.0.0.1:",
        "ollama",
        "llama",
        "src/",
        ".rs",
        "retries",
        "Error",
        "error",
    ] {
        assert!(
            !reason.contains(forbidden),
            "ERROR-CODE reason leaks internals ({forbidden:?}): {reason:?}"
        );
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

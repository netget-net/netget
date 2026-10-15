//! Regression test: a TURN Allocate request with NO configured grant policy is fail-closed
//! (nothing granted, nothing sent) with ZERO LLM calls.
//!
//! Whether to grant an allocation is a policy decision, not wire-determined. With no operator
//! policy (no server instruction, no event handler) TURN's own fail-closed default applies —
//! grant nothing — and it must do so WITHOUT an LLM round-trip. The mock's
//! `turn_allocate_request` rule has `expect_calls(0)`: if the control path ever reaches the LLM,
//! that rule fires and `verify_mocks()` fails.

#![cfg(unix)]

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

const MAGIC_COOKIE: u32 = 0x2112_A442;
const ALLOCATE_REQUEST: u16 = 0x0003;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;

fn allocate_request(tid: &[u8; 12]) -> Vec<u8> {
    // A single REQUESTED-TRANSPORT attribute (17 = UDP), 4-byte value, already 4-aligned.
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

#[tokio::test]
async fn test_turn_grants_nothing_without_policy_and_needs_no_llm() -> E2EResult<()> {
    let config = NetGetConfig::new_no_scripts("Start a TURN relay server on port {AVAILABLE_PORT}")
        .with_mock(|mock| {
            mock
                // Startup: the only legitimate LLM call. EMPTY instruction => no grant policy.
                .on_instruction_containing("server")
                .respond_with_actions(serde_json::json!([
                    { "type": "open_server", "port": 0, "base_stack": "TURN", "instruction": "" }
                ]))
                .expect_calls(1)
                .and()
                // If the control path ever calls the LLM, this fires and expect_calls(0) fails.
                .on_event("turn_allocate_request")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "send_turn_allocate_response",
                        "transaction_id": e["transaction_id"],
                        "relay_address": e["relay_address"]
                    }])
                })
                .expect_calls(0)
                .and()
        });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.connect(format!("127.0.0.1:{}", server.port)).await?;
    client.send(&allocate_request(&[0x11; 12])).await?;

    // The correct static default is fail-closed silence: no allocation granted without policy.
    let mut buf = [0u8; 2048];
    match timeout(Duration::from_millis(1500), client.recv(&mut buf)).await {
        Ok(Ok(n)) => {
            return Err(format!(
                "expected fail-closed silence (no grant policy configured), but got {n} bytes back"
            )
            .into())
        }
        Ok(Err(e)) => return Err(format!("recv error: {e}").into()),
        Err(_) => { /* timeout == the expected fail-closed silence */ }
    }

    // Asserts the turn_allocate_request rule was hit 0 times: the path took NO LLM call.
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

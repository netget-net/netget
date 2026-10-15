//! Regression test: a RIP request with NO configured routing policy is answered with silence
//! and ZERO LLM calls.
//!
//! A RIP response is not wire-determined — which routes to advertise is routing policy, like
//! DNS/DHCP. With no operator policy (no server instruction, no event handler) there is nothing
//! correct to advertise, so the server must stay silent AND must not burn an LLM round-trip to
//! decide that. The mock's `rip_request` rule has `expect_calls(0)`: if the request path ever
//! reaches the LLM, that rule fires and `verify_mocks()` fails.

use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

fn build_rip_request_all() -> Vec<u8> {
    let mut msg = Vec::new();
    msg.push(1); // Command: Request
    msg.push(2); // Version: RIPv2
    msg.push(0);
    msg.push(0);
    // Single entry requesting the entire table: AFI=0, metric=16.
    msg.extend_from_slice(&[0, 0]); // AFI
    msg.extend_from_slice(&[0, 0]); // Route tag
    msg.extend_from_slice(&[0, 0, 0, 0]); // IP
    msg.extend_from_slice(&[0, 0, 0, 0]); // Subnet mask
    msg.extend_from_slice(&[0, 0, 0, 0]); // Next hop
    msg.extend_from_slice(&16u32.to_be_bytes()); // Metric = 16
    msg
}

#[tokio::test]
async fn test_rip_stays_silent_without_policy_and_needs_no_llm() -> E2EResult<()> {
    let config =
        NetGetConfig::new_no_scripts("listen on port {AVAILABLE_PORT} via rip").with_mock(|mock| {
            mock
                // Startup: the only legitimate LLM call. EMPTY instruction => no routing policy.
                .on_instruction_containing("listen")
                .and_instruction_containing("rip")
                .respond_with_actions(serde_json::json!([
                    { "type": "open_server", "port": 0, "base_stack": "RIP", "instruction": "" }
                ]))
                .expect_calls(1)
                .and()
                // If the request path ever calls the LLM, this fires and expect_calls(0) fails.
                .on_event("rip_request")
                .respond_with_actions(serde_json::json!([{ "type": "ignore_request" }]))
                .expect_calls(0)
                .and()
        });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.connect(format!("127.0.0.1:{}", server.port)).await?;
    client.send(&build_rip_request_all()).await?;

    // The correct static default is silence: no routes to advertise without a policy.
    let mut buf = [0u8; 512];
    match timeout(Duration::from_secs(2), client.recv(&mut buf)).await {
        Ok(Ok(n)) => {
            return Err(format!(
                "expected silence (no routing policy configured), but got a {n}-byte RIP response"
            )
            .into())
        }
        Ok(Err(e)) => return Err(format!("recv error: {e}").into()),
        Err(_) => { /* timeout == the expected silence */ }
    }

    // Asserts the rip_request rule was hit 0 times: the request path took NO LLM call.
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

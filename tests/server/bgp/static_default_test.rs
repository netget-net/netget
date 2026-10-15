//! Regression test: the BGP OPEN handshake completes with ZERO LLM calls when no operator
//! policy is configured.
//!
//! The OPEN we send is fully determined by the configured ASN / router-id / hold-time and a
//! peer that passed validation — it is mechanical, which is why the server already answers a
//! silent handler with the configured OPEN. So with no operator policy (no server instruction,
//! no event handler) the handshake must proceed on that configured OPEN with NO model call, and
//! established/update must advertise nothing (there is no routing policy to apply). The mock's
//! `bgp_open` and `bgp_established` rules have `expect_calls(0)`: if the session path ever reaches
//! the LLM, they fire and `verify_mocks()` fails.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const BGP_MSG_OPEN: u8 = 1;
const BGP_MSG_KEEPALIVE: u8 = 4;
const BGP_MARKER: [u8; 16] = [0xff; 16];

fn build_bgp_open(
    my_as: u16,
    hold_time: u16,
    router_id: [u8; 4],
    four_octet_as: Option<u32>,
) -> Vec<u8> {
    let mut params = Vec::new();
    if let Some(asn) = four_octet_as {
        params.push(0x02); // Optional Parameter type 2: Capabilities
        params.push(0x06);
        params.push(0x41); // capability 65: four-octet AS
        params.push(0x04);
        params.extend_from_slice(&asn.to_be_bytes());
    }
    let mut msg = Vec::new();
    msg.extend_from_slice(&BGP_MARKER);
    msg.extend_from_slice(&[0, 0]); // length, patched below
    msg.push(BGP_MSG_OPEN);
    msg.push(4); // version
    msg.extend_from_slice(&my_as.to_be_bytes());
    msg.extend_from_slice(&hold_time.to_be_bytes());
    msg.extend_from_slice(&router_id);
    msg.push(params.len() as u8);
    msg.extend_from_slice(&params);
    let msg_len = msg.len() as u16;
    msg[16..18].copy_from_slice(&msg_len.to_be_bytes());
    msg
}

fn build_bgp_keepalive() -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&BGP_MARKER);
    msg.extend_from_slice(&19u16.to_be_bytes());
    msg.push(BGP_MSG_KEEPALIVE);
    msg
}

async fn read_bgp_message(stream: &mut TcpStream) -> E2EResult<(u8, Vec<u8>)> {
    let mut header = [0u8; 19];
    stream.read_exact(&mut header).await?;
    if header[..16] != BGP_MARKER {
        return Err("Invalid BGP marker".into());
    }
    let length = u16::from_be_bytes([header[16], header[17]]) as usize;
    if !(19..=4096).contains(&length) {
        return Err(format!("BGP message length {length} out of range").into());
    }
    let mut full = vec![0u8; length];
    full[..19].copy_from_slice(&header);
    if length > 19 {
        stream.read_exact(&mut full[19..]).await?;
    }
    Ok((header[18], full))
}

#[tokio::test]
async fn test_bgp_open_handshake_needs_no_llm() -> E2EResult<()> {
    let config =
        NetGetConfig::new_no_scripts("listen on port {AVAILABLE_PORT} via bgp").with_mock(|mock| {
            mock
                // Startup: the only legitimate LLM call. EMPTY instruction => no policy, so the
                // configured OPEN (default AS 65000 / router-id 192.168.1.1) is used.
                .on_instruction_containing("bgp")
                .respond_with_actions(serde_json::json!([
                    { "type": "open_server", "port": 0, "base_stack": "BGP", "instruction": "" }
                ]))
                .expect_calls(1)
                .and()
                // If the handshake path ever calls the LLM, these fire and expect_calls(0) fails.
                .on_event("bgp_open")
                .respond_with_actions(serde_json::json!([{ "type": "wait_for_more" }]))
                .expect_calls(0)
                .and()
                .on_event("bgp_established")
                .respond_with_actions(serde_json::json!([{ "type": "wait_for_more" }]))
                .expect_calls(0)
                .and()
        });

    let server = start_netget_server(config).await?;

    let mut client = timeout(
        Duration::from_secs(10),
        TcpStream::connect(format!("127.0.0.1:{}", server.port)),
    )
    .await??;

    // Peer OPEN: AS 65000, hold 180, router-id 192.168.1.100, four-octet capable.
    client
        .write_all(&build_bgp_open(65000, 180, [192, 168, 1, 100], Some(65000)))
        .await?;

    // 1. The server's configured OPEN — sent statically, no model call.
    let (msg_type, _open) =
        timeout(Duration::from_secs(10), read_bgp_message(&mut client)).await??;
    assert_eq!(
        msg_type, BGP_MSG_OPEN,
        "expected the configured OPEN as the static handshake, got type {msg_type}"
    );

    // 2. The KEEPALIVE that completes our side of the OPEN exchange (RFC 4271 8.2.2).
    let (msg_type, _ka) = timeout(Duration::from_secs(10), read_bgp_message(&mut client)).await??;
    assert_eq!(
        msg_type, BGP_MSG_KEEPALIVE,
        "expected a KEEPALIVE right after the OPEN, got type {msg_type}"
    );

    // 3. Our KEEPALIVE drives the session to Established, which raises bgp_established — also
    //    handled statically (advertise nothing), so still no model call.
    client.write_all(&build_bgp_keepalive()).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Asserts bgp_open and bgp_established rules were each hit 0 times: NO LLM call on the path.
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

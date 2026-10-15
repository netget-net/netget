//! Regression test: a STUN Binding request is answered CORRECTLY with ZERO LLM calls.
//!
//! A Binding response is fully determined by the request (reflect the source address into
//! XOR-MAPPED-ADDRESS, echo the transaction ID), so when the operator gives neither a server
//! instruction nor an event handler, the server must answer statically and never consult the
//! model. The mock has a `stun_binding_request` rule with `expect_calls(0)`: if the mechanical
//! path ever reaches the LLM, that rule fires and `verify_mocks()` fails.

#![cfg(unix)]

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::net::UdpSocket;

const MAGIC_COOKIE: u32 = 0x2112_A442;
const TRANSACTION_ID: [u8; 12] = [
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c,
];

#[tokio::test]
async fn test_stun_binding_response_needs_no_llm() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via stun";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock
            // Startup: the only legitimate LLM call. The resulting server has an EMPTY
            // instruction, so the binding path is purely static.
            .on_instruction_containing("via stun")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "STUN",
                    "instruction": ""
                }
            ]))
            .expect_calls(1)
            .and()
            // If the mechanical binding path ever calls the LLM, this rule fires and the
            // expect_calls(0) assertion fails. It also returns a valid action so a
            // regression cannot be masked by a coincidental timeout.
            .on_event("stun_binding_request")
            .respond_with_actions_from_event(|event_data| {
                let transaction_id = event_data["transaction_id"]
                    .as_str()
                    .unwrap_or("000000000000000000000000");
                let peer_addr = event_data["peer_addr"].as_str().unwrap_or("127.0.0.1:1");
                serde_json::json!([{
                    "type": "send_stun_binding_response",
                    "transaction_id": transaction_id,
                    "mapped_address": peer_addr,
                    "xor_mapped_address": true
                }])
            })
            .expect_calls(0)
            .and()
    });

    let server = start_netget_server(server_config).await?;
    server.wait_for_log("STUN receive loop started", 5).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Binding Request: type 0x0001, length 0, magic cookie, transaction ID.
    let mut request = Vec::with_capacity(20);
    request.extend_from_slice(&0x0001u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    request.extend_from_slice(&TRANSACTION_ID);

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let client_addr = socket.local_addr()?;
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;
    socket.send(&request).await?;

    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(10), socket.recv(&mut buf))
        .await
        .map_err(|_| "No static STUN response within 10s")??;

    assert!(n >= 20, "response shorter than a STUN header: {n} bytes");

    let message_type = u16::from_be_bytes([buf[0], buf[1]]);
    assert_eq!(
        message_type, 0x0101,
        "expected a Binding Success Response (0x0101), got 0x{message_type:04x}"
    );
    assert_eq!(
        u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        MAGIC_COOKIE,
        "magic cookie must be present"
    );
    assert_eq!(
        &buf[8..20],
        &TRANSACTION_ID,
        "the transaction ID must be echoed, or the client discards the response"
    );

    let mapped =
        find_xor_mapped_address(&buf[..n]).expect("XOR-MAPPED-ADDRESS attribute must be present");
    assert_eq!(
        mapped, client_addr,
        "XOR-MAPPED-ADDRESS must decode to the client's own source address"
    );

    // Asserts the binding rule was hit 0 times: the mechanical path took NO LLM call.
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Decode the XOR-MAPPED-ADDRESS (0x0020) attribute into a SocketAddr (IPv4 only).
fn find_xor_mapped_address(msg: &[u8]) -> Option<std::net::SocketAddr> {
    let message_length = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let attributes = msg.get(20..20 + message_length)?;
    let magic = MAGIC_COOKIE.to_be_bytes();

    let mut offset = 0usize;
    while offset + 4 <= attributes.len() {
        let attr_type = u16::from_be_bytes([attributes[offset], attributes[offset + 1]]);
        let attr_len =
            u16::from_be_bytes([attributes[offset + 2], attributes[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end = value_start + attr_len;
        if value_end > attributes.len() {
            return None;
        }
        if attr_type == 0x0020 && attr_len >= 8 {
            let value = &attributes[value_start..value_end];
            let xport = u16::from_be_bytes([value[2], value[3]]);
            let port = xport ^ (MAGIC_COOKIE >> 16) as u16;
            let ip = std::net::Ipv4Addr::new(
                value[4] ^ magic[0],
                value[5] ^ magic[1],
                value[6] ^ magic[2],
                value[7] ^ magic[3],
            );
            return Some(std::net::SocketAddr::from((ip, port)));
        }
        offset = value_start + attr_len.div_ceil(4) * 4;
    }
    None
}

//! What a STUN client gets when the LLM backend fails while the operator opted into LLM
//! control: the correct static Binding Success Response, not an error and not silence.
//!
//! A STUN Binding response is fully determined by the request — reflect the source address into
//! XOR-MAPPED-ADDRESS and echo the 96-bit transaction ID — so it is the safe fallback here. It
//! can never be a credential or an approval, so answering with the client's own real address on
//! LLM failure fails *closed*, not open: the worst case is that a request to lie about the
//! address is quietly ignored and the truth is told instead. A silent drop, by contrast, is
//! indistinguishable from packet loss and costs the client its full retransmission schedule.
//!
//! The response is decoded here from the raw bytes against the RFC's header and attribute
//! layout, not through the server's own builder.
//!
//! Because the fallback bytes are byte-identical to the ones a server with no instruction
//! would have sent, the test also asserts the log tag. The token is `static_fallback_llm_error`
//! rather than a `fail_closed_*` one precisely because the peer *did* get an affirmative
//! answer here; tagging it `fail_closed_` would mislead anyone grepping for requests that went
//! unanswered. See the failure-behaviour table in `src/server/stun/CLAUDE.md`.

#![cfg(unix)]

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::net::UdpSocket;

const MAGIC_COOKIE: u32 = 0x2112_A442;
const TRANSACTION_ID: [u8; 12] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];

#[tokio::test]
async fn test_stun_answers_static_response_when_llm_fails() -> E2EResult<()> {
    // The instruction opts this server into LLM control; the mock then fails every
    // binding request (no matching rule -> HTTP 500), forcing the fallback path.
    let prompt = "listen on port {AVAILABLE_PORT} via stun. Reflect the client address";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via stun")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "STUN",
                    "instruction": "Reflect the client address"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `stun_binding_request`: the mock answers 500, the LLM call fails,
        // and the server must fall back to the correct static Binding Success Response.
    });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

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
    let n = tokio::time::timeout(Duration::from_secs(20), socket.recv(&mut buf))
        .await
        .map_err(|_| {
            "No STUN response within 20s - the server went silent on LLM failure, which is the \
             exact defect this test exists to catch"
        })??;

    // The pcap oracle. Wireshark's `stun` dissector checks the two things this file's
    // hand-indexed assertions cannot: that the 16-bit Message Length equals the bytes
    // that follow the header, and that each attribute is padded to a 4-byte boundary.
    // Attribute padding is the classic STUN encoder bug — XOR-MAPPED-ADDRESS for IPv4
    // happens to be a multiple of four, so it hides until the first odd-length
    // attribute — and this reply is built on the fail-closed path, with no model
    // involved and nothing else reading it.
    crate::helpers::pcap_oracle::PcapOracle::udp("stun")
        .to_server(&request)
        .from_server(&buf[..n])
        .assert_clean();

    assert!(n >= 20, "response shorter than a STUN header: {n} bytes");

    let message_type = u16::from_be_bytes([buf[0], buf[1]]);
    assert_eq!(
        message_type, 0x0101,
        "expected a Binding Success Response (0x0101) as the static fallback, got 0x{message_type:04x}"
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
        "the static fallback must reflect the client's own source address"
    );

    // The bytes on the wire are identical to the ones a server with no instruction at all
    // would have sent, so the wire cannot say which path produced them. The log has to: a
    // backend outage and an operator who never opted in must not read the same.
    server
        .wait_for_any(&["decision=static_fallback_llm_error"], 30)
        .await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=static_fallback_llm_error")),
        "the fallback must be logged with a decision= tag; `static_default` (no model asked) \
         and `static_fallback_llm_error` (asked, backend failed) send the same bytes and are \
         otherwise indistinguishable. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=static_default")),
        "this server has an instruction, so it opted into model control: the static default \
         path must not have run. Output was:\n{}",
        lines.join("\n")
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Decode the XOR-MAPPED-ADDRESS (0x0020) attribute from a STUN message into a SocketAddr,
/// undoing the RFC 8489 §14.2 XOR with the magic cookie. IPv4 only, which is all this server
/// emits.
pub(crate) fn find_xor_mapped_address(msg: &[u8]) -> Option<std::net::SocketAddr> {
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
            // reserved(1) | family(1) | x-port(2) | x-address(4)
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

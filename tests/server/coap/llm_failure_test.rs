//! What a CoAP client gets when the model cannot answer, and how the two ways that happens
//! are told apart.
//!
//! `src/server/coap/CLAUDE.md` describes a `decision=` vocabulary modelled on
//! `src/server/radius/`: 5.03 Service Unavailable is what **both** fail-closed paths put on the
//! wire *and* a code the model may legitimately choose for itself, so the peer cannot tell the
//! three apart and the log is the only place the distinction survives. Until this file existed
//! nothing asserted any of it — `tests/server/coap/CLAUDE.md` listed "no test of the 5.03
//! fail-closed path" as a gap, and a documented decision table nothing checks is the shape this
//! repository keeps finding in `metadata()` claims.
//!
//! Two paths, one server:
//!
//! * **`fail_closed_llm_error`** — the backend failed. Forced by configuring a mock for the
//!   *startup* instruction only, so the `coap_request` event matches no rule, the mock answers
//!   HTTP 500, and `call_llm` returns `Err`.
//! * **`fail_closed_no_action`** — the model answered, and with nothing this protocol can send.
//!   `show_message` is a *common* action, so it never enters `protocol_results` and
//!   `outcome_from_results` finds no `coap_response`, `coap_reset` or `coap_ignore`.
//!
//! The assertion that matters is not "it answered 5.03" — a server that answered 5.03 to
//! everything would satisfy that, and so would one whose model genuinely chose 5.03. It is that
//! the reply is **matchable** (ACK type, the request's message id, the request's token) and that
//! the log says which of the two happened.


use crate::helpers::pcap_oracle::PcapOracle;
use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use coap_lite::{CoapOption, MessageClass, MessageType, Packet, RequestType};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// A Confirmable GET with a chosen message id and token, built by coap-lite.
fn confirmable_get(message_id: u16, token: Vec<u8>, path: &str) -> Vec<u8> {
    let mut packet = Packet::new();
    packet.header.set_version(1);
    packet.header.set_type(MessageType::Confirmable);
    packet.header.code = MessageClass::Request(RequestType::Get);
    packet.header.message_id = message_id;
    packet.set_token(token);
    packet.add_option(CoapOption::UriPath, path.as_bytes().to_vec());
    packet.to_bytes().expect("coap-lite failed to encode")
}

async fn exchange(socket: &UdpSocket, server: SocketAddr, out: &[u8]) -> Vec<u8> {
    socket.send_to(out, server).await.expect("send failed");
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(25), socket.recv_from(&mut buf))
        .await
        .expect(
            "no CoAP reply within 25s: the server went silent instead of failing closed, which \
             is the defect this test exists to catch",
        )
        .expect("recv failed");
    buf.truncate(n);

    PcapOracle::udp("coap")
        .to_server(out)
        .from_server(&buf)
        .assert_clean();

    buf
}

/// Assert a 5.03 that a client can actually match to its request.
fn assert_matchable_503(reply: &[u8], message_id: u16, token: &[u8]) {
    assert_eq!(
        (reply[1] >> 5, reply[1] & 0x1F),
        (5, 3),
        "a fail-closed answer is 5.03 Service Unavailable; got {}",
        hex::encode(reply)
    );
    let decoded = Packet::from_bytes(reply).expect("coap-lite must accept the 5.03");
    assert_eq!(
        decoded.header.get_type(),
        MessageType::Acknowledgement,
        "a Confirmable request is answered with an ACK, refusal or not — without it the client \
         keeps retransmitting and the refusal is worse than useless"
    );
    assert_eq!(decoded.header.message_id, message_id);
    assert_eq!(
        decoded.get_token(),
        token,
        "CoAP matches a response to its request by token equality (RFC 7252 §5.3.2); a 5.03 \
         with the wrong token is discarded silently and is indistinguishable from the silence \
         it exists to replace"
    );
    assert!(
        decoded.payload.is_empty(),
        "the fail-closed reply must not invent a body"
    );
}

#[tokio::test]
async fn test_coap_fails_closed_with_5_03_and_says_which_path_it_took() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a CoAP server on port {AVAILABLE_PORT}")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("CoAP server")
                .and_instruction_containing("on port")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "coap",
                    "instruction": "Fail-closed probe"
                }]))
                .expect_calls(1)
                .and()
                // An answer the model is entitled to give and this protocol cannot send.
                // Deliberately no rule for `/backend-down`, so that path gets an HTTP 500.
                .on_event("coap_request")
                .and_event_data_contains("path", "/no-action")
                .respond_with_actions(serde_json::json!([
                    {"type": "show_message", "message": "thinking about it"}
                ]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    server.wait_for_log("CoAP receive loop started", 15).await?;
    let target: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    // --- the backend failed ----------------------------------------------------------
    let token = vec![0xF0, 0x0D, 0xBA, 0xBE];
    let reply = exchange(
        &socket,
        target,
        &confirmable_get(0x5150, token.clone(), "backend-down"),
    )
    .await;
    assert_matchable_503(&reply, 0x5150, &token);

    // --- the model answered with nothing usable --------------------------------------
    let token2 = vec![0x01, 0x02, 0x03];
    let reply = exchange(
        &socket,
        target,
        &confirmable_get(0x5151, token2.clone(), "no-action"),
    )
    .await;
    assert_matchable_503(&reply, 0x5151, &token2);

    // --- and the log is where the two are distinguishable ----------------------------
    //
    // The peer got the same five bytes twice. `grep 'decision=fail_closed_'` has to find both
    // *and tell them apart*, or an operator cannot separate a backend outage from a model that
    // is answering badly — which are opposite problems with opposite fixes.
    // `wait_for_all`, not `wait_for_any`: this test asserts on BOTH tags below, and the
    // any-variant returns on the first match. Under a 32-thread sweep that is a real
    // difference — the backend-failure tag landed inside the window, the wait returned
    // satisfied, and the assertion on the second tag failed while it was still in flight.
    server
        .wait_for_all(
            &[
                "decision=fail_closed_llm_error",
                "decision=fail_closed_no_action",
            ],
            20,
        )
        .await;
    let output = server.get_output().await.join("\n");
    assert!(
        output.contains("decision=fail_closed_llm_error"),
        "the backend-failure path must log its own tag; log was:\n{output}"
    );
    assert!(
        output.contains("decision=fail_closed_no_action"),
        "the nothing-usable path must log a *different* tag from the backend-failure one, or \
         the wire and the log are equally uninformative; log was:\n{output}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

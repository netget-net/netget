//! E2E tests for the CoAP (RFC 7252) server.
//!
//! Two independent peers, neither of which shares code with `src/server/coap/codec.rs`:
//!
//! * **`coap` 0.27** (`UdpCoAPClient`) — a real client that does its own CON/ACK matching,
//!   so a wrong message id or token shows up as a timeout rather than a passing test.
//! * **`coap-lite` 0.13** — an independent codec, used to build requests with a *chosen*
//!   token and message id and to decode the replies field by field.
//!
//! CoAP is UDP, so the mocks use `respond_with_actions_from_event()` throughout: the
//! reply is derived from the request that provoked it. Note the thing that is echoed
//! dynamically here is the **path**, not the message id — this server echoes the message
//! id and token itself, in `codec::response_to`, precisely so the model can never break
//! reliability matching. The second test asserts that echo explicitly.
//!
//! See `tests/server/coap/CLAUDE.md` for the LLM call budget.


use crate::helpers::pcap_oracle::PcapOracle;
use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use coap_lite::{
    CoapOption, ContentFormat, MessageClass, MessageType, Packet, RequestType, ResponseType,
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Send one datagram and wait for one reply.
async fn exchange(socket: &UdpSocket, server: SocketAddr, out: &[u8]) -> Vec<u8> {
    socket
        .send_to(out, server)
        .await
        .expect("failed to send a CoAP datagram");
    let mut buf = vec![0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
        .await
        .expect("timed out waiting for a CoAP reply")
        .expect("failed to receive a CoAP reply");
    buf.truncate(n);

    // The pcap oracle: a third independent reading of RFC 7252, after coap-lite and
    // the `coap` client. It is worth having here specifically because CoAP's option
    // encoding is delta-and-length nibbles with extension bytes, and an option that
    // runs past the end of the datagram is a silent off-by-one in every codec that
    // trusts its own writer - Wireshark says "option longer than the package".
    PcapOracle::udp("coap")
        .to_server(out)
        .from_server(&buf)
        .assert_clean();

    buf
}

/// Build a request with coap-lite, our independent codec.
fn build_request(
    mtype: MessageType,
    method: RequestType,
    message_id: u16,
    token: Vec<u8>,
    path_segments: &[&str],
    query: Option<&str>,
) -> Vec<u8> {
    let mut packet = Packet::new();
    packet.header.set_version(1);
    packet.header.set_type(mtype);
    packet.header.code = MessageClass::Request(method);
    packet.header.message_id = message_id;
    packet.set_token(token);
    for segment in path_segments {
        packet.add_option(CoapOption::UriPath, segment.as_bytes().to_vec());
    }
    if let Some(q) = query {
        packet.add_option(CoapOption::UriQuery, q.as_bytes().to_vec());
    }
    packet.to_bytes().expect("coap-lite failed to encode")
}

// ===========================================================================
// A real CoAP client drives the server
// ===========================================================================

#[tokio::test]
async fn test_coap_get_post_and_not_found_with_coap_client() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Start a CoAP server on port {AVAILABLE_PORT} pretending to be a soil moisture sensor",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock
            // 1. Server startup
            .on_instruction_containing("CoAP server")
            .and_instruction_containing("on port")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "coap",
                "instruction": "Soil moisture sensor"
            }]))
            .expect_calls(1)
            .and()
            // 2. GET a resource the device has.
            .on_event("coap_request")
            .and_event_data_contains("path", "/sensors/moisture")
            .respond_with_actions_from_event(|event| {
                // Representation derived from the request, not a fixed literal.
                let path = event["path"].as_str().unwrap_or("/");
                serde_json::json!([{
                    "type": "send_coap_response",
                    "code": "2.05",
                    "payload": format!("{{\"resource\":\"{path}\",\"pct\":41.2}}"),
                    "content_format": "application/json"
                }])
            })
            .expect_calls(1)
            .and()
            // 3. POST to an actuator: a state change, so 2.04 Changed.
            .on_event("coap_request")
            .and_event_data_contains("path", "/actuators/valve")
            .respond_with_actions_from_event(|event| {
                let body = event["payload"].as_str().unwrap_or("");
                serde_json::json!([{
                    "type": "send_coap_response",
                    "code": "2.04",
                    "payload": format!("valve={body}"),
                    "content_format": "text/plain"
                }])
            })
            .expect_calls(1)
            .and()
            // 4. A resource the device does not have.
            .on_event("coap_request")
            .and_event_data_contains("path", "/nope")
            // Matches only when the event carries the per-request hint that names the 4.04.
            .and_event_data_contains("answer_with", "for a resource at /nope")
            .respond_with_actions(serde_json::json!([{
                "type": "send_coap_response",
                "code": "4.04"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    server.wait_for_log("CoAP receive loop started", 15).await?;

    let base = format!("coap://127.0.0.1:{}", server.port);

    // --- GET 2.05 Content --------------------------------------------------
    let response = coap::UdpCoAPClient::get_with_timeout(
        &format!("{base}/sensors/moisture"),
        Duration::from_secs(10),
    )
    .await
    .expect("coap client GET failed");

    assert_eq!(
        response.message.header.code,
        MessageClass::Response(ResponseType::Content),
        "a successful GET must decode as 2.05 Content"
    );
    assert_eq!(
        String::from_utf8_lossy(&response.message.payload),
        "{\"resource\":\"/sensors/moisture\",\"pct\":41.2}",
        "the payload the model produced must arrive intact"
    );
    assert_eq!(
        response.message.get_content_format(),
        Some(ContentFormat::ApplicationJSON),
        "the Content-Format option must be encoded so a real client can decode it"
    );

    // --- POST 2.04 Changed -------------------------------------------------
    let response = coap::UdpCoAPClient::post_with_timeout(
        &format!("{base}/actuators/valve"),
        b"open".to_vec(),
        Duration::from_secs(10),
    )
    .await
    .expect("coap client POST failed");

    assert_eq!(
        response.message.header.code,
        MessageClass::Response(ResponseType::Changed),
        "a POST that changed state must decode as 2.04 Changed"
    );
    assert_eq!(
        String::from_utf8_lossy(&response.message.payload),
        "valve=open",
        "the request body must reach the model and come back in its answer"
    );
    assert_eq!(
        response.message.get_content_format(),
        Some(ContentFormat::TextPlain)
    );

    // --- GET 4.04 Not Found ------------------------------------------------
    let response =
        coap::UdpCoAPClient::get_with_timeout(&format!("{base}/nope"), Duration::from_secs(10))
            .await
            .expect("coap client GET failed");

    assert_eq!(
        response.message.header.code,
        MessageClass::Response(ResponseType::NotFound),
        "the model's refusal must reach the client as 4.04, not as an empty 2.05"
    );
    assert!(
        response.message.payload.is_empty(),
        "a 4.04 with no payload must not acquire one"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

// ===========================================================================
// Message layer: type, message id, token, and the ping/RST rule
// ===========================================================================

#[tokio::test]
async fn test_coap_message_layer_echo_and_ping() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a CoAP server on port {AVAILABLE_PORT}")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("CoAP server")
                .and_instruction_containing("on port")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "coap",
                    "instruction": "Status endpoint"
                }]))
                .expect_calls(1)
                .and()
                .on_event("coap_request")
                .and_event_data_contains("path", "/status")
                .respond_with_actions_from_event(|event| {
                    // Echo the request's own view of itself, so the assertion below
                    // proves the path and query really reached the model.
                    let path = event["path"].as_str().unwrap_or("");
                    let query = event["query"].as_str().unwrap_or("none");
                    let mtype = event["message_type"].as_str().unwrap_or("?");
                    serde_json::json!([{
                        "type": "send_coap_response",
                        "code": "2.05",
                        "payload": format!("{path}?{query} via {mtype}"),
                        "content_format": "text/plain"
                    }])
                })
                .expect_calls(2)
                .and()
        });

    let server = start_netget_server(config).await?;
    server.wait_for_log("CoAP receive loop started", 15).await?;

    let server_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    // --- CoAP ping: an empty Confirmable must be answered with RST ---------
    // RFC 7252 section 4.3. This never reaches the model.
    let mut ping = Packet::new();
    ping.header.set_version(1);
    ping.header.set_type(MessageType::Confirmable);
    ping.header.code = MessageClass::Empty;
    ping.header.message_id = 0xAB12;
    let reply = exchange(&socket, server_addr, &ping.to_bytes().unwrap()).await;
    let reply = Packet::from_bytes(&reply).expect("coap-lite failed to decode the ping reply");
    assert_eq!(
        reply.header.get_type(),
        MessageType::Reset,
        "an empty Confirmable message (a CoAP ping) must be answered with Reset"
    );
    assert_eq!(
        reply.header.message_id, 0xAB12,
        "the Reset must carry the ping's message id"
    );
    assert_eq!(reply.header.code, MessageClass::Empty);

    // --- CON GET: piggybacked ACK, same message id, same token -------------
    let token = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    let request = build_request(
        MessageType::Confirmable,
        RequestType::Get,
        0x4711,
        token.clone(),
        &["status"],
        Some("verbose=1"),
    );
    let reply = exchange(&socket, server_addr, &request).await;
    let reply = Packet::from_bytes(&reply).expect("coap-lite failed to decode the ACK");

    assert_eq!(
        reply.header.get_type(),
        MessageType::Acknowledgement,
        "a Confirmable request must get a piggybacked Acknowledgement"
    );
    assert_eq!(
        reply.header.message_id, 0x4711,
        "the Acknowledgement must carry the request's message id, or the client will \
         retransmit forever"
    );
    assert_eq!(
        reply.get_token(),
        token.as_slice(),
        "the full 8-byte token must be echoed byte for byte"
    );
    assert_eq!(
        reply.header.code,
        MessageClass::Response(ResponseType::Content)
    );
    assert_eq!(
        String::from_utf8_lossy(&reply.payload),
        "/status?verbose=1 via CON",
        "path, query and message type must all have reached the model"
    );
    assert_eq!(
        reply.get_content_format(),
        Some(ContentFormat::TextPlain),
        "Content-Format must round-trip through the option encoding"
    );

    // --- NON GET: Non-confirmable reply, fresh message id, same token ------
    let token = vec![0x77];
    let request = build_request(
        MessageType::NonConfirmable,
        RequestType::Get,
        0x0815,
        token.clone(),
        &["status"],
        None,
    );
    let reply = exchange(&socket, server_addr, &request).await;
    let reply = Packet::from_bytes(&reply).expect("coap-lite failed to decode the NON reply");

    assert_eq!(
        reply.header.get_type(),
        MessageType::NonConfirmable,
        "a Non-confirmable request must be answered Non-confirmably"
    );
    assert_ne!(
        reply.header.message_id, 0x0815,
        "a Non-confirmable response carries its own message id, not the request's"
    );
    assert_eq!(
        reply.get_token(),
        token.as_slice(),
        "the token is what correlates a NON response, so it must be echoed"
    );
    assert_eq!(
        String::from_utf8_lossy(&reply.payload),
        "/status?none via NON"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

// ===========================================================================
// Codec assertions against literal, RFC-derived bytes
// ===========================================================================

#[test]
fn test_codec_option_extension_encoding_round_trips() {
    use netget::server::coap::codec as ng;

    // A single-byte option delta extension: Uri-Path is 11, Accept is 17, so the
    // second option needs a delta of 6 - still a plain nibble. Push past 12 with a
    // high-numbered option to exercise the 13 form, and past 268 for the 14 form.
    let message = ng::CoapMessage {
        mtype: ng::MessageType::Confirmable,
        code: ng::CODE_GET,
        message_id: 0x1234,
        token: vec![0xAA, 0xBB],
        options: vec![
            (ng::OPT_URI_PATH, b"a".to_vec()),
            (ng::OPT_URI_PATH, b"bb".to_vec()),
            (60, b"x".to_vec()),  // delta 49 -> the 13 (one extension byte) form
            (600, b"y".to_vec()), // delta 540 -> the 14 (two extension bytes) form
        ],
        payload: b"hello".to_vec(),
    };

    let bytes = message.encode().expect("a legal message encodes");
    let decoded = ng::CoapMessage::decode(&bytes).expect("our own encoding must decode");
    assert_eq!(decoded, message);

    // coap-lite, an independent implementation, must agree.
    let via_coap_lite = Packet::from_bytes(&bytes).expect("coap-lite must accept our encoding");
    assert_eq!(via_coap_lite.header.message_id, 0x1234);
    assert_eq!(via_coap_lite.get_token(), &[0xAA, 0xBB]);
    assert_eq!(via_coap_lite.payload, b"hello");
    let path: Vec<Vec<u8>> = via_coap_lite
        .get_option(CoapOption::UriPath)
        .expect("Uri-Path options must survive")
        .iter()
        .cloned()
        .collect();
    assert_eq!(path, vec![b"a".to_vec(), b"bb".to_vec()]);
}

#[test]
fn test_codec_header_bits_match_the_rfc() {
    use netget::server::coap::codec as ng;

    // RFC 7252 section 3: Ver=01, T=00 (CON), TKL=0, Code=0.01 (GET), MID=0x0001.
    let message = ng::CoapMessage {
        mtype: ng::MessageType::Confirmable,
        code: ng::CODE_GET,
        message_id: 0x0001,
        token: Vec::new(),
        options: Vec::new(),
        payload: Vec::new(),
    };
    assert_eq!(message.encode().unwrap(), vec![0x40, 0x01, 0x00, 0x01]);

    // 2.05 Content is 0b010_00101 = 0x45; 4.04 Not Found is 0b100_00100 = 0x84.
    assert_eq!(ng::CODE_CONTENT, 0x45);
    assert_eq!(ng::CODE_NOT_FOUND, 0x84);
    assert_eq!(ng::code_to_string(ng::CODE_CONTENT), "2.05");
    assert_eq!(ng::parse_code_string("4.04"), Some(ng::CODE_NOT_FOUND));
    assert_eq!(
        ng::parse_code_string("2.05 Content"),
        Some(ng::CODE_CONTENT)
    );
    assert_eq!(ng::parse_code_string("not a code"), None);

    // A datagram shorter than the header, or with the wrong version, is not CoAP.
    assert_eq!(
        ng::CoapMessage::decode(&[0x40, 0x01]),
        Err(ng::DecodeError::TooShort { len: 2 })
    );
    assert_eq!(
        ng::CoapMessage::decode(&[0x80, 0x01, 0x00, 0x01]),
        Err(ng::DecodeError::BadVersion { version: 2 })
    );
    // Token length 9 is reserved.
    assert_eq!(
        ng::CoapMessage::decode(&[0x49, 0x01, 0x00, 0x01]),
        Err(ng::DecodeError::BadTokenLength { tkl: 9 })
    );
}

// ===========================================================================
// A response has to fit one datagram, and the model is told so
// ===========================================================================

/// A representation larger than one datagram must be **refused at the action**, with a
/// message the model can act on.
///
/// Without the bound the oversize datagram reaches `send_to`, which fails with `EMSGSIZE`
/// past ~65507 bytes: the error is logged and the peer simply never hears back. A
/// request/response protocol must not produce a fail-silent, and a CON client would
/// retransmit four times and then give up with no diagnostic anywhere on its side.
///
/// The number used to be RFC 7252 §4.6's 1024-byte payload. Block-wise transfer (RFC 7959)
/// now splits anything larger into blocks, so the bound is on the representation the server
/// holds while it serves those blocks: `MAX_REPRESENTATION_LEN`, 64 KiB.
#[test]
fn test_oversize_payload_is_refused_rather_than_silently_dropped() {
    use netget::llm::actions::protocol_trait::Server;
    use netget::server::coap::actions::CoapProtocol;
    use netget::server::coap::codec;

    let protocol = CoapProtocol::new();

    let at_limit = "x".repeat(codec::MAX_REPRESENTATION_LEN);
    assert!(
        protocol
            .execute_action(serde_json::json!({
                "type": "send_coap_response",
                "code": "2.05",
                "payload": at_limit,
            }))
            .is_ok(),
        "exactly MAX_REPRESENTATION_LEN bytes is legal and must still be accepted - a guard that \
         refused everything would pass the over-limit assertion below for the wrong reason"
    );

    let over_limit = "x".repeat(codec::MAX_REPRESENTATION_LEN + 1);
    let err = protocol
        .execute_action(serde_json::json!({
            "type": "send_coap_response",
            "code": "2.05",
            "payload": over_limit,
        }))
        .expect_err("one byte over the limit must be refused");
    let err = err.to_string();
    assert!(
        err.contains(&codec::MAX_REPRESENTATION_LEN.to_string()),
        "the refusal must tell the model the actual limit, got: {err}"
    );
    assert!(
        err.contains("7959") || err.contains("Block-wise"),
        "the refusal should say why there is a ceiling at all when Block-wise transfer \
         splits a representation, got: {err}"
    );

    // The bound is on the decoded bytes, not on the string: two hex digits per byte, so a
    // hex payload of 2 * MAX_REPRESENTATION_LEN characters is exactly at the limit and legal.
    let hex_at_limit = "41".repeat(codec::MAX_REPRESENTATION_LEN);
    assert!(protocol
        .execute_action(serde_json::json!({
            "type": "send_coap_response",
            "code": "2.05",
            "payload": hex_at_limit,
            "encoding": "hex",
        }))
        .is_ok());

    let hex_over_limit = "41".repeat(codec::MAX_REPRESENTATION_LEN + 1);
    assert!(
        protocol
            .execute_action(serde_json::json!({
                "type": "send_coap_response",
                "code": "2.05",
                "payload": hex_over_limit,
                "encoding": "hex",
            }))
            .is_err(),
        "the limit counts decoded bytes; a hex payload must not get twice the budget"
    );

    // A response with no payload at all is unaffected.
    assert!(protocol
        .execute_action(serde_json::json!({
            "type": "send_coap_response",
            "code": "4.04",
        }))
        .is_ok());
}

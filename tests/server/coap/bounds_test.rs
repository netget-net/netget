//! Every bound the CoAP server declares, driven from a UDP socket.
//!
//! "A bound nobody tested is a comment." `ProtocolMetadataV2::max_inbound_bytes` declares
//! `codec::MAX_MESSAGE_LEN`, the codec declares `MAX_TOKEN_LEN`, `MAX_OPTION_LEN` and
//! `MAX_PAYLOAD_LEN`, and `mod.rs` sizes a receive buffer against the first of them. This
//! file is where each of those numbers is made to bite.
//!
//! # Why a separate file from `e2e_test.rs`
//!
//! `tests/max_inbound_bytes_bound_plus_one_test.rs` is the generic probe that sends
//! `bound + 1` to every declaring protocol — and it **skips every UDP protocol**, because it
//! reaches servers with `TcpStream::connect`. CoAP is `ETH>IP>UDP>COAP`, so nothing generic
//! covers it and the per-protocol test is the only coverage there is. That is the case the
//! generic file's own header describes as "the job of the per-protocol tests".
//!
//! # The assertion that makes the size bound mean something
//!
//! Not "the server answered 4.13" on its own — a server that answered 4.13 to *everything*
//! would pass that. Each size test is a pair: the datagram at exactly the bound must still be
//! served, and the one a single byte over must be refused **without the model being asked**.
//! The model-call count is read off the mock directly rather than inferred, because the
//! expensive half of an unbounded inbound path is not the memory, it is that a stranger's
//! oversize message becomes a prompt.

use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use coap_lite::{CoapOption, MessageClass, MessageType, Packet, RequestType};
use netget::server::coap::codec;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Send one datagram and wait for one reply.
async fn exchange(socket: &UdpSocket, server: SocketAddr, out: &[u8]) -> Vec<u8> {
    socket
        .send_to(out, server)
        .await
        .expect("failed to send a CoAP datagram");
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(15), socket.recv_from(&mut buf))
        .await
        .expect("timed out waiting for a CoAP reply")
        .expect("failed to receive a CoAP reply");
    buf.truncate(n);
    buf
}

/// Send one datagram and assert that nothing comes back within `secs`.
async fn expect_silence(socket: &UdpSocket, server: SocketAddr, out: &[u8], secs: u64) {
    socket
        .send_to(out, server)
        .await
        .expect("failed to send a CoAP datagram");
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_secs(secs), socket.recv_from(&mut buf)).await {
        Err(_) => {}
        Ok(Ok((n, _))) => panic!(
            "expected no reply, got {n} bytes: {}",
            hex::encode(&buf[..n])
        ),
        Ok(Err(e)) => panic!("recv failed: {e}"),
    }
}

/// A GET request whose *total encoded length* is exactly `total_len` bytes.
///
/// CoAP's payload has no length field — it runs to the end of the datagram — so growing the
/// payload grows the datagram byte for byte, and the arithmetic below is exact rather than
/// approximate. The test asserts that, so a coap-lite change that made it untrue would be a
/// failure here rather than a silently mis-sized probe.
fn request_of_exact_length(
    message_id: u16,
    token: Vec<u8>,
    path: &str,
    total_len: usize,
) -> Vec<u8> {
    let build = |payload_len: usize| -> Vec<u8> {
        let mut packet = Packet::new();
        packet.header.set_version(1);
        packet.header.set_type(MessageType::Confirmable);
        packet.header.code = MessageClass::Request(RequestType::Post);
        packet.header.message_id = message_id;
        packet.set_token(token.clone());
        packet.add_option(CoapOption::UriPath, path.as_bytes().to_vec());
        packet.payload = vec![b'x'; payload_len];
        packet.to_bytes().expect("coap-lite failed to encode")
    };

    // One byte of payload, so the 0xFF marker is present in the measurement.
    let floor = build(1);
    assert!(
        floor.len() <= total_len,
        "cannot build a {total_len}-byte request: the smallest one is already {}",
        floor.len()
    );
    let out = build(1 + (total_len - floor.len()));
    assert_eq!(
        out.len(),
        total_len,
        "CoAP payload length is supposed to be datagram length minus everything before it"
    );
    out
}

/// Class and detail of a CoAP code byte, as the `c.dd` pair the RFC writes.
fn code_pair(datagram: &[u8]) -> (u8, u8) {
    (datagram[1] >> 5, datagram[1] & 0x1F)
}

// ===========================================================================
// max_inbound_bytes / codec::MAX_MESSAGE_LEN
// ===========================================================================

/// `MAX_MESSAGE_LEN` bytes are served; `MAX_MESSAGE_LEN + 1` is refused 4.13, unasked.
///
/// The number is RFC 7252 §4.6's `MAX_MESSAGE_SIZE`: with the path MTU unknown an endpoint
/// assumes 1152 bytes, and Block-wise transfer (RFC 7959) — the only legal way past it — is
/// not implemented here.
///
/// **Verified by removal.** Deleting the `data.len() > MAX_MESSAGE_LEN` guard in
/// `handle_datagram` makes the over-limit datagram decode normally, reach the model, and be
/// answered 2.05: the `assert_eq!` on the code fails with `(2, 5)`, and `expect_calls(1)` on
/// the mock rule fails with 2 calls. Both halves bite, which is the point of counting the
/// calls as well as reading the code.
#[tokio::test]
async fn test_inbound_message_bound_refuses_one_byte_over_without_asking_the_model() -> E2EResult<()>
{
    let config = NetGetConfig::new("Start a CoAP server on port {AVAILABLE_PORT}")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("CoAP server")
                .and_instruction_containing("on port")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "coap",
                    "instruction": "Bounds probe"
                }]))
                .expect_calls(1)
                .and()
                // Exactly one request may reach the model: the one at the bound. If the
                // guard stops firing this becomes two and verify_mocks says so.
                .on_event("coap_request")
                .and_event_data_contains("path", "/bulk")
                .respond_with_actions_from_event(|event| {
                    let n = event["payload"].as_str().map(str::len).unwrap_or(0);
                    serde_json::json!([{
                        "type": "send_coap_response",
                        "code": "2.05",
                        "payload": format!("accepted {n}"),
                        "content_format": "text/plain"
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    server.wait_for_log("CoAP receive loop started", 15).await?;
    let target: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    // -- exactly at the bound: served ------------------------------------------------
    let token = vec![0xC0, 0xFF, 0xEE, 0x01];
    let at_limit = request_of_exact_length(0x1111, token.clone(), "bulk", codec::MAX_MESSAGE_LEN);
    assert_eq!(at_limit.len(), codec::MAX_MESSAGE_LEN);
    let reply = exchange(&socket, target, &at_limit).await;
    assert_eq!(
        code_pair(&reply),
        (2, 5),
        "a datagram of exactly MAX_MESSAGE_LEN bytes must still be served, or the \
         over-limit assertion below would pass for a server that refuses everything. \
         Reply was {}",
        hex::encode(&reply)
    );
    let decoded = Packet::from_bytes(&reply).expect("coap-lite must accept the 2.05");
    assert_eq!(decoded.header.message_id, 0x1111);
    assert_eq!(decoded.get_token(), &token[..]);
    let body = String::from_utf8_lossy(&decoded.payload).to_string();
    assert!(
        body.starts_with("accepted "),
        "the model answered, so its payload must be what came back, got {body:?}"
    );

    // -- one byte over: refused 4.13, and the model is never asked --------------------
    let over_limit =
        request_of_exact_length(0x2222, token.clone(), "bulk", codec::MAX_MESSAGE_LEN + 1);
    assert_eq!(over_limit.len(), codec::MAX_MESSAGE_LEN + 1);
    let reply = exchange(&socket, target, &over_limit).await;
    assert_eq!(
        code_pair(&reply),
        (4, 13),
        "one byte over MAX_MESSAGE_LEN must be 4.13 Request Entity Too Large (RFC 7252 \
         §5.9.2.9), not decoded and not asked about. Reply was {}",
        hex::encode(&reply)
    );

    // A refusal a client cannot match to its request is silence wearing a response code:
    // CoAP correlates by token equality (§5.3.2) and by message id for a piggybacked ACK.
    let decoded = Packet::from_bytes(&reply).expect("coap-lite must accept the 4.13");
    assert_eq!(
        decoded.header.get_type(),
        MessageType::Acknowledgement,
        "a Confirmable request is answered with an ACK, refusal or not"
    );
    assert_eq!(decoded.header.message_id, 0x2222);
    assert_eq!(decoded.get_token(), &token[..]);
    assert!(
        decoded.payload.is_empty(),
        "the refusal must not carry a body"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // The direct form of the same claim: startup plus exactly one request-shaped call.
    // `expect_calls(1)` above catches a second call that *matched the rule*; this catches
    // one that reached the model by any other route.
    let calls = server.llm_call_count().await.expect("mock model in use");
    assert_eq!(
        calls, 2,
        "expected 1 startup call + 1 request call; an oversize datagram must not become a \
         prompt"
    );

    server.stop().await?;
    Ok(())
}

// ===========================================================================
// codec::MAX_TOKEN_LEN, from the wire
// ===========================================================================

/// A token length the format cannot describe is rejected before the options are walked.
///
/// TKL is four bits and RFC 7252 §3 reserves 9-15, so `MAX_TOKEN_LEN` is a format limit and
/// not a policy. A Confirmable message that cannot be processed gets a Reset (§4.2).
///
/// **Verified by removal**, and the observed failure is more interesting than the predicted
/// one. Deleting the `if tkl > 8` arm in `CoapMessage::decode` makes the datagram decode as a
/// GET carrying a nine-octet token, so it reaches the model — and then the *encode*-side
/// `MAX_TOKEN_LEN` guard refuses to put a nine-octet token in a reply's TKL field, the server
/// logs `decision=fail_closed_encode` and writes nothing. The test fails on the 15-second
/// `exchange` timeout rather than on the RST assertion. Two guards stating the same bound in
/// opposite directions is what turns a wrong reply into no reply; both are load-bearing.
#[tokio::test]
async fn test_reserved_token_length_is_reset_and_never_reaches_the_model() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a CoAP server on port {AVAILABLE_PORT}")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("CoAP server")
                .and_instruction_containing("on port")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "coap",
                    "instruction": "Bounds probe"
                }]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    server.wait_for_log("CoAP receive loop started", 15).await?;
    let target: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    // Ver=1, T=CON, TKL=9 (reserved), Code=0.01 GET, MID=0x0042, then nine token octets so
    // the datagram is long enough for the token it claims — the refusal has to be the
    // reserved length, not a truncation.
    let mut datagram = vec![0x49, 0x01, 0x00, 0x42];
    datagram.extend_from_slice(&[0xAA; 9]);
    let reply = exchange(&socket, target, &datagram).await;

    assert_eq!(
        reply.len(),
        4,
        "a Reset is a bare header: {}",
        hex::encode(&reply)
    );
    assert_eq!(reply[0] >> 6, 1, "version 1");
    assert_eq!((reply[0] >> 4) & 0x03, 3, "T=3 is Reset");
    assert_eq!(reply[0] & 0x0F, 0, "a Reset carries no token");
    assert_eq!(reply[1], 0x00, "code 0.00");
    assert_eq!(
        u16::from_be_bytes([reply[2], reply[3]]),
        0x0042,
        "the Reset must name the message id it rejects, or the client cannot stop \
         retransmitting"
    );

    // A NON message with the same defect gets nothing at all — §4.2 attaches the Reset to
    // the Confirmable case, and inventing one for NON would be a reply the peer never
    // asked for.
    let mut non = vec![0x59, 0x01, 0x00, 0x43];
    non.extend_from_slice(&[0xBB; 9]);
    expect_silence(&socket, target, &non, 3).await;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    let calls = server.llm_call_count().await.expect("mock model in use");
    assert_eq!(
        calls, 1,
        "only the startup call: a malformed datagram must not become a prompt"
    );

    server.stop().await?;
    Ok(())
}

// ===========================================================================
// The encode-side bounds: what the codec refuses to put on the wire
// ===========================================================================

/// `encode` refuses exactly what `decode` refuses, rather than narrowing to fit.
///
/// These two bounds are unreachable from the wire today — a reply's token is echoed from a
/// request `decode` already bounded at 8, and the model never supplies one — so this is a
/// unit test by necessity rather than by preference, and the fact that it is unreachable is
/// itself worth pinning: a future action that let the model choose a token would land on a
/// guard that is already there and already tested.
///
/// **Verified by removal.** Replacing the `TokenTooLong` guard with the old
/// `self.token.len().min(8)` truncation makes `encode` return `Ok` with an eight-octet
/// token, and the first `expect_err` fails; dropping the `OptionTooLong` guard makes the
/// second one fail the same way, with the length silently narrowed by the `as u16`.
#[test]
fn test_encode_refuses_what_decode_would_refuse() {
    // At the limit: still legal, so a guard that refused everything would not pass here.
    let at_limit = codec::CoapMessage {
        mtype: codec::MessageType::Acknowledgement,
        code: codec::CODE_CONTENT,
        message_id: 1,
        token: vec![0xAA; codec::MAX_TOKEN_LEN],
        options: Vec::new(),
        payload: Vec::new(),
    };
    let bytes = at_limit
        .encode()
        .expect("8 octets is the largest legal token");
    assert_eq!(
        bytes[0] & 0x0F,
        codec::MAX_TOKEN_LEN as u8,
        "TKL is the token length"
    );
    assert_eq!(
        codec::CoapMessage::decode(&bytes).expect("our own encoding must decode"),
        at_limit
    );

    // One octet over: refused, with the reason and the number in the message.
    let mut over = at_limit.clone();
    over.token = vec![0xAA; codec::MAX_TOKEN_LEN + 1];
    let err = over
        .encode()
        .expect_err("a 9-octet token has no TKL that can describe it");
    assert_eq!(
        err,
        codec::EncodeError::TokenTooLong {
            len: codec::MAX_TOKEN_LEN + 1
        }
    );
    let text = err.to_string();
    assert!(
        text.contains(&codec::MAX_TOKEN_LEN.to_string()),
        "the refusal must state the limit, got {text:?}"
    );

    // An option value longer than the extended length form can describe. `read_extended`
    // saturates at u16::MAX, so an encoder that narrowed with `as u16` would write a length
    // its own decoder reads as something else.
    let mut big_option = at_limit.clone();
    big_option.options = vec![(codec::OPT_URI_PATH, vec![b'x'; codec::MAX_OPTION_LEN + 1])];
    assert_eq!(
        big_option
            .encode()
            .expect_err("an over-long option value must be refused"),
        codec::EncodeError::OptionTooLong {
            number: codec::OPT_URI_PATH,
            len: codec::MAX_OPTION_LEN + 1,
        }
    );

    // And exactly at the option limit still encodes and decodes back, for the same reason
    // the token case has an at-limit half.
    let mut at_option_limit = at_limit.clone();
    at_option_limit.options = vec![(codec::OPT_URI_PATH, vec![b'x'; codec::MAX_OPTION_LEN])];
    let bytes = at_option_limit
        .encode()
        .expect("an option of exactly MAX_OPTION_LEN octets is legal");
    assert_eq!(
        codec::CoapMessage::decode(&bytes).expect("our own encoding must decode"),
        at_option_limit
    );
}

/// `message_prefix` reads only what lives at a fixed offset, and refuses the rest.
///
/// It is the reason an over-bound datagram can be answered at all: the refusal carries the
/// request's message id and token, which CoAP needs to match a reply to a request, and
/// reading them must not require walking options the server has decided not to trust.
#[test]
fn test_message_prefix_reads_only_the_fixed_offsets() {
    // CON, TKL=2, GET, MID=0x0A0B, token AA BB, then an option the walker never reaches
    // because the bytes after the token are deliberately not a legal option.
    let datagram = [0x42, 0x01, 0x0A, 0x0B, 0xAA, 0xBB, 0xF0, 0x99, 0x99];
    let prefix = codec::message_prefix(&datagram).expect("header and token are readable");
    assert_eq!(prefix.mtype, codec::MessageType::Confirmable);
    assert_eq!(prefix.code, codec::CODE_GET);
    assert_eq!(prefix.message_id, 0x0A0B);
    assert_eq!(prefix.token, vec![0xAA, 0xBB]);
    assert!(
        codec::CoapMessage::decode(&datagram).is_err(),
        "the datagram as a whole must not decode, or this test proves nothing about \
         reading the prefix of something unparseable"
    );

    assert!(
        codec::message_prefix(&[0x40, 0x01, 0x00]).is_none(),
        "short of the header"
    );
    assert!(
        codec::message_prefix(&[0x80, 0x01, 0x00, 0x01]).is_none(),
        "version 2 is not CoAP"
    );
    assert!(
        codec::message_prefix(&[0x49, 0x01, 0x00, 0x01]).is_none(),
        "a reserved token length has no token to read"
    );
    assert!(
        codec::message_prefix(&[0x42, 0x01, 0x00, 0x01, 0xAA]).is_none(),
        "a token that runs off the end is not a token"
    );
}

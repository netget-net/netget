//! RADIUS server tests.
//!
//! Two layers, deliberately:
//!
//! 1. **Codec against literal, independently-verified bytes.** Every hex literal below was
//!    checked with Python's `hashlib` (a genuinely separate MD5 implementation) before being
//!    written here, and the RFC 2865 §7.1 pair is the published example. This is what makes
//!    "the Response Authenticator is correct" a claim rather than a hope.
//! 2. **End-to-end through the real binary**, driven by a raw UDP socket, with the LLM
//!    mocked — including the fail-closed regression tests that OAuth2 never had.
//!
//! A third layer lives in `real_client_test.rs`: FreeRADIUS `radclient`, an entirely
//! independent implementation, which is the only peer here that NetGet did not write.

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use netget::server::radius::packet::{
    self, decode_user_password, encode_response, encode_user_password, verify_accounting_request,
    Attribute, RadiusPacket,
};
use std::time::Duration;
use tokio::net::UdpSocket;

/// RFC 2865 §7.1, the Access-Request on the wire.
///
/// User-Name = "nemo", User-Password = "arctangent" (secret "xyzzy5461"),
/// NAS-IP-Address = 192.168.1.16, NAS-Port = 3.
const RFC_7_1_REQUEST: &str = "01000038\
0f403f9473978057bd83d5cb98f4227a\
01066e656d6f\
0212 0dbe708d93d413ce3196e43f782a0aee\
0406c0a80110\
050600000003";

/// RFC 2865 §7.1, the Access-Accept the RFC shows in reply.
///
/// Service-Type = Login-User, Login-Service = Telnet, Login-IP-Host = 192.168.1.3.
const RFC_7_1_RESPONSE: &str = "02000026\
86fe220e7624ba2a1005f6bf9b55e0b2\
060600000001\
0f0600000000\
0e06c0a80103";

const SECRET: &[u8] = b"xyzzy5461";

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.replace(' ', "")).expect("test literal is not valid hex")
}

// ===========================================================================
// Layer 1 — codec against literal RFC / independently computed bytes
// ===========================================================================

#[test]
fn decodes_the_rfc_2865_7_1_access_request() {
    let bytes = unhex(RFC_7_1_REQUEST);
    let request = RadiusPacket::decode(&bytes).expect("RFC example must decode");

    assert_eq!(request.code, packet::CODE_ACCESS_REQUEST);
    assert_eq!(request.identifier, 0);
    assert_eq!(request.attributes.len(), 4);

    assert_eq!(
        request.first(packet::ATTR_USER_NAME),
        Some(&b"nemo"[..]),
        "User-Name"
    );
    assert_eq!(
        request.first(packet::ATTR_NAS_IP_ADDRESS),
        Some(&[192u8, 168, 1, 16][..]),
        "NAS-IP-Address"
    );
    assert_eq!(
        request.first(packet::ATTR_NAS_PORT),
        Some(&[0u8, 0, 0, 3][..]),
        "NAS-Port"
    );
}

/// The §5.2 unhiding, against the RFC's own ciphertext. If this is wrong the model is handed
/// a password the user never typed, and every authorization decision after it is garbage.
#[test]
fn decrypts_the_rfc_2865_5_2_user_password() {
    let bytes = unhex(RFC_7_1_REQUEST);
    let request = RadiusPacket::decode(&bytes).unwrap();
    let ciphertext = request.first(packet::ATTR_USER_PASSWORD).unwrap();

    let plaintext =
        decode_user_password(ciphertext, &request.authenticator, SECRET).expect("must decrypt");

    assert_eq!(
        String::from_utf8(plaintext).unwrap(),
        "arctangent",
        "RFC 2865 §7.1 password"
    );
}

/// **The one computation that cannot be faked.** A real client discards a reply whose
/// Response Authenticator does not verify, and that looks exactly like the server being
/// down — so this is asserted against the RFC's published reply, byte for byte.
#[test]
fn produces_the_rfc_2865_7_1_access_accept_byte_for_byte() {
    let request = RadiusPacket::decode(&unhex(RFC_7_1_REQUEST)).unwrap();

    let attributes = vec![
        Attribute::integer(packet::ATTR_SERVICE_TYPE, 1), // Login-User
        Attribute::integer(15, 0),                        // Login-Service = Telnet
        Attribute::ipv4(14, "192.168.1.3".parse().unwrap()), // Login-IP-Host
    ];

    let encoded = encode_response(
        packet::CODE_ACCESS_ACCEPT,
        request.identifier,
        &attributes,
        &request.authenticator,
        SECRET,
    )
    .expect("must encode");

    assert_eq!(
        hex::encode(&encoded),
        RFC_7_1_RESPONSE.replace(' ', ""),
        "encoded Access-Accept must match RFC 2865 §7.1 exactly, authenticator included"
    );
}

/// A wrong secret must produce a different authenticator. Without this, a bug that ignored
/// the secret entirely would still pass the test above.
#[test]
fn the_response_authenticator_depends_on_the_secret() {
    let request = RadiusPacket::decode(&unhex(RFC_7_1_REQUEST)).unwrap();
    let attributes = vec![Attribute::integer(packet::ATTR_SERVICE_TYPE, 1)];

    let right = encode_response(
        packet::CODE_ACCESS_ACCEPT,
        request.identifier,
        &attributes,
        &request.authenticator,
        SECRET,
    )
    .unwrap();
    let wrong = encode_response(
        packet::CODE_ACCESS_ACCEPT,
        request.identifier,
        &attributes,
        &request.authenticator,
        b"not-the-secret",
    )
    .unwrap();

    assert_ne!(&right[4..20], &wrong[4..20]);
}

/// Passwords longer than 16 octets chain each block onto the previous ciphertext block.
/// The literal was produced by Python `hashlib`, not by this crate.
#[test]
fn unhides_a_multi_block_password_matching_an_independent_implementation() {
    let ra: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f")
        .try_into()
        .unwrap();
    let expected_cipher = unhex(
        "212c9c8dbc6f67903ca70d1c1ae9ea18\
         0fe2c435330ee84b8346143f67326dcc\
         3d31221cd7a6e4635eb90f5ce2b7be1b",
    );
    let password = b"a-very-long-password-over-32-bytes!!";

    assert_eq!(
        encode_user_password(password, &ra, SECRET).unwrap(),
        expected_cipher,
        "hiding must match the independently computed ciphertext"
    );
    assert_eq!(
        decode_user_password(&expected_cipher, &ra, SECRET).unwrap(),
        password.to_vec(),
        "unhiding must recover the original, pad stripped"
    );
}

#[test]
fn rejects_password_lengths_the_rfc_forbids() {
    let ra = [0u8; 16];
    // Not a multiple of 16.
    assert!(decode_user_password(&[0u8; 20], &ra, SECRET).is_err());
    // Empty.
    assert!(decode_user_password(&[], &ra, SECRET).is_err());
    // Over 128 octets.
    assert!(decode_user_password(&[0u8; 144], &ra, SECRET).is_err());
}

/// RFC 2866 §3. Unlike an Access-Request's random nonce, this authenticator is keyed and
/// therefore checkable — so the server checks it. Literal produced by Python `hashlib`.
#[test]
fn verifies_an_accounting_request_and_rejects_a_forged_one() {
    let bytes = unhex("0407002459d8807212d3a190a4954b6c4457c79128060000000101066e656d6f2c043432");
    let request = RadiusPacket::decode(&bytes).expect("must decode");

    assert_eq!(request.code, packet::CODE_ACCOUNTING_REQUEST);
    assert_eq!(request.identifier, 7);
    assert_eq!(
        request.first(packet::ATTR_ACCT_STATUS_TYPE),
        Some(&[0u8, 0, 0, 1][..]),
        "Acct-Status-Type = Start"
    );

    verify_accounting_request(&request, SECRET)
        .expect("authenticator computed with the right secret must verify");

    assert!(
        verify_accounting_request(&request, b"wrong-secret").is_err(),
        "a packet from a sender that does not hold the secret must be rejected"
    );

    // And the Accounting-Response we would send back.
    let response = encode_response(
        packet::CODE_ACCOUNTING_RESPONSE,
        request.identifier,
        &[],
        &request.authenticator,
        SECRET,
    )
    .unwrap();
    assert_eq!(
        hex::encode(&response),
        "050700144d851d3e6029984a721018be33306f01"
    );
}

#[test]
fn drops_malformed_datagrams() {
    // Shorter than the 20-byte header.
    assert!(RadiusPacket::decode(&[1, 0, 0, 5]).is_err());
    // Header claims more bytes than arrived.
    let mut short = unhex(RFC_7_1_REQUEST);
    short.truncate(30);
    assert!(RadiusPacket::decode(&short).is_err());
    // Attribute length byte of 0 would loop forever in a naive parser.
    let mut bad = unhex("01000016");
    bad.extend_from_slice(&[0u8; 16]);
    bad.extend_from_slice(&[1, 0]); // type 1, length 0
    assert!(RadiusPacket::decode(&bad).is_err());
    // Attribute running past the end of the packet.
    let mut over = unhex("01000018");
    over.extend_from_slice(&[0u8; 16]);
    over.extend_from_slice(&[1, 40, 0, 0]);
    assert!(RadiusPacket::decode(&over).is_err());
}

/// RFC 2865 §3: octets beyond the Length field are padding and must be ignored, not
/// treated as attributes.
#[test]
fn ignores_padding_beyond_the_declared_length() {
    let mut padded = unhex(RFC_7_1_REQUEST);
    padded.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let request = RadiusPacket::decode(&padded).expect("padding must not break decoding");
    assert_eq!(request.attributes.len(), 4);
}

// ===========================================================================
// Layer 2 — end to end through the real binary, LLM mocked
// ===========================================================================

/// Send one RADIUS packet and wait for the reply.
async fn exchange(port: u16, request: &[u8]) -> E2EResult<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket
        .send_to(request, format!("127.0.0.1:{}", port))
        .await?;

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
        .await
        .map_err(|_| "timed out waiting for a RADIUS reply")??;
    buf.truncate(n);

    // The pcap oracle. Every other decode in this file goes through
    // `netget::server::radius::packet`, which is the same code that wrote the reply —
    // agreement there is a tautology. Wireshark's `radius` dissector walks the
    // attribute list independently and objects to a Length that disagrees with the
    // packet, or an attribute whose own length runs past the end. The fail-closed
    // Access-Reject is written on a path the model never sees, so it is the one most
    // likely to carry a hand-computed length that nobody has checked.
    crate::helpers::pcap_oracle::PcapOracle::udp("radius")
        .to_server(request)
        .from_server(&buf)
        .assert_clean();

    Ok(buf)
}

/// Wait for a log line to appear in the captured output.
///
/// The reply arrives on the socket before the server's stdout has necessarily been drained
/// into `output_lines` by the harness's reader task, so a bare `output_contains` right after
/// `exchange()` is a race — it passed on a quiet machine and failed under a full parallel
/// run. This still asserts the line must appear; it only stops asserting *when*.
async fn wait_for_log(server: &helpers::server::NetGetServer, needle: &str) -> bool {
    for _ in 0..100 {
        if server.output_contains(needle).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

fn reply_messages(reply: &RadiusPacket) -> String {
    reply
        .all(packet::ATTR_REPLY_MESSAGE)
        .into_iter()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .collect::<Vec<_>>()
        .join("")
}

/// The model grants access, and the reply is one a real client would accept: right code,
/// echoed identifier, and a Response Authenticator that verifies against the secret.
///
/// The mock derives its answer from the event (`respond_with_actions_from_event`) rather
/// than being a fixed blob, so the test would fail if the server handed the model the wrong
/// user or a wrongly decrypted password.
#[tokio::test]
async fn access_request_accepted_when_the_model_says_so() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via radius with shared secret xyzzy5461. \
         Accept nemo when the password is arctangent, reject everyone else.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_event("radius_access_request")
            .respond_with_actions_from_event(|event| {
                // Derived from the event: if the server mis-decrypted the password or
                // mis-read the user, this becomes a reject and the assertions below fail.
                let user = event["user_name"].as_str().unwrap_or("");
                let password = event["password"].as_str().unwrap_or("");
                if user == "nemo" && password == "arctangent" {
                    serde_json::json!([{
                        "type": "send_access_accept",
                        "reply_message": "Welcome nemo",
                        "framed_ip_address": "192.168.1.3",
                        "service_type": "Login-User",
                        "session_timeout": 3600
                    }])
                } else {
                    serde_json::json!([{
                        "type": "send_access_reject",
                        "reply_message": "Invalid credentials"
                    }])
                }
            })
            .expect_calls(1)
            .and()
            .on_instruction_containing("via radius")
            .respond_with_actions_from_event(|_| {
                serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "radius",
                    "startup_params": {"shared_secret": "xyzzy5461"},
                    "instruction": "Accept nemo/arctangent, reject everyone else"
                }])
            })
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let raw = exchange(server.port, &unhex(RFC_7_1_REQUEST)).await?;
    let reply = RadiusPacket::decode(&raw).expect("reply must be a well-formed RADIUS packet");

    assert_eq!(
        reply.code,
        packet::CODE_ACCESS_ACCEPT,
        "expected Access-Accept, got {}",
        packet::code_name(reply.code)
    );
    assert_eq!(reply.identifier, 0, "identifier must be echoed");

    // Re-derive the Response Authenticator the way a client would.
    let request = RadiusPacket::decode(&unhex(RFC_7_1_REQUEST)).unwrap();
    let expected = packet::response_authenticator(
        reply.code,
        reply.identifier,
        &raw[20..],
        &request.authenticator,
        SECRET,
    );
    assert_eq!(
        reply.authenticator, expected,
        "Response Authenticator must verify; a real client discards the reply otherwise"
    );

    assert_eq!(reply_messages(&reply), "Welcome nemo");
    assert_eq!(
        reply.first(packet::ATTR_FRAMED_IP_ADDRESS),
        Some(&[192u8, 168, 1, 3][..]),
        "Framed-IP-Address the model chose"
    );
    assert_eq!(
        reply.first(packet::ATTR_SESSION_TIMEOUT),
        Some(&3600u32.to_be_bytes()[..])
    );
    assert_eq!(
        reply.first(packet::ATTR_SERVICE_TYPE),
        Some(&1u32.to_be_bytes()[..]),
        "'Login-User' must really be translated to 1, not passed through as text"
    );

    assert!(
        wait_for_log(&server, "decision=model_accept").await,
        "the grant must be logged as the model's decision. Output: {:?}",
        server.get_output().await
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// **The OAuth2 regression test.**
///
/// OAuth2 fell through to a hardcoded token when the LLM returned nothing usable, so an LLM
/// outage silently issued credentials. RADIUS must do the opposite: no decision means
/// Access-Reject, and it must be labelled as the *server's* denial, not the model's.
#[tokio::test]
async fn fails_closed_when_the_model_returns_nothing() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via radius with shared secret xyzzy5461.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock
            // The model answers, but with no protocol action at all — the exact shape that
            // turned into an approval in OAuth2.
            .on_event("radius_access_request")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("via radius")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "radius",
                "startup_params": {"shared_secret": "xyzzy5461"},
                "instruction": "Decide who may connect"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let raw = exchange(server.port, &unhex(RFC_7_1_REQUEST)).await?;
    let reply = RadiusPacket::decode(&raw).expect("even the denial must be well formed");

    assert_eq!(
        reply.code,
        packet::CODE_ACCESS_REJECT,
        "no decision MUST deny. Got {}",
        packet::code_name(reply.code)
    );

    // The whole synthesised packet, byte for byte, against a literal computed with Python's
    // hmac and hashlib. This pins the denial and both of its signatures: the RFC 3579
    // Message-Authenticator (first attribute, HMAC-MD5 over the reply with the Request
    // Authenticator in place) and the Response Authenticator that then covers it.
    assert_eq!(
        hex::encode(&raw),
        "0300005db4669b514d44711ec4fe19e0ad2191b3\
         50127277f47e15336e8e8f09aff9a26cabf01237\
         4163636573732064656e6965643a206e6f206175\
         74686f72697a6174696f6e206465636973696f6e\
         207761732070726f6475636564",
        "fail-closed Access-Reject must be exactly the packet an independent implementation \
         computes"
    );

    assert_eq!(
        reply_messages(&reply),
        "Access denied: no authorization decision was produced",
        "the Reply-Message must say the server denied, not the model"
    );

    assert!(
        wait_for_log(&server, "decision=fail_closed_no_action").await,
        "silence must be logged as fail_closed_no_action. Output: {:?}",
        server.get_output().await
    );
    assert!(
        !server.output_contains("decision=model_reject").await,
        "silence must NOT be recorded as a model decision — that conflation is the OAuth2 bug"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The other half of the pair: an explicit denial is also Access-Reject on the wire, but is
/// distinguishable from silence both in the log and in its Reply-Message.
#[tokio::test]
async fn model_denial_is_distinguishable_from_silence() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via radius with shared secret xyzzy5461.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_event("radius_access_request")
            .respond_with_actions_from_event(|event| {
                let user = event["user_name"].as_str().unwrap_or("");
                serde_json::json!([{
                    "type": "send_access_reject",
                    "reply_message": format!("{} is not permitted here", user)
                }])
            })
            .expect_calls(1)
            .and()
            .on_instruction_containing("via radius")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "radius",
                "startup_params": {"shared_secret": "xyzzy5461"},
                "instruction": "Deny everyone"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let raw = exchange(server.port, &unhex(RFC_7_1_REQUEST)).await?;
    let reply = RadiusPacket::decode(&raw).unwrap();

    assert_eq!(reply.code, packet::CODE_ACCESS_REJECT);
    assert_eq!(
        reply_messages(&reply),
        "nemo is not permitted here",
        "the model's own reason must reach the wire"
    );
    assert_ne!(
        reply_messages(&reply),
        "Access denied: no authorization decision was produced",
        "a model denial must not look like the server's fail-closed denial"
    );

    assert!(
        wait_for_log(&server, "decision=model_reject").await,
        "Output: {:?}",
        server.get_output().await
    );
    assert!(
        !server
            .output_contains("decision=fail_closed_no_action")
            .await,
        "an explicit denial must not be logged as a fail-closed one"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Access-Challenge carries a State the NAS echoes; the model must be able to recognise the
/// continuation. This checks the State survives the round trip in both directions.
#[tokio::test]
async fn access_challenge_state_round_trips() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via radius with shared secret xyzzy5461.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_event("radius_access_request")
            .respond_with_actions_from_event(|event| {
                // First request has no State; the continuation echoes ours back.
                match event["state"].as_str() {
                    Some("otp-round-1") => serde_json::json!([{
                        "type": "send_access_accept",
                        "reply_message": "Code accepted"
                    }]),
                    _ => serde_json::json!([{
                        "type": "send_access_challenge",
                        "state": "otp-round-1",
                        "reply_message": "Enter your one-time code"
                    }]),
                }
            })
            .expect_calls(2)
            .and()
            .on_instruction_containing("via radius")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "radius",
                "startup_params": {"shared_secret": "xyzzy5461"},
                "instruction": "Challenge for a one-time code, then accept"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let first = RadiusPacket::decode(&exchange(server.port, &unhex(RFC_7_1_REQUEST)).await?)
        .expect("challenge must decode");
    assert_eq!(first.code, packet::CODE_ACCESS_CHALLENGE);
    assert_eq!(
        first.first(packet::ATTR_STATE),
        Some(&b"otp-round-1"[..]),
        "State must reach the wire as the model wrote it"
    );

    // Build the continuation: same shape, new identifier and authenticator, plus the State.
    let mut continuation = Vec::new();
    let authenticator: [u8; 16] = *b"0123456789abcdef";
    let attributes = vec![
        Attribute::text(packet::ATTR_USER_NAME, "nemo"),
        Attribute::new(
            packet::ATTR_USER_PASSWORD,
            encode_user_password(b"123456", &authenticator, SECRET).unwrap(),
        ),
        Attribute::new(packet::ATTR_STATE, b"otp-round-1".to_vec()),
    ];
    let mut attr_bytes = Vec::new();
    for attr in &attributes {
        attr_bytes.extend_from_slice(&attr.encode().unwrap());
    }
    continuation.push(packet::CODE_ACCESS_REQUEST);
    continuation.push(9);
    continuation.extend_from_slice(&((20 + attr_bytes.len()) as u16).to_be_bytes());
    continuation.extend_from_slice(&authenticator);
    continuation.extend_from_slice(&attr_bytes);

    let second = RadiusPacket::decode(&exchange(server.port, &continuation).await?)
        .expect("continuation reply must decode");
    assert_eq!(
        second.code,
        packet::CODE_ACCESS_ACCEPT,
        "the model must have seen the echoed State"
    );
    assert_eq!(second.identifier, 9, "identifier of the second request");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

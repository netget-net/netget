//! Every bound the DNS server declares, driven from a UDP socket where it is reachable
//! from one and from the executor where it is not.
//!
//! "A bound nobody tested is a comment." DNS declares no `max_inbound_bytes` — it is one of
//! the "fixed-size read" entries in `tests/max_inbound_bytes_declaration_test.rs`, on the
//! reason "single recv_from into a fixed 4096-byte buffer; no TCP path exists" — so the
//! receive buffer *is* the bound and it is the first thing tested here. The rest are the
//! range checks the action executor states in its own error messages: the 16-bit transaction
//! id, the 16-bit MX preference, the 12-byte floor on a hand-assembled message, and the
//! 255-octet DNS character-string.
//!
//! # What the receive-buffer test proves, and how it was checked
//!
//! A `recv_from` into a 4096-byte buffer silently discards whatever does not fit, so the
//! bound is not a refusal — it is a truncation, after which the bytes do not parse as DNS
//! and the datagram is dropped. That is a weaker property than CoAP's 4.13 and it is stated
//! rather than dressed up: what it guarantees is that **no allocation and no prompt scales
//! with what the peer sent**, which is the property `max_inbound_bytes` exists for.
//!
//! The pair is what makes it mean anything: a legal query is answered in the same test, so a
//! server that dropped everything would fail rather than pass.

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use hickory_proto::op::{Message as DnsMessage, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use netget::llm::actions::protocol_trait::Server;
use netget::server::DnsProtocol;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// The receive buffer in `src/server/dns/mod.rs`. Restated here rather than imported
/// because it is a literal in a `vec![0u8; 4096]` and not a `pub const` — if it is ever
/// promoted to one, import it and delete this.
const DNS_RECV_BUFFER: usize = 4096;

/// Build a syntactically valid DNS query whose encoding is at least `min_len` bytes.
///
/// Repeated questions rather than a giant name: a label is capped at 63 octets and a name at
/// 255 by the wire format itself, so one question cannot get near 4 KiB. QDCOUNT is what
/// grows, and that matters for the truncation property being tested — the header still
/// *claims* every question, so a decoder handed the first 4096 bytes runs off the end of the
/// last one and errors, rather than quietly parsing a shorter message.
fn oversize_query(first_domain: &str, min_len: usize) -> (Vec<u8>, u16) {
    let mut message = DnsMessage::new();
    message.set_id(0x4242);
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    message.set_recursion_desired(true);
    message.add_query(Query::query(
        Name::from_str(first_domain).expect("valid name"),
        RecordType::A,
    ));

    let mut filler = 0usize;
    loop {
        let bytes = message.to_vec().expect("a query must encode");
        if bytes.len() >= min_len {
            return (bytes, message.queries().len() as u16);
        }
        // Distinct names, so nothing is compressed away into a pointer.
        let name = format!("pad{filler}.filler-{filler}.example.invalid.");
        message.add_query(Query::query(
            Name::from_str(&name).expect("valid name"),
            RecordType::A,
        ));
        filler += 1;
    }
}

// ===========================================================================
// The receive buffer is the inbound bound
// ===========================================================================

/// A datagram larger than the receive buffer is dropped, and the model is never asked.
///
/// **Verified by removal.** Raising `vec![0u8; 4096]` in `src/server/dns/mod.rs` to
/// `vec![0u8; 65535]` delivers the whole 8 KiB query, `DnsMessage::from_vec` accepts it, the
/// first question is `bounds.example.com` and it matches the mock rule — so the rule's
/// `expect_calls(1)` fails with 2 and the call-count assertion fails with 3. The zero is
/// therefore the buffer's and not the routing table's.
#[tokio::test]
async fn test_a_datagram_past_the_receive_buffer_is_dropped_and_never_asked() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via dns for a bounds probe")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("dns")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DNS",
                    "instruction": "Bounds probe"
                }]))
                .expect_calls(1)
                .and()
                .on_event("dns_query")
                .and_event_data_contains("domain", "bounds.example.com")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_dns_a_response",
                        "query_id": event["query_id"],
                        "domain": event["domain"],
                        "ip": "192.0.2.7",
                        "ttl": 60,
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    server.wait_for_log("DNS server listening on", 20).await?;
    let target: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    // -- control: a legal query is answered ------------------------------------------
    let (small, _) = oversize_query("bounds.example.com.", 0);
    assert!(
        small.len() < DNS_RECV_BUFFER,
        "the control query must fit the buffer, it is {} bytes",
        small.len()
    );
    socket.send_to(&small, target).await?;
    let mut buf = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(15), socket.recv_from(&mut buf))
        .await
        .map_err(|_| "timed out waiting for the answer to a legal DNS query")??;
    // The pcap oracle over the *success* path. `llm_failure_test.rs` runs it over a SERVFAIL,
    // which is the reply most likely to have counts that disagree with its body — but until
    // this call the oracle had never read a NOERROR answer with rdata in it, because every
    // other success-path test drives hickory-client and never sees bytes. An independent
    // dissector reading an A record is a different assertion from hickory decoding what
    // hickory encoded.
    crate::helpers::pcap_oracle::PcapOracle::udp("dns")
        .to_server(&small)
        .from_server(&buf[..n])
        .assert_clean();

    let answer = DnsMessage::from_vec(&buf[..n]).expect("the reply must be a DNS message");
    assert_eq!(answer.id(), 0x4242, "the transaction id must come back");
    assert_eq!(answer.answers().len(), 1, "one A record");

    // -- the bound: 8 KiB is dropped without a reply and without a prompt --------------
    let (big, questions) = oversize_query("bounds.example.com.", 2 * DNS_RECV_BUFFER);
    assert!(
        big.len() > DNS_RECV_BUFFER,
        "the probe must exceed the receive buffer"
    );
    println!("[bounds] sending {} bytes, QDCOUNT={questions}", big.len());
    socket.send_to(&big, target).await?;
    match tokio::time::timeout(Duration::from_secs(4), socket.recv_from(&mut buf)).await {
        Err(_) => {}
        Ok(Ok((n, _))) => panic!(
            "a datagram past the receive buffer was answered with {n} bytes; the truncated \
             bytes are not a DNS message and must not be acted on: {}",
            hex::encode(&buf[..n.min(64)])
        ),
        Ok(Err(e)) => panic!("recv failed: {e}"),
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    let calls = server.llm_call_count().await.expect("mock model in use");
    assert_eq!(
        calls, 2,
        "startup plus the one legal query. An oversize datagram must not become a prompt, \
         and the control above is what makes this number mean something rather than \
         measuring a server nobody reached"
    );

    server.stop().await?;
    Ok(())
}

// ===========================================================================
// The range checks the executor states
// ===========================================================================

/// The transaction id is refused outside 0-65535 rather than narrowed with `as u16`.
///
/// This is the one bound whose *violation* is invisible on the wire: a truncated id produces
/// a perfectly well-formed response that the client silently discards as unsolicited, so the
/// query times out with no diagnostic at either end. `parse_query_id` exists for that.
///
/// **Verified by removal.** Replacing the `u16::try_from` with `raw as u16` makes
/// `execute_action` return `Ok` for 65536 — and the value it puts in the header is `0`, the
/// id of nobody's query — so both `expect_err` assertions below fail.
#[test]
fn test_query_id_is_refused_outside_sixteen_bits_rather_than_truncated() {
    let protocol = DnsProtocol::new();
    let at_limit = protocol.execute_action(serde_json::json!({
        "type": "send_dns_a_response",
        "query_id": 65535,
        "domain": "example.com.",
        "ip": "192.0.2.1",
    }));
    assert!(
        at_limit.is_ok(),
        "65535 is a legal transaction id and must still be accepted: {at_limit:?}"
    );

    for over in [65536u64, 70000, u32::MAX as u64] {
        let err = protocol
            .execute_action(serde_json::json!({
                "type": "send_dns_a_response",
                "query_id": over,
                "domain": "example.com.",
                "ip": "192.0.2.1",
            }))
            .expect_err("an out-of-range transaction id must be refused, not truncated")
            .to_string();
        assert!(
            err.contains("65535") && err.contains(&over.to_string()),
            "the refusal must name the range and the value it got, so the model can fix it; \
             got {err:?}"
        );
    }
}

/// The MX preference is a 16-bit field and is refused rather than narrowed.
///
/// **Verified by removal.** With `u16::try_from` replaced by `as u16`, 65536 becomes
/// preference 0 — the *highest* priority rather than a rejected value — and the `expect_err`
/// fails.
#[test]
fn test_mx_preference_is_refused_outside_sixteen_bits() {
    let protocol = DnsProtocol::new();
    assert!(protocol
        .execute_action(serde_json::json!({
            "type": "send_dns_mx_response",
            "query_id": 1,
            "domain": "example.com.",
            "exchange": "mail.example.com.",
            "preference": 65535,
        }))
        .is_ok());

    let err = protocol
        .execute_action(serde_json::json!({
            "type": "send_dns_mx_response",
            "query_id": 1,
            "domain": "example.com.",
            "exchange": "mail.example.com.",
            "preference": 65536,
        }))
        .expect_err("an out-of-range preference must be refused")
        .to_string();
    assert!(
        err.contains("65535"),
        "the refusal must name the range: {err:?}"
    );
}

/// `send_dns_response` refuses anything shorter than a DNS header.
///
/// The escape hatch takes wire bytes, so it is the one action where the model can put
/// anything at all on the wire; 12 octets is the floor below which what it produced cannot be
/// a DNS message under any reading.
///
/// **Verified by removal.** Deleting the `bytes.len() < 12` bail makes an 11-byte fragment
/// `Ok`, and the `expect_err` fails — the server would then `send_to` eleven bytes that every
/// resolver discards without a diagnostic.
#[test]
fn test_raw_dns_response_requires_a_full_header() {
    let protocol = DnsProtocol::new();

    // Exactly a header: legal, so the guard is not simply refusing everything.
    let header_only = "0042818000010000000000000";
    assert!(protocol
        .execute_action(serde_json::json!({
            "type": "send_dns_response",
            "data": &header_only[..24],
        }))
        .is_ok());

    let err = protocol
        .execute_action(serde_json::json!({
            "type": "send_dns_response",
            "data": &header_only[..22], // 11 bytes
        }))
        .expect_err("11 bytes cannot be a DNS message")
        .to_string();
    assert!(
        err.contains("12-byte header"),
        "the refusal must say what the floor is: {err:?}"
    );

    // And it is hex-only: a plain string is refused rather than sent as its own bytes, which
    // is what used to happen and put non-DNS garbage on the wire.
    assert!(protocol
        .execute_action(serde_json::json!({
            "type": "send_dns_response",
            "data": "this is not hex at all",
        }))
        .is_err());
}

/// A TXT character-string is 255 octets, and going over is refused with a legible message.
///
/// RFC 1035 §3.3.14 builds a TXT record out of `<character-string>`s, and §3.3 defines one as
/// a single length octet followed by that many characters — so 255 is a **format** limit, not
/// a policy. hickory's encoder refuses to emit a longer one, which is correct; what was wrong
/// is where the refusal landed. `finish_response`'s `to_vec()` failed deep inside the action,
/// the action failed, no `ActionResult::Output` was produced, and `src/server/dns/mod.rs`
/// took the `Ok` branch with an empty result set and wrote **nothing** — a fail-silent, and
/// exactly the shape `coap`'s `MAX_PAYLOAD_LEN` exists to prevent on the other protocol.
///
/// The bound is now stated where the model can act on it, in `execute_send_dns_txt_response`.
///
/// **Verified by removal.** Deleting the `text.len() > MAX_CHARACTER_STRING_LEN` bail puts
/// the failure back inside hickory's encoder: `execute_action` still returns `Err`, so the
/// first `expect_err` still passes — but the message becomes "Failed to serialize DNS
/// message", the `err.contains("255")` assertion fails, and the model is told nothing it can
/// act on.
#[test]
fn test_txt_character_string_is_bounded_at_255_octets() {
    let protocol = DnsProtocol::new();

    let at_limit = "t".repeat(255);
    assert!(
        protocol
            .execute_action(serde_json::json!({
                "type": "send_dns_txt_response",
                "query_id": 7,
                "domain": "example.com.",
                "text": at_limit,
            }))
            .is_ok(),
        "255 octets is exactly one character-string and must still be accepted"
    );

    let over = "t".repeat(256);
    let err = protocol
        .execute_action(serde_json::json!({
            "type": "send_dns_txt_response",
            "query_id": 7,
            "domain": "example.com.",
            "text": over,
        }))
        .expect_err("256 octets cannot be one DNS character-string")
        .to_string();
    assert!(
        err.contains("255") && err.contains("256"),
        "the refusal must name the limit and what it got, so the model can shorten it: \
         {err:?}"
    );
    assert!(
        err.contains("1035"),
        "and where the limit comes from: {err:?}"
    );
}

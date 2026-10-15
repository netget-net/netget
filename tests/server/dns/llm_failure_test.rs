//! What a DNS client gets when the LLM backend fails.
//!
//! The failure is forced by configuring a mock for the *startup* instruction only. The
//! `dns_query` event then matches no rule, the mock Ollama server answers HTTP 500, and
//! `call_llm` returns `Err` - the same shape as a real backend outage, an overload, or a
//! malformed model response.
//!
//! Before this path existed the server wrote nothing at all, and the client sat in `recvfrom`
//! until its own timeout (5s per server in glibc's resolver) with no way to tell an outage from
//! a black hole. The assertion below is at the protocol level: RCODE 2 (SERVFAIL), the
//! transaction ID echoed, and the question section repeated - all three are required or a real
//! stub resolver discards the packet and we are back to silence.


use crate::helpers::pcap_oracle::PcapOracle;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use hickory_proto::op::{Message as DnsMessage, MessageType, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::UdpSocket;

const QUERY_ID: u16 = 0xBEEF;

#[tokio::test]
async fn test_dns_answers_servfail_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via dns. Respond to A queries for example.com";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via dns")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DNS",
                    "instruction": "Respond to A queries for example.com"
                }
            ]))
            .expect_calls(1)
            .and()
        // Deliberately NO rule for the `dns_query` event: the mock answers 500,
        // which is what drives the server down its LLM-failure path.
    });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Build a real DNS query rather than driving a resolver: a resolver would hide the
    // wire-level detail this test is about.
    let mut query = DnsMessage::new();
    query.set_id(QUERY_ID);
    query.set_message_type(MessageType::Query);
    query.set_recursion_desired(true);
    query.add_query(hickory_proto::op::Query::query(
        Name::from_str("example.com.")?,
        RecordType::A,
    ));
    let query_bytes = query.to_bytes()?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;
    socket.send(&query_bytes).await?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(20), socket.recv(&mut buf))
        .await
        .map_err(|_| {
            "No DNS response within 20s - the server went silent on LLM failure, which is the \
             exact defect this test exists to catch"
        })??;

    // Byte-level check first, independent of any decoder: RCODE is the low nibble of byte 3,
    // and QR (byte 2 bit 7) must be set for this to be a response at all.
    assert!(n >= 12, "response is shorter than a DNS header: {n} bytes");
    assert_eq!(buf[0], (QUERY_ID >> 8) as u8, "transaction ID high byte");
    assert_eq!(buf[1], (QUERY_ID & 0xFF) as u8, "transaction ID low byte");
    assert_eq!(buf[2] & 0x80, 0x80, "QR bit must mark this as a response");
    assert_eq!(buf[3] & 0x0F, 2, "RCODE must be 2 (SERVFAIL)");

    // The pcap oracle. hickory parsing its own way through the bytes says the packet
    // is self-consistent; Wireshark's DNS dissector is a second, unrelated reading of
    // RFC 1035, and a SERVFAIL is exactly where a server is most likely to emit a
    // header whose counts do not match the body it then writes.
    PcapOracle::udp("dns")
        .to_server(&query_bytes)
        .from_server(&buf[..n])
        .assert_clean();

    let response = DnsMessage::from_vec(&buf[..n])?;
    assert_eq!(response.id(), QUERY_ID, "transaction ID must be echoed");
    assert_eq!(response.message_type(), MessageType::Response);
    assert_eq!(
        response.response_code(),
        ResponseCode::ServFail,
        "LLM failure must be reported as SERVFAIL"
    );
    assert_eq!(
        response.answers().len(),
        0,
        "a SERVFAIL must not carry answers"
    );

    // The question section must come back, or glibc/systemd-resolved/dig discard the packet.
    // This regressed once before (fixed in 6a384617) and is easy to lose again.
    let questions = response.queries();
    assert_eq!(questions.len(), 1, "question section must be echoed");
    assert_eq!(questions[0].name(), &Name::from_str("example.com.")?);
    assert_eq!(questions[0].query_type(), RecordType::A);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The other two ways a model answer can produce no packet, which must not look alike.
///
/// `call_llm` returning `Err` — the case above — was the only fail-closed path this server
/// had. But it returns **`Ok`** whenever the model produced a syntactically valid answer that
/// this protocol could not turn into bytes:
///
/// * an answer made only of *common* actions (`show_message` is the one a model reaches for
///   when it is explaining itself), which never enter `protocol_results` at all;
/// * a DNS action `execute_action` refused — an invalid IP, an out-of-range `query_id`, a TXT
///   string over 255 octets — which is recorded as a failure and produces no output.
///
/// In both cases the old loop iterated an empty (or output-less) result set and simply ended,
/// having written nothing: the client waited out its own timeout, while
/// `src/server/dns/CLAUDE.md` claimed in as many words that "backend down, overloaded, or
/// returned nothing usable" all answered SERVFAIL. Only the first two did.
///
/// The test drives both halves against **one** server, because the assertion is that they are
/// *different*: `show_message` must be SERVFAIL and `ignore_query` must be silence. A fix that
/// answered SERVFAIL to everything would pass the first half and fail the second, which is the
/// point — `ignore_query` is a decision the model is entitled to make, and a DNS black hole is
/// a thing people build on purpose.
///
/// **Verified by removal.** Reverting the `wrote_answer` / `model_chose_silence` bookkeeping in
/// `src/server/dns/mod.rs` to the bare `for` loop makes the `show_message` query time out at
/// the 20-second deadline below; the test returns `Err` there, so the black-hole half is never
/// reached and the harness's own drop check reports rule #2 with 0 of 1 calls.
#[tokio::test]
async fn test_dns_distinguishes_no_usable_action_from_a_deliberate_black_hole() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via dns for a fail-closed probe";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via dns")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DNS",
                    "instruction": "Fail-closed probe"
                }
            ]))
            .expect_calls(1)
            .and()
            // A valid model answer this protocol cannot send: `show_message` is a common
            // action, so it never reaches `protocol_results`.
            .on_event("dns_query")
            .and_event_data_contains("domain", "nothing-usable.example.com")
            .respond_with_actions(serde_json::json!([
                {"type": "show_message", "message": "thinking about it"}
            ]))
            .expect_calls(1)
            .and()
            // The model choosing silence on purpose.
            .on_event("dns_query")
            .and_event_data_contains("domain", "blackhole.example.com")
            .respond_with_actions(serde_json::json!([{"type": "ignore_query"}]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(server_config).await?;
    server.wait_for_log("DNS server listening on", 20).await?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;

    fn query_for(id: u16, domain: &str) -> E2EResult<Vec<u8>> {
        let mut query = DnsMessage::new();
        query.set_id(id);
        query.set_message_type(MessageType::Query);
        query.set_recursion_desired(true);
        query.add_query(hickory_proto::op::Query::query(
            Name::from_str(domain)?,
            RecordType::A,
        ));
        Ok(query.to_bytes()?)
    }

    // --- no usable action -> SERVFAIL -------------------------------------------------
    let bytes = query_for(0x0A0A, "nothing-usable.example.com.")?;
    socket.send(&bytes).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(20), socket.recv(&mut buf))
        .await
        .map_err(|_| {
            "No DNS response within 20s. The model answered, but with nothing this server \
             could send, and the server went silent instead of failing closed - which is the \
             defect this test exists to catch"
        })??;

    PcapOracle::udp("dns")
        .to_server(&bytes)
        .from_server(&buf[..n])
        .assert_clean();

    let response = DnsMessage::from_vec(&buf[..n])?;
    assert_eq!(response.id(), 0x0A0A, "transaction ID must be echoed");
    assert_eq!(
        response.response_code(),
        ResponseCode::ServFail,
        "an unusable model answer must fail closed, not fall through to silence"
    );
    assert_eq!(response.answers().len(), 0);
    assert_eq!(
        response.queries().len(),
        1,
        "question section must be echoed or a stub resolver discards the packet"
    );

    // --- ignore_query -> silence, and it must stay silence -----------------------------
    let bytes = query_for(0x0B0B, "blackhole.example.com.")?;
    socket.send(&bytes).await?;
    match tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf)).await {
        Err(_) => {}
        Ok(Ok(n)) => panic!(
            "`ignore_query` must send nothing; got {n} bytes: {}",
            hex::encode(&buf[..n])
        ),
        Ok(Err(e)) => panic!("recv failed: {e}"),
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

//! End-to-end tests for the LLMNR (RFC 4795) responder.
//!
//! **These tests build their queries with `hickory-proto`, which is the same crate the server
//! encodes its responses with. That is CIRCULAR evidence** — the failure mode the root
//! `CLAUDE.md` names for `webrtc_signaling`/`websocket`, where the "independent peer" turned
//! out to be the library the server itself framed with. It proves the codec round-trips
//! through itself and that NetGet's own wiring (event, routing, actions, decision, socket) is
//! correct; it proves nothing about interoperability with a real LLMNR querier. See
//! `tests/server/llmnr/CLAUDE.md` for what was checked and why no independent client exists.
//!
//! Half of what is asserted here is the *absence* of a datagram, which is the protocol's
//! required behaviour and is the thing most likely to break silently. Each silence assertion
//! first waits for the server's own `decision=` line, so it never passes merely because the
//! server had not got round to answering yet.

use crate::helpers::{self, E2EResult, NetGetConfig};
use hickory_proto::op::{Message as DnsMessage, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const OWNED_NAME: &str = "printer.local.";
const UNOWNED_NAME: &str = "stranger.local.";
const REFUSED_NAME: &str = "broken.local.";
const OWNED_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 42);

/// Build an LLMNR query.
///
/// LLMNR reuses the DNS message format, so this is a DNS query with two deliberate
/// differences: the `C` bit (DNS's `AA`) and the `T` bit (DNS's `RD`) are both left clear.
/// A DNS client would set `RD` here; in LLMNR that bit means "tentative" and setting it would
/// be a different message.
fn llmnr_query(id: u16, name: &str, record_type: RecordType) -> E2EResult<Vec<u8>> {
    let mut message = DnsMessage::new();
    message.set_id(id);
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    message.set_authoritative(false); // C = 0
    message.set_recursion_desired(false); // T = 0
    message.set_recursion_available(false); // part of LLMNR's Z field

    let mut question = Query::query(Name::from_str(name)?, record_type);
    question.set_query_class(DNSClass::IN);
    message.add_query(question);

    Ok(message.to_bytes()?)
}

/// Assert that nothing at all comes back.
///
/// Callers wait for the server's `decision=` log line *first*, so by the time this runs the
/// server has already finished deciding — a timeout here means it decided to say nothing,
/// not that it was still thinking.
async fn expect_silence(socket: &UdpSocket, what: &str) -> E2EResult<()> {
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_millis(1500), socket.recv(&mut buf)).await {
        Err(_) => Ok(()),
        Ok(Ok(n)) => Err(format!(
            "{what}: expected NO datagram, got {n} bytes ({}). An LLMNR responder that answers \
             here writes a binding into the querier's name cache that no host actually claims.",
            hex::encode(&buf[..n])
        )
        .into()),
        Ok(Err(e)) => Err(format!("{what}: socket error while expecting silence: {e}").into()),
    }
}

/// One server, four queries: the answer, the two silences, and the TCP-only RCODE.
///
/// They share a server deliberately — the mock budget is per suite, and the four rules are
/// distinguishable by name so first-match-wins cannot misroute them.
#[tokio::test]
async fn test_llmnr_answers_only_for_names_it_owns() -> E2EResult<()> {
    // LLMNR binds TCP to the UDP listener's actual port, including port-0 startup.
    let port = 0u16;
    let prompt = format!(
        "listen on port {port} via llmnr and answer for {OWNED_NAME} only, staying silent for \
         every other name"
    );

    let server_config = NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(move |mock| {
            mock
                // Startup.
                .on_instruction_containing("via llmnr")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": port,
                    "base_stack": "LLMNR",
                    "instruction": "Answer LLMNR queries for printer.local only"
                }]))
                .expect_calls(1)
                .and()
                // A name this host owns. The transaction ID MUST come from the event: the querier
                // picks it at random and discards a response carrying anything else.
                .on_event("llmnr_query")
                .and_event_data_contains("name", OWNED_NAME)
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_llmnr_response",
                        "transaction_id": event["transaction_id"].as_u64().unwrap_or(0),
                        "name": event["name"].as_str().unwrap_or(OWNED_NAME),
                        "record_type": "A",
                        "address": OWNED_ADDRESS.to_string(),
                        "ttl": 30
                    }])
                })
                .expect_calls(1)
                .and()
                // A name this host does not own: RFC 4795 requires silence, not NXDOMAIN.
                .on_event("llmnr_query")
                .and_event_data_contains("name", UNOWNED_NAME)
                .respond_with_actions(serde_json::json!([{"type": "no_response"}]))
                .expect_calls(1)
                .and()
                // An explicit RCODE refusal, asked for twice: once over UDP (where it must be
                // suppressed) and once over TCP (where it is legal).
                .on_event("llmnr_query")
                .and_event_data_contains("name", REFUSED_NAME)
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_llmnr_error",
                        "transaction_id": event["transaction_id"].as_u64().unwrap_or(0),
                        "name": event["name"].as_str().unwrap_or(REFUSED_NAME),
                        "query_type": event["query_type"].as_str().unwrap_or("A"),
                        "rcode": "REFUSED"
                    }])
                })
                .expect_calls(2)
                .and()
        });

    let server = helpers::start_netget_server(server_config).await?;
    assert_ne!(server.port, 0, "the responder must report its bound port");
    let target = format!("127.0.0.1:{}", server.port);

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(&target).await?;

    // ---------------------------------------------------------------------
    // 1. A name this host owns -> a unicast answer with the ID and question echoed.
    // ---------------------------------------------------------------------
    const OWNED_ID: u16 = 0x1234;
    socket
        .send(&llmnr_query(OWNED_ID, OWNED_NAME, RecordType::A)?)
        .await?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(20), socket.recv(&mut buf))
        .await
        .map_err(|_| {
            "No LLMNR response within 20s for a name the model owns - the responder went silent \
             on the one query it was supposed to answer"
        })??;

    // Byte-level first, independent of any decoder, because the LLMNR header is where this
    // protocol differs from DNS and a decoder would hide it.
    assert!(
        n >= 12,
        "response shorter than a DNS/LLMNR header: {n} bytes"
    );
    assert_eq!(buf[0], (OWNED_ID >> 8) as u8, "transaction ID high byte");
    assert_eq!(buf[1], (OWNED_ID & 0xFF) as u8, "transaction ID low byte");
    assert_eq!(buf[2] & 0x80, 0x80, "QR must mark this as a response");
    assert_eq!(
        buf[2] & 0x04,
        0,
        "the LLMNR C (Conflict) bit occupies DNS's AA position and must be clear; every other \
         DNS builder in this repo sets AA on an authoritative answer, which here would claim a \
         name conflict on the link"
    );
    assert_eq!(
        buf[2] & 0x01,
        0,
        "the LLMNR T (Tentative) bit occupies DNS's RD position and must be clear unless the \
         model asked for it"
    );
    assert_eq!(buf[3] & 0x0F, 0, "RCODE must be 0 on a real answer");

    let response = DnsMessage::from_vec(&buf[..n])?;
    assert_eq!(response.id(), OWNED_ID);
    assert_eq!(response.message_type(), MessageType::Response);
    assert_eq!(response.response_code(), ResponseCode::NoError);

    // The question must be echoed or the querier discards the packet, which is silence with
    // extra steps.
    let questions = response.queries();
    assert_eq!(questions.len(), 1, "question section must be echoed");
    assert_eq!(questions[0].name(), &Name::from_str(OWNED_NAME)?);
    assert_eq!(questions[0].query_type(), RecordType::A);
    assert_eq!(questions[0].query_class(), DNSClass::IN);

    let answers = response.answers();
    assert_eq!(answers.len(), 1, "expected exactly one answer record");
    assert_eq!(answers[0].name(), &Name::from_str(OWNED_NAME)?);
    assert_eq!(answers[0].ttl(), 30);
    match answers[0].data() {
        Some(RData::A(a)) => assert_eq!(a.0, OWNED_ADDRESS),
        other => panic!("expected an A record, got {other:?}"),
    }

    // ---------------------------------------------------------------------
    // 2. A name this host does NOT own -> nothing on the wire.
    // ---------------------------------------------------------------------
    socket
        .send(&llmnr_query(0x2345, UNOWNED_NAME, RecordType::A)?)
        .await?;
    server.wait_for_log("decision=model_silent", 30).await?;
    expect_silence(&socket, "unowned name").await?;

    // ---------------------------------------------------------------------
    // 3. An RCODE refusal over UDP -> suppressed, because RFC 4795 2.1.1 requires RCODE 0 in
    //    response to a multicast query and this server cannot tell unicast UDP from multicast.
    // ---------------------------------------------------------------------
    socket
        .send(&llmnr_query(0x3456, REFUSED_NAME, RecordType::A)?)
        .await?;
    server
        .wait_for_log("decision=model_reject_suppressed_udp", 30)
        .await?;
    expect_silence(&socket, "RCODE refusal over UDP").await?;

    // ---------------------------------------------------------------------
    // 4. The same refusal over TCP -> legal, and delivered. RFC 4795 2.4 carries unicast
    //    queries over TCP with the RFC 1035 4.2.2 two-byte length prefix.
    // ---------------------------------------------------------------------
    const TCP_ID: u16 = 0x4567;
    let mut stream = TcpStream::connect(&target).await?;
    let query = llmnr_query(TCP_ID, REFUSED_NAME, RecordType::A)?;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(&query);
    stream.write_all(&framed).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| "No LLMNR TCP response within 20s")??;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut tcp_response = vec![0u8; len];
    stream.read_exact(&mut tcp_response).await?;

    assert_eq!(tcp_response[3] & 0x0F, 5, "RCODE must be 5 (REFUSED)");
    let tcp_message = DnsMessage::from_vec(&tcp_response)?;
    assert_eq!(tcp_message.id(), TCP_ID, "transaction ID must be echoed");
    assert_eq!(tcp_message.response_code(), ResponseCode::Refused);
    assert_eq!(
        tcp_message.answers().len(),
        0,
        "a refusal must not carry answers"
    );
    assert_eq!(
        tcp_message.queries().len(),
        1,
        "question section must be echoed on a refusal too"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// When the model cannot be reached, the responder writes **nothing**.
///
/// This is the assertion that matters most in this file. Every other UDP protocol in NetGet
/// answers a backend failure with an error frame, because silence costs the client its own
/// timeout. LLMNR inverts that: its success frame is a name-to-address binding written into
/// the querier's resolver cache, so a fabricated answer during an outage is cache poisoning,
/// and its only error frame is an RCODE the RFC forbids in response to a multicast query.
///
/// The failure is forced the same way `tests/server/dns/llm_failure_test.rs` forces it: no
/// mock rule matches `llmnr_query`, so the mock answers HTTP 500 and `call_llm` returns `Err`.
#[tokio::test]
async fn test_llmnr_is_silent_when_the_model_cannot_be_reached() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via llmnr and answer for printer.local";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via llmnr")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "LLMNR",
                "instruction": "Answer LLMNR queries for printer.local"
            }]))
            .expect_calls(1)
            .and()
        // Deliberately NO rule for `llmnr_query`.
    });

    let server = helpers::start_netget_server(server_config).await?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;
    socket
        .send(&llmnr_query(0x5678, OWNED_NAME, RecordType::A)?)
        .await?;

    // The log is where the distinction lives: `model_silent` (the model looked and said this
    // host does not own the name) and `fail_closed_llm_error` (the model was never reached)
    // are byte-identical on the wire, and conflating them is the OAuth2 defect the root
    // CLAUDE.md records.
    server
        .wait_for_log("decision=fail_closed_llm_error", 30)
        .await?;
    expect_silence(&socket, "LLM failure").await?;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

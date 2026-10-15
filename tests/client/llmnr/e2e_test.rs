//! End-to-end tests for the LLMNR (RFC 4795) querier.
//!
//! **The evidence here is circular on two axes at once, and that is why the protocol is rated
//! Experimental.** Three of the four tests use NetGet's own LLMNR *responder* as the peer, so
//! both ends are this project's code; and both ends frame with `hickory-proto`, so even the
//! fourth test — which hand-builds its responses — is asserting that one codec round-trips
//! through itself. That is exactly the failure the root `CLAUDE.md` names for
//! `webrtc_signaling`/`websocket`. See `tests/client/llmnr/CLAUDE.md` for what was searched for
//! and why no independent peer is runnable here.
//!
//! What these tests *do* prove is the part that actually breaks: that a response is accepted
//! only when it carries the right transaction ID **and** echoes the right question, that a
//! query nobody answers is reported as its own expected outcome rather than as an error, that
//! two responders disagreeing is surfaced loudly instead of being resolved by whichever packet
//! arrived first, and that every event reaches the model and its answer is executed.
//!
//! ## Everything is unicast, deliberately
//!
//! `PROTOCOL_ROADMAP.md` records the measurement: bound to `127.0.0.1`, joining a multicast
//! group **succeeds** but *sending* to one fails with `EADDRNOTAVAIL` (49), because loopback
//! carries no multicast route. So no test here sends to `224.0.0.252`. Three of the four point
//! `remote_addr` straight at an ephemeral port; only
//! `test_llmnr_client_treats_no_answer_as_a_normal_outcome` opens the client on the real
//! multicast group, and it overrides the destination per query with `send_llmnr_query`'s
//! `target`, which is what that parameter exists for.
//!
//! ## `response_wait_secs` is raised in every test
//!
//! A query collects responses for a fixed window and *then* reports. The 2s default is right
//! for a link; it is not right for a hundred test processes sharing a machine, where the mocked
//! model behind the responder can take longer than that to answer. Every client here passes
//! `response_wait_secs` through `startup_params` so the window cannot expire before the peer
//! has had a chance to speak — a fixed wait that is too short would present as "the querier
//! ignored a valid answer", which is a product bug, not a timing one.

use crate::helpers::{self, E2EResult, NetGetConfig};
use hickory_proto::op::{Header, Message as DnsMessage, MessageType, OpCode, Query};
use hickory_proto::rr::{rdata, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Long enough that a mocked round-trip on a loaded machine cannot outrun the window.
const WAIT_SECS: u64 = 12;

/// How long to wait for a log line before calling it a failure.
const LOG_TIMEOUT: Duration = Duration::from_secs(45);

// ---------------------------------------------------------------------------
// 1. A response that matches is accepted
// ---------------------------------------------------------------------------

/// The happy path, end to end: NetGet's responder answers for a name it owns, and the querier
/// accepts the answer and hands it to the model.
#[tokio::test]
async fn test_llmnr_client_accepts_a_matching_response() -> E2EResult<()> {
    let server_config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via llmnr and answer for printer.local")
            .with_mock(|mock| {
                mock.on_instruction_containing("via llmnr")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "LLMNR",
                        "instruction": "Answer LLMNR queries for printer.local only"
                    }]))
                    .expect_calls(1)
                    .and()
                    // The transaction ID MUST come from the event. A hardcoded one is the documented
                    // cause of timeouts in every UDP suite here — and this querier really does discard
                    // a mismatched ID, so a static value would make the test fail for the right reason
                    // at the wrong step.
                    .on_event("llmnr_query")
                    .and_event_data_contains("name", "printer.local")
                    .respond_with_actions_from_event(|event| {
                        serde_json::json!([{
                            "type": "send_llmnr_response",
                            "transaction_id": event["transaction_id"].as_u64().unwrap_or(0),
                            "name": event["name"].as_str().unwrap_or("printer.local."),
                            "record_type": "A",
                            "address": "192.168.1.42",
                            "ttl": 30
                        }])
                    })
                    .expect_calls(1)
                    .and()
            });

    let server = helpers::start_netget_server(server_config).await?;
    let remote = format!("127.0.0.1:{}", server.port);

    let client_config = NetGetConfig::new(format!(
        "Connect to {remote} via LLMNR and resolve printer.local"
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("via LLMNR")
            .respond_with_actions(serde_json::json!([{
                "type": "open_client",
                "protocol": "LLMNR",
                "remote_addr": remote,
                "instruction": "Resolve printer.local (A) and report every host that answers",
                // `bind_address` is passed explicitly here so both declared startup
                // parameters are exercised by the suite.
                "startup_params": {"bind_address": "0.0.0.0", "response_wait_secs": WAIT_SECS}
            }]))
            .expect_calls(1)
            .and()
            .on_event("llmnr_connected")
            .respond_with_actions(serde_json::json!([{
                "type": "send_llmnr_query",
                "name": "printer.local",
                "record_type": "A"
            }]))
            .expect_calls(1)
            .and()
            .on_event("llmnr_response_received")
            .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
    });

    let client = helpers::start_netget_client(client_config).await?;

    // The assertion that matters: the answer was accepted and attributed to the host that sent
    // it. `responder_index/responder_count` is in the line because on a real link the count is
    // the thing a reader needs to see.
    client
        .wait_for_pattern("LLMNR A printer.local. = 192.168.1.42", LOG_TIMEOUT)
        .await?;
    client.wait_for_pattern("(1/1)", LOG_TIMEOUT).await?;

    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    client.stop().await?;
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. A response that does not match is discarded
// ---------------------------------------------------------------------------

/// **The client's central correctness property.** LLMNR has no authentication whatsoever, so
/// the random transaction ID and the echoed question are the *entire* defence against an answer
/// that was not written for this query. Both are checked here, one per query:
///
/// * the responder is made to reply with the right question but a **wrong transaction ID**;
/// * and then with the right transaction ID but a **different name** in the echoed question.
///
/// Both must be discarded, and each query must end as an ordinary `llmnr_query_timeout` — with
/// `discarded_count` at 1, which is what tells the model that something *did* answer and was
/// refused. A client that accepted either of these would accept an off-path forgery.
#[tokio::test]
async fn test_llmnr_client_discards_a_response_that_does_not_match_its_query() -> E2EResult<()> {
    let server_config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via llmnr and answer every query")
            .with_mock(|mock| {
                mock.on_instruction_containing("via llmnr")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "LLMNR",
                "instruction": "Answer every LLMNR query"
            }]))
            .expect_calls(1)
            .and()
            // Right question, WRONG transaction ID. XOR keeps it a valid u16 and guarantees it
            // differs from the querier's.
            .on_event("llmnr_query")
            .and_event_data_contains("name", "spoofed.local")
            .respond_with_actions_from_event(|event| {
                serde_json::json!([{
                    "type": "send_llmnr_response",
                    "transaction_id": event["transaction_id"].as_u64().unwrap_or(0) ^ 0x5555,
                    "name": event["name"].as_str().unwrap_or("spoofed.local."),
                    "record_type": "A",
                    "address": "203.0.113.9",
                    "ttl": 30
                }])
            })
            .expect_calls(1)
            .and()
            // Right transaction ID, WRONG echoed question.
            .on_event("llmnr_query")
            .and_event_data_contains("name", "mislabelled.local")
            .respond_with_actions_from_event(|event| {
                serde_json::json!([{
                    "type": "send_llmnr_response",
                    "transaction_id": event["transaction_id"].as_u64().unwrap_or(0),
                    "name": "somewhere.else.local.",
                    "record_type": "A",
                    "address": "203.0.113.10",
                    "ttl": 30
                }])
            })
            .expect_calls(1)
            .and()
            });

    let server = helpers::start_netget_server(server_config).await?;
    let remote = format!("127.0.0.1:{}", server.port);

    let client_config = NetGetConfig::new(format!(
        "Connect to {remote} via LLMNR and resolve two names"
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("via LLMNR")
            .respond_with_actions(serde_json::json!([{
                "type": "open_client",
                "protocol": "LLMNR",
                "remote_addr": remote,
                "instruction": "Resolve spoofed.local and mislabelled.local (A)",
                "startup_params": {"response_wait_secs": WAIT_SECS}
            }]))
            .expect_calls(1)
            .and()
            // Both queries are issued from the connect event rather than chaining the second
            // off the first result: chaining is what looped the DNS client into a stack
            // overflow, and there is nothing to learn from it here.
            .on_event("llmnr_connected")
            .respond_with_actions(serde_json::json!([
                {"type": "send_llmnr_query", "name": "spoofed.local", "record_type": "A"},
                {"type": "send_llmnr_query", "name": "mislabelled.local", "record_type": "A"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("llmnr_query_timeout")
            .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
            .expect_calls(2)
            .and()
        // Deliberately NO rule for `llmnr_response_received`: if either forgery were accepted
        // that event would fire, the mock would answer HTTP 500, and the run would show it.
    });

    let client = helpers::start_netget_client(client_config).await?;

    // Each rejection is named on its own, so a client that started accepting one of the two
    // still fails.
    client
        .wait_for_pattern("transaction ID mismatch", LOG_TIMEOUT)
        .await?;
    client
        .wait_for_pattern("echoed question is for", LOG_TIMEOUT)
        .await?;

    // …and each query still ends as an ordinary unanswered query, with the rejected datagram
    // counted. `(1 datagram(s) discarded)` is the whole point: "nobody answered" and "somebody
    // answered and was refused" must not look the same to the model.
    client
        .wait_for_pattern(
            "spoofed.local.: no host claims this name (1 datagram(s) discarded)",
            LOG_TIMEOUT,
        )
        .await?;
    client
        .wait_for_pattern(
            "mislabelled.local.: no host claims this name (1 datagram(s) discarded)",
            LOG_TIMEOUT,
        )
        .await?;

    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    client.stop().await?;
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Nobody answering is a normal outcome
// ---------------------------------------------------------------------------

/// A responder that does not own the name says **nothing** — RFC 4795 §2.1.1 forbids NXDOMAIN
/// precisely so the host that *does* own the name can still answer. So an unanswered query is
/// how the link reports "no host here claims that name", and it must reach the model as its own
/// expected outcome rather than as a fault.
///
/// This test also exercises the `target` override on its own terms: the client is opened on the
/// **real multicast group**, which it can never send to on a loopback-only host, and every
/// query is redirected per-action to the responder's ephemeral port.
#[tokio::test]
async fn test_llmnr_client_treats_no_answer_as_a_normal_outcome() -> E2EResult<()> {
    let server_config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via llmnr and own no names",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("via llmnr")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "LLMNR",
                "instruction": "This host owns no names; stay silent"
            }]))
            .expect_calls(1)
            .and()
            .on_event("llmnr_query")
            .respond_with_actions(serde_json::json!([{"type": "no_response"}]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(server_config).await?;
    let target = format!("127.0.0.1:{}", server.port);

    let client_config =
        NetGetConfig::new("Connect to the LLMNR group via LLMNR and resolve stranger.local")
            .with_mock(move |mock| {
                mock.on_instruction_containing("via LLMNR")
            .respond_with_actions(serde_json::json!([{
                "type": "open_client",
                "protocol": "LLMNR",
                // The genuine multicast group. Nothing is ever sent here: loopback
                // carries no multicast route, so `sendto` would fail with
                // EADDRNOTAVAIL — which is why `target` exists.
                "remote_addr": "224.0.0.252:5355",
                "instruction": "Resolve stranger.local (A) against the responder under test",
                "startup_params": {"response_wait_secs": WAIT_SECS}
            }]))
            .expect_calls(1)
            .and()
            .on_event("llmnr_connected")
            .respond_with_actions(serde_json::json!([{
                "type": "send_llmnr_query",
                "name": "stranger.local",
                "record_type": "A",
                "target": target
            }]))
            .expect_calls(1)
            .and()
            .on_event("llmnr_query_timeout")
            .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
            });

    let client = helpers::start_netget_client(client_config).await?;

    // Nothing was rejected, so the count is 0 — distinguishing this from test 2, where
    // something answered and was refused.
    client
        .wait_for_pattern(
            "stranger.local.: no host claims this name (0 datagram(s) discarded)",
            LOG_TIMEOUT,
        )
        .await?;

    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    client.stop().await?;
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Two responders that disagree
// ---------------------------------------------------------------------------

/// Build an LLMNR response by hand.
///
/// This is a DNS response with two deliberate differences: the `C` bit (DNS's `AA`) and the `T`
/// bit (DNS's `RD`) are both left clear. Every other DNS builder in this repo sets `AA` on an
/// authoritative answer; here that bit means "a name conflict was detected on this link", which
/// is a different message entirely.
fn llmnr_response(id: u16, question: &Query, address: Ipv4Addr) -> E2EResult<Vec<u8>> {
    let mut message = DnsMessage::new();
    let mut header = Header::new();
    header.set_id(id);
    header.set_message_type(MessageType::Response);
    header.set_op_code(OpCode::Query);
    header.set_authoritative(false); // C = 0
    header.set_truncated(false);
    header.set_recursion_desired(false); // T = 0
    header.set_recursion_available(false); // part of LLMNR's Z field
    message.set_header(header);
    message.add_query(question.clone());

    let mut record = Record::with(question.name().clone(), RecordType::A, 30);
    record.set_data(Some(RData::A(rdata::A(address))));
    message.add_answer(record);

    Ok(message.to_bytes()?)
}

/// **The hazard LLMNR is built around.** A query goes to the whole link and every host that
/// claims the name answers; LLMNR authenticates nothing, so a host that answers faster than the
/// real owner simply wins the name. A querier that took the first answer would make that
/// invisible.
///
/// Two responders on two ports answer the *same* query with *different* addresses. The querier
/// must report **both** — one `llmnr_response_received` each, with `responder_count` 2 — and
/// then raise `llmnr_conflicting_responses` on top.
///
/// The peers are hand-written here because NetGet's own responder sends exactly one datagram
/// per query, by design. They are not independent evidence of anything (they use
/// `hickory-proto`, like both halves of NetGet); what they test is this client's own decision.
#[tokio::test]
async fn test_llmnr_client_reports_two_responders_that_disagree() -> E2EResult<()> {
    let responder_a = UdpSocket::bind("127.0.0.1:0").await?;
    let responder_b = UdpSocket::bind("127.0.0.1:0").await?;
    let a_addr = responder_a.local_addr()?;

    // One task owns both sockets: `b` answers the query that arrived at `a`, which is what
    // makes the two answers belong to the *same* transaction.
    let responders = tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];
        loop {
            let Ok((n, from)) = responder_a.recv_from(&mut buffer).await else {
                return;
            };
            let Ok(query) = DnsMessage::from_vec(&buffer[..n]) else {
                continue;
            };
            let Some(question) = query.queries().first().cloned() else {
                continue;
            };

            for (socket, address) in [
                (&responder_a, Ipv4Addr::new(192, 0, 2, 10)),
                (&responder_b, Ipv4Addr::new(192, 0, 2, 20)),
            ] {
                // `let ... else` rather than `if let Ok`: `E2EResult`'s boxed error is not
                // `Send`, and holding the `Result` across the `await` below would make this
                // whole task non-`Send` and un-spawnable.
                let Ok(bytes) = llmnr_response(query.id(), &question, address) else {
                    continue;
                };
                let _ = socket.send_to(&bytes, from).await;
            }
        }
    });

    let remote = a_addr.to_string();
    let client_config = NetGetConfig::new(format!(
        "Connect to {remote} via LLMNR and resolve contested.local"
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("via LLMNR")
            .respond_with_actions(serde_json::json!([{
                "type": "open_client",
                "protocol": "LLMNR",
                "remote_addr": remote,
                "instruction": "Resolve contested.local (A) and report every host that answers",
                "startup_params": {"response_wait_secs": WAIT_SECS}
            }]))
            .expect_calls(1)
            .and()
            .on_event("llmnr_connected")
            .respond_with_actions(serde_json::json!([{
                "type": "send_llmnr_query",
                "name": "contested.local",
                "record_type": "A"
            }]))
            .expect_calls(1)
            .and()
            // One per responder: the multiplicity is visible to the model even before the
            // conflict event arrives.
            .on_event("llmnr_response_received")
            .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
            .expect_calls(2)
            .and()
            .on_event("llmnr_conflicting_responses")
            .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
    });

    let client = helpers::start_netget_client(client_config).await?;

    // Both answers reported, neither discarded, and neither presented as the resolution.
    client
        .wait_for_pattern("= 192.0.2.10 from 127.0.0.1:", LOG_TIMEOUT)
        .await?;
    client
        .wait_for_pattern("= 192.0.2.20 from 127.0.0.1:", LOG_TIMEOUT)
        .await?;
    client.wait_for_pattern("(2/2)", LOG_TIMEOUT).await?;
    client
        .wait_for_pattern(
            "LLMNR CONFLICT: 'contested.local.' (A) answered differently by 2 hosts",
            LOG_TIMEOUT,
        )
        .await?;

    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    client.stop().await?;
    responders.abort();
    Ok(())
}

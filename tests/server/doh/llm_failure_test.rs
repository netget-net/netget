//! What a DoH client gets when the LLM backend fails: a SERVFAIL message in a 200, not a 5xx.
//!
//! DoH is DNS in an HTTP body, and RFC 8484 §4.2.1 makes `200 application/dns-message` the
//! status for "this HTTP transaction carried a DNS message" — whether that message is an
//! answer or a failure is DNS's business, not HTTP's.
//!
//! This server used to return `500 "LLM error"`. That is a statement about the *resolver
//! endpoint*, not about the name: real DoH clients treat a 5xx as the server being broken,
//! mark it down and fail over, which is a far heavier reaction than the transient backend
//! hiccup that caused it. SERVFAIL says the right thing — this query failed, ask someone else,
//! the endpoint is fine.
//!
//! As with DNS and DoT, the transaction id and the question section must be echoed. A reply
//! that fails either is discarded by the client and is worth exactly as much as silence, which
//! is why they are asserted here rather than just the RCODE.
//!
//! `dns` and `dot` and `mdns` each had a failure test and DoH did not; this closes that gap.


use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use hickory_proto::op::{Message as DnsMessage, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use std::str::FromStr;
use std::time::Duration;

#[tokio::test]
async fn test_doh_answers_servfail_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via doh. Resolve example.com";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via doh")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DoH",
                    "instruction": "Resolve example.com"
                }
            ]))
            .expect_calls(1)
            .and()
        // Deliberately no rule for the doh_query event: the mock answers it with an error,
        // which is what drives `call_llm` to `Err` and exercises the failure path.
    });

    let server = start_netget_server(config).await?;
    server
        .wait_for_log("DoH server listening on", 20)
        .await
        .map_err(|e| format!("DoH server never reported a listening socket: {e}"))?;

    let client = super::e2e_test::create_insecure_client(server.port)?;

    let domain = Name::from_str("example.com.")?;
    let query_id: u16 = rand::random();
    let mut query = DnsMessage::new();
    query.set_id(query_id);
    query.add_query(Query::query(domain.clone(), RecordType::A));
    query.set_recursion_desired(true);
    let query_bytes = query.to_vec()?;

    let http = tokio::time::timeout(
        Duration::from_secs(30),
        client
            .post(format!("https://127.0.0.1:{}/dns-query", server.port))
            .header("Content-Type", "application/dns-message")
            .body(query_bytes)
            .send(),
    )
    .await
    .map_err(|_| {
        "No DoH reply within 30s - the server went silent on LLM failure, which is the exact \
         defect this test exists to catch"
    })??;

    assert_eq!(
        http.status(),
        reqwest::StatusCode::OK,
        "a DNS-level failure is carried in a 200 as a SERVFAIL message; a 5xx would tell the \
         client this resolver endpoint is broken and make it fail over"
    );
    assert_eq!(
        http.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/dns-message"),
        "the body is a DNS message and must be labelled as one"
    );

    let body = http.bytes().await?;
    let response = DnsMessage::from_vec(&body)?;
    println!("DoH reply: {response:?}");

    assert_eq!(
        response.response_code(),
        ResponseCode::ServFail,
        "expected SERVFAIL. NOERROR with an empty answer section would tell the client the \
         name exists and has no A record, and it would cache that."
    );
    assert_eq!(
        response.id(),
        query_id,
        "the reply must echo the transaction id or the client discards it as unsolicited, \
         leaving it exactly as stuck as with silence"
    );
    assert_eq!(
        response.queries().len(),
        1,
        "the reply must echo the question section"
    );
    assert_eq!(
        response.queries()[0].name(),
        &domain,
        "the reply must echo the queried name"
    );
    assert!(
        response.answers().is_empty(),
        "a SERVFAIL must not carry answers: {response:?}"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

//! E2E tests for SIP protocol
//!
//! These tests verify SIP server functionality by starting NetGet with SIP prompts
//! and using raw UDP sockets to send SIP messages.


use crate::server::helpers::*;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Send a SIP request and return the response.
///
/// This deliberately uses `tokio::net::UdpSocket` rather than the blocking
/// `std::net::UdpSocket`: the mock Ollama server runs as a task on this test's
/// runtime, and `#[tokio::test]` gives each test a *current-thread* runtime. A
/// blocking `recv_from` therefore parks the only worker thread, the mocked LLM
/// can no longer answer NetGet's request, and the server never produces a
/// response — the read then "times out" for a reason that has nothing to do
/// with SIP.
async fn sip_exchange(
    client: &UdpSocket,
    server_addr: SocketAddr,
    request: &str,
) -> E2EResult<String> {
    client.send_to(request.as_bytes(), server_addr).await?;

    let mut buf = vec![0u8; 65535];
    let (len, _) = tokio::time::timeout(Duration::from_secs(10), client.recv_from(&mut buf))
        .await
        .map_err(|_| "Timed out waiting for SIP response")??;

    // The pcap oracle. Every assertion in this file is `response.contains("...")` on a
    // lossily-decoded string, which cannot see framing at all. Wireshark's `sip`
    // dissector parses the status line, requires the mandatory Via / From / To /
    // Call-ID / CSeq headers, and checks Content-Length against the body that follows
    // it — and a SIP server that answers INVITE with SDP is exactly where a
    // Content-Length is computed by hand and gets it wrong.
    crate::helpers::pcap_oracle::PcapOracle::udp("sip")
        .to_server(request.as_bytes())
        .from_server(&buf[..len])
        .assert_clean();

    Ok(String::from_utf8_lossy(&buf[..len]).to_string())
}

#[tokio::test]
async fn test_sip_comprehensive() -> E2EResult<()> {
    // Single comprehensive server covering every SIP method the test exercises.
    let prompt = r#"listen on port 0 via sip

You are a SIP (Session Initiation Protocol) server implementing RFC 3261.

REGISTRATION (REGISTER method):
- User 'alice@localhost' with any contact: Accept (200 OK), set expires to 3600
- User 'bob@localhost' with any contact: Accept (200 OK), set expires to 1800
- All other users: Reject (403 Forbidden)

INCOMING CALLS (INVITE method):
- From alice to bob: Accept (200 OK) with SDP:
  v=0
  o=- 12345 12345 IN IP4 127.0.0.1
  s=Test Call
  c=IN IP4 127.0.0.1
  t=0 0
  m=audio 8000 RTP/AVP 0
  a=rtpmap:0 PCMU/8000

- From bob to alice: Reject (486 Busy Here)
- From unknown users: Reject (403 Forbidden)

CALL TERMINATION (BYE method):
- Always accept (200 OK)

CAPABILITY QUERY (OPTIONS method):
- Return 200 OK with Allow header: INVITE, ACK, BYE, REGISTER, OPTIONS

ACKNOWLEDGMENT (ACK method):
- No response needed (ACK is not a request that requires response)
"#;

    // The SDP the server answers an accepted INVITE with.
    let sdp = "v=0\r\no=- 12345 12345 IN IP4 127.0.0.1\r\ns=Test Call\r\nc=IN IP4 127.0.0.1\r\n\
               t=0 0\r\nm=audio 8000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";

    // One mock rule per SIP transaction: 1 startup + 8 requests = 9 LLM calls,
    // inside the suite's 10-call budget.
    //
    // This used to be a single startup rule whose open_server action carried
    // `"scripting": true`, on the assumption that the server would then answer
    // every request from a generated script with no further LLM calls. There is
    // no such open_server parameter — the field was silently dropped, every
    // request went to the LLM, and with no matching rule the mock answered 500
    // and the server sent nothing back. (Deterministic handling is configured
    // through `event_handlers`, not a boolean.)
    //
    // Rules are matched in declaration order and the first match wins, so each
    // rule below discriminates on the `from` header rather than relying on
    // per-rule call counts.
    let config = NetGetConfig::new(prompt)
        .with_log_level("off")
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("listen on port")
                .and_instruction_containing("SIP")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "SIP",
                        "instruction": prompt
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: REGISTER alice -> accepted, 1 hour binding
                .on_event("sip_register")
                .and_event_data_contains("from", "alice")
                .respond_with_actions(serde_json::json!([
                    {"type": "sip_register", "status_code": 200, "reason_phrase": "OK", "expires": 3600}
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: REGISTER bob -> accepted, 30 minute binding
                .on_event("sip_register")
                .and_event_data_contains("from", "bob")
                .respond_with_actions(serde_json::json!([
                    {"type": "sip_register", "status_code": 200, "reason_phrase": "OK", "expires": 1800}
                ]))
                .expect_calls(1)
                .and()
                // Mock 4: REGISTER charlie -> refused
                .on_event("sip_register")
                .and_event_data_contains("from", "charlie")
                .respond_with_actions(serde_json::json!([
                    {"type": "sip_register", "status_code": 403, "reason_phrase": "Forbidden"}
                ]))
                .expect_calls(1)
                .and()
                // Mock 5: OPTIONS -> advertise supported methods
                .on_event("sip_options")
                // Matches only when the event says which status fits which situation.
                .and_event_data_contains("answer_with", "486 (Busy Here)")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "sip_options",
                        "status_code": 200,
                        "reason_phrase": "OK",
                        "allow_methods": ["INVITE", "ACK", "BYE", "REGISTER", "OPTIONS"]
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 6: INVITE alice->bob -> accepted with an SDP answer
                .on_event("sip_invite")
                .and_event_data_contains("from", "alice")
                .respond_with_actions(serde_json::json!([
                    {"type": "sip_invite", "status_code": 200, "reason_phrase": "OK", "sdp": sdp}
                ]))
                .expect_calls(1)
                .and()
                // Mock 7: INVITE bob->alice -> busy. No reason_phrase: the status line must
                // carry RFC 3261's own phrase for the code, not "OK".
                .on_event("sip_invite")
                .and_event_data_contains("from", "bob")
                .respond_with_actions(serde_json::json!([
                    {"type": "sip_invite", "status_code": 486}
                ]))
                .expect_calls(1)
                .and()
                // Mock 8: INVITE from an unregistered user -> refused
                .on_event("sip_invite")
                .and_event_data_contains("from", "charlie")
                .respond_with_actions(serde_json::json!([
                    {"type": "sip_invite", "status_code": 403, "reason_phrase": "Forbidden"}
                ]))
                .expect_calls(1)
                .and()
                // Mock 9: BYE -> acknowledge teardown
                .on_event("sip_bye")
                .respond_with_actions(serde_json::json!([
                    {"type": "sip_bye", "status_code": 200, "reason_phrase": "OK"}
                ]))
                .expect_calls(1)
                .and()
        });

    let test_state = start_netget_server(config).await?;

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_secs(2)).await;

    let server_addr: SocketAddr = format!("127.0.0.1:{}", test_state.port)
        .parse()
        .expect("Failed to parse server address");

    // Create UDP client socket
    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client socket");

    println!("✓ SIP server started on {}", server_addr);

    // Test 1: REGISTER alice (should succeed)
    println!("\n[Test 1] REGISTER alice@localhost");
    let register_alice = build_sip_register("alice@localhost", "alice", &server_addr);
    let response = sip_exchange(&client, server_addr, &register_alice).await?;
    println!("Response:\n{}", response);
    assert!(
        response.contains("SIP/2.0 200"),
        "Expected 200 OK for alice"
    );
    assert!(response.contains("Expires:"), "Expected Expires header");
    println!("✓ alice registered successfully");

    // Test 2: REGISTER bob (should succeed)
    println!("\n[Test 2] REGISTER bob@localhost");
    let register_bob = build_sip_register("bob@localhost", "bob", &server_addr);
    let response = sip_exchange(&client, server_addr, &register_bob).await?;
    println!("Response:\n{}", response);
    assert!(response.contains("SIP/2.0 200"), "Expected 200 OK for bob");
    println!("✓ bob registered successfully");

    // Test 3: REGISTER unknown user (should be rejected)
    println!("\n[Test 3] REGISTER charlie@localhost (should be rejected)");
    let register_charlie = build_sip_register("charlie@localhost", "charlie", &server_addr);
    let response = sip_exchange(&client, server_addr, &register_charlie).await?;
    println!("Response:\n{}", response);
    assert!(
        response.contains("SIP/2.0 403"),
        "Expected 403 Forbidden for charlie"
    );
    println!("✓ charlie registration rejected as expected");

    // Test 4: OPTIONS query
    println!("\n[Test 4] OPTIONS query");
    let options = build_sip_options(&server_addr);
    let response = sip_exchange(&client, server_addr, &options).await?;
    println!("Response:\n{}", response);
    assert!(
        response.contains("SIP/2.0 200"),
        "Expected 200 OK for OPTIONS"
    );
    assert!(
        response.contains("Allow:"),
        "Expected Allow header in OPTIONS response"
    );
    println!("✓ OPTIONS query successful");

    // Test 5: INVITE alice→bob (should accept)
    println!("\n[Test 5] INVITE from alice to bob (should accept)");
    let invite_alice_to_bob = build_sip_invite("alice", "bob", &server_addr, "call-123");
    let response = sip_exchange(&client, server_addr, &invite_alice_to_bob).await?;
    println!("Response:\n{}", response);
    assert!(
        response.contains("SIP/2.0 200"),
        "Expected 200 OK for alice→bob"
    );
    assert!(
        response.contains("Content-Type: application/sdp"),
        "Expected SDP in response"
    );
    assert!(
        response.contains("v=0"),
        "Expected SDP body with v=0 in response"
    );
    println!("✓ alice→bob INVITE accepted with SDP");

    // Test 6: BYE to terminate call
    println!("\n[Test 6] BYE to terminate call");
    let bye = build_sip_bye("alice", "bob", &server_addr, "call-123");
    let response = sip_exchange(&client, server_addr, &bye).await?;
    println!("Response:\n{}", response);
    assert!(response.contains("SIP/2.0 200"), "Expected 200 OK for BYE");
    println!("✓ BYE call termination successful");

    // Test 7: INVITE bob→alice (should reject with Busy)
    println!("\n[Test 7] INVITE from bob to alice (should reject)");
    let invite_bob_to_alice = build_sip_invite("bob", "alice", &server_addr, "call-456");
    let response = sip_exchange(&client, server_addr, &invite_bob_to_alice).await?;
    println!("Response:\n{}", response);
    assert!(
        response.starts_with("SIP/2.0 486 Busy Here\r\n"),
        "Expected 486 Busy Here (the default phrase for 486) for bob→alice"
    );
    println!("✓ bob→alice INVITE rejected as expected");

    // Test 8: INVITE from unknown user (should reject)
    println!("\n[Test 8] INVITE from charlie to bob (should reject)");
    let invite_charlie_to_bob = build_sip_invite("charlie", "bob", &server_addr, "call-789");
    let response = sip_exchange(&client, server_addr, &invite_charlie_to_bob).await?;
    println!("Response:\n{}", response);
    assert!(
        response.contains("SIP/2.0 403"),
        "Expected 403 Forbidden for charlie→bob"
    );
    println!("✓ charlie→bob INVITE rejected as expected");

    println!("\n✓ All SIP tests passed!");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;

    // Cleanup
    test_state.stop().await?;
    Ok(())
}

/// Build SIP REGISTER request
fn build_sip_register(user: &str, from_tag: &str, server_addr: &SocketAddr) -> String {
    let call_id = format!("reg-{}@127.0.0.1", user);
    let branch = format!("z9hG4bK{}", user);

    format!(
        "REGISTER sip:{} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch={}\r\n\
         From: <sip:{}@localhost>;tag={}\r\n\
         To: <sip:{}@localhost>\r\n\
         Call-ID: {}\r\n\
         CSeq: 1 REGISTER\r\n\
         Contact: <sip:{}@127.0.0.1:5060>\r\n\
         Expires: 3600\r\n\
         Content-Length: 0\r\n\
         \r\n",
        server_addr.ip(),
        branch,
        user,
        from_tag,
        user,
        call_id,
        user
    )
}

/// Build SIP OPTIONS request
fn build_sip_options(server_addr: &SocketAddr) -> String {
    let call_id = "options-test@127.0.0.1";
    let branch = "z9hG4bKoptions";

    format!(
        "OPTIONS sip:{} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch={}\r\n\
         From: <sip:test@localhost>;tag=12345\r\n\
         To: <sip:{}>\r\n\
         Call-ID: {}\r\n\
         CSeq: 1 OPTIONS\r\n\
         Content-Length: 0\r\n\
         \r\n",
        server_addr.ip(),
        branch,
        server_addr,
        call_id
    )
}

/// Build SIP INVITE request
fn build_sip_invite(from: &str, to: &str, server_addr: &SocketAddr, call_id: &str) -> String {
    let branch = format!("z9hG4bK{}", call_id);
    let sdp = format!(
        "v=0\r\n\
         o=- 53655765 2353687637 IN IP4 127.0.0.1\r\n\
         s=Call\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio 49170 RTP/AVP 0\r\n\
         a=rtpmap:0 PCMU/8000\r\n"
    );

    format!(
        "INVITE sip:{}@{} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch={}\r\n\
         From: <sip:{}@localhost>;tag={}-tag\r\n\
         To: <sip:{}@localhost>\r\n\
         Call-ID: {}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:{}@127.0.0.1:5060>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        to,
        server_addr.ip(),
        branch,
        from,
        from,
        to,
        call_id,
        from,
        sdp.len(),
        sdp
    )
}

/// Build SIP BYE request
fn build_sip_bye(from: &str, to: &str, server_addr: &SocketAddr, call_id: &str) -> String {
    let branch = format!("z9hG4bKbye-{}", call_id);

    format!(
        "BYE sip:{}@{} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch={}\r\n\
         From: <sip:{}@localhost>;tag={}-tag\r\n\
         To: <sip:{}@localhost>;tag={}-tag\r\n\
         Call-ID: {}\r\n\
         CSeq: 2 BYE\r\n\
         Content-Length: 0\r\n\
         \r\n",
        to,
        server_addr.ip(),
        branch,
        from,
        from,
        to,
        to,
        call_id
    )
}

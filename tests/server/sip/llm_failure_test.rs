//! What a SIP UAC gets when the LLM backend fails: 503 Service Unavailable.
//!
//! A SIP response is only usable if it can be matched to the transaction that produced it, so
//! this asserts the correlation headers as well as the status line: Via (with its branch),
//! From, To, Call-ID and CSeq must all come back. Left silent, the UAC retransmits on timer E
//! and only gives up at timer F, 32 seconds later.
//!
//! ACK is checked too, because it is the one method where silence *is* correct: RFC 3261 §17
//! makes ACK a message that takes no response at all, so answering it would be the bug.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::net::UdpSocket;

const CALL_ID: &str = "netget-failure-test@127.0.0.1";
const BRANCH: &str = "z9hG4bK-netget-failure";

fn request(method: &str, cseq: u32, port: u16) -> String {
    format!(
        "{method} sip:service@127.0.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:{port};branch={BRANCH}\r\n\
         From: <sip:caller@127.0.0.1>;tag=callertag\r\n\
         To: <sip:service@127.0.0.1>\r\n\
         Call-ID: {CALL_ID}\r\n\
         CSeq: {cseq} {method}\r\n\
         Content-Length: 0\r\n\
         \r\n"
    )
}

#[tokio::test]
async fn test_sip_answers_503_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via sip. Accept registrations";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via sip")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SIP",
                    "instruction": "Accept registrations"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for any sip_* event: the mock answers 500.
    });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_port = socket.local_addr()?.port();
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;

    socket
        .send(request("OPTIONS", 1, local_port).as_bytes())
        .await?;

    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(Duration::from_secs(20), socket.recv(&mut buf))
        .await
        .map_err(|_| {
            "No SIP response within 20s - the server went silent on LLM failure, which is the \
             exact defect this test exists to catch"
        })??;
    let response = String::from_utf8_lossy(&buf[..n]).to_string();
    println!("SIP response:\n{response}");

    assert!(
        response.starts_with("SIP/2.0 503 Service Unavailable\r\n"),
        "expected a 503 status line, got: {response}"
    );

    // Correlation headers: without these the UAC cannot match the response to its transaction
    // and treats it as if it never arrived.
    assert!(
        response.contains(&format!("branch={BRANCH}")),
        "Via (with branch) must be echoed: {response}"
    );
    assert!(
        response.contains(&format!("Call-ID: {CALL_ID}")),
        "Call-ID must be echoed: {response}"
    );
    assert!(
        response.contains("CSeq: 1 OPTIONS"),
        "CSeq must be echoed verbatim: {response}"
    );
    assert!(
        response.contains("From: <sip:caller@127.0.0.1>;tag=callertag"),
        "From must be echoed: {response}"
    );
    assert!(
        response.contains("To: <sip:service@127.0.0.1>"),
        "To must be echoed: {response}"
    );
    // RFC 3261 §20.33: a 503 SHOULD say when to come back.
    assert!(
        response.contains("Retry-After:"),
        "a 503 should carry Retry-After: {response}"
    );

    // ACK is the exception: it is not a transaction that takes a response, so answering one
    // would be a protocol violation. Silence here is the correct behaviour.
    socket
        .send(request("ACK", 2, local_port).as_bytes())
        .await?;
    match tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf)).await {
        Err(_) => { /* expected: no response to an ACK */ }
        Ok(Ok(n)) => panic!(
            "SIP answered an ACK, which RFC 3261 forbids: {}",
            String::from_utf8_lossy(&buf[..n])
        ),
        Ok(Err(e)) => return Err(format!("SIP recv failed: {e}").into()),
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

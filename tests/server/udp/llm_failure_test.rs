//! What a UDP peer gets when the LLM backend fails: deliberately nothing.
//!
//! This is the one protocol in the failure-response sweep where silence is the *correct*
//! answer, and the test exists to pin that decision rather than to leave it looking like an
//! oversight.
//!
//! Bare UDP (RFC 768) has no error frame, no transaction identifier, and no application
//! semantics. The server does not know what the datagram meant, so any bytes it invented could
//! be parsed as a real reply by whatever protocol the peer is actually speaking - a worse
//! failure than dropping it, because the peer would act on the answer. Dropping a datagram is
//! also normal UDP behaviour that every UDP client already copes with.
//!
//! Protocols layered on UDP that *do* have an error form must use it, and do: see the SERVFAIL,
//! Kiss-o'-Death and STUN 500 tests beside this one.
//!
//! So what is asserted here is the pair: nothing on the wire, and a loud, specific log line
//! saying why. A silent drop with no log would be indistinguishable from the defect.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_udp_stays_silent_but_logs_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via udp. Echo whatever arrives";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via udp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "UDP",
                    "instruction": "Echo whatever arrives"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `udp_datagram_received`: the mock answers 500.
    });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;
    socket.send(b"PING").await?;

    // Nothing should come back. 5s is comfortably longer than the failing LLM round trip
    // (which is a local mock returning 500 immediately).
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf)).await {
        Err(_) => { /* timed out: the expected outcome */ }
        Ok(Ok(n)) => panic!(
            "UDP server invented a {n}-byte reply on LLM failure: {:?}. Bare UDP has no error \
             form, so anything sent here could be misparsed as a real reply by the peer's \
             actual protocol.",
            String::from_utf8_lossy(&buf[..n])
        ),
        Ok(Err(e)) => return Err(format!("UDP recv failed: {e}").into()),
    }

    // ...but the silence must be explained, not merely happen.
    server
        .wait_for_pattern(
            "no reply possible: bare UDP has no error form",
            Duration::from_secs(10),
        )
        .await
        .map_err(|e| {
            format!(
                "UDP dropped the datagram without logging why - that is indistinguishable from \
                 the silent-failure defect: {e}"
            )
        })?;

    // And the explanation must carry the grep-able token, because the prose alone does not
    // separate a dead backend from the model answering `ignore_datagram` or answering with
    // nothing - both of which are the same silence on the socket. See
    // `decision_tag_test.rs` for those two.
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=fail_closed_llm_error")
                || l.contains("decision=fail_closed_llm_overloaded")),
        "the dropped datagram must be tagged decision=fail_closed_llm_* so `grep \
         decision=fail_closed` finds it. Output was:\n{}",
        lines.join("\n")
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

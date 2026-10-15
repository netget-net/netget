//! UDP is silent on every unhappy path, so the log is the *only* place those paths differ.
//!
//! `llm_failure_test.rs` beside this one pins the backend-failure path: nothing on the wire,
//! and `decision=fail_closed_llm_error` in the log. That is one third of the contract; these
//! two cover the rest. A dead backend, a model that answered `ignore_datagram`, and a model
//! that answered with nothing at all are byte-for-byte identical to the peer — one datagram
//! in, none out — and before the `decision=` tokens they were also identical in the log.
//!
//! Each test below asserts **both** halves, because either alone is meaningless: a silent
//! drop with no log is indistinguishable from the "reset to Idle and write nothing" defect,
//! and a log line with a datagram on the wire would mean the tag was lying.
//!
//! Do not "fix" the silence. Bare UDP (RFC 768) has no error frame, no transaction id and no
//! application semantics, so any bytes invented here could be parsed as a real reply by
//! whatever protocol the peer is actually speaking. See `src/server/udp/CLAUDE.md`.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::net::UdpSocket;

fn open_udp_server() -> serde_json::Value {
    serde_json::json!([
        {
            "type": "open_server",
            "port": 0,
            "base_stack": "UDP",
            "instruction": "Answer datagrams"
        }
    ])
}

/// Assert nothing arrives on `socket` within 3s.
async fn assert_silent(socket: &UdpSocket, what: &str) -> E2EResult<()> {
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
        Err(_) => Ok(()),
        Ok(Ok(n)) => Err(format!(
            "UDP invented a {n}-byte reply on the {what} path; bare UDP has no error form, so \
             anything sent here can be misparsed as a real reply by the peer's actual \
             protocol. Payload: {:?}",
            String::from_utf8_lossy(&buf[..n])
        )
        .into()),
        Ok(Err(e)) => Err(format!("UDP recv failed: {e}").into()),
    }
}

/// The model was reached and chose `ignore_datagram`. Nothing on the wire, and the log says
/// the *model* chose it — not that the backend fell over.
#[tokio::test]
async fn test_udp_ignore_datagram_is_silent_and_logged_as_a_refusal() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via udp. Ignore anything you do not recognise";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via udp")
            .respond_with_actions(open_udp_server())
            .expect_calls(1)
            .and()
            .on_event("udp_datagram_received")
            .respond_with_actions(serde_json::json!([{ "type": "ignore_datagram" }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;
    socket.send(b"PING").await?;

    server.wait_for_any(&["decision=model_reject"], 30).await;
    assert_silent(&socket, "ignore_datagram").await?;

    let lines = server.get_output().await;
    assert!(
        lines.iter().any(|l| l.contains("decision=model_reject")),
        "an explicit ignore_datagram must be logged decision=model_reject, distinct from a \
         backend failure and from the model saying nothing. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=fail_closed")),
        "the model answered; nothing here failed closed. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The model was reached and answered with no action at all. Same silence on the wire as the
/// refusal above and as a backend failure; a different token in the log.
#[tokio::test]
async fn test_udp_empty_answer_is_silent_and_logged_as_model_silence() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via udp. Answer datagrams";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via udp")
            .respond_with_actions(open_udp_server())
            .expect_calls(1)
            .and()
            .on_event("udp_datagram_received")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;
    socket.send(b"PING").await?;

    server.wait_for_any(&["decision=model_silent"], 30).await;
    assert_silent(&socket, "empty answer").await?;

    let lines = server.get_output().await;
    assert!(
        lines.iter().any(|l| l.contains("decision=model_silent")),
        "a model that returned no usable action must be logged decision=model_silent. It is \
         not decision=model_reject (nobody refused) and not fail_closed (the backend \
         answered). Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=fail_closed")),
        "the backend answered fine; this is not a fail-closed. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

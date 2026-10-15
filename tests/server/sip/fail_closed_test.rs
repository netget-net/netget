//! What SIP does when the model's answer is not an answer.
//!
//! REGISTER and INVITE are admission decisions — they say who may register a location and who
//! may place a call — so the fail-open question is the whole of this file: **can anything reach
//! a 200 without the model having explicitly said 200?** Three shapes are checked, each of
//! which used to be a way through:
//!
//! - the model returns no SIP response action at all (only a common action, or nothing);
//! - the model returns a SIP response action with no `status_code`;
//! - the model returns something that is not a JSON object.
//!
//! And one in the other direction: **ACK must never be answered** (RFC 3261 §17 makes it a
//! message that takes no response). `llm_failure_test.rs` already checks the LLM-error path
//! stays silent for ACK; the *success* path did not, and answered every ACK with a status line.
//!
//! In-process (`netget::` APIs directly) with static handlers, so no model is involved at all
//! and no LLM budget is spent. The LLM endpoint points at a closed port, which makes any
//! accidental model call fail fast and loudly rather than hanging.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Start an in-process SIP server with the given routing rules and return its bound port.
///
/// `instruction: Some(String::new())` is load-bearing: `ServerForm::create` substitutes a
/// default instruction for `None`, which makes the server consult the model and would turn
/// every case below into an LLM-error test instead of the handler test it is meant to be.
async fn start_sip_in_process(
    event_handlers: Vec<serde_json::Value>,
) -> (::netget::state::app_state::AppState, u16) {
    use ::netget::cli::management::ServerForm;
    use ::netget::state::app_state::AppState;
    use tokio::sync::mpsc;

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(::netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel::<String>();

    let server_id = ServerForm {
        protocol: "sip".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        instruction: Some(String::new()),
        event_handlers: Some(event_handlers),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create sip server");

    let mut port = 0u16;
    for _ in 0..200 {
        if let Some(s) = state.get_server(server_id).await {
            if let Some(addr) = s.local_addr {
                port = addr.port();
                break;
            }
            if s.port != 0 {
                port = s.port;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_ne!(port, 0, "SIP server never bound a port");
    (state, port)
}

fn handler(pattern: &str, actions: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "event_pattern": pattern,
        "handler": {"type": "static", "actions": actions}
    })
}

fn request(method: &str, cseq: u32) -> String {
    format!(
        "{method} sip:service@127.0.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-failclosed\r\n\
         From: <sip:caller@127.0.0.1>;tag=callertag\r\n\
         To: <sip:service@127.0.0.1>\r\n\
         Call-ID: netget-failclosed@127.0.0.1\r\n\
         CSeq: {cseq} {method}\r\n\
         Contact: <sip:caller@127.0.0.1:5060>\r\n\
         Content-Length: 0\r\n\
         \r\n"
    )
}

/// Send one request and return the response, or `None` if the server stayed silent.
async fn exchange(port: u16, method: &str, cseq: u32, wait: Duration) -> Option<String> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    socket
        .send_to(request(method, cseq).as_bytes(), server)
        .await
        .expect("send request");

    let mut buf = vec![0u8; 65535];
    match tokio::time::timeout(wait, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(String::from_utf8_lossy(&buf[..n]).to_string()),
        _ => None,
    }
}

/// The status line must never be a 2xx unless the model asked for one by name.
fn assert_not_accepted(response: &str, context: &str) {
    assert!(
        !response.starts_with("SIP/2.0 2"),
        "{context}: the request was ACCEPTED without an explicit model decision:\n{response}"
    );
    assert!(
        response.starts_with("SIP/2.0 500"),
        "{context}: expected a 500 refusal, got:\n{response}"
    );
    // The correlation headers still have to come back, or the UAC discards the refusal as
    // unmatched and retransmits until timer F — a refusal it cannot match is just a timeout.
    for header in [
        "branch=z9hG4bK-failclosed",
        "Call-ID: netget-failclosed@127.0.0.1",
        "From: <sip:caller@127.0.0.1>;tag=callertag",
    ] {
        assert!(
            response.contains(header),
            "{context}: refusal must echo {header:?}:\n{response}"
        );
    }
}

/// A handler that answers with a *common* action and no SIP response action is the model
/// saying nothing about the request. It must refuse, not stay silent and not default to 200.
///
/// Silence is the shape this used to take, and it is wrong twice: the UAC retransmits on timer
/// E for 32 seconds before giving up, and the operator's log says only "no action taken".
#[tokio::test]
async fn sip_register_with_no_response_action_refuses_rather_than_accepting() {
    let (_state, port) = start_sip_in_process(vec![handler(
        "sip_register",
        serde_json::json!([{"type": "set_memory", "content": "saw a registration"}]),
    )])
    .await;

    let response = exchange(port, "REGISTER", 1, Duration::from_secs(20))
        .await
        .expect("SIP went silent on a REGISTER the model did not answer");
    assert_not_accepted(&response, "REGISTER with only a common action");
}

/// Same for INVITE: no SIP response action means no call is set up.
#[tokio::test]
async fn sip_invite_with_no_response_action_refuses_rather_than_accepting() {
    let (_state, port) = start_sip_in_process(vec![handler(
        "sip_invite",
        serde_json::json!([{"type": "set_memory", "content": "saw a call"}]),
    )])
    .await;

    let response = exchange(port, "INVITE", 1, Duration::from_secs(20))
        .await
        .expect("SIP went silent on an INVITE the model did not answer");
    assert_not_accepted(&response, "INVITE with only a common action");
    assert!(
        !response.contains("application/sdp"),
        "a refused INVITE must not carry an SDP answer:\n{response}"
    );
}

/// An empty action list is the model answering with nothing at all. Also a refusal.
#[tokio::test]
async fn sip_register_with_an_empty_action_list_refuses() {
    let (_state, port) =
        start_sip_in_process(vec![handler("sip_register", serde_json::json!([]))]).await;

    let response = exchange(port, "REGISTER", 1, Duration::from_secs(20))
        .await
        .expect("SIP went silent on an empty action list");
    assert_not_accepted(&response, "REGISTER with an empty action list");
}

/// A `sip_register` action that forgot `status_code` is a malformed action, not a decision.
/// SIP has no default status, so the honest answer is the server's own 500 — a defaulted 200
/// would grant a registration because a field was left out.
#[tokio::test]
async fn sip_register_with_no_status_code_refuses() {
    let (_state, port) = start_sip_in_process(vec![handler(
        "sip_register",
        serde_json::json!([{"type": "sip_register", "expires": 3600}]),
    )])
    .await;

    let response = exchange(port, "REGISTER", 1, Duration::from_secs(20))
        .await
        .expect("SIP went silent on an action with no status_code");
    assert_not_accepted(&response, "REGISTER with no status_code");
}

/// The model naming a status code is the one thing that gets through, in both directions.
/// Without this the tests above would pass against a server that answers 500 to everything.
#[tokio::test]
async fn sip_register_with_an_explicit_status_code_is_honoured() {
    let (_state, port) = start_sip_in_process(vec![
        handler(
            "sip_register",
            serde_json::json!([{"type": "sip_register", "status_code": 200, "expires": 1800}]),
        ),
        handler(
            "sip_invite",
            serde_json::json!([{"type": "sip_invite", "status_code": 403,
                               "reason_phrase": "Forbidden"}]),
        ),
    ])
    .await;

    let accepted = exchange(port, "REGISTER", 1, Duration::from_secs(20))
        .await
        .expect("no response to an explicitly accepted REGISTER");
    assert!(
        accepted.starts_with("SIP/2.0 200"),
        "an explicit 200 must be honoured, got:\n{accepted}"
    );
    assert!(
        accepted.contains("Expires: 1800"),
        "the action's expires must reach the wire:\n{accepted}"
    );

    let refused = exchange(port, "INVITE", 2, Duration::from_secs(20))
        .await
        .expect("no response to an explicitly refused INVITE");
    assert!(
        refused.starts_with("SIP/2.0 403"),
        "an explicit 403 must be honoured, got:\n{refused}"
    );
}

/// ACK takes no response, ever (RFC 3261 §17). Not even when the model answers it.
///
/// The success path used to build and send a response for an ACK like any other method: the
/// handler below returns `{"type": "sip_ack"}`, which carries no `status_code`, so the server
/// framed a `SIP/2.0 500 Server Internal Error` and sent it to a peer that is not in a
/// transaction. `llm_failure_test.rs` covers the LLM-error path; this covers the one that
/// actually fires in normal operation.
#[tokio::test]
async fn sip_never_answers_an_ack_even_when_the_model_does() {
    let (_state, port) = start_sip_in_process(vec![
        handler("sip_ack", serde_json::json!([{"type": "sip_ack"}])),
        // A rule for OPTIONS too, so the "no datagram arrived" assertion below is known to be
        // about ACK rather than about a server that never answers anything.
        handler(
            "sip_options",
            serde_json::json!([{"type": "sip_options", "status_code": 200}]),
        ),
    ])
    .await;

    let control = exchange(port, "OPTIONS", 1, Duration::from_secs(20))
        .await
        .expect("control: the server answers OPTIONS, so it is alive and routing");
    assert!(control.starts_with("SIP/2.0 200"), "control: {control}");

    if let Some(response) = exchange(port, "ACK", 2, Duration::from_secs(5)).await {
        panic!("SIP answered an ACK, which RFC 3261 §17 forbids:\n{response}");
    }
}

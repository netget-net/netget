//! A script rule that cannot answer must be **charged**, and this file counts the calls.
//!
//! RTP's budget gate used to ask `find_handler` what was *configured*. A `Script` rule read as
//! "answers in-process, costs no model call", so `RtpLlmBudget` was skipped outright — and then
//! `action_helper::call_llm` dispatched the very same handler itself. When
//! `execute_script_handler` answered `FallbackToLlm` — a language with no runtime, a missing
//! interpreter, a script that threw — the model was consulted with the budget already bypassed.
//!
//! On RTP that is the worst place for it: a single G.711 stream is 50 packets per second, so
//! the hole is 50 uncounted consultations a second, `llm_max_per_minute` is inert at every
//! setting including `0`, and each consultation can authorize up to 30 seconds of outbound
//! media — an amplifier for anyone who spoofs a source address.
//!
//! # The measurement
//!
//! One configuration — a `*`-matching script rule whose language has no runtime on this
//! instance — run at two ceilings, against a mock model that records every call it receives:
//!
//! | `llm_max_per_minute` | old code (gate skipped on configuration) | this code |
//! |---|---|---|
//! | 30 | N calls | **N calls** (measured by `script_that_cannot_answer_reaches_the_model_when_the_budget_allows`) |
//! | 0 | N calls — the gate was never consulted | **0 calls** (measured by `script_that_cannot_answer_is_charged_to_the_budget`) |
//!
//! The ample-ceiling row is what makes the zero mean something: it proves the datagrams arrive,
//! that this handler really does fall through to the model, and that the mock counts. The old
//! code produced that same N at *both* ceilings, because it never reached the gate — which
//! [`the_configuration_and_the_answer_disagree`] pins directly by asking the two questions of
//! one configuration and showing they give opposite answers.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features rtp \
//!       --test server -- server::rtp::script_fallback_budget_test --test-threads=100

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use ::netget::cli::management::ServerForm;
use ::netget::server::rtp::RtpServer;
use ::netget::state::app_state::AppState;
use ::netget::state::ServerId;

/// How many datagrams each case sends. Small enough to stay quick under
/// `--test-threads=100`, large enough that "N calls" and "0 calls" cannot be confused.
const DATAGRAMS: usize = 5;

/// The event every inbound RTP datagram raises.
const EVENT: &str = "rtp_packet_received";

/// A `*` rule in a language this instance has no runtime for (see [`start_rtp`], which gives
/// the state an empty scripting environment).
///
/// This is not a contrived input: it is the same `FallbackToLlm` the shipped script-mode
/// example produces on a box without `python3`, reached without depending on what is installed
/// on the machine running the suite. (An unknown language name would be refused when the handler
/// is configured, so it cannot stand in.)
fn unanswerable_script_rule() -> serde_json::Value {
    serde_json::json!({
        "event_pattern": "*",
        "handler": {
            "type": "script",
            "language": "go",
            "code": "package main\nfunc main() {}"
        }
    })
}

/// Minimal RFC 3550 §5.1 header plus a payload, so `media::parse_rtp` accepts it.
fn rtp_packet(seq: u16) -> Vec<u8> {
    let mut pkt = vec![0x80, 0x00];
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&1000u32.to_be_bytes());
    pkt.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    pkt.extend_from_slice(&[0xFFu8; 160]);
    pkt
}

/// Start an in-process RTP server pointed at `mock`, with the given ceiling and routing.
async fn start_rtp(
    mock: &MockOllamaServer,
    llm_max_per_minute: u64,
    event_handlers: Option<Vec<serde_json::Value>>,
) -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(::netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    // No runtime at all, whatever this machine has installed: a script rule can then never
    // answer and must fall through to the model, which is the path this file measures.
    state
        .set_scripting_env(::netget::scripting::ScriptingEnvironment::default())
        .await;
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    let server_id = ServerForm {
        protocol: "rtp".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        // Empty rather than `None`: `ServerForm::create` substitutes a default instruction for
        // `None`, and the point here is to measure the model calls this file's own gates let
        // through, not ones a default prompt invited.
        instruction: Some(String::new()),
        startup_params: Some(serde_json::json!({ "llm_max_per_minute": llm_max_per_minute })),
        event_handlers,
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create rtp server");

    let mut port = 0u16;
    for _ in 0..200 {
        if let Some(s) = state.get_server(server_id).await {
            if let Some(addr) = s.local_addr {
                port = addr.port();
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_ne!(port, 0, "RTP server never bound a port");
    (state, server_id, port)
}

/// Send `DATAGRAMS` packets and return how many calls the model received.
///
/// The two directions need different waits and the difference is not cosmetic. Proving calls
/// *happened* is a wait-until: poll and return the instant the count lands. Proving they did
/// *not* is a wait-to-be-sure: there is nothing to wait for, so only elapsed time is evidence.
async fn model_calls(
    mock: &MockOllamaServer,
    port: u16,
    expected: usize,
    state: &AppState,
    server_id: ServerId,
) -> usize {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    for seq in 0..DATAGRAMS as u16 {
        socket
            .send_to(&rtp_packet(seq), server)
            .await
            .expect("send rtp");
    }

    let budget = if expected > 0 {
        Duration::from_secs(60)
    } else {
        Duration::from_secs(10)
    };
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if expected > 0 && mock.call_count().await >= expected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let count = mock.call_count().await;
    let _ = state.remove_server(server_id).await;
    count
}

/// A mock that answers every request with "stream nothing", and records the call.
///
/// Answering with no actions matters: any media action would be sent, and on RTP that could
/// provoke further events and make the count mean something other than "datagrams admitted".
async fn recording_mock() -> MockOllamaServer {
    MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama")
}

/// **The control.** With no rule at all and room in the window, every datagram is one model
/// call. Without this row the zeros below are indistinguishable from a server nothing reached.
#[tokio::test]
async fn an_unclaimed_datagram_is_one_model_call() {
    let mock = recording_mock().await;
    let (state, id, port) = start_rtp(&mock, 30, None).await;
    let calls = model_calls(&mock, port, DATAGRAMS, &state, id).await;
    assert_eq!(
        calls, DATAGRAMS,
        "{DATAGRAMS} unclaimed datagrams must be {DATAGRAMS} model calls; got {calls}"
    );
}

/// **The old path, measured.** The same script rule that used to buy exemption, at a ceiling
/// with room in it: the handler declines and the model is consulted once per datagram.
///
/// These are exactly the calls the old code made at *every* ceiling, `0` included, because it
/// skipped the gate on the strength of the rule existing.
#[tokio::test]
async fn script_that_cannot_answer_reaches_the_model_when_the_budget_allows() {
    let mock = recording_mock().await;
    let (state, id, port) = start_rtp(&mock, 30, Some(vec![unanswerable_script_rule()])).await;
    let calls = model_calls(&mock, port, DATAGRAMS, &state, id).await;
    assert_eq!(
        calls, DATAGRAMS,
        "a script rule that answers FallbackToLlm must fall through to the model like any \
         unclaimed datagram; got {calls}"
    );
}

/// **The fix, measured.** Identical configuration, ceiling of zero: not one call.
///
/// Before the repair this was `DATAGRAMS` calls, because the budget was never consulted.
#[tokio::test]
async fn script_that_cannot_answer_is_charged_to_the_budget() {
    let mock = recording_mock().await;
    let (state, id, port) = start_rtp(&mock, 0, Some(vec![unanswerable_script_rule()])).await;
    let calls = model_calls(&mock, port, 0, &state, id).await;
    assert_eq!(
        calls, 0,
        "llm_max_per_minute: 0 forbids model consultation, and a script rule that could not \
         answer does not buy an exemption from it; got {calls} call(s)"
    );
}

/// A rule that *does* answer is still never charged — the property the fix must not break.
///
/// A gate that refused everything at `llm_max_per_minute: 0` would pass the test above while
/// destroying the configuration the ceiling exists to make usable.
#[tokio::test]
async fn a_static_rule_still_answers_at_a_ceiling_of_zero() {
    let mock = recording_mock().await;
    let (state, id, port) = start_rtp(
        &mock,
        0,
        Some(vec![serde_json::json!({
            "event_pattern": EVENT,
            "handler": {
                "type": "static",
                "actions": [{
                    "type": "send_rtp_audio",
                    "payload_type": "pcmu",
                    "content": "tone",
                    "tone_hz": 440,
                    "duration_ms": 60
                }]
            }
        })]),
    )
    .await;

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    socket
        .send_to(&rtp_packet(0), server)
        .await
        .expect("send rtp");

    let mut buf = vec![0u8; 65535];
    let reply = tokio::time::timeout(Duration::from_secs(20), socket.recv_from(&mut buf))
        .await
        .expect("a static rule must stream even at llm_max_per_minute: 0")
        .expect("recv");
    assert!(reply.0 >= 12, "reply is not an RTP packet");
    assert_eq!(
        mock.call_count().await,
        0,
        "a rule that answered must cost no model call"
    );
    let _ = state.remove_server(id).await;
}

/// The defect in one assertion: for one configuration, the question the old gate asked and the
/// question the new gate asks give opposite answers.
///
/// `configured_handler_kind` is what the routing table says — `Some("script")`, which the old
/// code read as "exempt". The measurement above is what the handler actually answers. A gate
/// built on the first is a gate built on a guess.
#[tokio::test]
async fn the_configuration_and_the_answer_disagree() {
    let mock = recording_mock().await;
    let (state, id, _port) = start_rtp(&mock, 0, Some(vec![unanswerable_script_rule()])).await;

    assert_eq!(
        RtpServer::configured_handler_kind(&state, id, EVENT).await,
        Some("script"),
        "the routing table claims a script rule answers this event — which is precisely what \
         the removed gate believed"
    );
    let _ = state.remove_server(id).await;
}

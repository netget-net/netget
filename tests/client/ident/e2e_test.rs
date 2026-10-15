//! Ident (RFC 1413) client E2E.
//!
//! Five things are worth proving about a client whose entire job is one line out and one line
//! in, and they are the five below: a USERID reply reaches the model as fields, each ERROR
//! token is recognised, whitespace is tolerated, **a reply whose port pair does not match the
//! query is rejected rather than accepted**, and the model's answer to a reply is carried out.
//!
//! ## What the peer is, and what that is worth
//!
//! Mostly **NetGet's own ident server**. That is same-project evidence — it shows the two
//! halves agree, not that either matches RFC 1413 — and it is the circular-evidence class the
//! root `CLAUDE.md` names. It is also all that is available: `src/server/ident/CLAUDE.md`
//! records the full search for a third-party ident implementation and why none can be used
//! (every ident client hardcodes destination port 113, because RFC 1413 has no notion of a
//! configurable one). Do not repeat that search, and do not read these tests as Beta evidence.
//!
//! The mismatch test cannot use NetGet's server at all: `enforce_port_pair` in
//! `src/server/ident/mod.rs` deliberately rewrites a wrong pair to the queried one, so it is
//! structurally incapable of producing the frame under test. That peer, and the whitespace
//! one, are hand-written from the wire format — an independent reading of the spec, not an
//! independent implementation.
//!
//! ## LLM budget
//!
//! Four of the five tests make **zero** LLM calls: every event is answered by a static
//! handler, on both the server and the client. Only `the_model_can_chain_a_second_query` uses
//! the model, through the in-process mock, for **3** calls. Total: 3.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ident \
//!       --test client -- client::ident::e2e_test --test-threads=100


use std::sync::Arc;
use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::{ClientForm, ServerForm};
use netget::client::ident::{parse_ident_reply, resolve_target, IdentReply};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId, ServerId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

/// An AppState whose LLM endpoint is unreachable on purpose: any test below that reaches the
/// model has a routing hole, and will say so loudly instead of quietly passing.
const UNREACHABLE_LLM: &str = "http://127.0.0.1:1";

async fn state_without_llm() -> AppState {
    let state = AppState::new_with_options(false, UNREACHABLE_LLM.to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(UNREACHABLE_LLM.to_string()))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..1_000 {
        if let Some(server) = state.get_server(id).await {
            if let Some(addr) = server.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("ident server #{} never bound a port", id.as_u32());
}

/// Every client-side access-log entry recorded for `event_id`, newest first.
async fn client_events(
    state: &AppState,
    client_id: ClientId,
    event_id: &str,
) -> Vec<serde_json::Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Client(client_id.as_u32())), None)
        .await
        .into_iter()
        .filter(|entry| entry.event_type == event_id)
        .map(|entry| entry.request)
        .collect()
}

/// Wait for the client to record `event_id` and return its data.
async fn await_client_event(
    state: &AppState,
    client_id: ClientId,
    event_id: &str,
) -> serde_json::Value {
    for _ in 0..1_000 {
        if let Some(data) = client_events(state, client_id, event_id).await.pop() {
            return data;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let seen: Vec<String> = state
        .list_access_logs_for(Some(AccessLogOwner::Client(client_id.as_u32())), None)
        .await
        .into_iter()
        .map(|e| e.event_type)
        .collect();
    panic!("ident client never raised {event_id:?}; it raised {seen:?}");
}

/// Start a NetGet ident **server** that answers every query with one fixed action.
///
/// A static handler cannot read the event, but it does not need to: the server's
/// `enforce_port_pair` rewrites the pair to whichever one was queried, so a fixed answer is
/// still correctly addressed. `instruction: Some(String::new())` is what actually keeps the
/// model out of it — `ServerForm::create` substitutes a default instruction for `None`, and a
/// non-empty instruction makes the server consult the model.
async fn start_ident_server(
    state: &AppState,
    tx: &mpsc::UnboundedSender<String>,
    action: serde_json::Value,
) -> u16 {
    let server_id = ServerForm {
        protocol: "ident".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [action] }
        })]),
        ..Default::default()
    }
    .create(state, tx.clone())
    .await
    .expect("create ident server");
    wait_for_port(state, server_id).await
}

/// A loopback peer that accepts one connection, reads the query line, and writes `reply`
/// verbatim. Hand-written from RFC 1413's wire format, because the two frames it produces
/// (a wrong port pair, gratuitous whitespace) are ones NetGet's own server cannot emit.
///
/// Returns the port and the query lines it received.
async fn spawn_raw_ident_peer(reply: &'static str) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let queries: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let queries_task = queries.clone();

    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let queries = queries_task.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 512];
                let mut seen = Vec::new();
                while let Ok(n) = socket.read(&mut buffer).await {
                    if n == 0 {
                        break;
                    }
                    seen.extend_from_slice(&buffer[..n]);
                    if seen.contains(&b'\n') {
                        break;
                    }
                }
                queries
                    .lock()
                    .await
                    .push(String::from_utf8_lossy(&seen).into_owned());
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.flush().await;
                let _ = socket.shutdown().await;
            });
        }
    });

    (port, queries)
}

/// Client routing that asks about one fixed pair on connect and answers everything else with
/// nothing. The zero-action static rule is what keeps the reply events off the model
/// (`tests/empty_static_handler_test.rs` measures that it really does suppress the call).
fn client_handlers(server_port: u16, client_port: u16) -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "event_pattern": "ident_connected",
            "handler": {
                "type": "static",
                "actions": [{
                    "type": "send_ident_query",
                    "server_port": server_port,
                    "client_port": client_port
                }]
            }
        }),
        serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [] }
        }),
    ]
}

async fn start_ident_client(
    state: &AppState,
    tx: &mpsc::UnboundedSender<String>,
    port: u16,
    handlers: Vec<serde_json::Value>,
) -> ClientId {
    ClientForm {
        protocol: "ident".to_string(),
        // Deliberately host-only: `ident_port` is the declared parameter, and this is the
        // asymmetry that makes ident awkward to test — RFC 1413 fixes the port at 113, so
        // `remote_addr` for this protocol is normally just a host.
        remote_addr: Some("127.0.0.1".to_string()),
        startup_params: Some(serde_json::json!({ "ident_port": port })),
        instruction: Some("Ask the ident server who owns the connection.".to_string()),
        event_handlers: Some(handlers),
        ..Default::default()
    }
    .create(
        state,
        netget::llm::OllamaClient::new(UNREACHABLE_LLM.to_string()),
        tx.clone(),
    )
    .await
    .expect("create ident client")
}

// ============================================================================
// The parse, directly. Cheap, exact, and the place a regression shows up first.
// ============================================================================

#[test]
fn whitespace_around_the_grammar_is_tolerated() {
    // The grammar admits it and real peers send it; rejecting it would be a gratuitous
    // failure. Both directions matter — NetGet writes "<sp> , <cp>" with spaces itself.
    let reply = parse_ident_reply("  6193  ,  23  :  USERID  :  UNIX , US-ASCII  :  stjohns  ");
    assert_eq!(
        reply,
        IdentReply::Userid {
            server_port: 6193,
            client_port: 23,
            opsys: "UNIX".to_string(),
            charset: Some("US-ASCII".to_string()),
            userid: "stjohns".to_string(),
        },
        "whitespace around the comma and the colons must parse"
    );
}

#[test]
fn a_malformed_reply_is_an_error_not_a_loose_parse() {
    // Each of these could be "nearly" parsed into something. None of them may be: every field
    // position in the grammar means something to whoever reads the result.
    let cases: [(&str, &str); 7] = [
        ("6193 , 23 : USERID : UNIX :", "empty_userid"),
        ("6193 , 23 : USERID : nobody", "userid_fields"),
        ("6193 , 23 : MAYBE : UNIX : nobody", "response_type"),
        ("6193 , 23 : ERROR : SOMETHING-ELSE", "error_token"),
        ("6193 ; 23 : ERROR : NO-USER", "port_pair"),
        ("0 , 23 : ERROR : NO-USER", "port_pair"),
        ("just some text", "no_response_type"),
    ];
    for (line, reason) in cases {
        assert_eq!(
            parse_ident_reply(line),
            IdentReply::Malformed { reason },
            "{line:?} must be rejected as {reason}"
        );
    }

    // Oversized: past the cap the line is refused without being parsed at all.
    let huge = format!("6193 , 23 : USERID : UNIX : {}", "a".repeat(4096));
    assert!(
        matches!(
            parse_ident_reply(&huge),
            IdentReply::Malformed {
                reason: "oversized"
            }
        ),
        "an oversized reply must be refused, not truncated into a userid"
    );
}

#[test]
fn the_default_port_is_113_and_ident_port_overrides_remote_addr() {
    assert_eq!(resolve_target("127.0.0.1", None).unwrap(), "127.0.0.1:113");
    assert_eq!(
        resolve_target("127.0.0.1:9999", None).unwrap(),
        "127.0.0.1:9999"
    );
    assert_eq!(
        resolve_target("127.0.0.1:9999", Some(4113)).unwrap(),
        "127.0.0.1:4113",
        "ident_port must win over a port written into remote_addr"
    );
    assert_eq!(resolve_target("::1", Some(4113)).unwrap(), "[::1]:4113");
}

// ============================================================================
// Against NetGet's own ident server. Same-project evidence; see the header.
// ============================================================================

#[tokio::test]
async fn a_userid_reply_reaches_the_model_as_fields() {
    let state = state_without_llm().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let port = start_ident_server(
        &state,
        &tx,
        serde_json::json!({
            "type": "send_ident_userid",
            "server_port": 6193,
            "client_port": 23,
            "opsys": "UNIX",
            "charset": "US-ASCII",
            "userid": "ircuser"
        }),
    )
    .await;

    let client_id = start_ident_client(&state, &tx, port, client_handlers(6193, 23)).await;

    let data = await_client_event(&state, client_id, "ident_response_received").await;
    assert_eq!(data["server_port"], 6193);
    assert_eq!(data["client_port"], 23);
    assert_eq!(data["userid"], "ircuser");
    assert_eq!(data["opsys"], "UNIX");
    assert_eq!(
        data["charset"], "US-ASCII",
        "the charset appended to opsys after a comma must be split out: {data}"
    );
    assert!(
        client_events(&state, client_id, "ident_reply_mismatch")
            .await
            .is_empty(),
        "a matching reply must not be reported as a mismatch"
    );
}

#[tokio::test]
async fn every_rfc1413_error_token_is_recognised() {
    for token in ["NO-USER", "INVALID-PORT", "HIDDEN-USER", "UNKNOWN-ERROR"] {
        let state = state_without_llm().await;
        let (tx, _rx) = mpsc::unbounded_channel();

        let port = start_ident_server(
            &state,
            &tx,
            serde_json::json!({
                "type": "send_ident_error",
                "server_port": 6193,
                "client_port": 23,
                "error": token
            }),
        )
        .await;
        let client_id = start_ident_client(&state, &tx, port, client_handlers(6193, 23)).await;

        let data = await_client_event(&state, client_id, "ident_error_received").await;
        assert_eq!(data["error_token"], token, "wrong token reported: {data}");
        assert_eq!(data["server_port"], 6193);
        assert_eq!(data["client_port"], 23);
        assert!(
            client_events(&state, client_id, "ident_response_received")
                .await
                .is_empty(),
            "an ERROR reply must never be reported as a USERID result"
        );
    }
}

// ============================================================================
// Against hand-written peers. Frames NetGet's own server cannot produce.
// ============================================================================

/// **The one correctness property an ident client really has.**
///
/// RFC 1413 §3 has the client match a reply to its query by the port pair. This peer answers a
/// query about `6193 , 23` with a perfectly well-formed USERID line about `9999 , 8888`. It is
/// not a slightly-wrong answer: it is an answer about a different connection, and accepting it
/// would attribute `imposter` to a socket nobody asked about.
///
/// NetGet's own ident server cannot be the peer here — `enforce_port_pair` rewrites exactly
/// this frame into a correct one on purpose.
#[tokio::test]
async fn a_reply_about_a_different_port_pair_is_rejected() {
    let state = state_without_llm().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let (port, queries) = spawn_raw_ident_peer("9999 , 8888 : USERID : UNIX : imposter\r\n").await;
    let client_id = start_ident_client(&state, &tx, port, client_handlers(6193, 23)).await;

    let data = await_client_event(&state, client_id, "ident_reply_mismatch").await;
    assert_eq!(data["reason"], "port_pair_mismatch");
    assert_eq!(data["queried_server_port"], 6193);
    assert_eq!(data["queried_client_port"], 23);
    assert_eq!(data["reply_server_port"], 9999);
    assert_eq!(data["reply_client_port"], 8888);
    assert!(
        data["reply_line"]
            .as_str()
            .unwrap_or("")
            .contains("imposter"),
        "the rejected line should be reported for diagnosis: {data}"
    );

    assert!(
        client_events(&state, client_id, "ident_response_received")
            .await
            .is_empty(),
        "a reply about a different port pair must NOT be accepted as a result — this is the \
         whole correctness property of an ident client"
    );

    // And the query really did go out with the pair that was asked for.
    let asked = queries.lock().await.join("");
    assert!(
        asked.trim() == "6193 , 23",
        "the query on the wire should be '6193 , 23', got {asked:?}"
    );
}

#[tokio::test]
async fn whitespace_from_a_real_peer_parses_on_the_wire() {
    let state = state_without_llm().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let (port, _queries) =
        spawn_raw_ident_peer("  6193 ,  23  :  USERID :  UNIX , US-ASCII : spacey \r\n").await;
    let client_id = start_ident_client(&state, &tx, port, client_handlers(6193, 23)).await;

    let data = await_client_event(&state, client_id, "ident_response_received").await;
    assert_eq!(data["userid"], "spacey");
    assert_eq!(data["opsys"], "UNIX");
    assert_eq!(data["charset"], "US-ASCII");
}

// ============================================================================
// With the model. The defect this guards is the most common client bug here.
// ============================================================================

/// The model is asked what to do about a reply, and what it answers is carried out.
///
/// The follow-up is a **new TCP connection**, because RFC 1413 is one exchange per connection
/// and the server has already closed — and it raises its own event, so the chain can continue
/// (bounded by `MAX_FOLLOWUP_DEPTH`, not by silence). Discarding `result.actions`, the defect
/// the root `CLAUDE.md` describes as the most common client bug in this repo, would leave the
/// second query unsent and this test red.
///
/// One rule per event id, and the `ident_response_received` rule branches on the event data
/// rather than being two rules — two rules on one event is the mocking mistake this repo makes
/// most often (the first answers everything, the second reports zero calls).
///
/// LLM calls: 3.
#[tokio::test]
async fn the_model_can_chain_a_second_query() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("ident_connected")
            .respond_with_actions(serde_json::json!([{
                "type": "send_ident_query",
                "server_port": 6193,
                "client_port": 23
            }]))
            .expect_calls(1)
            .and()
            .on_event("ident_response_received")
            .respond_with_actions_from_event(|event| {
                if event.get("server_port").and_then(|v| v.as_u64()) == Some(6193) {
                    // The follow-up. This is the action that gets discarded when a client is
                    // wired the wrong way.
                    serde_json::json!([{
                        "type": "send_ident_query",
                        "server_port": 7000,
                        "client_port": 24
                    }])
                } else {
                    serde_json::json!([{ "type": "disconnect" }])
                }
            })
            .expect_calls(2)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // The server answers with a fixed pair; its own `enforce_port_pair` readdresses each reply
    // to whichever pair was queried, so the follow-up comes back as 7000,24 and the mock's
    // branch fires.
    let port = start_ident_server(
        &state,
        &tx,
        serde_json::json!({
            "type": "send_ident_userid",
            "server_port": 6193,
            "client_port": 23,
            "opsys": "UNIX",
            "userid": "ircuser"
        }),
    )
    .await;

    let client_id = ClientForm {
        protocol: "ident".to_string(),
        remote_addr: Some("127.0.0.1".to_string()),
        startup_params: Some(serde_json::json!({ "ident_port": port })),
        instruction: Some(
            "Ask who owns 6193,23; when you know, ask about 7000,24 as well.".to_string(),
        ),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new(mock.base_url()),
        tx.clone(),
    )
    .await
    .expect("create ident client");

    // Both replies were accepted, and the second one is about the pair the model chose second.
    for _ in 0..1_000 {
        let seen = client_events(&state, client_id, "ident_response_received").await;
        if seen
            .iter()
            .any(|d| d["server_port"] == 7000 && d["client_port"] == 24)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let seen = client_events(&state, client_id, "ident_response_received").await;
    assert!(
        seen.iter()
            .any(|d| d["server_port"] == 7000 && d["client_port"] == 24),
        "the follow-up query the model asked for never happened — its answer to \
         ident_response_received was discarded. Events seen: {seen:?}"
    );
    assert!(
        client_events(&state, client_id, "ident_reply_mismatch")
            .await
            .is_empty(),
        "the follow-up's reply must be matched to the follow-up's own query"
    );

    mock.wait_for_expectations(30).await;
    mock.verify_calls().await.expect("mock expectations");
}

//! Does a static handler with an **empty** `actions` array suppress the LLM call?
//!
//! The root `CLAUDE.md` recorded this as an unexplained observation under "Known systemic
//! issues": with `{"type":"static","actions":[]}` on a `*` pattern, a probe on the `call_llm`
//! error branch fired with a real backend error, apparently proving the model was consulted;
//! changing only that JSON to `[{"type":"wait_for_more"}]` made the probe stop firing. The
//! mechanism was never found, and every candidate was ruled out by inspection.
//!
//! **This matters well beyond one xmpp test.** `src/tui/modal/form.rs` uses exactly the
//! empty-list form for every dashboard-created client's `<proto>_connected` rule, whose entire
//! purpose is to stop the connect event parking or reaching the model. If the observation
//! generalises, that rule does nothing and every dashboard-created client sends its connect
//! event to the LLM.
//!
//! # How this answers it
//!
//! The earlier observation was indirect — a probe on an error branch, in a full-suite run,
//! under load. This asks the question directly: point NetGet at a mock model that **records
//! every call it receives**, and count.
//!
//! A zero on its own proves nothing (the harness might simply be unreachable), so the negative
//! control has to show a non-zero on the same harness. The three cases share everything except
//! the routing table:
//!
//! | case | routing | expectation |
//! |---|---|---|
//! | control | no handler at all | the model **is** called, and its answer reaches the peer |
//! | empty | `{"type":"static","actions":[]}` | the model is **not** called |
//! | wait_for_more | `{"type":"static","actions":[{"type":"wait_for_more"}]}` | the model is **not** called |
//!
//! # Why all three live in ONE test
//!
//! They used to be three `#[tokio::test]`s, and that shape is what let this file assert
//! nothing for weeks while looking mostly green.
//!
//! The control **had never passed** — not once, from the commit that introduced the file
//! (`74dbb7f4`). The cause was not the routing at all: the harness never configured a model, so
//! `ensure_model_selected` fell through to auto-selection, which was hardcoded to
//! `http://localhost:11434` and ignored the endpoint the `AppState` was built with. Every event
//! *did* reach the LLM path and then failed closed at
//! `decision=fail_closed_llm_error … error=Failed to ensure model is selected` — before any
//! request was issued to the mock. So the mock recorded zero calls in **all three** cases, for
//! two unrelated reasons, and the two that expected zero passed.
//!
//! Split across three tests, the run reads `7 passed; 1 failed` and the two headline claims are
//! green — which is precisely backwards, because a dead control makes them worthless. In one
//! test the control is a precondition: if it ever stops reaching the model, the suppression
//! claims cannot report success on their own. That is the structural lesson, and it is cheaper
//! to encode than to remember.
//!
//! The product defect is fixed (`ensure_model_selected` takes the configured endpoint) and is
//! pinned separately by `tests/model_selection_endpoint_test.rs`. This file deliberately does
//! **not** pin a model: doing so would make the control pass without the fix and hide the same
//! class of failure again.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp --test empty_static_handler_test -- --test-threads=100


mod helpers;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use helpers::mock_builder::MockLlmBuilder;
use helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::sync::mpsc;

/// What one poke of a TCP server produced.
struct Probe {
    /// How many calls the mock model recorded.
    llm_calls: usize,
    /// What the peer read back off the socket.
    ///
    /// The counter alone cannot tell a suppressed call apart from a server that never got as
    /// far as raising an event. The control's mock answers with `send_tcp_data
    /// "from-the-model"`, so bytes on the wire prove the whole event → LLM → action → peer
    /// path ran, not merely that an HTTP request was logged somewhere.
    reply: String,
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..200 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

/// Start a TCP server with the given routing, poke it once, and report what happened.
///
/// The instruction is deliberately non-empty. `ServerForm::create` substitutes a default
/// instruction when `instruction` is `None`, and any non-empty instruction makes
/// `operator_wants_dynamic` true — which is precisely the condition under which the model
/// *would* be consulted. A test that left this empty would measure nothing.
///
/// `expect_call` selects how long to wait, and the two directions genuinely differ. Proving a
/// call *happened* is a wait-until: poll generously and return the instant it lands, so a slow
/// machine costs nothing when the answer is yes. Proving one *did not* happen is a
/// wait-to-be-sure: there is no event to wait for, so the only guarantee is elapsed time, and
/// the wait has to be long enough that a call would have shown up.
async fn probe(routing: Option<serde_json::Value>, expect_call: bool) -> Probe {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            // Unconstrained, so anything that reaches the model matches and is recorded
            // rather than 500-ing into an error path that could be mistaken for silence.
            .on_any()
            .respond_with_actions(serde_json::json!([{
                "type": "send_tcp_data",
                "data": "from-the-model",
                "encoding": "utf8"
            }]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let id = ServerForm {
        protocol: "tcp".to_string(),
        port: Some(0),
        instruction: Some("Answer whatever arrives.".to_string()),
        event_handlers: routing.map(|r| r.as_array().unwrap().clone()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create tcp server");

    let port = wait_for_port(&state, id).await;

    // One request, then give the server room to make (or not make) a round trip.
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"ping").expect("write");
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).unwrap_or(0);
    let reply = String::from_utf8_lossy(&buf[..n]).to_string();

    let budget = if expect_call {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(10)
    };
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if expect_call && mock.call_count().await > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let llm_calls = mock.call_count().await;
    let _ = state.remove_server(id).await;
    Probe { llm_calls, reply }
}

fn rule(handler: serde_json::Value) -> serde_json::Value {
    serde_json::json!([{ "event_pattern": "*", "handler": handler }])
}

/// The control and both claims, in one test, so a dead control cannot leave the claims
/// reporting success. See the module header for why that is not merely tidier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_static_handler_suppresses_the_llm_call() {
    // === Control: no routing at all. The model must be reached. ===
    let control = probe(None, true).await;
    assert!(
        control.llm_calls > 0,
        "CONTROL FAILED: no routing at all must reach the model. Everything below this line is \
         worthless while this is 0 — a zero in the suppression cases would then mean only that \
         the mock is unreachable. Check the server's log for \
         `decision=fail_closed_llm_error` before touching the routing: the harness reached the \
         LLM path and died inside it once already, at model selection."
    );
    assert_eq!(
        control.reply, "from-the-model",
        "CONTROL FAILED: the model's answer must reach the peer. A recorded HTTP call with no \
         bytes on the wire would mean the event → LLM → action path is broken downstream, and \
         the comparison below would be between two different kinds of silence."
    );

    // === The claim under test. Same harness, one field of the routing table different. ===
    let empty = probe(
        Some(rule(serde_json::json!({"type": "static", "actions": []}))),
        false,
    )
    .await;
    assert_eq!(
        empty.llm_calls, 0,
        "a static handler with an empty actions array must answer the event itself. If this \
         fails, the CLAUDE.md observation generalises and src/tui/modal/form.rs's connect rule \
         for every dashboard-created client is a no-op — fix that too, do not just relax this."
    );

    // === The comparison the original observation drew, measured the same way. ===
    let wait_for_more = probe(
        Some(rule(serde_json::json!({
            "type": "static",
            "actions": [{"type": "wait_for_more"}]
        }))),
        false,
    )
    .await;
    assert_eq!(
        wait_for_more.llm_calls, 0,
        "a static handler naming a real no-op verb must also answer without the model"
    );

    // The original observation was that these two forms differ. They do not.
    assert_eq!(
        empty.llm_calls, wait_for_more.llm_calls,
        "the empty-actions and wait_for_more forms must behave identically — the CLAUDE.md \
         observation was that they differed, and that is the thing being refuted"
    );
}

// ============================================================================
// The client side — which is the side `src/tui/modal/form.rs` actually uses
// ============================================================================

/// Poke a TCP client and report how many LLM calls its connect event provoked.
///
/// Servers and clients have **separate dispatchers** — `try_execute_event_handler` and
/// `try_execute_client_event_handler`, each with its own `EventHandlerType::Static` arm and
/// its own caller (`action_helper::call_llm` vs `client/llm_budget.rs::call_llm_for_client`).
/// Nothing makes them agree. So a server-side measurement says nothing about the client, and
/// the connect rule this is here to check is a client rule.
async fn client_connect_llm_calls(routing: Option<serde_json::Value>, expect_call: bool) -> usize {
    use netget::cli::management::ClientForm;

    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_any()
            .respond_with_actions(serde_json::json!([{
                "type": "send_tcp_data",
                "data": "from-the-model",
                "encoding": "utf8"
            }]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");

    // A plain listener that accepts and then says nothing, so `tcp_connected` is the only
    // event the client can raise. Anything chattier would blur the measurement.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind peer");
    let peer_addr = listener.local_addr().expect("peer addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            // Hold the connection open; drop only when the test ends.
            std::mem::forget(stream);
        }
    });

    let state = AppState::new_with_options(false, mock.base_url());
    let llm_client = netget::llm::OllamaClient::new(mock.base_url());
    state.set_llm_client(llm_client.clone()).await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let id = ClientForm {
        protocol: "tcp".to_string(),
        remote_addr: Some(peer_addr.to_string()),
        instruction: Some("Say something on connect.".to_string()),
        event_handlers: routing.map(|r| r.as_array().unwrap().clone()),
        ..Default::default()
    }
    .create(&state, llm_client, tx)
    .await
    .expect("create tcp client");

    let budget = if expect_call {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(10)
    };
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if expect_call && mock.call_count().await > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let count = mock.call_count().await;
    let _ = state.remove_client(id).await;
    count
}

/// The dashboard's default client routing really does keep the connect event off the model.
///
/// `src/tui/modal/form.rs::default_event_handlers` gives every interactively created client a
/// zero-action static rule on each `<proto>_connected` id, ahead of the `*` → manual wildcard.
/// `CLAUDE.md` recorded that rule as working **on the strength of the server-side measurement
/// above** — which was doubly wrong: that measurement's control had never passed, and even had
/// it passed, the server and client dispatchers are different code with different callers.
/// This measures the rule that actually ships, on the side that actually uses it.
///
/// The rule is inlined rather than called, because `default_event_handlers` is private to the
/// TUI module. It must stay in step with it; the shape is one exact-id static rule per connect
/// event plus the manual wildcard (`EventPattern` has no globbing, so `*_connected` would match
/// nothing).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_dashboards_client_connect_rule_keeps_the_event_off_the_model() {
    // === Control: no routing at all. The connect event must reach the model. ===
    let control = client_connect_llm_calls(None, true).await;
    assert!(
        control > 0,
        "CONTROL FAILED: a client with no routing must consult the model on connect. While \
         this is 0 the assertion below proves nothing about the connect rule — only that the \
         mock is unreachable."
    );

    // === What the dashboard actually builds. ===
    let dashboard_default = client_connect_llm_calls(
        Some(serde_json::json!([
            {
                "event_pattern": "tcp_connected",
                "handler": {"type": "static", "actions": []}
            },
            { "event_pattern": "*", "handler": {"type": "manual"} }
        ])),
        false,
    )
    .await;
    assert_eq!(
        dashboard_default, 0,
        "the dashboard's zero-action `<proto>_connected` rule must answer the connect event \
         itself. If this is non-zero, every dashboard-created client sends its connect event to \
         the LLM and form.rs's rule is decoration."
    );
}

// ============================================================================
// The server side of the dashboard's routing: connect events
// ============================================================================

/// Start a Telnet server with the given routing, CONNECT without sending anything, and count the
/// calls the model received. Only `telnet_connection_opened` can fire.
async fn server_connect_llm_calls(routing: Option<serde_json::Value>, expect_call: bool) -> usize {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_any()
            .respond_with_actions(serde_json::json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let id = ServerForm {
        protocol: "telnet".to_string(),
        port: Some(0),
        instruction: Some("Answer whatever arrives.".to_string()),
        event_handlers: routing.map(|r| r.as_array().unwrap().clone()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create telnet server");
    let port = wait_for_port(&state, id).await;

    let _stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let budget = if expect_call {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(5)
    };
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if expect_call && mock.call_count().await > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let count = mock.call_count().await;
    let _ = state.remove_server(id).await;
    count
}

/// `telnet_connection_opened` is raised for every connection, and a server created at the
/// dashboard must still pay nothing for it.
///
/// The routing is the one `src/tui/modal/form.rs::default_event_handlers` really builds for a
/// Telnet server — called, not inlined — so if the protocol stops declaring its connect event with
/// `raised_on_every_connection()`, or the dashboard stops reading the marker, the rule vanishes
/// and this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_dashboards_server_connect_rule_keeps_the_connect_event_off_the_model() {
    // === Control: no routing. A bare connection must now reach the model. ===
    let control = server_connect_llm_calls(None, true).await;
    assert!(
        control > 0,
        "CONTROL FAILED: telnet_connection_opened must be raised for a connection that has sent \
         nothing, and with no routing it must reach the model. While this is 0 the assertion \
         below proves nothing."
    );

    let dashboard_default = netget::tui::modal::form::default_event_handlers(
        netget::tui::app::Section::Servers,
        "telnet",
    );
    let rules = dashboard_default.as_array().expect("an array of rules");
    assert_eq!(
        rules.first().map(|r| r["event_pattern"].clone()),
        Some(serde_json::json!("telnet_connection_opened")),
        "the dashboard's server routing must answer the connect event ahead of the manual \
         wildcard: {dashboard_default}"
    );

    // Without the manual wildcard, only the connect rule stands between the event and the
    // model, so a zero here is the rule answering, not a park.
    let connect_rule_only = serde_json::Value::Array(vec![rules[0].clone()]);
    let with_rule = server_connect_llm_calls(Some(connect_rule_only), false).await;
    assert_eq!(
        with_rule, 0,
        "the dashboard's zero-action telnet_connection_opened rule must answer the connect event \
         itself; every connection to a dashboard-created server would otherwise cost a model \
         call"
    );
}

//! E2E tests for the Gopher (RFC 1436) client.
//!
//! # What the peer is, and what that proves
//!
//! The server on the other end is **NetGet's own Gopher server**. That makes every wire
//! assertion here *same-project evidence*: it shows the two halves of this repo agree with
//! each other, not that either agrees with RFC 1436. The root `CLAUDE.md` names that class by
//! name ("circular: the peer is the same crate the server frames with") and it is why the
//! client is rated `Experimental` and not `Beta`. See `src/client/gopher/CLAUDE.md` for what
//! would earn the promotion.
//!
//! It is still worth doing. What it does prove is everything on this client's own side of the
//! socket: that a menu is parsed into structured items, that a document's doubled leading dots
//! are undone, that a type-7 search puts the query on the wire after a tab, that a type-3 item
//! is recognised whatever type was asked for — and, the one that matters most, that a menu item
//! the model picks is fetched on a **new connection**, because Gopher closes after every reply.
//!
//! # Mocking
//!
//! One in-process mock model serves both halves. The rules are ordered so that the three
//! client events and the server's `gopher_request` match first; the client's
//! initial-instruction call (`event: None`) is caught last by the literal user message
//! `call_llm_for_client` writes for it, "Waiting for instructions". Two rules that cannot be
//! told apart is the most common mocking mistake in this repo, so the server's single rule
//! branches on the selector inside one `respond_with_actions_from_event` rather than being
//! split into three rules on the same event id.
//!
//! LLM call budget: 7 + 3 = **10**, and the parsing test spends none.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features gopher --test client -- gopher --test-threads=100

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::{ClientForm, ServerForm};
use netget::client::gopher::{
    item_type_name, parse_gopher_reply, request_line, GopherMenuItem, GopherReply,
};
use netget::state::app_state::AppState;
use netget::state::{ClientId, ClientStatus, ServerId};
use serde_json::{json, Value};
use tokio::sync::mpsc;

/// The user message `call_llm_for_client` writes when there is no event — the client's
/// opening turn. Matching on it is how the initial fetch is distinguished from every event.
const OPENING_TURN: &str = "Waiting for instructions";

type Captured = Arc<Mutex<Vec<Value>>>;

fn captured() -> Captured {
    Arc::new(Mutex::new(Vec::new()))
}

/// Record an event and hand back the actions to answer it with.
///
/// The generator is rendered exactly once per request (the harness used to render it twice,
/// which advanced a stateful closure two steps per call), so recording here is safe.
fn record(sink: &Captured, event: &Value) {
    sink.lock().expect("capture lock").push(event.clone());
}

fn first(sink: &Captured) -> Value {
    sink.lock()
        .expect("capture lock")
        .first()
        .cloned()
        .unwrap_or(Value::Null)
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..1_000 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Gopher server #{} never bound a port", id.as_u32());
}

async fn wait_for_disconnect(state: &AppState, id: ClientId) -> bool {
    for _ in 0..600 {
        if matches!(
            state.get_client(id).await.map(|c| c.status),
            Some(ClientStatus::Disconnected)
        ) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    false
}

// -------------------------------------------------------------------------------------
// 1. The iterative path: menu -> follow an item -> document -> a refused selector
// -------------------------------------------------------------------------------------

/// Browsing, which is the thing this client exists to do.
///
/// The chain is four model turns on the client side: fetch the root menu, follow the text
/// file the menu lists, ask for a selector the server refuses, stop. Each step needs the
/// previous step's reply to have been **raised as an event and acted on** — a follow-up fetch
/// that raised nothing would give the model one turn and then go deaf, which is the
/// `elasticsearch`/`http2` defect this repo has hit repeatedly.
///
/// The follow-up deliberately copies the menu item's `selector`, `host`, `port` and
/// `item_type` back verbatim rather than hardcoding them. That is the contract the event
/// promises the model, and it only holds if the item was parsed into real fields.
#[tokio::test]
async fn browsing_follows_a_menu_item_to_a_document_and_then_to_a_refusal() {
    // The server's menu has to point at the port it actually bound, which is not known until
    // after the mock is built. Nothing reads it before the client's first request, which is
    // long after it is set.
    let server_port = Arc::new(AtomicU16::new(0));

    let menus = captured();
    let documents = captured();
    let errors = captured();

    let menu_port = server_port.clone();
    let menus_seen = menus.clone();
    let documents_seen = documents.clone();
    let errors_seen = errors.clone();

    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            // --- the server half: one rule, branching on the selector -------------------
            .on_event("gopher_request")
            .respond_with_actions_from_event(move |event| {
                let selector = event.get("selector").and_then(|v| v.as_str()).unwrap_or("");
                let port = menu_port.load(Ordering::SeqCst) as u64;
                match selector {
                    "" | "/" => json!([{
                        "type": "send_gopher_menu",
                        "items": [
                            {"type": "i", "display": "Welcome to the burrow"},
                            {"type": "0", "display": "About this hole",
                             "selector": "/about.txt", "host": "127.0.0.1", "port": port},
                            {"type": "1", "display": "Files",
                             "selector": "/files", "host": "127.0.0.1", "port": port},
                            {"type": "7", "display": "Search the archive",
                             "selector": "/search", "host": "127.0.0.1", "port": port}
                        ]
                    }]),
                    // The middle line begins with a period, so the server doubles it on the
                    // wire and the client has to undo that.
                    "/about.txt" => json!([{
                        "type": "send_gopher_text",
                        "text": "About this hole\n.hidden line starts with a period\nend\n"
                    }]),
                    _ => json!([{
                        "type": "send_gopher_error",
                        "message": "No such selector"
                    }]),
                }
            })
            .expect_calls(3)
            .and()
            // --- the client half --------------------------------------------------------
            .on_event("gopher_menu_received")
            .respond_with_actions_from_event(move |event| {
                record(&menus_seen, event);
                // Follow the text file by echoing the item back, field for field.
                let item = event
                    .get("items")
                    .and_then(|v| v.as_array())
                    .and_then(|items| {
                        items
                            .iter()
                            .find(|i| i.get("item_type").and_then(|t| t.as_str()) == Some("0"))
                    })
                    .cloned()
                    .unwrap_or(Value::Null);
                json!([{
                    "type": "send_gopher_request",
                    "selector": item.get("selector").cloned().unwrap_or(Value::Null),
                    "host": item.get("host").cloned().unwrap_or(Value::Null),
                    "port": item.get("port").cloned().unwrap_or(Value::Null),
                    "item_type": item.get("item_type").cloned().unwrap_or(Value::Null)
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("gopher_document_received")
            .respond_with_actions_from_event(move |event| {
                record(&documents_seen, event);
                // Ask for something that is not there. The reply is a type-3 item even
                // though this asks for a document, which is the one case where the reply's
                // own bytes overrule the requested type.
                json!([{"type": "send_gopher_request", "selector": "/nope", "item_type": "0"}])
            })
            .expect_calls(1)
            .and()
            .on_event("gopher_error_received")
            .respond_with_actions_from_event(move |event| {
                record(&errors_seen, event);
                json!([{"type": "disconnect"}])
            })
            .expect_calls(1)
            .and()
            // The opening turn. Last, so every event rule above is tried first.
            .on_prompt_containing(OPENING_TURN)
            .respond_with_actions(json!([{
                "type": "send_gopher_request", "selector": "", "item_type": "1"
            }]))
            .expect_calls(1)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;

    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "gopher".to_string(),
        port: Some(0),
        instruction: Some("Serve the burrow.".to_string()),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create gopher server");
    let port = wait_for_port(&state, server_id).await;
    server_port.store(port, Ordering::SeqCst);

    let client_id: ClientId = ClientForm {
        protocol: "gopher".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Browse the burrow from the root menu.".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new(mock.base_url()),
        tx.clone(),
    )
    .await
    .expect("create gopher client");

    mock.wait_for_expectations(30).await;

    // --- the menu was parsed into items ------------------------------------------------
    let menu = first(&menus);
    assert_eq!(
        menu.get("item_count").and_then(|v| v.as_u64()),
        Some(4),
        "the root menu should have parsed into four items: {menu:#}"
    );
    let items = menu
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    assert_eq!(
        items[0].get("item_type").and_then(|v| v.as_str()),
        Some("i"),
        "the first line is the informational one: {menu:#}"
    );
    assert_eq!(
        items[0].get("display").and_then(|v| v.as_str()),
        Some("Welcome to the burrow")
    );
    assert!(
        items[0]
            .get("item_type_name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains("informational"),
        "an 'i' item must say it is not a link, or the model will try to follow it: {menu:#}"
    );

    assert_eq!(
        items[1].get("selector").and_then(|v| v.as_str()),
        Some("/about.txt"),
        "the tab-separated fields must have become real fields: {menu:#}"
    );
    assert_eq!(
        items[1].get("port").and_then(|v| v.as_u64()),
        Some(port as u64),
        "an item carries its own host and port so a gopherspace can span servers: {menu:#}"
    );
    assert_eq!(
        items[3].get("item_type").and_then(|v| v.as_str()),
        Some("7"),
        "the search item's type must survive parsing: {menu:#}"
    );
    assert!(
        menu.get("malformed_lines").is_none(),
        "nothing in this menu is malformed: {menu:#}"
    );

    // --- the document arrived un-escaped, on a second connection ------------------------
    let document = first(&documents);
    let text = document
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        text.contains("\n.hidden line starts with a period\n"),
        "the doubled leading period must have been undone: {text:?}"
    );
    assert!(
        !text.contains(".."),
        "a doubled period must not survive into the event: {text:?}"
    );
    assert!(
        !text.contains("\n.\n") && !text.ends_with("\n."),
        "the terminating '.' line is framing and must not reach the model: {text:?}"
    );
    assert_eq!(
        document.get("line_count").and_then(|v| v.as_u64()),
        Some(3),
        "three lines, with no blank line left by the trailing newline: {document:#}"
    );
    assert_eq!(
        document.get("selector").and_then(|v| v.as_str()),
        Some("/about.txt"),
        "the event must name the selector that was followed: {document:#}"
    );

    // --- a type-3 item is an error however it was asked for ------------------------------
    let error = first(&errors);
    assert_eq!(
        error.get("message").and_then(|v| v.as_str()),
        Some("No such selector"),
        "a type-3 reply to a document request must raise gopher_error_received: {error:#}"
    );
    assert_eq!(
        error.get("selector").and_then(|v| v.as_str()),
        Some("/nope")
    );

    assert!(
        wait_for_disconnect(&state, client_id).await,
        "the model's disconnect should have ended the browsing session; status={:?}",
        state.get_client(client_id).await.map(|c| c.status)
    );
    assert!(
        !state.has_client_handle(client_id).await,
        "a finished client must stop offering [ send ]"
    );

    mock.verify_calls().await.expect("mock expectations");
}

// -------------------------------------------------------------------------------------
// 2. A type-7 search
// -------------------------------------------------------------------------------------

/// `send_gopher_search` puts `<selector>\t<query>` on the wire, and the result menu comes
/// back parsed like any other.
///
/// The assertion that matters is on the *server's* view of the request: the query has to
/// arrive as `search_query`, which only happens if the tab was written. NetGet's Gopher
/// server omits that key entirely for a plain fetch, so its presence is the proof.
#[tokio::test]
async fn a_type_7_search_sends_the_query_after_a_tab_and_parses_the_results() {
    let requests = captured();
    let menus = captured();

    let requests_seen = requests.clone();
    let menus_seen = menus.clone();

    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("gopher_request")
            .respond_with_actions_from_event(move |event| {
                record(&requests_seen, event);
                let query = event
                    .get("search_query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                json!([{
                    "type": "send_gopher_menu",
                    "items": [{
                        "type": "0",
                        "display": format!("Result for {query}"),
                        "selector": "/hit.txt",
                        "host": "127.0.0.1",
                        "port": 70
                    }]
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("gopher_menu_received")
            .respond_with_actions_from_event(move |event| {
                record(&menus_seen, event);
                json!([{"type": "disconnect"}])
            })
            .expect_calls(1)
            .and()
            .on_prompt_containing(OPENING_TURN)
            .respond_with_actions(json!([{
                "type": "send_gopher_search", "selector": "/search", "query": "burrow depth"
            }]))
            .expect_calls(1)
            .build(),
    )
    .await
    .expect("mock ollama");

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;

    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "gopher".to_string(),
        port: Some(0),
        instruction: Some("Answer searches.".to_string()),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create gopher server");
    let port = wait_for_port(&state, server_id).await;

    let client_id: ClientId = ClientForm {
        protocol: "gopher".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Search the archive for burrow depth.".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new(mock.base_url()),
        tx.clone(),
    )
    .await
    .expect("create gopher client");

    mock.wait_for_expectations(30).await;

    let request = first(&requests);
    assert_eq!(
        request.get("selector").and_then(|v| v.as_str()),
        Some("/search"),
        "the selector must be the part before the tab: {request:#}"
    );
    assert_eq!(
        request.get("search_query").and_then(|v| v.as_str()),
        Some("burrow depth"),
        "the query must arrive after a tab, or this was a plain fetch: {request:#}"
    );

    let menu = first(&menus);
    assert_eq!(
        menu.get("item_count").and_then(|v| v.as_u64()),
        Some(1),
        "search results are an ordinary menu: {menu:#}"
    );
    let items = menu
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        items[0].get("display").and_then(|v| v.as_str()),
        Some("Result for burrow depth"),
        "the result should name what was searched for: {menu:#}"
    );

    assert!(
        wait_for_disconnect(&state, client_id).await,
        "the search session should have ended"
    );

    mock.verify_calls().await.expect("mock expectations");
}

// -------------------------------------------------------------------------------------
// 3. The parser on its own — no sockets, no model
// -------------------------------------------------------------------------------------

/// The reply carries no content type, so `parse_gopher_reply` is told what was *asked* for.
/// These are the four outcomes that decision produces, pinned directly.
#[test]
fn a_reply_is_read_according_to_the_item_type_that_was_requested() {
    // A menu, asked for as one.
    let menu_bytes = "iWelcome\tfake\t(NULL)\t0\r\n\
                      0About\t/about.txt\t127.0.0.1\t70\r\n\
                      1Files\t/files\tgopher.example\t7070\r\n\
                      .\r\n";
    match parse_gopher_reply(menu_bytes, '1') {
        GopherReply::Menu {
            items,
            malformed_lines,
        } => {
            assert!(malformed_lines.is_empty(), "{malformed_lines:?}");
            assert_eq!(
                items[0],
                GopherMenuItem {
                    item_type: 'i',
                    display: "Welcome".to_string(),
                    selector: "fake".to_string(),
                    host: "(NULL)".to_string(),
                    port: 0,
                }
            );
            assert_eq!(items[2].host, "gopher.example");
            assert_eq!(items[2].port, 7070);
        }
        other => panic!("expected a menu, got {other:?}"),
    }

    // A document, asked for as one. The terminator goes, the doubled dot comes back to one,
    // and the trailing newline before the terminator does not leave a blank line.
    let document_bytes = "About\r\n..hidden\r\nend\r\n.\r\n";
    match parse_gopher_reply(document_bytes, '0') {
        GopherReply::Document { text } => {
            assert_eq!(text, "About\n.hidden\nend");
        }
        other => panic!("expected a document, got {other:?}"),
    }

    // A type-3 item, asked for as a document. The requested type does not get a vote here:
    // type 3 is the only error the protocol has, and it can answer any request.
    let error_bytes = "3No such selector\t\terror.host\t1\r\n.\r\n";
    match parse_gopher_reply(error_bytes, '0') {
        GopherReply::Error { message } => assert_eq!(message, "No such selector"),
        other => panic!("expected an error item, got {other:?}"),
    }

    // The guess was wrong: a menu was asked for and nothing parses as a menu line. The bytes
    // are reported as a document rather than as an empty menu, so nothing is lost.
    let prose = "this is not a menu\r\nnor is this\r\n.\r\n";
    match parse_gopher_reply(prose, '1') {
        GopherReply::Document { text } => {
            assert_eq!(text, "this is not a menu\nnor is this");
        }
        other => panic!("a menu request with no menu lines should fall back, got {other:?}"),
    }

    // A document whose first line merely starts with the digit 3 is not an error: the test
    // is structural, and a type-3 item has the tab-separated fields of a menu line.
    match parse_gopher_reply("3 apples and a pear\r\n.\r\n", '0') {
        GopherReply::Document { text } => assert_eq!(text, "3 apples and a pear"),
        other => panic!("a leading '3' with no tab is prose, got {other:?}"),
    }

    // A server that closes without a terminator is still a complete transfer: the FIN is the
    // framing.
    match parse_gopher_reply("just this\r\n", '0') {
        GopherReply::Document { text } => assert_eq!(text, "just this"),
        other => panic!("expected a document, got {other:?}"),
    }
}

/// The request line, which is the whole of what this client writes.
#[test]
fn the_request_line_is_a_selector_and_optionally_a_tab_and_a_query() {
    assert_eq!(request_line("", None), "\r\n");
    assert_eq!(request_line("/about.txt", None), "/about.txt\r\n");
    assert_eq!(
        request_line("/search", Some("burrow depth")),
        "/search\tburrow depth\r\n"
    );
    assert!(item_type_name('7').contains("search"));
    assert!(item_type_name('i').contains("not a link"));
}

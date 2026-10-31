//! Reusing the model's answers: record → rules (`export_rules`) and memoisation.
//!
//! Every test here counts model calls on a mock that records each one it receives, and every
//! zero is preceded on the same harness by a non-zero: the recording phase (or a control
//! request) must reach the model, or a zero later would only mean the mock was unreachable.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!     --test answer_reuse_test -- --test-threads=8

mod helpers;

use std::time::Duration;

use helpers::mock_builder::MockLlmBuilder;
use helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::llm::rule_export::{self, Fallback};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

async fn state_for(mock: &MockOllamaServer) -> AppState {
    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    state
}

async fn start(state: &AppState, form: ServerForm) -> (ServerId, std::net::SocketAddr) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = form.create(state, tx).await.expect("server starts");
    for _ in 0..300 {
        if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
            return (id, addr);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server #{} never bound", id.as_u32());
}

/// One HTTP/1.1 request on its own connection, with fixed headers so recording and replay
/// send byte-identical requests. Returns (status, body).
async fn http(addr: std::net::SocketAddr, method: &str, path: &str, body: &str) -> (u16, String) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: answer-reuse\r\nConnection: close\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut raw))
        .await
        .expect("HTTP response within 30s")
        .expect("read");
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {text:?}"));
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

/// The mock's HTTP answers: the body names the method and path, so a rule answering the
/// wrong request is visible in the body.
fn http_answer(event: &Value) -> Value {
    let method = event["method"].as_str().unwrap_or("");
    let path = event["path"].as_str().unwrap_or("");
    match (method, path) {
        ("GET", "/hello") => json!([{"type": "send_http_response", "status": 200,
            "headers": {"Content-Type": "text/plain"}, "body": "hello world"}]),
        ("GET", "/users") => json!([{"type": "send_http_response", "status": 200,
            "headers": {"Content-Type": "application/json"}, "body": "[{\"id\":1}]"}]),
        ("POST", "/users") => json!([{"type": "send_http_response", "status": 201,
            "body": "created"}]),
        // An action the executor refuses: never memoised, never a rule.
        ("GET", "/broken") => json!([{"type": "send_http_response", "status": 9999}]),
        _ => json!([{"type": "send_http_response", "status": 404, "body": format!("no {path}")}]),
    }
}

fn http_mock() -> helpers::mock_config::MockLlmConfig {
    MockLlmBuilder::new()
        .on_event("http_request")
        .respond_with_actions_from_event(http_answer)
        .expect_at_least(1)
        .build()
}

/// Build a DNS A query for `name` with transaction id `id`.
fn dns_query(name: &str, id: u16) -> Vec<u8> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    let mut message = Message::new();
    message
        .set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);
    message.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    message.to_vec().unwrap()
}

/// Send one query and return (id, first A record's address).
async fn dns(addr: std::net::SocketAddr, name: &str, id: u16) -> (u16, String) {
    use hickory_proto::op::Message;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&dns_query(name, id), addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(30), socket.recv_from(&mut buf))
        .await
        .expect("DNS answer within 30s")
        .unwrap();
    let answer = Message::from_vec(&buf[..n]).expect("a DNS message");
    let ip = answer
        .answers()
        .first()
        .and_then(|r| r.data())
        .map(|d| d.to_string())
        .unwrap_or_default();
    (answer.id(), ip)
}

fn dns_mock() -> helpers::mock_config::MockLlmConfig {
    MockLlmBuilder::new()
        .on_event("dns_query")
        .respond_with_actions_from_event(|event| {
            let domain = event["domain"].as_str().unwrap_or("");
            let ip = if domain.starts_with("a.") {
                "192.0.2.1"
            } else {
                "192.0.2.2"
            };
            json!([{
                "type": "send_dns_a_response",
                "query_id": event["query_id"],
                "domain": event["domain"],
                "ip": ip,
                "ttl": 60,
            }])
        })
        .expect_at_least(1)
        .build()
}

async fn answered_by(state: &AppState, id: ServerId) -> Vec<String> {
    let mut entries = state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await;
    entries.reverse();
    entries
        .into_iter()
        .map(|e| e.answered_by.unwrap_or_else(|| "?".to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// Record -> rules
// ---------------------------------------------------------------------------

/// Record HTTP traffic with the model, export rules, apply them, and replay the same traffic
/// with zero model calls. A request nothing recorded still reaches the model afterwards,
/// which is the fallback working and the control that makes the zero mean something.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_traffic_recorded_with_the_model_replays_from_exported_rules() {
    let mock = MockOllamaServer::start(http_mock()).await.unwrap();
    let state = state_for(&mock).await;
    let (id, addr) = start(
        &state,
        ServerForm {
            protocol: "http".into(),
            port: Some(0),
            instruction: Some("Serve a tiny users API.".into()),
            ..Default::default()
        },
    )
    .await;

    // === Record: every request reaches the model. ===
    let traffic = [
        ("GET", "/hello", ""),
        ("GET", "/users", ""),
        ("POST", "/users", "{\"name\":\"ada\"}"),
        ("GET", "/hello", ""),
    ];
    let mut recorded = Vec::new();
    for (method, path, body) in traffic {
        recorded.push(http(addr, method, path, body).await);
    }
    assert_eq!(recorded[0], (200, "hello world".to_string()));
    assert_eq!(recorded[2], (201, "created".to_string()));
    let recording_calls = mock.call_count().await;
    assert_eq!(
        recording_calls, 4,
        "CONTROL: each recorded request must reach the model once"
    );
    assert_eq!(answered_by(&state, id).await, vec!["model"; 4]);

    // === Export. ===
    let export =
        rule_export::export_rules(&state, AccessLogOwner::Server(id.as_u32()), Fallback::Llm)
            .await
            .expect("export");
    println!("{}", rule_export::describe_export(&export));
    assert_eq!(export.derived.recorded_answers, 4);
    assert_eq!(
        export.derived.rules.len(),
        3,
        "one rule per distinct request: {:#?}",
        export.derived.rules
    );
    assert!(
        export.derived.undetermined.is_empty(),
        "{:#?}",
        export.derived.undetermined
    );
    for rule in &export.derived.rules {
        let conditions = rule["match"]
            .as_object()
            .expect("every rule has conditions");
        assert!(
            conditions.contains_key("method") && conditions.contains_key("path"),
            "the rules must be keyed on method and path: {rule:#}"
        );
    }

    // === Apply, then replay the same traffic: no model at all. ===
    rule_export::apply_export(
        &state,
        AccessLogOwner::Server(id.as_u32()),
        &export,
        netget::llm::OllamaClient::new(mock.base_url()),
    )
    .await
    .expect("apply");
    for ((method, path, body), expected) in traffic.iter().zip(&recorded) {
        assert_eq!(
            &http(addr, method, path, body).await,
            expected,
            "{method} {path} must be answered as the model answered it"
        );
    }
    assert_eq!(
        mock.call_count().await,
        recording_calls,
        "replaying recorded traffic must make ZERO model calls"
    );
    let log = answered_by(&state, id).await;
    assert_eq!(
        &log[4..],
        &["rule"; 4],
        "the replay is answered by the rules"
    );

    // === The fallback: an unrecorded request still goes to the model. ===
    assert_eq!(
        http(addr, "GET", "/other", "").await,
        (404, "no /other".to_string())
    );
    assert_eq!(mock.call_count().await, recording_calls + 1);

    mock.wait_for_expectations(10).await;
    mock.verify_calls().await.unwrap();
    let _ = state.remove_server(id).await;
}

/// DNS: the per-request `query_id` must be echoed through `{{event.query_id}}`, never baked
/// in, so a replay with a new id is answered with that id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_rules_echo_the_new_query_id() {
    let mock = MockOllamaServer::start(dns_mock()).await.unwrap();
    let state = state_for(&mock).await;
    let (id, addr) = start(
        &state,
        ServerForm {
            protocol: "dns".into(),
            port: Some(0),
            instruction: Some("Resolve the test zone.".into()),
            ..Default::default()
        },
    )
    .await;

    assert_eq!(
        dns(addr, "a.example.com.", 0x1111).await,
        (0x1111, "192.0.2.1".into())
    );
    assert_eq!(
        dns(addr, "b.example.com.", 0x2222).await,
        (0x2222, "192.0.2.2".into())
    );
    assert_eq!(
        dns(addr, "a.example.com.", 0x3333).await,
        (0x3333, "192.0.2.1".into())
    );
    let recording_calls = mock.call_count().await;
    assert_eq!(
        recording_calls, 3,
        "CONTROL: every recorded query reaches the model"
    );

    let export =
        rule_export::export_rules(&state, AccessLogOwner::Server(id.as_u32()), Fallback::Llm)
            .await
            .expect("export");
    println!("{}", rule_export::describe_export(&export));
    assert_eq!(export.derived.rules.len(), 2, "{:#?}", export.derived);
    for rule in &export.derived.rules {
        let action = &rule["handler"]["actions"][0];
        assert_eq!(
            action["query_id"], "{{event.query_id}}",
            "the query id must be a reference, not a recorded constant: {rule:#}"
        );
        assert!(
            rule["match"].get("domain").is_some(),
            "keyed on the name: {rule:#}"
        );
        assert!(
            rule["match"].get("query_id").is_none() && rule["match"].get("client_port").is_none(),
            "per-request fields are never conditions: {rule:#}"
        );
    }

    rule_export::apply_export(
        &state,
        AccessLogOwner::Server(id.as_u32()),
        &export,
        netget::llm::OllamaClient::new(mock.base_url()),
    )
    .await
    .expect("apply");
    assert_eq!(
        dns(addr, "a.example.com.", 0x4444).await,
        (0x4444, "192.0.2.1".into())
    );
    assert_eq!(
        dns(addr, "b.example.com.", 0x5555).await,
        (0x5555, "192.0.2.2".into())
    );
    assert_eq!(
        mock.call_count().await,
        recording_calls,
        "the replay must make ZERO model calls"
    );

    mock.wait_for_expectations(10).await;
    mock.verify_calls().await.unwrap();
    let _ = state.remove_server(id).await;
}

/// The `.netget` file the export writes starts a server that answers the recorded traffic
/// with no model: the same `open_server` path `--load` executes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_exported_netget_file_replays_without_the_model() {
    let mock = MockOllamaServer::start(http_mock()).await.unwrap();
    let state = state_for(&mock).await;
    let (id, addr) = start(
        &state,
        ServerForm {
            protocol: "http".into(),
            port: Some(0),
            instruction: Some("Serve a tiny users API.".into()),
            ..Default::default()
        },
    )
    .await;
    let hello = http(addr, "GET", "/hello", "").await;
    let users = http(addr, "GET", "/users", "").await;
    assert_eq!(
        mock.call_count().await,
        2,
        "CONTROL: recording reaches the model"
    );

    let export =
        rule_export::export_rules(&state, AccessLogOwner::Server(id.as_u32()), Fallback::Llm)
            .await
            .expect("export");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recorded.netget");
    let written = netget::utils::save_load::save_with_handlers(
        &state,
        AccessLogOwner::Server(id.as_u32()),
        &export.event_handlers,
        path.to_str().unwrap(),
    )
    .await
    .expect("save");
    let _ = state.remove_server(id).await;

    // What `--load` does with the file: read the actions, run each `open_server`.
    let actions = netget::utils::save_load::load_actions(written.to_str().unwrap())
        .await
        .expect("load");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0]["event_handlers"], json!(export.event_handlers));
    let netget::llm::actions::common::CommonAction::OpenServer {
        protocol,
        instruction,
        event_handlers,
        ..
    } = netget::llm::actions::common::CommonAction::from_json(&actions[0]).expect("open_server")
    else {
        panic!("the saved action must be open_server");
    };
    let (replayed, addr) = start(
        &state,
        ServerForm {
            protocol,
            port: Some(0),
            instruction: Some(instruction),
            event_handlers,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(http(addr, "GET", "/hello", "").await, hello);
    assert_eq!(http(addr, "GET", "/users", "").await, users);
    assert_eq!(
        mock.call_count().await,
        2,
        "the loaded server must make ZERO model calls"
    );
    let _ = state.remove_server(replayed).await;
}

/// The same loop through the MCP surface an agent drives: `start_server` with memoisation,
/// traffic, `export_rules` with `apply` and `save_to`, and a replay with no model calls.
#[cfg(feature = "mcp-stdio")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn export_rules_over_mcp_applies_and_saves() {
    use clap::Parser;
    use rmcp::model::CallToolRequestParams;
    use rmcp::{serve_client, ServiceExt};

    let mock = MockOllamaServer::start(http_mock()).await.unwrap();
    let args = netget::cli::Args::parse_from(["netget", "--ollama-url", &mock.base_url()]);
    let service = netget::mcp_stdio::tools::NetGetMcpService::new(
        &args,
        netget::settings::Settings::default(),
    )
    .await
    .expect("service");
    let state = service.app_state();
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(server) = service.serve(server_io).await {
            let _ = server.waiting().await;
        }
    });
    let client = serve_client((), client_io).await.expect("handshake");
    let call = |name: &'static str, args: Value| {
        let mut params = CallToolRequestParams::new(name);
        params.arguments = args.as_object().cloned();
        let client = &client;
        async move {
            let result = client.call_tool(params).await.expect("call tool");
            let text: String = result
                .content
                .iter()
                .filter_map(|c| c.as_text().map(|t| t.text.clone()))
                .collect();
            (result.is_error == Some(true), text)
        }
    };

    let (failed, text) = call(
        "start_server",
        json!({"protocol": "http", "port": 0, "instruction": "Serve a tiny users API.",
               "memoize_ttl_secs": 60}),
    )
    .await;
    assert!(!failed, "{text}");
    let id: u32 = text
        .split("Server #")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no server id in {text}"));
    let id = ServerId::new(id);
    let mut addr = None;
    for _ in 0..300 {
        addr = state.get_server(id).await.and_then(|s| s.local_addr);
        if addr.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let addr = addr.expect("bound");

    let hello = http(addr, "GET", "/hello", "").await;
    let users = http(addr, "GET", "/users", "").await;
    assert_eq!(http(addr, "GET", "/hello", "").await, hello);
    assert_eq!(
        mock.call_count().await,
        2,
        "CONTROL, and the repeat came from the memo"
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcp.netget");
    let (failed, text) = call(
        "export_rules",
        json!({"server_id": id.as_u32(), "apply": true, "fallback": "llm",
               "save_to": path.to_str().unwrap()}),
    )
    .await;
    assert!(!failed, "{text}");
    assert!(text.contains("2 rule(s) derived"), "{text}");
    assert!(text.contains("Applied:"), "{text}");
    assert!(path.exists(), "save_to must write the file: {text}");

    // The memoised replay of /hello is model-authored too and agrees with the model's answer.
    assert_eq!(http(addr, "GET", "/hello", "").await, hello);
    assert_eq!(http(addr, "GET", "/users", "").await, users);
    assert_eq!(
        mock.call_count().await,
        2,
        "after export_rules: ZERO model calls"
    );

    let (failed, text) = call("export_rules", json!({"server_id": 1, "client_id": 1})).await;
    assert!(failed, "both ids must be refused: {text}");
    let _ = state.remove_server(id).await;
}

/// Answers that cannot be made deterministic are reported, not turned into wrong rules.
#[test]
fn undeterminable_answers_are_reported_rather_than_guessed() {
    use netget::state::app_state::AccessLogEntry;
    let entry = |id: u64, request: Value, response: Value, by: &str| AccessLogEntry {
        id,
        unix_ms: 0,
        server_id: Some(1),
        client_id: None,
        protocol: "HTTP".into(),
        connection_id: Some(1),
        event_type: "http_request".into(),
        request,
        response: response.as_array().unwrap().clone(),
        answered_by: Some(by.into()),
    };
    let get = |path: &str| json!({"method": "GET", "path": path, "body": ""});
    let reply = |body: &str| json!([{"type": "send_http_response", "status": 200, "body": body}]);
    let entries = vec![
        // The same request answered two different ways: no field explains it.
        entry(1, get("/time"), reply("10:00"), "model"),
        entry(2, get("/time"), reply("10:01"), "model"),
        // A consistent one beside it still becomes a rule.
        entry(3, get("/ok"), reply("ok"), "model"),
        // An answer that also wrote memory would be replayed only in part.
        entry(
            4,
            get("/count"),
            json!([{"type": "append_memory", "content": "seen"}, {"type": "send_http_response", "status": 200}]),
            "model",
        ),
        // Answered by a rule, not the model: not read at all.
        entry(5, get("/rule"), reply("from a rule"), "rule"),
    ];
    let derived = rule_export::derive_rules(&entries);
    assert_eq!(derived.recorded_answers, 4);
    assert_eq!(derived.rules.len(), 1, "{:#?}", derived.rules);
    assert_eq!(derived.rules[0]["match"]["path"], "/ok");
    assert_eq!(derived.undetermined.len(), 1, "{:#?}", derived.undetermined);
    assert_eq!(derived.undetermined[0].conditions["path"], "/time");
    assert_eq!(derived.undetermined[0].distinct_answers, 2);
    assert_eq!(derived.skipped.len(), 1, "{:#?}", derived.skipped);
    assert!(derived.skipped[0].reason.contains("did more than reply"));
}

/// `match` is validated where every other part of a handler is: at configuration time.
#[test]
fn a_malformed_match_is_rejected_at_parse_time() {
    use netget::events::handler::EventHandler;
    let rule = |m: Value| {
        vec![json!({"event_pattern": "http_request", "match": m,
            "handler": {"type": "static", "actions": []}})]
    };
    assert!(EventHandler::parse_event_handlers(rule(json!({"method": "GET"}))).is_ok());
    for bad in [
        json!("GET"),
        json!({"": 1}),
        json!({"a..b": 1}),
        json!({"event.method": "GET"}),
    ] {
        let err = EventHandler::parse_event_handlers(rule(bad.clone()))
            .expect_err(&format!("{bad} must be rejected"));
        assert!(err.to_string().contains("match"), "{err}");
    }
    // An unread key is refused rather than ignored: ignored, a rule meant for some events
    // would answer all of them.
    let misspelt = vec![
        json!({"event_pattern": "http_request", "matches": {"method": "GET"},
        "handler": {"type": "static", "actions": []}}),
    ];
    let err = EventHandler::parse_event_handlers(misspelt).expect_err("an unknown key");
    assert!(err.to_string().contains("matches"), "{err}");
    // A rule with a condition answers only the events it names.
    let config =
        EventHandler::parse_event_handlers(rule(json!({"method": "GET", "headers.host": "h"})))
            .unwrap();
    let get = json!({"method": "GET", "headers": {"host": "h"}});
    let post = json!({"method": "POST", "headers": {"host": "h"}});
    assert!(config
        .find_handler_for("http_request", Some(&get))
        .is_some());
    assert!(config
        .find_handler_for("http_request", Some(&post))
        .is_none());
    // A missing field reads as null.
    let null_rule =
        EventHandler::parse_event_handlers(rule(json!({"query_string": null}))).unwrap();
    assert!(null_rule
        .find_handler_for("http_request", Some(&get))
        .is_some());
}

// ---------------------------------------------------------------------------
// Memoisation
// ---------------------------------------------------------------------------

/// With memoisation on, a repeated request is answered from the cache (recorded as such), a
/// failed answer is never memoised, and an answer expires with its TTL.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_memoisation_replays_within_the_ttl_and_never_caches_failures() {
    let mock = MockOllamaServer::start(http_mock()).await.unwrap();
    let state = state_for(&mock).await;
    let (id, addr) = start(
        &state,
        ServerForm {
            protocol: "http".into(),
            port: Some(0),
            instruction: Some("Serve a tiny users API.".into()),
            memoize_ttl_secs: Some(60),
            ..Default::default()
        },
    )
    .await;

    let first = http(addr, "GET", "/hello", "").await;
    assert_eq!(
        mock.call_count().await,
        1,
        "CONTROL: the first request reaches the model"
    );
    assert_eq!(http(addr, "GET", "/hello", "").await, first);
    assert_eq!(http(addr, "GET", "/users", "").await.0, 200);
    assert_eq!(http(addr, "GET", "/hello", "").await, first);
    assert_eq!(
        mock.call_count().await,
        2,
        "/hello twice more and /users once: only /users may reach the model"
    );
    assert_eq!(
        answered_by(&state, id).await,
        ["model", "cache", "model", "cache"]
    );

    // A failed answer is not memoised: the same request asks the model again.
    let _ = http(addr, "GET", "/broken", "").await;
    let _ = http(addr, "GET", "/broken", "").await;
    assert_eq!(
        mock.call_count().await,
        4,
        "a failure must never be replayed"
    );

    // A one-second TTL: a fresh cache, and an answer that expires.
    let (tx, _rx) = mpsc::unbounded_channel();
    netget::cli::management::update_server(
        &state,
        id,
        ServerForm {
            memoize_ttl_secs: Some(1),
            ..Default::default()
        },
        tx,
    )
    .await
    .unwrap();
    let _ = http(addr, "GET", "/hello", "").await; // a new setting starts an empty cache
    let _ = http(addr, "GET", "/hello", "").await; // within the 1s TTL: cached
    assert_eq!(mock.call_count().await, 5);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let _ = http(addr, "GET", "/hello", "").await; // expired
    assert_eq!(
        mock.call_count().await,
        6,
        "an answer must expire with its TTL"
    );

    mock.wait_for_expectations(10).await;
    mock.verify_calls().await.unwrap();
    let _ = state.remove_server(id).await;
}

/// A memoised DNS answer is re-rendered for each query: the new query id goes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_memoisation_echoes_each_querys_own_id() {
    let mock = MockOllamaServer::start(dns_mock()).await.unwrap();
    let state = state_for(&mock).await;
    let (id, addr) = start(
        &state,
        ServerForm {
            protocol: "dns".into(),
            port: Some(0),
            instruction: Some("Resolve the test zone.".into()),
            memoize_ttl_secs: Some(60),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        dns(addr, "a.example.com.", 0x0101).await,
        (0x0101, "192.0.2.1".into())
    );
    assert_eq!(
        mock.call_count().await,
        1,
        "CONTROL: the first query reaches the model"
    );
    // A different id (and a different source port): the same question, answered from the memo.
    assert_eq!(
        dns(addr, "a.example.com.", 0x0202).await,
        (0x0202, "192.0.2.1".into())
    );
    assert_eq!(
        dns(addr, "a.example.com.", 0x7e57).await,
        (0x7e57, "192.0.2.1".into())
    );
    assert_eq!(
        mock.call_count().await,
        1,
        "repeats must make ZERO model calls"
    );
    // A different question is not the same event.
    assert_eq!(
        dns(addr, "b.example.com.", 0x0303).await,
        (0x0303, "192.0.2.2".into())
    );
    assert_eq!(mock.call_count().await, 2);
    assert_eq!(
        answered_by(&state, id).await,
        ["model", "cache", "cache", "model"]
    );
    let _ = state.remove_server(id).await;
}

/// Where the model is shown a connection's history, a memoised answer stays on its own
/// connection unless the operator opts in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memoised_answers_stay_on_their_connection_when_history_is_on() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("tcp_data_received")
            .respond_with_actions(json!([{"type": "send_tcp_data", "data": "pong"}]))
            .expect_at_least(1)
            .build(),
    )
    .await
    .unwrap();
    let state = state_for(&mock).await;

    async fn ping(stream: &mut tokio::net::TcpStream) {
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut buf))
            .await
            .expect("reply within 30s")
            .unwrap();
        assert_eq!(&buf[..n], b"pong");
    }

    for (across, calls_for_second_connection) in [(false, 1), (true, 0)] {
        let before = mock.call_count().await;
        let (id, addr) = start(
            &state,
            ServerForm {
                protocol: "tcp".into(),
                port: Some(0),
                instruction: Some("Answer ping with pong.".into()),
                memoize_ttl_secs: Some(60),
                memoize_across_connections: Some(across),
                ..Default::default()
            },
        )
        .await;
        assert!(
            state.server_conversation_settings(id).await.unwrap().0 > 0,
            "tcp shows the model history by default; the test depends on it"
        );
        let mut a = tokio::net::TcpStream::connect(addr).await.unwrap();
        ping(&mut a).await;
        ping(&mut a).await;
        assert_eq!(
            mock.call_count().await - before,
            1,
            "CONTROL and claim: the first ping reaches the model, the repeat on the same \
             connection is memoised"
        );
        let mut b = tokio::net::TcpStream::connect(addr).await.unwrap();
        ping(&mut b).await;
        assert_eq!(
            mock.call_count().await - before,
            1 + calls_for_second_connection,
            "across_connections={across}: another connection {} the memo",
            if across { "shares" } else { "must not share" }
        );
        drop((a, b));
        let _ = state.remove_server(id).await;
    }
}

/// A client memoises too: the server says the same thing twice, the model is asked once, and
/// the client's answer still goes out both times.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_memoises_its_answers() {
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("tcp_data_received")
            .respond_with_actions(json!([{"type": "send_tcp_data", "data": "pong"}]))
            .expect_at_least(1)
            .and()
            .on_any()
            .respond_with_actions(json!([]))
            .expect_at_least(0)
            .build(),
    )
    .await
    .unwrap();
    let state = state_for(&mock).await;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = netget::cli::management::ClientForm {
        protocol: "tcp".into(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("Answer ping with pong.".into()),
        memoize_ttl_secs: Some(60),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new(mock.base_url()), tx)
    .await
    .expect("client");
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client connects")
        .unwrap();
    let data_calls = || async {
        mock.recorded_calls()
            .await
            .iter()
            .filter(|c| c.context.event_type.as_deref() == Some("tcp_data_received"))
            .count()
    };
    for round in 0..2 {
        socket.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(30), socket.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("round {round}: the client must answer"))
            .unwrap();
        assert_eq!(&buf[..n], b"pong", "round {round}");
    }
    assert_eq!(
        data_calls().await,
        1,
        "CONTROL and claim: the first ping reaches the model, the second is memoised"
    );
    let mut entries = state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await;
    entries.reverse();
    let by: Vec<_> = entries
        .iter()
        .filter(|e| e.event_type == "tcp_data_received")
        .map(|e| e.answered_by.clone().unwrap_or_default())
        .collect();
    assert_eq!(by, ["model", "cache"]);
    let _ = state.remove_client(id).await;
}

/// The settings are validated: an over-long TTL and the cross-connection flag without
/// memoisation are refused, before anything starts.
#[test]
fn memo_settings_are_validated() {
    use netget::llm::answer_reuse::{resolve_memo_settings, MemoSettings, MAX_MEMO_TTL_SECS};
    assert!(resolve_memo_settings(Some(MAX_MEMO_TTL_SECS + 1), None, None).is_err());
    assert!(resolve_memo_settings(None, Some(true), None).is_err());
    assert_eq!(resolve_memo_settings(None, None, None).unwrap(), None);
    assert_eq!(
        resolve_memo_settings(Some(0), None, None).unwrap(),
        Some(None)
    );
    let on = MemoSettings {
        ttl_secs: 30,
        across_connections: false,
    };
    assert_eq!(
        resolve_memo_settings(None, Some(true), Some(on)).unwrap(),
        Some(Some(MemoSettings {
            across_connections: true,
            ..on
        }))
    );
}

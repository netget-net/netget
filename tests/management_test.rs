//! Tests for the create/update management surface (`netget::cli::management`).
//!
//! These assert behaviour at the protocol level (an updated HTTP server actually
//! serves the new response) and the error/isolation guarantees (unknown id errors
//! cleanly; a bad startup param is rejected and leaves the running server working).
//!
//! No LLM is involved: every server uses a *static* event handler, so requests are
//! answered deterministically in-process. Everything binds to 127.0.0.1 only.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use netget::cli::management::{self, ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::{ClientId, ServerId};
use tokio::sync::mpsc;

/// A static HTTP handler that answers every request with `200 <body>`.
fn static_http_handler(body: &str) -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "event_pattern": "http_request",
        "handler": {
            "type": "static",
            "actions": [
                { "type": "send_http_response", "status": 200, "body": body }
            ]
        }
    })]
}

/// Fresh AppState with an LLM client pointed at an unreachable URL — the static
/// handlers never call it, and if any code path did, it would fail loudly rather
/// than reach the network.
async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_types_tls_material_and_task_delays_preserve_running_server() {
    let state = new_state().await;
    let (id, port) = create_http_server(&state, "STILL-RUNNING").await;
    for params in [
        serde_json::json!({"tls_enabled": "true"}),
        serde_json::json!({"tls_enabled": true, "san_dns_names": ["localhost", 1]}),
        serde_json::json!({"tls_enabled": true, "validity_days": 0}),
        serde_json::json!({"tls_enabled": true, "cert_path": "/missing/cert"}),
    ] {
        let (tx, _rx) = mpsc::unbounded_channel();
        assert!(management::update_server(
            &state,
            id,
            ServerForm {
                startup_params: Some(params),
                instruction: Some("must not apply".into()),
                ..Default::default()
            },
            tx
        )
        .await
        .is_err());
        assert!(state.get_server(id).await.is_some());
        assert!(http_get(port).contains("STILL-RUNNING"));
    }
    let bad_task = netget::llm::actions::common::ServerTaskDefinition {
        task_id: "invalid-delay".into(),
        recurring: false,
        delay_secs: Some(u64::MAX),
        interval_secs: None,
        max_executions: None,
        instruction: "noop".into(),
        context: None,
    };
    let (tx, _rx) = mpsc::unbounded_channel();
    assert!(management::update_server(
        &state,
        id,
        ServerForm {
            port: Some(0),
            scheduled_tasks: Some(vec![bad_task.clone()]),
            ..Default::default()
        },
        tx
    )
    .await
    .is_err());
    assert!(http_get(port).contains("STILL-RUNNING"));
    let (tx, _rx) = mpsc::unbounded_channel();
    assert!(ServerForm {
        protocol: "http".into(),
        port: Some(0),
        scheduled_tasks: Some(vec![bad_task]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .is_err());
    assert_eq!(state.get_all_servers().await.len(), 1);
    assert!(state.get_all_tasks().await.is_empty());
    state.remove_server(id).await;
}

/// Wait until a server has a concrete bound address, returning its port. Polls
/// `local_addr` (set once the listener is bound) rather than the requested port.
async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
            if s.port != 0 {
                return s.port;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

/// Connect with a few retries to absorb the bind/accept race.
fn connect_retry(port: u16) -> TcpStream {
    for _ in 0..50 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            return s;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    panic!("could not connect to 127.0.0.1:{port}");
}

/// Send a minimal HTTP/1.1 GET and return the raw response text. Reads until the
/// server closes the connection (we send `Connection: close`) or a short timeout.
fn http_get(port: u16) -> String {
    let mut stream = connect_retry(port);
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break, // timeout or reset: return what we have
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

/// Create an HTTP server bound to an OS-assigned port with the given static body.
async fn create_http_server(state: &AppState, body: &str) -> (ServerId, u16) {
    let (tx, _rx) = mpsc::unbounded_channel();
    let form = ServerForm {
        protocol: "http".to_string(),
        port: Some(0),
        event_handlers: Some(static_http_handler(body)),
        ..Default::default()
    };
    let id = form.create(state, tx).await.expect("create http server");
    let port = wait_for_port(state, id).await;
    assert!(port != 0, "server should have a concrete bound port");
    (id, port)
}

/// #1 — Create then update an HTTP server's handler in place and observe the NEW
/// response on the wire. This is the core "update is real" assertion, at the
/// protocol level, and proves the hot path preserves the listening socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn update_server_hot_swaps_http_handler() {
    let state = new_state().await;
    let (id, port) = create_http_server(&state, "OLD-BODY").await;

    let before = http_get(port);
    assert!(before.contains("OLD-BODY"), "initial response: {before}");

    // Update only the event handlers — a hot change, no rebind.
    let (tx, _rx) = mpsc::unbounded_channel();
    let update = ServerForm {
        event_handlers: Some(static_http_handler("NEW-BODY")),
        ..Default::default()
    };
    let outcome = management::update_server(&state, id, update, tx)
        .await
        .expect("update should succeed");
    assert!(
        !outcome.restarted,
        "handler swap must NOT restart the server"
    );
    assert_eq!(outcome.id, id.as_u32(), "hot update keeps the same id");

    let after = http_get(port);
    assert!(
        after.contains("NEW-BODY") && !after.contains("OLD-BODY"),
        "updated response should be NEW-BODY, got: {after}"
    );
}

/// Changing the port forces a clean stop+start: a NEW id, and the server serving
/// on the new port with its handlers preserved across the restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn update_server_port_triggers_restart_and_preserves_handler() {
    let state = new_state().await;
    let (id, old_port) = create_http_server(&state, "KEEP-ME").await;
    assert!(http_get(old_port).contains("KEEP-ME"));

    let (tx, _rx) = mpsc::unbounded_channel();
    let update = ServerForm {
        port: Some(0), // rebind to a new OS-assigned port
        ..Default::default()
    };
    let outcome = management::update_server(&state, id, update, tx)
        .await
        .expect("restart update should succeed");
    assert!(outcome.restarted, "port change must restart");
    assert_ne!(outcome.id, id.as_u32(), "restart allocates a new id");

    let new_port = wait_for_port(&state, ServerId::new(outcome.id)).await;
    assert_ne!(new_port, old_port, "should rebind to a different port");

    // Handler survived the restart (it was re-applied from the old config).
    assert!(
        http_get(new_port).contains("KEEP-ME"),
        "handler must be preserved across a restart"
    );
    // Old server is gone.
    assert!(state.get_server(id).await.is_none(), "old id is removed");
}

/// #2 — Updating a server that does not exist errors cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn update_nonexistent_server_errors() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let update = ServerForm {
        instruction: Some("whatever".to_string()),
        ..Default::default()
    };
    let err = management::update_server(&state, ServerId::new(987654), update, tx)
        .await
        .expect_err("must error");
    let msg = err.to_string();
    assert!(msg.contains("not found"), "clear error, got: {msg}");
}

/// #3 — An update with an undeclared startup param is rejected, names the key,
/// and leaves the ORIGINAL server running and serving its original response.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn update_bad_param_rejected_and_old_server_survives() {
    let state = new_state().await;
    let (id, port) = create_http_server(&state, "SURVIVOR").await;
    assert!(http_get(port).contains("SURVIVOR"));

    let (tx, _rx) = mpsc::unbounded_channel();
    let update = ServerForm {
        startup_params: Some(serde_json::json!({ "totally_bogus_key_xyz": true })),
        ..Default::default()
    };
    let err = management::update_server(&state, id, update, tx)
        .await
        .expect_err("bad param must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("totally_bogus_key_xyz"),
        "error should name the offending key, got: {msg}"
    );

    // The server was never touched: same id, still serving.
    assert!(
        state.get_server(id).await.is_some(),
        "old server still registered"
    );
    assert!(
        http_get(port).contains("SURVIVOR"),
        "old server must still serve its original response"
    );
}

/// An invalid update container is rejected before any restart or hot mutation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_object_startup_update_keeps_the_existing_server() {
    let state = new_state().await;
    let (id, port) = create_http_server(&state, "UNCHANGED").await;
    for invalid in [
        serde_json::json!([]),
        serde_json::json!(true),
        serde_json::json!("bad"),
        serde_json::Value::Null,
    ] {
        let (tx, _rx) = mpsc::unbounded_channel();
        let error = management::update_server(
            &state,
            id,
            ServerForm {
                startup_params: Some(invalid),
                instruction: Some("must not be applied".into()),
                ..Default::default()
            },
            tx,
        )
        .await
        .expect_err("non-object update must be rejected before restart");
        assert!(error.to_string().contains("JSON object"), "{error}");
        assert!(state.get_server(id).await.is_some());
        assert!(http_get(port).contains("UNCHANGED"));
    }
    state
        .remove_server(id)
        .await
        .expect("remove original server");
}

/// Updating a client that does not exist errors cleanly (client mirror of #2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn update_nonexistent_client_errors() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let llm = netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string());
    let update = ClientForm {
        instruction: Some("whatever".to_string()),
        ..Default::default()
    };
    let err = management::update_client(&state, ClientId::new(987654), update, llm, tx)
        .await
        .expect_err("must error");
    assert!(err.to_string().contains("not found"), "clear error");
}

/// A hot instruction update on an existing client mutates its stored instruction
/// without a reconnect. Uses a directly-inserted client instance so the test is
/// deterministic and touches no network.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn update_client_hot_changes_instruction() {
    use netget::state::client::{ClientInstance, ClientStatus};

    let state = new_state().await;

    let client = ClientInstance {
        id: ClientId::new(0),
        remote_addr: "127.0.0.1:9".to_string(),
        protocol_name: "HTTP".to_string(),
        instruction: "original".to_string(),
        memory: String::new(),
        status: ClientStatus::Connected,
        connection: None,
        created_at: std::time::Instant::now(),
        status_changed_at: std::time::Instant::now(),
        startup_params: None,
        event_handler_config: None,
        protocol_data: serde_json::Value::Null,
        log_files: Default::default(),
        feedback_instructions: None,
        feedback_buffer: Vec::new(),
        last_feedback_processed: None,
        connection_history: Default::default(),
        history_entries: 0,
        batching: false,
        exchange_history: Default::default(),
    };
    let id = state.add_client(client).await;

    let (tx, _rx) = mpsc::unbounded_channel();
    let llm = netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string());
    let update = ClientForm {
        instruction: Some("updated-instruction".to_string()),
        ..Default::default()
    };
    let outcome = management::update_client(&state, id, update, llm, tx)
        .await
        .expect("hot client update should succeed");
    assert!(!outcome.restarted, "instruction change must not reconnect");
    assert_eq!(outcome.id, id.as_u32());

    let stored = state.get_client(id).await.expect("client exists");
    assert_eq!(stored.instruction, "updated-instruction");
}

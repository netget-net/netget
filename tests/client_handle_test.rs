//! E2E for the client command channel (`AppState::send_to_client`): a NetGet
//! client connected to a NetGet server of the same protocol, with an action
//! injected from outside the client's loop — the dashboard's [send] path.
//!
//! Zero LLM involvement: the server answers via static handlers and the
//! client's LLM points at an unreachable URL (errors are tolerated by the
//! loops; nothing here depends on a model).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp,telnet --test client_handle_test -- --test-threads=100


use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ServerId};
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

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

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..100 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("client #{} never registered a command handle", id.as_u32());
}

/// Poll the owner-scoped access log until an entry's serialized form contains
/// `needle`, or panic after ~3s.
async fn wait_for_log_containing(
    state: &AppState,
    owner: AccessLogOwner,
    needle: &str,
) -> netget::state::app_state::AccessLogEntry {
    for _ in 0..100 {
        for entry in state.list_access_logs_for(Some(owner), None).await {
            let text = serde_json::to_string(&entry).unwrap_or_default();
            if text.contains(needle) {
                return entry;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

#[tokio::test]
async fn injected_tcp_action_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // TCP server that statically answers every data event with "pong".
    let server_form = ServerForm {
        protocol: "tcp".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "tcp_data_received",
            "handler": {
                "type": "static",
                "actions": [ { "type": "send_tcp_data", "data": "pong" } ]
            }
        })]),
        ..Default::default()
    };
    let server_id = server_form
        .create(&state, tx.clone())
        .await
        .expect("create tcp server");
    let port = wait_for_port(&state, server_id).await;

    // TCP client (dual protocol!) connected to our own server.
    let client_form = ClientForm {
        protocol: "tcp".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    };
    let client_id = client_form
        .create(
            &state,
            netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
            tx.clone(),
        )
        .await
        .expect("create tcp client");

    wait_for_client_handle(&state, client_id).await;

    // Inject a send through the running client — the dashboard's [send] path.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_tcp_data", "data": "ping-from-ui"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    match outcome {
        ClientSendOutcome::Sent { bytes_sent } => assert_eq!(bytes_sent, "ping-from-ui".len()),
        other => panic!("expected Sent, got {other:?}"),
    }

    // The server saw the bytes: its static handler ran and the access log
    // recorded the event (printable payloads appear as text on the tcp
    // server side; only non-printable data is hex-encoded).
    let server_entry = wait_for_log_containing(
        &state,
        AccessLogOwner::Server(server_id.as_u32()),
        "ping-from-ui",
    )
    .await;
    assert_eq!(server_entry.server_id, Some(server_id.as_u32()));

    // The injection itself is in the client's request log.
    let client_entry = wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
    assert_eq!(client_entry.client_id, Some(client_id.as_u32()));
    assert_eq!(client_entry.event_type, "injected_action");

    // A malformed action is rejected by the protocol, not swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "no_such_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (bad action)");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // Disconnect via injected action: loop breaks, handle is dropped, and a
    // later send fails fast with a clear error instead of hanging.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client (disconnect)");
    assert!(matches!(outcome, ClientSendOutcome::Disconnected));

    for _ in 0..100 {
        if !state.has_client_handle(client_id).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let err = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_tcp_data", "data": "late"}),
            Duration::from_secs(1),
        )
        .await
        .expect_err("send after disconnect must error");
    assert!(
        err.to_string()
            .contains("does not accept injected commands")
            || err.to_string().contains("not running"),
        "unexpected error: {err}"
    );
}

/// A client id that never existed (or a protocol that has not adopted the
/// channel) fails cleanly and immediately.
#[tokio::test]
async fn send_to_unknown_client_errors_cleanly() {
    let state = new_state().await;
    let err = state
        .send_to_client(
            ClientId::new(4242),
            serde_json::json!({"type": "send_tcp_data", "data": "x"}),
            Duration::from_secs(1),
        )
        .await
        .expect_err("must error");
    assert!(err
        .to_string()
        .contains("does not accept injected commands"));
}

/// Every client that registers a command handle must actually accept an
/// injected action. This walks the adopters generically: connect each to a TCP
/// server (they are all stream clients, so a plain socket is enough to
/// establish the connection), and assert the handle appears.
///
/// The point is to catch a client that was wired mechanically and compiles but
/// never registers — the failure mode of adopting by pattern.
#[tokio::test]
async fn every_wired_client_registers_a_command_handle() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // A quiet TCP server any stream client can connect to.
    let server_form = ServerForm {
        protocol: "tcp".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [] }
        })]),
        ..Default::default()
    };
    let server_id = server_form
        .create(&state, tx.clone())
        .await
        .expect("create tcp server");
    let port = wait_for_port(&state, server_id).await;
    let remote = format!("127.0.0.1:{port}");

    // Protocols whose loops have adopted the command channel. Keep in step
    // with `register_command_channel` call sites in src/client/.
    let adopters: &[&str] = &[
        "tcp",
        "telnet",
        #[cfg(unix)]
        "SocketFile",
        "SOCKS5",
    ];

    for protocol in adopters {
        // Skip anything not compiled into this build.
        if netget::protocol::CLIENT_REGISTRY.resolve(protocol).is_err() {
            continue;
        }
        let form = ClientForm {
            protocol: protocol.to_string(),
            remote_addr: Some(remote.clone()),
            instruction: Some("handle registration probe".to_string()),
            ..Default::default()
        };
        let Ok(client_id) = form
            .create(
                &state,
                netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
                tx.clone(),
            )
            .await
        else {
            // A protocol that cannot complete its handshake against a plain
            // TCP server is out of scope here; the wiring test is about
            // registration, not about faking every protocol's peer.
            continue;
        };

        let mut registered = false;
        for _ in 0..100 {
            if state.has_client_handle(client_id).await {
                registered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert!(
            registered,
            "{protocol} connected but never registered a command handle — \
             [send] would be dead for it"
        );
        state.remove_client(client_id).await;
    }
}

#[tokio::test]
async fn injected_telnet_command_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Telnet server with a wildcard static handler that answers nothing —
    // enough to exercise dispatch and access logging without a model.
    let server_form = ServerForm {
        protocol: "telnet".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "static", "actions": [] }
        })]),
        ..Default::default()
    };
    let server_id = server_form
        .create(&state, tx.clone())
        .await
        .expect("create telnet server");
    let port = wait_for_port(&state, server_id).await;

    let client_form = ClientForm {
        protocol: "telnet".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    };
    let client_id = client_form
        .create(
            &state,
            netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
            tx.clone(),
        )
        .await
        .expect("create telnet client");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_command", "command": "hello-dashboard"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "expected Sent, got {outcome:?}"
    );

    // The server-side event carries the command text.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Server(server_id.as_u32()),
        "hello-dashboard",
    )
    .await;
}

/// The dashboard flow: the server carries the dashboard's own default routing
/// (its per-connection `telnet_connection_opened` answered with nothing, then
/// `*` → manual) and the client a plain `*` → manual, so the human answers the
/// client's parked `telnet_connected` with a `send_command`, and the server must
/// (a) still list the connection as live and (b) park the resulting
/// `telnet_message_received` for the human.
///
/// The server's routing is the real `default_event_handlers`, not a copy: the
/// connect event is raised for every connection, and a bare `*` → manual would
/// park it — holding the line reader, which starts only once it is answered, so
/// the command would never be read.
#[tokio::test]
async fn manual_telnet_client_answer_reaches_manual_telnet_server() {
    use netget::state::intercepts::InterceptOwner;
    use netget::state::server::ConnectionStatus;

    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let manual = || {
        Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": { "type": "manual" }
        })])
    };

    let dashboard_server_routing = netget::tui::modal::form::default_event_handlers(
        netget::tui::app::Section::Servers,
        "telnet",
    );
    let server_id = ServerForm {
        protocol: "telnet".to_string(),
        port: Some(0),
        event_handlers: dashboard_server_routing.as_array().cloned(),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create telnet server");
    let port = wait_for_port(&state, server_id).await;

    // The client's connect event parks inside `connect()`, so create it in
    // the background exactly as the dashboard does.
    let client_form = ClientForm {
        protocol: "telnet".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("dashboard client".to_string()),
        event_handlers: manual(),
        ..Default::default()
    };
    let state_bg = state.clone();
    let tx_bg = tx.clone();
    let create = tokio::spawn(async move {
        client_form
            .create(
                &state_bg,
                netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
                tx_bg,
            )
            .await
    });

    // Answer the client's parked telnet_connected with a command.
    let client_intercept = wait_for_intercept(&state, |v| {
        matches!(v.owner, InterceptOwner::Client(_)) && v.event_type == "telnet_connected"
    })
    .await;
    state
        .resolve_intercept(
            client_intercept.id,
            vec![serde_json::json!({"type": "send_command", "command": "hello-manual"})],
        )
        .await
        .expect("resolve client intercept");
    let client_id = create.await.unwrap().expect("create telnet client");
    wait_for_client_handle(&state, client_id).await;

    // The server parks the line for the human…
    let server_intercept = wait_for_intercept(&state, |v| {
        v.owner == InterceptOwner::Server(server_id) && v.event_type == "telnet_message_received"
    })
    .await;
    assert!(
        serde_json::to_string(&server_intercept.event_data)
            .unwrap()
            .contains("hello-manual"),
        "server intercept should carry the command: {server_intercept:?}"
    );

    // …and its connection is still live while the question waits — including
    // across the dashboard's idle sweep. That sweep is for connectionless
    // protocols whose per-address entries nothing closes; it used to run over
    // every server, and a telnet peer parked >10s for a human's answer was
    // evicted and shown as `(closed)` while its socket was alive.
    state.cleanup_old_connections(0).await;
    let server = state.get_server(server_id).await.expect("server row");
    let conn = server
        .connections
        .values()
        .next()
        .expect("server should list the client's connection");
    assert_eq!(
        conn.status,
        ConnectionStatus::Active,
        "connection must not read as closed while a manual answer is pending"
    );

    // Answer it; the client must receive the line.
    state
        .resolve_intercept(
            server_intercept.id,
            vec![serde_json::json!({"type": "send_telnet_line", "line": "hi-from-server"})],
        )
        .await
        .expect("resolve server intercept");
    wait_for_intercept(&state, |v| {
        v.owner == InterceptOwner::Client(client_id) && v.event_type == "telnet_data_received"
    })
    .await;
    let server = state.get_server(server_id).await.expect("server row");
    assert!(
        server
            .connections
            .values()
            .all(|c| c.status == ConnectionStatus::Active),
        "connection must still be live after the server answered"
    );
}

async fn wait_for_intercept(
    state: &AppState,
    pred: impl Fn(&netget::state::intercepts::InterceptView) -> bool,
) -> netget::state::intercepts::InterceptView {
    for _ in 0..200 {
        if let Some(v) = state.list_intercepts().await.into_iter().find(|v| pred(v)) {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("no matching intercept appeared");
}

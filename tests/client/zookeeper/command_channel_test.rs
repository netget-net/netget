//! The dashboard's `[ send ]` path on a ZooKeeper client: `AppState::send_to_client` injects
//! an action from outside the connect task and the operation runs on the *live*
//! `zookeeper-async` session — the one `connect_with_llm_actions` established — reaching a
//! NetGet ZooKeeper server of our own.
//!
//! Zero LLM calls: the server answers through static handlers and the client's LLM points at
//! an unreachable URL, so its `zookeeper_connected` call fails and the connect path must
//! tolerate that. Verifying it does is part of the point.
//!
//! The whole exchange is a real ZooKeeper session — handshake, ping, and the four verbs below
//! — over 127.0.0.1. Nothing here is mocked at the protocol level.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features zookeeper --test client -- zookeeper::command_channel --test-threads=100

use std::time::Duration;

use netget::cli::management::{ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus, ServerId};
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
    for _ in 0..1_000 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("ZooKeeper server #{} never bound a port", id.as_u32());
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "ZooKeeper client #{} never registered a command handle",
        id.as_u32()
    );
}

async fn wait_for_log_containing(state: &AppState, owner: AccessLogOwner, needle: &str) {
    for _ in 0..1_000 {
        for entry in state.list_access_logs_for(Some(owner), None).await {
            if serde_json::to_string(&entry)
                .unwrap_or_default()
                .contains(needle)
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

/// A NetGet ZooKeeper server that answers each verb with the shape that verb's reply
/// requires. `{{event.xid}}` is not optional: a ZooKeeper client correlates replies to
/// requests by xid and desynchronises if it is wrong.
/// One script handler, branching on the request's operation.
///
/// It cannot be five static rules. `EventHandler` has exactly two fields --
/// `event_pattern` and `handler` -- so there is no data-based matching for server
/// event handlers, and every rule registered against `zookeeper_request` matches every
/// request. First-match-wins then made the `create` rule answer a `getData`, and the
/// client got a reply with no `Stat` where a `GetDataResponse` was due: `MarshallingError`.
///
/// `resident` is required, not incidental: a resident script defines
/// `handle(event_type, event, message)`, while a non-resident one must read stdin and
/// print its own output. Defining `handle` without `resident` produces no output at all,
/// the handler yields no actions, and the server fails closed -- which the client sees as
/// `SystemError`.
///
/// Each reply echoes the request's own `xid`. A ZooKeeper client correlates replies to
/// requests by that value and desynchronizes for the rest of the connection if it differs.
fn server_handlers() -> Vec<serde_json::Value> {
    let script = r#"
def handle(event_type, event, message):
    op = event.get("operation")
    xid = event.get("xid")
    if op == "create":
        return [{"type": "zookeeper_created", "xid": xid, "zxid": 300,
                 "path": "/dashboard/marker"}]
    if op == "getData":
        return [{"type": "zookeeper_data", "xid": xid, "zxid": 100,
                 "data": "injected-hello", "version": 7}]
    if op in ("getChildren", "getChildren2"):
        return [{"type": "zookeeper_children", "xid": xid, "zxid": 200,
                 "children": ["web", "api"]}]
    if op == "setData":
        return [{"type": "zookeeper_stat", "xid": xid, "zxid": 400, "version": 9}]
    # delete and anything else: header-only reply, which is what real ZooKeeper sends.
    return [{"type": "zookeeper_response", "xid": xid, "zxid": 500, "error_code": 0}]
"#;
    vec![serde_json::json!({
        "event_pattern": "zookeeper_request",
        "handler": { "type": "script", "language": "python", "resident": true, "code": script }
    })]
}

#[tokio::test]
async fn injected_zookeeper_operation_reaches_our_own_server() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "zookeeper".to_string(),
        port: Some(0),
        event_handlers: Some(server_handlers()),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create zookeeper server");
    let port = wait_for_port(&state, server_id).await;

    let client_id = ClientForm {
        protocol: "zookeeper".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create zookeeper client");

    // Regression guard for "register the channel BEFORE the connected-event LLM call":
    // the handle must exist without anything having answered that call. It also proves the
    // client got past `ZooKeeper::connect`, i.e. that a real session was established —
    // before this the client never opened one at all.
    wait_for_client_handle(&state, client_id).await;

    // A read, injected from outside the client's own tasks.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "get_data", "path": "/dashboard/marker"}),
            Duration::from_secs(20),
        )
        .await
        .expect("send_to_client get_data");

    // Deliberately `Executed`, never `Sent`: `zookeeper-async` owns the socket and never
    // reports how many bytes a request serialised to, so a byte count here would be
    // invented. The detail carries what the server actually answered — and the fact that
    // the version is the 7 our handler returned is what proves the round-trip happened.
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("/dashboard/marker")
                    && detail.contains("14 byte(s)")
                    && detail.contains("version 7"),
                "detail should carry the path, size and version our server returned, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // Recorded on the client like LLM-produced traffic, and received by the server.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
    wait_for_log_containing(
        &state,
        AccessLogOwner::Server(server_id.as_u32()),
        "/dashboard/marker",
    )
    .await;

    // A second verb on the same handle proves the session is held rather than re-dialled.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "get_children", "path": "/dashboard"}),
            Duration::from_secs(20),
        )
        .await
        .expect("send_to_client get_children");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("web, api"),
                "detail should carry the child list, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // A write verb: its reply is a bare Stat, and it raises the operation-complete event.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "set_data", "path": "/dashboard/marker", "data": "updated"
            }),
            Duration::from_secs(20),
        )
        .await
        .expect("send_to_client set_data");
    match &outcome {
        ClientSendOutcome::Executed { detail } => {
            assert!(
                detail.contains("version 9"),
                "detail should carry the version our server returned, got {detail:?}"
            );
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // An unknown verb is refused, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "definitely_not_a_zookeeper_action"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // An injected disconnect ends the command loop, closes the session and takes the
    // handle with it.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "client should be Disconnected with no command handle; status={:?} has_handle={}",
        state.get_client(client_id).await.map(|c| c.status),
        state.has_client_handle(client_id).await
    );
}

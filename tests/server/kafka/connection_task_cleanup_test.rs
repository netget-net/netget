//! A Kafka connection that ends reaps its connection-scoped scheduled tasks.
//!
//! `TaskScope::Connection` says in its own doc comment that such a task is "automatically
//! cleaned up when connection closes", and the mechanism that does it is
//! `AppState::close_connection_on_server`, which marks the row `Closed` **and** calls
//! `cleanup_connection_tasks`. Kafka's teardown called `update_connection_status(…, Closed)`
//! instead: the same row, the same status, and none of the reaping. The tasks outlived the
//! socket, and a recurring one kept ticking — each tick an LLM prompt about a peer that had
//! hung up, charged to a `connection_id` nothing answers to any more. That is the defect
//! `remove_server` was restructured to prevent (`tests/mcp_stop_cleanup_test.rs`), one level
//! down: there it was a stopped server's tasks, here it is a closed connection's.
//!
//! **This test fails without the fix.** Put `update_connection_status` back and the task is
//! still in `get_connection_tasks` after the connection is gone.
//!
//! The control half matters as much as the assertion: the task is registered while the
//! connection is live and asserted present, so a test that reaped nothing because it never
//! registered anything cannot pass.
//!
//! Zero LLM calls: the peer connects and closes without sending a request, and the LLM
//! endpoint is a dead port so a stray call would fail loudly. Loopback only.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features kafka --test server -- kafka::connection_task_cleanup --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::server::connection::ConnectionId;
use netget::state::app_state::AppState;
use netget::state::server::ConnectionStatus;
use netget::state::task::{ScheduledTask, TaskId, TaskScope};
use netget::state::ServerId;
use tokio::net::TcpStream;
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
    for _ in 0..200 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Kafka broker #{} never bound a port", id.as_u32());
}

/// The first connection the broker has registered for this server.
async fn wait_for_connection(state: &AppState, id: ServerId) -> ConnectionId {
    for _ in 0..200 {
        if let Some(s) = state.get_server(id).await {
            if let Some(conn) = s.connections.values().next() {
                return conn.id;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Kafka broker #{} never tracked a connection", id.as_u32());
}

async fn wait_for_closed(state: &AppState, id: ServerId, conn: ConnectionId) {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            match s.connections.get(&conn) {
                // Gone entirely is a close too — the idle sweep may have removed the row.
                None => return,
                Some(c) if c.status == ConnectionStatus::Closed => return,
                Some(_) => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Kafka connection {} never reached Closed", conn.as_u32());
}

#[tokio::test]
async fn a_closed_kafka_connection_reaps_its_connection_scoped_tasks() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "kafka".to_string(),
        port: Some(0),
        // An empty instruction is genuinely model-free; `None` is replaced by a default one.
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create kafka broker");
    let port = wait_for_port(&state, server_id).await;

    let peer = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let connection_id = wait_for_connection(&state, server_id).await;

    // A recurring connection-scoped task, which is the shape that keeps costing something
    // after the connection is gone: a one-shot fires once and stops either way.
    let task = ScheduledTask::new_recurring(
        TaskId::new(0),
        "kafka_connection_scoped_probe".to_string(),
        TaskScope::Connection(server_id, connection_id),
        1,
        None,
        "Report the state of this connection.".to_string(),
        None,
    )
    .unwrap();
    state.add_task(task).await;

    // Control: the task really is registered against this connection while it is live. Without
    // this the assertion below would pass on a test that scheduled nothing.
    assert_eq!(
        state
            .get_connection_tasks(server_id, connection_id)
            .await
            .len(),
        1,
        "the connection-scoped task was not registered, so reaping it proves nothing"
    );

    drop(peer);
    wait_for_closed(&state, server_id, connection_id).await;

    // `close_connection_on_server` runs `cleanup_connection_tasks`; `update_connection_status`
    // does not. The row reaching `Closed` above says nothing about which one ran — this does.
    let survivors = state.get_connection_tasks(server_id, connection_id).await;
    assert!(
        survivors.is_empty(),
        "{} connection-scoped task(s) outlived the Kafka connection that owned them: {:?}. \
         Kafka's teardown is marking the row Closed without reaping — it must call \
         `close_connection_on_server`, not `update_connection_status`. A recurring task left \
         here keeps firing, and every tick is an LLM prompt about a peer that has hung up.",
        survivors.len(),
        survivors.iter().map(|t| t.name.clone()).collect::<Vec<_>>()
    );

    let _ = state.remove_server(server_id).await;
}

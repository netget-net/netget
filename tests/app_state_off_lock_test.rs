//! The parts of `AppState` kept outside its main lock must still read as one state.
//!
//! Three things that every handled event touches live behind locks of their own, because
//! `tests/app_state_contention_test.rs` measured them as the writers that serialised a busy
//! server through the main `RwLock`: connection counters (`update_connection_stats`), the
//! access log, and the per-server task registry. Each split has a way to be subtly wrong that no
//! protocol suite would notice — a byte counted twice or not at all, a counter left behind for
//! a connection that never existed, a task registered against a stopped server and left
//! running — and these tests pin each one.

use std::net::SocketAddr;
use std::time::Duration;

use netget::server::connection::ConnectionId;
use netget::state::app_state::{AccessLogOwner, AppState};
use netget::state::server::{
    ConnectionState, ConnectionStatus, ProtocolConnectionInfo, ServerInstance,
};
use netget::state::ServerId;

fn connection(id: u32) -> ConnectionState {
    let now = netget::utils::clock::Instant::now();
    let addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    ConnectionState {
        id: ConnectionId::new(id),
        remote_addr: addr,
        local_addr: addr,
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0,
        last_activity: now,
        status: ConnectionStatus::Active,
        status_changed_at: now,
        protocol_info: ProtocolConnectionInfo::new(serde_json::json!({})),
    }
}

async fn server(state: &AppState) -> ServerId {
    state
        .add_server(ServerInstance::new(
            ServerId::new(0),
            0,
            "tcp".to_string(),
            String::new(),
        ))
        .await
}

async fn counters(state: &AppState, sid: ServerId, cid: ConnectionId) -> (u64, u64, u64, u64) {
    let server = state.get_server(sid).await.expect("server exists");
    let c = &server.connections[&cid];
    (
        c.bytes_received,
        c.bytes_sent,
        c.packets_received,
        c.packets_sent,
    )
}

#[tokio::test]
async fn connection_counters_count_every_byte_once_through_every_reader() {
    let state = AppState::new();
    let sid = server(&state).await;
    let cid = ConnectionId::new(7);
    state.add_connection_to_server(sid, connection(7)).await;

    for _ in 0..2 {
        state
            .update_connection_stats(sid, cid, Some(10), Some(3), Some(1), Some(1))
            .await;
    }
    assert_eq!(counters(&state, sid, cid).await, (20, 6, 2, 2));
    let all = state.get_all_servers().await;
    assert_eq!(all[0].connections[&cid].bytes_received, 20);

    // A write path folds the pending counters in; what it sees must be the same total, and a
    // reader afterwards must not add them a second time.
    let seen = state
        .with_server_mut(sid, |s| s.connections[&cid].bytes_received)
        .await;
    assert_eq!(seen, Some(20));
    assert_eq!(counters(&state, sid, cid).await, (20, 6, 2, 2));

    // Folded and pending together.
    state
        .update_connection_stats(sid, cid, Some(5), None, Some(1), None)
        .await;
    assert_eq!(counters(&state, sid, cid).await, (25, 6, 3, 2));

    // The summary kept for a closed connection carries the final counters.
    state.close_connection_on_server(sid, cid).await;
    state.remove_connection_from_server(sid, cid).await;
    let closed = state.get_recent_connections(sid).await;
    assert_eq!(closed.len(), 1);
    assert_eq!(
        (closed[0].bytes_received, closed[0].bytes_sent),
        (25, 6),
        "the closed-connection summary must include counters reported before the close"
    );
}

#[tokio::test]
async fn activity_reported_off_lock_keeps_a_connection_from_looking_idle() {
    let state = AppState::new();
    let sid = server(&state).await;
    let cid = ConnectionId::new(3);
    let mut stale = connection(3);
    stale.last_activity = netget::utils::clock::Instant::now() - Duration::from_secs(60);
    state.add_connection_to_server(sid, stale).await;

    state
        .update_connection_stats(sid, cid, Some(1), None, None, None)
        .await;
    let server = state.get_server(sid).await.unwrap();
    assert!(
        server.connections[&cid].last_activity.elapsed() < Duration::from_secs(5),
        "the idle sweep reads last_activity; a report must move it"
    );
}

#[tokio::test]
async fn counters_reported_before_a_connection_exists_do_not_attach_to_it() {
    let state = AppState::new();
    let sid = server(&state).await;
    let cid = ConnectionId::new(9);

    state
        .update_connection_stats(sid, cid, Some(1000), Some(1000), None, None)
        .await;
    state.add_connection_to_server(sid, connection(9)).await;
    assert_eq!(counters(&state, sid, cid).await, (0, 0, 0, 0));
}

#[tokio::test]
async fn a_task_registered_after_its_server_stopped_is_aborted() {
    let state = AppState::new();
    let sid = server(&state).await;
    let live = state
        .spawn_server_task(sid, std::future::pending::<()>())
        .await;
    assert_eq!(state.server_task_count(sid).await, 1);

    state.remove_server(sid).await;
    assert!(live.is_finished(), "stop must abort what the server owned");

    let late = state
        .spawn_server_task(sid, std::future::pending::<()>())
        .await;
    for _ in 0..100 {
        if late.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        late.is_finished(),
        "a task registered against a stopped server must be aborted, not left running"
    );
    assert_eq!(state.server_task_count(sid).await, 0);
}

#[tokio::test]
async fn the_access_log_keeps_its_ids_order_and_total_past_capacity() {
    let state = AppState::new();
    let sid = server(&state).await;
    let owner = AccessLogOwner::Server(sid.as_u32());

    let mut ids = Vec::new();
    for n in 0..1005u32 {
        ids.push(
            state
                .record_access_log(
                    owner,
                    "tcp",
                    None,
                    "tcp_data_received",
                    serde_json::json!({ "n": n }),
                    vec![],
                )
                .await,
        );
    }
    assert_eq!(ids.first(), Some(&1));
    assert!(
        ids.windows(2).all(|w| w[1] == w[0] + 1),
        "ids are consecutive"
    );
    assert_eq!(state.access_log_total().await, 1005);

    let listed = state.list_access_logs(None).await;
    assert_eq!(listed.len(), 1000, "the ring keeps its capacity");
    assert_eq!(listed[0].id, 1005, "newest first");
    assert_eq!(listed[0].request["n"], 1004);
    assert!(state.get_access_log(5).await.is_none(), "evicted");
    assert_eq!(state.get_access_log(1005).await.unwrap().request["n"], 1004);
    assert_eq!(
        state
            .list_access_logs_for(Some(AccessLogOwner::Server(sid.as_u32() + 1)), None)
            .await
            .len(),
        0
    );
}

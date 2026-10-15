//! The MySQL server updates the dashboard's per-connection counters as it processes queries.
//!
//! opensrv-mysql owns the socket inside `run_on` and never exposes the raw byte streams, so
//! there is no peer handle and no wire-action injection for MySQL (see the server CLAUDE.md).
//! What the shim *can* do is record the application-visible payload it sees at each command
//! boundary. This test proves those counters move, with **zero LLM calls**: a `*` script handler
//! answers every query in-process, so `call_llm` never reaches the (deliberately dead) backend.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mysql --test server -- mysql::connection_stats --test-threads=100

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
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
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("MySQL server #{} never bound a port", id.as_u32());
}

/// A `*` handler that branches: SELECT gets a result set (drivers issue `SELECT @@...` during
/// setup and expect one), everything else gets an OK packet. Pure Python, no LLM.
const BRANCHING_SCRIPT: &str = r#"
import json, sys
try:
    inp = json.load(sys.stdin)
except Exception:
    inp = {}
event = inp.get("event") or {}
query = str(event.get("query", "")).strip().upper()
if query.startswith("SELECT"):
    print(json.dumps({"actions": [{
        "type": "mysql_query_response",
        "columns": [{"name": "value", "type": "VARCHAR"}],
        "rows": [["1000"]]
    }]}))
else:
    print(json.dumps({"actions": [{"type": "mysql_ok_response", "affected_rows": 0}]}))
"#;

#[tokio::test]
async fn mysql_query_updates_connection_counters_without_llm() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "mysql".to_string(),
        port: Some(0),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "script",
                "language": "python",
                "code": BRANCHING_SCRIPT
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create mysql server");
    let port = wait_for_port(&state, server_id).await;

    // Best-effort connect + query. Whether the driver's full setup completes or not, at least one
    // statement reaches the shim, which is all the counters need. Errors are intentionally ignored
    // - this test asserts on the server's counters, not the client's result.
    let _ = tokio::time::timeout(Duration::from_secs(20), async {
        use mysql_async::prelude::Queryable;
        let url = format!("mysql://root@127.0.0.1:{port}/test");
        let pool = mysql_async::Pool::new(url.as_str());
        if let Ok(mut conn) = pool.get_conn().await {
            let _: Result<Vec<(String,)>, _> = conn.query("SELECT 1").await;
        }
        let _ = pool.disconnect().await;
    })
    .await;

    // Poll for a tracked connection whose inbound counter has moved. The entry survives the
    // connection closing (status flips to Closed, stats are retained), so this is not racy against
    // teardown.
    let mut moved = None;
    for _ in 0..100 {
        if let Some(s) = state.get_server(server_id).await {
            if let Some(conn) = s.connections.values().find(|c| c.bytes_received > 0) {
                moved = Some((
                    conn.bytes_received,
                    conn.bytes_sent,
                    conn.packets_received,
                    conn.packets_sent,
                ));
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    let (bytes_in, bytes_out, pkts_in, pkts_out) = moved.expect(
        "no MySQL connection ever recorded inbound bytes - the shim is not calling \
         update_connection_stats for the queries it processes",
    );

    assert!(bytes_in > 0, "bytes_received should count the query text");
    assert!(
        pkts_in > 0,
        "packets_received should count at least one query"
    );
    // Every query path writes a response (result set, OK, ERR), so the outbound packet counter
    // must have moved even though the byte estimate for a bare OK is zero.
    assert!(
        pkts_out > 0,
        "packets_sent should count at least one response, got {pkts_out}"
    );
    // A SELECT is answered with a result set carrying the literal "1000", so some outbound payload
    // bytes are recorded too.
    assert!(
        bytes_out > 0,
        "bytes_sent should count the result-set cell text, got {bytes_out}"
    );
}

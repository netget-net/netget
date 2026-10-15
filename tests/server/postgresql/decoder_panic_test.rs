//! A malformed frame makes `pgwire` panic inside the connection task; this pins what NetGet
//! does about it.
//!
//! `pgwire` 0.35's `decode_packet` bounds a message's declared length only from above and then
//! hands `decode_fn` the whole remaining buffer, so `get_cstring` can `split_to(remaining + 1)`
//! and panic on a message that carries no NUL. Six bytes after a valid startup handshake are
//! enough (IMPROVEMENTS #77). The fix belongs upstream — pgwire owns the socket loop and takes
//! a concrete `TcpStream`, so nothing in NetGet can bound the frame without proxying the
//! connection.
//!
//! What NetGet *can* do is not lose the connection's bookkeeping to it. A panic inside
//! `tokio::spawn` is swallowed, so the panic used to unwind straight past
//! `close_connection_on_server`: the dashboard kept an `Active` row for a socket that was
//! already gone, and PostgreSQL is not `connectionless`, so the 10-second idle sweep never
//! collected it either. That row was immortal for the life of the server.
//!
//! Zero LLM calls: a `*` static handler answers, and `instruction: Some(String::new())` keeps
//! `ServerForm::create` from substituting its default instruction (which would make the server
//! consult the model).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features postgresql --test server -- postgresql::decoder_panic --test-threads=100


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::server::ConnectionStatus;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("PostgreSQL server #{} never bound a port", id.as_u32());
}

/// A PostgreSQL v3 StartupMessage: Int32 length, Int32 protocol 196608, then NUL-terminated
/// key/value pairs and a final NUL. `pgwire`'s `NoopStartupHandler` accepts it and replies
/// AuthenticationOk + ParameterStatus* + ReadyForQuery.
fn startup_message() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&196_608i32.to_be_bytes());
    for kv in ["user", "netget", "database", "netget"] {
        body.extend_from_slice(kv.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut msg = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    msg.extend_from_slice(&body);
    msg
}

/// Read until a ReadyForQuery ('Z') message byte shows up, so the handshake is known complete
/// before the malformed frame goes out. Waiting for the condition rather than sleeping.
async fn read_until_ready(stream: &mut TcpStream) {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        let mut buf = [0u8; 1024];
        let n = match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("read during startup failed: {e}"),
            Err(_) => continue,
        };
        seen.extend_from_slice(&buf[..n]);
        // ReadyForQuery is exactly five bytes: 'Z', Int32 5, one status byte.
        if seen
            .windows(5)
            .any(|w| w[0] == b'Z' && w[1..5] == [0, 0, 0, 5])
        {
            return;
        }
    }
    panic!("PostgreSQL never sent ReadyForQuery; startup handshake did not complete");
}

async fn count_open_connections(state: &AppState, id: ServerId) -> usize {
    state
        .get_server(id)
        .await
        .expect("server")
        .connections
        .values()
        .filter(|c| c.status != ConnectionStatus::Closed)
        .count()
}

#[tokio::test]
async fn a_decoder_panic_closes_the_connection_row_and_leaves_the_server_serving() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "postgresql".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ { "type": "postgresql_ok_response", "tag": "OK" } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create postgresql server");
    let port = wait_for_port(&state, server_id).await;

    // A connection that completes the handshake and is then killed by six bytes.
    let mut victim = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect victim");
    victim
        .write_all(&startup_message())
        .await
        .expect("write startup");
    read_until_ready(&mut victim).await;

    // 'Q' (simple query), declared length 5, one payload byte and no NUL terminator.
    victim
        .write_all(&[0x51, 0x00, 0x00, 0x00, 0x05, 0x78])
        .await
        .expect("write malformed frame");

    // The peer's socket dies with the task, so the read side reaches EOF (or a reset).
    let mut buf = [0u8; 64];
    let ended = tokio::time::timeout(Duration::from_secs(10), victim.read(&mut buf)).await;
    match ended {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!(
            "expected the connection to die, got {n} bytes back: {:?}",
            &buf[..n]
        ),
        Err(_) => panic!("the panicking connection neither replied nor closed within 10s"),
    }

    // The bookkeeping is the point. Without the containment the row stays Active forever:
    // the panic unwinds past `close_connection_on_server`, and PostgreSQL is not
    // `connectionless` so the idle sweep never collects it.
    let mut closed = false;
    for _ in 0..100 {
        if count_open_connections(&state, server_id).await == 0 {
            closed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        closed,
        "the panicking connection stayed Active in the server's connection map - the panic \
         unwound past close_connection_on_server and nothing else will ever collect the row"
    );

    // And the server itself is unaffected: a fresh client still gets a real answer.
    let (client, connection) = tokio_postgres::connect(
        &format!("host=127.0.0.1 port={port} user=netget dbname=netget"),
        tokio_postgres::NoTls,
    )
    .await
    .expect("connect a second client after the panic");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let rows = tokio::time::timeout(Duration::from_secs(15), client.simple_query("SELECT 1"))
        .await
        .expect("the server answered within 15s after a connection panicked")
        .expect("simple_query succeeded");
    assert!(
        !rows.is_empty(),
        "expected a CommandComplete from the static handler after the panic"
    );
}

/// Nothing on this protocol ever called `update_connection_stats`, so every PostgreSQL peer row
/// read `0 / 0` for its whole life however much SQL crossed it. pgwire never exposes the raw
/// byte streams, so these are application-visible payload sizes measured at the handler
/// boundary - the assertion is deliberately "moved off zero", not an exact wire count.
#[tokio::test]
async fn a_query_moves_the_connection_counters_off_zero() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let server_id = ServerForm {
        protocol: "postgresql".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "*",
            "handler": {
                "type": "static",
                "actions": [ {
                    "type": "postgresql_query_response",
                    "columns": [{"name": "id", "type": "int4"}],
                    "rows": [[1]]
                } ]
            }
        })]),
        ..Default::default()
    }
    .create(&state, tx.clone())
    .await
    .expect("create postgresql server");
    let port = wait_for_port(&state, server_id).await;

    let (client, connection) = tokio_postgres::connect(
        &format!("host=127.0.0.1 port={port} user=netget dbname=netget"),
        tokio_postgres::NoTls,
    )
    .await
    .expect("connect");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    const SQL: &str = "SELECT id FROM users WHERE id = 1";
    let rows = tokio::time::timeout(Duration::from_secs(15), client.simple_query(SQL))
        .await
        .expect("answered within 15s")
        .expect("simple_query succeeded");
    assert!(
        !rows.is_empty(),
        "expected a row back from the static handler"
    );

    let mut counted = None;
    for _ in 0..100 {
        let server = state.get_server(server_id).await.expect("server");
        if let Some(conn) = server
            .connections
            .values()
            .find(|c| c.bytes_received > 0 && c.bytes_sent > 0)
        {
            counted = Some((conn.bytes_received, conn.bytes_sent, conn.packets_received));
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let (received, sent, packets_in) = counted.expect(
        "no PostgreSQL connection ever counted a byte - update_connection_stats is not being \
         called, so the rail's counters read 0/0 and last_activity never advances",
    );
    assert!(
        received >= SQL.len() as u64,
        "expected at least the SQL text ({} bytes) counted inbound, got {received}",
        SQL.len()
    );
    assert!(sent > 0, "expected the result payload counted outbound");
    assert!(
        packets_in >= 1,
        "expected at least one inbound packet counted"
    );
}

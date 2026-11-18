//! A malformed frontend message is refused with a protocol error, and the connection's
//! bookkeeping survives it.
//!
//! pgwire before 0.42.3 handed each body decoder the whole receive buffer and read it with
//! panicking getters, so six bytes after a valid startup handshake panicked the connection task
//! (IMPROVEMENTS #77). pgwire 0.42.3 isolates each body and refuses a short one, but its
//! `process_socket` answers a decode error by ending the session with nothing written, and it
//! reads a Query whose string has no NUL as an empty query. NetGet's frontend screen
//! (`src/server/postgresql/guard.rs`) runs pgwire's decoder on each message first and answers
//! every one of these the way PostgreSQL does — `ErrorResponse`, severity FATAL, SQLSTATE 08P01 —
//! and closes, before pgwire sees it. Without the screen's check these tests fail: the peer
//! reads EOF, or an EmptyQueryResponse.
//!
//! The containment around the session task stays: any other panic in pgwire or in the handler
//! still takes the `JoinError` path. Before it,
//! the panic unwound straight past `close_connection_on_server`: the dashboard kept an `Active`
//! row for a socket that was already gone, and PostgreSQL is not `connectionless`, so the
//! 10-second idle sweep never collected it either.
//!
//! The screen half, every malformed shape, is `tests/pgwire_frontend_screen_test.rs`.
//!
//! Zero LLM calls: a `*` static handler answers, and `instruction: Some(String::new())` keeps
//! `ServerForm::create` from substituting its default instruction (which would make the server
//! consult the model).
//!
//! Run with:
//!   ./cargo-isolated.sh test --test server -- server::postgresql::decoder_panic --test-threads=100

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
async fn a_malformed_query_is_refused_fatal_08p01_and_the_server_keeps_serving() {
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

    // A connection that completes the handshake and then sends six malformed bytes.
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

    // Everything the server sends until it closes.
    let mut reply = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let mut buf = [0u8; 256];
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, victim.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => reply.extend_from_slice(&buf[..n]),
            Err(_) => panic!(
                "the malformed message neither got an answer nor closed the connection within \
                 10s; got {reply:?}"
            ),
        }
    }

    // ErrorResponse: 'E', Int32 length, then (code byte, cstring) fields.
    assert_eq!(
        reply.first(),
        Some(&b'E'),
        "expected an ErrorResponse for the malformed Query, got {reply:?} - pgwire alone \
         serves it as an empty query (IMPROVEMENTS #77)"
    );
    let fields = String::from_utf8_lossy(&reply[5..]).to_string();
    assert!(
        fields.contains("SFATAL") && fields.contains("C08P01"),
        "expected severity FATAL and SQLSTATE 08P01 (protocol_violation), got {fields:?}"
    );

    // The bookkeeping closes on this path too. PostgreSQL is not `connectionless`, so the idle
    // sweep never collects a row the connection task forgets.
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
        "the refused connection stayed Active in the server's connection map - nothing else \
         will ever collect the row"
    );

    // And the server itself is unaffected: a fresh client still gets a real answer.
    let (client, connection) = tokio_postgres::connect(
        &format!("host=127.0.0.1 port={port} user=netget dbname=netget"),
        tokio_postgres::NoTls,
    )
    .await
    .expect("connect a second client after the refusal");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let rows = tokio::time::timeout(Duration::from_secs(15), client.simple_query("SELECT 1"))
        .await
        .expect("the server answered within 15s after refusing a connection")
        .expect("simple_query succeeded");
    assert!(
        !rows.is_empty(),
        "expected a CommandComplete from the static handler after the refusal"
    );
}

/// The six frames that panicked pgwire 0.35's connection task, each sent after a valid startup
/// on a connection of its own: every one is answered with exactly one message, `ErrorResponse`
/// FATAL 08P01, and then the close, and logged `decision=refused_malformed_message`.
///
/// Exactly one message is the point of the last case: a Query with no NUL followed by a Sync
/// must not be read into the Sync (the 0.35 desynchronisation), and must not be served as an
/// empty query whose Sync then gets a ReadyForQuery of its own (pgwire 0.42.3 alone).
#[tokio::test]
async fn each_frame_that_panicked_pgwire_0_35_is_refused_fatal_08p01() {
    let state = new_state().await;
    let (tx, mut rx) = mpsc::unbounded_channel();

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

    let cases: [(&str, &[u8]); 6] = [
        ("Query, no NUL", &[0x51, 0, 0, 0, 0x05, 0x78]),
        ("Close, no body", &[0x43, 0, 0, 0, 0x04]),
        ("Describe, no body", &[0x44, 0, 0, 0, 0x04]),
        (
            "Bind, parameter declares 100 bytes, has 1",
            &[
                0x42, 0, 0, 0, 0x0f, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0x64, 0x35,
            ],
        ),
        (
            "Bind, result-format count -1",
            &[0x42, 0, 0, 0, 0x0c, 0, 0, 0, 0, 0, 0, 0xff, 0xff],
        ),
        (
            "Query with no NUL, then a Sync",
            &[0x51, 0, 0, 0, 0x05, 0x78, 0x53, 0, 0, 0, 0x04],
        ),
    ];

    let mut failures = Vec::new();
    for (name, frame) in cases {
        let mut peer = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connect");
        peer.write_all(&startup_message()).await.expect("startup");
        read_until_ready(&mut peer).await;
        peer.write_all(frame).await.expect("write the frame");

        let mut reply = Vec::new();
        let closed = tokio::time::timeout(Duration::from_secs(10), peer.read_to_end(&mut reply))
            .await
            .is_ok();
        if !closed {
            failures.push(format!(
                "{name}: still open 10s later, having sent {reply:?}"
            ));
            continue;
        }
        let one_message = reply.len() > 5
            && reply[0] == b'E'
            && u32::from_be_bytes([reply[1], reply[2], reply[3], reply[4]]) as usize + 1
                == reply.len();
        let fields = String::from_utf8_lossy(reply.get(5..).unwrap_or_default()).to_string();
        if !one_message || !fields.contains("SFATAL") || !fields.contains("C08P01") {
            failures.push(format!(
                "{name}: expected exactly one ErrorResponse FATAL 08P01, got {:?}",
                String::from_utf8_lossy(&reply)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    // Every refusal was the screen's, and nothing panicked. The relay logs a refusal once it has
    // closed the peer's socket, so the lines may trail the closes a little.
    let mut log = Vec::new();
    let refused = |log: &[String]| {
        log.iter()
            .filter(|l| l.contains("decision=refused_malformed_message"))
            .count()
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while refused(&log) < cases.len() {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(line)) => log.push(line),
            _ => break,
        }
    }
    let refusals = refused(&log);
    assert_eq!(
        refusals,
        cases.len(),
        "expected one decision=refused_malformed_message per frame; the log was {log:#?}"
    );
    assert!(
        !log.iter().any(|l| l.contains("decoder_panic")),
        "a connection task panicked: {log:#?}"
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

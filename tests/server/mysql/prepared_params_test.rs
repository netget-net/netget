//! Prepared-statement parameter values reach the model, and a malformed `COM_STMT_EXECUTE` is
//! refused with an ERR packet on a connection that stays up.
//!
//! Two peers, for two different claims:
//!
//! - **`mysql_async`** executes a real prepared statement over the binary protocol with eight
//!   parameter types, and the test asserts on the event the mock model received: each value,
//!   its MySQL type, and the readable rendering beside the untouched statement text. Before
//!   the decoder existed the model saw `?` and nothing else.
//! - **A raw socket**, because no real client will send a malformed execute. It sends every
//!   shape that panics `opensrv-mysql`'s own `ParamParser` and several lying lengths besides,
//!   and asserts each is answered ERR 1835 `ER_MALFORMED_PACKET` at the right sequence id,
//!   that none reaches the model, and that the same connection then answers a ping, a
//!   well-formed execute, an execute reusing the types bound earlier, and one whose value
//!   arrived as `COM_STMT_SEND_LONG_DATA`.

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use mysql_async::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const ER_MALFORMED_PACKET: u16 = 1835;
const ER_WRONG_ARGUMENTS: u16 = 1210;

type Seen = Arc<Mutex<Vec<serde_json::Value>>>;

/// A server whose model answers every statement OK and records the event it was given.
fn recording_config(seen: Seen) -> NetGetConfig {
    NetGetConfig::new_no_scripts("Open MySQL on port {AVAILABLE_PORT} and accept every insert.")
        .with_mock(move |mock| {
            mock.on_instruction_containing("Open MySQL")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MySQL",
                    "instruction": "Accept every insert"
                }]))
                .expect_calls(1)
                .and()
                // mysql_async opens with `SELECT @@max_allowed_packet,…`, which reaches the
                // model; it must be answered with a large number (see packet_limit_test.rs).
                .on_event("mysql_query")
                .and_event_data_contains("query", "@@")
                .respond_with_actions(serde_json::json!([{
                    "type": "mysql_query_response",
                    "columns": [{"name": "value", "type": "VARCHAR"}],
                    "rows": [["16777216"]]
                }]))
                .expect_at_least(0)
                .and()
                .on_event("mysql_query")
                .respond_with_actions_from_event(move |event| {
                    seen.lock().unwrap().push(event.clone());
                    serde_json::json!([{"type": "mysql_ok_response", "affected_rows": 1}])
                })
                .expect_at_least(1)
                .and()
        })
}

fn statements(seen: &Seen) -> Vec<serde_json::Value> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|e| !e["query"].as_str().unwrap_or("").contains("@@"))
        .cloned()
        .collect()
}

#[tokio::test]
async fn mysql_async_bound_values_reach_the_model_with_their_types() -> E2EResult<()> {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let server = helpers::start_netget_server(recording_config(seen.clone())).await?;

    let opts = mysql_async::OptsBuilder::default()
        .ip_or_hostname("127.0.0.1")
        .tcp_port(server.port)
        .user(Some("root"))
        .pass(Some(""))
        .prefer_socket(false);
    let pool = mysql_async::Pool::new(opts);
    let mut conn = tokio::time::timeout(Duration::from_secs(20), pool.get_conn()).await??;

    use mysql_async::Value;
    let sql = "INSERT INTO t (a, b, c, d, e, f, g, h) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    let params = vec![
        Value::Int(-42),
        Value::UInt(u64::MAX),
        Value::Double(2.5),
        Value::Bytes("O'Brien ⟩".as_bytes().to_vec()),
        Value::NULL,
        Value::Bytes(vec![0xFF, 0xFE]),
        Value::Date(2026, 10, 31, 12, 34, 56, 789),
        Value::Time(true, 1, 2, 3, 4, 5),
    ];
    tokio::time::timeout(Duration::from_secs(20), conn.exec_drop(sql, params)).await??;
    assert_eq!(conn.affected_rows(), 1);

    drop(conn);
    pool.disconnect().await?;
    server.wait_for_mocks(10).await;
    server.verify_mocks().await?;

    let events = statements(&seen);
    assert_eq!(events.len(), 1, "one execute, one model call: {events:#?}");
    let event = &events[0];
    assert_eq!(
        event["query"], sql,
        "the statement text is shown exactly as prepared"
    );
    assert_eq!(
        event["params"],
        serde_json::json!([
            {"index": 1, "type": "LONGLONG", "value": -42},
            {"index": 2, "type": "LONGLONG", "unsigned": true, "value": u64::MAX},
            {"index": 3, "type": "DOUBLE", "value": 2.5},
            {"index": 4, "type": "VAR_STRING", "value": "O'Brien ⟩"},
            {"index": 5, "type": "NULL", "value": null},
            {"index": 6, "type": "VAR_STRING", "value": "\u{FFFD}\u{FFFD}", "not_utf8": true},
            {"index": 7, "type": "DATETIME", "value": "2026-10-31 12:34:56.000789"},
            {"index": 8, "type": "TIME", "value": "-26:03:04.000005"},
        ]),
        "every bound value, with its type, in placeholder order"
    );
    assert_eq!(
        event["query_rendered"],
        "INSERT INTO t (a, b, c, d, e, f, g, h) VALUES (⟨-42⟩, ⟨18446744073709551615⟩, ⟨2.5⟩, \
         ⟨\"O'Brien \\u27e9\"⟩, ⟨NULL⟩, ⟨\"\u{FFFD}\u{FFFD}\"⟩, ⟨\"2026-10-31 12:34:56.000789\"⟩, \
         ⟨\"-26:03:04.000005\"⟩)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Raw socket
// ---------------------------------------------------------------------------------------------

fn packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut p = vec![len as u8, (len >> 8) as u8, (len >> 16) as u8, seq];
    p.extend_from_slice(payload);
    p
}

async fn read_packet(sock: &mut TcpStream) -> E2EResult<(u8, Vec<u8>)> {
    let mut header = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(20), sock.read_exact(&mut header))
        .await
        .map_err(|_| "no packet within 20s — the server dropped or wedged the connection")??;
    let len = u32::from_le_bytes([header[0], header[1], header[2], 0]) as usize;
    let mut payload = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(20), sock.read_exact(&mut payload)).await??;
    Ok((header[3], payload))
}

/// Read the greeting, answer it as a `CLIENT_DEPRECATE_EOF` client with no password, and read
/// the OK packet.
async fn connect(port: u16) -> E2EResult<TcpStream> {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await?;
    let (_, greeting) = read_packet(&mut sock).await?;
    assert_eq!(greeting[0], 10, "protocol version 10 greeting");

    const CLIENT_LONG_PASSWORD: u32 = 0x1;
    const CLIENT_PROTOCOL_41: u32 = 0x200;
    const CLIENT_TRANSACTIONS: u32 = 0x2000;
    const CLIENT_SECURE_CONNECTION: u32 = 0x8000;
    const CLIENT_PLUGIN_AUTH: u32 = 0x8_0000;
    const CLIENT_DEPRECATE_EOF: u32 = 0x100_0000;
    let caps = CLIENT_LONG_PASSWORD
        | CLIENT_PROTOCOL_41
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH
        | CLIENT_DEPRECATE_EOF;
    let mut resp = caps.to_le_bytes().to_vec();
    resp.extend_from_slice(&(16u32 << 20).to_le_bytes());
    resp.push(33);
    resp.extend_from_slice(&[0u8; 23]);
    resp.extend_from_slice(b"root\0");
    resp.push(0); // empty auth response
    resp.extend_from_slice(b"caching_sha2_password\0");
    sock.write_all(&packet(1, &resp)).await?;

    let (_, ok) = read_packet(&mut sock).await?;
    assert_eq!(ok[0], 0x00, "expected the OK packet, got {ok:?}");
    Ok(sock)
}

/// COM_STMT_PREPARE; returns the statement id after reading its parameter definitions.
async fn prepare(sock: &mut TcpStream, sql: &str) -> E2EResult<u32> {
    let mut cmd = vec![0x16];
    cmd.extend_from_slice(sql.as_bytes());
    sock.write_all(&packet(0, &cmd)).await?;
    let (_, ok) = read_packet(sock).await?;
    assert_eq!(ok[0], 0x00, "PREPARE OK, got {ok:?}");
    let stmt_id = u32::from_le_bytes([ok[1], ok[2], ok[3], ok[4]]);
    let params = u16::from_le_bytes([ok[7], ok[8]]);
    for _ in 0..params {
        read_packet(sock).await?;
    }
    Ok(stmt_id)
}

/// Send one COM_STMT_EXECUTE (`body` is everything after the statement id) and return the
/// reply's first packet.
async fn execute(sock: &mut TcpStream, stmt_id: u32, body: &[u8]) -> E2EResult<(u8, Vec<u8>)> {
    let mut cmd = vec![0x17];
    cmd.extend_from_slice(&stmt_id.to_le_bytes());
    cmd.extend_from_slice(body);
    sock.write_all(&packet(0, &cmd)).await?;
    read_packet(sock).await
}

fn assert_err(reply: &(u8, Vec<u8>), code: u16, what: &str) {
    let (seq, p) = reply;
    assert_eq!(
        // Not `p.first()`: mysql_async's prelude puts a `Query::first` on `Vec<u8>`.
        p.get(..1),
        Some(&[0xFFu8][..]),
        "{what}: expected an ERR packet, got {p:?}"
    );
    assert_eq!(
        u16::from_le_bytes([p[1], p[2]]),
        code,
        "{what}: wrong error number ({})",
        String::from_utf8_lossy(&p[9..])
    );
    assert_eq!(&p[3..9], b"#HY000", "{what}: SQLSTATE");
    assert_eq!(
        *seq, 1,
        "{what}: the reply must follow the command's sequence id"
    );
    let message = String::from_utf8_lossy(&p[9..]);
    assert!(
        !message.contains("truncated") && !message.contains("needs"),
        "{what}: the parser's diagnosis belongs in the log, not on the wire: {message}"
    );
}

/// The OK packet the mock model's `mysql_ok_response` produces: affected_rows 1. An OK with
/// zero affected rows is one the crate wrote on its own, which is a different claim.
fn assert_model_ok(reply: &(u8, Vec<u8>), what: &str) {
    let (seq, p) = reply;
    assert_eq!(
        p.get(..2),
        Some(&[0x00u8, 0x01][..]),
        "{what}: expected the model's OK (affected_rows 1), got seq {seq} {p:?}"
    );
    assert_eq!(*seq, 1, "{what}: sequence id");
}

#[tokio::test]
async fn malformed_executes_get_an_err_packet_and_the_connection_survives() -> E2EResult<()> {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let server = helpers::start_netget_server(recording_config(seen.clone())).await?;
    helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let mut sock = connect(server.port).await?;
    let stmt = prepare(&mut sock, "INSERT INTO t (n, s) VALUES (?, ?)").await?;

    // `flags · iteration_count` — the part of every execute before the parameter block.
    let head: &[u8] = &[0, 1, 0, 0, 0];
    let with = |rest: &[u8]| [head, rest].concat();
    const LONGLONG: u8 = 0x08;
    const VAR_STRING: u8 = 0xFD;
    let types = [LONGLONG, 0, VAR_STRING, 0];

    let mut huge = vec![0x00, 0x01];
    huge.extend_from_slice(&types);
    huge.extend_from_slice(&5i64.to_le_bytes());
    huge.push(0xFE);
    huge.extend_from_slice(&u64::MAX.to_le_bytes());
    huge.extend_from_slice(b"short");

    let cases: Vec<(&str, Vec<u8>)> = vec![
        // The five `opensrv-mysql` `ParamParser` panics, in source order.
        ("no NULL bitmap", with(&[])),
        ("one type pair of two", with(&[0x00, 0x01, LONGLONG, 0])),
        (
            "unknown type byte",
            with(&[0x00, 0x01, 0x42, 0, VAR_STRING, 0, 0, 0, 0, 0, 1, b'x']),
        ),
        (
            "types never bound",
            with(&[0x00, 0x00, 1, 0, 0, 0, 0, 0, 0, 0, 1, b'x']),
        ),
        (
            "LONGLONG with three bytes",
            with(&[[0x00, 0x01].as_slice(), &types, &[1, 2, 3]].concat()),
        ),
        // Lying lengths.
        ("8-byte length of u64::MAX", with(&huge)),
        (
            "2-byte length past the packet",
            with(
                &[
                    [0x00, 0x01].as_slice(),
                    &types,
                    &[0; 8],
                    &[0xFC, 0xFF, 0xFF, b'a'],
                ]
                .concat(),
            ),
        ),
        (
            "0xFF where a length belongs",
            with(&[[0x00, 0x01].as_slice(), &types, &[0; 8], &[0xFF]].concat()),
        ),
        (
            "trailing bytes",
            with(&[[0x00, 0x01].as_slice(), &types, &[0; 8], &[1, b'x', 0xAA]].concat()),
        ),
    ];
    for (what, body) in &cases {
        let reply = execute(&mut sock, stmt, body).await?;
        assert_err(&reply, ER_MALFORMED_PACKET, what);
    }

    // Still the same, working connection.
    sock.write_all(&packet(0, &[0x0E])).await?;
    let (_, pong) = read_packet(&mut sock).await?;
    assert_eq!(pong[0], 0x00, "COM_PING after the refusals");

    // A well-formed execute binds types; the next reuses them with the flag clear.
    let mut good = vec![0x00, 0x01];
    good.extend_from_slice(&types);
    good.extend_from_slice(&7i64.to_le_bytes());
    good.extend_from_slice(&[3, b'b', b'o', b'b']);
    let reply = execute(&mut sock, stmt, &with(&good)).await?;
    assert_model_ok(&reply, "a well-formed execute");

    let mut rebound = vec![0x00, 0x00];
    rebound.extend_from_slice(&8i64.to_le_bytes());
    rebound.extend_from_slice(&[5, b'c', b'a', b'r', b'o', b'l']);
    let reply = execute(&mut sock, stmt, &with(&rebound)).await?;
    assert_model_ok(&reply, "an execute reusing bound types");

    // The string parameter as long data, in two chunks; the execute then carries only the int.
    for chunk in [&b"from "[..], &b"long data"[..]] {
        let mut cmd = vec![0x18];
        cmd.extend_from_slice(&stmt.to_le_bytes());
        cmd.extend_from_slice(&1u16.to_le_bytes());
        cmd.extend_from_slice(chunk);
        sock.write_all(&packet(0, &cmd)).await?;
    }
    let mut via_long_data = vec![0x00, 0x01];
    via_long_data.extend_from_slice(&types);
    via_long_data.extend_from_slice(&9i64.to_le_bytes());
    let reply = execute(&mut sock, stmt, &with(&via_long_data)).await?;
    assert_model_ok(&reply, "an execute whose value came as long data");

    // Long data naming a parameter the statement does not have: refused at the next execute,
    // as mysqld does, and then forgotten.
    let mut cmd = vec![0x18];
    cmd.extend_from_slice(&stmt.to_le_bytes());
    cmd.extend_from_slice(&5u16.to_le_bytes());
    cmd.extend_from_slice(b"nowhere");
    sock.write_all(&packet(0, &cmd)).await?;
    let reply = execute(&mut sock, stmt, &with(&good)).await?;
    assert_err(&reply, ER_WRONG_ARGUMENTS, "long data for parameter 6 of 2");
    let reply = execute(&mut sock, stmt, &with(&good)).await?;
    assert_model_ok(&reply, "the statement after the refusal");

    drop(sock);
    server.wait_for_mocks(10).await;
    server.verify_mocks().await?;

    let events = statements(&seen);
    let params: Vec<_> = events.iter().map(|e| e["params"].clone()).collect();
    assert_eq!(
        params,
        vec![
            serde_json::json!([
                {"index": 1, "type": "LONGLONG", "value": 7},
                {"index": 2, "type": "VAR_STRING", "value": "bob"}
            ]),
            serde_json::json!([
                {"index": 1, "type": "LONGLONG", "value": 8},
                {"index": 2, "type": "VAR_STRING", "value": "carol"}
            ]),
            serde_json::json!([
                {"index": 1, "type": "LONGLONG", "value": 9},
                {"index": 2, "type": "VAR_STRING", "long_data": true, "value": "from long data"}
            ]),
            serde_json::json!([
                {"index": 1, "type": "LONGLONG", "value": 7},
                {"index": 2, "type": "VAR_STRING", "value": "bob"}
            ]),
        ],
        "exactly the four well-formed executes reached the model — no malformed one did"
    );
    Ok(())
}

/// Long data past `max_allowed_packet` for one statement is refused at its next execute with
/// mysqld's own ERR 1105, and the statement works again afterwards.
///
/// `opensrv-mysql` would store every chunk (`lib.rs:663-678`), so the bound is enforced by
/// withholding the chunks past it (`command_tap::LongDataGate`). Five 16 MB chunks: four fit
/// under 64 MiB, the fifth does not. This moves 80 MB over loopback, which is what reaching
/// the real bound costs; `stmt_params_test.rs` drives both bounds at small sizes.
#[tokio::test]
async fn long_data_past_max_allowed_packet_is_refused_at_execute() -> E2EResult<()> {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let server = helpers::start_netget_server(recording_config(seen.clone())).await?;
    helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let mut sock = connect(server.port).await?;
    let stmt = prepare(&mut sock, "INSERT INTO blobs (b) VALUES (?)").await?;

    const CHUNK: usize = 16_000_000;
    let mut chunk = vec![0x18];
    chunk.extend_from_slice(&stmt.to_le_bytes());
    chunk.extend_from_slice(&0u16.to_le_bytes());
    chunk.resize(7 + CHUNK, b'z');
    let chunk = packet(0, &chunk);
    for _ in 0..5 {
        sock.write_all(&chunk).await?;
    }
    assert!(
        5 * CHUNK as u64 > netget::server::mysql::command_tap::LONG_DATA_PER_STATEMENT
            && 4 * CHUNK as u64 <= netget::server::mysql::command_tap::LONG_DATA_PER_STATEMENT,
        "the fifth chunk is the one past the bound"
    );

    // flags · iteration count · NULL bitmap · new-params-bound · VAR_STRING; no value bytes,
    // because the parameter's value is the long data.
    let body = [0, 1, 0, 0, 0, 0x00, 0x01, 0xFD, 0];
    let reply = execute(&mut sock, stmt, &body).await?;
    assert_err(&reply, 1105, "long data past max_allowed_packet");
    let message = String::from_utf8_lossy(&reply.1[9..]).to_string();
    assert!(message.contains("max_allowed_packet"), "{message}");

    let mut good = vec![0, 1, 0, 0, 0, 0x00, 0x01, 0xFD, 0];
    good.extend_from_slice(&[2, b'o', b'k']);
    let reply = execute(&mut sock, stmt, &good).await?;
    assert_model_ok(&reply, "the statement after the refusal");

    drop(sock);
    server.wait_for_mocks(10).await;
    server.verify_mocks().await?;
    let events = statements(&seen);
    assert_eq!(events.len(), 1, "only the second execute reached the model");
    assert_eq!(
        events[0]["params"],
        serde_json::json!([{"index": 1, "type": "VAR_STRING", "value": "ok"}])
    );
    Ok(())
}

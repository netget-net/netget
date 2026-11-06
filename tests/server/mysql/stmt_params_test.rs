//! The `COM_STMT_EXECUTE` parameter decoder and the reader that captures its input.
//!
//! `opensrv-mysql`'s own decoder panics on five malformed shapes (see
//! `src/server/mysql/stmt_params.rs`), so the server decodes with its own. These tests drive
//! that decoder directly with packets built byte by byte, and drive `CommandTapReader` — which
//! copies the packets out from beneath the crate — with the framing split at every byte.
//! `prepared_params_test.rs` covers the same path end to end, over a socket.

use netget::server::mysql::command_tap::{Captured, CommandTap, CommandTapReader, LongDataGate};
use netget::server::mysql::packet_limit::FULL_PACKET_PAYLOAD;
use netget::server::mysql::placeholder_offsets;
use netget::server::mysql::stmt_params::{
    params_json, parse_execute, render_query, ExecuteError, LongData, ParamType, ParamValue,
    MAX_RENDERED_VALUE_BYTES,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

const VAR_STRING: u8 = 0xFD;
const LONGLONG: u8 = 0x08;
const LONG: u8 = 0x03;
const TINY: u8 = 0x01;
const DOUBLE: u8 = 0x05;
const FLOAT: u8 = 0x04;
const NULL: u8 = 0x06;
const DATETIME: u8 = 0x0C;
const DATE: u8 = 0x0A;
const TIME: u8 = 0x0B;
const NEWDECIMAL: u8 = 0xF6;
const BLOB: u8 = 0xFC;

/// `stmt_id · flags · iteration_count`, then — for a statement with parameters — the NULL
/// bitmap, the new-params-bound flag, the types when bound, and the values.
fn execute_payload(
    stmt_id: u32,
    nulls: &[bool],
    types: Option<&[(u8, bool)]>,
    values: &[u8],
) -> Vec<u8> {
    let mut p = stmt_id.to_le_bytes().to_vec();
    p.push(0);
    p.extend_from_slice(&1u32.to_le_bytes());
    if !nulls.is_empty() {
        let mut bitmap = vec![0u8; nulls.len().div_ceil(8)];
        for (i, n) in nulls.iter().enumerate() {
            if *n {
                bitmap[i / 8] |= 1 << (i % 8);
            }
        }
        p.extend_from_slice(&bitmap);
        match types {
            Some(t) => {
                p.push(1);
                for (code, unsigned) in t {
                    p.push(*code);
                    p.push(if *unsigned { 0x80 } else { 0 });
                }
            }
            None => p.push(0),
        }
    }
    p.extend_from_slice(values);
    p
}

fn lenenc_str(s: &[u8]) -> Vec<u8> {
    assert!(s.len() < 0xFB);
    let mut v = vec![s.len() as u8];
    v.extend_from_slice(s);
    v
}

fn no_long_data() -> HashMap<u16, LongData> {
    HashMap::new()
}

#[test]
fn every_supported_type_decodes_and_reaches_the_model_as_typed_json() {
    let mut values = Vec::new();
    values.extend_from_slice(&42i64.to_le_bytes()); // LONGLONG
    values.extend_from_slice(&u64::MAX.to_le_bytes()); // LONGLONG unsigned
    values.extend_from_slice(&(-7i32).to_le_bytes()); // LONG
    values.push(0xFF); // TINY signed -1
    values.extend_from_slice(&2.5f64.to_le_bytes()); // DOUBLE
    values.extend_from_slice(&0.1f32.to_le_bytes()); // FLOAT
    values.extend(lenenc_str("alice".as_bytes())); // VAR_STRING
    values.extend(lenenc_str(b"12.50")); // NEWDECIMAL
                                         // NULL by bitmap: no bytes
    values.extend_from_slice(&[11, 0xEA, 0x07, 10, 31, 12, 34, 56]); // DATETIME 2026-10-31 12:34:56
    values.extend_from_slice(&789u32.to_le_bytes()); //  .000789
    values.extend_from_slice(&[4, 0xEA, 0x07, 1, 2]); // DATE 2026-01-02
    values.extend_from_slice(&[8, 1, 1, 0, 0, 0, 2, 3, 4]); // TIME -26:03:04
    values.extend(lenenc_str(&[0xFF, 0xFE, 0x00])); // BLOB, not UTF-8

    let types = [
        (LONGLONG, false),
        (LONGLONG, true),
        (LONG, false),
        (TINY, false),
        (DOUBLE, false),
        (FLOAT, false),
        (VAR_STRING, false),
        (NEWDECIMAL, false),
        (LONG, false),
        (DATETIME, false),
        (DATE, false),
        (TIME, false),
        (BLOB, false),
    ];
    let mut nulls = vec![false; types.len()];
    nulls[8] = true;
    let payload = execute_payload(9, &nulls, Some(&types), &values);
    let ld = no_long_data();
    let req = parse_execute(&payload, types.len(), None, &ld).expect("well-formed execute");

    assert_eq!(req.stmt_id, 9);
    assert_eq!(req.params.len(), types.len());
    assert_eq!(req.params[0].value, ParamValue::Int(42));
    assert_eq!(req.params[1].value, ParamValue::UInt(u64::MAX));
    assert_eq!(req.params[3].value, ParamValue::Int(-1));
    assert_eq!(req.params[8].value, ParamValue::Null);

    let json = params_json(&req);
    let expected = serde_json::json!([
        {"index": 1, "type": "LONGLONG", "value": 42},
        {"index": 2, "type": "LONGLONG", "unsigned": true, "value": u64::MAX},
        {"index": 3, "type": "LONG", "value": -7},
        {"index": 4, "type": "TINY", "value": -1},
        {"index": 5, "type": "DOUBLE", "value": 2.5},
        {"index": 6, "type": "FLOAT", "value": 0.1},
        {"index": 7, "type": "VAR_STRING", "value": "alice"},
        {"index": 8, "type": "NEWDECIMAL", "value": "12.50"},
        {"index": 9, "type": "LONG", "value": null},
        {"index": 10, "type": "DATETIME", "value": "2026-10-31 12:34:56.000789"},
        {"index": 11, "type": "DATE", "value": "2026-01-02"},
        {"index": 12, "type": "TIME", "value": "-26:03:04"},
        {"index": 13, "type": "BLOB", "value": "\u{FFFD}\u{FFFD}\u{0}", "not_utf8": true},
    ]);
    assert_eq!(json, expected);

    // Re-executing without rebinding uses the types the first execute bound.
    let rebinding = execute_payload(9, &nulls, None, &values);
    let again = parse_execute(&rebinding, types.len(), req.new_types.as_deref(), &ld)
        .expect("an execute that reuses bound types");
    assert_eq!(params_json(&again), expected);
    assert!(again.new_types.is_none());
}

/// Every shape `opensrv-mysql`'s `Params` iterator panics on, and the lying lengths besides.
/// Each must be a refusal, and a refusal naming the right problem.
#[test]
fn malformed_executes_are_refused_never_panicked_on() {
    let ld = no_long_data();
    let two = [(LONG, false), (VAR_STRING, false)];

    // params.rs:81 — no room for the NULL bitmap.
    let p = execute_payload(1, &[], None, &[]);
    assert!(matches!(
        parse_execute(&p, 2, None, &ld),
        Err(ExecuteError::Truncated {
            field: "NULL bitmap",
            ..
        })
    ));

    // params.rs:86 — the bound flag set, then one type pair where two are owed.
    let mut p = execute_payload(1, &[false, false], None, &[]);
    *p.last_mut().unwrap() = 1;
    p.extend_from_slice(&[LONG, 0]);
    assert!(matches!(
        parse_execute(&p, 2, None, &ld),
        Err(ExecuteError::Truncated {
            field: "parameter types",
            ..
        })
    ));

    // params.rs:90 — a type byte the crate's `ColumnType` does not know.
    let p = execute_payload(1, &[false], Some(&[(0x42, false)]), &[0; 4]);
    assert_eq!(
        parse_execute(&p, 1, None, &ld),
        Err(ExecuteError::UnsupportedType {
            param: 0,
            code: 0x42
        })
    );

    // params.rs:103 — the bound flag clear on the statement's first execute.
    let p = execute_payload(1, &[false], None, &[0; 4]);
    assert_eq!(
        parse_execute(&p, 1, None, &ld),
        Err(ExecuteError::NoBoundTypes)
    );

    // params.rs:127 — a LONG with two of its four bytes.
    let p = execute_payload(1, &[false], Some(&[(LONG, false)]), &[1, 2]);
    assert!(matches!(
        parse_execute(&p, 1, None, &ld),
        Err(ExecuteError::Truncated {
            field: "LONG value",
            needed: 4,
            remaining: 2
        })
    ));

    // A string whose 8-byte length claims 2^63 bytes.
    let mut v = vec![0xFE];
    v.extend_from_slice(&(1u64 << 63).to_le_bytes());
    v.extend_from_slice(b"abc");
    let p = execute_payload(1, &[false], Some(&[(VAR_STRING, false)]), &v);
    assert!(matches!(
        parse_execute(&p, 1, None, &ld),
        Err(ExecuteError::Truncated {
            field: "string value",
            needed,
            remaining: 3
        }) if needed == 1u64 << 63
    ));

    // u64::MAX: a length that would overflow any `usize` arithmetic done on it.
    let mut v = vec![0xFE];
    v.extend_from_slice(&u64::MAX.to_le_bytes());
    let p = execute_payload(1, &[false], Some(&[(VAR_STRING, false)]), &v);
    assert!(matches!(
        parse_execute(&p, 1, None, &ld),
        Err(ExecuteError::Truncated { .. })
    ));

    // A 2-byte length that runs past the packet.
    let p = execute_payload(
        1,
        &[false],
        Some(&[(VAR_STRING, false)]),
        &[0xFC, 0xE8, 0x03, b'a'],
    );
    assert!(matches!(
        parse_execute(&p, 1, None, &ld),
        Err(ExecuteError::Truncated {
            needed: 1000,
            remaining: 1,
            ..
        })
    ));

    // 0xFB and 0xFF are not lengths.
    for byte in [0xFBu8, 0xFF] {
        let p = execute_payload(1, &[false], Some(&[(VAR_STRING, false)]), &[byte, 0]);
        assert_eq!(
            parse_execute(&p, 1, None, &ld),
            Err(ExecuteError::BadLengthPrefix { param: 0, byte })
        );
    }

    // A temporal length the format does not define.
    let p = execute_payload(1, &[false], Some(&[(DATETIME, false)]), &[5, 0, 0, 0, 0, 0]);
    assert!(matches!(
        parse_execute(&p, 1, None, &ld),
        Err(ExecuteError::BadTemporalLength { len: 5, .. })
    ));

    // Bytes left over after the last value.
    let mut v = 7i32.to_le_bytes().to_vec();
    v.extend(lenenc_str(b"x"));
    v.push(0x00);
    let p = execute_payload(1, &[false, false], Some(&two), &v);
    assert_eq!(
        parse_execute(&p, 2, None, &ld),
        Err(ExecuteError::TrailingBytes { count: 1 })
    );

    // Shorter than the fixed header.
    assert!(matches!(
        parse_execute(&[1, 0, 0], 0, None, &ld),
        Err(ExecuteError::Truncated { .. })
    ));
}

/// Every prefix of a valid packet is refused, and none of them panics.
#[test]
fn every_truncation_of_a_valid_execute_is_refused() {
    let types = [(LONGLONG, false), (VAR_STRING, false), (TIME, false)];
    let mut v = 5i64.to_le_bytes().to_vec();
    v.extend(lenenc_str(b"hello"));
    v.extend_from_slice(&[12, 0, 2, 0, 0, 0, 1, 2, 3, 9, 0, 0, 0]);
    let p = execute_payload(3, &[false; 3], Some(&types), &v);
    let ld = no_long_data();
    assert!(parse_execute(&p, 3, None, &ld).is_ok());
    for cut in 0..p.len() {
        assert!(
            parse_execute(&p[..cut], 3, None, &ld).is_err(),
            "a {cut}-byte prefix of a {}-byte execute was accepted",
            p.len()
        );
    }
}

#[test]
fn long_data_takes_the_place_of_the_value_and_is_shown_as_a_bounded_prefix() {
    let mut ld = HashMap::new();
    let mut entry = LongData::default();
    let big = "é".repeat(2000); // 4000 bytes, two per character
    entry.append(big.as_bytes(), big.len() as u64);
    entry.append(b"more", 4);
    ld.insert(1u16, entry);

    // Parameter 1 (index 1) has long data, so only parameter 0's value is in the packet —
    // even though the bitmap marks parameter 1 NULL, as `mysqld` reads it.
    let p = execute_payload(
        4,
        &[false, true],
        Some(&[(LONG, false), (BLOB, false)]),
        &3i32.to_le_bytes(),
    );
    let req = parse_execute(&p, 2, None, &ld).expect("execute with long data");
    let json = params_json(&req);
    let shown = json[1]["value"].as_str().unwrap();
    assert!(shown.len() <= MAX_RENDERED_VALUE_BYTES);
    assert!(
        shown.chars().all(|c| c == 'é'),
        "cut on a character boundary"
    );
    assert_eq!(json[1]["long_data"], true);
    assert_eq!(json[1]["truncated"], true);
    assert_eq!(json[1]["byte_length"], 4004);
    assert!(json[1].get("not_utf8").is_none());
}

#[test]
fn the_rendered_query_cannot_be_mistaken_for_sql() {
    let sql = "SELECT * FROM t WHERE a = ? AND note = '?' AND b = ? -- ?\n AND c = ?";
    let offsets = placeholder_offsets(sql);
    assert_eq!(offsets.len(), 3);

    let mut v = 42i64.to_le_bytes().to_vec();
    v.extend(lenenc_str("it's ⟩ OR 1=1 ⟨".as_bytes()));
    let p = execute_payload(
        2,
        &[false, false, true],
        Some(&[(LONGLONG, false), (VAR_STRING, false), (NULL, false)]),
        &v,
    );
    let ld = no_long_data();
    let req = parse_execute(&p, 3, None, &ld).unwrap();
    let rendered = render_query(sql, &offsets, &req);
    assert_eq!(
        rendered,
        "SELECT * FROM t WHERE a = ⟨42⟩ AND note = '?' AND b = ⟨\"it's \\u27e9 OR 1=1 \\u27e8\"⟩ \
         -- ?\n AND c = ⟨NULL⟩"
    );
    // A value can never close its own bracket: exactly one ⟩ per placeholder.
    assert_eq!(rendered.matches('⟩').count(), 3);

    // A long string is cut and says so.
    let long = "x".repeat(MAX_RENDERED_VALUE_BYTES + 100);
    let mut v = vec![0xFC];
    v.extend_from_slice(&(long.len() as u16).to_le_bytes());
    v.extend_from_slice(long.as_bytes());
    let p = execute_payload(2, &[false], Some(&[(VAR_STRING, false)]), &v);
    let req = parse_execute(&p, 1, None, &ld).unwrap();
    let rendered = render_query("SELECT ?", &placeholder_offsets("SELECT ?"), &req);
    assert!(rendered.ends_with("\"…⟩"), "{rendered}");
    assert_eq!(params_json(&req)[0]["byte_length"], long.len());
}

#[test]
fn bound_types_must_cover_every_parameter_when_reused() {
    let ld = no_long_data();
    let previous = [ParamType {
        code: LONG,
        unsigned: false,
    }];
    let p = execute_payload(1, &[false, false], None, &[0; 8]);
    assert_eq!(
        parse_execute(&p, 2, Some(&previous), &ld),
        Err(ExecuteError::NoBoundTypes)
    );
}

// ---------------------------------------------------------------------------------------------
// The capture beneath opensrv-mysql
// ---------------------------------------------------------------------------------------------

fn packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut p = vec![
        (len & 0xFF) as u8,
        ((len >> 8) & 0xFF) as u8,
        ((len >> 16) & 0xFF) as u8,
        seq,
    ];
    p.extend_from_slice(payload);
    p
}

/// Read `stream` through a tap `chunk` bytes at a time, checking every byte passes unchanged.
async fn tap(stream: &[u8], chunk: usize) -> Arc<CommandTap> {
    let queue = Arc::new(CommandTap::default());
    let mut reader = CommandTapReader::new(stream, queue.clone());
    let mut out = Vec::with_capacity(stream.len());
    let mut buf = vec![0u8; chunk];
    loop {
        let n = reader.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    assert!(
        out == stream,
        "the tap must pass every byte through unchanged"
    );
    queue
}

/// One `COM_STMT_SEND_LONG_DATA` packet for `stmt`, parameter 0, carrying `len` bytes.
fn long_data(stmt: u32, len: usize) -> Vec<u8> {
    let mut body = vec![0x18];
    body.extend_from_slice(&stmt.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend(std::iter::repeat_n(b'd', len));
    packet(0, &body)
}

fn command(cmd: u8, stmt: u32, rest: &[u8]) -> Vec<u8> {
    let mut body = vec![cmd];
    body.extend_from_slice(&stmt.to_le_bytes());
    body.extend_from_slice(rest);
    packet(0, &body)
}

/// `opensrv-mysql` stores every long-data chunk with no limit (`lib.rs:663-678`), so the
/// chunks past the per-statement and per-connection bounds must never reach it. Read through
/// `LongDataGate` (bounds 100 and 150 bytes here) and the tap above it, exactly as the server
/// stacks them, and check what the crate would have been handed.
#[tokio::test]
async fn long_data_past_its_bounds_never_reaches_the_crate() {
    let exec = command(0x17, 1, &[0, 1, 0, 0, 0]);
    let close2 = command(0x19, 2, &[]);
    let admitted = [
        long_data(1, 60),      // statement 1: 60 of 100
        exec.clone(),          // releases statement 1
        long_data(1, 60),      // statement 1: 60 again
        long_data(2, 60),      // connection: 120 of 150
        close2.clone(),        // releases statement 2
        long_data(3, 60),      // connection: 120 of 150
        command(0x03, 0, &[]), // an unrelated command passes untouched
    ];
    let mut stream = Vec::new();
    stream.extend(long_data(1, 60));
    stream.extend(long_data(1, 60)); // statement 1 would hold 120: withheld
    stream.extend(exec.clone());
    stream.extend(long_data(1, 60));
    stream.extend(long_data(2, 60));
    stream.extend(long_data(4, 60)); // connection would hold 180: withheld
    stream.extend(close2.clone());
    stream.extend(long_data(3, 60));
    stream.extend(command(0x03, 0, &[]));
    let expected: Vec<u8> = admitted.concat();

    for chunk in [1usize, 3, 4096] {
        let queue = Arc::new(CommandTap::default());
        let gate = LongDataGate::with_limits(&stream[..], queue.clone(), 100, 150);
        let mut reader = CommandTapReader::new(gate, queue.clone());
        let mut out = Vec::new();
        let mut buf = vec![0u8; chunk];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert!(
            out == expected,
            "chunk {chunk}: the crate must see exactly the admitted packets ({} bytes, got {})",
            expected.len(),
            out.len()
        );
        let kinds: Vec<String> = queue
            .drain()
            .into_iter()
            .map(|c| match c {
                Captured::LongData { stmt_id, .. } => format!("data {stmt_id}"),
                Captured::LongDataRefused { stmt_id } => format!("refused {stmt_id}"),
                Captured::Execute(p) => format!("execute {}", p[0]),
                Captured::Reset { stmt_id } => format!("reset {stmt_id}"),
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "data 1",
                "refused 1",
                "execute 1",
                "data 1",
                "data 2",
                "refused 4",
                "data 3"
            ],
            "chunk {chunk}"
        );
    }
}

#[tokio::test]
async fn the_tap_captures_commands_and_nothing_else_at_any_split() {
    let exec1 = execute_payload(1, &[false], Some(&[(LONG, false)]), &5i32.to_le_bytes());
    let exec2 = execute_payload(2, &[], None, &[]);

    let mut stream = Vec::new();
    // A handshake response (sequence 1) that happens to begin 0x17: not a command.
    let mut handshake = vec![0x17];
    handshake.extend_from_slice(&[0u8; 40]);
    stream.extend(packet(1, &handshake));
    // A COM_QUERY: a command, but not one the tap keeps.
    stream.extend(packet(0, b"\x03SELECT 1"));
    // A short execute the crate's parser rejects (and answers OK without calling the shim).
    stream.extend(packet(0, &[0x17, 1, 0, 0, 0]));
    // Long data: the chunk is 2000 bytes; only a prefix is kept.
    let mut long = vec![0x18, 1, 0, 0, 0, 0, 0];
    long.extend(std::iter::repeat_n(b'z', 2000));
    stream.extend(packet(0, &long));
    // A reset, and two executes.
    stream.extend(packet(0, &[0x1A, 1, 0, 0, 0]));
    let mut e = vec![0x17];
    e.extend_from_slice(&exec1);
    stream.extend(packet(0, &e));
    let mut e = vec![0x17];
    e.extend_from_slice(&exec2);
    stream.extend(packet(0, &e));
    // An empty sequence-0 packet: nothing to capture, and it must not wedge the framing.
    stream.extend(packet(0, &[]));

    for chunk in [1usize, 2, 3, 7, 4096] {
        let q = tap(&stream, chunk).await;
        assert_eq!(q.queued(), 4, "chunk size {chunk}");

        let first = q.take_execute(1);
        assert_eq!(first.discarded, 0);
        assert_eq!(first.payload.as_deref(), Some(&exec1[..]));
        assert_eq!(first.preceding.len(), 2);
        match &first.preceding[0] {
            Captured::LongData {
                stmt_id,
                param,
                prefix,
                len,
            } => {
                assert_eq!((*stmt_id, *param, *len), (1, 0, 2000));
                assert_eq!(prefix.len(), MAX_RENDERED_VALUE_BYTES + 4);
            }
            other => panic!("expected long data, got {other:?}"),
        }
        assert_eq!(first.preceding[1], Captured::Reset { stmt_id: 1 });

        let second = q.take_execute(2);
        assert_eq!(second.payload.as_deref(), Some(&exec2[..]));
        assert_eq!(q.queued(), 0);
    }
}

#[tokio::test]
async fn an_execute_for_another_statement_is_discarded_not_paired() {
    let mut stream = Vec::new();
    for id in [7u32, 8] {
        let mut e = vec![0x17];
        e.extend_from_slice(&execute_payload(id, &[], None, &[]));
        stream.extend(packet(0, &e));
    }
    let q = tap(&stream, 4096).await;
    let got = q.take_execute(8);
    assert_eq!(got.discarded, 1);
    assert_eq!(&got.payload.unwrap()[..4], &8u32.to_le_bytes());
    let none = q.take_execute(8);
    assert!(none.payload.is_none(), "nothing left to pair");
}

#[tokio::test]
async fn a_fragmented_execute_is_captured_whole() {
    // First fragment exactly FULL_PACKET_PAYLOAD (which means "more follows"), then a
    // continuation with a higher sequence id: one logical packet.
    let mut body = vec![0x17];
    body.extend_from_slice(&execute_payload(3, &[], None, &[]));
    body.resize(FULL_PACKET_PAYLOAD + 10, 0xAB);
    let mut stream = packet(0, &body[..FULL_PACKET_PAYLOAD]);
    stream.extend(packet(1, &body[FULL_PACKET_PAYLOAD..]));
    let q = tap(&stream, 64 * 1024).await;
    assert_eq!(q.queued(), 1);
    let got = q.take_execute(3).payload.expect("captured");
    assert_eq!(got.len(), body.len() - 1);
    assert_eq!(&got[..], &body[1..]);
}

// ---------------------------------------------------------------------------------------------
// opensrv-mysql beneath the tap: one packet per read
// ---------------------------------------------------------------------------------------------

struct ProbeShim;

#[async_trait::async_trait]
impl<W: tokio::io::AsyncWrite + Send + Unpin> opensrv_mysql::AsyncMysqlShim<W> for ProbeShim {
    type Error = std::io::Error;

    async fn on_prepare<'a>(
        &'a mut self,
        _query: &'a str,
        info: opensrv_mysql::StatementMetaWriter<'a, W>,
    ) -> std::io::Result<()> {
        static PARAMS: std::sync::LazyLock<Vec<opensrv_mysql::Column>> =
            std::sync::LazyLock::new(|| {
                (0..2)
                    .map(|_| opensrv_mysql::Column {
                        table: String::new(),
                        column: "?".into(),
                        coltype: opensrv_mysql::ColumnType::MYSQL_TYPE_VAR_STRING,
                        colflags: opensrv_mysql::ColumnFlags::empty(),
                    })
                    .collect()
            });
        info.reply(1, &PARAMS[..], &[]).await
    }

    async fn on_execute<'a>(
        &'a mut self,
        _id: u32,
        _params: opensrv_mysql::ParamParser<'a>,
        results: opensrv_mysql::QueryResultWriter<'a, W>,
    ) -> std::io::Result<()> {
        results
            .completed(opensrv_mysql::OkResponse {
                affected_rows: 9,
                ..Default::default()
            })
            .await
    }

    async fn on_close(&mut self, _stmt: u32) {}

    async fn on_query<'a>(
        &'a mut self,
        _query: &'a str,
        results: opensrv_mysql::QueryResultWriter<'a, W>,
    ) -> std::io::Result<()> {
        results
            .completed(opensrv_mysql::OkResponse::default())
            .await
    }
}

async fn probe_read<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Option<(u8, Vec<u8>)> {
    let mut h = [0u8; 4];
    tokio::time::timeout(std::time::Duration::from_millis(500), r.read_exact(&mut h))
        .await
        .ok()?
        .ok()?;
    let n = u32::from_le_bytes([h[0], h[1], h[2], 0]) as usize;
    let mut p = vec![0u8; n];
    r.read_exact(&mut p).await.ok()?;
    Some((h[3], p))
}

/// Drive a bare `opensrv-mysql` server over an in-memory pipe, the way the MySQL server does:
/// with `CommandTapReader` directly beneath it.
///
/// The client writes two `COM_STMT_SEND_LONG_DATA` chunks back to back, which lands them in
/// one read for a reader that does not split them. `opensrv-mysql`'s `PacketReader` then
/// parses the first from a buffer it has just freed (see `command_tap`'s module docs); here
/// that came back as a stray OK packet for a command that has no reply, after which every
/// reply was one behind. Through the tap no read crosses a packet boundary, so the chunks get
/// no reply at all and the execute after them gets its own.
#[tokio::test]
async fn pipelined_commands_reach_opensrv_one_packet_per_read() {
    use tokio::io::AsyncWriteExt;
    let (client, server) = tokio::io::duplex(1 << 16);
    let (sr, sw) = tokio::io::split(server);
    let sr = CommandTapReader::new(sr, Arc::new(CommandTap::default()));
    tokio::spawn(opensrv_mysql::AsyncMysqlIntermediary::run_on(
        ProbeShim, sr, sw,
    ));
    let (mut cr, mut cw) = tokio::io::split(client);

    probe_read(&mut cr).await.expect("greeting");
    let caps: u32 = 0x1 | 0x200 | 0x2000 | 0x8000 | 0x8_0000 | 0x100_0000;
    let mut resp = caps.to_le_bytes().to_vec();
    resp.extend_from_slice(&(16u32 << 20).to_le_bytes());
    resp.push(33);
    resp.extend_from_slice(&[0u8; 23]);
    // The plugin opensrv's default shim offers, so it sends no AuthSwitchRequest.
    resp.extend_from_slice(b"root\0\0mysql_native_password\0");
    cw.write_all(&packet(1, &resp)).await.unwrap();
    assert_eq!(
        probe_read(&mut cr).await.map(|r| r.1[0]),
        Some(0x00),
        "auth OK"
    );

    cw.write_all(&packet(0, b"\x16SELECT ?, ?")).await.unwrap();
    for what in ["prepare OK", "parameter 1", "parameter 2"] {
        probe_read(&mut cr).await.expect(what);
    }

    let exec_head = b"\x17\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x08\x00\xfd\x00";
    let mut exec = exec_head.to_vec();
    exec.extend_from_slice(&7i64.to_le_bytes());
    exec.extend_from_slice(b"\x03bob");
    cw.write_all(&packet(0, &exec)).await.unwrap();
    assert_eq!(
        probe_read(&mut cr).await.map(|r| r.1),
        Some(vec![0, 9, 0, 0, 0, 0, 0]),
        "the first execute's own OK"
    );

    // Two long-data chunks and the execute that uses them, in a single write.
    let mut burst = packet(0, b"\x18\x01\x00\x00\x00\x01\x00hello");
    burst.extend(packet(0, b"\x18\x01\x00\x00\x00\x01\x00world"));
    let mut exec = exec_head.to_vec();
    exec.extend_from_slice(&9i64.to_le_bytes());
    burst.extend(packet(0, &exec));
    cw.write_all(&burst).await.unwrap();

    let mut replies = Vec::new();
    while let Some(r) = probe_read(&mut cr).await {
        replies.push(r);
    }
    assert_eq!(
        replies,
        vec![(1, vec![0, 9, 0, 0, 0, 0, 0])],
        "long data has no reply; only the execute is answered"
    );
}

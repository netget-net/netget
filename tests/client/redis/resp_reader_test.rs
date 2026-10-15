//! The Redis client's RESP reply reader and command splitter, fed bytes directly — no server,
//! no LLM calls.
//!
//! The reader decides what one `redis_response_received` event is, so its framing is pinned
//! here byte by byte, and so are its bounds: each bound was verified by removing it and watching
//! the matching test fail.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features redis --test client -- redis::resp_reader_test --test-threads=100

use netget::client::redis::resp::{
    encode_command, read_reply, split_command, MAX_AGGREGATE_LEN, MAX_REPLY_BYTES, MAX_REPLY_DEPTH,
};
use serde_json::json;

async fn read_all(bytes: &[u8]) -> Vec<(String, serde_json::Value, String)> {
    let mut reader = tokio::io::BufReader::new(bytes);
    let mut out = Vec::new();
    while let Some(reply) = read_reply(&mut reader).await.expect("well-formed") {
        out.push((reply.reply_type.to_string(), reply.value, reply.response));
    }
    out
}

async fn read_one_err(bytes: &[u8]) -> String {
    let mut reader = tokio::io::BufReader::new(bytes);
    match read_reply(&mut reader).await {
        Ok(r) => panic!("expected an error, got {r:?}"),
        Err(e) => e.to_string(),
    }
}

#[tokio::test]
async fn a_bulk_string_is_one_reply_not_two_lines() {
    // The shape that used to become two events: "$5" and then "hello".
    let replies = read_all(b"$5\r\nhello\r\n").await;
    assert_eq!(
        replies,
        vec![("bulk_string".into(), json!("hello"), "\"hello\"".into())]
    );

    // CRLF inside the value is part of the value, because the length says so.
    let replies = read_all(b"$7\r\na\r\nb\r\nc\r\n").await;
    assert_eq!(replies[0].1, json!("a\r\nb\r\nc"));
}

#[tokio::test]
async fn every_resp2_type_and_a_pipeline() {
    let replies = read_all(
        b"+OK\r\n-ERR unknown command\r\n:42\r\n$-1\r\n*-1\r\n$0\r\n\r\n*3\r\n$1\r\na\r\n:2\r\n*2\r\n+x\r\n$-1\r\n",
    )
    .await;
    let got: Vec<(&str, serde_json::Value, &str)> = replies
        .iter()
        .map(|(t, v, r)| (t.as_str(), v.clone(), r.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("simple_string", json!("OK"), "OK"),
            (
                "error",
                json!({"error": "ERR unknown command"}),
                "(error) ERR unknown command"
            ),
            ("integer", json!(42), "(integer) 42"),
            ("null", json!(null), "(nil)"),
            ("null", json!(null), "(nil)"),
            ("bulk_string", json!(""), "\"\""),
            (
                "array",
                json!(["a", 2, ["x", null]]),
                r#"["a",2,["x",null]]"#
            ),
        ]
    );
}

#[tokio::test]
async fn resp3_types_including_an_attribute_that_is_not_an_element() {
    let replies = read_all(
        b"%2\r\n+name\r\n$6\r\nvalkey\r\n+version\r\n:9\r\n\
          _\r\n#t\r\n,3.5\r\n(123456789012345678901234567890\r\n=8\r\ntxt:hi!!\r\n\
          ~2\r\n:1\r\n:2\r\n>2\r\n+message\r\n+hi\r\n\
          *2\r\n|1\r\n+ttl\r\n:10\r\n:1\r\n:2\r\n",
    )
    .await;
    let types: Vec<&str> = replies.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(
        types,
        vec![
            "map",
            "null",
            "boolean",
            "double",
            "big_number",
            "verbatim_string",
            "set",
            "push",
            "array"
        ]
    );
    assert_eq!(replies[0].1, json!({"name": "valkey", "version": 9}));
    assert_eq!(replies[3].1, json!(3.5));
    assert_eq!(replies[5].1, json!("hi!!"));
    // The attribute before the first element was read and dropped, and did not count as one.
    assert_eq!(replies[8].1, json!([1, 2]));
}

#[tokio::test]
async fn nesting_deeper_than_the_bound_is_refused() {
    let mut ok = Vec::new();
    for _ in 0..MAX_REPLY_DEPTH {
        ok.extend_from_slice(b"*1\r\n");
    }
    ok.extend_from_slice(b":1\r\n");
    let replies = read_all(&ok).await;
    assert_eq!(
        replies.len(),
        1,
        "{MAX_REPLY_DEPTH} levels must still parse"
    );

    // Four bytes a level: this is ~40 KB, and would build a Value too deep to serialise or drop.
    let mut bomb = Vec::new();
    for _ in 0..10_000 {
        bomb.extend_from_slice(b"*1\r\n");
    }
    bomb.extend_from_slice(b":1\r\n");
    let err = read_one_err(&bomb).await;
    assert!(err.contains("nests deeper"), "{err}");
}

#[tokio::test]
async fn a_declared_size_over_the_limit_is_refused_before_allocating() {
    // Thirty bytes on the wire declaring a multi-gigabyte string. Nothing follows the header,
    // so a reader that allocated first and checked later would block or abort here.
    let err = read_one_err(format!("${}\r\n", u32::MAX).as_bytes()).await;
    assert!(err.contains("reply limit"), "{err}");

    let err = read_one_err(format!("${}\r\n", MAX_REPLY_BYTES).as_bytes()).await;
    assert!(err.contains("reply limit"), "{err}");

    let err = read_one_err(format!("*{}\r\n", MAX_AGGREGATE_LEN + 1).as_bytes()).await;
    assert!(err.contains("elements"), "{err}");
}

#[tokio::test]
async fn malformed_replies_are_errors_not_guesses() {
    assert!(read_one_err(b"?what\r\n")
        .await
        .contains("not a RESP reply"));
    assert!(read_one_err(b"$3\r\nabcX\n").await.contains("CRLF"));
    assert!(read_one_err(b"*2\r\n:1\r\n")
        .await
        .contains("middle of a reply"));
    assert!(read_one_err(b":notanumber\r\n").await.contains("bad RESP"));
}

#[test]
fn commands_split_the_way_redis_cli_splits_them() {
    let s = |line: &str| -> Vec<String> {
        split_command(line)
            .expect("valid")
            .into_iter()
            .map(|a| String::from_utf8(a).unwrap())
            .collect()
    };
    assert_eq!(s("GET key"), vec!["GET", "key"]);
    assert_eq!(s("  SET   k   v  "), vec!["SET", "k", "v"]);
    assert_eq!(
        s(r#"SET greeting "hello world""#),
        vec!["SET", "greeting", "hello world"]
    );
    assert_eq!(s("SET key1 'value1'"), vec!["SET", "key1", "value1"]);
    assert_eq!(s(r#"SET k "a\"b\n""#), vec!["SET", "k", "a\"b\n"]);
    assert_eq!(s(r"SET k 'it\'s'"), vec!["SET", "k", "it's"]);
    assert_eq!(s(r#"SET k "\x41\x42""#), vec!["SET", "k", "AB"]);
    assert_eq!(s(r#"SET k """#), vec!["SET", "k", ""]);

    assert!(split_command(r#"SET k "unterminated"#).is_err());
    assert!(split_command("SET k 'unterminated").is_err());
    assert!(split_command(r#"SET k "a"b"#).is_err());
    assert!(split_command("   ").is_err());

    assert_eq!(
        encode_command(&split_command(r#"SET k "a b""#).unwrap()),
        b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$3\r\na b\r\n".to_vec()
    );
}

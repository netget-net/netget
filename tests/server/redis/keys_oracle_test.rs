//! `utils::redis_keys` against a real `redis-server` as the oracle: the hash slot NetGet
//! computes for a key must equal what Redis's own `CLUSTER KEYSLOT` answers, and the set of
//! keys a glob pattern matches must equal what Redis's own `KEYS <pattern>` returns — both
//! run Redis's C code (`keyHashSlot`, `stringmatchlen`), which shares nothing with ours.
//!
//! A slot that disagrees sends a cluster client to the wrong node forever; a pattern that
//! disagrees delivers a message to a subscriber that did not ask for it, or withholds it from
//! one that did. Each key below was chosen to exercise a rule: braces in every position and
//! count, empty tags, the escape and class syntax, unterminated classes and reversed ranges.
//!
//! `redis-server` is required; the test fails rather than skips without it.

use crate::helpers::real_server::{InstallHint, RealServer};
use netget::client::redis::resp::{encode_command, read_reply};
use netget::utils::redis_keys::{crc16, glob_match, key_hash_slot};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const REDIS_SERVER: InstallHint = InstallHint {
    brew: "valkey",
    apt: "redis-server",
};

fn keys() -> Vec<Vec<u8>> {
    let mut keys: Vec<Vec<u8>> = [
        "foo",
        "bar",
        "hello",
        "hallo",
        "hbllo",
        "hillo",
        "heeeello",
        "123456789",
        "{user1000}.following",
        "{user1000}.followers",
        "foo{}{bar}",
        "foo{{bar}}zap",
        "foo{bar}{zap}",
        "{}",
        "{",
        "}",
        "}{",
        "{a",
        "a}",
        "{}a",
        "a{b}c{d}",
        "*",
        "]",
        "[",
        "a[",
        "\\",
        "a\\b",
        "-",
        "^",
        "a-",
        "a",
        "ab",
        "abc",
        "news.sports",
        "news",
        "news.",
        "ключ",
        "{ключ}x",
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect();
    for i in 0..1500u32 {
        let k = match i % 5 {
            0 => format!("k:{i}:{}", i.wrapping_mul(7919)),
            1 => format!("{{tag{}}}:{i}", i % 37),
            2 => format!("x{}{{{}}}y{i}", i % 11, i % 13),
            3 => format!("{i}}}{{{}", i * 3),
            _ => format!("user:{i}:{{}}"),
        };
        keys.push(k.into_bytes());
    }
    keys.push(vec![0xff, 0x00, b'{', 0x80, b'}']);
    keys
}

const PATTERNS: &[&str] = &[
    "*",
    "h?llo",
    "h*llo",
    "h[ae]llo",
    "h[^e]llo",
    "h[a-b]llo",
    "h[b-a]llo",
    "\\*",
    "[\\]]",
    "*{*}*",
    "k:1*",
    "k:?:*",
    "[",
    "a[",
    "[abc",
    "*[",
    "**a",
    "\\",
    "a\\",
    "a\\\\b",
    "[\\",
    "[a-",
    "[-a]",
    "[^]",
    "[]",
    "*\\{*",
    "news*",
    "news.*",
    "n?ws.*",
    "{*",
    "*}",
    "[{}]*",
    "user:1?:*",
    "x[0-9]{1*",
    "[a-c]*",
    "[^a-c]*",
];

async fn pipeline(port: u16, commands: &[Vec<Vec<u8>>]) -> Vec<serde_json::Value> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (r, mut w) = stream.into_split();
    let mut out = Vec::new();
    for c in commands {
        out.extend(encode_command(c));
    }
    let writer = tokio::spawn(async move {
        w.write_all(&out).await.unwrap();
        w
    });
    let mut reader = BufReader::new(r);
    let mut replies = Vec::new();
    for _ in commands {
        let reply = tokio::time::timeout(Duration::from_secs(30), read_reply(&mut reader))
            .await
            .expect("redis-server did not answer")
            .unwrap()
            .unwrap();
        replies.push(reply.value);
    }
    drop(writer.await.unwrap());
    replies
}

#[tokio::test]
async fn hash_slots_and_glob_matching_agree_with_redis_server() {
    // The published vectors first: the CRC16 check value, and the slots Redis's own
    // documentation gives.
    assert_eq!(crc16(b"123456789"), 0x31C3);
    assert_eq!(key_hash_slot(b"foo"), 12182);
    assert_eq!(key_hash_slot(b"bar"), 5061);
    assert_eq!(key_hash_slot(b"hello"), 866);

    let cluster = RealServer::builder("redis-server", REDIS_SERVER)
        .args([
            "--port",
            "{port}",
            "--bind",
            "127.0.0.1",
            "--save",
            "",
            "--appendonly",
            "no",
            "--dir",
            "{dir}",
            "--cluster-enabled",
            "yes",
            "--cluster-config-file",
            "{dir}/nodes.conf",
            "--cluster-port",
            "{port1}",
        ])
        .extra_ports(1)
        .ready_when_log_matches("Ready to accept connections")
        .start()
        .await
        .unwrap();
    let keys = keys();
    let commands: Vec<Vec<Vec<u8>>> = keys
        .iter()
        .map(|k| vec![b"CLUSTER".to_vec(), b"KEYSLOT".to_vec(), k.clone()])
        .collect();
    let slots = pipeline(cluster.port, &commands).await;
    let mut checked = 0;
    for (key, slot) in keys.iter().zip(slots) {
        assert_eq!(
            slot.as_u64(),
            Some(u64::from(key_hash_slot(key))),
            "slot of {:?}: redis-server says {slot}",
            String::from_utf8_lossy(key)
        );
        checked += 1;
    }
    assert_eq!(checked, keys.len());

    let standalone = RealServer::builder("redis-server", REDIS_SERVER)
        .args([
            "--port",
            "{port}",
            "--bind",
            "127.0.0.1",
            "--save",
            "",
            "--appendonly",
            "no",
            "--dir",
            "{dir}",
        ])
        .ready_when_log_matches("Ready to accept connections")
        .start()
        .await
        .unwrap();
    let mut setup: Vec<Vec<Vec<u8>>> = keys
        .iter()
        .map(|k| vec![b"SET".to_vec(), k.clone(), b"1".to_vec()])
        .collect();
    setup.push(vec![b"DBSIZE".to_vec()]);
    let replies = pipeline(standalone.port, &setup).await;
    assert_eq!(replies.last().unwrap().as_u64(), Some(keys.len() as u64));

    let queries: Vec<Vec<Vec<u8>>> = PATTERNS
        .iter()
        .map(|p| vec![b"KEYS".to_vec(), p.as_bytes().to_vec()])
        .collect();
    let answers = pipeline(standalone.port, &queries).await;
    for (pattern, answer) in PATTERNS.iter().zip(answers) {
        let theirs: BTreeSet<String> = answer
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let ours: BTreeSet<String> = keys
            .iter()
            .filter(|k| glob_match(pattern.as_bytes(), k))
            .map(|k| String::from_utf8_lossy(k).to_string())
            .collect();
        assert_eq!(
            ours, theirs,
            "pattern {pattern:?}: NetGet and redis-server disagree"
        );
    }

    // Redis's own quirk, kept: the empty string matches only the empty pattern.
    assert!(!glob_match(b"*", b""));
    assert!(glob_match(b"", b""));

    // A pattern built to make a backtracking matcher explode costs a bounded number of steps.
    let pattern = "*a".repeat(64) + "b";
    let subject = "a".repeat(1024);
    let started = Instant::now();
    assert!(!glob_match(pattern.as_bytes(), subject.as_bytes()));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the matcher took {:?} on a pathological pattern",
        started.elapsed()
    );
}

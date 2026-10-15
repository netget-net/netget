//! One UDP datagram used to kill the whole netget process.
//!
//! `serde_bencode` 0.2 has no depth limit anywhere. `Deserializer::deserialize_any` recurses
//! into `visit_seq`/`visit_map` for every `l` or `d` byte, and a *typed* decode reaches the
//! same code through serde's `IgnoredAny` when it skips an unknown field — so
//! `from_bytes::<DhtMessage>` is no safer than `from_bytes::<Value>`. Bencode opens a nesting
//! level in **one byte**, which is what makes the cost to an attacker so small.
//!
//! Measured against 0.2.4, decoding `l` repeated N times on a thread of a given stack size:
//!
//! | nesting | stack | result |
//! |---|---|---|
//! | 800 | 2 MiB (a tokio worker) | returns `Err("End of stream")` |
//! | 1,000 | 2 MiB | **`fatal runtime error: stack overflow, aborting`** |
//! | 9,215 | 8 MiB (a main thread) | **`fatal runtime error: stack overflow, aborting`** |
//!
//! So roughly **one kilobyte on the wire** is enough, and 9,215 bytes — the largest UDP
//! datagram macOS will send, `net.inet.udp.maxdgram` being 9216 — overflows even the main
//! thread. **This is not a panic.** A Rust stack overflow is a `SIGSEGV` against the guard
//! page: `tokio::spawn` cannot contain it, `catch_unwind` cannot see it, and the server does
//! not merely drop the datagram — the process dies. The DHT server reads from an
//! unauthenticated UDP socket, so the whole cost to an attacker is one `sendto`.
//!
//! [`netget::utils::bencode::check_bencode_structure`] walks the bytes iteratively first and
//! refuses anything nested past the limit, so nothing `serde_bencode` cannot survive reaches
//! it.
//!
//! The wire test below is the one that matters, and its shape is deliberate: **it proves the
//! process is still alive** by asking the same server a second, well-formed question after
//! the bomb and requiring an answer. Asserting only that the bomb produced no reply would
//! pass just as happily against a server that had died. To see it fail, delete the
//! `check_bencode_structure` call in `src/server/torrent_dht/mod.rs::parse_krpc_message` —
//! the second query then times out, because there is no longer a process to answer it.

use crate::helpers::*;
use ::netget::utils::bencode::{
    check_bencode_structure, check_bencode_structure_with_limit, BencodeStructureError,
    MAX_BENCODE_DEPTH,
};
use serde_bencode::value::Value;
use std::collections::HashMap;
use std::time::Duration;
use tokio::net::UdpSocket;

/// As many nesting levels as fit in one UDP datagram the OS will actually send.
///
/// `net.inet.udp.maxdgram` is 9216 by default on macOS, so a larger buffer is refused by
/// `send_to` with `EMSGSIZE` and never reaches the server — which is why this is not the
/// 65 KB a `recv_from` buffer would suggest. It does not need to be: 1,000 levels already
/// overflows a 2 MiB tokio worker, so 9,000 is nine times over.
const BOMB_DEPTH: usize = 9_000;

fn depth_bomb() -> Vec<u8> {
    let mut data = vec![b'l'; BOMB_DEPTH];
    data.push(b'e');
    data
}

/// A well-formed KRPC ping query with the given transaction id.
fn ping_query(transaction_id: &[u8]) -> Vec<u8> {
    let mut query = HashMap::new();
    query.insert(b"t".to_vec(), Value::Bytes(transaction_id.to_vec()));
    query.insert(b"y".to_vec(), Value::Bytes(b"q".to_vec()));
    query.insert(b"q".to_vec(), Value::Bytes(b"ping".to_vec()));
    let mut args = HashMap::new();
    args.insert(
        b"id".to_vec(),
        Value::Bytes(b"abcdefghij0123456789".to_vec()),
    );
    query.insert(b"a".to_vec(), Value::Dict(args));
    serde_bencode::to_bytes(&Value::Dict(query)).expect("a KRPC ping always encodes")
}

/// The guard refuses the bomb, and still accepts everything the protocols actually send.
///
/// Both halves are load-bearing. A guard that refused everything would satisfy the first
/// assertion and break every real exchange, which is why a real KRPC query is checked here
/// and why the e2e suite still passes.
#[test]
fn test_guard_refuses_depth_bomb_and_accepts_real_krpc() {
    assert_eq!(
        check_bencode_structure(&depth_bomb()),
        Err(BencodeStructureError::TooDeep {
            limit: MAX_BENCODE_DEPTH
        }),
        "9,000 nested lists must be refused before serde_bencode sees them"
    );

    check_bencode_structure(&ping_query(b"aa"))
        .expect("a real KRPC ping query must pass the guard untouched");

    // The deepest shape KRPC defines: outer dict, `r` dict, a list of nodes, a node dict.
    let mut node = HashMap::new();
    node.insert(b"id".to_vec(), Value::Bytes(vec![0u8; 20]));
    let mut r = HashMap::new();
    r.insert(b"nodes".to_vec(), Value::List(vec![Value::Dict(node)]));
    let mut reply = HashMap::new();
    reply.insert(b"t".to_vec(), Value::Bytes(b"aa".to_vec()));
    reply.insert(b"y".to_vec(), Value::Bytes(b"r".to_vec()));
    reply.insert(b"r".to_vec(), Value::Dict(r));
    let encoded = serde_bencode::to_bytes(&Value::Dict(reply)).expect("encodes");
    check_bencode_structure(&encoded)
        .expect("a four-level find_node reply is well within the limit");
}

/// The boundary is where it says it is, in both directions.
#[test]
fn test_guard_boundary_is_exact() {
    // `limit` levels of list, closed. Accepted.
    let mut at_limit = vec![b'l'; MAX_BENCODE_DEPTH];
    at_limit.extend(std::iter::repeat(b'e').take(MAX_BENCODE_DEPTH));
    check_bencode_structure(&at_limit).expect("exactly the limit must be accepted");

    // One more. Refused.
    let mut over = vec![b'l'; MAX_BENCODE_DEPTH + 1];
    over.extend(std::iter::repeat(b'e').take(MAX_BENCODE_DEPTH + 1));
    assert_eq!(
        check_bencode_structure(&over),
        Err(BencodeStructureError::TooDeep {
            limit: MAX_BENCODE_DEPTH
        })
    );

    // An explicit small limit, so the constant is not the only thing under test.
    assert_eq!(
        check_bencode_structure_with_limit(b"llee", 1),
        Err(BencodeStructureError::TooDeep { limit: 1 })
    );
    check_bencode_structure_with_limit(b"llee", 2).expect("depth 2 under a limit of 2");
}

/// The other half of the pair of defects this programme keeps finding: a declared length
/// trusted without being checked against the bytes that actually arrived.
#[test]
fn test_guard_bounds_declared_length_against_the_input() {
    // A byte string claiming 4 GB, in eleven bytes on the wire.
    assert!(matches!(
        check_bencode_structure(b"d1:x4000000000:"),
        Err(BencodeStructureError::BadLength)
    ));

    // A length that fits in a usize but not in this datagram.
    assert!(matches!(
        check_bencode_structure(b"d1:x20:short"),
        Err(BencodeStructureError::BadLength | BencodeStructureError::Truncated)
    ));

    // Structural nonsense is refused rather than passed along.
    assert_eq!(
        check_bencode_structure(b"e"),
        Err(BencodeStructureError::UnbalancedEnd)
    );
    assert_eq!(
        check_bencode_structure(b""),
        Err(BencodeStructureError::Empty)
    );
    assert!(matches!(
        check_bencode_structure(b"d1:x"),
        Err(BencodeStructureError::Truncated)
    ));
}

/// End to end, over the wire, against the real server.
///
/// Send the bomb, then send a real ping to the **same** server and require an answer. The
/// second half is the assertion: it can only be satisfied by a process that is still running.
#[tokio::test]
async fn test_dht_server_survives_a_depth_bomb_datagram() -> E2EResult<()> {
    let config = NetGetConfig::new_no_scripts(
        "Listen on port {AVAILABLE_PORT} via torrent-dht and answer DHT queries.".to_string(),
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("torrent-dht")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "Torrent-DHT",
                "instruction": "DHT node for peer discovery"
            }]))
            .expect_calls(1)
            .and()
            // Echoing the transaction id from the event is required for UDP-style
            // protocols: a hardcoded id would be discarded by the querying socket.
            .on_event("dht_ping_query")
            .respond_with_actions_from_event(|e| {
                serde_json::json!([{
                    "type": "send_ping_response",
                    "transaction_id": e["transaction_id"].as_str().unwrap_or(""),
                    "node_id": "0000000000000000000000000000000000000000"
                }])
            })
            // Exactly one: the bomb must be refused during parsing, before any event is
            // raised, so it must not add a second call here.
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let dht_addr = format!("127.0.0.1:{}", server.port);

    socket.send_to(&depth_bomb(), &dht_addr).await?;

    // Give the server a moment to have died, if it is going to. Without the guard this is
    // where the process aborts; the wait is not a synchronisation point for the assertion
    // below, which has its own generous timeout, only a way to make the failure prompt.
    tokio::time::sleep(Duration::from_millis(300)).await;

    socket.send_to(&ping_query(b"zz"), &dht_addr).await?;

    let mut buf = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(30), socket.recv_from(&mut buf))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no reply to a well-formed ping sent after the depth bomb — the bomb took the \
                 netget process down with it, which is exactly the defect the guard exists for",
            )
        })??;

    let dict = match serde_bencode::from_bytes::<Value>(&buf[..n])? {
        Value::Dict(d) => d,
        other => panic!("KRPC reply must be a dictionary, got {:?}", other),
    };
    assert_eq!(
        match dict.get(b"t" as &[u8]) {
            Some(Value::Bytes(b)) => b.clone(),
            _ => Vec::new(),
        },
        b"zz".to_vec(),
        "the surviving server must answer the second query, echoing its transaction id"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

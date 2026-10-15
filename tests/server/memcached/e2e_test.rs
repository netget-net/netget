//! Memcached server tests.
//!
//! Two layers:
//!
//! 1. **Parser and framer against literal bytes**, including the case every memcached
//!    implementation gets wrong once — a stored value that itself contains CRLF.
//! 2. **End to end through the real binary** with the LLM mocked, driven by a raw socket
//!    (exact framing) and, in `real_client_test.rs`, by libmemcached's C tools.
//!
//! There is also a test that this server really does store nothing, because "the model is
//! the cache" is the design claim and an accidental cache would silently invalidate it.

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use netget::server::memcached::protocol::{
    self, encode_stats, encode_values, parse_command, Command, Parsed, ValueItem,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ===========================================================================
// Layer 1 — parsing and framing
// ===========================================================================

fn expect_complete(input: &[u8]) -> (Command, usize) {
    match parse_command(input) {
        Parsed::Complete { command, consumed } => (command, consumed),
        other => panic!("expected a complete command, got {:?}", other),
    }
}

#[test]
fn parses_a_multi_key_get() {
    let (command, consumed) = expect_complete(b"get alpha beta gamma\r\n");
    assert_eq!(consumed, 22);
    match command {
        Command::Retrieval { command, keys } => {
            assert_eq!(command, "get");
            assert_eq!(keys, vec!["alpha", "beta", "gamma"]);
        }
        other => panic!("wrong command: {:?}", other),
    }
}

#[test]
fn distinguishes_gets_from_get() {
    let (command, _) = expect_complete(b"gets alpha\r\n");
    match command {
        Command::Retrieval { command, .. } => assert_eq!(command, "gets"),
        other => panic!("wrong command: {:?}", other),
    }
}

/// **The classic memcached implementation bug.** The data block is delimited by its declared
/// byte count, not by scanning for CRLF. A value containing CRLF must survive intact; a
/// server that scans desynchronises its parser for the rest of the connection.
#[test]
fn a_stored_value_may_contain_crlf() {
    let payload = b"line one\r\nline two";
    let mut input = format!("set doc 0 0 {}\r\n", payload.len()).into_bytes();
    input.extend_from_slice(payload);
    input.extend_from_slice(b"\r\n");
    let total = input.len();
    // A second command right behind it, to prove the framing left the stream aligned.
    input.extend_from_slice(b"version\r\n");

    let (command, consumed) = expect_complete(&input);
    assert_eq!(consumed, total, "must consume exactly the storage frame");
    match command {
        Command::Storage {
            command,
            key,
            bytes,
            data,
            ..
        } => {
            assert_eq!(command, "set");
            assert_eq!(key, "doc");
            assert_eq!(bytes, payload.len());
            assert_eq!(data, payload, "the embedded CRLF must survive");
        }
        other => panic!("wrong command: {:?}", other),
    }

    let (next, _) = expect_complete(&input[consumed..]);
    assert_eq!(next, Command::Version, "the stream must still be aligned");
}

#[test]
fn a_storage_command_is_incomplete_until_the_whole_data_block_arrives() {
    let full = b"set k 0 0 5\r\nhello\r\n";
    for cut in 0..full.len() {
        assert!(
            matches!(parse_command(&full[..cut]), Parsed::Incomplete),
            "prefix of {} bytes must be Incomplete, not a partial command",
            cut
        );
    }
    assert!(matches!(parse_command(full), Parsed::Complete { .. }));
}

#[test]
fn parses_cas_with_its_unique() {
    let (command, _) = expect_complete(b"cas k 7 0 2 12345 noreply\r\nhi\r\n");
    match command {
        Command::Storage {
            command,
            flags,
            cas_unique,
            noreply,
            data,
            ..
        } => {
            assert_eq!(command, "cas");
            assert_eq!(flags, 7);
            assert_eq!(cas_unique, Some(12345));
            assert!(noreply);
            assert_eq!(data, b"hi");
        }
        other => panic!("wrong command: {:?}", other),
    }
}

#[test]
fn parses_the_remaining_verbs() {
    assert!(matches!(
        expect_complete(b"delete k\r\n").0,
        Command::Delete { .. }
    ));
    assert!(matches!(
        expect_complete(b"incr counter 5\r\n").0,
        Command::Arithmetic { delta: 5, .. }
    ));
    assert!(matches!(
        expect_complete(b"decr counter 2\r\n").0,
        Command::Arithmetic { delta: 2, .. }
    ));
    assert!(matches!(
        expect_complete(b"touch k 60\r\n").0,
        Command::Touch { exptime: 60, .. }
    ));
    assert!(matches!(
        expect_complete(b"stats items\r\n").0,
        Command::Stats { .. }
    ));
    assert_eq!(expect_complete(b"version\r\n").0, Command::Version);
    assert!(matches!(
        expect_complete(b"flush_all 30\r\n").0,
        Command::FlushAll { delay: 30, .. }
    ));
    assert_eq!(expect_complete(b"quit\r\n").0, Command::Quit);
    assert!(matches!(
        expect_complete(b"frobnicate x\r\n").0,
        Command::Unknown { .. }
    ));
}

#[test]
fn rejects_oversized_keys_and_malformed_storage_headers() {
    let long_key = "k".repeat(protocol::MAX_KEY_LEN + 1);
    assert!(matches!(
        parse_command(format!("get {}\r\n", long_key).as_bytes()),
        Parsed::Invalid { .. }
    ));
    assert!(matches!(parse_command(b"get\r\n"), Parsed::Invalid { .. }));

    // A retrieval command is one CRLF-terminated line, so `Invalid` can skip it and the
    // connection carries on. A *storage* command is not self-delimiting, which is what the
    // next two tests are about.
    assert!(matches!(
        parse_command(b"set k notanumber 0 5\r\nhello\r\n"),
        Parsed::Invalid { .. }
    ));
}

/// **The data block of a rejected storage command must be consumed with it.**
///
/// A storage command is `<header>\r\n<bytes octets>\r\n`. Rejecting the header and consuming
/// only the header leaves those octets at the front of the buffer, where the next
/// `parse_command` reads them as commands — so a peer chooses what runs. Upstream memcached
/// avoids this by swallowing exactly `<bytes> + 2` octets.
///
/// `flags` is `notanumber` here, so the header is rejected; the payload is a perfectly valid
/// `version\r\n` command line, which is what would have been executed.
#[test]
fn a_rejected_storage_header_consumes_its_data_block_rather_than_leaving_it_as_commands() {
    const FRAME: &[u8] = b"set k notanumber 0 9\r\nversion\r\n\r\n";

    let Parsed::Invalid { consumed, .. } = parse_command(FRAME) else {
        panic!("expected the malformed header to be rejected");
    };
    assert_eq!(
        consumed,
        FRAME.len(),
        "the rejection must consume the header AND its {}-octet data block AND the trailing \
         CRLF; consuming only the header leaves `version\\r\\n` to be parsed as a command",
        9
    );

    // Nothing is left over, so nothing smuggled through.
    assert!(matches!(
        parse_command(&FRAME[consumed..]),
        Parsed::Incomplete
    ));
}

/// Where `<bytes>` itself is unusable there is no boundary to skip to, so the only safe exit
/// is to reply and close. Guessing a boundary is the smuggling bug above.
#[test]
fn a_storage_command_whose_length_is_unusable_is_fatal_rather_than_guessed() {
    // No `<bytes>` field at all.
    assert!(matches!(
        parse_command(b"set k 0 0\r\n"),
        Parsed::Fatal { .. }
    ));
    // `<bytes>` present but not a number.
    assert!(matches!(
        parse_command(b"set k 0 0 notanumber\r\nhello\r\n"),
        Parsed::Fatal { .. }
    ));
    // Larger than the cap: skipping it would mean buffering an arbitrary number of octets
    // purely to throw them away, which is the allocation the cap exists to prevent.
    assert!(matches!(
        parse_command(format!("set k 0 0 {}\r\n", protocol::MAX_VALUE_LEN + 1).as_bytes()),
        Parsed::Fatal { .. }
    ));
    // `cas` needs six fields, but five is enough to know the length, so it stays skippable.
    assert!(matches!(
        parse_command(b"cas k 0 0 5\r\nhello\r\n"),
        Parsed::Invalid { .. }
    ));
}

/// The reply framing, byte for byte. `<bytes>` must be the payload's real length: a count
/// that disagrees desynchronises the client for the rest of the connection.
#[test]
fn frames_values_exactly() {
    let items = vec![
        ValueItem {
            key: "greeting".to_string(),
            flags: 0,
            data: b"hello world".to_vec(),
            cas_unique: None,
        },
        ValueItem {
            key: "binary".to_string(),
            flags: 42,
            data: vec![0x00, 0x01, 0xff],
            cas_unique: None,
        },
    ];
    assert_eq!(
        encode_values(&items, false),
        b"VALUE greeting 0 11\r\nhello world\r\nVALUE binary 42 3\r\n\x00\x01\xff\r\nEND\r\n"
            .to_vec()
    );
}

#[test]
fn frames_gets_with_the_cas_unique() {
    let items = vec![ValueItem {
        key: "k".to_string(),
        flags: 0,
        data: b"v".to_vec(),
        cas_unique: Some(99),
    }];
    assert_eq!(
        encode_values(&items, true),
        b"VALUE k 0 1 99\r\nv\r\nEND\r\n".to_vec()
    );
}

#[test]
fn a_cache_miss_is_end_alone() {
    assert_eq!(encode_values(&[], false), b"END\r\n".to_vec());
}

#[test]
fn frames_stats() {
    let entries = vec![
        ("pid".to_string(), "1".to_string()),
        ("uptime".to_string(), "3600".to_string()),
    ];
    assert_eq!(
        encode_stats(&entries),
        b"STAT pid 1\r\nSTAT uptime 3600\r\nEND\r\n".to_vec()
    );
}

/// The design claim, asserted rather than merely documented: nothing in this protocol's
/// source stores anything. If someone adds a cache, this fails and they must argue for it.
#[test]
fn the_protocol_implements_no_storage() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server/memcached");
    for entry in std::fs::read_dir(&dir).expect("memcached source directory") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).unwrap();
        // Strip comments and doc comments: this file, and the module docs, talk *about*
        // HashMap precisely to say there isn't one.
        let code: String = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in ["HashMap", "BTreeMap", "DashMap", "std::fs::"] {
            assert!(
                !code.contains(forbidden),
                "{} contains `{}`. Memcached must not implement storage — the model \
                 answers every get. If persistence is genuinely needed, use the generic \
                 SQLite facility in src/state/sqlite.rs, which the model opts into at \
                 runtime.",
                path.display(),
                forbidden
            );
        }
    }
}

// ===========================================================================
// Layer 2 — end to end through the real binary, LLM mocked
// ===========================================================================

/// Open a connection, write `request`, and read until `terminator` appears.
async fn exchange(port: u16, request: &[u8], terminator: &[u8]) -> E2EResult<Vec<u8>> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
    stream.write_all(request).await?;
    stream.flush().await?;

    let mut buffer = Vec::new();
    let mut chunk = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "timed out; got so far: {:?}",
                String::from_utf8_lossy(&buffer)
            )
            .into());
        }
        let n = tokio::time::timeout(remaining, stream.read(&mut chunk))
            .await
            .map_err(|_| "timed out waiting for a memcached reply")??;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..n]);
        if buffer.windows(terminator.len()).any(|w| w == terminator) {
            break;
        }
    }

    // The pcap oracle. Wireshark's `memcache` dissector reads the text protocol's
    // framing independently: the command line, the `VALUE <key> <flags> <bytes>`
    // header and the data block whose length that header declares. This suite's
    // central hazard is a byte count that disagrees with the block it introduces —
    // `set_with_an_embedded_crlf_is_counted_not_scanned` is exactly that — and a
    // second reader of the same rule is worth having.
    crate::helpers::pcap_oracle::PcapOracle::tcp("memcached")
        .to_server(request)
        .from_server(&buffer)
        .assert_clean();

    Ok(buffer)
}

fn startup_mock(instruction: &str) -> serde_json::Value {
    serde_json::json!([{
        "type": "open_server",
        "port": 0,
        "base_stack": "memcached",
        "instruction": instruction
    }])
}

/// A hit and a miss, framed exactly. The mock derives its answer from the event's `keys`,
/// so a server that parsed the keys wrongly turns this red.
#[tokio::test]
async fn get_returns_the_value_the_model_invents() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via memcached. Serve greeting=hello world, \
         everything else is a miss.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_event("memcached_get")
            .respond_with_actions_from_event(|event| {
                let keys: Vec<String> = event["keys"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|k| k.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let values: Vec<serde_json::Value> = keys
                    .iter()
                    .filter(|k| k.as_str() == "greeting")
                    .map(|k| serde_json::json!({"key": k, "value": "hello world", "flags": 0}))
                    .collect();
                serde_json::json!([{ "type": "send_memcached_values", "values": values }])
            })
            .expect_calls(2)
            .and()
            .on_instruction_containing("via memcached")
            .respond_with_actions(startup_mock("Serve greeting=hello world"))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let hit = exchange(server.port, b"get greeting\r\n", b"END\r\n").await?;
    assert_eq!(
        String::from_utf8_lossy(&hit),
        "VALUE greeting 0 11\r\nhello world\r\nEND\r\n",
        "exact VALUE framing, with the byte count computed from the payload"
    );

    let miss = exchange(server.port, b"get absent\r\n", b"END\r\n").await?;
    assert_eq!(
        String::from_utf8_lossy(&miss),
        "END\r\n",
        "a miss is END alone"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A `set` whose payload contains CRLF, end to end. The model must be told the right byte
/// count and the right value, and the connection must stay aligned afterwards.
#[tokio::test]
async fn set_with_an_embedded_crlf_is_counted_not_scanned() -> E2EResult<()> {
    let payload = "first\r\nsecond";

    let config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via memcached. Accept every store.")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_event("memcached_store")
            .respond_with_actions_from_event(|event| {
                // Only STORE if the server framed the value correctly; otherwise say so
                // loudly instead of quietly passing.
                let value = event["value"].as_str().unwrap_or("");
                let bytes = event["bytes"].as_u64().unwrap_or(0);
                if value == "first\r\nsecond" && bytes == 13 {
                    serde_json::json!([{"type": "send_memcached_status", "status": "STORED"}])
                } else {
                    serde_json::json!([{
                        "type": "send_memcached_error",
                        "kind": "SERVER_ERROR",
                        "message": format!("framing wrong: bytes={} value={:?}", bytes, value)
                    }])
                }
            })
            .expect_calls(1)
            .and()
            .on_event("memcached_version")
            .respond_with_actions(serde_json::json!([{
                "type": "send_memcached_version", "version": "1.6.45"
            }]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("via memcached")
            .respond_with_actions(startup_mock("Accept every store"))
            .expect_calls(1)
            .and()
            });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Both commands in one write: the second only parses if the first was counted, not
    // scanned for a delimiter.
    let mut request = format!("set doc 0 0 {}\r\n", payload.len()).into_bytes();
    request.extend_from_slice(payload.as_bytes());
    request.extend_from_slice(b"\r\nversion\r\n");

    let reply = exchange(server.port, &request, b"VERSION").await?;
    let text = String::from_utf8_lossy(&reply);

    assert!(
        text.starts_with("STORED\r\n"),
        "the model must have received the exact value and byte count. Got: {:?}",
        text
    );
    assert!(
        text.contains("VERSION 1.6.45"),
        "the pipelined command after the data block must still parse. Got: {:?}",
        text
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// incr, delete and an unknown verb, bundled into one server to stay inside the call budget.
#[tokio::test]
async fn arithmetic_delete_and_unknown_verbs() -> E2EResult<()> {
    let config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via memcached. counter starts at 41.")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_event("memcached_arithmetic")
                    .respond_with_actions_from_event(|event| {
                        let delta = event["delta"].as_u64().unwrap_or(0);
                        serde_json::json!([{"type": "send_memcached_number", "value": 41 + delta}])
                    })
                    .expect_calls(1)
                    .and()
                    .on_event("memcached_delete")
                    .respond_with_actions(serde_json::json!([{
                        "type": "send_memcached_status", "status": "DELETED"
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_event("memcached_unknown_command")
                    .respond_with_actions(serde_json::json!([{
                        "type": "send_memcached_error", "kind": "ERROR"
                    }]))
                    .expect_calls(1)
                    .and()
                    .on_instruction_containing("via memcached")
                    .respond_with_actions(startup_mock("counter starts at 41"))
                    .expect_calls(1)
                    .and()
            });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let reply = exchange(server.port, b"incr counter 2\r\n", b"\r\n").await?;
    assert_eq!(String::from_utf8_lossy(&reply), "43\r\n");

    let reply = exchange(server.port, b"delete counter\r\n", b"\r\n").await?;
    assert_eq!(String::from_utf8_lossy(&reply), "DELETED\r\n");

    let reply = exchange(server.port, b"frobnicate x\r\n", b"\r\n").await?;
    assert_eq!(String::from_utf8_lossy(&reply), "ERROR\r\n");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// When the model answers nothing, a memcached client would otherwise hang until its own
/// timeout. The server must say SERVER_ERROR — and must never invent a cache hit or a
/// STORED, which is the caching equivalent of the OAuth2 fail-open.
#[tokio::test]
async fn an_unanswered_command_becomes_server_error_not_a_fabricated_hit() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via memcached.")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_event("memcached_get")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(1)
                .and()
                .on_instruction_containing("via memcached")
                .respond_with_actions(startup_mock("Answer lookups"))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let reply = exchange(server.port, b"get anything\r\n", b"\r\n").await?;
    let text = String::from_utf8_lossy(&reply);

    assert!(
        text.starts_with("SERVER_ERROR"),
        "an unanswered command must fail visibly, not hang. Got: {:?}",
        text
    );
    assert!(
        !text.contains("VALUE"),
        "silence must never become a cache hit. Got: {:?}",
        text
    );
    assert!(
        !text.contains("END\r\n"),
        "silence must not be reported as a clean miss either — that is a lie the client \
         would cache. Got: {:?}",
        text
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

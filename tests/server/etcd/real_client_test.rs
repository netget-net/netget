//! The real `etcdctl` binary, which is grpc-go, against NetGet's etcd server.
//!
//! # Why this test exists, and why it could not be written before
//!
//! Every other test in this directory drives `etcd_client`, which is tonic. Tonic accepts a
//! `grpc-status` sitting in the *initial* HEADERS beside a DATA body; the gRPC specification
//! does not, and grpc-go does not either. So the entire suite passed while `etcdctl` could not
//! complete one RPC:
//!
//! ```text
//! Error: rpc error: code = Internal desc = server closed the stream without sending trailers
//! ```
//!
//! That is the `mysql`/`mysql_async` shape the project CLAUDE.md records — a maturity rating
//! resting on one lenient client agreeing with one bug. A second, stricter implementation is
//! the only thing that finds it, which is what this file is.
//!
//! It was deliberately **not** committed while the bug was live. A test written against broken
//! behaviour locks the behaviour in.
//!
//! # What it proves
//!
//! `etcdctl` is a full gRPC client: it negotiates HTTP/2, sends a length-prefixed protobuf
//! message, and refuses any stream that does not end in a trailing HEADERS frame carrying
//! `grpc-status`. Four commands cover the three KV verbs plus the repeated-field path:
//!
//! | command | exercises |
//! |---|---|
//! | `put` | trailers after a DATA frame — the case that was broken |
//! | `get` | Range with one pair, and the `key\nvalue` output shape |
//! | `get --prefix` | Range with `range_end` set and three pairs, so repeated fields are real |
//! | `del` | DeleteRange, whose count the handler decides |
//!
//! Everything binds to 127.0.0.1 and no real etcd cluster is contacted.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::json;
use std::time::Duration;
use tokio::process::Command;

/// Fail unless a usable `etcdctl` is on PATH.
///
/// **This must not skip.** A `println!("SKIP")` + `return Ok(())` is a silent pass on any
/// machine without the binary, and a silent pass is exactly how a maturity claim outlives the
/// evidence that justified it. The project CLAUDE.md lists four protocols held at Experimental
/// for precisely this gate; `npm` and `kubernetes` are the shape copied here.
async fn require_etcdctl() -> E2EResult<String> {
    match Command::new("etcdctl").arg("version").output().await {
        Ok(out) if out.status.success() => {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        Ok(out) => Err(format!(
            "`etcdctl version` exited {}: this test's whole point is driving the real etcdctl \
             binary, which is grpc-go, against NetGet's etcd server. An etcdctl older than 3.4 \
             defaults to the **v2** API, where `version` is not a command at all (it prints \
             \"No help topic for 'version'\" and exits 3) and where the client speaks HTTP/1.1 \
             REST rather than gRPC — so that binary could not produce this evidence even if \
             the gate let it through. Ubuntu 22.04's `etcd-client` package is exactly that: \
             etcd 3.3.25. Install a 3.4+ release instead.",
            out.status
        )
        .into()),
        Err(e) => Err(format!(
            "etcdctl is not available ({e}): this test's whole point is driving grpc-go against \
             NetGet's etcd server. Skipping would leave etcd's maturity rating resting on tonic \
             alone, which is the lenient client that accepted the trailers bug this test was \
             written to catch. `brew install etcd` provides it."
        )
        .into()),
    }
}

struct CtlOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Run one `etcdctl` command against the server.
///
/// **`tokio::process`, not `std::process`.** `#[tokio::test]` runs a current-thread runtime, so
/// a blocking `Command::output()` parks the only worker and stops the harness tasks draining
/// the netget child's stdout/stderr. The pipes then fill and netget blocks inside a log call
/// while serving the request, and etcdctl times out against a server that is perfectly correct.
async fn etcdctl(port: u16, args: &[&str]) -> CtlOutput {
    let endpoint = format!("http://127.0.0.1:{port}");
    let out = Command::new("etcdctl")
        .arg("--endpoints")
        .arg(&endpoint)
        .arg("--command-timeout=30s")
        .arg("--dial-timeout=30s")
        .args(args)
        .output()
        .await
        .expect("failed to spawn etcdctl");

    CtlOutput {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// One rule per event, each branching on the event itself.
///
/// Two rules on the same event with no way to tell them apart is the most common mocking
/// mistake in this repo — the first answers everything and the second reports zero calls. The
/// Range rule therefore branches internally on `range_end`, which is what distinguishes a
/// single-key get from `--prefix`.
fn etcdctl_server() -> NetGetConfig {
    NetGetConfig::new("listen on port {AVAILABLE_PORT} via etcd. Serve KV requests").with_mock(
        |mock| {
            mock.on_instruction_containing("via etcd")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "ETCD",
                    "instruction": "Serve etcd KV requests"
                }]))
                .expect_calls(1)
                .and()
                .on_event("etcd_put_request")
                .respond_with_actions_from_event(|_e| json!([{ "type": "etcd_put_response" }]))
                .expect_calls(3)
                .and()
                .on_event("etcd_range_request")
                .respond_with_actions_from_event(|e| {
                    // `--prefix` sets range_end; a bare get does not. That one field is the
                    // whole difference between the two Range shapes this test covers.
                    let prefixed = e.get("range_end").map(|v| !v.is_null()).unwrap_or(false);
                    if prefixed {
                        json!([{
                            "type": "etcd_range_response",
                            "kvs": [
                                {"key": "/config/a", "value": "1",
                                 "create_revision": 2, "mod_revision": 2, "version": 1, "lease": 0},
                                {"key": "/config/b", "value": "2",
                                 "create_revision": 3, "mod_revision": 3, "version": 1, "lease": 0},
                                {"key": "/config/database", "value": "localhost:5432",
                                 "create_revision": 1, "mod_revision": 1, "version": 1, "lease": 0}
                            ],
                            "more": false,
                            "count": 3
                        }])
                    } else {
                        json!([{
                            "type": "etcd_range_response",
                            "kvs": [
                                {"key": "/config/database", "value": "localhost:5432",
                                 "create_revision": 1, "mod_revision": 1, "version": 1, "lease": 0}
                            ],
                            "more": false,
                            "count": 1
                        }])
                    }
                })
                .expect_calls(2)
                .and()
                .on_event("etcd_delete_request")
                .respond_with_actions_from_event(
                    |_e| json!([{ "type": "etcd_delete_range_response", "deleted": 1 }]),
                )
                .expect_calls(1)
                .and()
        },
    )
}

#[tokio::test]
async fn etcdctl_completes_put_get_prefix_and_delete() -> E2EResult<()> {
    let version = require_etcdctl().await?;
    println!("etcdctl: {version}");

    let server = start_netget_server(etcdctl_server()).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    // Every etcdctl process reaches the server through a recording relay, so the pcap oracle
    // at the end reads each HTTP/2 connection exactly as it crossed.
    let (relay, streams) = crate::helpers::recording_relay::tcp_relay(
        format!("127.0.0.1:{}", server.port).parse().unwrap(),
    )
    .await;
    let port = relay.port();

    // --- put: the RPC that could not complete at all -----------------------
    //
    // A PutResponse has a body, so the stream must end in trailing HEADERS. With the status in
    // the initial headers instead, grpc-go reports "server closed the stream without sending
    // trailers" here and every assertion below is unreachable.
    let put = etcdctl(port, &["put", "/config/database", "localhost:5432"]).await;
    assert!(
        put.success,
        "etcdctl put failed.\nstdout: {}\nstderr: {}\n\nA \"closed the stream without sending \
         trailers\" here means grpc-status has moved back into the initial HEADERS beside the \
         DATA frame, which is not gRPC — see grpc_body() in src/server/etcd/mod.rs.",
        put.stdout, put.stderr
    );
    assert!(
        put.stdout.contains("OK"),
        "etcdctl prints OK on a successful put; got {:?}",
        put.stdout
    );

    etcdctl(port, &["put", "/config/a", "1"]).await;
    etcdctl(port, &["put", "/config/b", "2"]).await;

    // --- get: one pair, printed as key then value on separate lines --------
    let get = etcdctl(port, &["get", "/config/database"]).await;
    assert!(
        get.success,
        "etcdctl get failed.\nstdout: {}\nstderr: {}",
        get.stdout, get.stderr
    );
    let lines: Vec<&str> = get.stdout.lines().collect();
    assert_eq!(
        lines,
        vec!["/config/database", "localhost:5432"],
        "etcdctl prints the key on one line and the value on the next; the server's ranging \
         reply did not decode into that"
    );

    // --- get --prefix: range_end set, three pairs --------------------------
    //
    // Repeated protobuf fields are where a hand-rolled encoder goes wrong, and one pair never
    // exercises them. etcdctl decodes all three or none.
    let prefix = etcdctl(port, &["get", "--prefix", "/config/"]).await;
    assert!(
        prefix.success,
        "etcdctl get --prefix failed.\nstdout: {}\nstderr: {}",
        prefix.stdout, prefix.stderr
    );
    for (key, value) in [
        ("/config/a", "1"),
        ("/config/b", "2"),
        ("/config/database", "localhost:5432"),
    ] {
        assert!(
            prefix.stdout.contains(key) && prefix.stdout.contains(value),
            "the prefix range lost {key}={value}; grpc-go decoded {:?}",
            prefix.stdout
        );
    }

    // --- del: the count the handler chose, not one the server invented -----
    let del = etcdctl(port, &["del", "/config/database"]).await;
    assert!(
        del.success,
        "etcdctl del failed.\nstdout: {}\nstderr: {}",
        del.stdout, del.stderr
    );
    assert_eq!(
        del.stdout.trim(),
        "1",
        "etcdctl prints the deleted count; the handler said 1"
    );

    // --- the pcap oracle over every connection ------------------------------
    //
    // Wireshark's `http2` dissector, with its `grpc` sub-dissector, reads the preface, both
    // SETTINGS exchanges, HPACK-compressed headers, the length-prefixed messages and the
    // trailers — independently of grpc-go and of hyper. It has no `rpc.proto`, so it checks
    // each protobuf message's wire structure rather than its field names.
    let connections = crate::helpers::recording_relay::recorded(&streams);
    assert!(
        connections.len() >= 6,
        "six etcdctl commands should have crossed the relay, saw {} connections",
        connections.len()
    );
    for chunks in &connections {
        crate::helpers::recording_relay::replay(
            crate::helpers::pcap_oracle::PcapOracle::tcp("etcd").also_named("grpc"),
            chunks,
        )
        .assert_clean();
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Run `etcdctl txn` with `script` on stdin (compares, blank line, success ops, blank line,
/// failure ops, blank line — etcdctl's non-interactive format).
async fn etcdctl_txn(port: u16, script: &str) -> CtlOutput {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    let mut child = Command::new("etcdctl")
        .arg("--endpoints")
        .arg(format!("http://127.0.0.1:{port}"))
        .arg("--command-timeout=30s")
        .arg("--dial-timeout=30s")
        .arg("txn")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn etcdctl txn");
    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(script.as_bytes()).await.expect("write txn");
    drop(stdin);
    let out = child.wait_with_output().await.expect("etcdctl txn");
    CtlOutput {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

fn kv(key: &str, value: &str, rev: i64) -> serde_json::Value {
    json!({"key": key, "value": value, "create_revision": rev, "mod_revision": rev,
           "version": 1, "lease": 0})
}

/// The server for the second session: the rest of the KV surface. Each rule branches on the
/// event, so one rule per event answers every shape this session sends.
fn etcdctl_rest_of_the_surface() -> NetGetConfig {
    NetGetConfig::new("listen on port {AVAILABLE_PORT} via etcd. Serve KV requests").with_mock(
        |mock| {
            mock.on_instruction_containing("via etcd")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "ETCD",
                    "instruction": "Serve etcd KV requests"
                }]))
                .expect_calls(1)
                .and()
                // put --prev-kv: the previous pair comes from the handler.
                .on_event("etcd_put_request")
                .respond_with_actions_from_event(|e| {
                    if e["wants_prev_kv"] == json!(true) {
                        json!([{"type": "etcd_put_response",
                                "prev_kv": kv("/config/database", "localhost:5432", 1)}])
                    } else {
                        json!([{"type": "etcd_put_response"}])
                    }
                })
                .expect_calls(2)
                .and()
                // Every Range answers with all three keys under /config/ (or an error for
                // /missing). --limit, --keys-only and --count-only are the server's to apply.
                .on_event("etcd_range_request")
                .respond_with_actions_from_event(|e| {
                    if e["key"] == json!("/missing") {
                        return json!([{"type": "etcd_error", "code": "KEY_NOT_FOUND",
                                       "message": "etcdserver: key not found"}]);
                    }
                    json!([{"type": "etcd_range_response", "count": 3, "kvs": [
                        kv("/config/a", "1", 2), kv("/config/b", "2", 3),
                        kv("/config/database", "db2:5432", 4)
                    ]}])
                })
                .expect_calls(4)
                .and()
                .on_event("etcd_delete_request")
                .respond_with_actions_from_event(|e| {
                    let prev_kvs = if e["wants_prev_kv"] == json!(true) {
                        json!([kv("/config/a", "1", 2)])
                    } else {
                        json!([])
                    };
                    json!([{"type": "etcd_delete_range_response", "deleted": 1,
                            "prev_kvs": prev_kvs}])
                })
                .expect_calls(1)
                .and()
                // The lock pattern, both ways round: /lock/a is free (the put runs), /lock/b is
                // held (the get of the failure branch runs and reads the owner).
                .on_event("etcd_txn_request")
                .respond_with_actions_from_event(|e| {
                    if e["compares"][0]["key"] == json!("/lock/a") {
                        json!([{"type": "etcd_txn_response", "succeeded": true,
                                "responses": [{}]}])
                    } else {
                        json!([{"type": "etcd_txn_response", "succeeded": false,
                                "responses": [{"kvs": [kv("/lock/b", "owner-1", 7)],
                                               "count": 1}]}])
                    }
                })
                .expect_calls(2)
                .and()
        },
    )
}

/// Non-empty, trimmed lines of `text`.
fn lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// The second session: Txn both ways, Compact, Range's shaping flags, the previous-pair flags
/// and an error status — the verbs and paths the first session does not reach.
///
/// | command | exercises |
/// |---|---|
/// | `txn` (lock free) | Txn, success branch, one `ResponsePut` per put |
/// | `txn` (lock held) | Txn, failure branch, the `ResponseRange` the handler gave |
/// | `get --prefix --limit 2` | `limit` applied by the server, not the handler |
/// | `get --prefix --keys-only` | values dropped by the server |
/// | `get --prefix --count-only` | pairs dropped, count kept |
/// | `put --prev-kv` | `PutResponse.prev_kv` from the handler |
/// | `del --prev-kv` | `DeleteRangeResponse.prev_kvs` from the handler |
/// | `get /missing` | an `etcd_error` as a Trailers-Only `NotFound` |
/// | `compaction` | Compact at the current revision, then the same one again (refused) |
#[tokio::test]
async fn etcdctl_drives_txn_compaction_range_flags_and_errors() -> E2EResult<()> {
    let version = require_etcdctl().await?;
    println!("etcdctl: {version}");

    let server = start_netget_server(etcdctl_rest_of_the_surface()).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let (relay, streams) = crate::helpers::recording_relay::tcp_relay(
        format!("127.0.0.1:{}", server.port).parse().unwrap(),
    )
    .await;
    let port = relay.port();

    // --- txn: the lock is free, the put runs ---------------------------------
    let taken = etcdctl_txn(
        port,
        "create(\"/lock/a\") = \"0\"\n\nput /lock/a me\n\nget /lock/a\n\n",
    )
    .await;
    assert!(
        taken.success,
        "etcdctl txn failed.\nstdout: {}\nstderr: {}",
        taken.stdout, taken.stderr
    );
    assert_eq!(
        lines(&taken.stdout),
        vec!["SUCCESS", "OK"],
        "etcdctl prints the branch and one line per operation's response; a TxnResponse without \
         the put's ResponseOp prints SUCCESS alone"
    );

    // --- txn: the lock is held, the failure branch's get reads the owner ----
    let held = etcdctl_txn(
        port,
        "create(\"/lock/b\") = \"0\"\n\nput /lock/b me\n\nget /lock/b\n\n",
    )
    .await;
    assert!(
        held.success,
        "etcdctl txn failed.\nstdout: {}\nstderr: {}",
        held.stdout, held.stderr
    );
    assert_eq!(
        lines(&held.stdout),
        vec!["FAILURE", "/lock/b", "owner-1"],
        "the failure branch's get must print the pair the handler gave"
    );

    // --- get --limit: three pairs from the handler, two printed --------------
    let limited = etcdctl(port, &["get", "--prefix", "--limit", "2", "/config/"]).await;
    assert!(limited.success, "get --limit failed: {}", limited.stderr);
    assert_eq!(
        lines(&limited.stdout),
        vec!["/config/a", "1", "/config/b", "2"],
        "the server must truncate to the request's limit"
    );

    // --- get --keys-only: keys, no values ------------------------------------
    let keys = etcdctl(port, &["get", "--prefix", "--keys-only", "/config/"]).await;
    assert!(keys.success, "get --keys-only failed: {}", keys.stderr);
    assert_eq!(
        lines(&keys.stdout),
        vec!["/config/a", "/config/b", "/config/database"],
        "keys-only must carry no values"
    );

    // --- get --count-only: the count -----------------------------------------
    // etcdctl prints a count-only reply only as `-w fields`: one `"Count" : N` line, and a
    // `"Key"` line per pair, of which there must be none.
    let count = etcdctl(
        port,
        &[
            "get",
            "--prefix",
            "--count-only",
            "-w",
            "fields",
            "/config/",
        ],
    )
    .await;
    assert!(count.success, "get --count-only failed: {}", count.stderr);
    assert!(
        count.stdout.contains("\"Count\" : 3") && !count.stdout.contains("\"Key\""),
        "count-only carries the count and no pairs:\n{}",
        count.stdout
    );

    // --- put --prev-kv --------------------------------------------------------
    let put = etcdctl(port, &["put", "--prev-kv", "/config/database", "db2:5432"]).await;
    assert!(put.success, "put --prev-kv failed: {}", put.stderr);
    assert_eq!(
        lines(&put.stdout),
        vec!["OK", "/config/database", "localhost:5432"],
        "put --prev-kv prints OK and then the previous pair the handler gave"
    );

    // --- del --prev-kv --------------------------------------------------------
    let del = etcdctl(port, &["del", "--prev-kv", "/config/a"]).await;
    assert!(del.success, "del --prev-kv failed: {}", del.stderr);
    assert_eq!(
        lines(&del.stdout),
        vec!["1", "/config/a", "1"],
        "del --prev-kv prints the count and then the deleted pairs"
    );

    // --- an error status, Trailers-Only ---------------------------------------
    let missing = etcdctl(port, &["get", "/missing"]).await;
    assert!(!missing.success, "a get the handler refused must fail");
    assert!(
        missing.stderr.contains("NotFound") && missing.stderr.contains("key not found"),
        "etcdctl must read the handler's NOT_FOUND and its message; stderr: {}",
        missing.stderr
    );

    // --- compaction at the current revision, then the same one again ----------
    // The revision is read from a header etcdctl prints, not assumed.
    let put_json = etcdctl(port, &["put", "/config/x", "y", "-w", "json"]).await;
    let header: serde_json::Value =
        serde_json::from_str(put_json.stdout.trim()).expect("put -w json prints JSON");
    let revision = header["header"]["revision"]
        .as_i64()
        .expect("the put's header carries a revision");
    let compacted = etcdctl(port, &["compaction", &revision.to_string()]).await;
    assert!(
        compacted.success
            && compacted
                .stdout
                .contains(&format!("compacted revision {revision}")),
        "compaction at the current revision must succeed.\nstdout: {}\nstderr: {}",
        compacted.stdout,
        compacted.stderr
    );
    let again = etcdctl(port, &["compaction", &revision.to_string()]).await;
    assert!(
        !again.success
            && again
                .stderr
                .contains("required revision has been compacted"),
        "compacting the same revision twice must be refused as etcd refuses it; stderr: {}",
        again.stderr
    );

    // --- the pcap oracle over every connection ---------------------------------
    let connections = crate::helpers::recording_relay::recorded(&streams);
    assert!(
        connections.len() >= 11,
        "eleven etcdctl commands should have crossed the relay, saw {} connections",
        connections.len()
    );
    for chunks in &connections {
        crate::helpers::recording_relay::replay(
            crate::helpers::pcap_oracle::PcapOracle::tcp("etcd").also_named("grpc"),
            chunks,
        )
        .assert_clean();
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

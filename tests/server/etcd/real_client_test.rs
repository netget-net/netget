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
    let port = server.port;

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

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

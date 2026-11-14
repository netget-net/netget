//! The Python gRPC client — grpcio (gRPC C-core) with upb protobuf — against NetGet's etcd server.
//!
//! # Why this is the second client and `etcd-client` is not
//!
//! The Stable bar asks for two clients independent of the server's own libraries. NetGet's etcd
//! server frames HTTP/2 with hyper (`h2`) and protobuf with `prost`. `etcd-client`, the official
//! Rust client in `e2e_test.rs`, is tonic — which is hyper and `h2` — over `prost`: the same HTTP/2
//! stack and the same protobuf codec at both ends, so its agreement with the server proves that
//! those crates agree with themselves. Only the gRPC framing between them is independent. That is
//! the `dot`/`doh` finding of 8 November 2026 (the "second peer" doing the DNS was the server's
//! own codec) in another protocol.
//!
//! grpcio is C-core's own HTTP/2 (`chttp2`, HPACK included) and upb's protobuf, and shares a line
//! with neither the server nor `etcdctl` (grpc-go, golang/protobuf). The message types are built
//! in `grpcio_client.py` from etcd's `rpc.proto` field numbers with protobuf's descriptor API, so
//! the encoding and decoding are upb's.
//!
//! # What it drives
//!
//! Every method the server implements, each asserted on the decoded reply:
//!
//! | step | method | asserted |
//! |---|---|---|
//! | put, put prev_kv | Put | the revision rises; `prev_kv` is the pair the handler gave |
//! | range | Range | one pair, count 1 |
//! | range limit | Range | the handler's three pairs truncated to `limit` 2, `more` set, count 3 |
//! | range keys_only | Range | three keys, no values |
//! | range error | Range | the handler's `etcd_error` as `NOT_FOUND` |
//! | delete | DeleteRange | deleted 1, `prev_kvs` from the handler |
//! | txn taken / not taken | Txn | the branch, and one `ResponseOp` of the right kind per operation |
//! | compact, again, future | Compact | success, then `OUT_OF_RANGE` twice |
//!
//! It hard-fails when `python3`, grpcio or protobuf is missing rather than skipping, and the pcap
//! oracle reads every connection it made through a recording relay.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::json;
use std::time::Duration;

/// Fail, naming the install command, unless `python3` can import grpcio and protobuf.
fn require_grpcio() {
    let ok = std::process::Command::new("python3")
        .args(["-c", "import grpc, google.protobuf.message_factory"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        ok,
        "`python3 -c 'import grpc'` failed. This test drives the Python gRPC client (grpcio, gRPC \
         C-core, with upb protobuf) against NetGet's etcd server; it is the second client \
         independent of the server's hyper/h2/prost stack, so it must fail rather than skip. \
         Install with `python3 -m pip install grpcio protobuf`."
    );
}

fn kv(key: &str, value: &str, rev: i64) -> serde_json::Value {
    json!({"key": key, "value": value, "create_revision": rev, "mod_revision": rev,
           "version": 1, "lease": 0})
}

fn server() -> NetGetConfig {
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
                .respond_with_actions_from_event(|e| {
                    if e["prev_kv"] == json!(true) {
                        json!([{"type": "etcd_put_response",
                                "prev_kv": kv("/config/database", "localhost:5432", 1)}])
                    } else {
                        json!([{"type": "etcd_put_response"}])
                    }
                })
                .expect_calls(2)
                .and()
                .on_event("etcd_range_request")
                .respond_with_actions_from_event(|e| {
                    if e["key"] == json!("/missing") {
                        json!([{"type": "etcd_error", "code": "KEY_NOT_FOUND",
                                "message": "etcdserver: key not found"}])
                    } else if e["range_end"].is_null() {
                        json!([{"type": "etcd_range_response", "count": 1,
                                "kvs": [kv("/config/database", "db2:5432", 2)]}])
                    } else {
                        json!([{"type": "etcd_range_response", "count": 3, "kvs": [
                            kv("/config/a", "1", 3), kv("/config/b", "2", 4),
                            kv("/config/database", "db2:5432", 2)
                        ]}])
                    }
                })
                // range, limit, keys_only, error, and the read of the revision before compact
                .expect_calls(5)
                .and()
                .on_event("etcd_delete_request")
                .respond_with_actions_from_event(|_| {
                    json!([{"type": "etcd_delete_range_response", "deleted": 1,
                            "prev_kvs": [kv("/config/database", "db2:5432", 2)]}])
                })
                .expect_calls(1)
                .and()
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

#[tokio::test]
async fn grpcio_drives_every_kv_method_and_the_pcap_oracle_reads_clean_grpc() -> E2EResult<()> {
    require_grpcio();
    let server = start_netget_server(server()).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let (relay, streams) = crate::helpers::recording_relay::tcp_relay(
        format!("127.0.0.1:{}", server.port).parse().unwrap(),
    )
    .await;

    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/server/etcd/grpcio_client.py"
    );
    let out = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new("python3")
            .arg("-I")
            .arg(script)
            .arg(relay.port().to_string())
            .env("no_proxy", "*")
            .env("GRPC_ENABLE_FORK_SUPPORT", "0")
            .output(),
    )
    .await
    .expect("the grpcio client did not finish within 120s")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    println!(
        "--- grpcio client (exit {:?}) ---\n{stdout}\n{stderr}",
        out.status.code()
    );
    assert!(
        out.status.success() && stdout.contains("ALL OK"),
        "the grpcio client failed:\n{stdout}\n{stderr}"
    );

    let connections = crate::helpers::recording_relay::recorded(&streams);
    assert!(
        !connections.is_empty(),
        "grpcio's traffic did not cross the relay"
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

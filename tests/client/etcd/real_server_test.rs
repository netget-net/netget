//! The etcd client against a real **`etcd`** — the evidence its maturity rating rests on.
//!
//! NetGet's etcd client is `etcd-client`, which is Rust on tonic. The server here is the
//! official Go `etcd`, whose gRPC stack is grpc-go: no code in common with the client, and the
//! stricter of the two gRPC implementations this repository has met (grpc-go refused the
//! trailers shape tonic tolerated; see the root `CLAUDE.md`). State is read back with the
//! official `etcdctl`.
//!
//! Condition 4 of the client bar — the client acts on the model's answer, asserted on the wire
//! — is asserted from the server's side: `etcdctl` reads a key whose value the mocked model
//! built from a GET reply it was shown, and finds absent the key the model deleted.
//!
//! **No test here skips.** A missing `etcd` or `etcdctl` fails with the install command.
//!
//! LLM calls: 6.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features etcd --test client -- etcd::real_server_test --test-threads=100


use crate::helpers::real_server::{run_tool, InstallHint, RealServer};
use crate::helpers::*;
use serde_json::json;
use std::process::Command;

const ETCD: InstallHint = InstallHint {
    brew: "etcd",
    apt: "etcd-server (or etcd from the upstream v3.5 release tarball)",
};
const ETCDCTL: InstallHint = InstallHint {
    brew: "etcd",
    apt: "etcd-client (must be v3.4+; jammy's 3.3 defaults to the v2 API - use the upstream release tarball)",
};

/// A throwaway single-member etcd that binds port 0 for both clients and peers and reports the
/// client port it got — so, unlike the probe-port path, no other process can take it first.
async fn start_etcd() -> E2EResult<RealServer> {
    // 3.5+ logs `"msg":"serving client traffic insecurely; …","address":"127.0.0.1:N"`;
    // 3.4 logs `serving insecure client requests on 127.0.0.1:N`.
    let client_port = r"(?:serving client traffic insecurely|serving insecure client requests)[^\n]*?127\.0\.0\.1:(\d+)";
    RealServer::builder("etcd", ETCD)
        .args([
            "--name",
            "netget-e2e",
            "--data-dir",
            "{dir}/data",
            "--listen-client-urls",
            "http://127.0.0.1:0",
            "--advertise-client-urls",
            "http://127.0.0.1:0",
            "--listen-peer-urls",
            "http://127.0.0.1:0",
            "--initial-advertise-peer-urls",
            "http://127.0.0.1:0",
            "--initial-cluster",
            "netget-e2e=http://127.0.0.1:0",
        ])
        .port_from_log(client_port)
        .ready_when_log_matches(client_port)
        .start()
        .await
}

/// `etcdctl --endpoints=<addr> <args…>`, trailing newline trimmed.
async fn etcdctl(server: &RealServer, args: &[&str]) -> E2EResult<String> {
    let mut cmd = Command::new("etcdctl");
    cmd.env("ETCDCTL_API", "3")
        .arg(format!("--endpoints={}", server.addr()))
        .args(args);
    Ok(run_tool(cmd, "etcdctl", ETCDCTL)
        .await?
        .trim_end_matches('\n')
        .to_string())
}

/// PUT, GET, a PUT built from the GET, and a DELETE — every decision the model's.
///
/// 1. `etcd_connected` → `etcd_put netget/greeting = "hello from the model"`.
/// 2. The put response (matched on operation `put` and key `netget/greeting`) → `etcd_get`.
/// 3. The get response (matched on operation `get` and the value appearing in `kvs`) →
///    `etcd_put netget/echo = "the model saw: <value> at version <version>"`, both taken from
///    the `kvs` entry etcd returned.
/// 4. That put's response (key `netget/echo`) → `etcd_delete netget/greeting`.
/// 5. The delete response (matched on `deleted` 1) → nothing.
///
/// Then `etcdctl` must find `netget/echo` holding exactly the model's sentence and
/// `netget/greeting` gone.
///
/// LLM calls: 6 (startup, etcd_connected, four etcd_response_received).
#[tokio::test]
async fn etcd_client_puts_gets_and_deletes_against_the_official_etcd() -> E2EResult<()> {
    let server = start_etcd().await?;
    let result = puts_gets_and_deletes(&server).await;
    server.with_log(result)
}

async fn puts_gets_and_deletes(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let config = NetGetConfig::new(format!(
        "Connect to etcd at {addr}. ETCD-REAL-SERVER-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("ETCD-REAL-SERVER-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "etcd",
                "remote_addr": addr,
                "instruction": "Store a greeting, read it back, record what you read, then \
                                remove the greeting."
            }]))
            .expect_calls(1)
            .and()
            .on_event("etcd_connected")
            .respond_with_actions(json!([{
                "type": "etcd_put",
                "key": "netget/greeting",
                "value": "hello from the model"
            }]))
            .expect_calls(1)
            .and()
            .on_event("etcd_response_received")
            .and_event_data_contains("operation", "put")
            .and_event_data_contains("key", "netget/greeting")
            .respond_with_actions(json!([{"type": "etcd_get", "key": "netget/greeting"}]))
            .expect_calls(1)
            .and()
            .on_event("etcd_response_received")
            .and_event_data_contains("operation", "get")
            .and_event_data_contains("kvs", "hello from the model")
            .respond_with_actions_from_event(|event| {
                let kv = &event["kvs"][0];
                json!([{
                    "type": "etcd_put",
                    "key": "netget/echo",
                    "value": format!(
                        "the model saw: {} at version {}",
                        kv["value"].as_str().unwrap_or("?"),
                        kv["version"]
                    )
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("etcd_response_received")
            .and_event_data_contains("operation", "put")
            .and_event_data_contains("key", "netget/echo")
            .respond_with_actions(json!([{"type": "etcd_delete", "key": "netget/greeting"}]))
            .expect_calls(1)
            .and()
            .on_event("etcd_response_received")
            .and_event_data_contains("operation", "delete")
            .and_event_data_contains("deleted", "1")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    // The last rule is the delete's response, so once every rule is met etcd has applied
    // everything the model sent.
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    assert_eq!(
        etcdctl(server, &["get", "netget/echo", "--print-value-only"]).await?,
        "the model saw: hello from the model at version 1",
        "etcd must hold the value the model built from the GET response it was shown"
    );
    assert_eq!(
        etcdctl(server, &["get", "netget/greeting", "--print-value-only"]).await?,
        "",
        "the model deleted netget/greeting; etcd must no longer hold it"
    );

    client.stop().await?;
    Ok(())
}

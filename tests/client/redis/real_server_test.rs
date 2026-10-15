//! The Redis client against a real **`redis-server`** — the evidence its maturity rating rests
//! on.
//!
//! NetGet's Redis client frames RESP itself (`src/client/redis/resp.rs`); the server here is
//! the real C implementation (Valkey on Homebrew, Redis on Ubuntu — both answer to
//! `redis-server`), spawned per test on a probed loopback port with persistence off, and the
//! state it holds is read back with `redis-cli`. Nothing on the wire was written by this
//! repository except NetGet.
//!
//! Condition 4 of the client bar — the client acts on the model's answer, asserted on the wire
//! — is asserted from the server's side: `redis-cli` reads back keys whose values the mocked
//! model chose, including one built from a reply the model was shown. And each reply the model
//! is shown is matched on its **parsed** fields, so a reply split across two events (the
//! line-reader defect this client had) fails the mock rather than passing.
//!
//! **No test here skips.** A missing `redis-server` or `redis-cli` fails with the install
//! command.
//!
//! LLM calls: 9 across the file (5 + 4).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features redis --test client -- redis::real_server_test --test-threads=100

use crate::helpers::real_server::{run_tool, InstallHint, RealServer};
use crate::helpers::*;
use serde_json::json;
use std::process::Command;

const REDIS_SERVER: InstallHint = InstallHint {
    brew: "valkey",
    apt: "redis-server",
};
const REDIS_CLI: InstallHint = InstallHint {
    brew: "valkey",
    apt: "redis-tools",
};

/// A throwaway `redis-server`: loopback only, no RDB snapshots, no AOF, working directory in
/// the guard's temp dir. `--port 0` means "no TCP listener" to Redis, so the port is probed.
async fn start_redis() -> E2EResult<RealServer> {
    RealServer::builder("redis-server", REDIS_SERVER)
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
}

/// `redis-cli -p <port> <args…>`, stdout trimmed of its trailing newline.
async fn redis_cli(server: &RealServer, args: &[&str]) -> E2EResult<String> {
    let mut cmd = Command::new("redis-cli");
    cmd.args(["-h", "127.0.0.1", "-p", &server.port.to_string()])
        .args(args);
    Ok(run_tool(cmd, "redis-cli", REDIS_CLI)
        .await?
        .trim_end_matches('\n')
        .to_string())
}

/// SET, then GET, then a write built from the GET's reply — the model's decisions read back by
/// `redis-cli`.
///
/// 1. On `redis_connected` the model sends `SET netget:greeting "hello from the model"`. The
///    quotes are `redis-cli` syntax: the value has a space, and must arrive as one argument.
/// 2. The `+OK` reaches the model as one event, `reply_type` `simple_string`; it sends
///    `GET netget:greeting`.
/// 3. The bulk-string reply reaches the model as **one** event whose `value` is the whole
///    string; it sends `RPUSH netget:log "the model saw: <value>"`.
/// 4. The `:1` reaches the model as an `integer` reply; it does nothing.
///
/// Then `redis-cli` must read `hello from the model` and `the model saw: hello from the model`
/// out of the real server.
///
/// LLM calls: 5 (startup, redis_connected, three redis_response_received).
#[tokio::test]
async fn redis_client_writes_reads_and_acts_on_a_reply_against_redis_server() -> E2EResult<()> {
    let server = start_redis().await?;
    let result = writes_reads_and_acts(&server).await;
    server.with_log(result)
}

async fn writes_reads_and_acts(server: &RealServer) -> E2EResult<()> {
    let addr = server.addr();
    let config = NetGetConfig::new(format!(
        "Connect to Redis at {addr}. REDIS-REAL-SERVER-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("REDIS-REAL-SERVER-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Redis",
                "remote_addr": addr,
                "instruction": "Store a greeting, read it back, and log what you read."
            }]))
            .expect_calls(1)
            .and()
            .on_event("redis_connected")
            .respond_with_actions(json!([{
                "type": "execute_redis_command",
                "command": "SET netget:greeting \"hello from the model\""
            }]))
            .expect_calls(1)
            .and()
            .on_event("redis_response_received")
            .and_event_data_contains("reply_type", "simple_string")
            .and_event_data_contains("value", "OK")
            .respond_with_actions(json!([{
                "type": "execute_redis_command",
                "command": "GET netget:greeting"
            }]))
            .expect_calls(1)
            .and()
            .on_event("redis_response_received")
            .and_event_data_contains("reply_type", "bulk_string")
            .and_event_data_contains("value", "hello from the model")
            .respond_with_actions_from_event(|event| {
                json!([{
                    "type": "execute_redis_command",
                    "command": format!(
                        "RPUSH netget:log \"the model saw: {}\"",
                        event["value"].as_str().unwrap_or("")
                    )
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("redis_response_received")
            .and_event_data_contains("reply_type", "integer")
            .and_event_data_contains("response", "(integer) 1")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    // The last expectation is the RPUSH's `:1`, so once every rule is satisfied the server has
    // already applied everything the model sent.
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    assert_eq!(
        redis_cli(server, &["GET", "netget:greeting"]).await?,
        "hello from the model",
        "redis-server must hold the value the model SET, as one argument with its space"
    );
    assert_eq!(
        redis_cli(server, &["LRANGE", "netget:log", "0", "-1"]).await?,
        "the model saw: hello from the model",
        "redis-server must hold the entry the model built from the GET reply it was shown"
    );

    client.stop().await?;
    Ok(())
}

/// An aggregate reply prepared by `redis-cli`, read by the model as one structured event.
///
/// `redis-cli` writes a hash whose values contain a space and a newline. The model sends
/// `HGETALL`; the flat RESP2 array reaches it as one `array` event, and it answers by storing a
/// summary computed from the parsed array (`4 elements; field2 has 9 chars`), which `redis-cli`
/// reads back. A reader that framed by lines would have delivered the newline-bearing value in
/// two pieces and the element count would be wrong.
///
/// LLM calls: 4 (startup, redis_connected, the array reply, the SET's `+OK`).
#[tokio::test]
async fn redis_client_reads_an_array_reply_prepared_by_redis_cli() -> E2EResult<()> {
    let server = start_redis().await?;
    let result = reads_an_array(&server).await;
    server.with_log(result)
}

async fn reads_an_array(server: &RealServer) -> E2EResult<()> {
    // Passed as argv, so the newline is a real newline in the stored value.
    redis_cli(
        server,
        &[
            "HSET",
            "netget:hash",
            "field1",
            "value one",
            "field2",
            "two\nlines",
        ],
    )
    .await?;

    let addr = server.addr();
    let config = NetGetConfig::new(format!(
        "Read the netget:hash hash from Redis at {addr}. REDIS-ARRAY-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("REDIS-ARRAY-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Redis",
                "remote_addr": addr,
                "instruction": "Read netget:hash and store a summary of it."
            }]))
            .expect_calls(1)
            .and()
            .on_event("redis_connected")
            .respond_with_actions(json!([{
                "type": "execute_redis_command",
                "command": "HGETALL netget:hash"
            }]))
            .expect_calls(1)
            .and()
            .on_event("redis_response_received")
            .and_event_data_contains("reply_type", "array")
            .respond_with_actions_from_event(|event| {
                let items = event["value"].as_array().cloned().unwrap_or_default();
                let field2 = items
                    .iter()
                    .position(|v| v == "field2")
                    .and_then(|i| items.get(i + 1))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                json!([{
                    "type": "execute_redis_command",
                    "command": format!(
                        "SET netget:summary \"{} elements; field2 has {} chars\"",
                        items.len(),
                        field2.chars().count()
                    )
                }])
            })
            .expect_calls(1)
            .and()
            // The SET's `+OK`. Being answered at all proves the SET completed on the server.
            .on_event("redis_response_received")
            .and_event_data_contains("reply_type", "simple_string")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    assert_eq!(
        redis_cli(server, &["GET", "netget:summary"]).await?,
        "4 elements; field2 has 9 chars",
        "the model must have seen HGETALL as one four-element array with the newline intact"
    );

    client.stop().await?;
    Ok(())
}

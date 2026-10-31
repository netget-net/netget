//! `redis-cli` — a second, independent client for the Redis server.
//!
//! `e2e_test.rs` drives **redis-rs**. That is a genuine third-party implementation, but it is
//! **one** implementation, in the same language, deserialising into typed Rust values — and a
//! rating resting on one client rests on that client's leniency. Elsewhere in this repository
//! a second, stricter peer showed that no conformant implementation could complete a call at
//! all, because the failure path happened to be right and the success path was broken.
//!
//! `redis-cli` is the C client shipped with the server (the binary on this machine is
//! `valkey-cli`, the redis-cli-compatible fork), sharing no code with redis-rs. What it adds:
//!
//! - **The rendering, not the deserialisation.** `--no-raw` prints each RESP2 type
//!   distinguishably — a bulk string quoted, an integer as `(integer) n`, a nil as `(nil)`, an
//!   error as `(error) …`, an array as numbered elements. redis-rs converts a reply into the
//!   Rust type the *test* asked for, so a test that asks for `String` cannot tell a bulk string
//!   from a simple string. Here the type is read off the wire and printed.
//! - **Ordering across a whole session.** The assertions below are one ordered list for seven
//!   commands on one connection, so a reply landing against the wrong command — the
//!   desynchronisation `resp_framing_test.rs` guards the *cause* of — fails here as a
//!   mismatched line rather than passing as a same-typed value.
//!
//! What this does not add: RESP3 (`resp3_test.rs` covers it), inline commands, and
//! pipelining — redis-cli, like redis-rs, sends one RESP array per command and waits.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features redis \
//!       --test server -- server::redis::real_client --test-threads=8

use crate::helpers::{self, E2EResult, NetGetConfig};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

/// The binary *is* the evidence. A machine without it must say so.
///
/// A `println!("SKIP")` + `Ok(())` here would be a silent pass on every runner that does not
/// have redis-cli installed, which is exactly how a maturity claim outlives the thing that
/// justified it. `.github/workflows/ci.yml`'s `registry-audit` job installs `redis-tools` for
/// this reason.
async fn require_redis_cli() -> E2EResult<String> {
    match tokio::process::Command::new("redis-cli")
        .arg("--version")
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        Ok(out) => Err(format!(
            "`redis-cli --version` exited {}: this test's whole point is driving the real \
             redis-cli binary against NetGet's Redis server",
            out.status
        )
        .into()),
        Err(e) => Err(format!(
            "redis-cli not available ({e}): this test's whole point is driving the real \
             redis-cli (C) client against NetGet's Redis server, and skipping it would leave \
             Redis's second-client evidence resting on nothing. Install it with \
             `brew install redis` (or valkey) / `apt-get install redis-tools`."
        )
        .into()),
    }
}

/// Run one redis-cli session: every command on a single connection, in order.
///
/// `tokio::process`, not `std::process`: `#[tokio::test]` runs a current-thread runtime, so a
/// blocking `output()` parks the only worker and the harness tasks draining the netget child's
/// stdout/stderr stop running. The pipes fill, netget blocks inside a log call while it is
/// serving this very command, and redis-cli times out against a server that is behaving
/// perfectly — a failure that reads as a protocol bug and is not one.
///
/// redis-cli reads commands from stdin when stdin is not a tty, and in that mode it sends
/// nothing of its own: no `COMMAND DOCS`, no `HELLO`. Every LLM call the mock counts is a
/// command written here.
async fn redis_cli_session(port: u16, commands: &str) -> E2EResult<std::process::Output> {
    let mut child = tokio::process::Command::new("redis-cli")
        // --no-raw forces the type-distinguishing rendering even though stdout is a pipe.
        // Without it redis-cli prints raw payloads and a nil is indistinguishable from an
        // empty bulk string, which is one of the two things this test exists to tell apart.
        .args(["--no-raw", "-h", "127.0.0.1", "-p", &port.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut stdin = child.stdin.take().ok_or("redis-cli stdin was not piped")?;
    stdin.write_all(commands.as_bytes()).await?;
    stdin.shutdown().await?;
    drop(stdin);

    let out = timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .map_err(|_| "redis-cli session did not finish within 60s")??;
    Ok(out)
}

/// One netget server, one redis-cli connection, seven commands.
///
/// LLM calls: 1 startup + 7 commands = **8**.
#[tokio::test]
async fn redis_cli_completes_a_session_against_the_redis_server() -> E2EResult<()> {
    let version = require_redis_cli().await?;
    println!("\n=== E2E: real redis-cli client ({version}) ===");

    let prompt = "Listen on port {AVAILABLE_PORT} via Redis. Answer PING with PONG, SET with \
        OK, GET with the stored value or nil, INCR with an integer, KEYS with an array, and a \
        type mismatch with an error.";

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Redis")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "Redis",
                "instruction": "Answer each command with the matching RESP2 reply type"
            }]))
            .expect_calls(1)
            .and()
            // ONE rule that branches on the event. Rules are first-match-wins, so seven rules
            // on `redis_command` would have the first answer every command and the other six
            // report zero calls.
            .on_event("redis_command")
            .respond_with_actions_from_event(|event| {
                let command = event
                    .get("command")
                    .and_then(|c| c.as_str())
                    .unwrap_or_default()
                    .to_ascii_uppercase();
                if command.starts_with("PING") {
                    serde_json::json!([{"type": "redis_simple_string", "value": "PONG"}])
                } else if command.starts_with("SET ") {
                    serde_json::json!([{"type": "redis_simple_string", "value": "OK"}])
                } else if command.starts_with("GET GREETING") {
                    serde_json::json!([{"type": "redis_bulk_string", "value": "hello"}])
                } else if command.starts_with("GET ") {
                    serde_json::json!([{"type": "redis_null"}])
                } else if command.starts_with("INCR ") {
                    serde_json::json!([{"type": "redis_integer", "value": 7}])
                } else if command.starts_with("KEYS ") {
                    serde_json::json!([{
                        "type": "redis_array",
                        "values": ["greeting", "hits"]
                    }])
                } else {
                    serde_json::json!([{
                        "type": "redis_error",
                        "message": "WRONGTYPE Operation against a key holding the wrong kind of value"
                    }])
                }
            })
            // A range, not an exact count, and the reason is the client rather than the server.
            //
            // The seven commands this test sends are PING, SET, GET, INCRBY, KEYS, GET of a
            // missing key, and LPUSH against a string. redis-cli also speaks for itself before
            // the first of them, and how much it says depends on its version: 7.0.15 on
            // ubuntu-24.04 issues two commands of its own that valkey-cli 9.1.2 does not, and
            // swallows their replies, so they never reach stdout. The server answers them with
            // the fall-through WRONGTYPE — visible in its log as three `redis_error` actions
            // against the one `(error)` line redis-cli printed.
            //
            // `expect_calls(7)` therefore pinned a property of the installed client, and it
            // failed on CI while every assertion about the session passed. The floor still
            // catches a server that stopped consulting the model, and the ceiling still
            // catches the runaway loop `expect_calls` exists for — CLAUDE.md records a rule
            // that answered its own event 99 times. What carries the evidence here is the
            // eight assertions on what redis-cli *rendered*, not the arithmetic.
            .expect_at_least(7)
            .expect_at_most(20)
            .and()
    });

    let server = timeout(
        Duration::from_secs(60),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "netget startup timed out")??;
    println!("Redis server on port {}", server.port);

    let out = redis_cli_session(
        server.port,
        "PING\nSET greeting hello\nGET greeting\nINCR hits\nKEYS *\nGET missing\nLPUSH greeting x\n",
    )
    .await?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    println!("redis-cli stdout:\n{stdout}\nredis-cli stderr:\n{stderr}");

    assert!(
        out.status.success(),
        "redis-cli exited {} — it could not complete the session.\n\
         stdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );
    assert!(
        !stderr.contains("Error:") && !stderr.contains("could not connect"),
        "redis-cli reported a transport failure.\nstderr:\n{stderr}"
    );

    // One ordered list for the whole session. Every RESP2 reply type the server can produce is
    // here, each rendered distinguishably by redis-cli, and each in the position of the
    // command that provoked it — so a reply landing against the wrong command fails as a
    // mismatched line rather than passing as a same-typed value.
    let actual: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let expected = vec![
        // simple string
        "PONG",
        // simple string
        "OK",
        // bulk string — quoted, so it is distinguishable from the simple string above
        "\"hello\"",
        // RESP integer
        "(integer) 7",
        // multi-bulk: a real RESP array, two elements, numbered
        "1) \"greeting\"",
        "2) \"hits\"",
        // nil bulk string — `(nil)`, not an empty line, which is what makes it distinct from
        // a zero-length bulk string
        "(nil)",
        // simple error
        "(error) WRONGTYPE Operation against a key holding the wrong kind of value",
    ];
    assert_eq!(
        actual, expected,
        "redis-cli did not print the replies this session should produce.\nfull output:\n{stdout}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// `redis_command` carries the command as the client framed it, in `args`.
///
/// `command` is the space-joined line, so `SET k "a b c"` and `SET k a b c` read the same
/// there. redis-cli parses quoting itself and puts each argument in its own bulk string; the
/// mock echoes `args` and `hex_args` back as an array, so what redis-cli prints is what the
/// event held. The third command carries a byte that is not UTF-8 (`\xff`, which redis-cli
/// decodes inside double quotes), so that argument arrives hex-encoded and is named in
/// `hex_args`.
///
/// LLM calls: 1 startup + 3 commands, plus whatever the installed redis-cli sends of its own.
#[tokio::test]
async fn redis_cli_arguments_reach_the_event_with_their_boundaries() -> E2EResult<()> {
    let version = require_redis_cli().await?;
    println!("\n=== E2E: redis_command args through redis-cli ({version}) ===");

    let config =
        NetGetConfig::new("Listen on port {AVAILABLE_PORT} via Redis.").with_mock(|mock| {
            mock.on_instruction_containing("Redis")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Redis",
                    "instruction": "Echo each command's arguments"
                }]))
                .expect_calls(1)
                .and()
                .on_event("redis_command")
                .respond_with_actions_from_event(|event| {
                    let mut values: Vec<serde_json::Value> = event
                        .get("args")
                        .and_then(|a| a.as_array())
                        .cloned()
                        .unwrap_or_default();
                    values.push(serde_json::Value::String(format!(
                        "hex_args={}",
                        event
                            .get("hex_args")
                            .map(|h| h.to_string())
                            .unwrap_or_default()
                    )));
                    serde_json::json!([{"type": "redis_array", "values": values}])
                })
                // At least the three commands; redis-cli versions differ in what they send of
                // their own first (see the session test above).
                .expect_at_least(3)
                .expect_at_most(10)
                .and()
        });

    let server = timeout(
        Duration::from_secs(60),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "netget startup timed out")??;

    let out = redis_cli_session(
        server.port,
        "SET k \"a b c\"\nSET k a b c\nSET bin \"a\\xffb\"\n",
    )
    .await?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    println!("redis-cli stdout:\n{stdout}\nredis-cli stderr:\n{stderr}");
    assert!(
        out.status.success(),
        "redis-cli exited {}.\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );

    let actual: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let expected = vec![
        // The quoted value is one argument...
        "1) \"SET\"",
        "2) \"k\"",
        "3) \"a b c\"",
        "4) \"hex_args=[]\"",
        // ...and the unquoted one is three.
        "1) \"SET\"",
        "2) \"k\"",
        "3) \"a\"",
        "4) \"b\"",
        "5) \"c\"",
        "6) \"hex_args=[]\"",
        // A non-UTF-8 argument is hex, and says so.
        "1) \"SET\"",
        "2) \"bin\"",
        "3) \"61ff62\"",
        "4) \"hex_args=[2]\"",
    ];
    assert_eq!(
        actual, expected,
        "the redis_command event did not carry the arguments as redis-cli framed them.\n\
         full output:\n{stdout}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

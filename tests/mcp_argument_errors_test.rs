//! A malformed MCP tool argument is reported by tool, argument and expected type.
//!
//! rmcp's own extractor answered `start_server {"port": "abc"}` with
//! `failed to deserialize parameters: invalid digit found in string` — nothing saying which
//! tool, which of fifteen arguments, or what it should have been. `mcp_stdio::params` replaces
//! it; this drives the real binary over a stdio session (JSON-RPC lines on its stdin and
//! stdout, as Claude Code does) and checks several tools and kinds of field: a number given as
//! text, a number out of range, a missing required string, a boolean, an array given as an
//! object, a string given as a number, and a misspelled argument. After every refusal the
//! session still works.
//!
//! No model: `--ollama-url` points at a closed port, and every call here fails before one
//! could be needed.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!       --test mcp_argument_errors_test

#![cfg(feature = "mcp-stdio")]

#[path = "helpers/child_guard.rs"]
mod child_guard;

use serde_json::{json, Value};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout};

struct Session {
    child: Child,
    pid: u32,
    input: ChildStdin,
    output: Lines<BufReader<ChildStdout>>,
    next_id: u64,
}

impl Session {
    async fn start() -> Self {
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_netget"))
            .args(["--mcp", "--ollama-url", "http://127.0.0.1:1"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn netget --mcp");
        let pid = child.id().expect("pid");
        child_guard::tie_child(pid);
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut session = Self {
            child,
            pid,
            input,
            output,
            next_id: 1,
        };
        let init = session
            .request(
                "initialize",
                json!({"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "argument-errors", "version": "1"}}),
            )
            .await;
        assert!(init.get("result").is_some(), "{init}");
        session
            .write(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        session
    }

    async fn write(&mut self, message: Value) {
        self.input
            .write_all(format!("{message}\n").as_bytes())
            .await
            .expect("write to netget");
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.write(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let line = self
                    .output
                    .next_line()
                    .await
                    .expect("read netget stdout")
                    .expect("netget closed stdout");
                let message: Value = serde_json::from_str(&line).expect("JSON-RPC line");
                if message["id"] == id {
                    return message;
                }
            }
        })
        .await
        .expect("an answer within 60s")
    }

    /// Call `tool` with `arguments` and return the JSON-RPC error message it must produce.
    async fn refusal(&mut self, tool: &str, arguments: Value) -> String {
        let response = self
            .request(
                "tools/call",
                json!({"name": tool, "arguments": arguments.clone()}),
            )
            .await;
        let error = response
            .get("error")
            .unwrap_or_else(|| panic!("{tool} {arguments} was not refused: {response}"));
        assert_eq!(error["code"], -32602, "invalid params: {response}");
        let message = error["message"].as_str().unwrap_or_default().to_string();
        assert!(
            message.starts_with(&format!("{tool}: ")),
            "the message names the tool: {message}"
        );
        message
    }

    async fn close(mut self) {
        drop(self.input);
        if tokio::time::timeout(Duration::from_secs(10), self.child.wait())
            .await
            .is_err()
        {
            let _ = self.child.kill().await;
        }
        child_guard::untie_child(self.pid);
    }
}

fn assert_all(message: &str, parts: &[&str]) {
    for part in parts {
        assert!(message.contains(part), "{part:?} missing from: {message}");
    }
}

#[tokio::test]
async fn a_wrong_argument_is_named_with_its_tool_and_expected_type() {
    let mut session = Session::start().await;

    // A number sent as text that is not a number (a numeric string is accepted).
    let message = session
        .refusal("start_server", json!({"protocol": "http", "port": "abc"}))
        .await;
    assert_all(
        &message,
        &["argument `port`", "an integer from 0 to 65535", "\"abc\""],
    );
    assert!(!message.contains("untagged enum"), "{message}");

    // A number out of the field's range.
    let message = session
        .refusal("start_server", json!({"protocol": "http", "port": 70000}))
        .await;
    assert_all(
        &message,
        &["argument `port`", "an integer from 0 to 65535", "70000"],
    );

    // A required string left out, and a misspelling of it named as not an argument.
    let message = session
        .refusal("start_server", json!({"protocl": "http", "port": 0}))
        .await;
    assert_all(
        &message,
        &[
            "missing required argument `protocol`",
            "a string",
            "Not arguments of start_server: `protocl`",
        ],
    );

    // A boolean given as text.
    let message = session
        .refusal("list_protocols", json!({"include_disabled": "yes"}))
        .await;
    assert_all(
        &message,
        &["argument `include_disabled`", "true or false", "\"yes\""],
    );

    // An array given as an object.
    let message = session
        .refusal(
            "start_server",
            json!({"protocol": "http", "port": 0, "event_handlers": {"event_pattern": "*"}}),
        )
        .await;
    assert_all(
        &message,
        &["argument `event_handlers`", "an array", "a JSON object"],
    );

    // A string given as a number.
    let message = session
        .refusal(
            "start_client",
            json!({"protocol": "redis", "remote_addr": 6379}),
        )
        .await;
    assert_all(
        &message,
        &["argument `remote_addr`", "a string", "the number 6379"],
    );

    // An id given as text, on a tool with a single argument.
    let message = session
        .refusal("stop_server", json!({"server_id": "first"}))
        .await;
    assert_all(&message, &["argument `server_id`", "integer", "\"first\""]);

    // A required id left out.
    let message = session
        .refusal("answer_intercept", json!({"actions": []}))
        .await;
    assert_all(&message, &["missing required argument `intercept_id`"]);

    // The session carries on after every refusal.
    let listed = session
        .request(
            "tools/call",
            json!({"name": "list_servers", "arguments": {}}),
        )
        .await;
    assert!(listed.get("result").is_some(), "{listed}");
    assert_ne!(listed["result"]["isError"], true, "{listed}");

    session.close().await;
}

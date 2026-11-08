//! Two independent POP3 clients — python3's stdlib `poplib` and curl's libcurl POP3 — each
//! completing a real session against NetGet's POP3 server.
//!
//! `poplib` is pure Python in the standard library and libcurl is C; neither shares code with
//! the server or with the other. Both tests **fail** rather than skip when their client is
//! absent: a skip that returns success is a silent pass wherever the suite runs.
//!
//! # What each client drives, against what the server implements
//!
//! | Verb | `poplib` | curl |
//! |---|---|---|
//! | greeting | `getwelcome()` | read |
//! | `CAPA` (NetGet's own answer) | `capa()`, parsed | sent first, to choose a login |
//! | `USER` / `PASS` | `user()` / `pass_()` | both, from the URL |
//! | `STAT` | `stat()` | - |
//! | `LIST` (all) / `LIST n` | both | `LIST` |
//! | `UIDL` (all) | `uidl()` | - |
//! | `RETR n` | `retr(1)` | `RETR 1` |
//! | `TOP n m` | `top(1, 0)` | - |
//! | `DELE` / `NOOP` / `RSET` | all three | - |
//! | `QUIT` | `quit()` | sent |
//!
//! `APOP`, `AUTH` and `STLS` are not implemented by the server, so `CAPA` does not offer them
//! and neither client tries them.
//!
//! # What these clients found
//!
//! 1. **`RETR`'s octet count counted the transparency dots.** The count in `+OK <n> octets`
//!    is the message's size — the number `LIST` gives for it; the dots are transport the client
//!    removes (RFC 1939 §3) — and the server counted the byte-stuffed body, so every message with a line starting with `.` was
//!    announced one byte larger per such line than its own `LIST` entry said. Verified by
//!    putting the stuffed length back: poplib's `retr` status then reads `+OK 177 octets`
//!    against `LIST`'s `176`.
//! 2. **`send_pop3_message` ended a line with a bare CR.** A message ending in `\n` was written
//!    as `text\r` with no LF, so the client never saw the end of the line. Covered here by the
//!    `NOOP` answer, which the mock writes as `send_pop3_message` ending in `\n`: poplib then
//!    blocks for the rest of the line and the session times out.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,mcp-http,sqlite,terminal-snapshot \
//!       --test server -- server::pop3::real_client_test --test-threads=8

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::{self, E2EResult, NetGetConfig};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// The message served as number 1, byte for byte as the client must receive it.
///
/// A line beginning with `.` (stuffed on the wire, unstuffed by the client) and multi-byte
/// UTF-8, so the octet count is a byte count of the unstuffed CRLF text.
const MESSAGE: &str = "From: Grace Hopper <grace@example.org>\r\n\
     To: alice@example.com\r\n\
     Subject: Grüße from the lab\r\n\
     \r\n\
     The compiler is finished.\r\n\
     .leading dot\r\n\
     last line\r\n";

/// The header block `TOP 1 0` returns.
const HEADERS: &str = "From: Grace Hopper <grace@example.org>\r\n\
     To: alice@example.com\r\n\
     Subject: Grüße from the lab\r\n";

const POPLIB_DRIVER: &str = r#"
import json, poplib, sys

host, port = sys.argv[1], int(sys.argv[2])
out = {"poplib_file": poplib.__file__, "python": sys.version.split()[0]}
d = lambda b: b.decode("utf-8", "replace")

p = poplib.POP3(host, port, timeout=30)
out["welcome"] = d(p.getwelcome())
out["capa"] = sorted(p.capa().keys())
out["user"] = d(p.user("alice"))
out["pass"] = d(p.pass_("secret"))
out["stat"] = list(p.stat())
resp, lines, octets = p.list()
out["list"] = [d(resp), [d(l) for l in lines]]
out["list_one"] = d(p.list(1))
resp, lines, octets = p.uidl()
out["uidl"] = [d(resp), [d(l) for l in lines]]
resp, lines, octets = p.retr(1)
out["retr"] = [d(resp), [d(l) for l in lines]]
resp, lines, octets = p.top(1, 0)
out["top"] = [d(resp), [d(l) for l in lines]]
out["dele"] = d(p.dele(2))
out["noop"] = d(p.noop())
out["rset"] = d(p.rset())
out["quit"] = d(p.quit())
json.dump(out, sys.stdout)
"#;

async fn require_python_poplib() -> E2EResult<String> {
    let out = timeout(
        Duration::from_secs(30),
        Command::new("python3")
            .args([
                "-I",
                "-c",
                "import poplib,sys; print(sys.version.split()[0])",
            ])
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| "`python3 -c 'import poplib'` did not finish within 30s")?
    .map_err(|e| {
        format!(
            "python3 is not available ({e}): this test drives python's stdlib `poplib`, one of \
             the two independent clients POP3's Beta rating rests on, and skipping it would \
             leave that rating resting on curl alone. Install python3 (`brew install python` / \
             `apt-get install -y python3`)."
        )
    })?;
    if !out.status.success() {
        return Err(format!(
            "`python3 -c 'import poplib'` exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

async fn require_curl_pop3() -> E2EResult<String> {
    let out = Command::new("curl")
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| {
            format!(
                "curl is not available ({e}): this test drives libcurl's POP3 client, one of the \
                 two independent clients POP3's Beta rating rests on. Install it (`brew install \
                 curl` / `apt-get install -y curl`)."
            )
        })?;
    let version = String::from_utf8_lossy(&out.stdout).to_string();
    let protocols = version
        .lines()
        .find(|l| l.starts_with("Protocols:"))
        .unwrap_or("");
    if !protocols.split_whitespace().any(|p| p == "pop3") {
        return Err(format!("this curl was built without POP3:\n{version}").into());
    }
    Ok(version.lines().next().unwrap_or("").to_string())
}

/// One rule per verb, matched on the `answer_with` NetGet attaches, each with its own count.
fn pop3_rules(mock: MockLlmBuilder, expect: &[(&'static str, usize)]) -> MockLlmBuilder {
    let count = |verb: &str| {
        expect
            .iter()
            .find(|(v, _)| *v == verb)
            .map(|(_, n)| *n)
            .unwrap_or(0)
    };
    let size = MESSAGE.len();
    let rules: Vec<(&str, &str, serde_json::Value)> = vec![
        (
            "greeting",
            "send_pop3_greeting",
            serde_json::json!([{"type": "send_pop3_greeting", "message": "NetGet POP3 ready"}]),
        ),
        (
            "user",
            "accept the user name",
            serde_json::json!([{"type": "send_pop3_ok", "message": "alice is welcome"}]),
        ),
        (
            "pass",
            "to log in",
            serde_json::json!([{"type": "send_pop3_ok", "message": "maildrop locked and ready"}]),
        ),
        (
            "stat",
            "send_pop3_stat",
            serde_json::json!([{"type": "send_pop3_stat", "message_count": 2, "total_size": size + 120}]),
        ),
        (
            "list",
            "send_pop3_list",
            serde_json::json!([{"type": "send_pop3_list",
                "messages": [{"id": 1, "size": size}, {"id": 2, "size": 120}]}]),
        ),
        (
            "list_one",
            "\"1 <size in octets>\"",
            serde_json::json!([{"type": "send_pop3_ok", "message": format!("1 {size}")}]),
        ),
        (
            "uidl",
            "send_pop3_uidl",
            serde_json::json!([{"type": "send_pop3_uidl",
                "messages": [{"id": 1, "uidl": "msg-0001"}, {"id": 2, "uidl": "msg-0002"}]}]),
        ),
        (
            "retr",
            "send_pop3_retr",
            serde_json::json!([{"type": "send_pop3_retr", "content": MESSAGE}]),
        ),
        (
            "top",
            "send_pop3_top",
            serde_json::json!([{"type": "send_pop3_top", "content": HEADERS}]),
        ),
        (
            "dele",
            "to mark message 2 deleted",
            serde_json::json!([{"type": "send_pop3_ok", "message": "message 2 deleted"}]),
        ),
        (
            "quit",
            "then close_connection",
            serde_json::json!([{"type": "send_pop3_ok", "message": "bye"}, {"type": "close_connection"}]),
        ),
    ];
    let mut mock = mock
        .on_instruction_containing("POP3")
        .respond_with_actions(serde_json::json!([{
            "type": "open_server",
            "port": 0,
            "base_stack": "POP3",
            "instruction": "Serve alice's maildrop of two messages"
        }]))
        .expect_calls(1)
        .and();
    for (verb, hint, answer) in rules {
        mock = mock
            .on_event("pop3_command")
            .and_event_data_contains("answer_with", hint)
            .respond_with_actions(answer)
            .expect_calls(count(verb))
            .and();
    }
    // NOOP and RSET share `answer_with` ("send_pop3_ok"); told apart by the command. NOOP's
    // answer is a raw line ending in "\n" on purpose: the framing has to supply the CRLF.
    mock.on_event("pop3_command")
        .and_event_data_contains("command", "NOOP")
        .respond_with_actions(serde_json::json!([
            {"type": "send_pop3_message", "message": "+OK still here\n"}
        ]))
        .expect_calls(count("noop"))
        .and()
        .on_event("pop3_command")
        .and_event_data_contains("command", "RSET")
        .respond_with_actions(serde_json::json!([
            {"type": "send_pop3_ok", "message": "maildrop has 2 messages"}
        ]))
        .expect_calls(count("rset"))
        .and()
}

/// The message as a client hands it back: one entry per line, CRLF removed, dots unstuffed.
fn lines_of(text: &str) -> Vec<String> {
    text.trim_end_matches("\r\n")
        .split("\r\n")
        .map(str::to_string)
        .collect()
}

/// poplib: every transaction-state command NetGet's actions answer, on one connection.
///
/// LLM calls: 1 startup + greeting + USER + PASS + STAT + LIST + LIST 1 + UIDL + RETR + TOP +
/// DELE + NOOP + RSET + QUIT = **14**. CAPA is NetGet's.
#[tokio::test]
async fn poplib_completes_a_session_against_the_pop3_server() -> E2EResult<()> {
    let python = require_python_poplib().await?;
    println!("\n=== E2E: python {python} stdlib poplib against the POP3 server ===");

    let config = NetGetConfig::new_no_scripts(
        "Start a POP3 server on port 0 serving alice's maildrop of two messages.",
    )
    .with_mock(|mock| {
        pop3_rules(
            mock,
            &[
                ("greeting", 1),
                ("user", 1),
                ("pass", 1),
                ("stat", 1),
                ("list", 1),
                ("list_one", 1),
                ("uidl", 1),
                ("retr", 1),
                ("top", 1),
                ("dele", 1),
                ("noop", 1),
                ("rset", 1),
                ("quit", 1),
            ],
        )
    });
    let server = timeout(
        Duration::from_secs(90),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "netget startup timed out")??;
    helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let upstream: std::net::SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let (relay, streams) = crate::helpers::recording_relay::tcp_relay(upstream).await;

    let out = timeout(
        Duration::from_secs(90),
        Command::new("python3")
            .args([
                "-I",
                "-c",
                POPLIB_DRIVER,
                "127.0.0.1",
                &relay.port().to_string(),
            ])
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| "the poplib driver did not finish within 90s")??;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    println!("  poplib stdout:\n{stdout}\n  poplib stderr:\n{stderr}");
    assert!(
        out.status.success(),
        "the poplib session failed (exit {}). Python's traceback is the failure:\n{stderr}",
        out.status
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("poplib driver did not emit JSON ({e}).\nstdout:\n{stdout}"))?;

    let size = MESSAGE.len();
    assert_eq!(parsed["welcome"], "+OK NetGet POP3 ready");
    assert_eq!(
        parsed["capa"],
        serde_json::json!(["RESP-CODES", "TOP", "UIDL", "USER"])
    );
    assert!(parsed["pass"].as_str().unwrap().starts_with("+OK"));
    assert_eq!(parsed["stat"], serde_json::json!([2, size + 120]));
    assert_eq!(
        parsed["list"][1],
        serde_json::json!([format!("1 {size}"), "2 120"])
    );
    assert_eq!(parsed["list_one"], format!("+OK 1 {size}"));
    assert_eq!(
        parsed["uidl"][1],
        serde_json::json!(["1 msg-0001", "2 msg-0002"])
    );
    // RFC 1939: the octet count is the message's size, the number LIST gave for it.
    assert_eq!(
        parsed["retr"][0],
        format!("+OK {size} octets"),
        "RETR's octet count must be the size LIST reported, not the byte-stuffed length"
    );
    assert_eq!(parsed["retr"][1], serde_json::json!(lines_of(MESSAGE)));
    assert_eq!(parsed["top"][1], serde_json::json!(lines_of(HEADERS)));
    assert_eq!(parsed["dele"], "+OK message 2 deleted");
    assert_eq!(parsed["noop"], "+OK still here");
    assert!(parsed["rset"].as_str().unwrap().starts_with("+OK"));
    assert_eq!(parsed["quit"], "+OK bye");

    let recorded = crate::helpers::recording_relay::recorded(&streams);
    assert_eq!(recorded.len(), 1, "one POP3 connection crossed the relay");
    crate::helpers::recording_relay::replay(
        crate::helpers::pcap_oracle::PcapOracle::tcp("pop"),
        &recorded[0],
    )
    .assert_clean();

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// curl: a listing and a retrieval, each its own connection, logging in from the URL.
///
/// LLM calls: 1 startup + 2 × (greeting + USER + PASS + QUIT) + LIST + RETR = **11**.
#[tokio::test]
async fn curl_lists_and_retrieves_from_the_pop3_server() -> E2EResult<()> {
    let curl = require_curl_pop3().await?;
    println!("\n=== E2E: {curl} against the POP3 server ===");

    let config = NetGetConfig::new_no_scripts(
        "Start a POP3 server on port 0 serving alice's maildrop of two messages.",
    )
    .with_mock(|mock| {
        pop3_rules(
            mock,
            &[
                ("greeting", 2),
                ("user", 2),
                ("pass", 2),
                ("list", 1),
                ("retr", 1),
                ("quit", 2),
            ],
        )
    });
    let server = timeout(
        Duration::from_secs(90),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "netget startup timed out")??;
    helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let port = server.port;

    let curl_pop3 = |path: &'static str| {
        let url = format!("pop3://alice:secret@127.0.0.1:{port}/{path}");
        async move {
            let out = timeout(
                Duration::from_secs(90),
                Command::new("curl")
                    .args(["--silent", "--show-error", "--verbose", "--max-time", "60"])
                    .arg(&url)
                    .stdin(Stdio::null())
                    .output(),
            )
            .await
            .map_err(|_| format!("curl {url} did not finish within 90s"))??;
            let stdout = out.stdout.clone();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            println!("  curl {path:?} transcript:\n{stderr}");
            if !out.status.success() {
                return Err(format!("curl {url} failed (exit {}):\n{stderr}", out.status).into());
            }
            E2EResult::Ok((stdout, stderr))
        }
    };

    let (listing, transcript) = curl_pop3("").await?;
    assert!(transcript.contains("> CAPA"), "{transcript}");
    assert!(transcript.contains("> USER alice"), "{transcript}");
    assert!(transcript.contains("> LIST"), "{transcript}");
    assert_eq!(
        String::from_utf8_lossy(&listing),
        format!("1 {}\r\n2 120\r\n", MESSAGE.len())
    );

    let (message, transcript) = curl_pop3("1").await?;
    assert!(transcript.contains("> RETR 1"), "{transcript}");
    assert_eq!(
        String::from_utf8_lossy(&message),
        MESSAGE,
        "curl must hand back the message byte for byte, dot-unstuffed"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

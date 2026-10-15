//! python3's stdlib `imaplib` — the **second** independent client for the IMAP server.
//!
//! The rest of this directory drives `async-imap`. That is a genuine third-party
//! implementation, but it is **one** implementation, and a rating resting on one client is a
//! rating resting on that client's leniency. Three times in this repository a second, stricter
//! peer showed that no conformant implementation could complete a session at all — `etcd` and
//! `grpc` emitted no gRPC trailers, `mysql` offered an auth plugin MySQL 9.0 had deleted — and
//! in every one of those the *error* path was accidentally correct and the tests asserted on
//! the error path.
//!
//! `imaplib` needs no install: it is in the Python standard library, it is C-free Python
//! sharing no line of code with `async-imap`, and it is what an operator reaches for when they
//! want to know whether a mail server actually works.
//!
//! # What `imaplib` adds over `async-imap`
//!
//! - **The literal byte count.** `imaplib` reads a `{n}` literal by reading *exactly* `n` bytes
//!   off the socket and then resuming line parsing. A count that is wrong by one desynchronises
//!   the whole connection — every later response is read from the middle of the previous one.
//!   The message body below deliberately contains multi-byte UTF-8 (`ü`, `ß`, an em dash), so
//!   `n` is a *byte* count and not a character count, which is the mistake the encoder could
//!   make and a `String`-oriented client would never notice.
//! - **The untagged responses a command is *defined* to carry.** `imaplib.select()` returns
//!   `self.untagged_responses.get('EXISTS', [None])` — the count, not the tagged line. A SELECT
//!   that omitted `* n EXISTS` would still complete with `OK` and `async-imap` would still be
//!   satisfied; `imaplib` hands back `[None]`.
//! - **The CAPABILITY command, not just the greeting's capability code.** `imaplib.__init__`
//!   issues a real `CAPABILITY` after reading the greeting and refuses to proceed unless
//!   `IMAP4REV1` is in the answer (`server not IMAP4 compliant`).
//! - **Its own tag sequence.** `imaplib` generates `AAAA1`, `AAAA2`, … and matches completions
//!   by tag. Echoing the client's tag is therefore load-bearing, and it is read back here as
//!   the prefix of every parsed response.
//!
//! # Non-vacuity: what was broken, and what the client then reported
//!
//! Verified by breaking the server and watching `imaplib`'s own output change.
//!
//! 1. **The literal count made a character count.** In `execute_send_imap_fetch`
//!    (`src/server/imap/actions.rs`), `body.len()` → `body.chars().count()`. The body's three
//!    multi-byte characters make that four bytes short (146 → 142), so `imaplib` read four
//!    bytes too few and resumed line parsing inside the message. The FETCH still completed
//!    `OK` — the *tagged* line was fine — but the untagged response never registered as a
//!    FETCH, so `m.fetch(...)` returned `('OK', [None])` and the test failed with
//!    `imaplib did not read a literal at all … It returned: [Null]`. Note which half was
//!    still correct: the completion, which is what a test asserting only on `typ == 'OK'`
//!    would have looked at.
//! 2. **The `* n EXISTS` line removed** from `execute_send_imap_select`. The SELECT still
//!    completed `OK`, nothing on the wire was malformed, and `imaplib.select()` returned
//!    `('OK', [None])` — the test failed naming the missing count.
//!
//! Both were reverted; `git diff src/server/imap/` is empty.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features imap \
//!       --test server -- server::imap::real_client --test-threads=8

use crate::helpers::{self, E2EResult, NetGetConfig};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// The message body the model serves, byte-for-byte.
///
/// Multi-byte UTF-8 on purpose: `ü` and `ß` cost one extra byte each and `—` costs two, so the
/// literal's byte count (146) differs from its character count (142) and an encoder that
/// counted characters would desynchronise the
/// connection rather than merely truncate a string. CRLF line endings because RFC 5322 says so
/// and because `imaplib` hands the bytes back unmodified.
const MESSAGE_BODY: &str = "From: Grace Hopper <grace@example.com>\r\n\
     To: alice@example.com\r\n\
     Subject: Grüße from the lab\r\n\
     \r\n\
     The compiler is finished — it compiles itself.\r\n";

/// Drive an IMAP session with `imaplib` and print what it parsed, as JSON, on stdout.
///
/// Everything asserted in the test comes out of this: `imaplib` does the framing, the literal
/// reading and the tag matching, and this only reports what it produced. Nothing here is told
/// what to expect, so a wrong answer arrives as a wrong value rather than as a passing test.
///
/// `-I` (isolated) is passed on the command line so a developer's `PYTHONPATH`,
/// `PYTHONSTARTUP` or user site-packages cannot substitute a different `imaplib`.
const IMAPLIB_DRIVER: &str = r#"
import imaplib, json, sys

host, port = sys.argv[1], int(sys.argv[2])
out = {"imaplib_file": imaplib.__file__, "python": sys.version.split()[0]}

m = imaplib.IMAP4(host, port, timeout=30)
out["welcome"] = m.welcome.decode("utf-8", "replace")
# Populated by imaplib's own CAPABILITY command, issued during __init__ after the greeting.
out["capabilities"] = list(m.capabilities)

def dec(seq):
    return [None if d is None else d.decode("utf-8", "replace") for d in seq]

typ, dat = m.login("alice", "secret")
out["login"] = [typ, dec(dat)]
out["state_after_login"] = m.state

# imaplib.select() returns the EXISTS count, not the tagged line.
typ, dat = m.select("INBOX")
out["select"] = [typ, dec(dat)]
out["state_after_select"] = m.state

typ, dat = m.search(None, "ALL")
out["search"] = [typ, dec(dat)]

typ, dat = m.fetch("1", "(FLAGS RFC822.SIZE UID BODY[])")
items = []
for item in dat:
    if isinstance(item, tuple):
        # (prefix-line-ending-in-{n}, exactly n bytes read off the socket)
        items.append({
            "prefix": item[0].decode("utf-8", "replace"),
            "literal": item[1].decode("utf-8", "replace"),
            "literal_bytes": len(item[1]),
        })
    elif item is None:
        items.append(None)
    else:
        items.append({"line": item.decode("utf-8", "replace")})
out["fetch"] = [typ, items]

typ, dat = m.logout()
out["logout"] = [typ, dec(dat)]
out["state_after_logout"] = m.state

json.dump(out, sys.stdout)
"#;

/// Fail — never skip — unless a usable `python3` with `imaplib` exists.
///
/// A `println!("SKIP: python3 is not installed")` and `Ok(())` is a silent pass on every runner
/// without it, and a maturity rating resting on a test like that rests on nothing wherever the
/// suite actually runs (`tests/server/npm/e2e_test.rs` says the same in its own words). The bar
/// is low here on purpose: `imaplib` is in the standard library, so this needs no install
/// beyond python itself.
async fn require_python_imaplib() -> E2EResult<String> {
    let out = timeout(
        Duration::from_secs(30),
        Command::new("python3")
            .args([
                "-I",
                "-c",
                "import imaplib,sys; print(sys.version.split()[0])",
            ])
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| "`python3 -c 'import imaplib'` did not finish within 30s")?;

    match out {
        Ok(out) if out.status.success() => {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        Ok(out) => Err(format!(
            "`python3 -c 'import imaplib'` exited {}: this test's whole point is driving \
             python's stdlib IMAP client against NetGet's IMAP server.\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into()),
        Err(e) => Err(format!(
            "python3 is not available ({e}): this test drives python's stdlib `imaplib`, which \
             is the SECOND independent client the IMAP server's Beta rating rests on, and \
             skipping it would leave that rating resting on `async-imap` alone. `imaplib` needs \
             no install of its own — only python3 (`brew install python` / \
             `apt-get install -y python3`)."
        )
        .into()),
    }
}

/// One `imaplib` session against one netget server.
///
/// LLM calls: 1 startup + 1 greeting + 1 LOGIN + SELECT/SEARCH/FETCH/LOGOUT = **7**.
/// CAPABILITY is answered by NetGet from the greeting's list and never reaches the model.
#[tokio::test]
async fn imaplib_completes_a_session_against_the_imap_server() -> E2EResult<()> {
    let python = require_python_imaplib().await?;
    println!("\n=== E2E: python {python} stdlib imaplib against the IMAP server ===");

    let prompt = "Start an IMAP server on port 0. Greet, accept the LOGIN, and serve one \
         mailbox called INBOX holding three messages.";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("IMAP")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "IMAP",
                "instruction": "Serve INBOX with three messages; accept alice/secret"
            }]))
            .expect_calls(1)
            .and()
            // The greeting. `imaplib.IMAP4.__init__` blocks on this line before it sends
            // anything at all, so a server that does not write it hangs the constructor. It
            // deliberately carries no [CAPABILITY ...] code, so the only place imaplib can
            // learn the capability list is NetGet's answer to its CAPABILITY command.
            .on_event("imap_connection")
            .respond_with_actions(serde_json::json!([{
                "type": "send_imap_response",
                "response": "* OK mail.example.com IMAP4rev1 Service Ready"
            }]))
            .expect_calls(1)
            .and()
            // LOGIN. The tag is echoed from the event: imaplib generates AAAA1, AAAA2, … and
            // matches completions by tag alone, so a hardcoded one is never matched and the
            // client blocks until its own timeout.
            .on_event("imap_auth")
            .respond_with_actions_from_event(|event| {
                let tag = event
                    .get("tag")
                    .and_then(|v| v.as_str())
                    .unwrap_or("A001")
                    .to_string();
                serde_json::json!([{
                    "type": "send_imap_response",
                    "tag": tag,
                    "status": "OK",
                    "message": "LOGIN completed"
                }])
            })
            .expect_calls(1)
            .and()
            // ONE rule branching on the command. Five rules on `imap_command` would be
            // first-match-wins: the first would answer every command and the other four would
            // report zero calls.
            .on_event("imap_command")
            .respond_with_actions_from_event(|event| {
                let tag = event
                    .get("tag")
                    .and_then(|v| v.as_str())
                    .unwrap_or("A001")
                    .to_string();
                let command = event
                    .get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_ascii_uppercase();
                match command.as_str() {
                    "SELECT" => serde_json::json!([
                        {
                            "type": "send_imap_select",
                            "exists": 3,
                            "recent": 1,
                            "unseen": 2,
                            "uidvalidity": 1729,
                            "uidnext": 1004,
                            "flags": ["\\Answered", "\\Flagged", "\\Deleted", "\\Seen", "\\Draft"],
                            "permanent_flags": ["\\Deleted", "\\Seen", "\\*"]
                        },
                        // READ-WRITE, not READ-ONLY: imaplib raises IMAP4.readonly when a
                        // SELECT it did not ask to be read-only comes back READ-ONLY.
                        {"type": "send_imap_response", "tag": tag, "status": "OK",
                         "code": "READ-WRITE", "message": "SELECT completed"}
                    ]),
                    "SEARCH" => serde_json::json!([
                        {"type": "send_imap_search", "results": [1, 3]},
                        {"type": "send_imap_response", "tag": tag, "status": "OK",
                         "message": "SEARCH completed"}
                    ]),
                    "FETCH" => serde_json::json!([
                        {
                            "type": "send_imap_fetch",
                            "sequence": 1,
                            "data": {
                                "BODY[]": MESSAGE_BODY,
                                "FLAGS": ["\\Seen"],
                                "RFC822.SIZE": MESSAGE_BODY.len(),
                                "UID": 1001
                            }
                        },
                        {"type": "send_imap_response", "tag": tag, "status": "OK",
                         "message": "FETCH completed"}
                    ]),
                    "LOGOUT" => serde_json::json!([
                        {"type": "send_imap_untagged", "response_type": "BYE",
                         "data": "IMAP4rev1 Server logging out"},
                        {"type": "send_imap_response", "tag": tag, "status": "OK",
                         "message": "LOGOUT completed"}
                    ]),
                    // Anything else: a tagged BAD, so an unexpected command fails the test
                    // loudly on the client side instead of hanging it.
                    _ => serde_json::json!([
                        {"type": "send_imap_response", "tag": tag, "status": "BAD",
                         "message": format!("unexpected command {command} in this test")}
                    ]),
                }
            })
            .expect_calls(4)
            .and()
    });

    let server = timeout(
        Duration::from_secs(90),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "netget startup timed out")??;
    helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let port = server.port;
    println!("  IMAP server on port {port}");

    let out = timeout(
        Duration::from_secs(90),
        Command::new("python3")
            .args(["-I", "-c", IMAPLIB_DRIVER, "127.0.0.1", &port.to_string()])
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| "the imaplib driver did not finish within 90s")??;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    println!("  imaplib stdout:\n{stdout}\n  imaplib stderr:\n{stderr}");
    assert!(
        out.status.success(),
        "the imaplib session failed (exit {}). Python's traceback is the failure:\n{stderr}",
        out.status
    );

    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("imaplib driver did not emit JSON ({e}).\nstdout:\n{stdout}"))?;
    println!(
        "  imaplib module: {}",
        parsed["imaplib_file"].as_str().unwrap_or("?")
    );

    // ---- The greeting imaplib accepted ----
    let welcome = parsed["welcome"].as_str().unwrap_or_default();
    assert!(
        welcome.starts_with("* OK ") && welcome.contains("mail.example.com"),
        "imaplib's welcome line is not the greeting the model wrote: {welcome:?}"
    );

    // ---- The CAPABILITY *command*: NetGet's answer, the greeting carried no code ----
    let capabilities: Vec<String> = parsed["capabilities"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        capabilities,
        vec!["IMAP4REV1".to_string()],
        "imaplib's capabilities can only have come from NetGet's answer to its CAPABILITY \
         command (the greeting carried no code), and that answer is IMAP4rev1 alone - without \
         it __init__ raises `server not IMAP4 compliant`"
    );

    // ---- LOGIN ----
    assert_eq!(
        parsed["login"][0].as_str(),
        Some("OK"),
        "imaplib did not get an OK for LOGIN: {:?}",
        parsed["login"]
    );
    assert_eq!(
        parsed["state_after_login"].as_str(),
        Some("AUTH"),
        "imaplib did not move to the authenticated state"
    );

    // ---- SELECT: the EXISTS count, which is what imaplib.select() returns ----
    assert_eq!(parsed["select"][0].as_str(), Some("OK"));
    assert_eq!(
        parsed["select"][1][0].as_str(),
        Some("3"),
        "imaplib.select() returned {:?} rather than the EXISTS count. It returns \
         `untagged_responses.get('EXISTS', [None])`, so `[null]` means the SELECT completed OK \
         while omitting the one untagged response a SELECT is defined to carry.",
        parsed["select"][1]
    );
    assert_eq!(
        parsed["state_after_select"].as_str(),
        Some("SELECTED"),
        "imaplib did not move to the selected state"
    );

    // ---- SEARCH: the untagged result line, parsed by imaplib ----
    assert_eq!(parsed["search"][0].as_str(), Some("OK"));
    assert_eq!(
        parsed["search"][1][0].as_str(),
        Some("1 3"),
        "imaplib did not read back the sequence numbers the model chose: {:?}",
        parsed["search"][1]
    );

    // ---- FETCH: the literal, read by byte count off the socket ----
    assert_eq!(parsed["fetch"][0].as_str(), Some("OK"));
    let items = parsed["fetch"][1]
        .as_array()
        .ok_or("imaplib's FETCH data is not a list")?;
    let literal_item = items
        .iter()
        .find(|i| i.get("literal").is_some())
        .ok_or_else(|| {
            format!(
                "imaplib did not read a literal at all — it returns a (prefix, bytes) tuple \
                 only when a response line ends in `{{n}}`. It returned: {items:?}"
            )
        })?;

    assert_eq!(
        literal_item["literal"].as_str(),
        Some(MESSAGE_BODY),
        "imaplib read the literal but its bytes are not the message the model wrote"
    );
    assert_eq!(
        literal_item["literal_bytes"].as_u64(),
        Some(MESSAGE_BODY.len() as u64),
        "the literal's declared length is not the message's BYTE length. MESSAGE_BODY is {} \
         bytes and {} characters — a `{{n}}` counted in characters desynchronises the \
         connection, because imaplib reads exactly n bytes and then resumes line parsing.",
        MESSAGE_BODY.len(),
        MESSAGE_BODY.chars().count()
    );
    // The prefix is the line imaplib matched `{n}` on, so it carries the sequence number and
    // the item name it belongs to.
    let prefix = literal_item["prefix"].as_str().unwrap_or_default();
    assert!(
        prefix.starts_with("1 (BODY[] {") && prefix.ends_with('}'),
        "imaplib's literal prefix is not a BODY[] item for message 1: {prefix:?}"
    );
    // The rest of the FETCH line, after the literal: the items the encoder wrote alongside it.
    let trailer = items
        .iter()
        .filter_map(|i| i.get("line").and_then(|v| v.as_str()))
        .collect::<Vec<_>>()
        .join(" ");
    for needle in [
        "FLAGS (\\Seen)",
        &format!("RFC822.SIZE {}", MESSAGE_BODY.len()),
        "UID 1001",
    ] {
        assert!(
            trailer.contains(needle),
            "imaplib did not read `{needle}` after the literal. It read: {trailer:?}\n\
             (A trailer that is missing or mangled means line parsing resumed at the wrong \
             offset, which is what a wrong literal count does.)"
        );
    }

    // ---- LOGOUT ----
    assert_eq!(
        parsed["logout"][0].as_str(),
        Some("BYE"),
        "imaplib did not see the untagged BYE folded into the LOGOUT completion: {:?}",
        parsed["logout"]
    );
    assert_eq!(parsed["state_after_logout"].as_str(), Some("LOGOUT"));

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ imaplib completed a real session\n");
    Ok(())
}

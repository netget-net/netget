//! Two independent SMTP clients — python3's stdlib `smtplib` and curl's libcurl SMTP — each
//! completing a real mail transaction against NetGet's SMTP server.
//!
//! Neither shares a line of code with the server or with the other: `smtplib` is pure Python
//! in the standard library, libcurl is C. Both tests **fail** rather than skip when their client
//! is absent, because a skip that returns success is a silent pass wherever the suite runs.
//!
//! # What each client drives, against what the server implements
//!
//! | Verb | `smtplib` | curl |
//! |---|---|---|
//! | greeting (220) | read in `SMTP.__init__` | read |
//! | `EHLO` (NetGet's own reply: `SIZE`, `8BITMIME`) | `ehlo()`, features parsed | sent, `SIZE` used |
//! | `NOOP` | `noop()` | - |
//! | `VRFY` | `verify()` | - |
//! | `MAIL FROM` with `SIZE=` | twice; the second declares more than the limit | once, with `SIZE=` |
//! | `RCPT TO`, accepted and refused | both | two accepted |
//! | `DATA` + message + `.` | `data()`, dot-stuffed by smtplib | upload, dot-stuffed by libcurl |
//! | `RSET` | `rset()` | - |
//! | `QUIT` | `quit()` | sent |
//!
//! `HELO`, `EXPN` and `HELP` are not driven by either: the model answers them like any other
//! verb, and `HELO` is NetGet's single-line form of the EHLO reply, covered by `test.rs`.
//!
//! # What these clients found
//!
//! 1. **The message arrived one model call per line, and the model judged it without seeing
//!    it.** Every body line was its own `smtp_command` event answered `wait_for_more`, so
//!    smtplib's twelve-line message cost twelve model calls before the one that mattered, and
//!    that one — the terminating `.` — carried only `"."`. NetGet now reads the message itself
//!    and raises one event with `headers`, `body` and `message_bytes`.
//! 2. **A body line of `" ."` ended the message.** Every line was `trim()`med before it was
//!    compared with `"."`, so a line consisting of a space and a dot — which smtplib sends
//!    unchanged, since it does not start with a dot — was taken for the terminator, and the rest
//!    of the body was read as commands. The same trim also removed the leading whitespace that
//!    marks a folded header line, and the leading `.` smtplib and libcurl double (RFC 5321
//!    §4.5.2 transparency) reached the model doubled.
//! 3. **No `SIZE`.** Nothing bounded a message across lines. The EHLO reply now advertises
//!    `SIZE 10485760` and NetGet answers `552 5.3.4` itself, both to a `MAIL FROM` declaring
//!    more and to a message that turns out larger.
//!
//! 4. **`send_smtp_message` ended a reply with a bare CR** when the model's text ended in `\n`,
//!    so the client never saw the end of the line. The `VRFY` answer here is such a reply.
//!
//! Verified by putting the old behaviour back and watching a test fail: the bare CR makes
//! smtplib time out waiting for the `VRFY` reply; dropping `unstuff_line` hands the model curl's
//! message with `..hidden line` in it; and comparing a trimmed line in
//! `ends_message` is caught by `data_framing_test.rs`, which the bare CR masks here. The
//! `declared_size` refusal is asserted (smtplib's second `MAIL` must read `552`) but was not
//! separately reverted.
//!
//! The pcap oracle reads smtplib's session as it crossed a recording relay, so Wireshark's own
//! SMTP dissector checks the replies' framing too.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,mcp-http,sqlite,terminal-snapshot \
//!       --test server -- server::smtp::real_client_test --test-threads=8

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::{self, E2EResult, NetGetConfig};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Drive one session with `smtplib` and print what it got back, as JSON, on stdout.
///
/// Nothing here is told what to expect: every reply code and text comes from smtplib's own
/// parsing, so a wrong answer arrives as a wrong value rather than as a passing test. `-I`
/// keeps a developer's `PYTHONPATH` from substituting a different `smtplib`.
const SMTPLIB_DRIVER: &str = r#"
import json, smtplib, sys

host, port = sys.argv[1], int(sys.argv[2])
out = {"smtplib_file": smtplib.__file__, "python": sys.version.split()[0]}

s = smtplib.SMTP(host, port, local_hostname="client.example.org", timeout=30)
code, msg = s.ehlo()
out["ehlo"] = [code, msg.decode()]
out["esmtp_features"] = s.esmtp_features
out["noop"] = list(s.noop())
out["noop"][1] = out["noop"][1].decode()
code, msg = s.verify("alice")
out["vrfy"] = [code, msg.decode()]

# A message with every line shape the framing has to get right: a folded header, a line that
# starts with a dot (smtplib doubles it on the wire), a line that is a space and a dot (sent as
# it is: it does not start with one), and non-ASCII text (8BITMIME).
message = (
    "From: Grace Hopper <grace@example.org>\r\n"
    "To: alice@example.com\r\n"
    "Subject: Grüße from the lab\r\n"
    "X-Folded: first part\r\n"
    "  second part\r\n"
    "\r\n"
    "The compiler is finished.\r\n"
    ".leading dot\r\n"
    " .\r\n"
    "after the space-dot line\r\n"
    "last line\r\n"
).encode("utf-8")

code, msg = s.mail("grace@example.org", ["SIZE=%d" % len(message), "BODY=8BITMIME"])
out["mail"] = [code, msg.decode()]
code, msg = s.rcpt("alice@example.com")
out["rcpt_ok"] = [code, msg.decode()]
code, msg = s.rcpt("mallory@elsewhere.test")
out["rcpt_refused"] = [code, msg.decode()]
code, msg = s.data(message)
out["data"] = [code, msg.decode()]
out["message_bytes"] = len(message)

code, msg = s.rset()
out["rset"] = [code, msg.decode()]

# A second transaction, declaring more than the server's SIZE: refused at MAIL FROM.
code, msg = s.mail("grace@example.org", ["SIZE=%d" % (int(s.esmtp_features["size"]) + 1)])
out["mail_too_big"] = [code, msg.decode()]
code, msg = s.docmd("NOOP")
out["after_too_big"] = [code, msg.decode()]

code, msg = s.quit()
out["quit"] = [code, msg.decode()]
json.dump(out, sys.stdout)
"#;

/// Fail — never skip — unless `python3` can import `smtplib`.
async fn require_python_smtplib() -> E2EResult<String> {
    let out = timeout(
        Duration::from_secs(30),
        Command::new("python3")
            .args([
                "-I",
                "-c",
                "import smtplib,sys; print(sys.version.split()[0])",
            ])
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| "`python3 -c 'import smtplib'` did not finish within 30s")?
    .map_err(|e| {
        format!(
            "python3 is not available ({e}): this test drives python's stdlib `smtplib`, one of \
             the two independent clients SMTP's Beta rating rests on, and skipping it would \
             leave that rating resting on curl alone. Install python3 (`brew install python` / \
             `apt-get install -y python3`)."
        )
    })?;
    if !out.status.success() {
        return Err(format!(
            "`python3 -c 'import smtplib'` exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Fail — never skip — unless `curl` exists and was built with SMTP.
async fn require_curl_smtp() -> E2EResult<String> {
    let out = Command::new("curl")
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| {
            format!(
                "curl is not available ({e}): this test drives libcurl's SMTP client, one of the \
                 two independent clients SMTP's Beta rating rests on. Install it (`brew install \
                 curl` / `apt-get install -y curl`)."
            )
        })?;
    let version = String::from_utf8_lossy(&out.stdout).to_string();
    let protocols = version
        .lines()
        .find(|l| l.starts_with("Protocols:"))
        .unwrap_or("");
    if !protocols.split_whitespace().any(|p| p == "smtp") {
        return Err(format!("this curl was built without SMTP:\n{version}").into());
    }
    Ok(version.lines().next().unwrap_or("").to_string())
}

/// One rule per verb, so `verify_mocks` counts what each client drove. The message rule
/// records what the model was handed, and answers with what it saw, so the client's own
/// output shows it too.
fn smtp_rules(
    mock: MockLlmBuilder,
    seen: Arc<Mutex<Vec<serde_json::Value>>>,
    expect: &[(&'static str, usize)],
) -> MockLlmBuilder {
    let count = |verb: &str| {
        expect
            .iter()
            .find(|(v, _)| *v == verb)
            .map(|(_, n)| *n)
            .unwrap_or(0)
    };
    let mut mock = mock
        .on_instruction_containing("SMTP")
        .respond_with_actions(serde_json::json!([{
            "type": "open_server",
            "port": 0,
            "base_stack": "SMTP",
            "instruction": "Accept mail for example.com only"
        }]))
        .expect_calls(1)
        .and()
        .on_event("smtp_command")
        .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
        .respond_with_actions(serde_json::json!([{
            "type": "send_smtp_greeting", "hostname": "mx.example.com", "message": "ESMTP NetGet"
        }]))
        .expect_calls(count("greeting"))
        .and()
        // The whole message. Matched before anything keyed on `command`, since a body line
        // can contain any verb.
        .on_event("smtp_command")
        .and_event_data_contains("answer_with", "accept the message")
        .respond_with_actions_from_event(move |event| {
            seen.lock().unwrap().push(event.clone());
            let subject = event["headers"]["subject"]
                .as_str()
                .unwrap_or("?")
                .to_string();
            let bytes = event["message_bytes"].as_u64().unwrap_or(0);
            serde_json::json!([{
                "type": "send_smtp_ok",
                "message": format!("2.0.0 queued: {bytes} bytes, subject {subject}")
            }])
        })
        .expect_calls(count("message"))
        .and()
        .on_event("smtp_command")
        .and_event_data_contains("answer_with", "accept this sender")
        .respond_with_actions(serde_json::json!([
            {"type": "send_smtp_ok", "message": "2.1.0 Sender OK"}
        ]))
        .expect_calls(count("mail"))
        .and()
        .on_event("smtp_command")
        .and_event_data_contains("answer_with", "accept mail for this recipient")
        .and_event_data_contains("domain", "example.com")
        .respond_with_actions(serde_json::json!([
            {"type": "send_smtp_ok", "message": "2.1.5 Recipient OK"}
        ]))
        .expect_calls(count("rcpt_ok"))
        .and()
        .on_event("smtp_command")
        .and_event_data_contains("answer_with", "accept mail for this recipient")
        .respond_with_actions(serde_json::json!([
            {"type": "send_smtp_error", "code": 550, "message": "5.1.1 Not a local domain"}
        ]))
        .expect_calls(count("rcpt_refused"))
        .and()
        .on_event("smtp_command")
        .and_event_data_contains("answer_with", "send_smtp_start_data")
        .respond_with_actions(serde_json::json!([{"type": "send_smtp_start_data"}]))
        .expect_calls(count("data"))
        .and()
        .on_event("smtp_command")
        .and_event_data_contains("verb", "VRFY")
        // A raw reply ending in "\n", as a model writes one: the framing has to supply CRLF.
        .respond_with_actions(serde_json::json!([{
            "type": "send_smtp_message",
            "message": "252 2.1.5 Cannot VRFY user, but will accept message\n"
        }]))
        .expect_calls(count("vrfy"))
        .and()
        .on_event("smtp_command")
        .and_event_data_contains("answer_with", "send_smtp_quit")
        .respond_with_actions(serde_json::json!([
            {"type": "send_smtp_quit"}, {"type": "close_connection"}
        ]))
        .expect_calls(count("quit"))
        .and();
    for verb in ["NOOP", "RSET"] {
        mock = mock
            .on_event("smtp_command")
            .and_event_data_contains("verb", verb)
            .respond_with_actions(serde_json::json!([
                {"type": "send_smtp_ok", "message": "2.0.0 OK"}
            ]))
            .expect_calls(count(verb))
            .and();
    }
    mock
}

/// The body the model must be handed for smtplib's message: dot-unstuffed, `" ."` kept as a
/// line of text, CRLF shown as `\n`.
const EXPECTED_BODY: &str =
    "The compiler is finished.\n.leading dot\n .\nafter the space-dot line\nlast line\n";

/// smtplib: two transactions on one connection, the second refused at `MAIL FROM` for its
/// declared size.
///
/// LLM calls: 1 startup + greeting + NOOP + VRFY + MAIL + 2 RCPT + DATA + message + RSET +
/// NOOP + QUIT = **12**. EHLO and the oversized MAIL are answered by NetGet.
#[tokio::test]
async fn smtplib_completes_a_mail_transaction_against_the_smtp_server() -> E2EResult<()> {
    let python = require_python_smtplib().await?;
    println!("\n=== E2E: python {python} stdlib smtplib against the SMTP server ===");

    let seen = Arc::new(Mutex::new(Vec::new()));
    let rules_seen = seen.clone();
    let config = NetGetConfig::new_no_scripts(
        "Start an SMTP server on port 0 that accepts mail for example.com only.",
    )
    .with_mock(move |mock| {
        smtp_rules(
            mock,
            rules_seen,
            &[
                ("greeting", 1),
                ("NOOP", 2),
                ("vrfy", 1),
                ("mail", 1),
                ("rcpt_ok", 1),
                ("rcpt_refused", 1),
                ("data", 1),
                ("message", 1),
                ("RSET", 1),
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
    println!("  SMTP server on {upstream}, recording relay on {relay}");

    let out = timeout(
        Duration::from_secs(90),
        Command::new("python3")
            .args([
                "-I",
                "-c",
                SMTPLIB_DRIVER,
                "127.0.0.1",
                &relay.port().to_string(),
            ])
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| "the smtplib driver did not finish within 90s")??;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    println!("  smtplib stdout:\n{stdout}\n  smtplib stderr:\n{stderr}");
    assert!(
        out.status.success(),
        "the smtplib session failed (exit {}). Python's traceback is the failure:\n{stderr}",
        out.status
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("smtplib driver did not emit JSON ({e}).\nstdout:\n{stdout}"))?;

    // EHLO: NetGet's own reply, parsed by smtplib into its feature table.
    assert_eq!(parsed["ehlo"][0], 250);
    assert_eq!(
        parsed["esmtp_features"]["size"],
        netget::server::smtp::MAX_MESSAGE_BYTES.to_string(),
        "the SIZE NetGet advertises must be the limit it enforces"
    );
    assert!(
        parsed["esmtp_features"].get("8bitmime").is_some(),
        "{parsed}"
    );
    assert_eq!(parsed["noop"][0], 250);
    assert_eq!(parsed["vrfy"][0], 252);
    assert_eq!(parsed["mail"][0], 250);
    assert_eq!(parsed["rcpt_ok"][0], 250);
    assert_eq!(parsed["rcpt_refused"][0], 550);
    // The reply to the message is the model's, and it names what the model was handed.
    let message_bytes = parsed["message_bytes"].as_u64().unwrap();
    assert_eq!(parsed["data"][0], 250, "{parsed}");
    assert_eq!(
        parsed["data"][1],
        format!("2.0.0 queued: {message_bytes} bytes, subject Grüße from the lab"),
        "the model's view of the message differs from what smtplib sent"
    );
    assert_eq!(parsed["rset"][0], 250);
    assert_eq!(
        parsed["mail_too_big"][0], 552,
        "a MAIL FROM declaring more than SIZE must be refused 552: {parsed}"
    );
    assert_eq!(
        parsed["after_too_big"][0], 250,
        "the session must stay in step after the refused MAIL"
    );
    assert_eq!(parsed["quit"][0], 221);

    // The one message event: exactly what smtplib meant, not what it put on the wire.
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "one event for the whole message: {seen:#?}");
    let event = &seen[0];
    assert_eq!(event["command"], ".");
    assert_eq!(event["message_bytes"], message_bytes);
    assert_eq!(event["body"], EXPECTED_BODY, "{event:#}");
    assert_eq!(event["headers"]["from"], "Grace Hopper <grace@example.org>");
    assert_eq!(event["headers"]["x-folded"], "first part second part");

    // Wireshark's SMTP dissector over what crossed.
    let recorded = crate::helpers::recording_relay::recorded(&streams);
    assert_eq!(recorded.len(), 1, "one SMTP connection crossed the relay");
    crate::helpers::recording_relay::replay(
        crate::helpers::pcap_oracle::PcapOracle::tcp("smtp"),
        &recorded[0],
    )
    .assert_clean();

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// curl: one message to two recipients, uploaded from a file.
///
/// LLM calls: 1 startup + greeting + MAIL + 2 RCPT + DATA + message + QUIT = **8**.
#[tokio::test]
async fn curl_sends_a_message_through_the_smtp_server() -> E2EResult<()> {
    let curl = require_curl_smtp().await?;
    println!("\n=== E2E: {curl} against the SMTP server ===");

    let seen = Arc::new(Mutex::new(Vec::new()));
    let rules_seen = seen.clone();
    let config = NetGetConfig::new_no_scripts(
        "Start an SMTP server on port 0 that accepts mail for example.com only.",
    )
    .with_mock(move |mock| {
        smtp_rules(
            mock,
            rules_seen,
            &[
                ("greeting", 1),
                ("mail", 1),
                ("rcpt_ok", 2),
                ("data", 1),
                ("message", 1),
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
    let port = server.port;

    let dir = tempfile::tempdir()?;
    let body_path = dir.path().join("message.eml");
    // LF line endings on purpose: curl's SMTP upload converts them to CRLF and doubles the
    // leading dot, so what reaches the wire is curl's encoding, not the test's.
    std::fs::write(
        &body_path,
        "From: ops@example.org\nTo: alice@example.com, bob@example.com\nSubject: nightly \
         report\n\nAll jobs passed.\n.hidden line\n",
    )?;

    let out = timeout(
        Duration::from_secs(90),
        Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--verbose",
                "--max-time",
                "60",
                "--crlf",
                &format!("smtp://127.0.0.1:{port}/client.example.org"),
                "--mail-from",
                "ops@example.org",
                "--mail-rcpt",
                "alice@example.com",
                "--mail-rcpt",
                "bob@example.com",
                "--upload-file",
            ])
            .arg(&body_path)
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| "curl did not finish within 90s")??;
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    println!("  curl transcript:\n{stderr}");
    assert!(
        out.status.success(),
        "curl's SMTP session failed (exit {}):\n{stderr}",
        out.status
    );
    // curl's own transcript: what it sent and what it read back.
    assert!(stderr.contains("> EHLO client.example.org"), "{stderr}");
    assert!(
        stderr.contains("> MAIL FROM:<ops@example.org> SIZE="),
        "curl uses the SIZE NetGet advertises: {stderr}"
    );
    assert!(stderr.contains("< 250 2.0.0 queued: "), "{stderr}");
    assert!(stderr.contains("subject nightly report"), "{stderr}");

    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "one event for the whole message: {seen:#?}");
    assert_eq!(seen[0]["body"], "All jobs passed.\n.hidden line\n");
    assert_eq!(
        seen[0]["headers"]["to"],
        "alice@example.com, bob@example.com"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

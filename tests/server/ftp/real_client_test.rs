//! Two independent FTP clients — python3's stdlib `ftplib` and curl's libcurl FTP — each
//! completing real sessions, transfers included, against NetGet's FTP server.
//!
//! `ftplib` is pure Python in the standard library and libcurl is C; neither shares code with
//! the server or with the other. Both tests **fail** rather than skip when their client is
//! absent: a skip that returns success is a silent pass wherever the suite runs.
//!
//! # What each client drives, against what the server implements
//!
//! The server answers the data-connection setup verbs and `TYPE` itself; every other reply,
//! every listing and every file is the mocked model's.
//!
//! | Verb | `ftplib` | curl |
//! |---|---|---|
//! | greeting, `USER`, `PASS`, `QUIT` | `login()`, `quit()` | every run |
//! | `PWD` | `pwd()` | every run |
//! | `PASV` (server) | passive transfers | `--disable-epsv` |
//! | `EPSV` (server) | - (IPv4 uses PASV) | default |
//! | `PORT` (server) | `set_pasv(False)` | `-P 127.0.0.1 --disable-eprt` |
//! | `EPRT` (server) | - (IPv4 uses PORT) | `-P 127.0.0.1` |
//! | `TYPE A` / `TYPE I` (server) | `retrlines` / `retrbinary`, `storlines` / `storbinary` | listings and `--use-ascii` / downloads and uploads |
//! | `LIST` | `retrlines("LIST")` | `ftp://host/` |
//! | `NLST` | `nlst()`, passive and active | `--list-only` |
//! | `MLSD` | `mlsd()`, facts parsed | - |
//! | `RETR` | binary, ASCII, active, and a 550 refusal | binary, ASCII, PASV, EPRT, PORT |
//! | `SIZE` | - | before a binary `RETR`, and a 550 refusal (curl then gives up before `RETR`) |
//! | `STOR` | `storlines` (ASCII) and `storbinary` (binary, not UTF-8) | `-T` |
//! | `APPE` | - | `--append -T` |
//!
//! Not implemented, so neither client is asked to: `REST`, `STOU`, `ABOR` during a transfer,
//! `MODE`s other than stream, `TYPE E`, FTPS.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,mcp-http,sqlite,terminal-snapshot \
//!       --test server -- server::ftp::real_client_test --test-threads=8

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::{self, E2EResult, NetGetConfig};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// The file served as `notes.txt`, with local (LF) line endings. 23 bytes.
const NOTES: &str = "first line\nsecond line\n";

const LS_LINES: [&str; 2] = [
    "-rw-r--r-- 1 ftp ftp 23 Jan 01 00:00 notes.txt",
    "drwxr-xr-x 2 ftp ftp 4096 Jan 01 00:00 pub",
];
const NAMES: [&str; 2] = ["notes.txt", "pub"];
const MLSD_LINES: [&str; 2] = [
    "type=file;size=23;modify=20260101000000; notes.txt",
    "type=dir;modify=20260101000000; pub",
];

/// What each upload must reach the handler as, by file name.
///
/// `lines.txt` crosses the wire as CRLF in TYPE A and must arrive as LF; `curl.txt` crosses in
/// TYPE I and must keep its CR; `blob.bin` is not UTF-8 and must arrive as a size alone.
fn expected_upload(command: &str) -> Option<(usize, Option<&'static str>)> {
    if command.ends_with("lines.txt") {
        Some((11, Some("alpha\nbeta\n")))
    } else if command.ends_with("curl.txt") {
        Some((9, Some("one\r\ntwo\n")))
    } else if command.ends_with("blob.bin") {
        Some((10, None))
    } else {
        None
    }
}

/// The handler's answer to an upload: `226` naming what arrived, or `451` saying what differed.
fn upload_answer(event: &serde_json::Value) -> serde_json::Value {
    let command = event["command"].as_str().unwrap_or("");
    let bytes = event["upload_bytes"].as_u64().unwrap_or(u64::MAX) as usize;
    let text = event["upload_text"].as_str();
    let verdict = match expected_upload(command) {
        Some((want_bytes, want_text)) if want_bytes == bytes && want_text == text => "intact",
        _ => "DIFFERENT",
    };
    serde_json::json!([{
        "type": "send_ftp_response",
        "code": if verdict == "intact" { 226 } else { 451 },
        "message": format!("{verdict}: {bytes} bytes, text {}", text.is_some())
    }])
}

fn reply(code: u16, message: &str) -> serde_json::Value {
    serde_json::json!([{"type": "send_ftp_response", "code": code, "message": message}])
}

/// One rule per command, each with its own count; any command without a rule fails the test
/// (the unmatched request errors, and the server answers 421).
fn ftp_rules(mock: MockLlmBuilder, expect: &[(&'static str, usize)]) -> MockLlmBuilder {
    let count = |name: &str| {
        expect
            .iter()
            .find(|(v, _)| *v == name)
            .map(|(_, n)| *n)
            .unwrap_or(0)
    };
    let rules: Vec<(&str, &str, serde_json::Value)> = vec![
        (
            "greeting",
            "CONNECTION_ESTABLISHED",
            reply(220, "NetGet FTP ready"),
        ),
        ("user", "USER ", reply(331, "send your password")),
        ("pass", "PASS ", reply(230, "logged in")),
        ("pwd", "PWD", reply(257, "\"/\" is the current directory")),
        (
            "list",
            "LIST",
            serde_json::json!([{"type": "send_ftp_list", "entries": LS_LINES}]),
        ),
        (
            "nlst",
            "NLST",
            serde_json::json!([{"type": "send_ftp_list", "entries": NAMES}]),
        ),
        (
            "mlsd",
            "MLSD",
            serde_json::json!([{"type": "send_ftp_list", "entries": MLSD_LINES}]),
        ),
        ("size", "SIZE notes.txt", reply(213, "23")),
        (
            "size_missing",
            "SIZE missing.txt",
            reply(550, "missing.txt: no such file"),
        ),
        (
            "retr",
            "RETR notes.txt",
            serde_json::json!([{"type": "send_ftp_data", "data": NOTES}]),
        ),
        (
            "missing",
            "RETR missing.txt",
            reply(550, "missing.txt: no such file"),
        ),
        (
            "quit",
            "QUIT",
            serde_json::json!([
                {"type": "send_ftp_response", "code": 221, "message": "bye"},
                {"type": "close_connection"}
            ]),
        ),
    ];
    let mut mock = mock
        .on_instruction_containing("FTP")
        .respond_with_actions(serde_json::json!([{
            "type": "open_server",
            "port": 0,
            "base_stack": "FTP",
            "instruction": "Serve notes.txt and the pub directory; accept uploads"
        }]))
        .expect_calls(1)
        .and();
    for (name, command, answer) in rules {
        mock = mock
            .on_event("ftp_command")
            .and_event_data_contains("command", command)
            .respond_with_actions(answer)
            .expect_calls(count(name))
            .and();
    }
    for (name, verb) in [("stor", "STOR "), ("appe", "APPE ")] {
        mock = mock
            .on_event("ftp_command")
            .and_event_data_contains("command", verb)
            .respond_with_actions_from_event(upload_answer)
            .expect_calls(count(name))
            .and();
    }
    mock
}

async fn require(program: &str, args: &[&str], why: &str) -> E2EResult<String> {
    let out = timeout(
        Duration::from_secs(30),
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| format!("`{program}` did not answer within 30s"))?
    .map_err(|e| format!("{program} is not available ({e}): {why}"))?;
    if !out.status.success() {
        return Err(format!(
            "`{program} {}` exited {}: {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

const FTPLIB_DRIVER: &str = r#"
import ftplib, io, json, sys

host, port = sys.argv[1], int(sys.argv[2])
out = {"python": sys.version.split()[0]}

f = ftplib.FTP()
f.connect(host, port, timeout=30)
out["welcome"] = f.getwelcome()
out["login"] = f.login("alice", "secret")
out["pwd"] = f.pwd()
out["nlst"] = f.nlst()
lines = []
out["list_resp"] = f.retrlines("LIST", lines.append)
out["list"] = lines
out["mlsd"] = [[name, facts] for name, facts in f.mlsd()]
buf = io.BytesIO()
out["retr_resp"] = f.retrbinary("RETR notes.txt", buf.write)
out["retr_binary"] = buf.getvalue().decode()
lines = []
f.retrlines("RETR notes.txt", lines.append)
out["retr_lines"] = lines
try:
    f.retrbinary("RETR missing.txt", lambda b: None)
    out["missing"] = "no error"
except ftplib.error_perm as e:
    out["missing"] = str(e)
out["storlines"] = f.storlines("STOR lines.txt", io.BytesIO(b"alpha\nbeta\n"))
out["storbinary"] = f.storbinary("STOR blob.bin", io.BytesIO(b"raw\r\n\x00\xffend"))
f.set_pasv(False)
out["active_nlst"] = f.nlst()
buf = io.BytesIO()
f.retrbinary("RETR notes.txt", buf.write)
out["active_retr"] = buf.getvalue().decode()
out["quit"] = f.quit()
json.dump(out, sys.stdout)
"#;

/// ftplib: every listing verb, both representation types in each direction, passive and active
/// data connections and a refused download, on one control connection.
///
/// LLM calls: 1 startup + greeting + USER + PASS + PWD + NLST ×2 + LIST + MLSD + RETR ×3 +
/// RETR missing + STOR ×2 + QUIT = **16**. TYPE, PASV and PORT are the server's.
#[tokio::test]
async fn ftplib_lists_retrieves_and_stores_against_the_ftp_server() -> E2EResult<()> {
    let python = require(
        "python3",
        &[
            "-I",
            "-c",
            "import ftplib,sys; print(sys.version.split()[0])",
        ],
        "this test drives python's stdlib `ftplib`, one of the two independent clients FTP's \
         Beta rating rests on, and skipping it would leave that rating resting on curl alone. \
         Install python3 (`brew install python` / `apt-get install -y python3`).",
    )
    .await?;
    println!(
        "\n=== E2E: python {} ftplib against the FTP server ===",
        python.trim()
    );

    let config = NetGetConfig::new_no_scripts(
        "Start an FTP server on port 0 serving notes.txt and the pub directory.",
    )
    .with_mock(|mock| {
        ftp_rules(
            mock,
            &[
                ("greeting", 1),
                ("user", 1),
                ("pass", 1),
                ("pwd", 1),
                ("nlst", 2),
                ("list", 1),
                ("mlsd", 1),
                ("retr", 3),
                ("missing", 1),
                ("stor", 2),
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
    // The control connection goes through a recording relay for the pcap oracle; the data
    // connections go straight to the server, at the port its 227 named.
    let (relay, streams) = crate::helpers::recording_relay::tcp_relay(upstream).await;

    let out = timeout(
        Duration::from_secs(120),
        Command::new("python3")
            .args([
                "-I",
                "-c",
                FTPLIB_DRIVER,
                "127.0.0.1",
                &relay.port().to_string(),
            ])
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| "the ftplib driver did not finish within 120s")??;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    println!("  ftplib stdout:\n{stdout}\n  ftplib stderr:\n{stderr}");
    assert!(
        out.status.success(),
        "the ftplib session failed (exit {}). Python's traceback is the failure:\n{stderr}",
        out.status
    );
    let p: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("ftplib driver did not emit JSON ({e}).\nstdout:\n{stdout}"))?;

    assert_eq!(p["welcome"], "220 NetGet FTP ready");
    assert_eq!(p["login"], "230 logged in");
    assert_eq!(p["pwd"], "/");
    assert_eq!(p["nlst"], serde_json::json!(NAMES));
    assert_eq!(p["list"], serde_json::json!(LS_LINES));
    assert!(
        p["list_resp"].as_str().unwrap().starts_with("226"),
        "{}",
        p["list_resp"]
    );
    assert_eq!(
        p["mlsd"],
        serde_json::json!([
            ["notes.txt", {"type": "file", "size": "23", "modify": "20260101000000"}],
            ["pub", {"type": "dir", "modify": "20260101000000"}]
        ])
    );
    assert!(p["retr_resp"].as_str().unwrap().starts_with("226"));
    assert_eq!(
        p["retr_binary"], NOTES,
        "TYPE I must deliver the file's bytes unchanged"
    );
    assert_eq!(
        p["retr_lines"],
        serde_json::json!(["first line", "second line"])
    );
    assert_eq!(p["missing"], "550 missing.txt: no such file");
    assert_eq!(
        p["storlines"], "226 intact: 11 bytes, text true",
        "a TYPE A upload must reach the handler with CRLF turned back into LF"
    );
    assert_eq!(
        p["storbinary"], "226 intact: 10 bytes, text false",
        "a binary upload that is not UTF-8 must reach the handler as its size alone"
    );
    assert_eq!(p["active_nlst"], serde_json::json!(NAMES));
    assert_eq!(p["active_retr"], NOTES);
    assert_eq!(p["quit"], "221 bye");

    let recorded = crate::helpers::recording_relay::recorded(&streams);
    assert_eq!(
        recorded.len(),
        1,
        "one FTP control connection crossed the relay"
    );
    let control: String = recorded[0]
        .iter()
        .map(|(_, b)| String::from_utf8_lossy(b).to_string())
        .collect();
    for verb in [
        "TYPE A", "TYPE I", "PASV", "PORT ", "NLST", "LIST", "MLSD", "RETR", "STOR",
    ] {
        assert!(
            control.contains(verb),
            "ftplib never sent {verb}:\n{control}"
        );
    }
    crate::helpers::recording_relay::replay(
        crate::helpers::pcap_oracle::PcapOracle::tcp("ftp"),
        &recorded[0],
    )
    .assert_clean();

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// curl: each transfer its own connection, logging in anonymously.
///
/// LLM calls: 1 startup + 10 × (greeting + USER + PASS + PWD + QUIT) + LIST + NLST +
/// RETR ×5 + SIZE ×4 (curl sends none before an ASCII download) + SIZE missing + STOR + APPE
/// = **65**. curl asks `SIZE` before a binary `RETR` and gives up on its `550`, so the refused
/// download never reaches `RETR`; ftplib's refusal is the `RETR` one.
#[tokio::test]
async fn curl_lists_retrieves_and_uploads_against_the_ftp_server() -> E2EResult<()> {
    let version = require(
        "curl",
        &["--version"],
        "this test drives libcurl's FTP client, one of the two independent clients FTP's Beta \
         rating rests on. Install it (`brew install curl` / `apt-get install -y curl`).",
    )
    .await?;
    let protocols = version
        .lines()
        .find(|l| l.starts_with("Protocols:"))
        .unwrap_or("");
    if !protocols.split_whitespace().any(|p| p == "ftp") {
        return Err(format!("this curl was built without FTP:\n{version}").into());
    }
    println!(
        "\n=== E2E: {} against the FTP server ===",
        version.lines().next().unwrap_or("")
    );

    let config = NetGetConfig::new_no_scripts(
        "Start an FTP server on port 0 serving notes.txt and the pub directory.",
    )
    .with_mock(|mock| {
        ftp_rules(
            mock,
            &[
                ("greeting", 10),
                ("user", 10),
                ("pass", 10),
                ("pwd", 10),
                ("quit", 10),
                ("list", 1),
                ("nlst", 1),
                ("retr", 5),
                ("size", 4),
                ("size_missing", 1),
                ("stor", 1),
                ("appe", 1),
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
    let base = format!("ftp://127.0.0.1:{}", server.port);

    let upload = tempfile::NamedTempFile::new()?;
    std::fs::write(upload.path(), b"one\r\ntwo\n")?;
    let upload_path = upload.path().to_string_lossy().to_string();

    let curl = |args: Vec<String>| async move {
        let out = timeout(
            Duration::from_secs(90),
            Command::new("curl")
                .args(["--silent", "--show-error", "--verbose", "--max-time", "60"])
                .args(&args)
                .stdin(Stdio::null())
                .output(),
        )
        .await
        .map_err(|_| format!("curl {args:?} did not finish within 90s"))??;
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        println!("  curl {args:?} (exit {}):\n{stderr}", out.status);
        E2EResult::Ok((out.status.code(), out.stdout, stderr))
    };
    let ok = |(code, stdout, transcript): (Option<i32>, Vec<u8>, String), what: &str| {
        assert_eq!(code, Some(0), "curl {what} failed:\n{transcript}");
        (String::from_utf8_lossy(&stdout).to_string(), transcript)
    };

    let (listing, t) = ok(curl(vec![format!("{base}/")]).await?, "LIST");
    assert!(
        t.contains("> EPSV") && t.contains("> TYPE A") && t.contains("> LIST"),
        "{t}"
    );
    // curl turns an ASCII transfer's CRLF back into LF (its CURL_DO_LINEEND_CONV), so what
    // reaches stdout is the listing's lines with local endings. The CRLF on the wire is
    // asserted from a raw socket in data_connection_test.rs.
    assert_eq!(listing, format!("{}\n{}\n", LS_LINES[0], LS_LINES[1]));

    let (names, t) = ok(
        curl(vec!["--list-only".into(), format!("{base}/")]).await?,
        "NLST",
    );
    assert!(t.contains("> NLST"), "{t}");
    assert_eq!(names, "notes.txt\npub\n");

    let (file, t) = ok(curl(vec![format!("{base}/notes.txt")]).await?, "RETR");
    assert!(
        t.contains("> TYPE I") && t.contains("> RETR notes.txt"),
        "{t}"
    );
    assert_eq!(
        file, NOTES,
        "TYPE I must deliver the file's bytes unchanged"
    );

    let (file, t) = ok(
        curl(vec!["--use-ascii".into(), format!("{base}/notes.txt")]).await?,
        "RETR in ASCII",
    );
    assert!(t.contains("> TYPE A"), "{t}");
    assert_eq!(
        file, NOTES,
        "an ASCII download must come back to the client's own line endings"
    );

    let (file, t) = ok(
        curl(vec!["--disable-epsv".into(), format!("{base}/notes.txt")]).await?,
        "RETR over PASV",
    );
    assert!(
        t.contains("> PASV") && t.contains("227 Entering Passive Mode (127,0,0,1,"),
        "{t}"
    );
    assert_eq!(file, NOTES);

    let (file, t) = ok(
        curl(vec![
            "--ftp-port".into(),
            "127.0.0.1".into(),
            format!("{base}/notes.txt"),
        ])
        .await?,
        "RETR over EPRT",
    );
    assert!(t.contains("> EPRT |1|127.0.0.1|"), "{t}");
    assert_eq!(file, NOTES);

    let (file, t) = ok(
        curl(vec![
            "--ftp-port".into(),
            "127.0.0.1".into(),
            "--disable-eprt".into(),
            format!("{base}/notes.txt"),
        ])
        .await?,
        "RETR over PORT",
    );
    assert!(t.contains("> PORT 127,0,0,1,"), "{t}");
    assert_eq!(file, NOTES);

    let (_, t) = ok(
        curl(vec![
            "-T".into(),
            upload_path.clone(),
            format!("{base}/curl.txt"),
        ])
        .await?,
        "STOR",
    );
    assert!(t.contains("> STOR curl.txt"), "{t}");
    assert!(t.contains("< 226 intact: 9 bytes, text true"), "{t}");

    let (_, t) = ok(
        curl(vec![
            "--append".into(),
            "-T".into(),
            upload_path.clone(),
            format!("{base}/curl.txt"),
        ])
        .await?,
        "APPE",
    );
    assert!(t.contains("> APPE curl.txt"), "{t}");
    assert!(t.contains("< 226 intact: 9 bytes, text true"), "{t}");

    // A refused download: curl asks SIZE first and stops at its 550, before any EPSV, RETR or
    // 150, reporting exit 78 (CURLE_REMOTE_FILE_NOT_FOUND).
    let (code, _, t) = curl(vec![format!("{base}/missing.txt")]).await?;
    assert_eq!(
        code,
        Some(78),
        "curl must report the 550 as file-not-found:\n{t}"
    );
    assert!(t.contains("< 550 missing.txt: no such file"), "{t}");
    assert!(
        !t.contains("< 150"),
        "a refusal must not follow a 150:\n{t}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

//! Two independent FTP clients — python3's stdlib `ftplib` and curl's libcurl FTP — each
//! completing real sessions, transfers included, against NetGet's FTP server, in clear text
//! and over explicit FTPS.
//!
//! `ftplib` is pure Python in the standard library (its TLS is python's `ssl`, OpenSSL) and
//! libcurl is C; neither shares code with the server (rustls) or with the other. Every test
//! **fails** rather than skips when its client is absent: a skip that returns success is a
//! silent pass wherever the suite runs.
//!
//! # What each client drives, against what the server implements
//!
//! The server answers the data-connection setup verbs, `TYPE`, `REST`, `ABOR`, `AUTH`, `PBSZ`
//! and `PROT` itself; every other reply, every listing and every file is the mocked model's.
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
//! | `LIST` | `retrlines("LIST")` | `ftp://host/`, also over FTPS |
//! | `NLST` | `nlst()`, passive, active and over FTPS | `--list-only` |
//! | `MLSD` | `mlsd()`, facts parsed | - |
//! | `RETR` | text in TYPE I and A, a binary file byte-exact (`encoding: "hex"`), active, a 550 refusal, over FTPS | text in TYPE I and A, a binary file byte-exact, PASV, EPRT, PORT, over FTPS |
//! | `SIZE` | `size()` | before every binary `RETR`, and a 550 refusal (curl then gives up before `RETR`) |
//! | `MDTM` | `sendcmd("MDTM …")` | `-R` |
//! | `REST` (server) | `retrbinary(rest=6)`, a marker past the end (554), `storbinary(rest=6)` | `-C 6` |
//! | `STOR` | `storlines` (ASCII), `storbinary` (binary, not UTF-8: the handler checks its hex), restarted, over FTPS | `-T` text and binary, over FTPS |
//! | `APPE` | - | `--append -T` |
//! | `STOU` | `storbinary("STOU")` | - (curl has no STOU) |
//! | `ABOR` (server) | `abort()` during an upload, during a download, and with nothing in progress | - (curl sends no ABOR) |
//! | `AUTH TLS` / `AUTH SSL` (server) | `FTP_TLS.login()` (`AUTH TLS`) | `--ssl-reqd` (`AUTH SSL`) |
//! | `PBSZ`, `PROT P` (server) | `prot_p()` | `--ssl-reqd` |
//!
//! FTPS certificates: both clients verify the server's certificate, given as `cert_path` /
//! `key_path` and trusted through `cafile` / `--cacert`. Both FTPS sessions run against a
//! server started with `require_tls`, so neither could have sent a command in the clear.
//!
//! Not implemented, so neither client is asked to: `MODE`s other than stream, `TYPE E`,
//! implicit FTPS, `CCC`.
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

/// The file served as `blob.bin`: not UTF-8, with a CRLF, a lone LF and NULs that a text
/// conversion anywhere on the path would change.
const BLOB: &[u8] = b"\x89PNG\r\n\x1a\n\x00\xff\xfe binary \x80\x00\n";

/// What ftplib uploads as `blob.bin`.
const FTPLIB_BLOB_UP: &[u8] = b"raw\r\n\x00\xffend";

/// What curl uploads as `curl.bin`.
const CURL_BLOB_UP: &[u8] = b"\xff\xd8\xff\xe0curl\x00\r\n\x01";

/// How big the file ftplib aborts mid-download is: more than the server's send buffer and the
/// client's 4 KiB receive buffer hold unread, so the server is still writing when `ABOR` arrives.
const HUGE: usize = 1024 * 1024;

const LS_LINES: [&str; 2] = [
    "-rw-r--r-- 1 ftp ftp 23 Jan 01 00:00 notes.txt",
    "drwxr-xr-x 2 ftp ftp 4096 Jan 01 00:00 pub",
];
const NAMES: [&str; 2] = ["notes.txt", "pub"];
const MLSD_LINES: [&str; 2] = [
    "type=file;size=23;modify=20260101000000; notes.txt",
    "type=dir;modify=20260101000000; pub",
];

/// What one upload must reach the handler as.
struct Expected {
    bytes: usize,
    text: Option<&'static str>,
    hex: Option<String>,
    restart: Option<u64>,
}

/// What each upload must reach the handler as, by its command line.
///
/// `lines.txt` crosses the wire as CRLF in TYPE A and must arrive as LF; `curl.txt` crosses in
/// TYPE I and must keep its CR; `blob.bin` and `curl.bin` are not UTF-8 and must arrive as hex;
/// `resume.bin` is the tail of a restarted STOR; `STOU` names no file.
fn expected_upload(command: &str) -> Option<Expected> {
    let text = |bytes, text| Expected {
        bytes,
        text: Some(text),
        hex: None,
        restart: None,
    };
    let binary = |raw: &[u8]| Expected {
        bytes: raw.len(),
        text: None,
        hex: Some(hex::encode(raw)),
        restart: None,
    };
    if command.ends_with("lines.txt") {
        Some(text(11, "alpha\nbeta\n"))
    } else if command.ends_with("curl.txt") {
        Some(text(9, "one\r\ntwo\n"))
    } else if command.ends_with("blob.bin") {
        Some(binary(FTPLIB_BLOB_UP))
    } else if command.ends_with("curl.bin") {
        Some(binary(CURL_BLOB_UP))
    } else if command.ends_with("resume.bin") {
        Some(Expected {
            restart: Some(6),
            ..text(6, "world\n")
        })
    } else if command == "STOU" {
        Some(text(7, "unique\n"))
    } else {
        None
    }
}

/// The handler's answer to an upload: `226` naming what arrived, or `451` saying what differed.
fn upload_answer(event: &serde_json::Value) -> serde_json::Value {
    let command = event["command"].as_str().unwrap_or("");
    let bytes = event["upload_bytes"].as_u64().unwrap_or(u64::MAX) as usize;
    let text = event["upload_text"].as_str();
    let hex = event["upload_hex"].as_str();
    let restart = event["restart_offset"].as_u64();
    let verdict = match expected_upload(command) {
        Some(want)
            if want.bytes == bytes
                && want.text == text
                && want.hex.as_deref() == hex
                && want.restart == restart =>
        {
            "intact"
        }
        _ => "DIFFERENT",
    };
    let stored_as = match event["unique_name"].as_str() {
        Some(name) => format!("; stored as {name}"),
        None => String::new(),
    };
    serde_json::json!([{
        "type": "send_ftp_response",
        "code": if verdict == "intact" { 226 } else { 451 },
        "message": format!(
            "{verdict}: {bytes} bytes, text {}, hex {}{stored_as}",
            text.is_some(),
            hex.is_some()
        )
    }])
}

fn reply(code: u16, message: &str) -> serde_json::Value {
    serde_json::json!([{"type": "send_ftp_response", "code": code, "message": message}])
}

/// One rule per command, each with its own count; any command without a rule fails the test
/// (the unmatched request errors, and the server answers 421).
fn ftp_rules(
    mock: MockLlmBuilder,
    startup_params: serde_json::Value,
    expect: &[(&'static str, usize)],
) -> MockLlmBuilder {
    let count = |name: &str| {
        expect
            .iter()
            .find(|(v, _)| *v == name)
            .map(|(_, n)| *n)
            .unwrap_or(0)
    };
    let mut rules: Vec<(&str, &str, serde_json::Value)> = vec![
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
            "size_blob",
            "SIZE blob.bin",
            reply(213, &BLOB.len().to_string()),
        ),
        (
            "size_missing",
            "SIZE missing.txt",
            reply(550, "missing.txt: no such file"),
        ),
        ("mdtm", "MDTM notes.txt", reply(213, "20260101000000")),
        (
            "retr",
            "RETR notes.txt",
            serde_json::json!([{"type": "send_ftp_data", "data": NOTES}]),
        ),
        (
            "blob",
            "RETR blob.bin",
            serde_json::json!([{
                "type": "send_ftp_data",
                "encoding": "hex",
                "data": hex::encode(BLOB)
            }]),
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
    // A megabyte in a rule is worth building only for the test that asks for it.
    if count("huge") > 0 {
        rules.push((
            "huge",
            "RETR huge.bin",
            serde_json::json!([{"type": "send_ftp_data", "data": "x".repeat(HUGE)}]),
        ));
    }
    let mut mock = mock
        .on_instruction_containing("FTP")
        .respond_with_actions(serde_json::json!([{
            "type": "open_server",
            "port": 0,
            "base_stack": "FTP",
            "startup_params": startup_params,
            "instruction": "Serve notes.txt, blob.bin and the pub directory; accept uploads"
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
    for (name, verb) in [("stor", "STOR "), ("appe", "APPE "), ("stou", "STOU")] {
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

async fn require_python() -> E2EResult<String> {
    let version = require(
        "python3",
        &[
            "-I",
            "-c",
            "import ftplib,ssl,sys; print(sys.version.split()[0])",
        ],
        "this test drives python's stdlib `ftplib`, one of the two independent clients FTP's \
         Beta rating rests on, and skipping it would leave that rating resting on curl alone. \
         Install python3 (`brew install python` / `apt-get install -y python3`).",
    )
    .await?;
    Ok(version.trim().to_string())
}

/// curl, with FTP (and FTPS) compiled in; the version line for the log.
async fn require_curl() -> E2EResult<String> {
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
    for needed in ["ftp", "ftps"] {
        if !protocols.split_whitespace().any(|p| p == needed) {
            return Err(format!("this curl was built without {needed}:\n{version}").into());
        }
    }
    Ok(version.lines().next().unwrap_or("").to_string())
}

/// Start the server through the binary, as the mocked model's `open_server`.
async fn start(
    startup_params: serde_json::Value,
    expect: &'static [(&'static str, usize)],
) -> E2EResult<crate::helpers::server::NetGetServer> {
    let config = NetGetConfig::new_no_scripts(
        "Start an FTP server on port 0 serving notes.txt, blob.bin and the pub directory.",
    )
    .with_mock(move |mock| ftp_rules(mock, startup_params, expect));
    let server = timeout(
        Duration::from_secs(90),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "netget startup timed out")??;
    helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    Ok(server)
}

/// Run a python driver with `args`, returning the JSON object it printed.
async fn run_python(driver: &str, args: &[String]) -> E2EResult<serde_json::Value> {
    let out = timeout(
        Duration::from_secs(120),
        Command::new("python3")
            .arg("-I")
            .arg("-c")
            .arg(driver)
            .args(args)
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
    Ok(serde_json::from_str(&stdout)
        .map_err(|e| format!("ftplib driver did not emit JSON ({e}).\nstdout:\n{stdout}"))?)
}

/// A certificate for `localhost` and `127.0.0.1`, written as PEM files the server loads through
/// `cert_path` / `key_path` and the clients trust as their only CA.
struct CertFiles {
    _dir: tempfile::TempDir,
    cert: String,
    key: String,
}

fn cert_files() -> E2EResult<CertFiles> {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    let dir = tempfile::tempdir()?;
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, certified.cert.pem())?;
    std::fs::write(&key, certified.signing_key.serialize_pem())?;
    Ok(CertFiles {
        cert: cert.to_string_lossy().to_string(),
        key: key.to_string_lossy().to_string(),
        _dir: dir,
    })
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
buf = io.BytesIO()
out["blob_resp"] = f.retrbinary("RETR blob.bin", buf.write)
out["blob_hex"] = buf.getvalue().hex()
out["size"] = f.size("notes.txt")
out["mdtm"] = f.sendcmd("MDTM notes.txt")
try:
    f.retrbinary("RETR missing.txt", lambda b: None)
    out["missing"] = "no error"
except ftplib.error_perm as e:
    out["missing"] = str(e)
out["storlines"] = f.storlines("STOR lines.txt", io.BytesIO(b"alpha\nbeta\n"))
out["storbinary"] = f.storbinary("STOR blob.bin", io.BytesIO(bytes.fromhex(sys.argv[3])))
f.set_pasv(False)
out["active_nlst"] = f.nlst()
buf = io.BytesIO()
f.retrbinary("RETR notes.txt", buf.write)
out["active_retr"] = buf.getvalue().decode()
out["quit"] = f.quit()
json.dump(out, sys.stdout)
"#;

/// ftplib: every listing verb, both representation types in each direction, a binary file
/// byte-exact both ways, `SIZE` and `MDTM`, passive and active data connections and a refused
/// download, on one control connection.
///
/// LLM calls: 1 startup + greeting + USER + PASS + PWD + NLST ×2 + LIST + MLSD + RETR ×3 +
/// RETR blob.bin + SIZE + MDTM + RETR missing + STOR ×2 + QUIT = **19**. TYPE, PASV and PORT
/// are the server's.
#[tokio::test]
async fn ftplib_lists_retrieves_and_stores_against_the_ftp_server() -> E2EResult<()> {
    let python = require_python().await?;
    println!("\n=== E2E: python {python} ftplib against the FTP server ===");

    let server = start(
        serde_json::json!({}),
        &[
            ("greeting", 1),
            ("user", 1),
            ("pass", 1),
            ("pwd", 1),
            ("nlst", 2),
            ("list", 1),
            ("mlsd", 1),
            ("retr", 3),
            ("blob", 1),
            ("size", 1),
            ("mdtm", 1),
            ("missing", 1),
            ("stor", 2),
            ("quit", 1),
        ],
    )
    .await?;
    let upstream: std::net::SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    // The control connection goes through a recording relay for the pcap oracle; the data
    // connections go straight to the server, at the port its 227 named.
    let (relay, streams) = crate::helpers::recording_relay::tcp_relay(upstream).await;

    let p = run_python(
        FTPLIB_DRIVER,
        &[
            "127.0.0.1".to_string(),
            relay.port().to_string(),
            hex::encode(FTPLIB_BLOB_UP),
        ],
    )
    .await?;

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
    assert!(p["blob_resp"].as_str().unwrap().starts_with("226"));
    assert_eq!(
        p["blob_hex"],
        hex::encode(BLOB),
        "a binary file given as hex must reach the client byte for byte in TYPE I"
    );
    assert_eq!(p["size"], 23);
    assert_eq!(p["mdtm"], "213 20260101000000");
    assert_eq!(p["missing"], "550 missing.txt: no such file");
    assert_eq!(
        p["storlines"], "226 intact: 11 bytes, text true, hex false",
        "a TYPE A upload must reach the handler with CRLF turned back into LF"
    );
    assert_eq!(
        p["storbinary"], "226 intact: 10 bytes, text false, hex true",
        "a binary upload that is not UTF-8 must reach the handler as its hex"
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
        "TYPE A", "TYPE I", "PASV", "PORT ", "NLST", "LIST", "MLSD", "RETR", "STOR", "SIZE", "MDTM",
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

const FTPLIB_RESTART_ABORT_DRIVER: &str = r#"
import ftplib, io, json, socket, sys

host, port = sys.argv[1], int(sys.argv[2])
out = {}

f = ftplib.FTP()
f.connect(host, port, timeout=30)
f.login("alice", "secret")

buf = io.BytesIO()
out["rest_retr_resp"] = f.retrbinary("RETR notes.txt", buf.write, rest=6)
out["rest_retr"] = buf.getvalue().decode()
try:
    f.retrbinary("RETR notes.txt", lambda b: None, rest=100)
    out["rest_past_end"] = "no error"
except ftplib.error_perm as e:
    out["rest_past_end"] = str(e)
out["rest_stor"] = f.storbinary("STOR resume.bin", io.BytesIO(b"world\n"), rest=6)
out["stou"] = f.storbinary("STOU", io.BytesIO(b"unique\n"))

# ABOR while the server is reading an upload it has not finished.
conn = f.transfercmd("STOR big.bin")
conn.sendall(b"partial")
out["abor_upload"] = f.abort()
out["abor_upload_then"] = f.getresp()
conn.close()

# ABOR while the server is writing a download the client has stopped reading. The data
# connection is opened as transfercmd() would, but with a small receive buffer, so the server's
# writes block well before the file has crossed.
conn = socket.socket()
conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
conn.settimeout(30)
conn.connect(f.makepasv())
out["abor_download_150"] = f.sendcmd("RETR huge.bin")[:3]
out["abor_download_read"] = len(conn.recv(4096))
out["abor_download"] = f.abort()
out["abor_download_then"] = f.getresp()
conn.close()

# ABOR with nothing in progress.
out["abor_idle"] = f.abort()
out["noop_after"] = f.sendcmd("PWD")
out["quit"] = f.quit()
json.dump(out, sys.stdout)
"#;

/// ftplib: `REST` before `RETR` and `STOR` and past the end of the file, `STOU`, and `ABOR`
/// during an upload, during a download and with nothing in progress.
///
/// Straight to the server, not through the recording relay: ftplib sends `ABOR` as TCP urgent
/// data, and a relay without `SO_OOBINLINE` would drop its last byte before the server saw it.
///
/// LLM calls: 1 startup + greeting + USER + PASS + RETR notes.txt ×2 + STOR resume.bin + STOU
/// + RETR huge.bin + PWD + QUIT = **11**. `STOR big.bin` is aborted before the handler is asked;
/// `REST` and `ABOR` are the server's.
#[tokio::test]
async fn ftplib_restarts_stores_unique_and_aborts_against_the_ftp_server() -> E2EResult<()> {
    let python = require_python().await?;
    println!("\n=== E2E: python {python} ftplib REST / STOU / ABOR against the FTP server ===");

    let server = start(
        serde_json::json!({}),
        &[
            ("greeting", 1),
            ("user", 1),
            ("pass", 1),
            ("retr", 2),
            ("stor", 1),
            ("stou", 1),
            ("huge", 1),
            ("pwd", 1),
            ("quit", 1),
        ],
    )
    .await?;

    let p = run_python(
        FTPLIB_RESTART_ABORT_DRIVER,
        &["127.0.0.1".to_string(), server.port.to_string()],
    )
    .await?;

    assert!(p["rest_retr_resp"].as_str().unwrap().starts_with("226"));
    assert_eq!(
        p["rest_retr"],
        &NOTES[6..],
        "REST 6 must start the download six bytes into the file the handler gave"
    );
    assert_eq!(
        p["rest_past_end"], "554 Restart offset 100 is past the end of the file (23 bytes)",
        "a marker past the end is refused before any 150"
    );
    assert_eq!(
        p["rest_stor"], "226 intact: 6 bytes, text true, hex false",
        "a restarted STOR must tell the handler its offset"
    );
    let stou = p["stou"].as_str().unwrap();
    assert!(
        stou.starts_with("226 intact: 7 bytes, text true, hex false; stored as ftp-"),
        "STOU must reach the handler with the name the server chose: {stou}"
    );
    assert_eq!(p["abor_upload"], "426 Connection closed; transfer aborted");
    assert_eq!(p["abor_upload_then"], "226 Abort successful");
    assert_eq!(p["abor_download_150"], "150");
    assert!(p["abor_download_read"].as_u64().unwrap() > 0);
    assert_eq!(
        p["abor_download"],
        "426 Connection closed; transfer aborted"
    );
    assert_eq!(p["abor_download_then"], "226 Abort successful");
    assert_eq!(p["abor_idle"], "225 No transfer to abort");
    assert_eq!(
        p["noop_after"], "257 \"/\" is the current directory",
        "after the aborts the replies must still line up with the commands"
    );
    assert_eq!(p["quit"], "221 bye");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

const FTPLIB_TLS_DRIVER: &str = r#"
import ftplib, io, json, ssl, sys

host, port, cafile = sys.argv[1], int(sys.argv[2]), sys.argv[3]
out = {}

ctx = ssl.create_default_context(cafile=cafile)
f = ftplib.FTP_TLS(context=ctx)
f.connect(host, port, timeout=30)
out["login"] = f.login("alice", "secret")
out["control_tls"] = f.sock.version()
out["prot_p"] = f.prot_p()
out["nlst"] = f.nlst()
buf = io.BytesIO()
out["retr_resp"] = f.retrbinary("RETR notes.txt", buf.write)
out["retr"] = buf.getvalue().decode()
buf = io.BytesIO()
f.retrbinary("RETR blob.bin", buf.write)
out["blob_hex"] = buf.getvalue().hex()
out["storbinary"] = f.storbinary("STOR blob.bin", io.BytesIO(bytes.fromhex(sys.argv[4])))
out["storlines"] = f.storlines("STOR lines.txt", io.BytesIO(b"alpha\nbeta\n"))
out["quit"] = f.quit()
json.dump(out, sys.stdout)
"#;

/// ftplib's `FTP_TLS`: `AUTH TLS`, `PBSZ 0`, `PROT P`, then listings, text and binary downloads
/// and uploads with every data connection TLS, verifying the server's certificate, against a
/// server started with `require_tls`.
///
/// LLM calls: 1 startup + greeting + USER + PASS + NLST + RETR notes.txt + RETR blob.bin +
/// STOR ×2 + QUIT = **10**. AUTH, PBSZ and PROT are the server's.
#[tokio::test]
async fn ftplib_ftps_against_the_ftp_server() -> E2EResult<()> {
    let python = require_python().await?;
    println!("\n=== E2E: python {python} ftplib.FTP_TLS against the FTP server ===");
    let certs = cert_files()?;

    let server = start(
        serde_json::json!({"cert_path": certs.cert, "key_path": certs.key, "require_tls": true}),
        &[
            ("greeting", 1),
            ("user", 1),
            ("pass", 1),
            ("nlst", 1),
            ("retr", 1),
            ("blob", 1),
            ("stor", 2),
            ("quit", 1),
        ],
    )
    .await?;

    let p = run_python(
        FTPLIB_TLS_DRIVER,
        &[
            "127.0.0.1".to_string(),
            server.port.to_string(),
            certs.cert.clone(),
            hex::encode(FTPLIB_BLOB_UP),
        ],
    )
    .await?;

    assert_eq!(p["login"], "230 logged in");
    assert!(
        p["control_tls"].as_str().unwrap_or("").starts_with("TLSv1"),
        "{}",
        p["control_tls"]
    );
    assert_eq!(p["prot_p"], "200 Protection level set to P");
    assert_eq!(p["nlst"], serde_json::json!(NAMES));
    assert!(p["retr_resp"].as_str().unwrap().starts_with("226"));
    assert_eq!(p["retr"], NOTES);
    assert_eq!(p["blob_hex"], hex::encode(BLOB));
    assert_eq!(
        p["storbinary"],
        "226 intact: 10 bytes, text false, hex true"
    );
    assert_eq!(p["storlines"], "226 intact: 11 bytes, text true, hex false");
    assert_eq!(p["quit"], "221 bye");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

type CurlOutcome = (Option<i32>, Vec<u8>, String);

async fn curl(args: Vec<String>) -> E2EResult<CurlOutcome> {
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
    Ok((out.status.code(), out.stdout, stderr))
}

fn ok((code, stdout, transcript): CurlOutcome, what: &str) -> (Vec<u8>, String) {
    assert_eq!(code, Some(0), "curl {what} failed:\n{transcript}");
    (stdout, transcript)
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes).to_string()
}

/// curl: each transfer its own connection, logging in anonymously.
///
/// LLM calls: 1 startup + 14 × (greeting + USER + PASS + PWD + QUIT) + LIST + NLST +
/// RETR notes.txt ×7 + SIZE notes.txt ×6 (curl sends none before an ASCII download) + SIZE
/// blob.bin + RETR blob.bin + MDTM + SIZE missing + STOR ×2 + APPE = **93**. curl asks `SIZE`
/// before a binary `RETR` and gives up on its `550`, so the refused download never reaches
/// `RETR`; ftplib's refusal is the `RETR` one.
#[tokio::test]
async fn curl_lists_retrieves_and_uploads_against_the_ftp_server() -> E2EResult<()> {
    let version = require_curl().await?;
    println!("\n=== E2E: {version} against the FTP server ===");

    let server = start(
        serde_json::json!({}),
        &[
            ("greeting", 14),
            ("user", 14),
            ("pass", 14),
            ("pwd", 14),
            ("quit", 14),
            ("list", 1),
            ("nlst", 1),
            ("retr", 7),
            ("size", 6),
            ("size_blob", 1),
            ("blob", 1),
            ("mdtm", 1),
            ("size_missing", 1),
            ("stor", 2),
            ("appe", 1),
        ],
    )
    .await?;
    let base = format!("ftp://127.0.0.1:{}", server.port);

    let dir = tempfile::tempdir()?;
    let upload = dir.path().join("curl.txt");
    std::fs::write(&upload, b"one\r\ntwo\n")?;
    let upload = upload.to_string_lossy().to_string();
    let binary = dir.path().join("curl.bin");
    std::fs::write(&binary, CURL_BLOB_UP)?;
    let binary = binary.to_string_lossy().to_string();
    let timed = dir.path().join("timed.txt").to_string_lossy().to_string();

    let (listing, t) = ok(curl(vec![format!("{base}/")]).await?, "LIST");
    assert!(
        t.contains("> EPSV") && t.contains("> TYPE A") && t.contains("> LIST"),
        "{t}"
    );
    // curl turns an ASCII transfer's CRLF back into LF (its CURL_DO_LINEEND_CONV), so what
    // reaches stdout is the listing's lines with local endings. The CRLF on the wire is
    // asserted from a raw socket in data_connection_test.rs.
    assert_eq!(text(listing), format!("{}\n{}\n", LS_LINES[0], LS_LINES[1]));

    let (names, t) = ok(
        curl(vec!["--list-only".into(), format!("{base}/")]).await?,
        "NLST",
    );
    assert!(t.contains("> NLST"), "{t}");
    assert_eq!(text(names), "notes.txt\npub\n");

    let (file, t) = ok(curl(vec![format!("{base}/notes.txt")]).await?, "RETR");
    assert!(
        t.contains("> TYPE I") && t.contains("> RETR notes.txt"),
        "{t}"
    );
    assert_eq!(
        text(file),
        NOTES,
        "TYPE I must deliver the file's bytes unchanged"
    );

    let (file, t) = ok(curl(vec![format!("{base}/blob.bin")]).await?, "binary RETR");
    assert!(t.contains("> RETR blob.bin"), "{t}");
    assert_eq!(
        file, BLOB,
        "a binary file given as hex must reach curl byte for byte"
    );

    let (file, t) = ok(
        curl(vec!["--use-ascii".into(), format!("{base}/notes.txt")]).await?,
        "RETR in ASCII",
    );
    assert!(t.contains("> TYPE A"), "{t}");
    assert_eq!(
        text(file),
        NOTES,
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
    assert_eq!(text(file), NOTES);

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
    assert_eq!(text(file), NOTES);

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
    assert_eq!(text(file), NOTES);

    let (file, t) = ok(
        curl(vec![
            "--continue-at".into(),
            "6".into(),
            format!("{base}/notes.txt"),
        ])
        .await?,
        "RETR restarted with REST",
    );
    assert!(t.contains("> REST 6") && t.contains("< 350 "), "{t}");
    assert_eq!(
        text(file),
        &NOTES[6..],
        "REST 6 must start the download six bytes into the file"
    );

    let (_, t) = ok(
        curl(vec![
            "--remote-time".into(),
            "-o".into(),
            timed.clone(),
            format!("{base}/notes.txt"),
        ])
        .await?,
        "RETR with MDTM",
    );
    assert!(t.contains("> MDTM notes.txt"), "{t}");
    let modified = std::fs::metadata(&timed)?.modified()?;
    assert_eq!(
        modified.duration_since(std::time::UNIX_EPOCH)?.as_secs(),
        1_767_225_600,
        "curl -R must set the file's time from the 213 the handler gave MDTM (2026-01-01)"
    );

    let (_, t) = ok(
        curl(vec![
            "-T".into(),
            upload.clone(),
            format!("{base}/curl.txt"),
        ])
        .await?,
        "STOR",
    );
    assert!(t.contains("> STOR curl.txt"), "{t}");
    assert!(
        t.contains("< 226 intact: 9 bytes, text true, hex false"),
        "{t}"
    );

    let (_, t) = ok(
        curl(vec![
            "-T".into(),
            binary.clone(),
            format!("{base}/curl.bin"),
        ])
        .await?,
        "binary STOR",
    );
    assert!(t.contains("> STOR curl.bin"), "{t}");
    assert!(
        t.contains("< 226 intact: 12 bytes, text false, hex true"),
        "a binary upload must reach the handler as its exact hex:\n{t}"
    );

    let (_, t) = ok(
        curl(vec![
            "--append".into(),
            "-T".into(),
            upload.clone(),
            format!("{base}/curl.txt"),
        ])
        .await?,
        "APPE",
    );
    assert!(t.contains("> APPE curl.txt"), "{t}");
    assert!(
        t.contains("< 226 intact: 9 bytes, text true, hex false"),
        "{t}"
    );

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

/// curl `--ssl-reqd`: explicit FTPS with the control and every data connection TLS, verifying
/// the server's certificate against `--cacert`, against a server started with `require_tls`.
///
/// LLM calls: 1 startup + 3 × (greeting + USER + PASS + PWD + QUIT) + LIST + SIZE blob.bin +
/// RETR blob.bin + STOR = **20**. AUTH, PBSZ and PROT are the server's.
#[tokio::test]
async fn curl_ftps_against_the_ftp_server() -> E2EResult<()> {
    let version = require_curl().await?;
    println!("\n=== E2E: {version} --ssl-reqd against the FTP server ===");
    let certs = cert_files()?;

    let server = start(
        serde_json::json!({"cert_path": certs.cert, "key_path": certs.key, "require_tls": true}),
        &[
            ("greeting", 3),
            ("user", 3),
            ("pass", 3),
            ("pwd", 3),
            ("quit", 3),
            ("list", 1),
            ("size_blob", 1),
            ("blob", 1),
            ("stor", 1),
        ],
    )
    .await?;
    let base = format!("ftp://127.0.0.1:{}", server.port);
    let tls = |mut args: Vec<String>| {
        let mut all = vec![
            "--ssl-reqd".to_string(),
            "--cacert".to_string(),
            certs.cert.clone(),
        ];
        all.append(&mut args);
        all
    };
    let dir = tempfile::tempdir()?;
    let binary = dir.path().join("curl.bin");
    std::fs::write(&binary, CURL_BLOB_UP)?;
    let binary = binary.to_string_lossy().to_string();

    let (listing, t) = ok(curl(tls(vec![format!("{base}/")])).await?, "LIST over FTPS");
    assert!(t.contains("> AUTH "), "curl never asked for TLS:\n{t}");
    assert!(t.contains("< 234 "), "{t}");
    assert!(t.contains("> PBSZ 0") && t.contains("> PROT P"), "{t}");
    assert!(t.contains("< 200 Protection level set to P"), "{t}");
    assert!(t.contains("SSL connection using TLSv1."), "{t}");
    assert_eq!(text(listing), format!("{}\n{}\n", LS_LINES[0], LS_LINES[1]));

    let (file, t) = ok(
        curl(tls(vec![format!("{base}/blob.bin")])).await?,
        "binary RETR over FTPS",
    );
    assert!(t.contains("> RETR blob.bin"), "{t}");
    assert_eq!(file, BLOB);

    let (_, t) = ok(
        curl(tls(vec!["-T".into(), binary, format!("{base}/curl.bin")])).await?,
        "binary STOR over FTPS",
    );
    assert!(
        t.contains("< 226 intact: 12 bytes, text false, hex true"),
        "{t}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

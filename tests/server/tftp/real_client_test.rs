//! Two independent TFTP clients — curl's libcurl TFTP and the system `tftp(1)` (BSD tftp on
//! macOS, tftp-hpa on Linux) — downloading and uploading files through NetGet's TFTP server.
//!
//! Neither shares code with the server or with the other, and both tests **fail** rather
//! than skip when their client is absent: a skip that returns success is a silent pass
//! wherever the suite runs.
//!
//! # What each client drives, against what the server implements
//!
//! | Packet | curl | `tftp(1)` |
//! |---|---|---|
//! | RRQ, `octet` | three files: whole-file, per-block, refused | `binary` + `get` |
//! | RRQ, `netascii` | - | `ascii` + `get` |
//! | WRQ, `octet` | `--upload-file` | `binary` + `put` |
//! | DATA (server → client) across several blocks, short final block | yes | yes |
//! | DATA, a file of exactly 1024 bytes (empty final block) | - | yes |
//! | ACK (client → server), one per block | yes | yes |
//! | DATA (client → server) / ACK (server → client) | yes | yes |
//! | ERROR 1 (file not found) | yes, curl exits 68 | - |
//!
//! curl sends RFC 2347 options (`blksize`, `tsize`) in its RRQ/WRQ; the server implements no
//! option negotiation, sends no OACK, and curl falls back to RFC 1350's 512-byte blocks, as
//! RFC 2347 requires of a client whose server ignores its options.
//!
//! # What this pass found
//!
//! Item 3 is what these two clients exposed, and 2 is what makes their downloads one model
//! call each rather than one per block; 1, 4 and 6 are the lockstep's failure
//! cases, which a loopback client rarely provokes, so `retransmit_test.rs` provokes them from
//! raw sockets; 5 was found reading the transfer code.
//!
//! 1. **A block was sent once.** The server sent each DATA packet a single time and read one
//!    datagram back; any other datagram — a duplicate ACK, or one from another port — ended
//!    the read with the transfer still registered. Every DATA block is now retransmitted until
//!    acknowledged ([`netget::server::tftp`]'s `await_ack`), an ACK for an earlier block is
//!    ignored (retransmitting on it is the Sorcerer's Apprentice bug), and a datagram from a
//!    stranger is answered `ERROR 5`.
//! 2. **The model had to write the file as hex, a block per call.** `send_tftp_data` took only
//!    `data_hex`, and every ACK cost a model call. `send_tftp_file` takes the whole file as
//!    text and NetGet sends the blocks; `send_tftp_data` takes text too.
//! 3. **`netascii` was not encoded.** RFC 1350 §5 makes a netascii file's lines end in CR LF;
//!    the server sent the bytes the model wrote, so `tftp(1)` in `ascii` mode received bare
//!    LFs. The file now goes out netascii-encoded and `tftp` writes back exactly the text the
//!    model served.
//! 4. **A retransmitted RRQ started a second transfer**, on a second TID, which a client
//!    rejects with ERROR 5 — and a model thinking for a few seconds is exactly when clients
//!    retransmit. A repeat of a request whose transfer is running is now ignored.
//! 5. **Transfer sockets were bound to `0.0.0.0`** whatever address the server was told to
//!    listen on, so a loopback server answered from every interface. They are bound to the
//!    server's own address.
//! 6. **An upload's retransmitted DATA block went to the model again**, and a lost final ACK
//!    was never resent. A duplicate block is now answered with the ACK already sent, and the
//!    transfer dallies after the final block (RFC 1350 §6).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,mcp-http,sqlite,terminal-snapshot \
//!       --test server -- server::tftp::real_client_test --test-threads=8

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::{self, E2EResult, NetGetConfig};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

/// A text file of three blocks (512, 512, the rest).
fn boot_menu() -> String {
    let mut text = String::from("DEFAULT linux\nPROMPT 0\nTIMEOUT 50\n");
    let mut n = 0;
    while text.len() < 1300 {
        n += 1;
        text.push_str(&format!(
            "LABEL entry{n:03}\n  KERNEL vmlinuz-{n}\n  APPEND quiet\n"
        ));
    }
    text
}

/// Exactly two blocks, so the transfer must end with an empty third block.
fn exact_two_blocks() -> String {
    let mut text = String::new();
    let mut i = 0;
    while text.len() < 1024 {
        text.push((b'a' + (i % 26) as u8) as char);
        i += 1;
        if i % 63 == 0 {
            text.push('\n');
        }
    }
    text.truncate(1024);
    text
}

/// The uploaded file's blocks, as the model saw them (`data`, the text form).
type Uploads = Arc<Mutex<Vec<(u64, String)>>>;

fn tftp_rules(mock: MockLlmBuilder, uploads: Uploads, expect: &[(&str, usize)]) -> MockLlmBuilder {
    let count = |name: &str| {
        expect
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, c)| *c)
            .unwrap_or(0)
    };
    let menu = boot_menu();
    let block1: String = menu.chars().take(512).collect();
    mock.on_instruction_containing("TFTP")
        .respond_with_actions(serde_json::json!([{
            "type": "open_server", "port": 0, "base_stack": "TFTP",
            "instruction": "Serve the boot files"
        }]))
        .expect_calls(1)
        .and()
        .on_event("tftp_read_request")
        .and_event_data_contains("filename", "pxelinux.cfg/default")
        .respond_with_actions(serde_json::json!([
            {"type": "send_tftp_file", "content": menu}
        ]))
        .expect_calls(count("menu"))
        .and()
        .on_event("tftp_read_request")
        .and_event_data_contains("filename", "exact.txt")
        .respond_with_actions(serde_json::json!([
            {"type": "send_tftp_file", "content": exact_two_blocks()}
        ]))
        .expect_calls(count("exact"))
        .and()
        // The model sends the file itself, a block per call.
        .on_event("tftp_read_request")
        .and_event_data_contains("filename", "blocks.txt")
        .respond_with_actions(serde_json::json!([
            {"type": "send_tftp_data", "block_number": 1, "data": block1}
        ]))
        .expect_calls(count("blocks"))
        .and()
        .on_event("tftp_ack_received")
        .respond_with_actions(serde_json::json!([
            {"type": "send_tftp_data", "block_number": 2, "data": "and that is all.\n"}
        ]))
        .expect_calls(count("blocks"))
        .and()
        .on_event("tftp_read_request")
        .and_event_data_contains("filename", "missing.bin")
        .respond_with_actions(serde_json::json!([
            {"type": "send_tftp_error", "error_code": 1, "error_message": "File not found"}
        ]))
        .expect_calls(count("missing"))
        .and()
        .on_event("tftp_write_request")
        .respond_with_actions(serde_json::json!([{"type": "send_tftp_ack", "block_number": 0}]))
        .expect_calls(count("upload"))
        .and()
        .on_event("tftp_data_block")
        .respond_with_actions_from_event(move |event| {
            let block = event["block_number"].as_u64().unwrap_or(0);
            let data = event["data"].as_str().unwrap_or("<not text>").to_string();
            uploads.lock().unwrap().push((block, data));
            serde_json::json!([{"type": "send_tftp_ack", "block_number": block}])
        })
        .expect_calls(count("upload_blocks"))
        .and()
}

/// The text a client wrote, as one file, from the blocks the model was shown.
fn reassemble(uploads: &Uploads) -> String {
    let mut blocks = uploads.lock().unwrap().clone();
    blocks.sort();
    blocks.into_iter().map(|(_, d)| d).collect()
}

/// An upload of two blocks and a bit.
fn upload_body() -> String {
    (0..30)
        .map(|i| format!("log line {i:02}: everything nominal\n"))
        .collect()
}

async fn require_curl_tftp() -> E2EResult<String> {
    let out = Command::new("curl")
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| {
            format!(
                "curl is not available ({e}): this test drives libcurl's TFTP client, one of the \
                 two independent clients TFTP's Beta rating rests on. Install it (`brew install \
                 curl` / `apt-get install -y curl`)."
            )
        })?;
    let version = String::from_utf8_lossy(&out.stdout).to_string();
    let protocols = version
        .lines()
        .find(|l| l.starts_with("Protocols:"))
        .unwrap_or("");
    if !protocols.split_whitespace().any(|p| p == "tftp") {
        return Err(format!("this curl was built without TFTP:\n{version}").into());
    }
    Ok(version.lines().next().unwrap_or("").to_string())
}

async fn start(
    expect: &[(&str, usize)],
) -> E2EResult<(crate::helpers::server::NetGetServer, Uploads)> {
    let uploads: Uploads = Arc::default();
    let rules_uploads = uploads.clone();
    let expect: Vec<(String, usize)> = expect.iter().map(|(n, c)| (n.to_string(), *c)).collect();
    let config = NetGetConfig::new_no_scripts("Start a TFTP server on port 0 serving boot files.")
        .with_mock(move |mock| {
            let expect: Vec<(&str, usize)> = expect.iter().map(|(n, c)| (n.as_str(), *c)).collect();
            tftp_rules(mock, rules_uploads, &expect)
        });
    let server = timeout(
        Duration::from_secs(90),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "netget startup timed out")??;
    Ok((server, uploads))
}

/// curl: a whole-file download, a model-driven download, a refused one, and an upload.
///
/// LLM calls: 1 startup + menu RRQ + blocks RRQ + 1 ACK + missing RRQ + WRQ + 2 DATA = **8**.
#[tokio::test]
async fn curl_downloads_and_uploads_through_the_tftp_server() -> E2EResult<()> {
    let curl = require_curl_tftp().await?;
    println!("\n=== E2E: {curl} against the TFTP server ===");
    let (server, uploads) = start(&[
        ("menu", 1),
        ("blocks", 1),
        ("missing", 1),
        ("upload", 1),
        ("upload_blocks", 2),
    ])
    .await?;
    let port = server.port;

    let curl_tftp = |args: Vec<String>| async move {
        let out = timeout(
            Duration::from_secs(90),
            Command::new("curl")
                .args(["--silent", "--show-error", "--max-time", "60"])
                .args(&args)
                .stdin(Stdio::null())
                .output(),
        )
        .await
        .map_err(|_| format!("curl {args:?} did not finish within 90s"))??;
        println!(
            "  curl {args:?}: exit {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        E2EResult::Ok(out)
    };

    let out = curl_tftp(vec![format!(
        "tftp://127.0.0.1:{port}/pxelinux.cfg/default"
    )])
    .await?;
    assert!(out.status.success(), "curl's whole-file download failed");
    assert_eq!(String::from_utf8_lossy(&out.stdout), boot_menu());

    let out = curl_tftp(vec![format!("tftp://127.0.0.1:{port}/blocks.txt")]).await?;
    assert!(out.status.success(), "curl's per-block download failed");
    let expected: String = boot_menu().chars().take(512).collect::<String>() + "and that is all.\n";
    assert_eq!(String::from_utf8_lossy(&out.stdout), expected);

    // 68 is CURLE_TFTP_NOTFOUND: curl read the ERROR packet's code, not a timeout.
    let out = curl_tftp(vec![format!("tftp://127.0.0.1:{port}/missing.bin")]).await?;
    assert_eq!(
        out.status.code(),
        Some(68),
        "curl must report TFTP file-not-found (68), got {:?}",
        out.status
    );

    let dir = tempfile::tempdir()?;
    let upload = dir.path().join("boot.log");
    std::fs::write(&upload, upload_body())?;
    let out = curl_tftp(vec![
        "--upload-file".to_string(),
        upload.display().to_string(),
        format!("tftp://127.0.0.1:{port}/boot.log"),
    ])
    .await?;
    assert!(out.status.success(), "curl's upload failed");
    assert_eq!(reassemble(&uploads), upload_body());

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Run one `tftp(1)` session, its commands on stdin, from inside `dir`.
async fn run_tftp(dir: &std::path::Path, port: u16, commands: &str) -> E2EResult<String> {
    let mut child = Command::new("tftp")
        .args(["127.0.0.1", &port.to_string()])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!(
                "tftp(1) is not available ({e}): this test drives the system TFTP client, one of \
                 the two independent clients TFTP's Beta rating rests on, and skipping it would \
                 leave that rating resting on curl alone. macOS ships it; on Linux \
                 `apt-get install -y tftp-hpa`."
            )
        })?;
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(commands.as_bytes()).await?;
    drop(stdin);
    let out = timeout(Duration::from_secs(120), child.wait_with_output())
        .await
        .map_err(|_| "tftp(1) did not finish within 120s")??;
    let transcript = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    println!("  tftp {commands:?}:\n{transcript}");
    Ok(transcript)
}

/// tftp(1): a netascii download, an octet download ending in an empty block, and an upload.
///
/// LLM calls: 1 startup + 2 RRQ + WRQ + 2 DATA = **6**.
#[tokio::test]
async fn tftp_cli_downloads_and_uploads_through_the_tftp_server() -> E2EResult<()> {
    let (server, uploads) = start(&[
        ("menu", 1),
        ("exact", 1),
        ("upload", 1),
        ("upload_blocks", 2),
    ])
    .await?;
    let port = server.port;
    println!("\n=== E2E: tftp(1) against the TFTP server on {port} ===");

    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("boot.log"), upload_body())?;

    // netascii: the client turns the wire's CR LF back into its own line ending, so the file
    // it writes is the model's text exactly, and would hold a CR before every LF otherwise.
    run_tftp(
        dir.path(),
        port,
        "ascii\nget pxelinux.cfg/default menu.txt\nquit\n",
    )
    .await?;
    let got = std::fs::read(dir.path().join("menu.txt"))
        .map_err(|e| format!("tftp(1) wrote no menu.txt ({e})"))?;
    assert_eq!(String::from_utf8_lossy(&got), boot_menu());

    run_tftp(dir.path(), port, "binary\nget exact.txt exact.txt\nquit\n").await?;
    let got = std::fs::read(dir.path().join("exact.txt"))
        .map_err(|e| format!("tftp(1) wrote no exact.txt ({e})"))?;
    assert_eq!(String::from_utf8_lossy(&got), exact_two_blocks());

    run_tftp(dir.path(), port, "binary\nput boot.log boot.log\nquit\n").await?;
    server.wait_for_mocks(30).await;
    assert_eq!(reassemble(&uploads), upload_body());

    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

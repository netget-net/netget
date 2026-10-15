//! Zabbix against a real, independent client: `zabbix_sender` 7.4.
//!
//! `zabbix_sender` (GPL, the Zabbix project's own C utility; `brew install zabbix`, Ubuntu
//! `zabbix-sender`) frames the request, reads the response header and body, and scans the
//! `info` string with `sscanf("processed: %d; failed: %d; total: %d; seconds spent: %lf")` to
//! choose its **exit status**: 0 when every value was processed, 2 when some failed. NetGet
//! neither links nor wrote it; it is run as a subprocess and what it printed, and how it
//! exited, are asserted.
//!
//! **These tests FAIL, they do not skip, when `zabbix_sender` is absent.** A skip gate
//! returns `Ok(())` on a runner without the binary and the rating built on it rests on
//! nothing; `tests/server/memcached/real_client_test.rs` is the precedent.
//!
//! The first test relays its connection through a recorder and runs the pcap oracle over the
//! captured bytes with Wireshark's own `zabbix` dissector.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features zabbix --test server -- zabbix::real_client --test-threads=100


use super::common::{self, trapper_handler, Chunk, Recorder};
use crate::helpers::pcap_oracle::PcapOracle;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use netget::cli::management::ServerForm;
use std::time::Duration;

/// Locate a binary, or fail saying why a skip would be worse. Named `require_tool("…")` so
/// `scripts/beta_evidence_table.py` can see which third-party client this file drives.
fn require_tool(name: &str) -> String {
    for prefix in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        let candidate = std::path::Path::new(prefix).join(name);
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        if let Some(found) = path
            .split(':')
            .map(|dir| std::path::Path::new(dir).join(name))
            .find(|candidate| candidate.exists())
        {
            return found.to_string_lossy().into_owned();
        }
    }
    panic!(
        "`{name}` not found (searched /opt/homebrew/bin, /usr/local/bin, /usr/bin and $PATH). \
         These tests drive the Zabbix project's own zabbix_sender against NetGet's trapper, \
         and it is the only independent check that our ZBXD framing and the info string it \
         scans for its exit status are what a real sender expects. Skipping would leave the \
         Zabbix evidence resting on nothing, so this is a failure and not a skip. Install \
         with `brew install zabbix` (macOS) or `apt-get install -y zabbix-sender` \
         (Debian/Ubuntu)."
    );
}

/// Run `zabbix_sender -z 127.0.0.1 -p <port> <args>`; returns (exit code, stdout+stderr).
async fn run_sender(port: u16, args: &[&str]) -> (i32, String) {
    let sender = require_tool("zabbix_sender");
    let mut command = tokio::process::Command::new(&sender);
    command
        .arg("-z")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .args(args)
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(120), command.output())
        .await
        .unwrap_or_else(|_| panic!("zabbix_sender {args:?} did not exit within 120s"))
        .expect("run zabbix_sender");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!(
        "--- zabbix_sender -z 127.0.0.1 -p {port} {} (exit {:?}) ---\n{all}",
        args.join(" "),
        output.status.code()
    );
    (output.status.code().unwrap_or(-1), all)
}

/// The line zabbix_sender prints from our info string, with the timing stripped.
fn counts(out: &str) -> String {
    let line = out
        .lines()
        .find(|l| l.starts_with("Response from"))
        .unwrap_or_else(|| panic!("zabbix_sender printed no response line: {out}"));
    let start = line
        .find("processed:")
        .expect("processed: in the response line");
    let end = line
        .find("; seconds spent")
        .expect("seconds spent in the line");
    line[start..end].to_string()
}

#[tokio::test]
async fn zabbix_sender_sends_one_value_and_the_pcap_oracle_reads_clean_zabbix() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![trapper_handler()], None).await;
    let relay = Recorder::start(port).await;

    let (code, out) = run_sender(relay.port, &["-s", "web1", "-k", "cpu.load", "-o", "0.42"]).await;
    assert_eq!(code, 0, "every value processed must exit 0: {out}");
    assert_eq!(counts(&out), "processed: 1; failed: 0; total: 1", "{out}");
    assert!(out.contains("sent: 1; skipped: 0; total: 1"), "{out}");

    // Everything that crossed the wire, read by Wireshark's own zabbix dissector.
    let chunks = relay.finished(30).await;
    let mut oracle = PcapOracle::tcp("zabbix");
    for chunk in &chunks {
        oracle = match chunk {
            Chunk::ToServer(b) => oracle.to_server(b),
            Chunk::FromServer(b) => oracle.from_server(b),
        };
    }
    oracle.assert_clean();
}

#[tokio::test]
async fn zabbix_sender_batch_with_a_rejected_value_exits_2() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, vec![trapper_handler()], None).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let input = dir.path().join("values.txt");
    std::fs::write(
        &input,
        "web1 cpu.load 0.42\nweb1 bad.key 1\n- net.if.in \"12 34\"\n",
    )
    .unwrap();

    let (code, out) = run_sender(port, &["-s", "db1", "-i", input.to_str().unwrap()]).await;
    assert_eq!(
        code, 2,
        "zabbix_sender exits 2 when the server reports failed values: {out}"
    );
    assert_eq!(counts(&out), "processed: 2; failed: 1; total: 3", "{out}");
    assert!(out.contains("sent: 3; skipped: 0; total: 3"), "{out}");
}

/// With the backend down, the sender is told nothing was stored — in the one form it turns
/// into a non-zero exit status.
#[tokio::test]
async fn a_backend_failure_makes_zabbix_sender_exit_2() {
    let state = common::new_state().await;
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "zabbix".to_string(),
        port: Some(0),
        instruction: Some("Accept every value".to_string()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create zabbix server");
    let port = common::wait_for_port(&state, server_id).await;

    let (code, out) = run_sender(port, &["-s", "web1", "-k", "cpu.load", "-o", "1"]).await;
    assert_eq!(code, 2, "a value nobody stored must not exit 0: {out}");
    assert_eq!(counts(&out), "processed: 0; failed: 1; total: 1", "{out}");
}

/// The model path behind the same real client.
#[tokio::test]
async fn zabbix_sender_reads_the_counts_the_model_decided() -> E2EResult<()> {
    let _ = require_tool("zabbix_sender");
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via zabbix. Hosts web1 only.")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("via zabbix")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "zabbix",
                    "instruction": "Accept values for host web1 only"
                }]))
                .expect_calls(1)
                .and()
                .on_event("zabbix_sender_data")
                .respond_with_actions_from_event(|e| {
                    let items = e["items"].as_array().cloned().unwrap_or_default();
                    let ok = items.iter().filter(|i| i["host"] == "web1").count();
                    serde_json::json!([{
                        "type": "send_zabbix_result",
                        "processed": ok,
                        "failed": items.len() - ok
                    }])
                })
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let dir = tempfile::tempdir()?;
    let input = dir.path().join("values.txt");
    std::fs::write(&input, "web1 a 1\nweb2 b 2\nweb1 c 3\n")?;
    let (code, out) = run_sender(server.port, &["-i", input.to_str().unwrap()]).await;
    assert_eq!(code, 2, "{out}");
    assert_eq!(counts(&out), "processed: 2; failed: 1; total: 3", "{out}");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

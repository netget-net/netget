//! `netget --server <protocol>` on the first try.
//!
//! - `--server-handlers` gives `--server` what `--client-handlers` gives `--client`: rules
//!   that answer in-process. When a `*` rule answers every event the run needs no model, so a
//!   static HTTP server starts with no backend reachable — it used to exit 1 asking for Ollama.
//! - Without handlers, the refusal names the way to run without a model, and does not point
//!   a command line at the dashboard's `/model`.
//!
//! The binary tests drive `CARGO_BIN_EXE_netget` with `--ollama-url` at a closed port.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!       --test cli_server_direct_test -- --test-threads=100

#[path = "helpers/child_guard.rs"]
mod child_guard;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn temp_dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "netget-server-direct-{name}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

#[test]
fn a_server_whose_handlers_answer_everything_needs_no_model() {
    let dir = temp_dir("static");
    let ready = dir.join("ready.json");
    let handlers = serde_json::json!([{
        "event_pattern": "*",
        "handler": {"type": "static", "actions": [
            {"type": "send_http_response", "status": 200, "body": "hello from the rule"}
        ]}
    }])
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_netget"))
        .args([
            "--server",
            "http",
            "--port",
            "0",
            "--host",
            "127.0.0.1",
            "--server-handlers",
            &handlers,
            "--ollama-url",
            "http://127.0.0.1:1",
            "--log-level",
            "error",
            "--run-for",
            "60",
            "--ready-file",
        ])
        .arg(&ready)
        .current_dir(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn netget");
    child_guard::tie_child(child.id());

    let deadline = Instant::now() + Duration::from_secs(60);
    let report = loop {
        if let Ok(text) = std::fs::read_to_string(&ready) {
            break text;
        }
        if let Some(status) = child.try_wait().expect("try_wait") {
            let mut stderr = String::new();
            if let Some(mut e) = child.stderr.take() {
                let _ = e.read_to_string(&mut stderr);
            }
            panic!("netget exited ({status}) before it was ready: {stderr}");
        }
        assert!(Instant::now() < deadline, "no --ready-file within 60s");
        std::thread::sleep(Duration::from_millis(100));
    };
    let report: serde_json::Value = serde_json::from_str(&report).expect("ready report");
    let port = report["servers"][0]["port"].as_u64().expect("bound port") as u16;

    let mut peer = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    peer.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    peer.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    let _ = peer.read_to_string(&mut response);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        response.starts_with("HTTP/1.1 200") && response.contains("hello from the rule"),
        "the static rule answered: {response:?}"
    );
}

#[test]
fn a_server_that_needs_a_model_says_how_to_run_without_one() {
    let dir = temp_dir("needs-model");
    let output = Command::new(env!("CARGO_BIN_EXE_netget"))
        .args([
            "--server",
            "http",
            "--port",
            "0",
            "--ollama-url",
            "http://127.0.0.1:1",
            "--log-level",
            "error",
            "--run-for",
            "5",
        ])
        .current_dir(&dir)
        .stdin(Stdio::null())
        .output()
        .expect("run netget");
    let _ = std::fs::remove_dir_all(&dir);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "no model, no handlers: {stderr}");
    assert!(
        stderr.contains("--server-handlers"),
        "the refusal names the way to run without a model: {stderr}"
    );
    assert!(
        !stderr.contains("`/model`"),
        "a command line has no /model to type: {stderr}"
    );
}

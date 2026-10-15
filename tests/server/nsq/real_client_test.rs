//! NSQ against real, independent clients: the NSQ project's `to_nsq` and `nsq_tail`.
//!
//! Both are built on go-nsq (Go, MIT; Homebrew `nsq`, the release tarball on Ubuntu), which
//! NetGet neither links nor wrote. `to_nsq` sends the magic and IDENTIFY with feature
//! negotiation, reads the JSON reply, then PUBs each stdin line and waits for OK; `nsq_tail`
//! does the same, SUBs, sends RDY, prints each message body it receives, FINs it, and exits
//! after `-n` messages. What they printed, and how they exited, are asserted.
//!
//! **These tests FAIL, they do not skip, when the binaries are absent.** A skip gate returns
//! `Ok(())` on a runner without them and the rating built on it rests on nothing;
//! `tests/server/memcached/real_client_test.rs` is the precedent.
//!
//! The broker is a Python script handler (`common::BROKER_SCRIPT`) in the first tests, so they
//! are deterministic; the last puts a mocked model behind both clients, and carries a message
//! published by `to_nsq` through the model to `nsq_tail`.
//!
//! Wireshark has no NSQ dissector (`tshark -G protocols`), so there is no pcap oracle here.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nsq --test server -- nsq::real_client --test-threads=100


use super::common::{self, broker_handler};
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

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
         These tests drive the NSQ project's own to_nsq and nsq_tail against NetGet's NSQ \
         server, and they are the only independent check that our frames, IDENTIFY reply and \
         message framing are what go-nsq expects. Skipping would leave the NSQ evidence resting \
         on nothing, so this is a failure and not a skip. Install with `brew install nsq` \
         (macOS) or unpack the release tarball from https://github.com/nsqio/nsq/releases \
         into /usr/local/bin (Debian/Ubuntu)."
    );
}

/// Run a tool with `stdin`; returns (exit code, stdout, stderr).
async fn run(tool: &str, args: &[String], stdin: &str) -> (i32, String, String) {
    let bin = require_tool(tool);
    let mut command = tokio::process::Command::new(&bin);
    command
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().expect("spawn the client");
    let mut input = child.stdin.take().expect("stdin");
    input
        .write_all(stdin.as_bytes())
        .await
        .expect("write stdin");
    drop(input);
    let output = tokio::time::timeout(Duration::from_secs(120), child.wait_with_output())
        .await
        .unwrap_or_else(|_| panic!("{tool} {args:?} did not exit within 120s"))
        .expect("run the client");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    println!(
        "--- {tool} {} (exit {:?}) ---\n{stdout}{stderr}",
        args.join(" "),
        output.status.code()
    );
    (output.status.code().unwrap_or(-1), stdout, stderr)
}

fn to_nsq_args(port: u16, topic: &str) -> Vec<String> {
    vec![
        "-nsqd-tcp-address".into(),
        format!("127.0.0.1:{port}"),
        "-topic".into(),
        topic.into(),
    ]
}

fn nsq_tail_args(port: u16, topic: &str, n: usize) -> Vec<String> {
    vec![
        "-nsqd-tcp-address".into(),
        format!("127.0.0.1:{port}"),
        "-topic".into(),
        topic.into(),
        "-n".into(),
        n.to_string(),
    ]
}

#[tokio::test]
async fn to_nsq_publishes_each_line_and_a_refusal_fails_it() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, vec![broker_handler()], None).await;

    let (code, out, err) = run(
        "to_nsq",
        &to_nsq_args(port, "orders"),
        "order 1 shipped\norder 2 packed\n",
    )
    .await;
    assert_eq!(code, 0, "to_nsq read OK for both PUBs: {out}{err}");
    let mut accepted = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while accepted < 2 && tokio::time::Instant::now() < deadline {
        let line = common::wait_for_log(&mut rx, "decision=model_answer", 30).await;
        if line
            .last()
            .is_some_and(|l| l.contains("PUB orders (1 message(s))"))
        {
            accepted += 1;
        }
    }
    assert_eq!(
        accepted, 2,
        "each stdin line was one PUB the handler accepted"
    );

    // A topic the handler refuses: to_nsq reads E_PUB_FAILED and says so.
    let (code, out, err) = run("to_nsq", &to_nsq_args(port, "refused"), "nope\n").await;
    assert!(
        format!("{out}{err}").contains("E_PUB_FAILED"),
        "to_nsq reported the refusal: {out}{err}"
    );
    assert_ne!(code, 0, "a refused publish is not a success: {out}{err}");
}

#[tokio::test]
async fn nsq_tail_prints_exactly_the_delivered_bodies() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, vec![broker_handler()], None).await;

    let (code, out, err) = run("nsq_tail", &nsq_tail_args(port, "greetings", 2), "").await;
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(
        out, "hello\nworld\n",
        "nsq_tail printed the two bodies, in order"
    );

    // Both came from one RDY: nsq_tail caps its in-flight count at -n. It exits from inside
    // the handler of the n-th message, before its FINs are flushed, so no FIN is asserted.
    common::wait_for_log(&mut rx, "NSQ RDY from", 30)
        .await
        .last()
        .filter(|l| l.contains("decision=model_answer offered=2"))
        .expect("one RDY, answered with both messages");
}

/// The model path behind both clients: what `to_nsq` published reaches the model as
/// `nsq_publish`, and the model delivers those same bodies to `nsq_tail`.
#[tokio::test]
async fn a_message_published_by_to_nsq_reaches_nsq_tail_through_the_model() -> E2EResult<()> {
    let _ = require_tool("to_nsq");
    let _ = require_tool("nsq_tail");
    let published: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = published.clone();
    let replay = published.clone();
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via nsq. A broker.")
        .with_log_level("debug")
        .with_mock(move |mock| {
            mock.on_instruction_containing("via nsq")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "nsq",
                    "instruction": "Accept everything and deliver what was published",
                    "event_handlers": [{
                        "event_pattern": "nsq_finish",
                        "handler": {"type": "static", "actions": []}
                    }]
                }]))
                .expect_calls(1)
                .and()
                .on_event("nsq_publish")
                .and_event_data_contains("topic", "news")
                .respond_with_actions_from_event(move |e| {
                    for m in e["messages"].as_array().into_iter().flatten() {
                        seen.lock()
                            .unwrap()
                            .push(m.as_str().unwrap_or("").to_string());
                    }
                    serde_json::json!([{"type": "send_nsq_ok"}])
                })
                .expect_calls(2)
                .and()
                .on_event("nsq_subscribe")
                .and_event_data_contains("topic", "news")
                .respond_with_actions(serde_json::json!([{"type": "send_nsq_ok"}]))
                .expect_calls(1)
                .and()
                .on_event("nsq_ready")
                .respond_with_actions_from_event(move |_| {
                    let bodies: Vec<serde_json::Value> = replay
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|b| serde_json::json!({"body": b}))
                        .collect();
                    serde_json::json!([{"type": "deliver_nsq_messages", "messages": bodies}])
                })
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let (code, out, err) = run(
        "to_nsq",
        &to_nsq_args(server.port, "news"),
        "quiet night\nbusy morning\n",
    )
    .await;
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(
        *published.lock().unwrap(),
        vec!["quiet night".to_string(), "busy morning".to_string()],
        "the model saw each line to_nsq published"
    );

    let (code, out, err) = run("nsq_tail", &nsq_tail_args(server.port, "news", 2), "").await;
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(out, "quiet night\nbusy morning\n");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

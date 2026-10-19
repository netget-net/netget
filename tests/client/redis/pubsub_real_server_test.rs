//! The Redis client's pub/sub against a real **`redis-server`** (Valkey on Homebrew, Redis on
//! Ubuntu), on RESP2 and RESP3.
//!
//! The model subscribes to a channel and a pattern. A message `redis-cli` publishes reaches
//! the model as one structured `redis_message_received` (channel, pattern, message), and the
//! model answers by publishing a reply of its own to a second channel — which a
//! `redis-cli SUBSCRIBE` on that channel must print. That is condition 4 of the client bar
//! asserted on the wire: the reply exists only if the model's answer was executed.
//!
//! On RESP2 the subscribed connection cannot publish, so the client's publish goes over a short
//! second connection; on RESP3 it goes on the subscribed connection itself and its `:1` comes
//! back as an ordinary reply. Both paths are driven. Each rule is matched on the parsed event,
//! so a message mis-read as a reply, or a pattern message mis-read as a channel one, fails the
//! mock.
//!
//! **No test here skips.** A missing `redis-server` or `redis-cli` fails with the install
//! command.
//!
//! LLM calls: 8 per RESP2 run (connect, two subscribe confirmations, three messages, two
//! unsubscribe confirmations) and 10 on RESP3, where each publish's own `:1` is a reply too.

use crate::helpers::common::E2EResult;
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use crate::helpers::real_server::{run_tool, InstallHint, RealServer};
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use serde_json::json;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

const REDIS_SERVER: InstallHint = InstallHint {
    brew: "valkey",
    apt: "redis-server",
};
const REDIS_CLI: InstallHint = InstallHint {
    brew: "valkey",
    apt: "redis-tools",
};

async fn start_redis() -> E2EResult<RealServer> {
    RealServer::builder("redis-server", REDIS_SERVER)
        .args([
            "--port",
            "{port}",
            "--bind",
            "127.0.0.1",
            "--save",
            "",
            "--appendonly",
            "no",
            "--dir",
            "{dir}",
        ])
        .ready_when_log_matches("Ready to accept connections")
        .start()
        .await
}

async fn redis_cli(port: u16, args: &[&str]) -> E2EResult<String> {
    let mut cmd = Command::new("redis-cli");
    cmd.args(["-h", "127.0.0.1", "-p", &port.to_string()])
        .args(args);
    Ok(run_tool(cmd, "redis-cli", REDIS_CLI)
        .await?
        .trim_end_matches('\n')
        .to_string())
}

/// A `redis-cli SUBSCRIBE` left running, its output collected line by line.
struct Subscriber {
    _child: tokio::process::Child,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Subscriber {
    fn spawn(port: u16, channel: &str) -> Subscriber {
        let mut child = tokio::process::Command::new("redis-cli")
            .args([
                "-h",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "SUBSCRIBE",
                channel,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("redis-cli is required: brew install valkey / apt install redis-tools");
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = lines.clone();
        let stdout = child.stdout.take().unwrap();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                sink.lock().unwrap().push(line);
            }
        });
        Subscriber {
            _child: child,
            lines,
        }
    }

    async fn wait_for(&self, line: &str) {
        for _ in 0..1200 {
            if self.lines.lock().unwrap().iter().any(|l| l == line) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!(
            "the redis-cli subscriber never printed {line:?}; it printed:\n{}",
            self.lines.lock().unwrap().join("\n")
        );
    }
}

/// Poll a redis-cli query until it prints `want`.
async fn wait_until(port: u16, args: &[&str], want: &str) -> E2EResult<()> {
    for _ in 0..1200 {
        if redis_cli(port, args).await? == want {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(format!("redis-cli {args:?} never printed {want:?}").into())
}

async fn round_trip(resp3: bool) -> E2EResult<()> {
    let server = start_redis().await?;
    let result = run(&server, resp3).await;
    server.with_log(result)
}

async fn run(server: &RealServer, resp3: bool) -> E2EResult<()> {
    let port = server.port;
    let out = Subscriber::spawn(port, "netget:out");
    wait_until(port, &["PUBSUB", "NUMSUB", "netget:out"], "netget:out\n1").await?;

    let mut builder = MockLlmBuilder::new()
        .on_event("redis_connected")
        .respond_with_actions(json!([{
            "type": "redis_subscribe",
            "channels": ["netget:in"],
            "patterns": ["netget:alerts.*"]
        }]))
        .expect_calls(1)
        .and()
        // Two subscribes, then the two unsubscribes "bye" asks for.
        .on_event("redis_subscription_changed")
        .respond_with_actions(json!([]))
        .expect_calls(4)
        .and()
        // Most specific first: "pmessage" also contains "message".
        .on_event("redis_message_received")
        .and_event_data_contains("kind", "pmessage")
        .and_event_data_contains("pattern", "netget:alerts.*")
        .respond_with_actions_from_event(|e| {
            json!([{
                "type": "redis_publish",
                "channel": "netget:out",
                "message": format!(
                    "alert on {} via {}: {}",
                    e["channel"].as_str().unwrap_or(""),
                    e["pattern"].as_str().unwrap_or(""),
                    e["message"].as_str().unwrap_or("")
                )
            }])
        })
        .expect_calls(1)
        .and()
        .on_event("redis_message_received")
        .and_event_data_contains("kind", "message")
        .and_event_data_contains("channel", "netget:in")
        .and_event_data_contains("protocol", if resp3 { "3" } else { "2" })
        .respond_with_actions_from_event(|e| {
            let message = e["message"].as_str().unwrap_or("");
            if message == "bye" {
                json!([{"type": "redis_unsubscribe"}])
            } else {
                json!([{
                    "type": "redis_publish",
                    "channel": "netget:out",
                    "message": format!("pong: {message}")
                }])
            }
        })
        .expect_calls(2)
        .and();
    if resp3 {
        // On RESP3 the publish runs on the subscribed connection; its `:1` is a reply.
        builder = builder
            .on_event("redis_response_received")
            .and_event_data_contains("reply_type", "integer")
            .respond_with_actions(json!([]))
            .expect_calls(2)
            .and();
    }
    let mock = MockOllamaServer::start(builder.build()).await?;

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    ClientForm {
        protocol: "redis".to_string(),
        remote_addr: Some(server.addr()),
        instruction: Some("Answer every message on netget:in on netget:out.".to_string()),
        startup_params: resp3.then(|| json!({"resp3": true})),
        // The subscription confirmations arrive together and the rules below count one call
        // per confirmation; batching them is `batching_test.rs`'s subject.
        batching: Some(false),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new(mock.base_url()),
        tx.clone(),
    )
    .await?;

    // The model's subscriptions are live on the real server.
    wait_until(port, &["PUBSUB", "NUMSUB", "netget:in"], "netget:in\n1").await?;
    wait_until(port, &["PUBSUB", "NUMPAT"], "1").await?;

    assert_eq!(
        redis_cli(port, &["PUBLISH", "netget:in", "ping one"]).await?,
        "1"
    );
    out.wait_for("pong: ping one").await;
    assert_eq!(
        redis_cli(port, &["PUBLISH", "netget:alerts.fire", "hot"]).await?,
        "1"
    );
    out.wait_for("alert on netget:alerts.fire via netget:alerts.*: hot")
        .await;

    // "bye" makes the model drop everything it holds; the real server sees it go.
    assert_eq!(
        redis_cli(port, &["PUBLISH", "netget:in", "bye"]).await?,
        "1"
    );
    wait_until(port, &["PUBSUB", "NUMSUB", "netget:in"], "netget:in\n0").await?;
    wait_until(port, &["PUBSUB", "NUMPAT"], "0").await?;

    mock.wait_for_expectations(30).await;
    mock.verify_calls().await?;
    Ok(())
}

#[tokio::test]
async fn redis_client_subscribes_and_answers_messages_on_resp2() -> E2EResult<()> {
    round_trip(false).await
}

#[tokio::test]
async fn redis_client_subscribes_and_answers_messages_on_resp3() -> E2EResult<()> {
    round_trip(true).await
}

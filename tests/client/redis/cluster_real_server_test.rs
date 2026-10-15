//! The Redis client's cluster mode against a real **Redis Cluster**: three `redis-server
//! --cluster-enabled yes` nodes joined by `redis-cli --cluster create`, all third-party code.
//!
//! The client reads the slot map at connect. Then the cluster changes underneath it, the way a
//! reshard changes it, using Redis's own `CLUSTER SETSLOT` protocol:
//!
//! * one slot is **moved** to another node, so the client's map is stale and the old owner
//!   answers `-MOVED`; the client must refresh and land on the new owner;
//! * another slot is left **migrating**, so its owner answers `-ASK` for a key it does not hold;
//!   the client must send `ASKING` and the command to the importing node, once.
//!
//! Each command is injected through the dashboard path (`send_to_client`), and the model is
//! shown the reply with the node that gave it and the redirection it took. It answers by
//! writing that node's address back into the cluster — so `redis-cli` reading
//! `netget:moved-via` and `netget:asked-via` proves both that the redirection was followed to
//! the right node and that the model's answer was executed (condition 4).
//!
//! **No test here skips.** A missing `redis-server` or `redis-cli` fails with the install
//! command.
//!
//! LLM calls: 5 (connect, the two redirected replies, the two follow-up writes).

use crate::helpers::common::E2EResult;
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use crate::helpers::real_server::{run_tool, InstallHint, RealServer};
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::utils::redis_keys::key_hash_slot;
use serde_json::json;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

const REDIS_SERVER: InstallHint = InstallHint {
    brew: "valkey",
    apt: "redis-server",
};
const REDIS_CLI: InstallHint = InstallHint {
    brew: "valkey",
    apt: "redis-tools",
};

async fn cluster_node() -> E2EResult<RealServer> {
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
            "--cluster-enabled",
            "yes",
            "--cluster-config-file",
            "{dir}/nodes.conf",
            "--cluster-port",
            "{port1}",
        ])
        .extra_ports(1)
        .ready_when_log_matches("Ready to accept connections")
        .start()
        .await
}

async fn cli(port: u16, args: &[&str]) -> E2EResult<String> {
    let mut cmd = Command::new("redis-cli");
    cmd.args(["-h", "127.0.0.1", "-p", &port.to_string()])
        .args(args);
    Ok(run_tool(cmd, "redis-cli", REDIS_CLI)
        .await?
        .trim_end_matches('\n')
        .to_string())
}

/// Several commands on one redis-cli connection (for `ASKING` followed by its command).
async fn cli_session(port: u16, script: &str) -> E2EResult<String> {
    let mut child = tokio::process::Command::new("redis-cli")
        .args(["-h", "127.0.0.1", "-p", &port.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(script.as_bytes()).await?;
    drop(stdin);
    let out = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output()).await??;
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

struct Node {
    port: u16,
    id: String,
}

/// Each node's id, by asking it.
async fn node(server: &RealServer) -> E2EResult<Node> {
    Ok(Node {
        port: server.port,
        id: cli(server.port, &["CLUSTER", "MYID"]).await?,
    })
}

/// Which of `nodes` owns `slot`, as `asker` sees it.
async fn owner(asker: u16, nodes: &[Node], slot: u16) -> E2EResult<usize> {
    let text = cli(asker, &["CLUSTER", "NODES"]).await?;
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let owns = fields.iter().skip(8).any(|f| match f.split_once('-') {
            Some((a, b)) => match (a.parse::<u16>(), b.parse::<u16>()) {
                (Ok(a), Ok(b)) => (a..=b).contains(&slot),
                _ => false,
            },
            None => f.parse::<u16>().ok() == Some(slot),
        });
        if owns {
            if let Some(i) = nodes.iter().position(|n| n.id == fields[0]) {
                return Ok(i);
            }
        }
    }
    Err(format!("no node owns slot {slot} according to {asker}:\n{text}").into())
}

async fn wait_for_owner(nodes: &[Node], slot: u16, want: usize) -> E2EResult<()> {
    for _ in 0..1200 {
        let mut all = true;
        for n in nodes {
            if owner(n.port, nodes, slot).await? != want {
                all = false;
            }
        }
        if all {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("the nodes never agreed that slot {slot} moved").into())
}

#[tokio::test]
async fn redis_cluster_client_follows_moved_and_ask_on_a_real_cluster() -> E2EResult<()> {
    let servers = [
        cluster_node().await?,
        cluster_node().await?,
        cluster_node().await?,
    ];
    let result = run(&servers).await;
    servers[0].with_log(result)
}

async fn run(servers: &[RealServer; 3]) -> E2EResult<()> {
    let addrs: Vec<String> = servers.iter().map(|s| s.addr()).collect();
    let mut create = vec!["--cluster", "create"];
    create.extend(addrs.iter().map(String::as_str));
    create.push("--cluster-yes");
    cli(servers[0].port, &create).await?;
    for s in servers {
        for attempt in 0.. {
            let info = cli(s.port, &["CLUSTER", "INFO"]).await?;
            if info.contains("cluster_state:ok") && info.contains("cluster_known_nodes:3") {
                break;
            }
            if attempt > 1200 {
                return Err(format!("the cluster never formed:\n{info}").into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let mut nodes = Vec::new();
    for s in servers {
        nodes.push(node(s).await?);
    }

    let moved_slot = key_hash_slot(b"netget:moved");
    let asked_slot = key_hash_slot(b"netget:asked");
    assert_ne!(moved_slot, asked_slot);
    let moved_from = owner(nodes[0].port, &nodes, moved_slot).await?;
    let moved_to = (moved_from + 1) % 3;
    let asked_from = owner(nodes[0].port, &nodes, asked_slot).await?;
    let asked_to = (asked_from + 1) % 3;
    let moved_to_addr = format!("127.0.0.1:{}", nodes[moved_to].port);
    let asked_to_addr = format!("127.0.0.1:{}", nodes[asked_to].port);

    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("redis_connected")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("redis_response_received")
            .and_event_data_contains("redirects", "MOVED")
            .and_event_data_contains("node", moved_to_addr.clone())
            .and_event_data_contains("reply_type", "simple_string")
            .respond_with_actions_from_event(|e| {
                json!([{
                    "type": "execute_redis_command",
                    "command": format!("SET netget:moved-via {}", e["node"].as_str().unwrap_or(""))
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("redis_response_received")
            .and_event_data_contains("redirects", "ASK")
            .and_event_data_contains("node", asked_to_addr.clone())
            .and_event_data_contains("reply_type", "simple_string")
            .respond_with_actions_from_event(|e| {
                json!([{
                    "type": "execute_redis_command",
                    "command": format!("SET netget:asked-via {}", e["node"].as_str().unwrap_or(""))
                }])
            })
            .expect_calls(1)
            .and()
            // The two follow-up writes, which need no redirection.
            .on_event("redis_response_received")
            .and_event_data_contains("redirects", "[]")
            .and_event_data_contains("reply_type", "simple_string")
            .respond_with_actions(json!([]))
            .expect_calls(2)
            .and()
            .build(),
    )
    .await?;

    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "redis".to_string(),
        remote_addr: Some(addrs[0].clone()),
        instruction: Some("Record which node answered each redirected write.".to_string()),
        startup_params: Some(json!({"cluster": true})),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new(mock.base_url()),
        tx.clone(),
    )
    .await?;
    for _ in 0..1200 {
        if state.has_client_handle(client_id).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Reshard one empty slot with Redis's own protocol; the client's map is now stale.
    let (from, to) = (&nodes[moved_from], &nodes[moved_to]);
    let s = moved_slot.to_string();
    cli(to.port, &["CLUSTER", "SETSLOT", &s, "IMPORTING", &from.id]).await?;
    cli(from.port, &["CLUSTER", "SETSLOT", &s, "MIGRATING", &to.id]).await?;
    for n in [to, from, &nodes[3 - moved_from - moved_to]] {
        cli(n.port, &["CLUSTER", "SETSLOT", &s, "NODE", &to.id]).await?;
    }
    wait_for_owner(&nodes, moved_slot, moved_to).await?;

    let sent = state
        .send_to_client(
            client_id,
            json!({"type": "execute_redis_command", "command": "SET netget:moved hello"}),
            Duration::from_secs(10),
        )
        .await?;
    assert!(matches!(sent, ClientSendOutcome::Sent { .. }), "{sent:?}");
    // The value is on the node the slot moved to — read there without -c.
    let mut moved_value = String::new();
    for _ in 0..1200 {
        moved_value = cli(nodes[moved_to].port, &["GET", "netget:moved"]).await?;
        if moved_value == "hello" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(moved_value, "hello");

    // Leave another slot mid-migration: its owner answers ASK for a key it does not hold.
    let (from, to) = (&nodes[asked_from], &nodes[asked_to]);
    let s = asked_slot.to_string();
    cli(to.port, &["CLUSTER", "SETSLOT", &s, "IMPORTING", &from.id]).await?;
    cli(from.port, &["CLUSTER", "SETSLOT", &s, "MIGRATING", &to.id]).await?;
    let sent = state
        .send_to_client(
            client_id,
            json!({"type": "execute_redis_command", "command": "SET netget:asked world"}),
            Duration::from_secs(10),
        )
        .await?;
    assert!(matches!(sent, ClientSendOutcome::Sent { .. }), "{sent:?}");

    mock.wait_for_expectations(30).await;
    mock.verify_calls().await?;

    // The importing node holds it, readable only after ASKING, as Redis requires.
    assert_eq!(
        cli_session(nodes[asked_to].port, "ASKING\nGET netget:asked\n").await?,
        "OK\nworld"
    );
    // And the model wrote down where each redirection took the client.
    assert_eq!(
        cli(nodes[0].port, &["-c", "GET", "netget:moved-via"]).await?,
        moved_to_addr
    );
    assert_eq!(
        cli(nodes[0].port, &["-c", "GET", "netget:asked-via"]).await?,
        asked_to_addr
    );
    Ok(())
}

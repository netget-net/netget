//! The memcached client against a real **`memcached`** — the evidence its maturity rating
//! rests on.
//!
//! NetGet frames the text protocol itself (`src/client/memcached/wire.rs`); the server is the
//! real C memcached, spawned per test on a probed loopback port with UDP off, and what it holds
//! is prepared and read back with **libmemcached**'s `memcp` and `memcat` — a separate C
//! client library. Nothing on the wire was written by this repository except NetGet.
//!
//! Condition 4 of the client bar — the client acts on the model's answer, asserted on the
//! wire — is asserted from the server's side: `memcat` reads back a value (and its flags) the
//! mocked model chose, and a value the model built from one `memcp` wrote and the model was
//! shown. Every event the model sees is matched on its parsed fields, so a reply attributed to
//! the wrong key, or split, fails the mock.
//!
//! **No test here skips.** A missing `memcached`, `memcp` or `memcat` fails with the install
//! command.
//!
//! LLM calls: 8 in the first test. None in the second, whose model endpoint is unreachable on
//! purpose: its connect turn fails (`decision=llm_error`) and the injected actions do not care.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features memcached --test client -- memcached::real_server_test --test-threads=100

use crate::helpers::real_server::{missing_binary, run_tool, InstallHint, RealServer};
use crate::helpers::*;
use serde_json::json;
use std::process::Command;
use std::time::Duration;

const MEMCACHED: InstallHint = InstallHint {
    brew: "memcached",
    apt: "memcached",
};
const LIBMEMCACHED: InstallHint = InstallHint {
    brew: "libmemcached",
    apt: "libmemcached-tools (and symlink memccat/memccp to memcat/memcp, as CI does)",
};

/// A throwaway memcached: loopback only, UDP off, `-vv` so it logs `server listening`.
async fn start_memcached() -> E2EResult<RealServer> {
    RealServer::builder("memcached", MEMCACHED)
        .args(["-p", "{port}", "-l", "127.0.0.1", "-U", "0", "-vv"])
        .ready_when_log_matches("server listening")
        .start()
        .await
}

fn servers(server: &RealServer) -> String {
    format!("--servers=127.0.0.1:{}", server.port)
}

/// `memcat --verbose <key>`: stdout and stderr together, since libmemcached writes the flags
/// line to one and the value to the other depending on the build.
async fn memcat_verbose(server: &RealServer, key: &str) -> E2EResult<String> {
    let mut cmd = Command::new("memcat");
    cmd.arg(servers(server)).arg("--verbose").arg(key);
    let output = tokio::task::spawn_blocking(move || cmd.output())
        .await?
        .map_err(|e| missing_binary("memcat", LIBMEMCACHED, e))?;
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

async fn memcat(server: &RealServer, key: &str) -> E2EResult<String> {
    let mut cmd = Command::new("memcat");
    cmd.arg(servers(server)).arg(key);
    Ok(run_tool(cmd, "memcat", LIBMEMCACHED)
        .await?
        .trim_end_matches('\n')
        .to_string())
}

/// `memcp` stores a file under its base name.
async fn memcp(server: &RealServer, name: &str, contents: &[u8]) -> E2EResult<()> {
    let path = server.dir().join(name);
    std::fs::write(&path, contents)?;
    let mut cmd = Command::new("memcp");
    cmd.arg(servers(server)).arg("--flag=7").arg(&path);
    run_tool(cmd, "memcp", LIBMEMCACHED).await?;
    Ok(())
}

/// The model's writes read back by libmemcached, and a libmemcached write read by the model.
///
/// 1. `memcp` stores `prepared` = `written by memcp` and `binary` = four non-UTF-8 octets.
/// 2. On `memcached_connected` the model sets `netget:greeting` = `hello from the model`,
///    flags 42.
/// 3. On `memcached_stored` it `gets` three keys plus one that does not exist.
/// 4. It is shown `netget:greeting` and `prepared` as values (with their flags and a CAS
///    unique), `binary` as a `non_text_value` error, and `absent` as a miss — one event each.
/// 5. From the `prepared` event it sets `netget:echo` = `the model saw: written by memcp`.
///
/// Then `memcat` must read both of the model's keys, and the greeting's flags must be 42.
///
/// LLM calls: 8 (startup, connected, stored, four per-key events, the echo's stored).
#[tokio::test]
async fn memcached_client_writes_and_acts_on_what_it_reads_against_memcached() -> E2EResult<()> {
    let server = start_memcached().await?;
    let result = writes_and_acts(&server).await;
    server.with_log(result)
}

async fn writes_and_acts(server: &RealServer) -> E2EResult<()> {
    memcp(server, "prepared", b"written by memcp").await?;
    memcp(server, "binary", &[0xff, 0xfe, 0x00, 0x80]).await?;

    let addr = server.addr();
    let config = NetGetConfig::new(format!(
        "Connect to memcached at {addr}. MEMCACHED-REAL-SERVER-STARTUP."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("MEMCACHED-REAL-SERVER-STARTUP")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Memcached",
                "remote_addr": addr,
                "instruction": "Store a greeting, read it back with the prepared keys, and \
                                record what you saw."
            }]))
            .expect_calls(1)
            .and()
            .on_event("memcached_connected")
            .respond_with_actions(json!([{
                "type": "memcached_set",
                "key": "netget:greeting",
                "value": "hello from the model",
                "flags": 42
            }]))
            .expect_calls(1)
            .and()
            .on_event("memcached_stored")
            .and_event_data_contains("key", "netget:greeting")
            .respond_with_actions(json!([{
                "type": "memcached_gets",
                "keys": ["netget:greeting", "prepared", "binary", "absent"]
            }]))
            .expect_calls(1)
            .and()
            .on_event("memcached_value")
            .and_event_data_contains("key", "netget:greeting")
            .and_event_data_contains("value", "hello from the model")
            .and_event_data_contains("flags", "42")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("memcached_value")
            .and_event_data_contains("key", "prepared")
            .and_event_data_contains("flags", "7")
            .respond_with_actions_from_event(|event| {
                // The CAS unique is present because the model asked with gets.
                assert!(
                    event["cas"].as_u64().is_some(),
                    "gets must carry cas: {event}"
                );
                json!([{
                    "type": "memcached_set",
                    "key": "netget:echo",
                    "value": format!("the model saw: {}", event["value"].as_str().unwrap_or(""))
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("memcached_error")
            .and_event_data_contains("kind", "non_text_value")
            .and_event_data_contains("key", "binary")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("memcached_miss")
            .and_event_data_contains("key", "absent")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
            .on_event("memcached_stored")
            .and_event_data_contains("key", "netget:echo")
            .respond_with_actions(json!([]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    assert_eq!(
        memcat(server, "netget:greeting").await?,
        "hello from the model",
        "memcached must hold the value the model set"
    );
    let verbose = memcat_verbose(server, "netget:greeting").await?;
    assert!(
        verbose.contains("flags: 42"),
        "memcached must hold the flags the model set; memcat --verbose said:\n{verbose}"
    );
    assert_eq!(
        memcat(server, "netget:echo").await?,
        "the model saw: written by memcp",
        "memcached must hold the value the model built from the one memcp wrote"
    );

    client.stop().await?;
    Ok(())
}

/// The dashboard's `[ send ]` / MCP `send_to_client` path, against the same real server.
///
/// Actions are injected from outside the client's loops with `AppState::send_to_client`, so
/// no model is involved in what reaches the wire: a `set` that `memcat` must read back, a
/// `flush_all` without `confirm` that must be refused before it is sent (and so must leave the
/// key in place), and a `disconnect` that must end the session.
#[tokio::test]
async fn injected_memcached_actions_reach_memcached() -> E2EResult<()> {
    let server = start_memcached().await?;
    let result = injected_actions(&server).await;
    server.with_log(result)
}

async fn injected_actions(server: &RealServer) -> E2EResult<()> {
    use ::netget::cli::management::ClientForm;
    use ::netget::state::app_state::AppState;
    use ::netget::state::client_handles::ClientSendOutcome;
    use ::netget::state::ClientStatus;

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "memcached".to_string(),
        remote_addr: Some(server.addr()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        ::netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .map_err(|e| format!("create memcached client: {e}"))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !state.has_client_handle(client_id).await {
        if std::time::Instant::now() > deadline {
            return Err("memcached client never registered a command handle".into());
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    // "set injected:key 0 0 18\r\nfrom the dashboard\r\n" is 45 bytes.
    let outcome = state
        .send_to_client(
            client_id,
            json!({"type": "memcached_set", "key": "injected:key", "value": "from the dashboard"}),
            Duration::from_secs(10),
        )
        .await?;
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { bytes_sent: 45 }),
        "expected Sent{{45}}, got {outcome:?}"
    );

    let outcome = state
        .send_to_client(
            client_id,
            json!({"type": "memcached_flush_all"}),
            Duration::from_secs(10),
        )
        .await?;
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "flush_all without confirm must be refused, got {outcome:?}"
    );

    // Read back only after a round trip that follows the set on the same connection, so the
    // set has certainly been applied.
    let outcome = state
        .send_to_client(
            client_id,
            json!({"type": "memcached_version"}),
            Duration::from_secs(10),
        )
        .await?;
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "{outcome:?}"
    );
    let mut value = String::new();
    for _ in 0..100 {
        value = memcat(server, "injected:key").await.unwrap_or_default();
        if !value.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        value, "from the dashboard",
        "memcached must hold the injected value"
    );

    let outcome = state
        .send_to_client(
            client_id,
            json!({"type": "disconnect"}),
            Duration::from_secs(10),
        )
        .await?;
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );
    for _ in 0..300 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    Err(format!(
        "client should be Disconnected with no command handle; status={:?}",
        state.get_client(client_id).await.map(|c| c.status)
    )
    .into())
}

//! Memcached against a real, independent client: libmemcached's C tools.
//!
//! `memcat`, `memstat` and `memping` ship with libmemcached (BSD-3;
//! `brew install libmemcached`). They are invoked as subprocesses, never linked, and they are
//! the only peer in this directory that NetGet did not write — everything else is our parser
//! checking our framer.
//!
//! They are also genuinely picky: `memcat` prints nothing and exits non-zero if the `VALUE`
//! header's byte count disagrees with the payload, which is the single most likely way to
//! break this protocol.
//!
//! **These tests FAIL, they do not skip, when libmemcached is absent.** That is deliberate and
//! it is the whole reason Memcached may be rated `Beta`. A skip-when-missing gate returns
//! `Ok(())` on a runner without the tools, so the suite reports a silent pass and the maturity
//! rating ends up resting on nothing — which is exactly how a claim outlives the evidence that
//! justified it. `tests/server/npm/e2e_test.rs::test_npm_with_real_cli` is the precedent.
//!
//! Install with `brew install libmemcached` (macOS) or `apt-get install -y libmemcached-tools`
//! (Debian/Ubuntu). `memcached` is not in CI's `CI_FEATURES`, so this costs the blocking CI
//! gate nothing; the `registry-audit` job installs the tools.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::process::Command;

/// Locate a libmemcached tool, or fail the test saying why a skip would be worse.
///
/// **Fail, never skip.** These binaries are the only peer in this directory that NetGet did not
/// write, and they are the whole of Memcached's `Beta` evidence. A machine without libmemcached
/// must say so loudly rather than return `Ok(())`.
fn require_tool(name: &str) -> E2EResult<String> {
    tool(name).ok_or_else(|| -> Box<dyn std::error::Error> {
        format!(
            "`{name}` not found (searched /opt/homebrew/bin, /usr/local/bin, /usr/bin and \
             $PATH). These tests drive libmemcached's own C client against NetGet's Memcached \
             server, and that is the only independent check that our `VALUE` byte counts and \
             `STAT`/`VERSION` replies are acceptable to something we did not write. Skipping \
             would leave Memcached's Beta rating resting on nothing, so this is a failure and \
             not a skip. Install with `brew install libmemcached` (macOS) or \
             `apt-get install -y libmemcached-tools` (Debian/Ubuntu) — note that Debian and \
             Ubuntu ship these same binaries under a `memc` prefix (`memccat`, `memcstat`, \
             `memcping`), so the package can be installed and this name still absent; CI \
             symlinks them to the names upstream uses."
        )
        .into()
    })
}

fn tool(name: &str) -> Option<String> {
    for prefix in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        let candidate = std::path::Path::new(prefix).join(name);
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    let path = std::env::var("PATH").ok()?;
    path.split(':')
        .map(|dir| std::path::Path::new(dir).join(name))
        .find(|candidate| candidate.exists())
        .map(|p| p.to_string_lossy().into_owned())
}

async fn run(binary: &str, args: &[String]) -> E2EResult<(bool, String)> {
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        Command::new(binary).args(args).output(),
    )
    .await??;
    Ok((
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    ))
}

/// `memcat` fetches a key and writes the value to stdout. It parses the `VALUE` header and
/// reads exactly that many bytes, so a wrong count shows up here as an empty or truncated
/// result rather than as a passing test.
#[tokio::test]
async fn libmemcached_memcat_reads_a_value_the_model_invented() -> E2EResult<()> {
    let memcat = require_tool("memcat")?;

    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via memcached. The key motd holds a short banner.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_event("memcached_get")
            .respond_with_actions_from_event(|event| {
                let key = event["keys"][0].as_str().unwrap_or("").to_string();
                serde_json::json!([{
                    "type": "send_memcached_values",
                    "values": [{"key": key, "value": "welcome to the fake cache", "flags": 0}]
                }])
            })
            .expect_at_least(1)
            .and()
            .on_instruction_containing("via memcached")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "memcached",
                "instruction": "The key motd holds a short banner"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (ok, output) = run(
        &memcat,
        &[
            format!("--servers=127.0.0.1:{}", server.port),
            "motd".to_string(),
        ],
    )
    .await?;

    println!("--- memcat ---\n{}", output);
    assert!(
        output.contains("welcome to the fake cache"),
        "an independent C client must be able to read the value. Output: {:?}",
        output
    );
    assert!(ok, "memcat exited non-zero. Output: {:?}", output);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// `memstat` issues `stats` and parses the `STAT <name> <value>` lines up to `END`.
/// `memping` opens a connection and issues `version`. Together they cover the two reply
/// shapes `memcat` does not.
#[tokio::test]
async fn libmemcached_memstat_and_memping_accept_our_replies() -> E2EResult<()> {
    let memstat = require_tool("memstat")?;
    let memping = require_tool("memping")?;

    let config =
        NetGetConfig::new("listen on port {AVAILABLE_PORT} via memcached. Report healthy stats.")
            .with_log_level("debug")
            .with_mock(|mock| {
                mock.on_event("memcached_stats")
                    .respond_with_actions(serde_json::json!([{
                        "type": "send_memcached_stats",
                        "stats": {
                            "pid": "4242",
                            "uptime": "86400",
                            "version": "1.6.45",
                            "curr_items": "17",
                            "bytes": "8192"
                        }
                    }]))
                    .expect_at_least(1)
                    .and()
                    .on_event("memcached_version")
                    .respond_with_actions(serde_json::json!([{
                        "type": "send_memcached_version", "version": "1.6.45"
                    }]))
                    .expect_at_least(1)
                    .and()
                    .on_instruction_containing("via memcached")
                    .respond_with_actions(serde_json::json!([{
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "memcached",
                        "instruction": "Report healthy stats"
                    }]))
                    .expect_calls(1)
                    .and()
            });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let servers_arg = format!("--servers=127.0.0.1:{}", server.port);

    let (_, stats_output) = run(&memstat, std::slice::from_ref(&servers_arg)).await?;
    println!("--- memstat ---\n{}", stats_output);
    assert!(
        stats_output.contains("4242"),
        "memstat must parse the STAT lines the model invented. Output: {:?}",
        stats_output
    );
    assert!(stats_output.contains("86400"), "Output: {:?}", stats_output);

    let (ping_ok, ping_output) = run(&memping, &[servers_arg]).await?;
    println!("--- memping ---\n{}", ping_output);
    assert!(
        ping_ok,
        "memping must consider the server alive. Output: {:?}",
        ping_output
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

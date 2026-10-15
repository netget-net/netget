//! STUN against a real, independent third-party client: **stuntman's `stunclient`**.
//!
//! # Why this test exists
//!
//! Every other test in `tests/server/stun/` builds its Binding Request by hand and decodes the
//! reply by hand. That is an independent *reading* of RFC 8489, not an independent
//! *implementation* of it — the same class of evidence `dhcp`'s in-test decoder provides, and
//! the reason `dhcp` is not Beta. A hand-rolled decoder that shares a misreading with the
//! server it checks agrees with it perfectly.
//!
//! `stunclient` is the command-line client from **stuntman** (1.2.16), a C++ STUN
//! implementation written by somebody who has never seen this repository. It builds its own
//! Binding Request with its own transaction ID, and — the part that matters — it must
//! **un-XOR** our XOR-MAPPED-ADDRESS attribute against the magic cookie and its own transaction
//! ID to recover the address it prints. If our attribute is encoded wrongly in any byte, the
//! address it prints is not the one it sent from, and the assertion below fails.
//!
//! # Not circular
//!
//! NetGet's STUN **server** is a hand-written RFC 8489 codec (`src/server/stun/`) with no STUN
//! library behind it. The `stunclient` *crate* that appears in `Cargo.toml` is a Rust library
//! used by NetGet's STUN **client** (`src/client/stun/`), which is a different program and is
//! not running here. The peer in this test is an unrelated C++ binary on `PATH`. Nothing on
//! either side of this exchange shares code with the other.
//!
//! # Zero LLM calls, deliberately
//!
//! The server is opened with an empty instruction, so the Binding response is produced
//! mechanically (see `static_default_test.rs`). That makes this test evidence about the
//! *protocol implementation* rather than about a mock's ability to echo a transaction ID: the
//! bytes stuntman accepts were assembled by `src/server/stun/`, and by nothing else.

#![cfg(unix)]

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::net::SocketAddr;
use std::time::Duration;

/// Run `stunclient` under a wall-clock bound and return its combined output.
///
/// stuntman retries a silent server on its own schedule before giving up, so a server that
/// answers *wrongly* does not fail this test — it hangs it. Bounded, a broken server produces a
/// failure that names the timeout instead of taking a `--test-threads=32` suite with it.
async fn run_stunclient(port: u16) -> E2EResult<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new("stunclient")
            .arg("127.0.0.1")
            .arg(port.to_string())
            .output(),
    )
    .await
    .map_err(|_| format!("stunclient did not finish within 60s against 127.0.0.1:{port}"))??;

    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    println!("--- stunclient output ---\n{combined}\n--- end ---");
    Ok(combined)
}

/// Pull `SocketAddr` out of a `Label: 1.2.3.4:5678` line of stuntman's output.
fn address_after(output: &str, label: &str) -> Option<SocketAddr> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix(label))
        .and_then(|rest| rest.trim().parse::<SocketAddr>().ok())
}

#[tokio::test]
async fn test_stun_binding_against_real_stunclient() -> E2EResult<()> {
    println!("\n=== E2E Test: STUN Binding Request from stuntman's stunclient ===");

    // The real client IS the evidence. A machine without it must say so rather than report a
    // silent pass: a vacuous green here is exactly how a maturity claim outlives the thing
    // that justified it, and STUN's `e2e_testing` field named "stuntman-client" for a long
    // time while nothing in this tree had ever run it.
    //
    // The status is deliberately not checked: `stunclient --help` exits 254 and a bare
    // `stunclient` exits 255. Presence is what the gate is for, and a spawn that returns
    // `Ok(_)` at all means the binary is there and executable.
    match std::process::Command::new("stunclient")
        .arg("--help")
        .output()
    {
        Ok(out) => {
            let banner = String::from_utf8_lossy(&out.stdout);
            println!(
                "stunclient present: {}",
                banner
                    .lines()
                    .find(|l| l.contains("STUNCLIENT"))
                    .unwrap_or("(banner not matched)")
            );
        }
        Err(e) => {
            return Err(format!(
                "stunclient not available ({e}): this test's whole point is driving the real \
                 stuntman STUN client against NetGet's server, and skipping it would leave \
                 STUN's maturity rating resting on nothing. Install it with `brew install \
                 stuntman` (or your distribution's stuntman package)."
            )
            .into())
        }
    }

    // Empty instruction: the Binding response is mechanical, so what stuntman validates is
    // `src/server/stun/`'s encoder and not a mock echoing fields back.
    let server_config = NetGetConfig::new_no_scripts("listen on port {AVAILABLE_PORT} via stun")
        .with_mock(|mock| {
            mock.on_instruction_containing("via stun")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "STUN",
                        "instruction": ""
                    }
                ]))
                .expect_calls(1)
                .and()
                // Same guard as static_default_test: if the mechanical path ever reaches the
                // model, this fires and expect_calls(0) fails.
                .on_event("stun_binding_request")
                .respond_with_actions(serde_json::json!([]))
                .expect_calls(0)
                .and()
        });

    let server = start_netget_server(server_config).await?;
    server.wait_for_log("STUN receive loop started", 5).await?;

    let output = run_stunclient(server.port).await?;

    // stuntman prints "Binding test: success" only after it has received a well-formed Binding
    // Success Response whose transaction ID matches the one it generated.
    assert!(
        output.contains("Binding test: success"),
        "stuntman's own client did not accept NetGet's Binding response. Its output was:\n{output}"
    );

    let local = address_after(&output, "Local address:").ok_or_else(|| {
        format!("stunclient printed no parseable 'Local address:' line:\n{output}")
    })?;
    let mapped = address_after(&output, "Mapped address:").ok_or_else(|| {
        format!("stunclient printed no parseable 'Mapped address:' line:\n{output}")
    })?;

    // This is the assertion that makes the test evidence rather than a liveness check.
    //
    // stuntman recovered `mapped` by XORing our XOR-MAPPED-ADDRESS value against the magic
    // cookie (address) and the magic cookie's high half (port), using the transaction ID it
    // chose. Getting back exactly the socket it sent from means every one of those bytes was
    // encoded the way RFC 8489 says — by an implementation that has never seen ours.
    assert_eq!(
        mapped, local,
        "XOR-MAPPED-ADDRESS did not decode, in stuntman's hands, to the address stuntman sent \
         from. local={local} mapped={mapped}\n{output}"
    );
    assert!(
        mapped.ip().is_loopback(),
        "expected the reflected address to be loopback, got {mapped}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The same client, against the **model-controlled** path rather than the static default.
///
/// The test above proves `src/server/stun/mod.rs`'s mechanical encoder is right. It says
/// nothing about the other encoder — the one behind the `send_stun_binding_response` **action**,
/// which is what runs whenever the operator opts into LLM control, and which builds its
/// XOR-MAPPED-ADDRESS from strings the model supplied rather than from the socket it just read.
///
/// Those are two different code paths producing what must be the same bytes, and only one of
/// them was ever shown to a third-party implementation. This shows it the other.
#[tokio::test]
async fn test_stun_llm_authored_response_is_accepted_by_real_stunclient() -> E2EResult<()> {
    println!("\n=== E2E Test: stunclient against STUN's LLM-authored response ===");

    if let Err(e) = std::process::Command::new("stunclient")
        .arg("--help")
        .output()
    {
        return Err(format!(
            "stunclient not available ({e}): this test's whole point is driving the real \
             stuntman STUN client against NetGet's action-built Binding response, and skipping \
             it would leave STUN's maturity rating resting on nothing. Install it with `brew \
             install stuntman`."
        )
        .into());
    }

    // A non-empty instruction is what sets `operator_wants_dynamic`, so the binding request
    // goes to the model instead of being answered mechanically.
    let prompt = "Start a STUN server on port {AVAILABLE_PORT} for NAT traversal";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Start a STUN server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "STUN",
                    "instruction": "Reflect every client's address back to it"
                }
            ]))
            .expect_calls(1)
            .and()
            // Dynamic, as every UDP-style protocol in this repo must be: the transaction ID is
            // stuntman's and is different every run, so a hardcoded one would be discarded by
            // the client and the test would time out rather than fail.
            .on_event("stun_binding_request")
            .respond_with_actions_from_event(|event| {
                serde_json::json!([{
                    "type": "send_stun_binding_response",
                    "transaction_id": event["transaction_id"].as_str().unwrap_or(""),
                    "mapped_address": event["peer_addr"].as_str().unwrap_or(""),
                    "xor_mapped_address": true
                }])
            })
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(server_config).await?;
    server.wait_for_log("STUN receive loop started", 5).await?;

    let output = run_stunclient(server.port).await?;

    assert!(
        output.contains("Binding test: success"),
        "stuntman rejected the Binding response built by the send_stun_binding_response \
         action. Its output was:\n{output}"
    );

    let local = address_after(&output, "Local address:")
        .ok_or_else(|| format!("no parseable 'Local address:' line:\n{output}"))?;
    let mapped = address_after(&output, "Mapped address:")
        .ok_or_else(|| format!("no parseable 'Mapped address:' line:\n{output}"))?;
    assert_eq!(
        mapped, local,
        "the action-built XOR-MAPPED-ADDRESS did not decode, in stuntman's hands, to the \
         address stuntman sent from. local={local} mapped={mapped}\n{output}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
